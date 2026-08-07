"""EP-Governance Proxy Service — HTTP server for governed PostgreSQL execution.

Runs on the NAS as a Docker container. Listens on port 8201 for
token-based execution requests from agents.

The proxy:
1. Receives a signed token + payload from an agent over HTTP
2. Verifies the token signature using EP's public key
3. Computes the payload hash from the actual payload
4. Atomically claims the authorization from the governance DB
5. Executes the SQL against the target database
6. Returns the result to the agent
7. EP records the result and advances the governance graph

Configuration via environment variables:
- EP_DB_URL: Governance DB connection string (NAS PostgreSQL)
- EP_DB_SCHEMA: Governance DB schema (ep_governance)
- EP_PROXY_TARGET_URL: Target database connection string (what the proxy executes against)
- EP_PROXY_AUDIENCE: Token audience string (must match what EP issues)
- EP_EP_SERVICE_ID: XID of the EP service principal
- EP_PUBLIC_KEY: Ed25519 public key (hex) for token verification
- EP_PROXY_PORT: Port to listen on (default 8201)
"""

from __future__ import annotations

import json
import os
import sys
import ssl
import time
import threading
import traceback
from collections import defaultdict, deque
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ep_governance.authorizations import AuthorizationEngine, KeyManager, AuthorizationToken
from ep_governance.branches import BranchCommitter
from ep_governance.canonical import canonical_hash
from ep_governance.config import load_config, OperatingMode
from ep_governance.db.postgres import create_engine
from ep_governance.db.repositories import PolicyRepository, BranchRepository, TransitionRepository
from ep_governance.deployment import EnforcementCapability, EnforcementUnavailableError
from ep_governance.policies import Policy
from ep_governance.policy_engine import PolicyEngine
from ep_governance.proxy.postgres_proxy import PostgresProxy
from ep_governance.proxy.base import ProxyConfig
from ep_governance.transitions import TransitionEngine


__all__ = ["ProxyServer", "ProxyHandler", "ProxyConfigurationError"]


class ProxyConfigurationError(RuntimeError):
    """Raised when the proxy cannot start due to a configuration error.

    This is a typed exception that load_proxy_capability() raises instead
    of calling sys.exit() directly. The main() entry point catches it and
    converts it to a process exit.
    """


class ProxyHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the proxy service."""

    def _send_json(self, status: int, data: dict[str, Any]) -> None:
        body = json.dumps(data, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json(200, {"status": "ok", "service": "ep-governance-proxy"})
        elif self.path == "/info":
            self._send_json(200, {
                "service": "ep-governance-proxy",
                "audience": self.server.proxy_audience,
                "target": "postgresql",
            })
        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self) -> None:
        if self.path != "/execute":
            self._send_json(404, {"error": "Not found"})
            return

        # Rate limiting on /execute endpoint
        client_ip = self.client_address[0] if self.client_address else "unknown"
        rate_limiter = getattr(self.server, "rate_limiter", None)
        if rate_limiter and not rate_limiter.check(client_ip):
            self._send_json(429, {
                "error": "Rate limit exceeded",
                "message": f"Too many requests from {client_ip}. "
                           f"Max {rate_limiter.max_requests} per "
                           f"{rate_limiter.window_seconds}s.",
            })
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            request = json.loads(body)
        except Exception as exc:
            self._send_json(400, {"error": f"Invalid request: {exc}"})
            return

        signed_token = request.get("signed_token")
        payload = request.get("payload")

        if not signed_token or not payload:
            self._send_json(400, {"error": "Missing signed_token or payload"})
            return

        try:
            result = self.server.proxy.execute(
                signed_token=signed_token,
                payload=payload,
                public_key=self.server.public_key,
                enforcement_capability=self.server.enforcement_capability,
            )
            self._send_json(200, {
                "success": result.success,
                "exit_status": result.exit_status,
                "result_summary": result.result_summary,
                "rows_affected": result.rows_affected,
                "output": result.output,
                "execution_attempt_id": result.execution_attempt_id,
                "started_at": result.started_at,
                "completed_at": result.completed_at,
                "redacted": result.redacted,
            })
        except Exception as exc:
            self._send_json(500, {"error": f"Execution failed: {exc}"})

    def log_message(self, format: str, *args: Any) -> None:
        # Log to stderr for Docker logs
        sys.stderr.write(f"[proxy] {self.address_string()} - {format % args}\n")


class RateLimiter:
    """Simple in-memory rate limiter using sliding window per client IP.

    Limits the number of requests per time window per client. Thread-safe.
    """

    def __init__(self, max_requests: int = 30, window_seconds: int = 60) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, client_ip: str) -> bool:
        """Return True if the request is allowed, False if rate-limited."""
        now = time.monotonic()
        with self._lock:
            reqs = self._requests[client_ip]
            # Evict entries outside the window
            while reqs and reqs[0] <= now - self.window_seconds:
                reqs.popleft()
            if len(reqs) >= self.max_requests:
                return False
            reqs.append(now)
            return True


class ProxyServer(HTTPServer):
    """HTTP server with proxy context."""

    proxy: PostgresProxy
    proxy_audience: str
    public_key: Any  # VerifyKey
    enforcement_capability: EnforcementCapability
    rate_limiter: RateLimiter


def _load_public_key(hex_key: str) -> Any:
    """Load an Ed25519 public key from hex."""
    from nacl.signing import VerifyKey
    # VerifyKey accepts raw bytes — decode hex first
    return VerifyKey(bytes.fromhex(hex_key))


def _load_policy_engine(engine, branch_id: str) -> PolicyEngine | None:
    """Load active policies for a branch and build a PolicyEngine."""
    import sqlalchemy as sa
    with engine.connect() as conn:
        # Get project_id from branch
        result = conn.execute(sa.text(
            "SELECT l.project_id FROM ep_branches b "
            "JOIN ep_lattices l ON b.lattice_id = l.id "
            "WHERE b.id = :bid"
        ), {"bid": branch_id})
        row = result.fetchone()
        if row is None:
            return None
        project_id = row[0]

        policy_repo = PolicyRepository(conn)
        rows = policy_repo.list_active_policies_for_project(project_id)
        policies = []
        for prow in rows:
            try:
                actions = prow.get("actions", [])
                if isinstance(actions, str):
                    actions = json.loads(actions)
                resources = prow.get("resources", [])
                if isinstance(resources, str):
                    resources = json.loads(resources)
                conditions = prow.get("conditions", {})
                if isinstance(conditions, str):
                    conditions = json.loads(conditions)
                exception_to = prow.get("exception_to", [])
                if isinstance(exception_to, str):
                    exception_to = json.loads(exception_to)

                p = Policy(
                    id=prow["id"],
                    effect=prow["effect"],
                    actions=actions,
                    resources=resources,
                    conditions=conditions,
                    priority=prow.get("priority", 0),
                    scope=prow.get("scope", "global"),
                    agent_scope=prow.get("agent_scope"),
                    project_id=prow.get("project_id"),
                    branch_id=prow.get("branch_id"),
                    description=prow.get("description", ""),
                    status=prow.get("status", "active"),
                    created_by=prow.get("created_by", ""),
                    approved_by=prow.get("approved_by", ""),
                    approved_at=str(prow.get("approved_at", "")),
                    activation_version=prow.get("activation_version", 1),
                    exception_to=exception_to,
                    valid_from=str(prow.get("valid_from", "")) if prow.get("valid_from") else None,
                    valid_until=str(prow.get("valid_until", "")) if prow.get("valid_until") else None,
                    justification=prow.get("justification"),
                )
                policies.append(p)
            except Exception:
                continue
        return PolicyEngine(policies) if policies else None


def load_proxy_capability(proxy_audience: str) -> EnforcementCapability:
    """Load and verify the proxy's enforcement capability from a signed attestation.

    The proxy refuses to self-mint a capability. Instead, a deployment
    controller signs an attestation document (JSON with a "signature" field)
    and the proxy loads it from the file path in EP_PROXY_ATTESTATION_PATH,
    verifying the signature against the controller public key in
    EP_CONTROLLER_PUBLIC_KEY.

    Required env vars:
      EP_PROXY_ATTESTATION_PATH: Path to the signed attestation JSON file.
      EP_CONTROLLER_PUBLIC_KEY: Hex-encoded Ed25519 public key of the
        trusted deployment controller.

    Required env vars (all four mandatory for attestation binding):
      EP_PROXY_AUDIENCE: Expected proxy audience string.
      EP_PROXY_PRINCIPAL_ID: Expected proxy principal identity.
      EP_DEPLOYMENT_ID: Expected deployment identifier.
      EP_PROXY_TARGET_ID: Expected target system identifier.

    After loading, the capability's proxy_audience is checked against the
    configured proxy_audience via matches_proxy_audience().

    Raises ProxyConfigurationError on any configuration failure.
    Returns the verified EnforcementCapability on success.
    """
    attestation_path = os.environ.get("EP_PROXY_ATTESTATION_PATH", "")
    if not attestation_path:
        raise ProxyConfigurationError(
            "EP_PROXY_ATTESTATION_PATH is required — the proxy cannot "
            "start without a signed proxy attestation. Self-minting a "
            "capability is prohibited."
        )

    try:
        with open(attestation_path, "r", encoding="utf-8") as f:
            attestation_content = f.read()
    except OSError as exc:
        raise ProxyConfigurationError(
            f"Failed to read attestation file {attestation_path}: {exc}"
        ) from exc

    controller_public_key_hex = os.environ.get("EP_CONTROLLER_PUBLIC_KEY", "")
    if not controller_public_key_hex:
        raise ProxyConfigurationError(
            "EP_CONTROLLER_PUBLIC_KEY is required — the proxy cannot "
            "verify the attestation signature without the trusted controller "
            "public key."
        )

    try:
        controller_public_key = _load_public_key(controller_public_key_hex)
    except (ValueError, TypeError) as exc:
        raise ProxyConfigurationError(
            f"Failed to load controller public key: {exc}"
        ) from exc

    expected_proxy_audience = (os.environ.get("EP_PROXY_AUDIENCE", "") or "").strip() or None
    expected_deployment_id = (os.environ.get("EP_DEPLOYMENT_ID", "") or "").strip() or None
    expected_target_id = (os.environ.get("EP_PROXY_TARGET_ID", "") or "").strip() or None
    expected_proxy_principal_id = (os.environ.get("EP_PROXY_PRINCIPAL_ID", "") or "").strip() or None

    # All four expected bindings are mandatory for any governed proxy.
    required_bindings = {
        "EP_PROXY_PRINCIPAL_ID": expected_proxy_principal_id,
        "EP_PROXY_AUDIENCE": expected_proxy_audience,
        "EP_DEPLOYMENT_ID": expected_deployment_id,
        "EP_PROXY_TARGET_ID": expected_target_id,
    }
    missing = [name for name, value in required_bindings.items() if not value]
    if missing:
        raise ProxyConfigurationError(
            f"Missing required attestation bindings: {', '.join(missing)}. "
            f"A governed proxy must verify the attestation belongs to its "
            f"exact deployment. Configure all four bindings."
        )

    try:
        capability = EnforcementCapability.from_signed_attestation(
            attestation_content,
            controller_public_key,
            expected_proxy_audience=expected_proxy_audience,
            expected_deployment_id=expected_deployment_id,
            expected_target_id=expected_target_id,
            expected_proxy_principal_id=expected_proxy_principal_id,
        )
    except EnforcementUnavailableError as exc:
        raise ProxyConfigurationError(
            f"Failed to load signed proxy attestation: {exc}"
        ) from exc
    except (ValueError, TypeError, KeyError) as exc:
        raise ProxyConfigurationError(
            f"Invalid attestation data: {exc}"
        ) from exc

    if not capability.matches_proxy_audience(proxy_audience):
        raise ProxyConfigurationError(
            f"Loaded capability's proxy_audience does not match the "
            f"configured proxy audience. Expected {proxy_audience!r}, got "
            f"{getattr(capability, 'proxy_audience', None)!r}."
        )

    print(
        "Proxy enforcement capability loaded and verified from signed "
        "attestation.",
        file=sys.stderr,
    )
    return capability


def main() -> None:
    cfg = load_config()

    # Production enforcement: the proxy refuses to start in advisory mode.
    # Advisory mode is only available in development (EP_DEV=true).
    if cfg.mode == OperatingMode.ADVISORY:
        if not cfg.dev:
            print(
                "FATAL: Proxy cannot start in advisory mode in production. "
                "Set EP_MODE=enforced.",
                file=sys.stderr,
            )
            sys.exit(1)
        if not cfg.allow_advisory_execution:
            print(
                "FATAL: Proxy cannot start in advisory mode without "
                "EP_ALLOW_ADVISORY_EXECUTION=true.",
                file=sys.stderr,
            )
            sys.exit(1)
        print(
            "WARNING: Proxy starting in advisory mode (development). "
            "Production deployments must use EP_MODE=enforced.",
            file=sys.stderr,
        )

    # Required environment variables
    target_url = os.environ.get("EP_PROXY_TARGET_URL", "")
    if not target_url:
        print("EP_PROXY_TARGET_URL is required", file=sys.stderr)
        sys.exit(1)

    public_key_hex = os.environ.get("EP_PUBLIC_KEY", "")
    if not public_key_hex:
        print("EP_PUBLIC_KEY is required (Ed25519 public key in hex)", file=sys.stderr)
        sys.exit(1)

    ep_service_id = os.environ.get("EP_EP_SERVICE_ID", "")
    if not ep_service_id:
        print("EP_EP_SERVICE_ID is required", file=sys.stderr)
        sys.exit(1)

    proxy_audience = os.environ.get("EP_PROXY_AUDIENCE", "postgres-proxy")
    proxy_port = int(os.environ.get("EP_PROXY_PORT", "8201"))

    # Create governance DB engine (for claiming tokens, reporting results)
    gov_engine = create_engine(cfg.db_url, schema=cfg.db_schema or None)

    # Create authorization engine
    # The proxy needs a KeyManager only for the public key — it doesn't sign
    km = KeyManager()
    public_key = _load_public_key(public_key_hex)

    # Auth engine for token claiming
    auth_engine = AuthorizationEngine(gov_engine, km, ep_service_id)

    # Transition engine for result reporting
    policy_engine = None  # Loaded per-request from the token's branch context
    trans_engine = TransitionEngine(gov_engine, ep_service_id, policy_engine=policy_engine)
    branch_committer = BranchCommitter(gov_engine, ep_service_id)

    # Proxy config
    proxy_config = ProxyConfig(
        target_connection_string=target_url,
        proxy_audience=proxy_audience,
        ep_service_principal_id=ep_service_id,
        timeout_seconds=30,
    )

    # Create the proxy
    proxy = PostgresProxy(
        engine=gov_engine,
        auth_engine=auth_engine,
        config=proxy_config,
        transition_engine=trans_engine,
        branch_committer=branch_committer,
        policy_engine=None,  # Set per-request if needed
    )

    # Load the enforcement capability from a signed proxy attestation.
    # The proxy must NOT self-mint a capability — that would bypass the
    # deployment controller's signature. Instead, the controller signs an
    # attestation document and the proxy loads/verifies it at startup.
    # See load_proxy_capability() for the encapsulated logic.
    try:
        proxy_capability = load_proxy_capability(proxy_audience)
    except ProxyConfigurationError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        sys.exit(1)

    # Start the HTTP server (with optional TLS)
    server = ProxyServer(("0.0.0.0", proxy_port), ProxyHandler)
    server.proxy = proxy
    server.proxy_audience = proxy_audience
    server.public_key = public_key
    server.enforcement_capability = proxy_capability

    # Rate limiter: 30 requests per minute per client IP
    rate_max = int(os.environ.get("EP_PROXY_RATE_LIMIT", "30"))
    rate_window = int(os.environ.get("EP_PROXY_RATE_WINDOW", "60"))
    server.rate_limiter = RateLimiter(max_requests=rate_max, window_seconds=rate_window)

    # TLS configuration (if cert and key files are provided)
    tls_cert = os.environ.get("EP_PROXY_TLS_CERT", "")
    tls_key = os.environ.get("EP_PROXY_TLS_KEY", "")
    use_tls = bool(tls_cert and tls_key)

    if use_tls:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(tls_cert, tls_key)
        server.socket = ssl_context.wrap_socket(server.socket, server_side=True)
        print(f"  TLS: enabled (cert: {tls_cert})", file=sys.stderr)
    else:
        print(f"  TLS: disabled (set EP_PROXY_TLS_CERT and EP_PROXY_TLS_KEY to enable)", file=sys.stderr)

    print(f"EP-Governance proxy listening on port {proxy_port}", file=sys.stderr)
    print(f"  Audience: {proxy_audience}", file=sys.stderr)
    print(f"  Target: {target_url.split('@')[1] if '@' in target_url else target_url}", file=sys.stderr)
    print(f"  Governance DB: {cfg.db_url.split('@')[1] if '@' in cfg.db_url else cfg.db_url}", file=sys.stderr)
    print(f"  Rate limit: {rate_max} requests per {rate_window}s per IP", file=sys.stderr)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Proxy shutting down", file=sys.stderr)
    finally:
        proxy.close()


if __name__ == "__main__":
    main()