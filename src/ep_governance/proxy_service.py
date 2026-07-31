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
import traceback
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ep_governance.authorizations import AuthorizationEngine, KeyManager, AuthorizationToken
from ep_governance.branches import BranchCommitter
from ep_governance.canonical import canonical_hash
from ep_governance.config import load_config
from ep_governance.db.postgres import create_engine
from ep_governance.db.repositories import PolicyRepository, BranchRepository, TransitionRepository
from ep_governance.policies import Policy
from ep_governance.policy_engine import PolicyEngine
from ep_governance.proxy.postgres_proxy import PostgresProxy
from ep_governance.proxy.base import ProxyConfig
from ep_governance.transitions import TransitionEngine


__all__ = ["ProxyServer", "ProxyHandler"]


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


class ProxyServer(HTTPServer):
    """HTTP server with proxy context."""

    proxy: PostgresProxy
    proxy_audience: str
    public_key: Any  # VerifyKey


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


def main() -> None:
    cfg = load_config()

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

    # Start the HTTP server
    server = ProxyServer(("0.0.0.0", proxy_port), ProxyHandler)
    server.proxy = proxy
    server.proxy_audience = proxy_audience
    server.public_key = public_key

    print(f"EP-Governance proxy listening on port {proxy_port}", file=sys.stderr)
    print(f"  Audience: {proxy_audience}", file=sys.stderr)
    print(f"  Target: {target_url.split('@')[1] if '@' in target_url else target_url}", file=sys.stderr)
    print(f"  Governance DB: {cfg.db_url.split('@')[1] if '@' in cfg.db_url else cfg.db_url}", file=sys.stderr)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Proxy shutting down", file=sys.stderr)
    finally:
        proxy.close()


if __name__ == "__main__":
    main()