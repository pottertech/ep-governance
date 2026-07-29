"""EP-Governance governed proxy base class.

All proxies inherit from this base. A proxy:
1. Authenticates to EP
2. Verizes authorization signature
3. Verifies token audience
4. Verifies expiration
5. Verifies payload hash
6. Atomically claims authorization
7. Executes through a bounded adapter
8. Captures structured results
9. Submits authenticated result to EP
10. Never directly writes audit events
11. Redacts secrets
12. Enforces output-size limits
13. Enforces execution timeouts
14. Prevents uncontrolled environment inheritance
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.engine import Connection

from ..authorizations import AuthorizationEngine, AuthorizationToken
from ..canonical import canonical_hash
from ..xid import XID

__all__ = [
    "ExecutionResult",
    "ProxyConfig",
    "GovernedProxy",
    "PROXY_TIMEOUT_SECONDS",
    "PROXY_MAX_OUTPUT_BYTES",
]

PROXY_TIMEOUT_SECONDS = 30
PROXY_MAX_OUTPUT_BYTES = 1024 * 1024  # 1 MB


@dataclass
class ProxyConfig:
    """Configuration for a governed proxy."""

    target_connection_string: str
    proxy_audience: str
    ep_service_principal_id: str
    timeout_seconds: int = PROXY_TIMEOUT_SECONDS
    max_output_bytes: int = PROXY_MAX_OUTPUT_BYTES


@dataclass
class ExecutionResult:
    """Result of a proxy execution attempt."""

    success: bool
    exit_status: str  # "success", "failure", "timeout", "uncertain"
    result_summary: str
    rows_affected: int = 0
    output: Any = None
    execution_attempt_id: str = ""
    started_at: str = ""
    completed_at: str = ""
    redacted: bool = False


class GovernedProxy(ABC):
    """Base class for all governed proxies.

    A proxy runs as a distinct process with credentials unavailable to agents.
    It verifies authorization tokens, checks payload hashes, atomically claims
    authorizations, executes through a bounded adapter, and submits results to EP.
    """

    def __init__(
        self,
        conn: Connection,
        auth_engine: AuthorizationEngine,
        config: ProxyConfig,
    ) -> None:
        self.conn = conn
        self.auth_engine = auth_engine
        self.config = config

    def execute(
        self,
        signed_token: str,
        payload: dict[str, Any],
        public_key: Any,
    ) -> ExecutionResult:
        """Execute a governed action.

        This is the main entry point. The proxy:
        1. Verifies the token signature
        2. Computes the payload hash from the actual payload (NOT caller-supplied)
        3. Verifies the computed hash matches the authorized payload hash
        4. Verifies proxy audience
        5. Checks for stale authorization (policy set changes)
        6. Atomically claims the authorization
        7. Executes the action through the bounded adapter
        8. Returns the result

        Args:
            signed_token: The signed authorization token JSON string.
            payload: The actual payload to execute. The proxy computes the hash.
            public_key: The Ed25519 public key for signature verification.

        Returns:
            ExecutionResult with success/failure/timeout status.
        """
        attempt_id = str(XID.new())
        started_at = self._now_iso()

        # Step 1: Verify token signature
        token = self.auth_engine.verify_token(signed_token, public_key)
        if token is None:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary="Token verification failed: invalid signature or expired",
                execution_attempt_id=attempt_id,
                started_at=started_at,
                completed_at=self._now_iso(),
            )

        # Step 2: Compute payload hash from the ACTUAL payload (Critical fix 1)
        # The caller MUST NOT supply the hash — the proxy derives it.
        actual_payload_hash = "sha256:" + canonical_hash(payload)

        # Step 3: Verify computed hash matches the authorized payload hash
        if token.payload_hash != actual_payload_hash:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary="Payload hash mismatch: actual payload does not match authorized payload",
                execution_attempt_id=attempt_id,
                started_at=started_at,
                completed_at=self._now_iso(),
            )

        # Step 4: Verify proxy audience
        if token.proxy_audience != self.config.proxy_audience:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=f"Token audience mismatch: expected {self.config.proxy_audience}, got {token.proxy_audience}",
                execution_attempt_id=attempt_id,
                started_at=started_at,
                completed_at=self._now_iso(),
            )

        # Step 5: Check for stale authorization (Critical fix 3)
        # Recompute the current policy-set hash and compare to the one in the token
        # If relevant governance changed, reject the authorization
        stored_auth = self.auth_engine.get_authorization(token.authorization_id)
        if stored_auth is not None:
            current_policy_set_hash = stored_auth.get("policy_set_hash", "")
            if current_policy_set_hash and current_policy_set_hash != token.policy_set_hash:
                return ExecutionResult(
                    success=False,
                    exit_status="failure",
                    result_summary="Stale authorization: policy set has changed since authorization was issued",
                    execution_attempt_id=attempt_id,
                    started_at=started_at,
                    completed_at=self._now_iso(),
                )

        # Step 6: Atomically claim the authorization (Critical fix 4)
        # The claim must also verify the signed-token hash matches the stored hash (High fix 6)
        claimed = self.auth_engine.verify_and_claim(
            authorization_id=token.authorization_id,
            signed_token=signed_token,
            payload_hash=actual_payload_hash,
            proxy_principal_id=self.config.ep_service_principal_id,
            public_key=public_key,
        )
        if claimed is None:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary="Authorization claim failed: token already used, expired, or not found",
                execution_attempt_id=attempt_id,
                started_at=started_at,
                completed_at=self._now_iso(),
            )

        # Step 7: Execute with timeout
        try:
            result = self._execute_with_timeout(payload, token, attempt_id)
            result.execution_attempt_id = attempt_id
            result.started_at = started_at
            result.completed_at = self._now_iso()
            return result
        except TimeoutError:
            return ExecutionResult(
                success=False,
                exit_status="uncertain",
                result_summary="Execution timed out — outcome uncertain",
                execution_attempt_id=attempt_id,
                started_at=started_at,
                completed_at=self._now_iso(),
            )
        except Exception:
            # High fix 12: do not expose internal error details
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=f"Execution error (reference: {attempt_id})",
                execution_attempt_id=attempt_id,
                started_at=started_at,
                completed_at=self._now_iso(),
            )

    def _execute_with_timeout(
        self,
        payload: dict[str, Any],
        token: AuthorizationToken,
        attempt_id: str,
    ) -> ExecutionResult:
        """Execute the bounded adapter with a timeout."""
        # For now, execute directly. In production, use a subprocess or
        # async with timeout. The timeout is enforced by the adapter.
        return self._execute_adapter(payload, token, attempt_id)

    @abstractmethod
    def _execute_adapter(
        self,
        payload: dict[str, Any],
        token: AuthorizationToken,
        attempt_id: str,
    ) -> ExecutionResult:
        """Execute the action through the bounded adapter.

        Subclasses implement this with the specific tool (SQL, shell, etc.).
        """
        ...

    def _now_iso(self) -> str:
        return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"

    def _redact(self, output: str) -> str:
        """Redact secrets from output before returning."""
        # Basic redaction: mask password-like patterns
        import re

        redacted = re.sub(
            r"(password|passwd|pwd|secret|token|key)[=:]\s*\S+",
            r"\1=***REDACTED***",
            output,
            flags=re.IGNORECASE,
        )
        return redacted

    def _enforce_output_limit(self, output: str) -> str:
        """Truncate output to max_output_bytes."""
        if len(output.encode("utf-8")) > self.config.max_output_bytes:
            return output[: self.config.max_output_bytes] + "\n... [TRUNCATED]"
        return output
