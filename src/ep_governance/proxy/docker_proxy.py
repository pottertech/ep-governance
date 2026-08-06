"""EP-Governance Docker proxy adapter.

A governed proxy for Docker operations.  The proxy classifies the requested
docker command server-side, enforces an allowed-operation subset, verifies
that the authorization token's ``tool`` field matches the classified operation,
and returns a *simulated* result.

This is a stub implementation — real execution requires Docker socket access
and is deferred to a later phase.  The simulated result includes the command
that would be run, the classified operation, and whether it would be allowed.

Supported operations:
  - Read-only (allowed):    ps, logs, inspect
  - Controlled (allowed):   start, stop
  - Restricted (auth req):  rm, exec, build, run
  - Forbidden:              none beyond the policy engine, but the proxy
                            rejects unknown/unclassifiable commands
"""

from __future__ import annotations

import shlex
from typing import Any

from ..authorizations import AuthorizationToken
from ..errors import ClassificationError
from .base import ExecutionResult, GovernedProxy, ProxyConfig

__all__ = ["DockerProxy"]

# Read-only operations the proxy will execute without additional authorization.
ALLOWED_OPERATIONS: frozenset[str] = frozenset({"ps", "logs", "inspect", "start", "stop"})

# Operations that require explicit authorization (the token's ``tool`` field
# must match the operation).
RESTRICTED_OPERATIONS: frozenset[str] = frozenset({"rm", "exec", "build", "run"})

# Operations the proxy will never execute.  Docker does not have operations
# that are universally forbidden beyond what the policy engine handles, so
# this set is empty by design.
FORBIDDEN_OPERATIONS: frozenset[str] = frozenset()

# All known docker operations the proxy can classify.
_KNOWN_OPERATIONS: frozenset[str] = ALLOWED_OPERATIONS | RESTRICTED_OPERATIONS


class DockerProxy(GovernedProxy):
    """Governed proxy for Docker command execution.

    The proxy holds the Docker socket connection string (via
    :class:`ProxyConfig`).  The agent never receives it.  The agent sends a
    signed token + payload to the proxy; the proxy verifies, classifies,
    and (in the real implementation) executes.

    This stub does **not** execute docker commands — it returns a simulated
    :class:`ExecutionResult` describing what would be executed.
    """

    def __init__(
        self,
        conn: Any,
        auth_engine: Any,
        config: ProxyConfig,
        transition_engine: Any | None = None,
        branch_committer: Any | None = None,
        policy_engine: Any | None = None,
    ) -> None:
        super().__init__(
            conn, auth_engine, config, transition_engine, branch_committer, policy_engine
        )

    # ------------------------------------------------------------------ #
    # Command classification
    # ------------------------------------------------------------------ #

    @staticmethod
    def _classify_command(command: str) -> str | None:
        """Parse a docker command string and return the operation name.

        Looks for ``docker <operation>`` in the command.  Returns the
        lowercased operation if it is a known docker sub-command, otherwise
        ``None`` (unclassifiable).

        Examples::

            "docker ps -a"            -> "ps"
            "docker logs mycontainer" -> "logs"
            "docker rm -f abc123"     -> "rm"
            "docker build -t img ."   -> "build"
            "ls -la"                  -> None  (not a docker command)
        """
        if not command or not command.strip():
            return None

        try:
            tokens = shlex.split(command.strip())
        except ValueError:
            # Unbalanced quotes or other shlex errors — treat as opaque.
            return None

        # Find the "docker" token, then the next token is the operation.
        docker_idx: int | None = None
        for i, tok in enumerate(tokens):
            if tok == "docker":
                docker_idx = i
                break

        if docker_idx is None or docker_idx + 1 >= len(tokens):
            return None

        operation = tokens[docker_idx + 1].lower()

        # Skip global docker options (e.g. "docker --host ... ps").
        while operation.startswith("-") and docker_idx + 2 < len(tokens):
            docker_idx += 1
            operation = tokens[docker_idx + 1].lower()

        if operation.startswith("-"):
            return None

        return operation if operation in _KNOWN_OPERATIONS else None

    # ------------------------------------------------------------------ #
    # Bounded adapter
    # ------------------------------------------------------------------ #

    def _execute_adapter(
        self,
        payload: dict[str, Any],
        token: AuthorizationToken,
        attempt_id: str,
    ) -> ExecutionResult:
        """Execute (simulate) a Docker command through the bounded adapter.

        Steps:
        1. Extract the docker command from the payload.
        2. Classify the command to identify the operation.
        3. Reject unknown / unclassifiable commands (opaque).
        4. Check forbidden operations.
        5. Verify the token's ``tool`` field matches the docker operation.
        6. Return a simulated result.
        """
        # Step 1: Extract command from payload.
        command = payload.get("command") or payload.get("action")
        if not command or not isinstance(command, str):
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary="No docker command in payload",
            )

        # Step 2: Classify the command.
        try:
            operation = self._classify_command(command)
        except ClassificationError as exc:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=f"Classification failed: {exc!s}",
            )

        # Step 3: Reject opaque / unclassifiable commands.
        if operation is None:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=(
                    "Docker command is opaque or unclassifiable — requires explicit approval"
                ),
            )

        # Step 4: Check forbidden operations.
        if operation in FORBIDDEN_OPERATIONS:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=f"Operation '{operation}' is forbidden by the proxy",
            )

        # Step 5: Verify the token's tool field matches the docker operation.
        # The token.tool should be "docker.<operation>" or just "<operation>".
        token_tool = token.tool.lower()
        expected_tool = f"docker.{operation}"
        if token_tool != expected_tool and token_tool != operation and token_tool != "docker":
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=(
                    f"Token tool '{token.tool}' does not match docker operation '{operation}'"
                ),
            )

        # Step 6: Determine if the operation would be allowed.
        is_restricted = operation in RESTRICTED_OPERATIONS
        is_allowed = operation in ALLOWED_OPERATIONS

        if not is_allowed and not is_restricted:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=f"Operation '{operation}' is not in the allowed docker subset",
            )

        # For restricted operations, verify the token's tool explicitly
        # authorizes this specific operation (not just "docker").
        if is_restricted:
            if token_tool == "docker":
                return ExecutionResult(
                    success=False,
                    exit_status="failure",
                    result_summary=(
                        f"Restricted operation '{operation}' requires explicit "
                        f"authorization (token tool '{token.tool}' is too broad)"
                    ),
                )

        # Step 7: Return simulated result.
        # This is a STUB — real execution requires Docker socket access.
        allowed_label = "allowed" if is_allowed else "restricted (explicitly authorized)"
        simulated_output = (
            f"[SIMULATED] Docker command: {command}\n"
            f"[SIMULATED] Classified operation: {operation}\n"
            f"[SIMULATED] Status: {allowed_label}\n"
            f"[SIMULATED] Token tool: {token.tool}\n"
            f"[SIMULATED] No actual docker execution performed (stub proxy)."
        )

        return ExecutionResult(
            success=False,
            exit_status="not_implemented",
            result_summary="Docker execution adapter is not implemented",
            output=None,
        )

    # ------------------------------------------------------------------ #
    # Cleanup
    # ------------------------------------------------------------------ #

    def close(self) -> None:
        """Release resources.

        This stub holds no external resources (no Docker socket connection),
        so close() is a no-op.  In a real implementation this would close
        the Docker client.
        """
        pass
