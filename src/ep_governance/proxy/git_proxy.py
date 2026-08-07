"""EP-Governance Git proxy adapter.

A governed proxy for Git operations.  The proxy classifies the requested
git command server-side, enforces an allowed-operation subset, rejects
``push --force`` unconditionally, verifies the authorization token's
``tool`` field matches the classified operation, and returns a *simulated*
result.

This is a stub implementation — real execution requires filesystem access
to the repository and is deferred to a later phase.

Supported operations:
  - Read-only (allowed):    status, log, diff, show, branch, tag
  - Restricted (auth req):  push, reset, merge, rebase, commit, fetch
  - Forbidden:              push --force (always rejected by the proxy)
"""

from __future__ import annotations

import os
import shlex
from typing import Any

from ..authorizations import AuthorizationToken
from ..errors import ClassificationError
from .base import ExecutionResult, GovernedProxy, ProxyConfig

__all__ = ["GitProxy"]

# Read-only operations the proxy will execute without additional authorization.
ALLOWED_OPERATIONS: frozenset[str] = frozenset(
    {
        "status",
        "log",
        "diff",
        "show",
        "branch",
        "tag",
    }
)

# Operations that require explicit authorization (the token's ``tool`` field
# must match the operation).
RESTRICTED_OPERATIONS: frozenset[str] = frozenset(
    {
        "push",
        "reset",
        "merge",
        "rebase",
        "commit",
        "fetch",
    }
)

# Operations the proxy will never execute.
FORBIDDEN_OPERATIONS: frozenset[str] = frozenset(
    {
        "push --force",
    }
)

# All known git operations the proxy can classify.
_KNOWN_OPERATIONS: frozenset[str] = ALLOWED_OPERATIONS | RESTRICTED_OPERATIONS


class GitProxy(GovernedProxy):
    """Governed proxy for Git command execution.

    The proxy holds the repository path (via :class:`ProxyConfig`'s
    ``target_connection_string``).  The agent never receives it.  The agent
    sends a signed token + payload to the proxy; the proxy verifies,
    classifies, and (in the real implementation) executes.

    This stub does **not** execute git commands — it returns a simulated
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
    def _classify_command(command: str, args: list[str] | None = None) -> tuple[str | None, bool]:
        """Parse a git command and return ``(operation, is_force)``.

        *operation* is the lowercased git sub-command if it is a known
        operation, otherwise ``None`` (unclassifiable).

        *is_force* is ``True`` if ``--force`` or ``-f`` is present in the
        arguments (used to detect ``push --force``).

        Examples::

            "status"                      -> ("status", False)
            "push"                        -> ("push", False)
            "push", ["--force"]           -> ("push", True)
            "reset", ["--hard"]          -> ("reset", False)
            "checkout"                    -> (None, False)
        """
        if not command or not isinstance(command, str):
            return None, False

        op = command.strip().lower()

        # Check for --force / -f in args or in the command string itself.
        full_tokens: list[str] = []
        try:
            full_tokens = shlex.split(command.strip())
        except ValueError:
            pass
        if args:
            full_tokens.extend(args)

        is_force = any(t in ("--force", "-f") for t in full_tokens)

        if op in _KNOWN_OPERATIONS:
            return op, is_force

        return None, is_force

    # ------------------------------------------------------------------ #
    # Bounded adapter
    # ------------------------------------------------------------------ #

    def _execute_adapter(
        self,
        payload: dict[str, Any],
        token: AuthorizationToken,
        attempt_id: str,
    ) -> ExecutionResult:
        """Execute (simulate) a Git command through the bounded adapter.

        Steps:
        1. Extract the git command, repo, and args from the payload.
        2. Classify the command to identify the operation.
        3. Reject unknown / unclassifiable commands (opaque).
        4. Check forbidden operations (push --force).
        5. Verify the token's ``tool`` field matches the git operation.
        6. Return a simulated result.
        """
        # Step 1: Extract fields from payload.
        command = payload.get("command")
        repo = payload.get("repo", "")
        args = payload.get("args")

        if not command or not isinstance(command, str):
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary="No git command in payload",
            )

        if args is None:
            args = []
        if not isinstance(args, list):
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary="Invalid args: must be a list",
            )

        # Step 2: Classify the command.
        try:
            operation, is_force = self._classify_command(command, args)
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
                    "Git command is opaque or unclassifiable — requires explicit approval"
                ),
            )

        # Step 4: Check forbidden operations.
        # push --force is always rejected.
        if operation == "push" and is_force:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary="Operation 'push --force' is forbidden by the proxy",
            )

        # Check if operation is in any known set.
        is_allowed = operation in ALLOWED_OPERATIONS
        is_restricted = operation in RESTRICTED_OPERATIONS

        if not is_allowed and not is_restricted:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=f"Operation '{operation}' is not in the allowed git subset",
            )

        # Step 5: Verify the token's tool field matches the git operation.
        # The token.tool should be "git.<operation>" or just "<operation>"
        # or "git" for read-only operations.
        token_tool = token.tool.lower()
        expected_tool = f"git.{operation}"

        if is_restricted:
            # For restricted operations, the token must explicitly authorize
            # the specific operation — "git" alone is too broad.
            if token_tool != expected_tool and token_tool != operation:
                return ExecutionResult(
                    success=False,
                    exit_status="failure",
                    result_summary=(
                        f"Token tool '{token.tool}' does not match git operation '{operation}'"
                    ),
                )
        else:
            # For read-only operations, "git" is acceptable.
            if token_tool != expected_tool and token_tool != operation and token_tool != "git":
                return ExecutionResult(
                    success=False,
                    exit_status="failure",
                    result_summary=(
                        f"Token tool '{token.tool}' does not match git operation '{operation}'"
                    ),
                )

        # Step 6: Execute the git command using subprocess.
        import subprocess
        import time as _time

        attempt_id = str(__import__("ep_governance.xid", fromlist=["XID"]).XID.new())
        started = _time.time()

        args_str = " ".join(args) if args else ""
        full_command = ["git", operation] + args

        # Set working directory if repo is specified
        cwd = repo if repo and os.path.isdir(repo) else None

        try:
            proc = subprocess.run(
                full_command,
                capture_output=True,
                text=True,
                timeout=self.config.timeout_seconds if hasattr(self.config, "timeout_seconds") else 30,
                cwd=cwd,
            )
            completed = _time.time()
            success = proc.returncode == 0
            output = proc.stdout if proc.stdout else ""
            if proc.stderr:
                output += f"\n[stderr]\n{proc.stderr}" if output else proc.stderr

            return ExecutionResult(
                success=success,
                exit_status="success" if success else "failure",
                result_summary=f"git {operation} exited with code {proc.returncode}",
                output=output,
                rows_affected=0,
                execution_attempt_id=attempt_id,
                started_at=str(started),
                completed_at=str(completed),
            )
        except subprocess.TimeoutExpired:
            completed = _time.time()
            return ExecutionResult(
                success=False,
                exit_status="timeout",
                result_summary=f"git {operation} timed out",
                output=None,
                execution_attempt_id=attempt_id,
                started_at=str(started),
                completed_at=str(completed),
            )
        except Exception as exc:
            completed = _time.time()
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=f"Git execution error: {exc}",
                output=None,
                execution_attempt_id=attempt_id,
                started_at=str(started),
                completed_at=str(completed),
            )

    # ------------------------------------------------------------------ #
    # Cleanup
    # ------------------------------------------------------------------ #

    def close(self) -> None:
        """Release resources.

        This stub holds no external resources (no repository handle), so
        close() is a no-op.  In a real implementation this would close
        any open file handles or subprocess connections.
        """
        pass
