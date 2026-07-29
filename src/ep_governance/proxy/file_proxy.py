"""EP-Governance file operations proxy.

Governs file system actions: read, write, create, delete, move.
The proxy holds file system access credentials; the agent does not.
"""

from __future__ import annotations

import os
from typing import Any

from ..authorizations import AuthorizationToken
from .base import ExecutionResult, GovernedProxy

__all__ = ["FileProxy"]


ALLOWED_OPERATIONS = frozenset({"read", "list", "stat"})
RESTRICTED_OPERATIONS = frozenset({"write", "create", "append", "move", "delete"})
FORBIDDEN_OPERATIONS = frozenset({"chmod", "chown", "symlink_create"})

_MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB read limit


class FileProxy(GovernedProxy):
    """Governed proxy for file system operations.

    Supported operations:
    - read: read file contents (up to _MAX_FILE_SIZE)
    - list: list directory contents
    - stat: get file metadata
    - write/create/append: file modifications (require authorization)
    - move/delete: destructive operations (require authorization)
    - chmod/chown/symlink_create: forbidden
    """

    def _execute_adapter(
        self,
        payload: dict[str, Any],
        token: AuthorizationToken,
        attempt_id: str,
    ) -> ExecutionResult:
        operation = payload.get("operation") or payload.get("action", "")
        path = payload.get("path", "")

        if not operation:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary="No 'operation' in payload",
            )
        if not path:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary="No 'path' in payload",
            )

        operation = operation.lower().strip()

        if operation in FORBIDDEN_OPERATIONS:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=f"Operation '{operation}' is forbidden by the file proxy",
            )

        is_allowed = operation in ALLOWED_OPERATIONS
        is_restricted = operation in RESTRICTED_OPERATIONS

        if not is_allowed and not is_restricted:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=f"Unknown file operation '{operation}' — requires approval",
            )

        # Verify the token authorizes this operation type
        if is_restricted:
            tool = token.tool.lower()
            if operation not in tool and "file" not in tool:
                return ExecutionResult(
                    success=False,
                    exit_status="failure",
                    result_summary=f"File operation '{operation}' was not authorized (token tool: {token.tool})",
                )

        # Execute the operation
        try:
            return self._do_file_operation(operation, path, payload)
        except Exception as exc:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=f"File operation error: {exc!s}",
            )

    def _do_file_operation(
        self, operation: str, path: str, payload: dict[str, Any]
    ) -> ExecutionResult:
        """Execute the file operation (simulated for safety)."""
        # Normalize path — reject relative paths for safety
        if not os.path.isabs(path):
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=f"Path must be absolute: {path}",
            )

        if operation == "read":
            return self._do_read(path)
        elif operation == "list":
            return self._do_list(path)
        elif operation == "stat":
            return self._do_stat(path)
        elif operation in ("write", "create", "append"):
            return self._do_write(path, payload, operation)
        elif operation == "move":
            return self._do_move(path, payload)
        elif operation == "delete":
            return self._do_delete(path)
        else:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=f"Unsupported operation: {operation}",
            )

    def _do_read(self, path: str) -> ExecutionResult:
        """Read file contents (simulated)."""
        # In production, this would read the actual file
        # For now, return a simulated result
        return ExecutionResult(
            success=True,
            exit_status="success",
            result_summary=f"Would read file: {path}",
            output=f"[simulated] Contents of {path}",
        )

    def _do_list(self, path: str) -> ExecutionResult:
        """List directory contents (simulated)."""
        return ExecutionResult(
            success=True,
            exit_status="success",
            result_summary=f"Would list directory: {path}",
            output=f"[simulated] Listing of {path}",
        )

    def _do_stat(self, path: str) -> ExecutionResult:
        """Get file metadata (simulated)."""
        return ExecutionResult(
            success=True,
            exit_status="success",
            result_summary=f"Would stat: {path}",
            output=f"[simulated] Stat of {path}",
        )

    def _do_write(self, path: str, payload: dict[str, Any], operation: str) -> ExecutionResult:
        """Write/create/append to a file (simulated)."""
        content = payload.get("content", "")
        content_preview = content[:100] if content else ""
        return ExecutionResult(
            success=True,
            exit_status="success",
            result_summary=f"Would {operation} to file: {path} (content length: {len(content)})",
            output=f"[simulated] {operation} to {path}",
        )

    def _do_move(self, path: str, payload: dict[str, Any]) -> ExecutionResult:
        """Move a file (simulated)."""
        dest = payload.get("destination", "")
        return ExecutionResult(
            success=True,
            exit_status="success",
            result_summary=f"Would move {path} to {dest}",
            output=f"[simulated] Moved {path} -> {dest}",
        )

    def _do_delete(self, path: str) -> ExecutionResult:
        """Delete a file (simulated)."""
        return ExecutionResult(
            success=True,
            exit_status="success",
            result_summary=f"Would delete: {path}",
            output=f"[simulated] Deleted {path}",
        )
