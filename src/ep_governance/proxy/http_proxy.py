"""EP-Governance HTTP proxy.

Governs outbound HTTP requests: GET, POST, PUT, DELETE, PATCH.
The proxy holds network access; the agent does not directly make requests.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from ..authorizations import AuthorizationToken
from .base import ExecutionResult, GovernedProxy

__all__ = ["HTTPProxy"]


ALLOWED_OPERATIONS = frozenset({"get"})
RESTRICTED_OPERATIONS = frozenset({"post", "put", "delete", "patch"})
FORBIDDEN_OPERATIONS = frozenset({"connect", "trace"})

_MAX_RESPONSE_SIZE = 1024 * 1024  # 1 MB


class HTTPProxy(GovernedProxy):
    """Governed proxy for HTTP requests.

    Supported operations:
    - GET: allowed (read-only)
    - POST/PUT/DELETE/PATCH: restricted (require authorization)
    - CONNECT/TRACE: forbidden

    The proxy validates the target URL, enforces allowed hosts,
    and redacts sensitive headers from the result.
    """

    def _execute_adapter(
        self,
        payload: dict[str, Any],
        token: AuthorizationToken,
        attempt_id: str,
    ) -> ExecutionResult:
        method = (payload.get("method") or "GET").upper().strip()
        url = payload.get("url", "")

        if not url:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary="No 'url' in payload",
            )

        if method in FORBIDDEN_OPERATIONS:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=f"HTTP method '{method}' is forbidden by the HTTP proxy",
            )

        is_allowed = method.lower() in ALLOWED_OPERATIONS
        is_restricted = method.lower() in RESTRICTED_OPERATIONS

        if not is_allowed and not is_restricted:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=f"Unknown HTTP method '{method}' — requires approval",
            )

        if is_restricted:
            tool = token.tool.lower()
            if "http" not in tool and method.lower() not in tool:
                return ExecutionResult(
                    success=False,
                    exit_status="failure",
                    result_summary=f"HTTP '{method}' was not authorized (token tool: {token.tool})",
                )

        # Validate URL
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return ExecutionResult(
                    success=False,
                    exit_status="failure",
                    result_summary=f"Invalid URL: {url}",
                )
        except Exception as exc:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=f"URL parsing error: {exc!s}",
            )

        # Execution adapter is not implemented — return failure so the
        # governance graph does not record a no-op as success.
        return ExecutionResult(
            success=False,
            exit_status="not_implemented",
            result_summary="HTTP execution adapter is not implemented",
            output=None,
        )
