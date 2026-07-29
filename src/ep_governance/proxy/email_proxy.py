"""EP-Governance Email proxy adapter.

A governed proxy for sending email.  The proxy validates recipients, checks
subject and body constraints, verifies the authorization token's ``tool``
field is ``"email.send"``, and returns a *simulated* result.

This is a stub implementation — real execution requires an SMTP relay or
email API access and is deferred to a later phase.

Privacy: the email **body** is never included in ``result_summary`` — only
the recipient count and subject are disclosed in the summary.
"""

from __future__ import annotations

import re
from typing import Any

from ..authorizations import AuthorizationToken
from ..errors import ClassificationError
from .base import ExecutionResult, GovernedProxy, ProxyConfig

__all__ = ["EmailProxy"]

# The proxy only supports sending email.  There is a single operation.
ALLOWED_OPERATIONS: frozenset[str] = frozenset({"send"})

# No restricted operations beyond the single "send" — sending always
# requires explicit authorization (the token tool must be "email.send").
RESTRICTED_OPERATIONS: frozenset[str] = frozenset()

# No forbidden operations — the proxy simply rejects invalid payloads.
FORBIDDEN_OPERATIONS: frozenset[str] = frozenset()

# RFC 5322 simplified email regex (sufficient for validation-level checks).
_EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

# Maximum subject length (RFC 5321 recommends 78 chars per line; we allow
# up to 998 for a single-line subject).
_MAX_SUBJECT_LENGTH = 998

# Maximum body size in bytes (configurable via ProxyConfig.max_output_bytes
# but we use a separate constant for the body to avoid coupling).
_MAX_BODY_BYTES = 1_048_576  # 1 MB


class EmailProxy(GovernedProxy):
    """Governed proxy for email sending.

    The proxy holds the SMTP connection string (via :class:`ProxyConfig`).
    The agent never receives it.  The agent sends a signed token + payload
    to the proxy; the proxy verifies, validates, and (in the real
    implementation) sends.

    This stub does **not** send email — it returns a simulated
    :class:`ExecutionResult` describing what would be sent.
    """

    def __init__(
        self,
        conn: Any,
        auth_engine: Any,
        config: ProxyConfig,
    ) -> None:
        super().__init__(conn, auth_engine, config)

    # ------------------------------------------------------------------ #
    # Validation helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _is_valid_email(address: str) -> bool:
        """Return ``True`` if *address* is a syntactically valid email."""
        if not address or not isinstance(address, str):
            return False
        return bool(_EMAIL_RE.match(address.strip()))

    @staticmethod
    def _validate_recipients(
        recipients: list[str],
        field_name: str,
    ) -> list[str] | None:
        """Validate a list of recipient email addresses.

        Returns the cleaned list of valid addresses, or ``None`` if any
        address is invalid or the list is empty.
        """
        if not recipients:
            return None
        if not isinstance(recipients, list):
            return None
        cleaned: list[str] = []
        for addr in recipients:
            if not EmailProxy._is_valid_email(addr):
                return None
            cleaned.append(addr.strip())
        return cleaned if cleaned else None

    # ------------------------------------------------------------------ #
    # Bounded adapter
    # ------------------------------------------------------------------ #

    def _execute_adapter(
        self,
        payload: dict[str, Any],
        token: AuthorizationToken,
        attempt_id: str,
    ) -> ExecutionResult:
        """Execute (simulate) an email send through the bounded adapter.

        Steps:
        1. Extract email fields from payload.
        2. Validate recipients (to, cc, bcc).
        3. Validate subject and body.
        4. Verify the token's ``tool`` field is ``"email.send"``.
        5. Return a simulated result (body is never in the summary).
        """
        # Step 1: Extract email fields.
        to = payload.get("to", [])
        subject = payload.get("subject", "")
        body = payload.get("body", "")
        cc = payload.get("cc", [])
        bcc = payload.get("bcc", [])

        # Step 2: Validate recipients.
        try:
            valid_to = self._validate_recipients(to, "to")
            if valid_to is None:
                return ExecutionResult(
                    success=False,
                    exit_status="failure",
                    result_summary=(
                        "Invalid recipients: 'to' list is empty or contains invalid email addresses"
                    ),
                )

            valid_cc: list[str] | None = None
            if cc:
                valid_cc = self._validate_recipients(cc, "cc")
                if valid_cc is None:
                    return ExecutionResult(
                        success=False,
                        exit_status="failure",
                        result_summary=(
                            "Invalid recipients: 'cc' list contains invalid email addresses"
                        ),
                    )

            valid_bcc: list[str] | None = None
            if bcc:
                valid_bcc = self._validate_recipients(bcc, "bcc")
                if valid_bcc is None:
                    return ExecutionResult(
                        success=False,
                        exit_status="failure",
                        result_summary=(
                            "Invalid recipients: 'bcc' list contains invalid email addresses"
                        ),
                    )
        except ClassificationError as exc:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=f"Classification failed: {exc!s}",
            )

        # Step 3: Validate subject and body.
        if not isinstance(subject, str):
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary="Invalid subject: must be a string",
            )

        if len(subject) > _MAX_SUBJECT_LENGTH:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=(
                    f"Subject exceeds maximum length of {_MAX_SUBJECT_LENGTH} characters"
                ),
            )

        if not isinstance(body, str):
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary="Invalid body: must be a string",
            )

        body_bytes = len(body.encode("utf-8"))
        if body_bytes > _MAX_BODY_BYTES:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=(f"Body exceeds maximum size of {_MAX_BODY_BYTES} bytes"),
            )

        # Step 4: Verify token tool is "email.send".
        if token.tool.lower() != "email.send":
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=(f"Token tool '{token.tool}' does not match required 'email.send'"),
            )

        # Step 5: Return simulated result.
        # PRIVACY: never include the body in result_summary.
        total_recipients = len(valid_to) + len(valid_cc or []) + len(valid_bcc or [])
        simulated_output = (
            f"[SIMULATED] Email send operation\n"
            f"[SIMULATED] To: {len(valid_to)} recipient(s)\n"
            f"[SIMULATED] Cc: {len(valid_cc or [])} recipient(s)\n"
            f"[SIMULATED] Bcc: {len(valid_bcc or [])} recipient(s)\n"
            f"[SIMULATED] Total recipients: {total_recipients}\n"
            f"[SIMULATED] Subject: {subject}\n"
            f"[SIMULATED] Body size: {body_bytes} bytes\n"
            f"[SIMULATED] No actual email sent (stub proxy)."
        )

        return ExecutionResult(
            success=True,
            exit_status="success",
            result_summary=(
                f"Simulated email send to {total_recipients} recipient(s) — subject: {subject}"
            ),
            output=self._enforce_output_limit(simulated_output),
            redacted=True,  # body is not included in summary
        )

    # ------------------------------------------------------------------ #
    # Cleanup
    # ------------------------------------------------------------------ #

    def close(self) -> None:
        """Release resources.

        This stub holds no external resources (no SMTP connection), so
        close() is a no-op.  In a real implementation this would close
        the SMTP client.
        """
        pass
