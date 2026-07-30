"""EP-Governance PostgreSQL proxy.

The first and primary governed proxy. It executes SQL against a target
PostgreSQL database using credentials that the agent never sees.

Supported SQL subset (initial):
- SELECT
- INSERT
- UPDATE
- DELETE
- Controlled DDL (CREATE, ALTER, DROP) only when explicitly approved

The proxy uses sqlglot to classify the SQL before execution. Unknown
or unclassifiable SQL is rejected.
"""

from __future__ import annotations

from typing import Any

import sqlalchemy as sa

from ..authorizations import AuthorizationToken
from ..classification import (
    get_classifier,
)
from ..errors import ClassificationError
from .base import ExecutionResult, GovernedProxy, ProxyConfig

__all__ = ["PostgresProxy"]


# SQL operations the proxy will execute
ALLOWED_OPERATIONS = frozenset({"select", "insert", "update", "delete"})
# DDL operations require explicit approval (the authorization token must
# have been issued for a DDL action type)
DDL_OPERATIONS = frozenset({"create", "alter", "drop"})
# Operations the proxy will NEVER execute
FORBIDDEN_OPERATIONS = frozenset({"truncate", "grant", "revoke", "vacuum"})


class PostgresProxy(GovernedProxy):
    """Governed proxy for PostgreSQL SQL execution.

    The proxy holds the target database connection string. The agent never
    receives it. The agent sends a signed token + payload to the proxy;
    the proxy verifies, classifies, and executes.
    """

    def __init__(
        self,
        engine: sa.Engine,
        auth_engine: Any,
        config: ProxyConfig,
        transition_engine: Any | None = None,
        branch_committer: Any | None = None,
        policy_engine: Any | None = None,
    ) -> None:
        super().__init__(
            engine, auth_engine, config, transition_engine, branch_committer, policy_engine
        )
        self._target_engine: sa.Engine | None = None

    @property
    def target_engine(self) -> sa.Engine:
        """Lazily create the target database engine."""
        if self._target_engine is None:
            self._target_engine = sa.create_engine(
                self.config.target_connection_string,
                future=True,
            )
        return self._target_engine

    def _validate_adapter_payload(
        self,
        payload: dict[str, Any],
        token: AuthorizationToken,
    ) -> str | None:
        """Validate the PostgreSQL payload before claiming the token.

        Checks adapter-specific constraints WITHOUT side effects:
        - SQL is present in the payload
        - The SQL can be classified (not opaque)
        - The operation is not in the forbidden set

        Returns ``None`` if valid, or an error message string.
        """
        # Extract SQL from payload
        sql = payload.get("sql") or payload.get("query") or payload.get("statement")
        if not sql:
            return "No SQL statement in payload"

        # Classify the SQL
        classifier = get_classifier("postgres.execute")
        if classifier is None:
            return "No classifier available for postgres.execute"

        try:
            classification = classifier.classify("postgres.execute", payload)
        except ClassificationError as exc:
            return f"Classification failed: {exc!s}"

        # Check for opaque classification
        if classification.opaque:
            return "SQL classification is opaque — requires explicit approval"

        # Extract operation type from classification
        action_type = classification.action_type
        # Normalize: "postgres.execute.select" -> "select"
        operation = (
            action_type.rsplit(".", 1)[-1].lower() if "." in action_type else action_type.lower()
        )

        # Check forbidden operations
        if operation in FORBIDDEN_OPERATIONS:
            return f"Operation '{operation}' is forbidden by the proxy"

        return None

    def _execute_adapter(
        self,
        payload: dict[str, Any],
        token: AuthorizationToken,
        attempt_id: str,
    ) -> ExecutionResult:
        """Execute SQL through the PostgreSQL adapter.

        Steps:
        1. Extract and classify the SQL
        2. Check the classified operation is allowed
        3. Verify the classified action type matches what was authorized (tool field)
        4. Execute the SQL against the target database
        5. Capture the result
        """
        # Extract SQL from payload
        sql = payload.get("sql") or payload.get("query") or payload.get("statement")
        if not sql:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary="No SQL statement in payload",
            )

        # Classify the SQL server-side
        classifier = get_classifier("postgres.execute")
        if classifier is None:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary="No classifier available for postgres.execute",
            )

        try:
            classification = classifier.classify("postgres.execute", payload)
        except ClassificationError as exc:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=f"Classification failed: {exc!s}",
            )

        # Check for opaque classification
        if classification.opaque:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary="SQL classification is opaque — requires explicit approval",
            )

        # Extract operation type from classification
        action_type = classification.action_type
        # Normalize: "postgres.execute.select" -> "select"
        operation = (
            action_type.rsplit(".", 1)[-1].lower() if "." in action_type else action_type.lower()
        )

        # Check forbidden operations
        if operation in FORBIDDEN_OPERATIONS:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=f"Operation '{operation}' is forbidden by the proxy",
            )

        # Check if operation is allowed
        is_ddl = operation in DDL_OPERATIONS
        is_dml = operation in ALLOWED_OPERATIONS
        if not is_ddl and not is_dml:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=f"Operation '{operation}' is not in the allowed SQL subset",
            )

        # For DDL, verify the token's tool field indicates DDL was authorized
        if is_ddl:
            # The token.tool should contain "ddl" or the specific DDL type
            if "ddl" not in token.tool.lower() and operation not in token.tool.lower():
                return ExecutionResult(
                    success=False,
                    exit_status="failure",
                    result_summary=f"DDL operation '{operation}' was not authorized (token tool: {token.tool})",
                )

        # Execute the SQL
        try:
            with self.target_engine.connect() as target_conn:
                # High fix 7: enforce statement and lock timeouts at the
                # database level. SET LOCAL applies only to the current
                # transaction and is automatically reset on COMMIT/ROLLBACK.
                # Only apply to PostgreSQL — SQLite does not support these.
                if self.target_engine.dialect.name != "sqlite":
                    target_conn.execute(
                        sa.text(
                            f"SET LOCAL statement_timeout = '{self.config.timeout_seconds * 1000}ms'"
                        )
                    )
                    target_conn.execute(sa.text("SET LOCAL lock_timeout = '5s'"))

                if operation == "select":
                    # High fix 11: bound result set to prevent memory exhaustion
                    result = target_conn.execute(sa.text(sql))
                    rows = result.fetchmany(1000)  # cap at 1000 rows
                    output = [dict(row._mapping) for row in rows]
                    target_conn.commit()
                    # Redact output before returning
                    output_str = self._redact(str(output))
                    return ExecutionResult(
                        success=True,
                        exit_status="success",
                        result_summary=f"SELECT returned {len(rows)} rows",
                        rows_affected=len(rows),
                        output=self._enforce_output_limit(output_str),
                        redacted=True,
                    )
                else:
                    result = target_conn.execute(sa.text(sql))
                    target_conn.commit()
                    return ExecutionResult(
                        success=True,
                        exit_status="success",
                        result_summary=f"{operation.upper()} affected {result.rowcount} rows",
                        rows_affected=result.rowcount,
                    )
        except Exception:
            # High fix 12: do not expose database error details
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary="SQL execution failed (check internal logs for details)",
            )

    def close(self) -> None:
        """Close the target database engine."""
        if self._target_engine is not None:
            self._target_engine.dispose()
            self._target_engine = None
