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
        conn: Any,
        auth_engine: Any,
        config: ProxyConfig,
    ) -> None:
        super().__init__(conn, auth_engine, config)
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
                if operation == "select":
                    result = target_conn.execute(sa.text(sql))
                    rows = result.fetchall()
                    columns = list(result.keys()) if rows else []
                    output = [dict(row._mapping) for row in rows]
                    target_conn.commit()
                    return ExecutionResult(
                        success=True,
                        exit_status="success",
                        result_summary=f"SELECT returned {len(rows)} rows",
                        rows_affected=len(rows),
                        output=self._enforce_output_limit(str(output)),
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
        except Exception as exc:
            return ExecutionResult(
                success=False,
                exit_status="failure",
                result_summary=f"SQL execution error: {exc!s}",
            )

    def close(self) -> None:
        """Close the target database engine."""
        if self._target_engine is not None:
            self._target_engine.dispose()
            self._target_engine = None
