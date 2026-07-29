"""Action classification for EP-Governance.

This module provides classification stubs that determine the action type,
canonical resources, and risk domain for a proposed tool invocation.

Classifiers:
  - :class:`SQLClassifier`  — classifies SQL statements via sqlglot (with
    regex fallback) for ``postgres.execute``.
  - :class:`ShellClassifier` — classifies shell commands for ``shell.execute``.

Design principles:
  - Parser failures are treated as high-risk (opaque, requires_approval).
  - The classifiers do NOT claim complete semantic understanding of SQL
    or shell commands.  When in doubt, they err on the side of caution.
  - No network, no filesystem, no embeddings.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .errors import ClassificationError

__all__ = [
    "ClassificationConfidence",
    "ClassificationResult",
    "ActionClassifier",
    "SQLClassifier",
    "ShellClassifier",
    "get_classifier",
]


# --------------------------------------------------------------------------- #
# Enums and dataclasses
# --------------------------------------------------------------------------- #


class ClassificationConfidence(StrEnum):
    """Confidence level of the classification."""

    high = "high"
    medium = "medium"
    low = "low"


@dataclass
class ClassificationResult:
    """The result of classifying a tool invocation.

    Attributes:
        action_type:             The classified action type string
                                 (e.g. ``"postgres.execute.select"``).
        canonical_resources:     Canonical resource URIs extracted from arguments.
        risk_domain:             The risk domain string.
        classification_method:   How the classification was performed
                                 (e.g. ``"sqlglot"``, ``"regex_fallback"``, ``"shell_bounded"``).
        classification_confidence: Confidence level.
        opaque:                  ``True`` if the action could not be fully understood.
        requires_approval:       ``True`` if the action requires human approval.
    """

    action_type: str
    canonical_resources: list[str] = field(default_factory=list)
    risk_domain: str = ""
    classification_method: str = ""
    classification_confidence: ClassificationConfidence = ClassificationConfidence.medium
    opaque: bool = False
    requires_approval: bool = False


# --------------------------------------------------------------------------- #
# Base class
# --------------------------------------------------------------------------- #


class ActionClassifier:
    """Base class for action classifiers."""

    def classify(self, tool: str, arguments: dict[str, Any]) -> ClassificationResult:
        """Classify a tool invocation.

        Args:
            tool:      The tool name (e.g. ``"postgres.execute"``).
            arguments: The tool arguments.

        Returns:
            A :class:`ClassificationResult`.

        Raises:
            ClassificationError: If classification fails catastrophically.
        """
        raise NotImplementedError


# --------------------------------------------------------------------------- #
# SQL Classifier
# --------------------------------------------------------------------------- #

# Mapping of sqlglot expression types to action type suffixes.
_SQL_OPERATION_MAP: dict[str, str] = {
    "select": "select",
    "insert": "insert",
    "update": "update",
    "delete": "delete",
    "drop": "drop",
    "alter": "alter",
    "create": "create",
    "truncate": "truncate",
    "merge": "merge",
    "grant": "grant",
    "revoke": "revoke",
    "set": "set",
    "begin": "begin",
    "commit": "commit",
    "rollback": "rollback",
}

# Regex fallback patterns (ordered by specificity).
_SQL_REGEX_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^\s*select\b", re.IGNORECASE), "select"),
    (re.compile(r"^\s*insert\b", re.IGNORECASE), "insert"),
    (re.compile(r"^\s*update\b", re.IGNORECASE), "update"),
    (re.compile(r"^\s*delete\b", re.IGNORECASE), "delete"),
    (re.compile(r"^\s*drop\b", re.IGNORECASE), "drop"),
    (re.compile(r"^\s*alter\b", re.IGNORECASE), "alter"),
    (re.compile(r"^\s*create\b", re.IGNORECASE), "create"),
    (re.compile(r"^\s*truncate\b", re.IGNORECASE), "truncate"),
    (re.compile(r"^\s*merge\b", re.IGNORECASE), "merge"),
    (re.compile(r"^\s*grant\b", re.IGNORECASE), "grant"),
    (re.compile(r"^\s*revoke\b", re.IGNORECASE), "revoke"),
    (re.compile(r"^\s*set\b", re.IGNORECASE), "set"),
    (re.compile(r"^\s*begin\b", re.IGNORECASE), "begin"),
    (re.compile(r"^\s*commit\b", re.IGNORECASE), "commit"),
    (re.compile(r"^\s*rollback\b", re.IGNORECASE), "rollback"),
]


def _detect_multi_statement(sql: str) -> bool:
    """Detect whether *sql* contains multiple statements (heuristic)."""
    # Remove string literals to avoid false positives from semicolons in strings.
    stripped = re.sub(r"'(?:[^']|'')*'", "''", sql)
    stripped = re.sub(r'"(?:[^"]|"")*"', '""', stripped)
    # A semicolon followed by non-trailing content indicates multi-statement.
    return ";" in stripped.rstrip().rstrip(";").strip()


class SQLClassifier(ActionClassifier):
    """Classifies SQL statements.

    Uses :mod:`sqlglot` when available for precise parsing.  Falls back to
    regex classification with medium confidence when sqlglot is not installed.

    Parser failures are treated as high-risk (opaque=True, requires_approval=True).
    """

    def classify(self, tool: str, arguments: dict[str, Any]) -> ClassificationResult:
        sql: str | None = arguments.get("sql") or arguments.get("query")
        if not sql:
            raise ClassificationError("SQL classifier requires 'sql' or 'query' argument")

        # Detect multi-statement payloads
        multi_statement = _detect_multi_statement(sql)

        if multi_statement:
            return ClassificationResult(
                action_type="postgres.execute.multi",
                canonical_resources=[],
                risk_domain="production_database",
                classification_method="multi_statement_detection",
                classification_confidence=ClassificationConfidence.high,
                opaque=True,
                requires_approval=True,
            )

        # Try sqlglot first
        try:
            import sqlglot  # type: ignore[import-untyped]
        except ImportError:
            sqlglot = None  # type: ignore[assignment]

        if sqlglot is not None:
            try:
                return self._classify_with_sqlglot(sql, sqlglot)
            except ClassificationError:
                raise
            except Exception:
                # Parser failure → high risk
                return ClassificationResult(
                    action_type="postgres.execute.opaque",
                    canonical_resources=[],
                    risk_domain="production_database",
                    classification_method="sqlglot_parse_failure",
                    classification_confidence=ClassificationConfidence.high,
                    opaque=True,
                    requires_approval=True,
                )
        else:
            return self._classify_with_regex(sql)

    # ------------------------------------------------------------------ #

    def _classify_with_sqlglot(self, sql: str, sqlglot: Any) -> ClassificationResult:
        """Classify using sqlglot parsing."""
        parsed = sqlglot.parse(sql)
        if not parsed or len(parsed) == 0:
            return ClassificationResult(
                action_type="postgres.execute.opaque",
                canonical_resources=[],
                risk_domain="production_database",
                classification_method="sqlglot_empty",
                classification_confidence=ClassificationConfidence.high,
                opaque=True,
                requires_approval=True,
            )

        if len(parsed) > 1:
            return ClassificationResult(
                action_type="postgres.execute.multi",
                canonical_resources=[],
                risk_domain="production_database",
                classification_method="sqlglot_multi_statement",
                classification_confidence=ClassificationConfidence.high,
                opaque=True,
                requires_approval=True,
            )

        stmt = parsed[0]
        stmt_type = type(stmt).__name__.lower()

        # Map sqlglot expression class to operation
        operation: str | None = None
        for key, op in _SQL_OPERATION_MAP.items():
            if key in stmt_type:
                operation = op
                break

        if operation is None:
            return ClassificationResult(
                action_type="postgres.execute.opaque",
                canonical_resources=[],
                risk_domain="production_database",
                classification_method="sqlglot_unknown_type",
                classification_confidence=ClassificationConfidence.high,
                opaque=True,
                requires_approval=True,
            )

        # Extract target tables
        canonical_resources = self._extract_tables_sqlglot(stmt, sqlglot)

        action_type = f"postgres.execute.{operation}"
        requires_approval = operation not in ("select",)

        return ClassificationResult(
            action_type=action_type,
            canonical_resources=canonical_resources,
            risk_domain="production_database",
            classification_method="sqlglot",
            classification_confidence=ClassificationConfidence.high,
            opaque=False,
            requires_approval=requires_approval,
        )

    def _extract_tables_sqlglot(self, stmt: Any, sqlglot: Any) -> list[str]:
        """Extract canonical resource URIs from the parsed statement."""
        resources: list[str] = []
        seen: set[str] = set()

        # sqlglot exposes .find_all() for expression types
        try:
            table_exprs = list(stmt.find_all(sqlglot.exp.Table))
        except Exception:
            table_exprs = []

        # Also try to get the schema/database from the connection arguments
        # (handled outside; here we just build from the parsed tables)
        for tbl in table_exprs:
            try:
                db = tbl.db
                schema = None
                name = tbl.name

                # tbl.db can be a Schema or a Table qualifier
                if hasattr(db, "name"):
                    schema = db.name
                    db_name = db.db.name if hasattr(db, "db") and hasattr(db.db, "name") else None
                else:
                    db_name = str(db) if db else None

                parts: list[str] = []
                if db_name:
                    parts.append(db_name.lower())
                if schema:
                    parts.append(schema.lower())
                if name:
                    parts.append(name.lower())

                if parts:
                    uri = f"postgres://localhost/{'/'.join(parts)}"
                    if uri not in seen:
                        seen.add(uri)
                        resources.append(uri)
            except Exception:
                continue

        return resources

    def _classify_with_regex(self, sql: str) -> ClassificationResult:
        """Fallback regex classification with medium confidence."""
        for pattern, op in _SQL_REGEX_PATTERNS:
            if pattern.match(sql):
                action_type = f"postgres.execute.{op}"
                requires_approval = op not in ("select",)
                return ClassificationResult(
                    action_type=action_type,
                    canonical_resources=[],
                    risk_domain="production_database",
                    classification_method="regex_fallback",
                    classification_confidence=ClassificationConfidence.medium,
                    opaque=False,
                    requires_approval=requires_approval,
                )

        # Unknown SQL
        return ClassificationResult(
            action_type="postgres.execute.opaque",
            canonical_resources=[],
            risk_domain="production_database",
            classification_method="regex_fallback_unknown",
            classification_confidence=ClassificationConfidence.medium,
            opaque=True,
            requires_approval=True,
        )


# --------------------------------------------------------------------------- #
# Shell Classifier
# --------------------------------------------------------------------------- #

# Known bounded commands that are safe to classify with high confidence.
_BOUNDED_COMMANDS: frozenset[str] = frozenset(
    {"ls", "cat", "echo", "pwd", "whoami", "date", "uptime"}
)

# Dangerous patterns that indicate opaque/unbounded execution.
_DANGEROUS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\$\("),  # Command substitution
    re.compile(r"`"),  # Backtick command substitution
    re.compile(r"\beval\b", re.IGNORECASE),  # eval
    re.compile(r"\bexec\b", re.IGNORECASE),  # exec
    re.compile(r"\bsh\b"),  # interpreter invocation
    re.compile(r"\bbash\b"),  # interpreter invocation
    re.compile(r"\bpython\b", re.IGNORECASE),  # interpreter
    re.compile(r"\bperl\b", re.IGNORECASE),  # interpreter
    re.compile(r"\bruby\b", re.IGNORECASE),  # interpreter
    re.compile(r"\bnode\b", re.IGNORECASE),  # interpreter
    re.compile(r"\bwget\b", re.IGNORECASE),  # network fetch
    re.compile(r"\bcurl\b", re.IGNORECASE),  # network fetch
    re.compile(r"\bchmod\b", re.IGNORECASE),  # permission change
    re.compile(r"\bchown\b", re.IGNORECASE),  # ownership change
    re.compile(r"\brm\b"),  # file deletion
    re.compile(r"\bmv\b"),  # file move
    re.compile(r"\bcp\b"),  # file copy (can be dangerous)
    re.compile(r"\bmkfs\b", re.IGNORECASE),  # filesystem format
    re.compile(r"\bdd\b", re.IGNORECASE),  # disk dump
    re.compile(r"\bsudo\b", re.IGNORECASE),  # privilege escalation
    re.compile(r"\bsu\b", re.IGNORECASE),  # user switch
    re.compile(r"\bpip\b", re.IGNORECASE),  # package install
    re.compile(r"\bapt\b", re.IGNORECASE),  # package install
    re.compile(r"\byum\b", re.IGNORECASE),  # package install
    re.compile(r"\bbrew\b", re.IGNORECASE),  # package install
    re.compile(r"\bbase64\b", re.IGNORECASE),  # encoded payload
    re.compile(r"\bdecode\b", re.IGNORECASE),  # encoded payload
    re.compile(r"\bopenssl\b", re.IGNORECASE),  # crypto/encoded payload
    re.compile(r"\bnc\b"),  # netcat
    re.compile(r"\bnetcat\b"),  # netcat
    re.compile(r"\bsshd\b", re.IGNORECASE),  # ssh daemon
    re.compile(r"\bsystemctl\b", re.IGNORECASE),  # service management
    re.compile(r"\bservice\b", re.IGNORECASE),  # service management
    re.compile(r"\bkill\b", re.IGNORECASE),  # process kill
    re.compile(r"\bpkill\b", re.IGNORECASE),  # process kill
    re.compile(r"\bkillall\b", re.IGNORECASE),  # process kill
    re.compile(r"\breboot\b", re.IGNORECASE),  # system control
    re.compile(r"\bshutdown\b", re.IGNORECASE),  # system control
    re.compile(r"\bhalt\b", re.IGNORECASE),  # system control
]

# Encoded payload patterns
_ENCODED_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"base64\s+decode", re.IGNORECASE),
    re.compile(r"\| base64\b", re.IGNORECASE),
    re.compile(r"\| base32\b", re.IGNORECASE),
    re.compile(r"\| xxd\b", re.IGNORECASE),
    re.compile(r"\| od\b", re.IGNORECASE),
]


class ShellClassifier(ActionClassifier):
    """Classifies shell commands.

    Known bounded commands (ls, cat, echo, pwd, whoami, date, uptime) are
    classified with high confidence.  Scripts, interpreters, encoded
    payloads, command substitution, eval, and unknown commands are
    classified as ``shell.exec.opaque`` (opaque=True, requires_approval=True,
    confidence=low).

    This classifier does NOT claim complete semantic understanding.
    """

    def classify(self, tool: str, arguments: dict[str, Any]) -> ClassificationResult:
        command: str | None = (
            arguments.get("command") or arguments.get("cmd") or arguments.get("script")
        )
        if not command:
            raise ClassificationError(
                "Shell classifier requires 'command', 'cmd', or 'script' argument"
            )

        # Check for dangerous patterns first
        for pattern in _DANGEROUS_PATTERNS:
            if pattern.search(command):
                return ClassificationResult(
                    action_type="shell.exec.opaque",
                    canonical_resources=[],
                    risk_domain="security",
                    classification_method="shell_dangerous_pattern",
                    classification_confidence=ClassificationConfidence.low,
                    opaque=True,
                    requires_approval=True,
                )

        # Check for encoded payloads
        for pattern in _ENCODED_PATTERNS:
            if pattern.search(command):
                return ClassificationResult(
                    action_type="shell.exec.opaque",
                    canonical_resources=[],
                    risk_domain="security",
                    classification_method="shell_encoded_payload",
                    classification_confidence=ClassificationConfidence.low,
                    opaque=True,
                    requires_approval=True,
                )

        # Check for multi-command separators (pipes, &&, ||, ;)
        # These indicate compound commands which we classify as opaque.
        if re.search(r"[|&;]", command):
            # But allow simple pipes for bounded commands? No — be conservative.
            return ClassificationResult(
                action_type="shell.exec.opaque",
                canonical_resources=[],
                risk_domain="security",
                classification_method="shell_compound_command",
                classification_confidence=ClassificationConfidence.low,
                opaque=True,
                requires_approval=True,
            )

        # Try to parse the command
        try:
            parts = shlex.split(command)
        except ValueError:
            # Unparseable — opaque
            return ClassificationResult(
                action_type="shell.exec.opaque",
                canonical_resources=[],
                risk_domain="security",
                classification_method="shell_parse_failure",
                classification_confidence=ClassificationConfidence.low,
                opaque=True,
                requires_approval=True,
            )

        if not parts:
            return ClassificationResult(
                action_type="shell.exec.opaque",
                canonical_resources=[],
                risk_domain="security",
                classification_method="shell_empty",
                classification_confidence=ClassificationConfidence.low,
                opaque=True,
                requires_approval=True,
            )

        base_cmd = parts[0].lower()
        # Strip path prefix (e.g. /bin/ls → ls)
        base_cmd = base_cmd.rsplit("/", 1)[-1]

        if base_cmd in _BOUNDED_COMMANDS:
            return ClassificationResult(
                action_type=f"shell.exec.{base_cmd}",
                canonical_resources=[],
                risk_domain="security",
                classification_method="shell_bounded",
                classification_confidence=ClassificationConfidence.high,
                opaque=False,
                requires_approval=False,
            )

        # Unknown command → opaque
        return ClassificationResult(
            action_type="shell.exec.opaque",
            canonical_resources=[],
            risk_domain="security",
            classification_method="shell_unknown_command",
            classification_confidence=ClassificationConfidence.low,
            opaque=True,
            requires_approval=True,
        )


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #

_TOOL_CLASSIFIERS: dict[str, type[ActionClassifier]] = {
    "postgres.execute": SQLClassifier,
    "shell.execute": ShellClassifier,
}


def get_classifier(tool: str) -> ActionClassifier | None:
    """Return the appropriate classifier for *tool*, or ``None``.

    Args:
        tool: The tool name (e.g. ``"postgres.execute"``).

    Returns:
        An :class:`ActionClassifier` instance, or ``None`` if no classifier
        is registered for *tool*.
    """
    cls = _TOOL_CLASSIFIERS.get(tool)
    if cls is None:
        return None
    return cls()
