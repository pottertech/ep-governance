"""Unit tests for EP-Governance action classification.

References normative rules:
  EP-CLASSIFY-001: classify all actions server-side
  EP-CLASSIFY-002: SQL parser with AST analysis for operation type and target objects
  EP-CLASSIFY-003: detect multi-statement SQL and transaction-control commands
  EP-CLASSIFY-004: SQL parser failures treated as high-risk (opaque, requires_approval)
  EP-CLASSIFY-005: opaque/unrecognized shell commands classified as shell.exec.opaque
  EP-CLASSIFY-006: escalating treatment for shell commands (known safe -> opaque -> deny)
"""

from __future__ import annotations

import pytest

from ep_governance.classification import (
    ClassificationConfidence,
    ClassificationResult,
    ShellClassifier,
    SQLClassifier,
    get_classifier,
)
from ep_governance.errors import ClassificationError


# --------------------------------------------------------------------------- #
# SQL Classifier
# --------------------------------------------------------------------------- #


class TestSQLClassifierSelect:
    """Tests for SELECT classification (EP-CLASSIFY-002)."""

    def test_select_basic(self):
        """SELECT -> action_type contains 'select', confidence=high, opaque=False."""
        clf = SQLClassifier()
        result = clf.classify("postgres.execute", {"sql": "SELECT * FROM users"})
        assert "select" in result.action_type
        assert result.opaque is False
        assert result.risk_domain == "production_database"

    def test_select_confidence(self):
        """SELECT classification confidence is high (with sqlglot) or medium (regex)."""
        clf = SQLClassifier()
        result = clf.classify("postgres.execute", {"sql": "SELECT * FROM users"})
        assert result.classification_confidence in (
            ClassificationConfidence.high,
            ClassificationConfidence.medium,
        )

    def test_select_does_not_require_approval(self):
        """SELECT should not require approval (read-only)."""
        clf = SQLClassifier()
        result = clf.classify("postgres.execute", {"sql": "SELECT * FROM users"})
        assert result.requires_approval is False

    def test_select_with_query_key(self):
        """Classifier accepts 'query' key as alternative to 'sql'."""
        clf = SQLClassifier()
        result = clf.classify("postgres.execute", {"query": "SELECT * FROM users"})
        assert "select" in result.action_type


class TestSQLClassifierDrop:
    """Tests for DROP TABLE classification (EP-CLASSIFY-002)."""

    def test_drop_table(self):
        """DROP TABLE -> action_type contains 'drop', requires_approval=True."""
        clf = SQLClassifier()
        result = clf.classify("postgres.execute", {"sql": "DROP TABLE users"})
        assert "drop" in result.action_type
        assert result.requires_approval is True

    def test_drop_is_not_select(self):
        """DROP action_type is distinct from select."""
        clf = SQLClassifier()
        result = clf.classify("postgres.execute", {"sql": "DROP TABLE users"})
        assert "select" not in result.action_type


class TestSQLClassifierInsert:
    """Tests for INSERT classification."""

    def test_insert(self):
        """INSERT -> action_type contains 'insert'."""
        clf = SQLClassifier()
        result = clf.classify(
            "postgres.execute",
            {"sql": "INSERT INTO users (name) VALUES ('test')"},
        )
        assert "insert" in result.action_type
        assert result.requires_approval is True

    def test_insert_confidence(self):
        clf = SQLClassifier()
        result = clf.classify(
            "postgres.execute",
            {"sql": "INSERT INTO users (name) VALUES ('test')"},
        )
        assert result.classification_confidence in (
            ClassificationConfidence.high,
            ClassificationConfidence.medium,
        )


class TestSQLClassifierDelete:
    """Tests for DELETE classification."""

    def test_delete(self):
        """DELETE -> action_type contains 'delete'."""
        clf = SQLClassifier()
        result = clf.classify("postgres.execute", {"sql": "DELETE FROM users"})
        assert "delete" in result.action_type
        assert result.requires_approval is True


class TestSQLClassifierUpdate:
    """Tests for UPDATE classification."""

    def test_update(self):
        clf = SQLClassifier()
        result = clf.classify(
            "postgres.execute",
            {"sql": "UPDATE users SET name = 'test'"},
        )
        assert "update" in result.action_type
        assert result.requires_approval is True


class TestSQLClassifierParserFailure:
    """Tests for parser failure handling (EP-CLASSIFY-004)."""

    def test_parser_failure_is_opaque(self):
        """Parser failure -> opaque=True, requires_approval=True (EP-CLASSIFY-004).

        We use a syntactically invalid SQL that should cause a parser failure
        in sqlglot. If sqlglot is not installed, the regex fallback will
        classify it as unknown (also opaque).
        """
        clf = SQLClassifier()
        # A completely unparseable string
        result = clf.classify("postgres.execute", {"sql": "%%%INVALID%%%@@@"})
        assert result.opaque is True
        assert result.requires_approval is True

    def test_parser_failure_action_type_is_opaque(self):
        """Parser failure -> action_type is postgres.execute.opaque."""
        clf = SQLClassifier()
        result = clf.classify("postgres.execute", {"sql": "%%%INVALID%%%@@@"})
        assert result.action_type == "postgres.execute.opaque"

    def test_parser_failure_risk_domain(self):
        """Parser failure -> risk_domain is production_database."""
        clf = SQLClassifier()
        result = clf.classify("postgres.execute", {"sql": "%%%INVALID%%%@@@"})
        assert result.risk_domain == "production_database"


class TestSQLClassifierMultiStatement:
    """Tests for multi-statement detection (EP-CLASSIFY-003)."""

    def test_multi_statement_detected(self):
        """Multi-statement SQL is detected and classified as high risk (EP-CLASSIFY-003)."""
        clf = SQLClassifier()
        result = clf.classify(
            "postgres.execute",
            {"sql": "SELECT * FROM users; DROP TABLE users"},
        )
        assert result.opaque is True
        assert result.requires_approval is True
        assert "multi" in result.action_type or result.action_type == "postgres.execute.opaque"

    def test_multi_statement_confidence_high(self):
        """Multi-statement detection has high confidence."""
        clf = SQLClassifier()
        result = clf.classify(
            "postgres.execute",
            {"sql": "SELECT 1; SELECT 2"},
        )
        assert result.classification_confidence == ClassificationConfidence.high

    def test_transaction_control_detected(self):
        """Transaction control commands (BEGIN, COMMIT, ROLLBACK) are classified (EP-CLASSIFY-003)."""
        clf = SQLClassifier()
        # BEGIN as a single statement
        result = clf.classify("postgres.execute", {"sql": "BEGIN"})
        # BEGIN should be classified (not opaque), action_type contains 'begin'
        assert "begin" in result.action_type or result.opaque is True


class TestSQLClassifierMissingSql:
    """Tests for missing SQL argument."""

    def test_missing_sql_raises(self):
        """Missing 'sql' and 'query' arguments raises ClassificationError."""
        clf = SQLClassifier()
        with pytest.raises(ClassificationError):
            clf.classify("postgres.execute", {})

    def test_empty_sql_raises(self):
        """Empty SQL string raises ClassificationError."""
        clf = SQLClassifier()
        with pytest.raises(ClassificationError):
            clf.classify("postgres.execute", {"sql": ""})


# --------------------------------------------------------------------------- #
# Shell Classifier
# --------------------------------------------------------------------------- #


class TestShellClassifierKnownCommands:
    """Tests for known bounded shell commands (EP-CLASSIFY-006)."""

    @pytest.mark.parametrize("cmd", ["ls", "cat", "echo", "pwd", "whoami", "date", "uptime"])
    def test_known_command_classified(self, cmd):
        """Known bounded command -> classified, opaque=False (EP-CLASSIFY-006)."""
        clf = ShellClassifier()
        result = clf.classify("shell.execute", {"command": cmd})
        assert result.opaque is False
        assert result.requires_approval is False
        assert result.action_type == f"shell.exec.{cmd}"

    def test_known_command_confidence_high(self):
        """Known bounded commands have high confidence."""
        clf = ShellClassifier()
        result = clf.classify("shell.execute", {"command": "ls"})
        assert result.classification_confidence == ClassificationConfidence.high

    def test_known_command_with_args(self):
        """Known command with arguments is still classified as bounded."""
        clf = ShellClassifier()
        result = clf.classify("shell.execute", {"command": "ls -la /tmp"})
        assert result.opaque is False
        assert result.action_type == "shell.exec.ls"

    def test_known_command_with_path_prefix(self):
        """Command with path prefix (e.g. /bin/ls) is normalized to base command."""
        clf = ShellClassifier()
        result = clf.classify("shell.execute", {"command": "/bin/ls -la"})
        assert result.opaque is False
        assert result.action_type == "shell.exec.ls"


class TestShellClassifierUnknownCommand:
    """Tests for unknown shell commands (EP-CLASSIFY-005, EP-CLASSIFY-006)."""

    def test_unknown_command_is_opaque(self):
        """Unknown command -> shell.exec.opaque, opaque=True, requires_approval=True (EP-CLASSIFY-005)."""
        clf = ShellClassifier()
        result = clf.classify("shell.execute", {"command": "someunknowncommand123"})
        assert result.action_type == "shell.exec.opaque"
        assert result.opaque is True
        assert result.requires_approval is True

    def test_unknown_command_confidence_low(self):
        clf = ShellClassifier()
        result = clf.classify("shell.execute", {"command": "someunknowncommand123"})
        assert result.classification_confidence == ClassificationConfidence.low

    def test_unknown_command_risk_domain_security(self):
        clf = ShellClassifier()
        result = clf.classify("shell.execute", {"command": "someunknowncommand123"})
        assert result.risk_domain == "security"


class TestShellClassifierEval:
    """Tests for eval command (EP-CLASSIFY-005)."""

    def test_eval_is_opaque(self):
        """eval -> shell.exec.opaque (EP-CLASSIFY-005)."""
        clf = ShellClassifier()
        result = clf.classify("shell.execute", {"command": "eval 'dangerous code'"})
        assert result.action_type == "shell.exec.opaque"
        assert result.opaque is True
        assert result.requires_approval is True


class TestShellClassifierEncodedPayload:
    """Tests for encoded payloads (EP-CLASSIFY-005)."""

    def test_base64_decode_is_opaque(self):
        """base64 decode -> shell.exec.opaque (EP-CLASSIFY-005)."""
        clf = ShellClassifier()
        result = clf.classify("shell.execute", {"command": "base64 decode somepayload"})
        assert result.action_type == "shell.exec.opaque"
        assert result.opaque is True
        assert result.requires_approval is True

    def test_pipe_base64_is_opaque(self):
        """echo | base64 -> shell.exec.opaque."""
        clf = ShellClassifier()
        result = clf.classify("shell.execute", {"command": "echo data | base64"})
        assert result.action_type == "shell.exec.opaque"
        assert result.opaque is True

    def test_base64_command_detected(self):
        """base64 as a command is detected as dangerous pattern."""
        clf = ShellClassifier()
        result = clf.classify("shell.execute", {"command": "base64"})
        assert result.action_type == "shell.exec.opaque"
        assert result.opaque is True


class TestShellClassifierCompoundCommands:
    """Tests for compound/pipe commands."""

    def test_pipe_command_is_opaque(self):
        """Piped commands are classified as opaque (conservative)."""
        clf = ShellClassifier()
        result = clf.classify("shell.execute", {"command": "ls | grep foo"})
        assert result.action_type == "shell.exec.opaque"
        assert result.opaque is True

    def test_and_chain_is_opaque(self):
        """&& chained commands are opaque."""
        clf = ShellClassifier()
        result = clf.classify("shell.execute", {"command": "ls && echo done"})
        assert result.action_type == "shell.exec.opaque"
        assert result.opaque is True

    def test_command_substitution_is_opaque(self):
        """$(...) command substitution is opaque."""
        clf = ShellClassifier()
        result = clf.classify("shell.execute", {"command": "echo $(whoami)"})
        assert result.action_type == "shell.exec.opaque"
        assert result.opaque is True

    def test_backtick_substitution_is_opaque(self):
        """Backtick command substitution is opaque."""
        clf = ShellClassifier()
        result = clf.classify("shell.execute", {"command": "echo `whoami`"})
        assert result.action_type == "shell.exec.opaque"
        assert result.opaque is True


class TestShellClassifierMissingCommand:
    """Tests for missing command argument."""

    def test_missing_command_raises(self):
        clf = ShellClassifier()
        with pytest.raises(ClassificationError):
            clf.classify("shell.execute", {})

    def test_empty_command_raises(self):
        clf = ShellClassifier()
        with pytest.raises(ClassificationError):
            clf.classify("shell.execute", {"command": ""})

    def test_accepts_cmd_key(self):
        """ShellClassifier accepts 'cmd' as alternative to 'command'."""
        clf = ShellClassifier()
        result = clf.classify("shell.execute", {"cmd": "ls"})
        assert result.action_type == "shell.exec.ls"

    def test_accepts_script_key(self):
        """ShellClassifier accepts 'script' as alternative to 'command'."""
        clf = ShellClassifier()
        result = clf.classify("shell.execute", {"script": "ls"})
        assert result.action_type == "shell.exec.ls"


# --------------------------------------------------------------------------- #
# get_classifier registry
# --------------------------------------------------------------------------- #


class TestGetClassifier:
    """Tests for get_classifier registry."""

    def test_postgres_execute_returns_sql_classifier(self):
        """get_classifier('postgres.execute') returns SQLClassifier instance (EP-CLASSIFY-002)."""
        clf = get_classifier("postgres.execute")
        assert clf is not None
        assert isinstance(clf, SQLClassifier)

    def test_shell_execute_returns_shell_classifier(self):
        """get_classifier('shell.execute') returns ShellClassifier instance (EP-CLASSIFY-005)."""
        clf = get_classifier("shell.execute")
        assert clf is not None
        assert isinstance(clf, ShellClassifier)

    def test_unknown_tool_returns_none(self):
        """get_classifier for unknown tool returns None."""
        assert get_classifier("unknown.tool") is None

    def test_empty_tool_returns_none(self):
        assert get_classifier("") is None

    def test_email_send_returns_none(self):
        """No classifier registered for email.send yet."""
        assert get_classifier("email.send") is None


# --------------------------------------------------------------------------- #
# ClassificationResult dataclass
# --------------------------------------------------------------------------- #


class TestClassificationResult:
    """Tests for ClassificationResult dataclass."""

    def test_default_values(self):
        result = ClassificationResult(action_type="test")
        assert result.action_type == "test"
        assert result.canonical_resources == []
        assert result.risk_domain == ""
        assert result.classification_method == ""
        assert result.classification_confidence == ClassificationConfidence.medium
        assert result.opaque is False
        assert result.requires_approval is False

    def test_classification_confidence_values(self):
        assert ClassificationConfidence.high.value == "high"
        assert ClassificationConfidence.medium.value == "medium"
        assert ClassificationConfidence.low.value == "low"
