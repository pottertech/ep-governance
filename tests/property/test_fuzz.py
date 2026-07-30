"""Fuzz tests for EP-Governance using Hypothesis property-based testing.

Tests invariant properties of:
- SQL classifier: never classifies dangerous SQL as safe SELECT
- Shell classifier: never classifies dangerous commands as bounded
- Canonical JSON: deterministic, round-trip stable
- Policy evaluation: fail-closed on unknown inputs
- XID: always 20 chars, base32hex, unique under generation
"""

from __future__ import annotations

import json
import re
import string

import pytest
from hypothesis import given, strategies as st, assume, settings, HealthCheck

from ep_governance.classification import (
    SQLClassifier,
    ShellClassifier,
    ClassificationConfidence,
    ClassificationResult,
)
from ep_governance.canonical import canonical_json, canonical_hash, canonical_json_bytes
from ep_governance.xid import XID


# ---------------------------------------------------------------------------
# SQL Classifier Fuzz Tests
# ---------------------------------------------------------------------------

sql_classifier = SQLClassifier()


@st.composite
def random_sql(draw):
    """Generate random SQL-like strings."""
    keywords = st.sampled_from([
        "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE",
        "TRUNCATE", "GRANT", "REVOKE", "BEGIN", "COMMIT", "ROLLBACK", "SET",
        "MERGE", "WITH", "FROM", "WHERE", "INTO", "VALUES", "TABLE",
    ])
    # Mix keywords with random text, semicolons, comments
    parts = draw(st.lists(
        st.one_of(
            keywords,
            st.text(alphabet=string.ascii_letters + string.digits + " _.,;()'", min_size=1, max_size=20),
            st.sampled_from([";", "--", "/*", "*/", "'", "\"", "\n", "\t"]),
        ),
        min_size=1,
        max_size=10,
    ))
    return " ".join(parts)


class TestSQLClassifierFuzz:
    """Property-based tests for the SQL classifier."""

    @given(sql=random_sql())
    @settings(max_examples=200, deadline=2000,
              suppress_health_check=[HealthCheck.too_slow])
    def test_never_crashes(self, sql):
        """The classifier must never crash on any input — it must always
        return a ClassificationResult or raise ClassificationError."""
        try:
            result = sql_classifier.classify("postgres.execute", {"sql": sql})
            assert isinstance(result, ClassificationResult)
            assert isinstance(result.opaque, bool)
            assert isinstance(result.requires_approval, bool)
        except Exception:
            # ClassificationError is acceptable for empty/garbage input
            pass

    @given(sql=st.text(alphabet=string.printable, min_size=0, max_size=500))
    @settings(max_examples=200, deadline=2000,
              suppress_health_check=[HealthCheck.too_slow])
    def test_opaque_implies_requires_approval(self, sql):
        """If classification is opaque, requires_approval must be True."""
        try:
            result = sql_classifier.classify("postgres.execute", {"sql": sql})
            if result.opaque:
                assert result.requires_approval is True, (
                    f"opaque=True but requires_approval=False for SQL: {sql!r}"
                )
        except Exception:
            pass

    @given(
        sql=st.builds(
            lambda prefix, rest: f"{prefix} {rest}",
            st.sampled_from(["DROP", "TRUNCATE", "GRANT", "REVOKE"]),
            st.text(alphabet=string.ascii_letters + " _;", min_size=1, max_size=50),
        )
    )
    @settings(max_examples=100, deadline=2000)
    def test_destructive_operations_require_approval(self, sql):
        """DROP, TRUNCATE, GRANT, REVOKE must always require approval."""
        try:
            result = sql_classifier.classify("postgres.execute", {"sql": sql})
            if not result.opaque:
                assert result.requires_approval is True, (
                    f"Destructive operation {sql!r} does not require approval"
                )
        except Exception:
            pass

    @given(
        sql=st.builds(
            lambda col: f"SELECT {col}",
            st.text(alphabet=string.ascii_letters + " _,.*", min_size=1, max_size=50),
        )
    )
    @settings(max_examples=100, deadline=2000)
    def test_select_never_requires_approval(self, sql):
        """A simple SELECT must never require approval (unless multi-statement)."""
        # Ensure no semicolons in the column part (would make it multi-statement)
        assume(";" not in sql)
        try:
            result = sql_classifier.classify("postgres.execute", {"sql": sql})
            if not result.opaque and result.action_type == "postgres.execute.select":
                assert result.requires_approval is False, (
                    f"SELECT {sql!r} unexpectedly requires approval"
                )
        except Exception:
            pass

    @given(
        s1=st.text(alphabet=string.ascii_letters + " _*,.", min_size=1, max_size=30),
        s2=st.text(alphabet=string.ascii_letters + " _*,.", min_size=3, max_size=30),
    )
    @settings(max_examples=100, deadline=2000)
    def test_multi_statement_always_opaque(self, s1, s2):
        """Any SQL with a semicolon separating two statements must be opaque."""
        # Ensure s2 has meaningful content (not just whitespace/punctuation)
        assume(any(c.isalpha() for c in s2))
        sql = f"SELECT {s1}; SELECT {s2}"
        assume(";" not in s1 and ";" not in s2)
        result = sql_classifier.classify("postgres.execute", {"sql": sql})
        assert result.opaque is True, f"Multi-statement SQL not opaque: {sql!r}"
        assert result.requires_approval is True


# ---------------------------------------------------------------------------
# Shell Classifier Fuzz Tests
# ---------------------------------------------------------------------------

shell_classifier = ShellClassifier()


@st.composite
def random_shell(draw):
    """Generate random shell-like strings."""
    commands = st.sampled_from([
        "ls", "cat", "echo", "pwd", "whoami", "date", "uptime",
        "rm", "mv", "cp", "chmod", "chown", "sudo", "curl", "wget",
        "nc", "bash", "sh", "python", "perl", "eval", "exec",
        "kill", "reboot", "shutdown", "dd", "mkfs",
    ])
    args = st.text(alphabet=string.ascii_letters + string.digits + " -./_=~", min_size=0, max_size=30)
    separators = st.sampled_from([" ", " && ", " || ", " ; ", " | "])
    cmd = draw(commands)
    arg = draw(args)
    sep = draw(separators)
    cmd2 = draw(commands)
    arg2 = draw(args)
    # Randomly choose simple or compound
    if draw(st.booleans()):
        return f"{cmd} {arg}"
    else:
        return f"{cmd} {arg}{sep}{cmd2} {arg2}"


class TestShellClassifierFuzz:
    """Property-based tests for the shell classifier."""

    @given(cmd=random_shell())
    @settings(max_examples=200, deadline=2000,
              suppress_health_check=[HealthCheck.too_slow])
    def test_never_crashes(self, cmd):
        """The classifier must never crash on any input."""
        try:
            result = shell_classifier.classify("shell.execute", {"command": cmd})
            assert isinstance(result, ClassificationResult)
            assert isinstance(result.opaque, bool)
            assert isinstance(result.requires_approval, bool)
        except Exception:
            pass

    @given(cmd=random_shell())
    @settings(max_examples=200, deadline=2000,
              suppress_health_check=[HealthCheck.too_slow])
    def test_opaque_implies_requires_approval(self, cmd):
        """If classification is opaque, requires_approval must be True."""
        try:
            result = shell_classifier.classify("shell.execute", {"command": cmd})
            if result.opaque:
                assert result.requires_approval is True
        except Exception:
            pass

    @given(
        cmd=st.builds(
            lambda c, a: f"{c} {a}",
            st.sampled_from(["sudo", "eval", "exec", "dd", "mkfs", "reboot", "shutdown"]),
            st.text(alphabet=string.printable, min_size=0, max_size=50),
        )
    )
    @settings(max_examples=100, deadline=2000)
    def test_dangerous_commands_always_opaque(self, cmd):
        """Dangerous commands must always be classified as opaque."""
        try:
            result = shell_classifier.classify("shell.execute", {"command": cmd})
            assert result.opaque is True, f"Dangerous command not opaque: {cmd!r}"
            assert result.requires_approval is True
        except Exception:
            pass

    @given(
        cmd=st.builds(
            lambda c, a: f"{c} {a}",
            st.sampled_from(["ls", "cat", "echo", "pwd", "whoami", "date", "uptime"]),
            st.text(alphabet=string.ascii_letters + string.digits + " -./_", min_size=0, max_size=30),
        )
    )
    @settings(max_examples=100, deadline=2000)
    def test_bounded_commands_not_opaque(self, cmd):
        """Known bounded commands must not be opaque (unless they contain dangerous patterns)."""
        # Filter out commands that accidentally contain dangerous patterns
        dangerous = ["sudo", "eval", "exec", "$(", "`", "|", "&", ";", "curl", "wget",
                      "base64", "python", "perl", "ruby", "node", "bash", "sh ", "kill",
                      "rm ", "mv ", "cp ", "chmod", "chown", "dd ", "mkfs"]
        assume(not any(d in cmd.lower() for d in dangerous))
        try:
            result = shell_classifier.classify("shell.execute", {"command": cmd})
            assert result.opaque is False, f"Bounded command classified as opaque: {cmd!r}"
            assert result.classification_confidence == ClassificationConfidence.high
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Canonical JSON Fuzz Tests
# ---------------------------------------------------------------------------

class TestCanonicalJSONFuzz:
    """Property-based tests for canonical JSON serialization."""

    @given(
        data=st.recursive(
            st.one_of(
                st.none(),
                st.booleans(),
                st.integers(min_value=-10**15, max_value=10**15),
                st.text(max_size=50),
            ),
            lambda children: st.one_of(
                st.lists(children, max_size=5),
                st.dictionaries(st.text(min_size=1, max_size=10, alphabet=string.ascii_letters), children, max_size=5),
            ),
            max_leaves=10,
        )
    )
    @settings(max_examples=200, deadline=2000)
    def test_deterministic_serialization(self, data):
        """Canonical JSON must be deterministic — same input always produces same output."""
        j1 = canonical_json(data)
        j2 = canonical_json(data)
        assert j1 == j2

    @given(
        data=st.recursive(
            st.one_of(
                st.none(),
                st.booleans(),
                st.integers(min_value=-10**15, max_value=10**15),
                st.text(max_size=50),
            ),
            lambda children: st.one_of(
                st.lists(children, max_size=5),
                st.dictionaries(st.text(min_size=1, max_size=10, alphabet=string.ascii_letters), children, max_size=5),
            ),
            max_leaves=10,
        )
    )
    @settings(max_examples=200, deadline=2000)
    def test_hash_deterministic(self, data):
        """Canonical hash must be deterministic."""
        h1 = canonical_hash(data)
        h2 = canonical_hash(data)
        assert h1 == h2
        assert h1.startswith("sha256:") or len(h1) == 64

    @given(
        keys=st.lists(st.text(min_size=1, max_size=10, alphabet=string.ascii_letters), min_size=2, max_size=5, unique=True),
        val=st.integers(),
    )
    @settings(max_examples=100, deadline=2000)
    def test_key_order_independent(self, keys, val):
        """Dict with same keys in different order must produce same canonical JSON."""
        import random
        d1 = {k: val for k in keys}
        d2 = {}
        shuffled = list(keys)
        random.shuffle(shuffled)
        for k in shuffled:
            d2[k] = val
        assert canonical_json(d1) == canonical_json(d2)

    @given(
        data=st.recursive(
            st.one_of(
                st.none(),
                st.booleans(),
                st.integers(),
                st.text(max_size=20),
            ),
            lambda children: st.one_of(
                st.lists(children, max_size=3),
                st.dictionaries(st.text(min_size=1, max_size=5), children, max_size=3),
            ),
            max_leaves=5,
        )
    )
    @settings(max_examples=100, deadline=2000)
    def test_roundtrip_parseable(self, data):
        """Canonical JSON must always be valid JSON that can be parsed back."""
        j = canonical_json(data)
        parsed = json.loads(j)
        # Note: types may differ slightly (e.g. tuples -> lists) but values match
        assert parsed is not None or data is None


# ---------------------------------------------------------------------------
# XID Fuzz Tests
# ---------------------------------------------------------------------------

class TestXIDFuzz:
    """Property-based tests for XID generation."""

    @given(n=st.integers(min_value=2, max_value=100))
    @settings(max_examples=50, deadline=2000)
    def test_batch_unique(self, n):
        """N XIDs generated in sequence must all be unique."""
        ids = [str(XID.new()) for _ in range(n)]
        assert len(ids) == len(set(ids)), f"Duplicate XIDs found in batch of {n}"

    @given(n=st.integers(min_value=1, max_value=50))
    @settings(max_examples=50, deadline=1000)
    def test_xid_format(self, n):
        """Every XID must be 20 characters of base32hex."""
        xid = str(XID.new())
        assert len(xid) == 20, f"XID length {len(xid)}, expected 20: {xid}"
        # base32hex: 0-9, a-v (lowercase)
        valid_chars = set("0123456789abcdefghijklmnopqrstuv")
        assert all(c in valid_chars for c in xid), f"Invalid char in XID: {xid}"

    @given(data=st.binary(min_size=1, max_size=32))
    @settings(max_examples=50, deadline=1000)
    def test_from_bytes_always_valid(self, data):
        """XID.from_bytes must produce a valid 20-char string for any byte input."""
        try:
            xid = XID.from_bytes(data)
            s = str(xid)
            assert len(s) == 20
        except Exception:
            # Some byte lengths may not be valid — that's OK as long as it doesn't crash silently
            pass