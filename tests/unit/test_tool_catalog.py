"""Unit tests for the dependency-free tool catalog.

These tests verify that ``ep_governance.tool_catalog`` can be imported and
exercised WITHOUT the MCP package, PyNaCl, or Hypothesis installed.
"""

from __future__ import annotations

from ep_governance.tool_catalog import (
    GOVERNED_TOOL_NAMES,
    RAW_TOOL_NAMES,
    TOOL_REQUIRED_ROLES,
    get_governed_tools,
    get_tool_definitions,
    is_governed_tool,
)


class TestGovernedToolNames:
    """Verify the set of governed tool names."""

    def test_governed_tool_names_is_frozenset(self):
        assert isinstance(GOVERNED_TOOL_NAMES, frozenset)

    def test_expected_governed_tools_present(self):
        expected = {
            "ep_execute",
            "ep_status",
            "ep_list_policies",
            "ep_pending_approvals",
            "ep_approve",
            "ep_audit_verify",
        }
        assert expected.issubset(GOVERNED_TOOL_NAMES)

    def test_ep_check_not_in_enforced_set(self):
        """ep_check is advisory-only; it is NOT in the enforced (governed) set."""
        assert "ep_check" not in GOVERNED_TOOL_NAMES

    def test_ep_execute_is_governed(self):
        assert "ep_execute" in GOVERNED_TOOL_NAMES


class TestRawToolNames:
    """Verify raw tool names are correctly defined and excluded."""

    def test_raw_tool_names_is_frozenset(self):
        assert isinstance(RAW_TOOL_NAMES, frozenset)

    def test_expected_raw_tools_present(self):
        assert "shell.exec" in RAW_TOOL_NAMES
        assert "postgres.execute" in RAW_TOOL_NAMES
        assert "docker.exec" in RAW_TOOL_NAMES
        assert "ssh.exec" in RAW_TOOL_NAMES

    def test_no_raw_tools_in_governed_set(self):
        assert GOVERNED_TOOL_NAMES.isdisjoint(RAW_TOOL_NAMES)

    def test_governed_and_raw_are_disjoint(self):
        assert GOVERNED_TOOL_NAMES & RAW_TOOL_NAMES == frozenset()


class TestIsGovernedTool:
    """Verify is_governed_tool predicate."""

    def test_returns_true_for_ep_execute(self):
        assert is_governed_tool("ep_execute") is True

    def test_returns_true_for_ep_check(self):
        """ep_check is advisory, but is_governed_tool checks the enforced set.
        ep_check is NOT in GOVERNED_TOOL_NAMES (enforced mode)."""
        # ep_check is advisory-only — NOT in the enforced governed set
        assert is_governed_tool("ep_check") is False

    def test_returns_true_for_ep_status(self):
        assert is_governed_tool("ep_status") is True

    def test_returns_true_for_ep_approve(self):
        assert is_governed_tool("ep_approve") is True

    def test_returns_true_for_ep_audit_verify(self):
        assert is_governed_tool("ep_audit_verify") is True

    def test_returns_false_for_shell_exec(self):
        assert is_governed_tool("shell.exec") is False

    def test_returns_false_for_postgres_execute(self):
        assert is_governed_tool("postgres.execute") is False

    def test_returns_false_for_docker_exec(self):
        assert is_governed_tool("docker.exec") is False

    def test_returns_false_for_ssh_exec(self):
        assert is_governed_tool("ssh.exec") is False

    def test_returns_false_for_unknown_tool(self):
        assert is_governed_tool("nonexistent.tool") is False

    def test_returns_false_for_empty_string(self):
        assert is_governed_tool("") is False


class TestGetGovernedTools:
    """Verify get_governed_tools returns a list of strings."""

    def test_returns_list(self):
        result = get_governed_tools()
        assert isinstance(result, list)

    def test_returns_non_empty_list(self):
        result = get_governed_tools()
        assert len(result) > 0

    def test_all_elements_are_strings(self):
        result = get_governed_tools()
        for name in result:
            assert isinstance(name, str)

    def test_matches_governed_tool_names(self):
        result = get_governed_tools()
        assert set(result) == set(GOVERNED_TOOL_NAMES)


class TestGetToolDefinitions:
    """Verify get_tool_definitions returns plain dicts for each mode."""

    def test_enforced_mode_returns_definitions(self):
        defs = get_tool_definitions("enforced")
        assert isinstance(defs, list)
        assert len(defs) > 0
        for d in defs:
            assert isinstance(d, dict)
            assert "name" in d
            assert "description" in d
            assert "inputSchema" in d

    def test_advisory_mode_returns_definitions(self):
        defs = get_tool_definitions("advisory")
        assert isinstance(defs, list)
        assert len(defs) > 0

    def test_enforced_contains_ep_execute(self):
        defs = get_tool_definitions("enforced")
        names = [d["name"] for d in defs]
        assert "ep_execute" in names

    def test_advisory_contains_ep_check(self):
        defs = get_tool_definitions("advisory")
        names = [d["name"] for d in defs]
        assert "ep_check" in names

    def test_enforced_does_not_contain_ep_check(self):
        defs = get_tool_definitions("enforced")
        names = [d["name"] for d in defs]
        assert "ep_check" not in names

    def test_no_raw_tools_in_any_mode(self):
        for mode in ("enforced", "advisory"):
            defs = get_tool_definitions(mode)
            names = {d["name"] for d in defs}
            assert names.isdisjoint(RAW_TOOL_NAMES)


class TestToolRequiredRoles:
    """Verify role requirements are defined for governed tools."""

    def test_ep_execute_requires_agent_role(self):
        assert "agent" in TOOL_REQUIRED_ROLES["ep_execute"]

    def test_ep_approve_requires_policy_approver(self):
        assert "policy_approver" in TOOL_REQUIRED_ROLES["ep_approve"]

    def test_ep_audit_verify_requires_auditor(self):
        assert "auditor" in TOOL_REQUIRED_ROLES["ep_audit_verify"]