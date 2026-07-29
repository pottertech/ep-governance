"""Phase 7 integration tests: MCP server.

Tests MCP tool exposure, tool calling, enforced vs advisory mode,
authentication boundary, and secret redaction.
"""

from __future__ import annotations

import json
import os
import tempfile

import pytest
from typer.testing import CliRunner

from ep_governance.mcp_server import get_tools, create_server, _handle_tool_call
from ep_governance.cli import app

runner = CliRunner()


@pytest.fixture
def temp_db_env(monkeypatch, tmp_path):
    db_path = str(tmp_path / "test_ep_mcp.db")
    monkeypatch.setenv("EP_DB_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("EP_MODE", "enforced")
    yield db_path


@pytest.fixture
def initialized_db(temp_db_env):
    """Initialize the database via CLI."""
    runner.invoke(app, ["init", "--json"])
    yield temp_db_env


class TestToolExposure:
    def test_enforced_mode_exposes_ep_execute_not_ep_check(self):
        """In enforced mode, ep_execute must be available and ep_check must NOT be."""
        tools = get_tools("enforced")
        names = {t.name for t in tools}
        assert "ep_execute" in names
        assert "ep_check" not in names

    def test_advisory_mode_exposes_ep_check_not_ep_execute(self):
        """In advisory mode, ep_check must be available and ep_execute must NOT be."""
        tools = get_tools("advisory")
        names = {t.name for t in tools}
        assert "ep_check" in names
        assert "ep_execute" not in names

    def test_enforced_mode_does_not_expose_raw_tools(self):
        """No raw protected tools (shell.exec, postgres.execute) in enforced mode."""
        tools = get_tools("enforced")
        names = {t.name for t in tools}
        assert "shell.exec" not in names
        assert "postgres.execute" not in names
        assert "docker.stop" not in names
        assert "email.send" not in names

    def test_both_modes_expose_governance_tools(self):
        """Both modes must expose governance management tools."""
        enforced = {t.name for t in get_tools("enforced")}
        advisory = {t.name for t in get_tools("advisory")}
        common = enforced & advisory
        assert "ep_status" in common
        assert "ep_list_policies" in common
        assert "ep_pending_approvals" in common
        assert "ep_audit_verify" in common


class TestServerCreation:
    def test_create_server_enforced(self):
        server = create_server("enforced", authenticated_principal_id="test-agent-1")
        assert server.name == "ep-governance"

    def test_create_server_advisory(self):
        server = create_server("advisory", authenticated_principal_id="test-agent-1")
        assert server.name == "ep-governance"

    def test_create_server_requires_authenticated_principal(self):
        """create_server must reject a missing authenticated_principal_id."""
        with pytest.raises(Exception):
            create_server("enforced")


class TestToolCalls:
    def test_ep_status_without_branch(self, initialized_db, monkeypatch):
        """ep_status without branch_id returns a message."""
        result = _handle_tool_call("ep_status", {}, "enforced", "test-agent-1", "agent")
        assert "message" in result or "branch_id" in result

    def test_ep_list_policies_empty(self, initialized_db):
        """ep_list_policies returns empty list when no active policies."""
        result = _handle_tool_call("ep_list_policies", {}, "enforced", "test-agent-1", "agent")
        assert "policies" in result
        assert result["policies"] == []

    def test_ep_pending_approvals_empty(self, initialized_db):
        """ep_pending_approvals returns empty list when no pending approvals."""
        result = _handle_tool_call("ep_pending_approvals", {}, "enforced", "test-agent-1", "agent")
        assert "pending_approvals" in result
        assert result["pending_approvals"] == []

    def test_ep_audit_verify_empty_lattice(self, initialized_db):
        """ep_audit_verify returns valid=True for a lattice with no events."""
        result = _handle_tool_call(
            "ep_audit_verify",
            {"lattice_id": "nonexistent"},
            "enforced",
            "test-agent-1",
            "agent",
        )
        assert result["valid"] is True

    def test_unknown_tool_returns_error(self, initialized_db):
        """Calling an unknown tool returns an error."""
        result = _handle_tool_call("unknown_tool", {}, "enforced", "test-agent-1", "agent")
        assert "error" in result


class TestNoSecretLeakage:
    def test_status_output_no_credentials(self, initialized_db):
        """MCP tool output must not contain database URLs or passwords."""
        result = _handle_tool_call("ep_status", {}, "enforced", "test-agent-1", "agent")
        output = json.dumps(result)
        assert "postgresql://" not in output
        assert "password" not in output.lower()

    def test_list_policies_no_credentials(self, initialized_db):
        """Policy listing must not contain secrets."""
        result = _handle_tool_call("ep_list_policies", {}, "enforced", "test-agent-1", "agent")
        output = json.dumps(result)
        assert "password" not in output.lower()
        assert "secret" not in output.lower()
        assert "api_key" not in output.lower()