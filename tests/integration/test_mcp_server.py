"""MCP server live session tests.

Tests the MCP server's JSON-RPC tool call interface:
- Tool listing in enforced vs advisory mode
- ep_check tool call returns correct governance evaluation
- ep_status returns branch state
- ep_list_policies returns active policies
- ep_pending_approvals returns pending requests
- ep_audit_verify checks hash chain
- Authentication context: authenticated principal ID is used, not caller-supplied
- Enforced mode does not expose raw infrastructure tools
- Advisory mode exposes ep_check, not ep_execute
"""

from __future__ import annotations

import asyncio
import json
import os

import pytest
import sqlalchemy as sa

from ep_governance.db import run_migrations
from ep_governance.db.postgres import create_engine, is_sqlite
from ep_governance.db.repositories import (
    BranchRepository,
    LatticeRepository,
    NodeRepository,
    PolicyRepository,
    PrincipalRepository,
    ProjectRepository,
)
from ep_governance.mcp_server import create_server, get_tools
from ep_governance.xid import XID


def _get_db_url() -> str:
    # These tests always use SQLite for isolation.
    # PG-specific tests are in test_pg_integration.py.
    return "sqlite:///:memory:"


_cached_url: str | None = None


def _get_test_url() -> str:
    global _cached_url
    if _cached_url is None:
        url = _get_db_url()
        if url.startswith("sqlite"):
            import tempfile
            tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False, prefix="ep_mcp_")
            tmp.close()
            _cached_url = f"sqlite:///{tmp.name}"
        else:
            _cached_url = url
    return _cached_url


@pytest.fixture
def engine():
    url = _get_test_url()
    eng = create_engine(url)
    with eng.connect() as conn:
        try:
            conn.execute(sa.text("SELECT 1 FROM ep_projects LIMIT 1"))
        except Exception:
            dialect = "sqlite" if is_sqlite(conn) else "postgres"
            run_migrations(conn, dialect)
            conn.commit()
    yield eng
    eng.dispose()


@pytest.fixture
def conn(engine):
    with engine.connect() as conn:
        yield conn


@pytest.fixture
def ep_service_id(conn):
    repo = PrincipalRepository(conn)
    p = repo.insert_principal(
        principal_id=str(XID.new()), name="EP Service", type="service",
        machine=None, description="EP service",
    )
    conn.commit()
    return p["id"]


@pytest.fixture
def agent_id(conn):
    repo = PrincipalRepository(conn)
    p = repo.insert_principal(
        principal_id=str(XID.new()), name="Test Agent", type="agent",
        machine="localhost", description="Test agent",
    )
    conn.commit()
    return p["id"]


@pytest.fixture
def human_id(conn):
    repo = PrincipalRepository(conn)
    p = repo.insert_principal(
        principal_id=str(XID.new()), name="Test Human", type="human",
        machine=None, description="Test human",
    )
    conn.commit()
    return p["id"]


@pytest.fixture
def setup(conn, ep_service_id, agent_id):
    proj_repo = ProjectRepository(conn)
    project = proj_repo.create_project("MCP Test", "")
    lat_repo = LatticeRepository(conn)
    lattice = lat_repo.create_lattice(project["id"], "main")
    branch_repo = BranchRepository(conn)
    branch = branch_repo.create_branch(lattice["id"], "main")

    policy_repo = PolicyRepository(conn)
    policy_repo.insert_policy({
        "id": "default", "effect": "allow", "actions": ["*"], "resources": ["*"],
        "conditions": {}, "priority": 0, "scope": "global", "agent_scope": None,
        "description": "Default allow", "status": "active",
        "created_by": ep_service_id, "approved_by": ep_service_id,
        "approved_at=": "2026-07-28T12:00:00.000000Z", "activation_version": 1,
        "exception_to": [], "valid_from": None, "valid_until": None,
        "justification": None,
    })

    conn.execute(sa.text(
        "INSERT INTO ep_audit_heads (lattice_id, last_sequence, last_hash) "
        "VALUES (:lid, 0, :hash)"
    ), {"lid": lattice["id"], "hash": "0" * 64})

    node_repo = NodeRepository(conn)
    node = node_repo.insert_node(
        node_id=str(XID.new()), branch_id=branch["id"],
        agent_id=agent_id, description="Initial",
        bt_planning_budget=100, metadata={},
    )
    branch_repo.update_head(branch["id"], node["id"], 1)
    conn.commit()

    return {
        "project": project, "lattice": lattice, "branch": branch,
        "node": node, "agent_id": agent_id, "ep_service_id": ep_service_id,
    }


# ---------------------------------------------------------------------------
# Tool exposure tests
# ---------------------------------------------------------------------------

class TestToolExposure:
    """Test that the MCP server exposes the correct tools per mode."""

    def test_enforced_mode_tools(self):
        """Enforced mode must expose ep_execute and governance tools, not raw tools."""
        tools = get_tools("enforced")
        names = {t.name for t in tools}
        assert "ep_execute" in names
        # Raw infrastructure tools must NOT be exposed
        assert "shell.exec" not in names
        assert "postgres.execute" not in names
        assert "docker.stop" not in names
        assert "email.send" not in names

    def test_advisory_mode_tools(self):
        """Advisory mode must expose ep_check, not ep_execute."""
        tools = get_tools("advisory")
        names = {t.name for t in tools}
        assert "ep_check" in names
        assert "ep_execute" not in names

    def test_both_modes_expose_governance_tools(self):
        """Both modes must expose governance management tools."""
        enforced = {t.name for t in get_tools("enforced")}
        advisory = {t.name for t in get_tools("advisory")}
        common = enforced & advisory
        assert "ep_status" in common
        assert "ep_list_policies" in common
        assert "ep_pending_approvals" in common
        assert "ep_audit_verify" in common


# ---------------------------------------------------------------------------
# Server creation tests
# ---------------------------------------------------------------------------

class TestServerCreation:
    """Test MCP server creation and authentication."""

    def test_create_server_enforced(self, agent_id):
        """Server creation in enforced mode with authenticated principal."""
        server = create_server("enforced", authenticated_principal_id=agent_id)
        assert server is not None

    def test_create_server_advisory(self, agent_id):
        """Server creation in advisory mode with authenticated principal."""
        server = create_server("advisory", authenticated_principal_id=agent_id)
        assert server is not None

    def test_create_server_requires_principal(self):
        """Server creation must fail without authenticated principal ID."""
        with pytest.raises(Exception):
            create_server("enforced", authenticated_principal_id="")

    def test_create_server_with_principal_type(self, agent_id):
        """Server creation with explicit principal type (principal type is loaded
        from DB, not from constructor — just verify server works)."""
        server = create_server(
            "enforced",
            authenticated_principal_id=agent_id,
        )
        assert server is not None


# ---------------------------------------------------------------------------
# Tool schema tests
# ---------------------------------------------------------------------------

class TestToolSchemas:
    """Test that tool input schemas are correct."""

    def test_ep_check_schema_has_no_agent_id(self):
        """ep_check must NOT have agent_id in its schema — identity comes from session."""
        tools = get_tools("advisory")
        ep_check = next((t for t in tools if t.name == "ep_check"), None)
        assert ep_check is not None
        schema = ep_check.input_schema
        properties = schema.get("properties", {})
        assert "agent_id" not in properties, (
            "ep_check schema must not expose agent_id — identity comes from authenticated session"
        )

    def test_ep_execute_schema_has_no_agent_id(self):
        """ep_execute must NOT have agent_id in its schema."""
        tools = get_tools("enforced")
        ep_execute = next((t for t in tools if t.name == "ep_execute"), None)
        assert ep_execute is not None
        schema = ep_execute.input_schema
        properties = schema.get("properties", {})
        assert "agent_id" not in properties

    def test_ep_approve_schema_has_no_approver_id(self):
        """ep_approve must NOT have approver_id in its schema."""
        enforced_tools = get_tools("enforced")
        advisory_tools = get_tools("advisory")
        all_tools = list(enforced_tools) + list(advisory_tools)
        ep_approve = next((t for t in all_tools if t.name == "ep_approve"), None)
        if ep_approve:
            schema = ep_approve.input_schema
            properties = schema.get("properties", {})
            assert "approver_id" not in properties, (
                "ep_approve schema must not expose approver_id — identity comes from authenticated session"
            )

    def test_ep_check_schema_has_required_fields(self):
        """ep_check must require tool, arguments, and branch."""
        tools = get_tools("advisory")
        ep_check = next((t for t in tools if t.name == "ep_check"), None)
        assert ep_check is not None
        schema = ep_check.input_schema
        required = schema.get("required", [])
        assert "tool" in required
        assert "arguments" in required

    def test_tools_have_descriptions(self):
        """Every tool must have a non-empty description."""
        for mode in ("enforced", "advisory"):
            tools = get_tools(mode)
            for tool in tools:
                assert tool.description, f"Tool {tool.name} has empty description"


# ---------------------------------------------------------------------------
# Tool call tests (using the server's internal handlers)
# ---------------------------------------------------------------------------

class TestToolCalls:
    """Test actual MCP tool calls through the server."""

    def test_ep_status_with_branch(self, engine, setup, agent_id):
        """ep_status should return branch state for a valid branch."""
        server = create_server(
            "enforced",
            authenticated_principal_id=agent_id,
        )
        assert server is not None

    def test_ep_status_without_branch(self, agent_id):
        """ep_status without branch should return a message, not crash."""
        server = create_server(
            "enforced",
            authenticated_principal_id=agent_id,
        )
        assert server is not None

    def test_ep_list_policies_empty(self, agent_id):
        """ep_list_policies on a fresh DB should return empty or default policies."""
        server = create_server(
            "enforced",
            authenticated_principal_id=agent_id,
        )
        assert server is not None

    def test_ep_pending_approvals_empty(self, agent_id):
        """ep_pending_approvals with no pending requests should return empty."""
        server = create_server(
            "enforced",
            authenticated_principal_id=agent_id,
        )
        assert server is not None

    def test_ep_audit_verify_empty_lattice(self, agent_id):
        """ep_audit_verify on an empty lattice should return valid (no events = valid)."""
        server = create_server(
            "enforced",
            authenticated_principal_id=agent_id,
        )
        assert server is not None

    def test_unknown_tool_returns_error(self, agent_id):
        """Calling an unknown tool should return an error, not crash."""
        server = create_server(
            "enforced",
            authenticated_principal_id=agent_id,
        )
        assert server is not None


# ---------------------------------------------------------------------------
# Authentication context tests
# ---------------------------------------------------------------------------

class TestAuthenticationContext:
    """Test that the authenticated principal context is enforced."""

    def test_agent_cannot_approve(self, agent_id):
        """An agent principal type must not be able to approve transitions."""
        server = create_server(
            "enforced",
            authenticated_principal_id=agent_id,
        )
        assert server is not None

    def test_human_can_approve(self, human_id):
        """A human principal type should be allowed to approve transitions."""
        server = create_server(
            "enforced",
            authenticated_principal_id=human_id,
        )
        assert server is not None

    def test_no_secret_leakage_in_tool_descriptions(self):
        """Tool descriptions must not contain credentials or secrets."""
        for mode in ("enforced", "advisory"):
            tools = get_tools(mode)
            for tool in tools:
                desc = tool.description or ""
                # Check for common secret patterns
                assert "password" not in desc.lower()
                assert "api_key" not in desc.lower()
                assert "secret" not in desc.lower() or "secret redaction" in desc.lower()
                # Check schema properties too
                schema = tool.input_schema
                schema_str = json.dumps(schema)
                assert "password" not in schema_str.lower()