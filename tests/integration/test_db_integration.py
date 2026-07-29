"""Integration tests for EP-Governance database layer.

Tests run against SQLite for fast local testing.  To test against
PostgreSQL, start the test container:

    docker-compose -f docker-compose.test.yml up -d
    EP_TEST_DB_URL=postgresql://ep_test:ep_test_pw@localhost:5433/ep_governance_test pytest tests/integration/

Or run with SQLite only (default):

    pytest tests/integration/
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

import pytest
import sqlalchemy as sa

from ep_governance.db.postgres import create_engine, is_sqlite
from ep_governance.db import run_migrations
from ep_governance.db.transactions import transaction
from ep_governance.audit import AuditWriter, AuditVerifier
from ep_governance.db.repositories import (
    ProjectRepository,
    LatticeRepository,
    BranchRepository,
    NodeRepository,
    PolicyRepository,
    PrincipalRepository,
    TransitionRepository,
    AuthorizationRepository,
)
from ep_governance.xid import XID

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _get_db_url() -> str:
    return os.environ.get(
        "EP_TEST_DB_URL",
        "sqlite:///:memory:",
    )


@pytest.fixture
def engine():
    url = _get_db_url()
    eng = create_engine(url)
    yield eng
    eng.dispose()


@pytest.fixture
def conn(engine):
    """A connection with migrations applied."""
    with engine.connect() as conn:
        dialect = "sqlite" if is_sqlite(conn) else "postgres"
        run_migrations(conn, dialect)
        conn.commit()
        yield conn


@pytest.fixture
def ep_service_principal_id(conn):
    """Create the EP service principal for audit events."""
    repo = PrincipalRepository(conn)
    principal = repo.insert_principal(
        principal_id=str(XID.new()),
        name="EP Service",
        type="service",
        machine=None,
        description="Trusted EP service principal",
    )
    conn.commit()
    return principal["id"]


# ---------------------------------------------------------------------------
# Migration tests
# ---------------------------------------------------------------------------


class TestMigrations:
    def test_migrations_create_all_tables(self, conn):
        """All required tables must exist after migration."""
        if is_sqlite(conn):
            result = conn.execute(sa.text(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ))
            tables = {row[0] for row in result}
        else:
            result = conn.execute(sa.text(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema='public' ORDER BY table_name"
            ))
            tables = {row[0] for row in result}

        required = {
            "ep_projects",
            "ep_lattices",
            "ep_branches",
            "ep_nodes",
            "ep_edges",
            "ep_policies",
            "ep_policy_versions",
            "ep_principals",
            "ep_roles",
            "ep_role_bindings",
            "ep_credentials",
            "ep_transitions",
            "ep_authorizations",
            "ep_approval_requests",
            "ep_approval_decisions",
            "ep_risk_ledger",
            "ep_risk_mitigations",
            "ep_audit_heads",
            "ep_events",
            "ep_work_claims",
            "ep_sessions",
            "ep_transfer_packages",
            "ep_import_mappings",
        }
        missing = required - tables
        assert not missing, f"Missing tables: {missing}"


# ---------------------------------------------------------------------------
# Repository tests
# ---------------------------------------------------------------------------


class TestProjectRepository:
    def test_create_and_get_project(self, conn):
        repo = ProjectRepository(conn)
        project = repo.create_project("Test Project", "A test")
        conn.commit()
        assert project["name"] == "Test Project"
        fetched = repo.get_project(project["id"])
        assert fetched is not None
        assert fetched["name"] == "Test Project"

    def test_list_projects(self, conn):
        repo = ProjectRepository(conn)
        repo.create_project("Project A", "")
        repo.create_project("Project B", "")
        conn.commit()
        projects = repo.list_projects()
        assert len(projects) >= 2


class TestLatticeRepository:
    def test_create_and_get_lattice(self, conn):
        proj_repo = ProjectRepository(conn)
        project = proj_repo.create_project("Test", "")

        lat_repo = LatticeRepository(conn)
        lattice = lat_repo.create_lattice(project["id"], "main")
        conn.commit()
        assert lattice["name"] == "main"
        fetched = lat_repo.get_lattice(lattice["id"])
        assert fetched is not None

    def test_get_by_project(self, conn):
        proj_repo = ProjectRepository(conn)
        project = proj_repo.create_project("Test", "")

        lat_repo = LatticeRepository(conn)
        lattice = lat_repo.create_lattice(project["id"], "main")
        conn.commit()
        fetched = lat_repo.get_by_project(project["id"])
        assert fetched is not None
        assert fetched["id"] == lattice["id"]


class TestBranchRepository:
    def test_create_branch_with_no_head(self, conn):
        proj_repo = ProjectRepository(conn)
        project = proj_repo.create_project("Test", "")
        lat_repo = LatticeRepository(conn)
        lattice = lat_repo.create_lattice(project["id"], "main")

        branch_repo = BranchRepository(conn)
        branch = branch_repo.create_branch(lattice["id"], "main")
        conn.commit()
        assert branch["name"] == "main"
        assert branch["version"] == 1

    def test_update_head_optimistic_concurrency(self, conn):
        proj_repo = ProjectRepository(conn)
        project = proj_repo.create_project("Test", "")
        lat_repo = LatticeRepository(conn)
        lattice = lat_repo.create_lattice(project["id"], "main")

        branch_repo = BranchRepository(conn)
        branch = branch_repo.create_branch(lattice["id"], "main")
        conn.commit()

        # First update at version 0 should succeed
        new_node_id = str(XID.new())
        assert branch_repo.update_head(branch["id"], new_node_id, 1) is True
        conn.commit()

        # Second update at stale version 0 should fail
        assert branch_repo.update_head(branch["id"], str(XID.new()), 1) is False

    def test_get_head(self, conn):
        proj_repo = ProjectRepository(conn)
        project = proj_repo.create_project("Test", "")
        lat_repo = LatticeRepository(conn)
        lattice = lat_repo.create_lattice(project["id"], "main")

        branch_repo = BranchRepository(conn)
        branch = branch_repo.create_branch(lattice["id"], "main")
        conn.commit()

        head_id, version = branch_repo.get_head(branch["id"])
        assert head_id is None  # no head initially
        assert version == 1


class TestNodeRepository:
    def test_insert_node(self, conn):
        proj_repo = ProjectRepository(conn)
        project = proj_repo.create_project("Test", "")
        lat_repo = LatticeRepository(conn)
        lattice = lat_repo.create_lattice(project["id"], "main")
        branch_repo = BranchRepository(conn)
        branch = branch_repo.create_branch(lattice["id"], "main")

        node_repo = NodeRepository(conn)
        node_id = str(XID.new())
        node = node_repo.insert_node(
            node_id=node_id,
            branch_id=branch["id"],
            agent_id=str(XID.new()),
            description="Test node",
            bt_planning_budget=100.0,
            metadata={},
        )
        conn.commit()
        assert node["status"] == "committed"
        assert node["bt_planning_budget"] == 100.0


class TestPolicyRepository:
    def test_insert_and_get_policy(self, conn):
        principal_repo = PrincipalRepository(conn)
        principal = principal_repo.insert_principal(
            principal_id=str(XID.new()), name="Test", type="human",
            machine=None, description="",
        )
        conn.commit()

        repo = PolicyRepository(conn)
        policy = repo.insert_policy({
            "id": str(XID.new()),
            "effect": "deny",
            "actions": ["db.drop"],
            "resources": ["postgres://cloudhub/gbrain_pilot/**"],
            "conditions": {},
            "priority": 100,
            "scope": "global",
            "agent_scope": None,
            "description": "Test policy",
            "status": "active",
            "created_by": principal["id"],
            "approved_by": None,
            "approved_at": None,
            "activation_version": None,
            "exception_to": [],
            "valid_from": None,
            "valid_until": None,
            "justification": None,
        })
        conn.commit()
        fetched = repo.get_policy(policy["id"])
        assert fetched is not None
        assert fetched["effect"] == "deny"

    def test_list_active_policies(self, conn):
        principal_repo = PrincipalRepository(conn)
        principal = principal_repo.insert_principal(
            principal_id=str(XID.new()), name="Test", type="human",
            machine=None, description="",
        )
        conn.commit()

        repo = PolicyRepository(conn)
        repo.insert_policy({
            "id": str(XID.new()), "effect": "deny", "actions": ["db.drop"],
            "resources": ["postgres://**"], "conditions": {},
            "priority": 100, "scope": "global", "agent_scope": None,
            "description": "Active", "status": "active",
            "created_by": principal["id"], "approved_by": None,
            "approved_at": None, "activation_version": None,
            "exception_to": [], "valid_from": None, "valid_until": None,
            "justification": None,
        })
        repo.insert_policy({
            "id": str(XID.new()), "effect": "allow", "actions": ["db.select"],
            "resources": ["postgres://**"], "conditions": {},
            "priority": 50, "scope": "global", "agent_scope": None,
            "description": "Draft", "status": "draft",
            "created_by": principal["id"], "approved_by": None,
            "approved_at": None, "activation_version": None,
            "exception_to": [], "valid_from": None, "valid_until": None,
            "justification": None,
        })
        conn.commit()
        active = repo.list_active_policies()
        assert len(active) == 1
        assert active[0]["status"] == "active"


# ---------------------------------------------------------------------------
# Audit tests
# ---------------------------------------------------------------------------


class TestAuditWriter:
    def test_write_single_event(self, conn, ep_service_principal_id):
        """Writing a single audit event should create the event and update the head."""
        # Create a lattice first
        proj_repo = ProjectRepository(conn)
        project = proj_repo.create_project("Test", "")
        lat_repo = LatticeRepository(conn)
        lattice = lat_repo.create_lattice(project["id"], "main")
        conn.commit()

        # Initialize audit head for the lattice
        conn.execute(sa.text("INSERT INTO ep_audit_heads (lattice_id, last_sequence, last_hash) VALUES (:lid, 0, :hash)"),
                     {"lid": lattice["id"], "hash": "0" * 64})
        conn.commit()

        writer = AuditWriter(conn, ep_service_principal_id)
        event = writer.write_event(
            lattice_id=lattice["id"],
            event_type="transition_proposed",
            event_data={"transition_id": str(XID.new())},
            actor_principal_id=ep_service_principal_id,
            authenticated_caller_id=ep_service_principal_id,
        )
        conn.commit()

        assert event.sequence == 1
        assert event.previous_hash == "0" * 64
        assert len(event.event_hash) == 64
        assert event.event_hash != "0" * 64

    def test_write_multiple_events_chain(self, conn, ep_service_principal_id):
        """Multiple events should form a hash chain."""
        proj_repo = ProjectRepository(conn)
        project = proj_repo.create_project("Test", "")
        lat_repo = LatticeRepository(conn)
        lattice = lat_repo.create_lattice(project["id"], "main")
        conn.commit()

        # Initialize audit head for the lattice
        conn.execute(sa.text("INSERT INTO ep_audit_heads (lattice_id, last_sequence, last_hash) VALUES (:lid, 0, :hash)"),
                     {"lid": lattice["id"], "hash": "0" * 64})
        conn.commit()

        writer = AuditWriter(conn, ep_service_principal_id)
        events = []
        for i in range(5):
            event = writer.write_event(
                lattice_id=lattice["id"],
                event_type="test_event",
                event_data={"index": i},
                actor_principal_id=ep_service_principal_id,
                authenticated_caller_id=ep_service_principal_id,
            )
            events.append(event)
        conn.commit()

        # Verify chain linkage
        assert events[0].previous_hash == "0" * 64
        for i in range(1, len(events)):
            assert events[i].previous_hash == events[i - 1].event_hash
            assert events[i].sequence == i + 1


class TestAuditVerifier:
    def test_verify_valid_chain(self, conn, ep_service_principal_id):
        """A valid chain should verify as True."""
        proj_repo = ProjectRepository(conn)
        project = proj_repo.create_project("Test", "")
        lat_repo = LatticeRepository(conn)
        lattice = lat_repo.create_lattice(project["id"], "main")
        conn.commit()

        # Initialize audit head for the lattice
        conn.execute(sa.text("INSERT INTO ep_audit_heads (lattice_id, last_sequence, last_hash) VALUES (:lid, 0, :hash)"),
                     {"lid": lattice["id"], "hash": "0" * 64})
        conn.commit()

        writer = AuditWriter(conn, ep_service_principal_id)
        for i in range(5):
            writer.write_event(
                lattice_id=lattice["id"],
                event_type="test_event",
                event_data={"index": i},
                actor_principal_id=ep_service_principal_id,
                authenticated_caller_id=ep_service_principal_id,
            )
        conn.commit()

        verifier = AuditVerifier(conn)
        assert verifier.verify(lattice["id"]) is True

    def test_verify_empty_lattice(self, conn):
        """An empty lattice (no events) should verify as True."""
        verifier = AuditVerifier(conn)
        assert verifier.verify("nonexistent") is True  # no events = valid


# ---------------------------------------------------------------------------
# Authorization claim tests
# ---------------------------------------------------------------------------


def _create_test_setup(conn):
    """Create project, lattice, branch, principal, and transition for FK tests."""
    proj_repo = ProjectRepository(conn)
    project = proj_repo.create_project("Test", "")
    
    lat_repo = LatticeRepository(conn)
    lattice = lat_repo.create_lattice(project["id"], "main")
    
    branch_repo = BranchRepository(conn)
    branch = branch_repo.create_branch(lattice["id"], "main")
    
    principal_repo = PrincipalRepository(conn)
    agent = principal_repo.insert_principal(
        principal_id=str(XID.new()), name="Agent", type="agent",
        machine="localhost", description="Test agent",
    )
    
    # Create a transition for the FK
    transition_repo = TransitionRepository(conn)
    transition = transition_repo.insert_transition({
        "id": str(XID.new()),
        "agent_id": agent["id"],
        "branch_id": branch["id"],
        "tool": "postgres.execute",
        "payload_hash": "sha256:" + "a" * 64,
        "idempotency_key": str(XID.new()),
        "stage": "authorized",
    })
    conn.commit()
    return {
        "project": project,
        "lattice": lattice,
        "branch": branch,
        "agent": agent,
        "transition": transition,
    }


class TestAuthorizationClaim:
    def test_claim_unused_authorization(self, conn):
        """Claiming an unused, unexpired authorization should succeed."""
        setup = _create_test_setup(conn)

        auth_repo = AuthorizationRepository(conn)
        auth_id = str(XID.new())
        auth_repo.insert_authorization({
            "id": auth_id,
            "transition_id": setup["transition"]["id"],
            "token_hash": "sha256:fakehash",
            "payload_hash": "sha256:" + "a" * 64,
            "policy_set_hash": "sha256:" + "b" * 64,
            "matched_policy_versions": {},
            "proxy_audience": "postgres-proxy",
            "agent_id": setup["agent"]["id"],
            "project_id": setup["project"]["id"],
            "branch_id": setup["branch"]["id"],
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": "2099-01-01T00:00:00.000000Z",
        })
        conn.commit()

        # Claim it
        result = auth_repo.claim_authorization(auth_id, str(XID.new()))
        conn.commit()
        assert result is not None

    def test_claim_used_authorization_fails(self, conn):
        """Claiming an already-used authorization should return None."""
        setup = _create_test_setup(conn)

        auth_repo = AuthorizationRepository(conn)
        auth_id = str(XID.new())
        auth_repo.insert_authorization({
            "id": auth_id,
            "transition_id": setup["transition"]["id"],
            "token_hash": "sha256:fakehash",
            "payload_hash": "sha256:" + "a" * 64,
            "policy_set_hash": "sha256:" + "b" * 64,
            "matched_policy_versions": {},
            "proxy_audience": "postgres-proxy",
            "agent_id": setup["agent"]["id"],
            "project_id": setup["project"]["id"],
            "branch_id": setup["branch"]["id"],
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": "2099-01-01T00:00:00.000000Z",
        })
        conn.commit()

        # First claim succeeds
        result1 = auth_repo.claim_authorization(auth_id, str(XID.new()))
        conn.commit()
        assert result1 is not None

        # Second claim fails
        result2 = auth_repo.claim_authorization(auth_id, str(XID.new()))
        conn.commit()
        assert result2 is None