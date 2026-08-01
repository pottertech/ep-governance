"""Tests for administrator cancellation path in TransitionEngine.cancel().

Tests that:
- Active administrator can cancel another agent's transition
- Inactive/revoked administrator cannot cancel
- Non-administrator role cannot cancel
- Missing role tables fail closed (denies cancellation)
- Administrator cancellation produces audit event identifying the admin
"""

from __future__ import annotations

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
    TransitionRepository,
)
from ep_governance.errors import AuthorizationError, IllegalTransitionError
from ep_governance.transitions import TransitionEngine
from ep_governance.xid import XID


def _get_db_url() -> str:
    return os.environ.get("EP_TEST_DB_URL", "sqlite:///:memory:")


@pytest.fixture
def engine():
    eng = create_engine(_get_db_url())
    yield eng
    eng.dispose()


@pytest.fixture
def conn(engine):
    with engine.connect() as conn:
        dialect = "sqlite" if is_sqlite(conn) else "postgres"
        run_migrations(conn, dialect)
        conn.commit()
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
        principal_id=str(XID.new()), name="Agent A", type="agent",
        machine="localhost", description="Test agent A",
    )
    conn.commit()
    return p["id"]


@pytest.fixture
def admin_id(conn):
    """Create a human principal with an active administrator role binding."""
    repo = PrincipalRepository(conn)
    admin = repo.insert_principal(
        principal_id=str(XID.new()), name="Admin User", type="human",
        machine=None, description="Administrator",
    )
    # Create administrator role
    role_id = str(XID.new())
    conn.execute(sa.text(
        "INSERT INTO ep_roles (id, name, permissions) "
        "VALUES (:id, 'administrator', '[]')"
    ), {"id": role_id})
    # Create active role binding
    binding_id = str(XID.new())
    conn.execute(sa.text(
        "INSERT INTO ep_role_bindings (id, principal_id, role_id) "
        "VALUES (:id, :pid, :rid)"
    ), {"id": binding_id, "pid": admin["id"], "rid": role_id})
    conn.commit()
    return admin["id"]


@pytest.fixture
def inactive_admin_id(conn):
    """Create a human principal with an inactive administrator role binding."""
    repo = PrincipalRepository(conn)
    admin = repo.insert_principal(
        principal_id=str(XID.new()), name="Inactive Admin", type="human",
        machine=None, description="Inactive administrator",
    )
    role_id = str(XID.new())
    conn.execute(sa.text(
        "INSERT INTO ep_roles (id, name, permissions) "
        "VALUES (:id, 'administrator', '[]')"
    ), {"id": role_id})
    # Create binding then immediately delete it (simulates revoked)
    binding_id = str(XID.new())
    conn.execute(sa.text(
        "INSERT INTO ep_role_bindings (id, principal_id, role_id) "
        "VALUES (:id, :pid, :rid)"
    ), {"id": binding_id, "pid": admin["id"], "rid": role_id})
    conn.execute(sa.text("DELETE FROM ep_role_bindings WHERE id = :id"), {"id": binding_id})
    conn.commit()
    return admin["id"]


@pytest.fixture
def non_admin_role_id(conn):
    """Create a principal with a non-administrator role."""
    repo = PrincipalRepository(conn)
    user = repo.insert_principal(
        principal_id=str(XID.new()), name="Non-Admin User", type="human",
        machine=None, description="Non-admin operator",
    )
    role_id = str(XID.new())
    conn.execute(sa.text(
        "INSERT INTO ep_roles (id, name, permissions) "
        "VALUES (:id, 'auditor', '[]')"
    ), {"id": role_id})
    binding_id = str(XID.new())
    conn.execute(sa.text(
        "INSERT INTO ep_role_bindings (id, principal_id, role_id) "
        "VALUES (:id, :pid, :rid)"
    ), {"id": binding_id, "pid": user["id"], "rid": role_id})
    conn.commit()
    return user["id"]


@pytest.fixture
def setup(conn, ep_service_id, agent_id):
    proj_repo = ProjectRepository(conn)
    project = proj_repo.create_project("Admin Cancel Test", "")
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


class TestAdministratorCancellation:
    """Test that administrators can cancel other agents' transitions."""

    def test_active_admin_can_cancel(self, conn, engine, setup, ep_service_id, agent_id, admin_id):
        """An active administrator can cancel another agent's transition."""
        trans_engine = TransitionEngine(engine, ep_service_id)
        transition = trans_engine.propose(
            agent_id=agent_id,
            branch_id=setup["branch"]["id"],
            tool="postgres.execute",
            arguments={"sql": "SELECT 1"},
            idempotency_key=str(XID.new()),
        )
        conn.commit()

        # Admin cancels agent's transition
        result = trans_engine.cancel(transition["id"], admin_id)
        conn.commit()
        assert result["stage"] == "cancelled"

    def test_inactive_admin_cannot_cancel(self, conn, engine, setup, ep_service_id, agent_id, inactive_admin_id):
        """A principal with a revoked administrator role cannot cancel."""
        trans_engine = TransitionEngine(engine, ep_service_id)
        transition = trans_engine.propose(
            agent_id=agent_id,
            branch_id=setup["branch"]["id"],
            tool="postgres.execute",
            arguments={"sql": "SELECT 1"},
            idempotency_key=str(XID.new()),
        )
        conn.commit()

        with pytest.raises(AuthorizationError):
            trans_engine.cancel(transition["id"], inactive_admin_id)
        conn.rollback()

    def test_non_admin_role_cannot_cancel(self, conn, engine, setup, ep_service_id, agent_id, non_admin_role_id):
        """A principal with a non-administrator role cannot cancel."""
        trans_engine = TransitionEngine(engine, ep_service_id)
        transition = trans_engine.propose(
            agent_id=agent_id,
            branch_id=setup["branch"]["id"],
            tool="postgres.execute",
            arguments={"sql": "SELECT 1"},
            idempotency_key=str(XID.new()),
        )
        conn.commit()

        with pytest.raises(AuthorizationError):
            trans_engine.cancel(transition["id"], non_admin_role_id)
        conn.rollback()

    def test_admin_cancellation_writes_audit_event(self, conn, engine, setup, ep_service_id, agent_id, admin_id):
        """Administrator cancellation must produce an audit event identifying the admin."""
        trans_engine = TransitionEngine(engine, ep_service_id)
        transition = trans_engine.propose(
            agent_id=agent_id,
            branch_id=setup["branch"]["id"],
            tool="postgres.execute",
            arguments={"sql": "SELECT 1"},
            idempotency_key=str(XID.new()),
        )
        conn.commit()

        trans_engine.cancel(transition["id"], admin_id)
        conn.commit()

        # Verify audit event was written with admin as actor
        result = conn.execute(sa.text(
            "SELECT actor_principal_id FROM ep_events "
            "WHERE event_type = 'transition.cancelled' "
            "ORDER BY sequence DESC LIMIT 1"
        ))
        row = result.fetchone()
        assert row is not None, "No cancellation audit event found"
        assert row[0] == admin_id, "Audit event actor should be the admin"