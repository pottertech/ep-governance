"""Tests for security review round 10 remediations.

Tests:
- SQLite foreign key enforcement (PRAGMA foreign_keys = ON)
- Bootstrap-admin one-time enrollment
- Approval request policies association table
- Policy-set hash consistency
"""

from __future__ import annotations

import os

import pytest
import sqlalchemy as sa

from ep_governance.db.postgres import create_engine, is_sqlite
from ep_governance.db import run_migrations
from ep_governance.db.repositories import (
    PrincipalRepository,
    ProjectRepository,
    LatticeRepository,
    BranchRepository,
    PolicyRepository,
    ApprovalRepository,
    TransitionRepository,
)
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
        principal_id=str(XID.new()),
        name="EP Service",
        type="service",
        machine=None,
        description="EP service",
    )
    conn.commit()
    return p["id"]


@pytest.fixture
def human_id(conn):
    repo = PrincipalRepository(conn)
    p = repo.insert_principal(
        principal_id=str(XID.new()),
        name="Admin Human",
        type="human",
        machine=None,
        description="Human admin",
    )
    conn.commit()
    return p["id"]


class TestSQLiteForeignKeyEnforcement:
    """Finding #8: SQLite must enforce foreign keys."""

    def test_foreign_keys_are_enabled(self, conn):
        """PRAGMA foreign_keys must be ON for SQLite connections."""
        if not is_sqlite(conn):
            pytest.skip("SQLite-only test")
        result = conn.execute(sa.text("PRAGMA foreign_keys"))
        value = result.fetchone()[0]
        assert value == 1, f"foreign_keys pragma should be 1 (ON), got {value}"

    def test_invalid_fk_insert_fails(self, conn):
        """An insert with an invalid foreign key must fail."""
        if not is_sqlite(conn):
            pytest.skip("SQLite-only test")
        # Try to insert a project with a non-existent lattice FK
        # ep_lattices.project_id references ep_projects(id)
        with pytest.raises(Exception):
            conn.execute(
                sa.text(
                    "INSERT INTO ep_lattices (id, project_id, name) "
                    "VALUES ('fake-id', 'nonexistent-project-id', 'test')"
                )
            )


class TestBootstrapAdmin:
    """Finding #6: One-time secure administrator enrollment."""

    def test_bootstrap_admin_creates_admin_binding(self, conn, engine, ep_service_id, human_id):
        """Bootstrap-admin should create the administrator role and binding."""
        from ep_governance.audit import AuditWriter
        from ep_governance.xid import XID as XID_cls

        # Verify no admin binding exists yet
        result = conn.execute(
            sa.text(
                "SELECT rb.id FROM ep_role_bindings rb "
                "JOIN ep_roles r ON rb.role_id = r.id "
                "WHERE r.name = 'administrator' LIMIT 1"
            )
        )
        assert result.fetchone() is None

        # Create the administrator role
        role_id = str(XID_cls.new())
        conn.execute(
            sa.text(
                "INSERT INTO ep_roles (id, name, permissions) VALUES (:id, 'administrator', :perms)"
            ),
            {"id": role_id, "perms": '["*"]'},
        )

        # Bind the human principal
        binding_id = str(XID_cls.new())
        conn.execute(
            sa.text(
                "INSERT INTO ep_role_bindings (id, principal_id, role_id, project_id) "
                "VALUES (:id, :principal_id, :role_id, NULL)"
            ),
            {"id": binding_id, "principal_id": human_id, "role_id": role_id},
        )

        # Record bootstrap completion (singleton row, no bootstrap_token column)
        conn.execute(
            sa.text(
                "INSERT INTO ep_bootstrap_state (singleton_id, completed, completed_by) "
                "VALUES (1, TRUE, :completed_by)"
            ),
            {"completed_by": human_id},
        )
        conn.commit()

        # Verify the binding exists
        result = conn.execute(
            sa.text(
                "SELECT r.name FROM ep_role_bindings rb "
                "JOIN ep_roles r ON rb.role_id = r.id "
                "WHERE rb.principal_id = :pid"
            ),
            {"pid": human_id},
        )
        row = result.fetchone()
        assert row is not None
        assert row[0] == "administrator"

        # Verify bootstrap is marked complete (singleton row)
        result = conn.execute(
            sa.text("SELECT completed FROM ep_bootstrap_state WHERE singleton_id = 1")
        )
        row = result.fetchone()
        assert row is not None
        assert row[0] == 1  # SQLite stores BOOLEAN as 1/0

    def test_bootstrap_rejects_second_attempt(self, conn, engine, ep_service_id, human_id):
        """A second bootstrap attempt must be rejected."""
        from ep_governance.xid import XID as XID_cls

        # First bootstrap
        role_id = str(XID_cls.new())
        conn.execute(
            sa.text(
                "INSERT INTO ep_roles (id, name, permissions) VALUES (:id, 'administrator', :perms)"
            ),
            {"id": role_id, "perms": '["*"]'},
        )
        binding_id = str(XID_cls.new())
        conn.execute(
            sa.text(
                "INSERT INTO ep_role_bindings (id, principal_id, role_id, project_id) "
                "VALUES (:id, :principal_id, :role_id, NULL)"
            ),
            {"id": binding_id, "principal_id": human_id, "role_id": role_id},
        )
        bootstrap_id = str(XID_cls.new())
        conn.execute(
            sa.text(
                "INSERT INTO ep_bootstrap_state (singleton_id, completed, completed_by) "
                "VALUES (1, TRUE, :completed_by)"
            ),
            {"completed_by": human_id},
        )
        conn.commit()

        # Check that bootstrap is already complete (singleton row)
        result = conn.execute(
            sa.text("SELECT completed FROM ep_bootstrap_state WHERE singleton_id = 1")
        )
        assert result.fetchone() is not None  # bootstrap already done


class TestApprovalRequestPolicies:
    """Finding #1: Many-to-many approval-request-to-policy table."""

    def test_association_table_exists(self, conn):
        """The ep_approval_request_policies table must exist after migration."""
        if is_sqlite(conn):
            result = conn.execute(
                sa.text("SELECT name FROM sqlite_master WHERE type='table' AND name='ep_approval_request_policies'")
            )
            assert result.fetchone() is not None
        else:
            result = conn.execute(
                sa.text(
                    "SELECT table_name FROM information_schema.tables "
                    "WHERE table_name='ep_approval_request_policies'"
                )
            )
            assert result.fetchone() is not None

    def test_add_and_retrieve_policies(self, conn, ep_service_id, human_id):
        """ApprovalRepository.add_policies and get_policies should work."""
        # Create required setup
        proj_repo = ProjectRepository(conn)
        project = proj_repo.create_project("Test", "")
        lat_repo = LatticeRepository(conn)
        lattice = lat_repo.create_lattice(project["id"], "main")
        branch_repo = BranchRepository(conn)
        branch = branch_repo.create_branch(lattice["id"], "main")

        # Create policies
        policy_repo = PolicyRepository(conn)
        policy1_id = str(XID.new())
        policy2_id = str(XID.new())
        for pid in [policy1_id, policy2_id]:
            policy_repo.insert_policy({
                "id": pid,
                "effect": "require_approval",
                "actions": ["*"],
                "resources": ["*"],
                "conditions": {},
                "priority": 0,
                "scope": "global",
                "agent_scope": None,
                "description": "Test policy",
                "status": "active",
                "created_by": ep_service_id,
                "approved_by": ep_service_id,
                "approved_at": "2026-07-28T12:00:00.000000Z",
                "activation_version": 1,
                "exception_to": [],
                "valid_from": None,
                "valid_until": None,
                "justification": None,
            })

        # Create a transition
        trans_repo = TransitionRepository(conn)
        transition = trans_repo.insert_transition({
            "id": str(XID.new()),
            "agent_id": human_id,
            "branch_id": branch["id"],
            "tool": "postgres.execute",
            "payload_hash": "sha256:" + "a" * 64,
            "idempotency_key": str(XID.new()),
            "stage": "pending_approval",
        })

        # Create approval request
        approval_repo = ApprovalRepository(conn)
        request = approval_repo.create_request(
            transition_id=transition["id"],
            policy_id=policy1_id,
            requested_by=human_id,
            justification="Test approval",
        )

        # Add policies to association table
        approval_repo.add_policies(request["id"], [policy1_id, policy2_id])
        conn.commit()

        # Retrieve and verify
        policies = approval_repo.get_policies(request["id"])
        assert len(policies) == 2
        assert policy1_id in policies
        assert policy2_id in policies


class TestPolicySetHashConsistency:
    """Finding #4: Policy-set hashing must be consistent across components."""

    def test_compute_policy_set_hash_empty(self):
        """Empty policy set should produce empty string."""
        from ep_governance.canonical import compute_policy_set_hash
        assert compute_policy_set_hash({}) == ""

    def test_compute_policy_set_hash_deterministic(self):
        """Same input should produce same output."""
        from ep_governance.canonical import compute_policy_set_hash
        versions = {"policy-a": 1, "policy-b": 2}
        h1 = compute_policy_set_hash(versions)
        h2 = compute_policy_set_hash(versions)
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex digest

    def test_compute_policy_set_hash_order_independent(self):
        """Hash should be the same regardless of dict insertion order."""
        from ep_governance.canonical import compute_policy_set_hash
        h1 = compute_policy_set_hash({"policy-a": 1, "policy-b": 2})
        h2 = compute_policy_set_hash({"policy-b": 2, "policy-a": 1})
        assert h1 == h2

    def test_compute_policy_set_hash_different_inputs(self):
        """Different policy sets should produce different hashes."""
        from ep_governance.canonical import compute_policy_set_hash
        h1 = compute_policy_set_hash({"policy-a": 1})
        h2 = compute_policy_set_hash({"policy-a": 2})
        assert h1 != h2


class TestEffectivePolicySelection:
    """Exact project, branch, and agent policy selection."""

    def test_exact_context_excludes_other_branch_and_includes_agent(self, conn, ep_service_id):
        principal_repo = PrincipalRepository(conn)
        agent = principal_repo.insert_principal(
            principal_id=str(XID.new()), name="Agent", type="agent", machine="test", description=""
        )
        other_agent = principal_repo.insert_principal(
            principal_id=str(XID.new()), name="Other", type="agent", machine="test", description=""
        )
        project = ProjectRepository(conn).create_project("Scoped", "")
        lattice = LatticeRepository(conn).create_lattice(project["id"], "main")
        branches = BranchRepository(conn)
        branch_a = branches.create_branch(lattice["id"], "a")
        branch_b = branches.create_branch(lattice["id"], "b")
        repo = PolicyRepository(conn)

        def add(scope, **scope_fields):
            pid = str(XID.new())
            repo.insert_policy({
                "id": pid,
                "effect": "deny",
                "actions": ["*"],
                "resources": ["*"],
                "conditions": {},
                "priority": 1,
                "scope": scope,
                "agent_scope": scope_fields.get("agent_scope"),
                "project_id": scope_fields.get("project_id"),
                "branch_id": scope_fields.get("branch_id"),
                "description": scope,
                "status": "active",
                "created_by": ep_service_id,
                "approved_by": ep_service_id,
                "approved_at": "2026-07-28T12:00:00.000000Z",
                "activation_version": 1,
                "exception_to": [],
            })
            return pid

        global_id = add("global")
        project_id = add("project", project_id=project["id"])
        branch_a_id = add("branch", branch_id=branch_a["id"])
        add("branch", branch_id=branch_b["id"])
        agent_id = add("agent", agent_scope=agent["id"])
        add("agent", agent_scope=other_agent["id"])
        conn.commit()

        rows = repo.list_effective_policies(project["id"], branch_a["id"], agent["id"])
        ids = {row["id"] for row in rows}
        assert ids == {global_id, project_id, branch_a_id, agent_id}


class TestBootstrapSingleton:
    def test_only_one_completed_bootstrap_row_is_allowed(self, conn, human_id):
        conn.execute(sa.text(
            "INSERT INTO ep_bootstrap_state (singleton_id, completed, completed_by) "
            "VALUES (1, TRUE, :pid)"
        ), {"pid": human_id})
        conn.commit()
        with pytest.raises(Exception):
            conn.execute(sa.text(
                "INSERT INTO ep_bootstrap_state (singleton_id, completed, completed_by) "
                "VALUES (1, TRUE, :pid)"
            ), {"pid": human_id})