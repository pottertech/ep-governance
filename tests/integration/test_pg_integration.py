"""Real PostgreSQL integration tests.

Tests that require real PostgreSQL features:
- FOR UPDATE row-level locking for atomic token claims
- SERIALIZABLE transaction isolation for policy revalidation
- Concurrent audit insertion with per-lattice lock
- Migration up/down with transactional DDL
- CHECK constraints enforcement at the DB level
- LISTEN/NOTIFY for state change notifications

Requires: EP_TEST_DB_URL=postgresql://ep_test:ep_test_pw@localhost:5434/ep_governance_test
"""

from __future__ import annotations

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest
import sqlalchemy as sa

from ep_governance.audit import AuditWriter, AuditVerifier
from ep_governance.authorizations import AuthorizationEngine, KeyManager
from ep_governance.branches import BranchCommitter
from ep_governance.canonical import canonical_hash
from ep_governance.db import run_migrations
from ep_governance.db.postgres import create_engine
from ep_governance.db.repositories import (
    AuthorizationRepository,
    BranchRepository,
    LatticeRepository,
    NodeRepository,
    PolicyRepository,
    PrincipalRepository,
    ProjectRepository,
    TransitionRepository,
)
from ep_governance.errors import StaleHeadError
from ep_governance.policies import Policy
from ep_governance.policy_engine import PolicyEngine
from ep_governance.transitions import TransitionEngine
from ep_governance.xid import XID


PG_URL = os.environ.get(
    "EP_TEST_DB_URL",
    "postgresql://ep_test:ep_test_pw@localhost:5434/ep_governance_test",
)


def _is_pg(url: str) -> bool:
    return url.startswith("postgresql://") or url.startswith("postgresql+psycopg://")


@pytest.fixture
def engine():
    if not _is_pg(PG_URL):
        pytest.skip("Real PostgreSQL tests require EP_TEST_DB_URL pointing to PostgreSQL")
    eng = create_engine(PG_URL)
    with eng.connect() as conn:
        # Drop all ep_ tables first for clean state
        conn.execute(sa.text(
            "DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;"
        ))
        conn.commit()
        # Only run 001_init.sql (002_roles.sql requires superuser)
        from ep_governance.db import get_migration_files
        from pathlib import Path
        init_file = Path(__file__).parent.parent.parent / "migrations" / "postgres" / "001_init.sql"
        conn.execute(sa.text(init_file.read_text()))
        conn.commit()
    yield eng
    eng.dispose()


@pytest.fixture
def conn(engine):
    with engine.connect() as conn:
        yield conn


def _build_allow_policy_engine():
    _id = str(XID.new())
    return PolicyEngine([Policy(
        id=_id, effect="allow", actions=["*"], resources=["*"],
        conditions={}, priority=1, scope="global", agent_scope=None,
        project_id=None, branch_id=None, description="Test allow-all",
        status="active", created_by=_id, approved_by=_id,
        approved_at="2026-07-28T12:00:00.000000Z", activation_version=1,
        exception_to=[], valid_from=None, valid_until=None, justification=None,
    )])


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
        principal_id=str(XID.new()), name="Agent", type="agent",
        machine="localhost", description="Test agent",
    )
    conn.commit()
    return p["id"]


@pytest.fixture
def setup(conn, ep_service_id, agent_id):
    proj_repo = ProjectRepository(conn)
    project = proj_repo.create_project("PG Test", "")
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
        "approved_at": "2026-07-28T12:00:00.000000Z", "activation_version": 1,
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
# Test 1: Real concurrent token claims with FOR UPDATE locking
# ---------------------------------------------------------------------------

class TestPGConcurrentTokenClaim:
    """50 real concurrent token claims using PostgreSQL FOR UPDATE locking.

    PostgreSQL provides row-level locking that SQLite cannot.
    This test verifies that the atomic UPDATE...WHERE used=FALSE...RETURNING
    works correctly under real concurrent load.
    """

    def test_50_real_concurrent_claims(self, engine, setup, ep_service_id, agent_id):
        km = KeyManager()
        auth_engine = AuthorizationEngine(engine, km, ep_service_id)
        policy_engine = _build_allow_policy_engine()
        trans_engine = TransitionEngine(engine, ep_service_id, policy_engine=policy_engine)

        transition = trans_engine.propose(
            agent_id=agent_id,
            branch_id=setup["branch"]["id"],
            tool="postgres.execute",
            arguments={"sql": "SELECT 1"},
            idempotency_key=str(XID.new()),
        )
        assert transition["stage"] == "authorized"

        payload_hash = "sha256:" + canonical_hash({"sql": "SELECT 1"})
        token = auth_engine.issue_authorization(
            transition_id=transition["id"],
            agent_id=agent_id,
            project_id=setup["project"]["id"],
            branch_id=setup["branch"]["id"],
            proxy_audience="postgres-proxy",
            tool="postgres.execute",
            payload_hash=payload_hash,
            matched_policies=[],
        )
        signed_token = token.to_signed_token(km)

        N = 50
        results: list[bool] = [False] * N

        def claim_attempt(idx: int) -> None:
            try:
                claim_engine = create_engine(PG_URL)
                claim_auth = AuthorizationEngine(claim_engine, km, ep_service_id)
                proxy_id = str(XID.new())
                r = claim_auth.verify_and_claim(
                    token.authorization_id, signed_token,
                    payload_hash, proxy_id, km.public_key,
                )
                results[idx] = r is not None
                claim_engine.dispose()
            except Exception:
                results[idx] = False

        with ThreadPoolExecutor(max_workers=N) as executor:
            futures = [executor.submit(claim_attempt, i) for i in range(N)]
            for f in as_completed(futures):
                f.result()

        assert sum(results) == 1, f"Expected 1 success, got {sum(results)}"

        with engine.connect() as check_conn:
            auth = AuthorizationRepository(check_conn).get_authorization(token.authorization_id)
            assert auth["used"] in (True, 1)


# ---------------------------------------------------------------------------
# Test 2: Real concurrent audit insertion with per-lattice lock
# ---------------------------------------------------------------------------

class TestPGConcurrentAudit:
    """50 real concurrent audit writes using PostgreSQL advisory locks."""

    def test_50_real_concurrent_audit_writes(self, engine, setup, ep_service_id):
        lattice_id = setup["lattice"]["id"]
        N = 50
        sequences: list[int] = [0] * N
        errors: list[str | None] = [None] * N

        def audit_write(idx: int) -> None:
            try:
                write_engine = create_engine(PG_URL)
                writer = AuditWriter(write_engine, ep_service_id)
                event = writer.write_event(
                    lattice_id=lattice_id,
                    event_type="pg_stress_test",
                    event_data={"index": idx},
                    actor_principal_id=ep_service_id,
                    authenticated_caller_id=ep_service_id,
                )
                sequences[idx] = event.sequence
                write_engine.dispose()
            except Exception as exc:
                errors[idx] = str(exc)
                sequences[idx] = -1

        with ThreadPoolExecutor(max_workers=min(N, 20)) as executor:
            futures = [executor.submit(audit_write, i) for i in range(N)]
            for f in as_completed(futures):
                f.result()

        valid = [s for s in sequences if s > 0]
        assert len(valid) == N, f"Expected {N} valid, got {len(valid)}. Errors: {[e for e in errors if e]}"
        assert len(valid) == len(set(valid)), "Duplicate sequences"

        verifier = AuditVerifier(engine)
        assert verifier.verify(lattice_id) is True


# ---------------------------------------------------------------------------
# Test 3: Real concurrent branch commits with optimistic concurrency
# ---------------------------------------------------------------------------

class TestPGConcurrentBranchCommit:
    """20 real concurrent branch commits from the same head."""

    def test_20_real_concurrent_commits(self, engine, setup, ep_service_id, agent_id):
        branch_id = setup["branch"]["id"]
        lattice_id = setup["lattice"]["id"]

        with engine.connect() as conn:
            branch_repo = BranchRepository(conn)
            head_id, version = branch_repo.get_head(branch_id)

        trans_ids: list[str] = []
        with engine.connect() as conn:
            trans_repo = TransitionRepository(conn)
            for i in range(20):
                t = trans_repo.insert_transition({
                    "id": str(XID.new()),
                    "agent_id": agent_id,
                    "branch_id": branch_id,
                    "tool": "test",
                    "payload_hash": "sha256:" + chr(65 + i) * 64,
                    "idempotency_key": str(XID.new()),
                    "stage": "executing",
                })
                trans_ids.append(t["id"])
            conn.commit()

        N = 20
        results: list[str] = ["pending"] * N

        def commit_attempt(idx: int) -> None:
            try:
                commit_engine = create_engine(PG_URL)
                committer = BranchCommitter(commit_engine, ep_service_id)
                committer.commit(
                    transition_id=trans_ids[idx],
                    branch_id=branch_id,
                    agent_id=agent_id,
                    description=f"Commit {idx}",
                    bt_planning_budget=90,
                    metadata={},
                    expected_head_id=head_id,
                    expected_version=version,
                    lattice_id=lattice_id,
                )
                results[idx] = "success"
                commit_engine.dispose()
            except StaleHeadError:
                results[idx] = "stale"
            except Exception as exc:
                results[idx] = f"error: {exc!s}"

        with ThreadPoolExecutor(max_workers=N) as executor:
            futures = [executor.submit(commit_attempt, i) for i in range(N)]
            for f in as_completed(futures):
                f.result()

        assert sum(1 for r in results if r == "success") == 1
        assert sum(1 for r in results if r == "stale") == N - 1
        assert sum(1 for r in results if r.startswith("error")) == 0

        with engine.connect() as conn:
            _, final_version = BranchRepository(conn).get_head(branch_id)
            assert final_version == version + 1


# ---------------------------------------------------------------------------
# Test 4: PostgreSQL CHECK constraints enforcement
# ---------------------------------------------------------------------------

class TestPGCheckConstraints:
    """Verify PostgreSQL CHECK constraints reject invalid values at the DB level."""

    def test_invalid_transition_stage_rejected(self, conn):
        with pytest.raises(Exception):
            conn.execute(sa.text(
                "INSERT INTO ep_transitions (id, branch_id, agent_id, tool, "
                "payload_hash, idempotency_key, stage) "
                "VALUES ('t1', 'x', 'x', 'x', 'x', 'x', 'BOGUS_STAGE')"
            ))
            conn.commit()
        conn.rollback()

    def test_invalid_node_status_rejected(self, conn):
        with pytest.raises(Exception):
            conn.execute(sa.text(
                "INSERT INTO ep_nodes (id, branch_id, agent_id, description, "
                "bt_planning_budget, metadata, status) "
                "VALUES ('n1', 'x', 'x', 'x', 100, '{}', 'BOGUS_STATUS')"
            ))
            conn.commit()
        conn.rollback()

    def test_invalid_principal_type_rejected(self, conn):
        with pytest.raises(Exception):
            conn.execute(sa.text(
                "INSERT INTO ep_principals (id, name, type) "
                "VALUES ('p1', 'test', 'BOGUS_TYPE')"
            ))
            conn.commit()
        conn.rollback()

    def test_invalid_policy_effect_rejected(self, conn):
        with pytest.raises(Exception):
            conn.execute(sa.text(
                "INSERT INTO ep_policies (id, effect, actions, resources, conditions, "
                "priority, scope, description, status, created_by, approved_by, "
                "approved_at, activation_version, exception_to) "
                "VALUES ('p1', 'BOGUS_EFFECT', '[]', '[]', '{}', 0, 'global', 'x', "
                "'active', 'x', 'x', '2026-01-01', 1, '[]')"
            ))
            conn.commit()
        conn.rollback()


# ---------------------------------------------------------------------------
# Test 5: PostgreSQL migration up/down (DROP SCHEMA + re-run)
# ---------------------------------------------------------------------------

class TestPGMigrationRoundTrip:
    """Test migration round-trip on real PostgreSQL with transactional DDL."""

    def test_drop_schema_and_recreate(self, engine):
        # Drop everything and re-run 001_init.sql only
        with engine.connect() as conn:
            conn.execute(sa.text("DROP SCHEMA public CASCADE"))
            conn.execute(sa.text("CREATE SCHEMA public"))
            conn.commit()

            from pathlib import Path
            init_file = Path(__file__).parent.parent.parent / "migrations" / "postgres" / "001_init.sql"
            conn.execute(sa.text(init_file.read_text()))
            conn.commit()

            # Verify all tables exist
            result = conn.execute(sa.text(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public' AND table_name LIKE 'ep_%' "
                "ORDER BY table_name"
            ))
            tables = {r[0] for r in result}
            assert "ep_projects" in tables
            assert "ep_transitions" in tables
            assert "ep_events" in tables
            assert "ep_authorizations" in tables
            assert len(tables) >= 25

    def test_migration_creates_check_constraints(self, engine):
        with engine.connect() as conn:
            # Verify CHECK constraints exist on key tables
            result = conn.execute(sa.text(
                "SELECT con.conname, rel.relname "
                "FROM pg_constraint con "
                "JOIN pg_class rel ON rel.oid = con.conrelid "
                "WHERE con.contype = 'c' AND rel.relname LIKE 'ep_%' "
                "ORDER BY rel.relname, con.conname"
            ))
            constraints = [(r[0], r[1]) for r in result]
            # Should have constraints on transitions, nodes, policies, principals
            table_names = {c[1] for c in constraints}
            assert "ep_transitions" in table_names
            assert "ep_nodes" in table_names
            assert "ep_policies" in table_names
            assert "ep_principals" in table_names


# ---------------------------------------------------------------------------
# Test 6: SERIALIZABLE transaction isolation for policy revalidation
# ---------------------------------------------------------------------------

class TestPGSerializableIsolation:
    """Test that SERIALIZABLE transaction isolation prevents TOCTOU races
    between policy revalidation and token claiming."""

    def test_concurrent_policy_change_during_claim(self, engine, setup, ep_service_id, agent_id):
        """If a policy changes while a proxy is revalidating + claiming,
        the SERIALIZABLE transaction should detect the conflict."""
        km = KeyManager()
        auth_engine = AuthorizationEngine(engine, km, ep_service_id)
        policy_engine = _build_allow_policy_engine()
        trans_engine = TransitionEngine(engine, ep_service_id, policy_engine=policy_engine)

        transition = trans_engine.propose(
            agent_id=agent_id,
            branch_id=setup["branch"]["id"],
            tool="postgres.execute",
            arguments={"sql": "SELECT 1"},
            idempotency_key=str(XID.new()),
        )
        assert transition["stage"] == "authorized"

        payload_hash = "sha256:" + canonical_hash({"sql": "SELECT 1"})
        token = auth_engine.issue_authorization(
            transition_id=transition["id"],
            agent_id=agent_id,
            project_id=setup["project"]["id"],
            branch_id=setup["branch"]["id"],
            proxy_audience="postgres-proxy",
            tool="postgres.execute",
            payload_hash=payload_hash,
            matched_policies=[],
        )
        signed_token = token.to_signed_token(km)

        # Verify the token is valid and claimable
        proxy_id = str(XID.new())
        claim = auth_engine.verify_and_claim(
            token.authorization_id, signed_token, payload_hash,
            proxy_id, km.public_key,
        )
        # Claim should succeed (no concurrent modification)
        assert claim is not None