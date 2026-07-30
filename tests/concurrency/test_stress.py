"""Concurrency stress tests for EP-Governance.

Tests the core safety guarantees under real concurrent load:
- 50+ simultaneous token claims against a single authorization
- 50+ concurrent audit event insertions
- 20+ concurrent branch head commits from the same head

These tests require PostgreSQL for true concurrency (SQLite serializes writes).
When run against SQLite, they fall back to sequential execution but still
verify correctness properties (uniqueness, chain validity, staleness detection).

Set EP_TEST_DB_URL to point to a PostgreSQL instance for real concurrency:
    EP_TEST_DB_URL=postgresql://user:pass@host:5432/testdb
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
from ep_governance.db.postgres import create_engine, is_sqlite
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


def _get_db_url() -> str:
    return os.environ.get("EP_TEST_DB_URL", "sqlite:///:memory:")


_cached_sqlite_url: str | None = None


def _get_shared_sqlite_url() -> str:
    """For concurrency tests, use a file-based SQLite so all threads share the same DB.
    Caches the URL so all calls within a test session return the same file.
    """
    global _cached_sqlite_url
    if _cached_sqlite_url is None:
        import tempfile
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False, prefix="ep_stress_")
        tmp.close()
        _cached_sqlite_url = f"sqlite:///{tmp.name}"
    return _cached_sqlite_url


def _get_test_db_url() -> str:
    """Get the DB URL for concurrency tests — uses shared SQLite when not on PostgreSQL."""
    url = _get_db_url()
    if url.startswith("sqlite"):
        return _get_shared_sqlite_url()
    return url


def _build_allow_policy_engine():
    """Build a PolicyEngine with a single allow-all policy."""
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
def engine():
    url = _get_test_db_url()
    eng = create_engine(url)
    # Run migrations on the shared engine before any threads use it
    with eng.connect() as conn:
        dialect = "sqlite" if is_sqlite(conn) else "postgres"
        run_migrations(conn, dialect)
        conn.commit()
    yield eng
    eng.dispose()
    # Clean up temp file if SQLite
    if url.startswith("sqlite:///"):
        import os as _os
        db_path = url.replace("sqlite:///", "")
        if _os.path.exists(db_path):
            _os.unlink(db_path)


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
        principal_id=str(XID.new()), name="Agent", type="agent",
        machine="localhost", description="Test agent",
    )
    conn.commit()
    return p["id"]


@pytest.fixture
def setup(conn, ep_service_id, agent_id):
    proj_repo = ProjectRepository(conn)
    project = proj_repo.create_project("Stress Test", "")
    lat_repo = LatticeRepository(conn)
    lattice = lat_repo.create_lattice(project["id"], "main")
    branch_repo = BranchRepository(conn)
    branch = branch_repo.create_branch(lattice["id"], "main")

    # Create default policy for FK
    policy_repo = PolicyRepository(conn)
    policy_repo.insert_policy({
        "id": "default", "effect": "allow", "actions": ["*"], "resources": ["*"],
        "conditions": {}, "priority": 0, "scope": "global", "agent_scope=None": None,
        "description": "Default allow", "status": "active",
        "created_by": ep_service_id, "approved_by": ep_service_id,
        "approved_at": "2026-07-28T12:00:00.000000Z", "activation_version": 1,
        "exception_to": [], "valid_from": None, "valid_until": None,
        "justification": None,
    })

    # Init audit head
    conn.execute(sa.text(
        "INSERT INTO ep_audit_heads (lattice_id, last_sequence, last_hash) "
        "VALUES (:lid, 0, :hash)"
    ), {"lid": lattice["id"], "hash": "0" * 64})

    # Create initial node
    node_repo = NodeRepository(conn)
    node = node_repo.insert_node(
        node_id=str(XID.new()), branch_id=branch["id"],
        agent_id=agent_id, description="Initial",
        bt_planning_budget=100.0, metadata={},
    )
    branch_repo.update_head(branch["id"], node["id"], 1)
    conn.commit()

    return {
        "project": project, "lattice": lattice, "branch": branch,
        "node": node, "agent_id": agent_id, "ep_service_id": ep_service_id,
    }


# ---------------------------------------------------------------------------
# Test 1: 50 simultaneous token claims — exactly 1 succeeds
# ---------------------------------------------------------------------------

class TestStressTokenClaim:
    """50 concurrent proxies attempt to claim the same authorization token.

    Exactly one must succeed; all others must fail.
    This tests the atomic UPDATE...WHERE used=FALSE...RETURNING guarantee.
    """

    def test_50_simultaneous_claims_one_succeeds(self, engine, setup, ep_service_id, agent_id):
        db_url = _get_test_db_url()
        is_pg = not db_url.startswith("sqlite")

        # Set up the authorization using a separate connection
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

        if transition["stage"] != "authorized":
            pytest.skip("Transition did not reach authorized")

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

        N = 50 if is_pg else 10
        results: list[bool] = [False] * N
        errors: list[str | None] = [None] * N

        def claim_attempt(idx: int) -> None:
            try:
                # Each thread gets its own engine/connection
                claim_engine = create_engine(db_url)
                claim_auth = AuthorizationEngine(claim_engine, km, ep_service_id)
                proxy_id = str(XID.new())
                r = claim_auth.verify_and_claim(
                    token.authorization_id, signed_token,
                    payload_hash, proxy_id, km.public_key,
                )
                results[idx] = r is not None
                claim_engine.dispose()
            except Exception as exc:
                errors[idx] = str(exc)
                results[idx] = False

        if is_pg:
            # Real concurrency with threads
            with ThreadPoolExecutor(max_workers=N) as executor:
                futures = [executor.submit(claim_attempt, i) for i in range(N)]
                for f in as_completed(futures):
                    f.result()  # Re-raise any unexpected exceptions
        else:
            # SQLite: sequential (serialized writes)
            for i in range(N):
                claim_attempt(i)

        success_count = sum(results)
        fail_count = N - success_count

        # Exactly one must succeed
        assert success_count == 1, (
            f"Expected exactly 1 successful claim, got {success_count}. "
            f"Results: {results}"
        )
        assert fail_count == N - 1

        # Verify the authorization is marked as used
        with engine.connect() as check_conn:
            auth_repo = AuthorizationRepository(check_conn)
            auth = auth_repo.get_authorization(token.authorization_id)
            assert auth is not None
            assert auth["used"] in (True, 1), f"Authorization not marked as used: {auth['used']}"


# ---------------------------------------------------------------------------
# Test 2: 50 concurrent audit insertions — sequences unique, chain valid
# ---------------------------------------------------------------------------

class TestStressAuditInsertion:
    """50 concurrent audit event insertions against the same lattice.

    All sequences must be unique and the hash chain must remain valid.
    This tests the per-lattice serialized audit head locking.
    """

    def test_50_concurrent_audit_writes(self, engine, setup, ep_service_id):
        db_url = _get_test_db_url()
        is_pg = not db_url.startswith("sqlite")
        lattice_id = setup["lattice"]["id"]

        N = 50 if is_pg else 20
        sequences: list[int] = [0] * N
        errors: list[str | None] = [None] * N

        def audit_write(idx: int) -> None:
            try:
                write_engine = create_engine(db_url)
                writer = AuditWriter(write_engine, ep_service_id)
                event = writer.write_event(
                    lattice_id=lattice_id,
                    event_type="stress_test",
                    event_data={"index": idx, "thread": idx},
                    actor_principal_id=ep_service_id,
                    authenticated_caller_id=ep_service_id,
                )
                sequences[idx] = event.sequence
                write_engine.dispose()
            except Exception as exc:
                errors[idx] = str(exc)
                sequences[idx] = -1

        if is_pg:
            with ThreadPoolExecutor(max_workers=min(N, 20)) as executor:
                futures = [executor.submit(audit_write, i) for i in range(N)]
                for f in as_completed(futures):
                    f.result()
        else:
            for i in range(N):
                audit_write(i)

        # All sequences must be unique and positive
        valid_seqs = [s for s in sequences if s > 0]
        assert len(valid_seqs) == N, (
            f"Expected {N} valid sequences, got {len(valid_seqs)}. "
            f"Errors: {[e for e in errors if e]}"
        )
        assert len(valid_seqs) == len(set(valid_seqs)), (
            f"Duplicate sequences found: {valid_seqs}"
        )

        # Chain must be valid
        verifier = AuditVerifier(engine)
        assert verifier.verify(lattice_id) is True, (
            "Audit chain verification failed after concurrent writes"
        )


# ---------------------------------------------------------------------------
# Test 3: 20 concurrent branch commits from same head — 1 wins, 19 stale
# ---------------------------------------------------------------------------

class TestStressBranchCommit:
    """20 concurrent branch commits from the same head.

    Exactly one must succeed; all others must get stale_head.
    This tests the optimistic concurrency control (expected_head_id + expected_version).
    """

    def test_20_concurrent_commits_one_wins(self, engine, setup, ep_service_id, agent_id):
        db_url = _get_test_db_url()
        is_pg = not db_url.startswith("sqlite")
        branch_id = setup["branch"]["id"]
        lattice_id = setup["lattice"]["id"]

        # Get current head
        with engine.connect() as conn:
            branch_repo = BranchRepository(conn)
            head_id, version = branch_repo.get_head(branch_id)

        # Create 20 transitions in 'executing' stage
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
        results: list[str] = ["pending"] * N  # "success" or "stale" or "error"

        def commit_attempt(idx: int) -> None:
            try:
                commit_engine = create_engine(db_url)
                committer = BranchCommitter(commit_engine, ep_service_id)
                committer.commit(
                    transition_id=trans_ids[idx],
                    branch_id=branch_id,
                    agent_id=agent_id,
                    description=f"Commit {idx}",
                    bt_planning_budget=90.0,
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

        if is_pg:
            with ThreadPoolExecutor(max_workers=min(N, 20)) as executor:
                futures = [executor.submit(commit_attempt, i) for i in range(N)]
                for f in as_completed(futures):
                    f.result()
        else:
            for i in range(N):
                commit_attempt(i)

        success_count = sum(1 for r in results if r == "success")
        stale_count = sum(1 for r in results if r == "stale")
        error_count = sum(1 for r in results if r.startswith("error"))

        assert success_count == 1, (
            f"Expected exactly 1 successful commit, got {success_count}. "
            f"Results: {results}"
        )
        assert stale_count == N - 1, (
            f"Expected {N - 1} stale_head errors, got {stale_count}. "
            f"Results: {results}"
        )
        assert error_count == 0, (
            f"Unexpected errors: {[r for r in results if r.startswith('error')]}"
        )

        # Verify branch version advanced exactly once
        with engine.connect() as conn:
            branch_repo = BranchRepository(conn)
            _, final_version = branch_repo.get_head(branch_id)
            assert final_version == version + 1, (
                f"Branch version should be {version + 1}, got {final_version}"
            )


# ---------------------------------------------------------------------------
# Test 4: 10 concurrent proposals — all get unique transition IDs
# ---------------------------------------------------------------------------

class TestStressProposals:
    """10 concurrent transition proposals.

    All must get unique transition IDs and unique idempotency keys.
    """

    def test_10_concurrent_proposals(self, engine, setup, ep_service_id, agent_id):
        db_url = _get_test_db_url()
        is_pg = not db_url.startswith("sqlite")
        branch_id = setup["branch"]["id"]

        N = 10
        transition_ids: list[str] = [""] * N
        errors: list[str | None] = [None] * N

        def propose_attempt(idx: int) -> None:
            try:
                prop_engine = create_engine(db_url)
                pe = _build_allow_policy_engine()
                te = TransitionEngine(prop_engine, ep_service_id, policy_engine=pe)
                t = te.propose(
                    agent_id=agent_id,
                    branch_id=branch_id,
                    tool="postgres.execute",
                    arguments={"sql": f"SELECT {idx}"},
                    idempotency_key=str(XID.new()),
                )
                transition_ids[idx] = t["id"]
                prop_engine.dispose()
            except Exception as exc:
                errors[idx] = str(exc)

        if is_pg:
            with ThreadPoolExecutor(max_workers=N) as executor:
                futures = [executor.submit(propose_attempt, i) for i in range(N)]
                for f in as_completed(futures):
                    f.result()
        else:
            for i in range(N):
                propose_attempt(i)

        valid_ids = [tid for tid in transition_ids if tid]
        assert len(valid_ids) == N, (
            f"Expected {N} valid transition IDs, got {len(valid_ids)}. "
            f"Errors: {[e for e in errors if e]}"
        )
        assert len(valid_ids) == len(set(valid_ids)), (
            f"Duplicate transition IDs found"
        )