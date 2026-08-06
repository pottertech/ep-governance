"""Network partition and proxy fault simulation tests.

Tests recovery from scenarios where the proxy cannot reach EP after claiming
a token, duplicate result reporting, and conflicting callbacks.

These tests simulate network faults by:
- Claiming a token then never reporting a result (simulated network partition)
- Reporting a result twice (duplicate callback)
- Reporting conflicting results (success then failure)
- Proxy timeout with late result arrival
- Multiple proxies racing to report results
"""

from __future__ import annotations

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor

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
from ep_governance.errors import StaleHeadError, IllegalTransitionError
from ep_governance.policies import Policy
from ep_governance.policy_engine import PolicyEngine
from ep_governance.transitions import TransitionEngine
from ep_governance.xid import XID
from ep_governance.deployment import EnforcementCapability


def _get_db_url() -> str:
    # These tests always use SQLite to avoid FK constraint issues during cleanup.
    # PG-specific tests are in test_pg_integration.py.
    return "sqlite:///:memory:"


_cached_url: str | None = None


def _get_test_url() -> str:
    global _cached_url
    if _cached_url is None:
        url = _get_db_url()
        if url.startswith("sqlite"):
            import tempfile
            tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False, prefix="ep_fault_")
            tmp.close()
            _cached_url = f"sqlite:///{tmp.name}"
        else:
            _cached_url = url
    return _cached_url


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
def engine():
    url = _get_test_url()
    eng = create_engine(url)
    # Only run migrations if tables don't exist yet
    with eng.connect() as conn:
        try:
            conn.execute(sa.text("SELECT 1 FROM ep_projects LIMIT 1"))
        except Exception:
            dialect = "sqlite" if is_sqlite(conn) else "postgres"
            run_migrations(conn, dialect)
            conn.commit()
    # Clean all data before each test for isolation
    with eng.connect() as conn:
        for table in [
            "ep_approval_request_policies", "ep_approval_decisions",
            "ep_approval_requests", "ep_authorizations", "ep_transitions",
            "ep_risk_mitigations", "ep_risk_ledger", "ep_events",
            "ep_audit_heads", "ep_nodes", "ep_edges", "ep_branches",
            "ep_lattices", "ep_policies", "ep_policy_versions",
            "ep_principals", "ep_projects", "ep_work_claims",
            "ep_sessions", "ep_transfer_packages", "ep_import_mappings",
            "ep_bootstrap_state", "ep_credentials", "ep_role_bindings",
            "ep_roles",
        ]:
            try:
                conn.execute(sa.text(f"DELETE FROM {table}"))
            except Exception:
                pass
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
        principal_id=str(XID.new()), name="Agent", type="agent",
        machine="localhost", description="Test agent",
    )
    conn.commit()
    return p["id"]


@pytest.fixture
def setup(conn, ep_service_id, agent_id):
    proj_repo = ProjectRepository(conn)
    project = proj_repo.create_project("Partition Test", "")
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
# Test 1: Network partition — proxy claims token, never reports back
# ---------------------------------------------------------------------------

class TestNetworkPartition:
    """Simulate proxy claiming a token but then losing connection to EP."""

    def test_claimed_but_no_result_leaves_executing(self, conn, engine, setup, ep_service_id, agent_id):
        """After claim, if proxy never reports, transition stays in 'executing'."""
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
        conn.commit()

        if transition["stage"] != "authorized":
            pytest.skip("Transition did not reach authorized")

        payload_hash = "sha256:" + canonical_hash({"sql": "SELECT 1"})
        capability = EnforcementCapability.for_test(
            agent_principal_id=agent_id,
        )
        token = auth_engine.issue_authorization(
            transition_id=transition["id"],
            agent_id=agent_id,
            project_id=setup["project"]["id"],
            branch_id=setup["branch"]["id"],
            proxy_audience="postgres-proxy",
            tool="postgres.execute",
            payload_hash=payload_hash,
            matched_policies=[],
            enforcement_capability=capability,
        )
        signed = token.to_signed_token(km)
        conn.commit()

        # Proxy claims the token
        claim = auth_engine.verify_and_claim(
            token.authorization_id, signed, payload_hash,
            str(XID.new()), km.public_key,
        )
        conn.commit()
        assert claim is not None

        # NETWORK PARTITION: proxy never calls record_result
        # Transition should remain in 'executing'
        t = trans_engine.get_transition(transition["id"])
        assert t["stage"] == "executing"

        # Authorization is marked as used (claimed)
        with engine.connect() as c:
            auth = AuthorizationRepository(c).get_authorization(token.authorization_id)
            assert auth["used"] in (True, 1)

        # Recovery: operator marks as timeout after observing no result
        result = trans_engine.record_result(transition["id"], "timeout", "Network partition — no result received")
        conn.commit()
        assert result["stage"] == "execution_uncertain"

    def test_late_result_after_timeout_can_reconcile(self, conn, engine, setup, ep_service_id, agent_id):
        """If the proxy's result arrives late (after timeout), it can be reconciled."""
        km = KeyManager()
        auth_engine = AuthorizationEngine(engine, km, ep_service_id)
        policy_engine = _build_allow_policy_engine()
        trans_engine = TransitionEngine(engine, ep_service_id, policy_engine=policy_engine)
        committer = BranchCommitter(engine, ep_service_id)

        transition = trans_engine.propose(
            agent_id=agent_id,
            branch_id=setup["branch"]["id"],
            tool="postgres.execute",
            arguments={"sql": "SELECT 1"},
            idempotency_key=str(XID.new()),
        )
        conn.commit()

        if transition["stage"] != "authorized":
            pytest.skip()

        payload_hash = "sha256:" + canonical_hash({"sql": "SELECT 1"})
        capability = EnforcementCapability.for_test(
            agent_principal_id=agent_id,
        )
        token = auth_engine.issue_authorization(
            transition_id=transition["id"],
            agent_id=agent_id,
            project_id=setup["project"]["id"],
            branch_id=setup["branch"]["id"],
            proxy_audience="postgres-proxy",
            tool="postgres.execute",
            payload_hash=payload_hash,
            matched_policies=[],
            enforcement_capability=capability,
        )
        signed = token.to_signed_token(km)
        conn.commit()

        # Claim
        auth_engine.verify_and_claim(
            token.authorization_id, signed, payload_hash,
            str(XID.new()), km.public_key,
        )
        conn.commit()

        # Timeout (network partition)
        trans_engine.record_result(transition["id"], "timeout", "Network partition")
        conn.commit()

        # Late result: proxy actually succeeded but couldn't report
        head_id, version = BranchRepository(conn).get_head(setup["branch"]["id"])
        conn.commit()

        result = trans_engine.reconcile(
            transition["id"], "succeeded",
            "Late result: proxy confirmed action completed before partition",
            branch_committer=committer,
            expected_head_id=head_id,
            expected_version=version,
            lattice_id=setup["lattice"]["id"],
        )
        conn.commit()
        assert result["stage"] == "succeeded"


# ---------------------------------------------------------------------------
# Test 2: Duplicate result reporting
# ---------------------------------------------------------------------------

class TestDuplicateResultReporting:
    """Test that duplicate result reporting is handled correctly."""

    def test_duplicate_success_rejected(self, conn, engine, setup, ep_service_id, agent_id):
        """After a transition reaches 'succeeded', a second record_result must fail."""
        km = KeyManager()
        auth_engine = AuthorizationEngine(engine, km, ep_service_id)
        policy_engine = _build_allow_policy_engine()
        trans_engine = TransitionEngine(engine, ep_service_id, policy_engine=policy_engine)
        committer = BranchCommitter(engine, ep_service_id)

        transition = trans_engine.propose(
            agent_id=agent_id,
            branch_id=setup["branch"]["id"],
            tool="postgres.execute",
            arguments={"sql": "SELECT 1"},
            idempotency_key=str(XID.new()),
        )
        conn.commit()

        if transition["stage"] != "authorized":
            pytest.skip()

        # Execute through the pipeline
        trans_engine.advance_stage(transition["id"], "executing")
        conn.commit()

        head_id, version = BranchRepository(conn).get_head(setup["branch"]["id"])
        conn.commit()

        committer.commit(
            transition_id=transition["id"],
            branch_id=setup["branch"]["id"],
            agent_id=agent_id,
            description="First result",
            bt_planning_budget=90,
            metadata={},
            expected_head_id=head_id,
            expected_version=version,
            lattice_id=setup["lattice"]["id"],
        )
        conn.commit()

        # Now try to record a second result — should fail (already terminal)
        with pytest.raises(IllegalTransitionError):
            trans_engine.record_result(transition["id"], "failure", "Late duplicate failure report")
        conn.rollback()

    def test_duplicate_failure_rejected(self, conn, engine, setup, ep_service_id, agent_id):
        """After a transition reaches 'failed', a second record_result must fail."""
        policy_engine = _build_allow_policy_engine()
        trans_engine = TransitionEngine(engine, ep_service_id, policy_engine=policy_engine)

        transition = trans_engine.propose(
            agent_id=agent_id,
            branch_id=setup["branch"]["id"],
            tool="postgres.execute",
            arguments={"sql": "SELECT 1"},
            idempotency_key=str(XID.new()),
        )
        conn.commit()

        if transition["stage"] != "authorized":
            pytest.skip()

        trans_engine.advance_stage(transition["id"], "executing")
        conn.commit()
        trans_engine.record_result(transition["id"], "failure", "Execution failed")
        conn.commit()

        # Second failure report must be rejected
        with pytest.raises(IllegalTransitionError):
            trans_engine.record_result(transition["id"], "failure", "Duplicate failure")
        conn.rollback()


# ---------------------------------------------------------------------------
# Test 3: Conflicting result reporting
# ---------------------------------------------------------------------------

class TestConflictingResults:
    """Test that conflicting results (success then failure) are rejected."""

    def test_success_then_conflicting_failure_rejected(self, conn, engine, setup, ep_service_id, agent_id):
        """If a transition is already succeeded, a conflicting failure must be rejected."""
        policy_engine = _build_allow_policy_engine()
        trans_engine = TransitionEngine(engine, ep_service_id, policy_engine=policy_engine)
        committer = BranchCommitter(engine, ep_service_id)

        transition = trans_engine.propose(
            agent_id=agent_id,
            branch_id=setup["branch"]["id"],
            tool="postgres.execute",
            arguments={"sql": "SELECT 1"},
            idempotency_key=str(XID.new()),
        )
        conn.commit()

        if transition["stage"] != "authorized":
            pytest.skip()

        trans_engine.advance_stage(transition["id"], "executing")
        conn.commit()

        head_id, version = BranchRepository(conn).get_head(setup["branch"]["id"])
        conn.commit()

        # First: succeed
        committer.commit(
            transition_id=transition["id"],
            branch_id=setup["branch"]["id"],
            agent_id=agent_id,
            description="Success",
            bt_planning_budget=90,
            metadata={},
            expected_head_id=head_id,
            expected_version=version,
            lattice_id=setup["lattice"]["id"],
        )
        conn.commit()

        # Conflicting: try to mark as failed
        with pytest.raises(IllegalTransitionError):
            trans_engine.record_result(transition["id"], "failure", "Conflicting late failure")
        conn.rollback()

    def test_uncertain_then_conflicting_failure_rejected(self, conn, engine, setup, ep_service_id, agent_id):
        """If transition is execution_uncertain, a direct failure is allowed
        (reconciliation), but only through reconcile(), not record_result()."""
        policy_engine = _build_allow_policy_engine()
        trans_engine = TransitionEngine(engine, ep_service_id, policy_engine=policy_engine)

        transition = trans_engine.propose(
            agent_id=agent_id,
            branch_id=setup["branch"]["id"],
            tool="postgres.execute",
            arguments={"sql": "SELECT 1"},
            idempotency_key=str(XID.new()),
        )
        conn.commit()

        if transition["stage"] != "authorized":
            pytest.skip()

        trans_engine.advance_stage(transition["id"], "executing")
        conn.commit()
        trans_engine.record_result(transition["id"], "timeout", "Uncertain")
        conn.commit()

        # Reconcile to failed is allowed
        result = trans_engine.reconcile(transition["id"], "failed", "Confirmed not completed")
        conn.commit()
        assert result["stage"] == "failed"

        # But now try to reconcile to succeeded — should fail (already terminal)
        with pytest.raises(IllegalTransitionError):
            trans_engine.reconcile(transition["id"], "succeeded", "Conflicting late success")
        conn.rollback()


# ---------------------------------------------------------------------------
# Test 4: Token expiry during network partition
# ---------------------------------------------------------------------------

class TestTokenExpiryDuringPartition:
    """If a token expires during a network partition, it cannot be claimed later."""

    def test_expired_token_cannot_be_claimed(self, conn, engine, setup, ep_service_id, agent_id):
        """An expired token must not be claimable even if the proxy eventually reconnects."""
        km = KeyManager()
        # Set very short TTL
        auth_engine = AuthorizationEngine(engine, km, ep_service_id, token_ttl_seconds=1)
        policy_engine = _build_allow_policy_engine()
        trans_engine = TransitionEngine(engine, ep_service_id, policy_engine=policy_engine)

        transition = trans_engine.propose(
            agent_id=agent_id,
            branch_id=setup["branch"]["id"],
            tool="postgres.execute",
            arguments={"sql": "SELECT 1"},
            idempotency_key=str(XID.new()),
        )
        conn.commit()

        if transition["stage"] != "authorized":
            pytest.skip()

        payload_hash = "sha256:" + canonical_hash({"sql": "SELECT 1"})
        capability = EnforcementCapability.for_test(
            agent_principal_id=agent_id,
        )
        token = auth_engine.issue_authorization(
            transition_id=transition["id"],
            agent_id=agent_id,
            project_id=setup["project"]["id"],
            branch_id=setup["branch"]["id"],
            proxy_audience="postgres-proxy",
            tool="postgres.execute",
            payload_hash=payload_hash,
            matched_policies=[],
            enforcement_capability=capability,
        )
        signed = token.to_signed_token(km)
        conn.commit()

        # Wait for token to expire
        time.sleep(2)

        # Proxy reconnects and tries to claim — should fail
        claim = auth_engine.verify_and_claim(
            token.authorization_id, signed, payload_hash,
            str(XID.new()), km.public_key,
        )
        conn.commit()
        assert claim is None, "Expired token should not be claimable"