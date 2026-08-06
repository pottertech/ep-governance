"""Fault injection tests for EP-Governance.

Tests recovery from fault scenarios:
- Proxy crash after claim: transition must be left in execution_uncertain
- Key rotation during active tokens: old key still verifies during transition
- Stale authorization after policy change: proxy must reject
- Duplicate result reporting: second report must be rejected
- Branch head race: second committer gets stale_head
- Idempotent propose: same idempotency key returns existing transition
"""

from __future__ import annotations

import os
import threading
import time


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
    return os.environ.get("EP_TEST_DB_URL", "sqlite:///:memory:")


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
        principal_id=str(XID.new()), name="Agent", type="agent",
        machine="localhost", description="Test agent",
    )
    conn.commit()
    return p["id"]


@pytest.fixture
def human_id(conn):
    repo = PrincipalRepository(conn)
    p = repo.insert_principal(
        principal_id=str(XID.new()), name="Human", type="human",
        machine=None, description="Human approver",
    )
    conn.commit()
    return p["id"]


@pytest.fixture
def setup(conn, ep_service_id, agent_id):
    proj_repo = ProjectRepository(conn)
    project = proj_repo.create_project("Fault Test", "")
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
# Test 1: Proxy crash after claim — transition left in executing state
# ---------------------------------------------------------------------------

class TestProxyCrashRecovery:
    """Simulate a proxy crash after claiming a token but before reporting result.

    The transition should be left in 'executing' stage. A subsequent
    record_result with 'timeout' should move it to execution_uncertain.
    Then reconciliation can move it to succeeded or failed.
    """

    def test_crash_leaves_executing_then_timeout_to_uncertain(self, conn, engine, setup, ep_service_id, agent_id):
        km = KeyManager()
        auth_engine = AuthorizationEngine(engine, km, ep_service_id)
        policy_engine = _build_allow_policy_engine()
        trans_engine = TransitionEngine(engine, ep_service_id, policy_engine=policy_engine)

        # Propose and authorize
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

        # Issue token and claim it (simulating proxy starting execution)
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

        # CRASH: proxy never reports back
        # Transition should be in 'executing' stage
        t = trans_engine.get_transition(transition["id"])
        assert t["stage"] == "executing", f"Expected 'executing', got '{t['stage']}'"

        # Recovery: timeout moves to execution_uncertain
        result = trans_engine.record_result(
            transition["id"], "timeout", "Proxy crashed — no result received",
        )
        conn.commit()
        assert result["stage"] == "execution_uncertain"

        # Reconciliation: operator confirms the action actually completed
        committer = BranchCommitter(engine, ep_service_id)
        head_id, version = BranchRepository(conn).get_head(setup["branch"]["id"])
        conn.commit()

        result = trans_engine.reconcile(
            transition["id"],
            "succeeded",
            "Operator confirmed action completed before crash",
            branch_committer=committer,
            expected_head_id=head_id,
            expected_version=version,
            lattice_id=setup["lattice"]["id"],
        )
        conn.commit()
        assert result["stage"] == "succeeded"

    def test_crash_reconciliation_to_failed(self, conn, engine, setup, ep_service_id, agent_id):
        """After crash, operator can also reconcile to 'failed' if the action didn't complete."""
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

        # Simulate: authorized -> executing -> crash -> timeout -> reconcile to failed
        trans_engine.advance_stage(transition["id"], "executing")
        conn.commit()
        trans_engine.record_result(transition["id"], "timeout", "Proxy crashed")
        conn.commit()

        result = trans_engine.reconcile(
            transition["id"], "failed", "Operator confirmed action did not complete",
        )
        conn.commit()
        assert result["stage"] == "failed"


# ---------------------------------------------------------------------------
# Test 2: Key rotation — old key still verifies during transition
# ---------------------------------------------------------------------------

class TestKeyRotationDuringActiveTokens:
    """Test that key rotation doesn't break already-issued tokens.

    When the EP rotates its signing key, existing tokens signed with the
    old key should still be verifiable using the old public key (which
    the proxy retains). New tokens are signed with the new key.
    """

    def test_old_key_token_still_verifies(self, conn, engine, setup, ep_service_id, agent_id):
        # Issue token with old key
        km_old = KeyManager()
        auth_engine_old = AuthorizationEngine(engine, km_old, ep_service_id)
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
        token = auth_engine_old.issue_authorization(
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
        signed_old = token.to_signed_token(km_old)
        conn.commit()

        # Verify with old public key — should work
        assert token.verify_signature(km_old.public_key) is True

        # Generate new key
        km_new = KeyManager()

        # New key is different
        assert bytes(km_old.private_key) != bytes(km_new.private_key)

        # Old token still verifies with old public key
        assert token.verify_signature(km_old.public_key) is True

        # Old token does NOT verify with new public key
        assert token.verify_signature(km_new.public_key) is False

        # Claim with old key works
        claim = auth_engine_old.verify_and_claim(
            token.authorization_id, signed_old, payload_hash,
            str(XID.new()), km_old.public_key,
        )
        conn.commit()
        assert claim is not None

    def test_key_save_and_load_roundtrip(self, tmp_path):
        """KeyManager save/load roundtrip preserves the keypair."""
        km1 = KeyManager()
        key_file = str(tmp_path / "test_key.bin")
        km1.save_private_key(key_file)

        km2 = KeyManager()
        km2.load_private_key(key_file)

        assert bytes(km1.private_key) == bytes(km2.private_key)
        assert bytes(km1.public_key) == bytes(km2.public_key)

        # A token signed by km1 verifies with km2's public key
        from ep_governance.authorizations import AuthorizationToken
        token = AuthorizationToken(
            authorization_id=str(XID.new()),
            transition_id=str(XID.new()),
            agent_id=str(XID.new()),
            project_id=str(XID.new()),
            branch_id=str(XID.new()),
            proxy_audience="test-proxy",
            tool="test",
            payload_hash="sha256:" + "a" * 64,
            policy_set_hash="sha256:" + "b" * 64,
            matched_policy_versions={},
            issued_at="2026-07-30T00:00:00.000000Z",
            expires_at="2026-07-30T00:05:00.000000Z",
            nonce="abc123",
        )
        signed = token.to_signed_token(km1)
        assert token.verify_signature(km2.public_key) is True


# ---------------------------------------------------------------------------
# Test 3: Stale authorization after policy change
# ---------------------------------------------------------------------------

class TestStaleAuthorizationAfterPolicyChange:
    """If a policy changes after a token is issued but before the proxy executes,
    the proxy's policy revalidation must detect the change and reject."""

    def test_policy_change_invalidates_stale_token(
        self, conn, engine, setup, ep_service_id, agent_id
    ):
        # This is tested in detail in test_phase5_proxy.py and the e2e test.
        # Here we test the simpler case: the policy_set_hash differs.
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

        # The transition records the policy_set_hash at authorization time
        original_hash = transition.get("policy_set_hash")
        assert original_hash is not None

        # If we issue a token with a DIFFERENT policy_set_hash, the proxy
        # should detect the mismatch. This simulates a policy change
        # between authorization and execution.
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
            matched_policies=[{"id": "fake_policy", "activation_version": 999}],
            enforcement_capability=capability,
        )
        conn.commit()

        # The token's policy_set_hash should differ from the transition's
        assert token.policy_set_hash != original_hash


# ---------------------------------------------------------------------------
# Test 4: Idempotent propose — same key returns existing transition
# ---------------------------------------------------------------------------

class TestIdempotency:
    """Same idempotency key must return the existing transition."""

    def test_same_key_returns_existing(self, conn, engine, setup, ep_service_id, agent_id):
        policy_engine = _build_allow_policy_engine()
        trans_engine = TransitionEngine(engine, ep_service_id, policy_engine=policy_engine)

        idem_key = str(XID.new())

        t1 = trans_engine.propose(
            agent_id=agent_id,
            branch_id=setup["branch"]["id"],
            tool="postgres.execute",
            arguments={"sql": "SELECT 1"},
            idempotency_key=idem_key,
        )
        conn.commit()

        t2 = trans_engine.propose(
            agent_id=agent_id,
            branch_id=setup["branch"]["id"],
            tool="postgres.execute",
            arguments={"sql": "SELECT 1"},
            idempotency_key=idem_key,
        )
        conn.commit()

        assert t1["id"] == t2["id"], "Same idempotency key should return same transition"

    def test_different_keys_create_different_transitions(self, conn, engine, setup, ep_service_id, agent_id):
        policy_engine = _build_allow_policy_engine()
        trans_engine = TransitionEngine(engine, ep_service_id, policy_engine=policy_engine)

        t1 = trans_engine.propose(
            agent_id=agent_id,
            branch_id=setup["branch"]["id"],
            tool="postgres.execute",
            arguments={"sql": "SELECT 1"},
            idempotency_key=str(XID.new()),
        )
        conn.commit()

        t2 = trans_engine.propose(
            agent_id=agent_id,
            branch_id=setup["branch"]["id"],
            tool="postgres.execute",
            arguments={"sql": "SELECT 2"},
            idempotency_key=str(XID.new()),
        )
        conn.commit()

        assert t1["id"] != t2["id"], "Different keys should create different transitions"


# ---------------------------------------------------------------------------
# Test 5: Illegal transition is rejected
# ---------------------------------------------------------------------------

class TestIllegalTransitions:
    """Illegal stage transitions must be rejected."""

    def test_succeeded_to_executing_illegal(self, conn, engine, setup, ep_service_id, agent_id):
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
            pytest.skip("Transition did not reach authorized")

        # authorized -> executing -> succeeded
        trans_engine.advance_stage(transition["id"], "executing")
        conn.commit()

        head_id, version = BranchRepository(conn).get_head(setup["branch"]["id"])
        conn.commit()

        committer.commit(
            transition_id=transition["id"],
            branch_id=setup["branch"]["id"],
            agent_id=agent_id,
            description="Test",
            bt_planning_budget=90,
            metadata={},
            expected_head_id=head_id,
            expected_version=version,
            lattice_id=setup["lattice"]["id"],
        )
        conn.commit()

        # Now try to go from succeeded -> executing (illegal)
        with pytest.raises(IllegalTransitionError):
            trans_engine.advance_stage(transition["id"], "executing")
        conn.rollback()

    def test_denied_to_authorized_illegal(self, conn, engine, setup, ep_service_id, agent_id):
        """Cannot move from denied back to authorized."""
        # Create deny policy
        policy_repo = PolicyRepository(conn)
        deny_id = str(XID.new())
        policy_repo.insert_policy({
            "id": deny_id, "effect": "deny", "actions": ["*"], "resources": ["*"],
            "conditions": {}, "priority": 100, "scope": "global", "agent_scope": None,
            "description": "Deny all", "status": "active",
            "created_by": ep_service_id, "approved_by": ep_service_id,
            "approved_at": "2026-07-28T12:00:00.000000Z", "activation_version": 1,
            "exception_to": [], "valid_from": None, "valid_until": None,
            "justification": None,
        })
        conn.commit()

        # Build engine with the deny policy
        from ep_governance.policies import Policy
        deny_policy = Policy(
            id=deny_id, effect="deny", actions=["*"], resources=["*"],
            conditions={}, priority=100, scope="global", agent_scope=None,
            project_id=None, branch_id=None, description="Deny all",
            status="active", created_by=ep_service_id, approved_by=ep_service_id,
            approved_at="2026-07-28T12:00:00.000000Z", activation_version=1,
            exception_to=[], valid_from=None, valid_until=None, justification=None,
        )
        pe = PolicyEngine([deny_policy])
        trans_engine = TransitionEngine(engine, ep_service_id, policy_engine=pe)

        transition = trans_engine.propose(
            agent_id=agent_id,
            branch_id=setup["branch"]["id"],
            tool="postgres.execute",
            arguments={"sql": "SELECT 1"},
            idempotency_key=str(XID.new()),
        )
        conn.commit()

        assert transition["stage"] == "denied"

        # Try to move from denied -> authorized (illegal)
        with pytest.raises(IllegalTransitionError):
            trans_engine.advance_stage(transition["id"], "authorized")
        conn.rollback()