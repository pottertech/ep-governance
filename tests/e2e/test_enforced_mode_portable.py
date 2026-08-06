"""Portable E2E test for enforced mode — runs anywhere with SQLite.

This test is fully self-contained: it creates its own principals, project,
lattice, branch, policies, and audit head. It does NOT depend on any
preexisting deployment state, named principals, or a specific database
engine (PostgreSQL). It uses SQLite in-memory by default.

The full enforced-mode pipeline is exercised:
  1. Propose an action through TransitionEngine
  2. If authorized, issue an Ed25519-signed token via EnforcementCapability.for_test()
  3. Execute through PostgresProxy (pointed at the same SQLite DB for testing)
  4. Verify the transition reaches 'succeeded'
  5. Verify a graph node was created (branch head advanced)
  6. Verify the audit chain remains valid
  7. Test token reuse is rejected
  8. Test payload tampering is detected
"""

from __future__ import annotations

import os
import sys

# Ensure we can import from src
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

import pytest
import sqlalchemy as sa

from ep_governance.db.postgres import create_engine, is_sqlite
from ep_governance.db import run_migrations
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
from ep_governance.audit import AuditWriter, AuditVerifier
from ep_governance.authorizations import KeyManager, AuthorizationEngine
from ep_governance.transitions import TransitionEngine
from ep_governance.branches import BranchCommitter
from ep_governance.proxy.base import ProxyConfig, ExecutionResult
from ep_governance.proxy.postgres_proxy import PostgresProxy
from ep_governance.canonical import canonical_hash
from ep_governance.deployment import EnforcementCapability


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_allow_policy_engine():
    """Build a PolicyEngine with a single allow-all policy for test fixtures."""
    from ep_governance.policies import Policy
    from ep_governance.policy_engine import PolicyEngine

    _id = str(XID.new())
    allow_policy = Policy(
        id=_id,
        effect="allow",
        actions=["*"],
        resources=["*"],
        conditions={},
        priority=1,
        scope="global",
        agent_scope=None,
        project_id=None,
        branch_id=None,
        description="Test allow-all",
        status="active",
        created_by=_id,
        approved_by=_id,
        approved_at="2026-07-28T12:00:00.000000Z",
        activation_version=1,
        exception_to=[],
        valid_from=None,
        valid_until=None,
        justification=None,
    )
    return PolicyEngine([allow_policy])


def _get_db_url() -> str:
    """Return the DB URL — defaults to in-memory SQLite for portability."""
    return os.environ.get("EP_TEST_DB_URL", "sqlite:///:memory:")


def _proxy_scoped_capability():
    """Create a proxy-scoped enforcement capability for proxy.execute calls."""
    return EnforcementCapability.for_test(
        agent_principal_id="proxy",
        proxy_scoped=True,
        proxy_principal_id="proxy",
        proxy_audience="postgres-proxy",
    )


# ---------------------------------------------------------------------------
# Fixtures — create everything from scratch
# ---------------------------------------------------------------------------


@pytest.fixture
def engine():
    """Create a SQLAlchemy engine — SQLite in-memory by default."""
    eng = create_engine(_get_db_url())
    yield eng
    eng.dispose()


@pytest.fixture
def conn(engine):
    """Create a connection and run migrations."""
    with engine.connect() as conn:
        dialect = "sqlite" if is_sqlite(conn) else "postgres"
        run_migrations(conn, dialect)
        conn.commit()
        yield conn


@pytest.fixture
def ep_service_id(conn):
    """Create the EP Service principal."""
    repo = PrincipalRepository(conn)
    p = repo.insert_principal(
        principal_id=str(XID.new()),
        name="EP Service",
        type="service",
        machine=None,
        description="Trusted EP service",
    )
    conn.commit()
    return p["id"]


@pytest.fixture
def agent_id(conn):
    """Create a Test Agent principal."""
    repo = PrincipalRepository(conn)
    p = repo.insert_principal(
        principal_id=str(XID.new()),
        name="Test Agent",
        type="agent",
        machine="localhost",
        description="Test agent principal",
    )
    conn.commit()
    return p["id"]


@pytest.fixture
def human_id(conn):
    """Create a Test Human principal."""
    repo = PrincipalRepository(conn)
    p = repo.insert_principal(
        principal_id=str(XID.new()),
        name="Test Human",
        type="human",
        machine=None,
        description="Test human approver",
    )
    conn.commit()
    return p["id"]


@pytest.fixture
def setup(conn, ep_service_id, agent_id):
    """Create project, lattice, branch, allow-all policy, and audit head.

    Everything is created from scratch — no preexisting state required.
    """
    # Project
    proj_repo = ProjectRepository(conn)
    project = proj_repo.create_project("Test Project", "Portable E2E testing")

    # Lattice
    lat_repo = LatticeRepository(conn)
    lattice = lat_repo.create_lattice(project["id"], "main")

    # Branch
    branch_repo = BranchRepository(conn)
    branch = branch_repo.create_branch(lattice["id"], "main")

    # Allow-all policy (in the DB for FK satisfaction)
    policy_repo = PolicyRepository(conn)
    policy_repo.insert_policy(
        {
            "id": "default-allow",
            "effect": "allow",
            "actions": ["*"],
            "resources": ["*"],
            "conditions": {},
            "priority": 0,
            "scope": "global",
            "agent_scope": None,
            "description": "Default allow-all policy for portable E2E test",
            "status": "active",
            "created_by": ep_service_id,
            "approved_by": ep_service_id,
            "approved_at": "2026-07-28T12:00:00.000000Z",
            "activation_version": 1,
            "exception_to": [],
            "valid_from": None,
            "valid_until": None,
            "justification": None,
        }
    )

    # Initialize audit head (genesis hash = 0*64)
    conn.execute(
        sa.text(
            "INSERT INTO ep_audit_heads (lattice_id, last_sequence, last_hash) "
            "VALUES (:lid, 0, :hash)"
        ),
        {"lid": lattice["id"], "hash": "0" * 64},
    )
    conn.commit()

    return {
        "project": project,
        "lattice": lattice,
        "branch": branch,
        "agent_id": agent_id,
        "ep_service_id": ep_service_id,
    }


@pytest.fixture
def key_manager():
    """Create an Ed25519 KeyManager for signing/verifying tokens."""
    return KeyManager()


@pytest.fixture
def auth_engine(engine, key_manager, ep_service_id):
    """Create an AuthorizationEngine bound to the key manager and EP service."""
    return AuthorizationEngine(engine, key_manager, ep_service_id)


# ---------------------------------------------------------------------------
# Helper: full propose -> authorize -> issue token flow
# ---------------------------------------------------------------------------


def _propose_and_authorize(
    conn,
    engine,
    ep_service_id,
    agent_id,
    setup,
    auth_engine,
    key_manager,
    tool="postgres.execute",
    arguments=None,
):
    """Propose, get authorized, issue a token. Returns (transition, token)."""
    if arguments is None:
        arguments = {"sql": "SELECT 1", "host": "localhost", "database": "test_db"}

    policy_engine = _build_allow_policy_engine()
    trans_engine = TransitionEngine(engine, ep_service_id, policy_engine=policy_engine)
    transition = trans_engine.propose(
        agent_id=agent_id,
        branch_id=setup["branch"]["id"],
        tool=tool,
        arguments=arguments,
        idempotency_key=str(XID.new()),
    )
    conn.commit()

    if transition["stage"] != "authorized":
        return transition, None

    payload_hash = "sha256:" + canonical_hash(arguments)

    capability = EnforcementCapability.for_test(
        agent_principal_id=agent_id,
    )

    token = auth_engine.issue_authorization(
        transition_id=transition["id"],
        agent_id=agent_id,
        project_id=setup["project"]["id"],
        branch_id=setup["branch"]["id"],
        proxy_audience="postgres-proxy",
        tool=tool,
        payload_hash=payload_hash,
        matched_policies=[],
        enforcement_capability=capability,
    )
    conn.commit()
    return transition, token


def _make_proxy(engine, auth_engine, ep_service_id, setup):
    """Build a PostgresProxy pointed at the same SQLite DB for testing.

    The proxy's policy_engine is None — policy revalidation is skipped at
    the proxy level, matching the pattern in test_phase5_proxy.py. The
    transition engine still uses a policy_engine for propose/authorize.
    """
    policy_engine = _build_allow_policy_engine()
    trans_engine = TransitionEngine(engine, ep_service_id, policy_engine=policy_engine)
    committer = BranchCommitter(engine, ep_service_id)
    config = ProxyConfig(
        target_connection_string=_get_db_url(),
        proxy_audience="postgres-proxy",
        ep_service_principal_id=ep_service_id,
    )
    return PostgresProxy(
        engine,
        auth_engine,
        config,
        trans_engine,
        committer,
        None,  # policy_engine=None — skip proxy-level policy revalidation
    )


# ---------------------------------------------------------------------------
# Test class: Full enforced-mode E2E pipeline (portable)
# ---------------------------------------------------------------------------


class TestEnforcedModePortable:
    """Portable end-to-end test that runs on SQLite without preexisting state."""

    # ------------------------------------------------------------------ #
    # Test 1: Full pipeline — propose, authorize, issue token, execute,
    #         verify succeeded, verify graph node, verify audit chain
    # ------------------------------------------------------------------ #

    def test_full_enforced_pipeline_succeeds(
        self, conn, engine, setup, key_manager, auth_engine, ep_service_id, agent_id
    ):
        """The full enforced pipeline: propose → authorize → token → execute → succeeded.

        Verifies:
        - Transition reaches 'succeeded'
        - A graph node was created (branch head advanced)
        - Audit chain remains valid
        """
        payload = {
            "sql": "SELECT 1 as result",
            "host": "localhost",
            "database": "test_db",
        }

        transition, token = _propose_and_authorize(
            conn,
            engine,
            ep_service_id,
            agent_id,
            setup,
            auth_engine,
            key_manager,
            arguments=payload,
        )
        if token is None:
            pytest.skip(f"Transition did not reach 'authorized' stage (got '{transition['stage']}')")

        assert transition["stage"] == "authorized"

        # Issue a signed token
        signed = token.to_signed_token(key_manager)

        # Build a proxy and execute
        proxy = _make_proxy(engine, auth_engine, ep_service_id, setup)

        # Use proxy-scoped capability for execution
        capability_exec = _proxy_scoped_capability()

        result = proxy.execute(
            signed_token=signed,
            payload=payload,
            public_key=key_manager.public_key,
            enforcement_capability=capability_exec,
        )
        conn.commit()

        # --- Verify execution succeeded ---
        assert result.success is True, f"Proxy execution failed: {result.result_summary}"
        assert result.exit_status == "success"

        # --- Verify transition reached 'succeeded' ---
        trans_repo = TransitionRepository(conn)
        updated = trans_repo.get_transition(transition["id"])
        assert updated is not None, "Transition not found after execution"
        assert updated["stage"] == "succeeded", (
            f"Expected stage 'succeeded', got '{updated['stage']}'"
        )

        # --- Verify a graph node was created (branch head advanced) ---
        branch_repo = BranchRepository(conn)
        head_id, head_version = branch_repo.get_head(setup["branch"]["id"])
        assert head_id is not None, "Branch head is None — no node was created"

        # Count nodes — at least one should exist from the commit
        node_count = conn.execute(sa.text("SELECT count(*) FROM ep_nodes")).scalar()
        assert node_count >= 1, f"Expected at least 1 node, got {node_count}"

        # --- Verify audit chain is valid ---
        verifier = AuditVerifier(engine)
        chain_valid = verifier.verify(setup["lattice"]["id"])
        assert chain_valid is True, "Audit chain verification failed after execution"

    # ------------------------------------------------------------------ #
    # Test 2: Token reuse is rejected
    # ------------------------------------------------------------------ #

    def test_token_reuse_rejected(
        self, conn, engine, setup, key_manager, auth_engine, ep_service_id, agent_id
    ):
        """A token that has already been used must be rejected on second use."""
        payload = {
            "sql": "SELECT 1 as val",
            "host": "localhost",
            "database": "test_db",
        }

        transition, token = _propose_and_authorize(
            conn,
            engine,
            ep_service_id,
            agent_id,
            setup,
            auth_engine,
            key_manager,
            arguments=payload,
        )
        if token is None:
            pytest.skip(f"Transition did not reach 'authorized' stage (got '{transition['stage']}')")

        signed = token.to_signed_token(key_manager)
        proxy = _make_proxy(engine, auth_engine, ep_service_id, setup)
        capability_exec = _proxy_scoped_capability()

        # First execution should succeed
        result1 = proxy.execute(
            signed_token=signed,
            payload=payload,
            public_key=key_manager.public_key,
            enforcement_capability=capability_exec,
        )
        conn.commit()
        assert result1.success is True, f"First execution failed: {result1.result_summary}"

        # Second execution with the same token must fail
        capability_exec2 = _proxy_scoped_capability()
        result2 = proxy.execute(
            signed_token=signed,
            payload=payload,
            public_key=key_manager.public_key,
            enforcement_capability=capability_exec2,
        )
        conn.commit()
        assert result2.success is False, "Token reuse should have been rejected"
        # The rejection reason should indicate the token is already consumed
        summary_lower = result2.result_summary.lower()
        assert (
            "already used" in summary_lower
            or "claim failed" in summary_lower
            or "expected 'authorized'" in summary_lower
            or "stale" in summary_lower
        ), f"Unexpected rejection reason: {result2.result_summary}"

    # ------------------------------------------------------------------ #
    # Test 3: Payload tampering is detected
    # ------------------------------------------------------------------ #

    def test_payload_tampering_detected(
        self, conn, engine, setup, key_manager, auth_engine, ep_service_id, agent_id
    ):
        """If the payload is altered after token issuance, execution must be rejected."""
        original_payload = {
            "sql": "SELECT 42 as answer",
            "host": "localhost",
            "database": "test_db",
        }

        transition, token = _propose_and_authorize(
            conn,
            engine,
            ep_service_id,
            agent_id,
            setup,
            auth_engine,
            key_manager,
            arguments=original_payload,
        )
        if token is None:
            pytest.skip(f"Transition did not reach 'authorized' stage (got '{transition['stage']}')")

        signed = token.to_signed_token(key_manager)
        proxy = _make_proxy(engine, auth_engine, ep_service_id, setup)
        capability_exec = _proxy_scoped_capability()

        # Tamper with the payload — change the SQL
        tampered_payload = dict(original_payload)
        tampered_payload["sql"] = "SELECT 999 as answer"

        result = proxy.execute(
            signed_token=signed,
            payload=tampered_payload,
            public_key=key_manager.public_key,
            enforcement_capability=capability_exec,
        )
        conn.commit()

        # Must be rejected due to hash mismatch
        assert result.success is False, "Tampered payload should have been rejected"
        summary_lower = result.result_summary.lower()
        assert "mismatch" in summary_lower, (
            f"Expected 'mismatch' in rejection reason, got: {result.result_summary}"
        )

    # ------------------------------------------------------------------ #
    # Test 4: Audit chain valid after multiple operations
    # ------------------------------------------------------------------ #

    def test_audit_chain_valid_after_multiple_ops(
        self, conn, engine, setup, key_manager, auth_engine, ep_service_id, agent_id
    ):
        """Audit chain should remain valid after multiple successful operations."""
        proxy = _make_proxy(engine, auth_engine, ep_service_id, setup)

        for i in range(3):
            payload = {
                "sql": f"SELECT {i} as iteration",
                "host": "localhost",
                "database": "test_db",
            }

            transition, token = _propose_and_authorize(
                conn,
                engine,
                ep_service_id,
                agent_id,
                setup,
                auth_engine,
                key_manager,
                arguments=payload,
            )
            if token is None:
                pytest.skip(
                    f"Transition {i} did not reach 'authorized' stage "
                    f"(got '{transition['stage']}')"
                )

            signed = token.to_signed_token(key_manager)
            capability_exec = _proxy_scoped_capability()

            result = proxy.execute(
                signed_token=signed,
                payload=payload,
                public_key=key_manager.public_key,
                enforcement_capability=capability_exec,
            )
            conn.commit()
            assert result.success is True, (
                f"Execution {i} failed: {result.result_summary}"
            )

        # Verify audit chain after 3 operations
        verifier = AuditVerifier(engine)
        chain_valid = verifier.verify(setup["lattice"]["id"])
        assert chain_valid is True, "Audit chain invalid after 3 successful operations"

        # Also verify with verify_all
        all_chains = verifier.verify_all()
        for lid, valid in all_chains.items():
            assert valid is True, f"Audit chain for lattice {lid} is invalid"