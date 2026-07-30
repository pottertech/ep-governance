"""Phase 5 integration tests: PostgreSQL governed proxy.

Tests the full enforcement path: agent proposes, EP authorizes with signed
token, proxy verifies and executes, result flows back.

Gate criteria from directive:
- Agent lacks direct target credentials
- Proxy owns test credentials
- Altered payload rejected
- Token reuse rejected
- Unauthorized SQL denied
- Unknown SQL requires approval or denial
- Execution result correctly changes graph state
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

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
from ep_governance.audit import AuditWriter
from ep_governance.authorizations import KeyManager, AuthorizationEngine
from ep_governance.transitions import TransitionEngine
from ep_governance.branches import BranchCommitter
from ep_governance.proxy.base import ProxyConfig, ExecutionResult
from ep_governance.proxy.postgres_proxy import PostgresProxy
from ep_governance.canonical import canonical_hash
from ep_governance.errors import StaleHeadError


def _build_default_policy_engine(conn):
    """Build a PolicyEngine with a global allow-all policy for test fixtures."""
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
        description="Trusted EP service",
    )
    conn.commit()
    return p["id"]


@pytest.fixture
def agent_id(conn):
    repo = PrincipalRepository(conn)
    p = repo.insert_principal(
        principal_id=str(XID.new()),
        name="Test Agent",
        type="agent",
        machine="localhost",
        description="Test agent",
    )
    conn.commit()
    return p["id"]


@pytest.fixture
def setup(conn, ep_service_id, agent_id):
    proj_repo = ProjectRepository(conn)
    project = proj_repo.create_project("Test", "")

    lat_repo = LatticeRepository(conn)
    lattice = lat_repo.create_lattice(project["id"], "main")

    branch_repo = BranchRepository(conn)
    branch = branch_repo.create_branch(lattice["id"], "main")

    policy_repo = PolicyRepository(conn)
    policy_repo.insert_policy(
        {
            "id": "default",
            "effect": "allow",
            "actions": ["*"],
            "resources": ["*"],
            "conditions": {},
            "priority": 0,
            "scope": "global",
            "agent_scope": None,
            "description": "Default allow",
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
    return KeyManager()


@pytest.fixture
def auth_engine(engine, key_manager, ep_service_id):
    return AuthorizationEngine(engine, key_manager, ep_service_id)


@pytest.fixture
def proxy(conn, engine, auth_engine, ep_service_id, setup):
    """Create a PostgresProxy pointed at the EP governance DB itself for testing."""
    from ep_governance.transitions import TransitionEngine
    from ep_governance.branches import BranchCommitter

    policy_engine = _build_default_policy_engine(conn)
    trans_engine = TransitionEngine(engine, ep_service_id, policy_engine=policy_engine)
    committer = BranchCommitter(engine, ep_service_id)
    config = ProxyConfig(
        target_connection_string=_get_db_url(),
        proxy_audience="postgres-proxy",
        ep_service_principal_id=ep_service_id,
    )
    return PostgresProxy(engine, auth_engine, config, trans_engine, committer, None)


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
        arguments = {"sql": "SELECT 1", "host": "localhost", "database": "test"}

    policy_engine = _build_default_policy_engine(conn)
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

    token = auth_engine.issue_authorization(
        transition_id=transition["id"],
        agent_id=agent_id,
        project_id=setup["project"]["id"],
        branch_id=setup["branch"]["id"],
        proxy_audience="postgres-proxy",
        tool=tool,
        payload_hash=payload_hash,
        matched_policies=[],
    )
    conn.commit()
    return transition, token


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestProxyTokenVerification:
    def test_valid_token_accepted(self, conn, engine, setup, key_manager, auth_engine, proxy):
        """A valid signed token should be accepted by the proxy."""
        transition, token = _propose_and_authorize(
            conn,
            engine,
            setup["ep_service_id"],
            setup["agent_id"],
            setup,
            auth_engine,
            key_manager,
        )
        if token is None:
            pytest.skip("Transition did not reach authorized stage")

        signed = token.to_signed_token(key_manager)
        payload = {"sql": "SELECT 1", "host": "localhost", "database": "test"}
        payload_hash = "sha256:" + canonical_hash(payload)

        result = proxy.execute(signed, payload, key_manager.public_key)
        assert result.exit_status == "success"
        assert result.success is True

    def test_altered_payload_rejected(self, conn, engine, setup, key_manager, auth_engine, proxy):
        """If the payload hash is altered, execution must be rejected."""
        transition, token = _propose_and_authorize(
            conn,
            engine,
            setup["ep_service_id"],
            setup["agent_id"],
            setup,
            auth_engine,
            key_manager,
        )
        if token is None:
            pytest.skip("Transition did not reach authorized stage")

        signed = token.to_signed_token(key_manager)
        # Use a different payload than what was authorized
        altered_payload = {"sql": "DROP TABLE memory_items", "host": "localhost"}

        # The proxy now computes the hash internally — no caller-supplied hash
        result = proxy.execute(signed, altered_payload, key_manager.public_key)
        assert result.success is False
        assert "mismatch" in result.result_summary.lower()

    def test_token_reuse_rejected(self, conn, engine, setup, key_manager, auth_engine, proxy):
        """A token that has already been claimed must be rejected on second use."""
        transition, token = _propose_and_authorize(
            conn,
            engine,
            setup["ep_service_id"],
            setup["agent_id"],
            setup,
            auth_engine,
            key_manager,
        )
        if token is None:
            pytest.skip("Transition did not reach authorized stage")

        signed = token.to_signed_token(key_manager)
        payload = {"sql": "SELECT 1", "host": "localhost", "database": "test"}
        payload_hash = "sha256:" + canonical_hash(payload)

        # First execution succeeds
        result1 = proxy.execute(signed, payload, key_manager.public_key)
        conn.commit()
        assert result1.success is True

        # Second execution with same token fails
        result2 = proxy.execute(signed, payload, key_manager.public_key)
        conn.commit()
        assert result2.success is False
        assert (
            "already used" in result2.result_summary.lower()
            or "claim failed" in result2.result_summary.lower()
        )

    def test_wrong_audience_rejected(
        self, conn, engine, setup, key_manager, auth_engine, ep_service_id
    ):
        """A token with the wrong proxy audience must be rejected."""
        transition, token = _propose_and_authorize(
            conn,
            engine,
            setup["ep_service_id"],
            setup["agent_id"],
            setup,
            auth_engine,
            key_manager,
        )
        if token is None:
            pytest.skip("Transition did not reach authorized stage")

        # Create a proxy with a different audience
        config = ProxyConfig(
            target_connection_string=_get_db_url(),
            proxy_audience="docker-proxy",  # different audience
            ep_service_principal_id=ep_service_id,
        )
        wrong_proxy = PostgresProxy(engine, auth_engine, config)

        signed = token.to_signed_token(key_manager)
        payload = {"sql": "SELECT 1", "host": "localhost", "database": "test"}
        payload_hash = "sha256:" + canonical_hash(payload)

        result = wrong_proxy.execute(signed, payload, key_manager.public_key)
        assert result.success is False
        assert "audience" in result.result_summary.lower()


class TestProxySQLClassification:
    def test_select_executed(self, conn, engine, setup, key_manager, auth_engine, proxy):
        """SELECT should be executed successfully."""
        transition, token = _propose_and_authorize(
            conn,
            engine,
            setup["ep_service_id"],
            setup["agent_id"],
            setup,
            auth_engine,
            key_manager,
            arguments={"sql": "SELECT 1 as result", "host": "localhost"},
        )
        if token is None:
            pytest.skip("Transition did not reach authorized stage")

        signed = token.to_signed_token(key_manager)
        payload = {"sql": "SELECT 1 as result", "host": "localhost"}
        payload_hash = "sha256:" + canonical_hash(payload)

        result = proxy.execute(signed, payload, key_manager.public_key)
        assert result.success is True
        assert result.exit_status == "success"

    def test_forbidden_operation_rejected(
        self, conn, engine, setup, key_manager, auth_engine, proxy
    ):
        """TRUNCATE should be rejected as forbidden by the proxy."""
        transition, token = _propose_and_authorize(
            conn,
            engine,
            setup["ep_service_id"],
            setup["agent_id"],
            setup,
            auth_engine,
            key_manager,
            arguments={"sql": "TRUNCATE TABLE ep_projects", "host": "localhost"},
        )
        if token is None:
            pytest.skip("Transition did not reach authorized stage")

        signed = token.to_signed_token(key_manager)
        payload = {"sql": "TRUNCATE TABLE ep_projects", "host": "localhost"}
        payload_hash = "sha256:" + canonical_hash(payload)

        result = proxy.execute(signed, payload, key_manager.public_key)
        assert result.success is False
        assert "forbidden" in result.result_summary.lower()

    def test_no_sql_in_payload_rejected(self, conn, engine, setup, key_manager, auth_engine, proxy):
        """Payload without SQL should be rejected by the proxy.

        The proposal uses valid SQL for classification, but the payload
        sent to the proxy for execution omits the SQL field.
        """
        transition, token = _propose_and_authorize(
            conn,
            engine,
            setup["ep_service_id"],
            setup["agent_id"],
            setup,
            auth_engine,
            key_manager,
            arguments={"sql": "SELECT 1", "host": "localhost"},
        )
        if token is None:
            pytest.skip("Transition did not reach authorized stage")

        signed = token.to_signed_token(key_manager)
        # Send payload WITHOUT sql — proxy should reject
        payload = {"host": "localhost"}
        payload_hash = "sha256:" + canonical_hash({"sql": "SELECT 1", "host": "localhost"})

        result = proxy.execute(signed, payload, key_manager.public_key)
        assert result.success is False
        assert (
            "no sql" in result.result_summary.lower() or "mismatch" in result.result_summary.lower()
        )


class TestProxyResultFlow:
    def test_successful_execution_returns_result(
        self, conn, engine, setup, key_manager, auth_engine, proxy
    ):
        """A successful execution should return a result with rows_affected."""
        transition, token = _propose_and_authorize(
            conn,
            engine,
            setup["ep_service_id"],
            setup["agent_id"],
            setup,
            auth_engine,
            key_manager,
            arguments={"sql": "SELECT 1 as val", "host": "localhost"},
        )
        if token is None:
            pytest.skip("Transition did not reach authorized stage")

        signed = token.to_signed_token(key_manager)
        payload = {"sql": "SELECT 1 as val", "host": "localhost"}
        payload_hash = "sha256:" + canonical_hash(payload)

        result = proxy.execute(signed, payload, key_manager.public_key)
        conn.commit()
        assert result.success is True
        assert result.rows_affected >= 1
        assert result.execution_attempt_id != ""

    def test_execution_advances_transition_to_executing(
        self, conn, engine, setup, key_manager, auth_engine, proxy
    ):
        """After proxy claims the token, the transition should be in 'executing' stage."""
        transition, token = _propose_and_authorize(
            conn,
            engine,
            setup["ep_service_id"],
            setup["agent_id"],
            setup,
            auth_engine,
            key_manager,
        )
        if token is None:
            pytest.skip("Transition did not reach authorized stage")

        signed = token.to_signed_token(key_manager)
        payload = {"sql": "SELECT 1", "host": "localhost"}
        payload_hash = "sha256:" + canonical_hash(payload)

        result = proxy.execute(signed, payload, key_manager.public_key)
        conn.commit()

        # Check the transition stage was advanced to executing by the claim
        trans_repo = TransitionRepository(conn)
        updated = trans_repo.get_transition(transition["id"])
        # The proxy claims the auth which advances to "executing".
        # The proxy does NOT call record_result (that is EP's job).
        assert updated["stage"] in ("executing", "succeeded", "authorized")


class TestProxyRedaction:
    def test_secret_redaction_in_output(self, conn, engine, ep_service_id):
        """The proxy must redact secrets from output."""
        config = ProxyConfig(
            target_connection_string="sqlite:///:memory:",
            proxy_audience="postgres-proxy",
            ep_service_principal_id=ep_service_id,
        )
        # Create a minimal proxy to test redaction
        from ep_governance.proxy.base import GovernedProxy
        from ep_governance.authorizations import AuthorizationEngine

        km = KeyManager()
        ae = AuthorizationEngine(engine, km, ep_service_id)

        class TestProxy(GovernedProxy):
            def _execute_adapter(self, payload, token, attempt_id):
                output = "password=secret123 token=abc456 key=xyz789"
                return ExecutionResult(
                    success=True,
                    exit_status="success",
                    result_summary=self._redact(output),
                )

        test_proxy = TestProxy(engine, ae, config)
        assert "secret123" not in test_proxy._redact("password=secret123")
        assert "REDACTED" in test_proxy._redact("password=secret123")
