"""Tests for multi-target proxy routing and configuration loading.

Tests that:
1. load_proxy_targets() correctly reads a JSON config file
2. PostgresProxy routes execution to the correct target based on the
   'database' field in the payload
3. Unknown databases are rejected
4. Single-target mode (backward compatibility) still works
5. Missing EP_PROXY_TARGETS_FILE returns empty dict (backward compat)
6. Invalid JSON raises ProxyConfigurationError
"""

from __future__ import annotations

import json
import os
import tempfile

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
)
from ep_governance.xid import XID
from ep_governance.authorizations import KeyManager, AuthorizationEngine
from ep_governance.transitions import TransitionEngine
from ep_governance.branches import BranchCommitter
from ep_governance.proxy.base import ProxyConfig, ExecutionResult
from ep_governance.proxy.postgres_proxy import PostgresProxy
from ep_governance.canonical import canonical_hash
from ep_governance.deployment import EnforcementCapability
from ep_governance.proxy_service import load_proxy_targets, ProxyConfigurationError


def _get_db_url() -> str:
    return os.environ.get("EP_TEST_DB_URL", "sqlite:///:memory:")


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


def _proxy_scoped_capability():
    """Create a proxy-scoped enforcement capability for proxy.execute calls."""
    return EnforcementCapability.for_test(
        agent_principal_id="proxy",
        proxy_scoped=True,
        proxy_principal_id="proxy",
        proxy_audience="postgres-proxy",
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Tests: load_proxy_targets()
# ---------------------------------------------------------------------------


class TestLoadProxyTargets:
    """Tests for the load_proxy_targets() configuration loader."""

    def test_returns_empty_when_env_not_set(self, monkeypatch):
        """When EP_PROXY_TARGETS_FILE is not set, returns empty dict."""
        monkeypatch.delenv("EP_PROXY_TARGETS_FILE", raising=False)
        result = load_proxy_targets()
        assert result == {}

    def test_returns_empty_when_file_not_found(self, monkeypatch, tmp_path):
        """When the targets file doesn't exist, returns empty dict (warns)."""
        monkeypatch.setenv("EP_PROXY_TARGETS_FILE", str(tmp_path / "nonexistent.json"))
        result = load_proxy_targets()
        assert result == {}

    def test_loads_valid_json_file(self, monkeypatch, tmp_path):
        """A valid JSON file with database->connection string mappings loads correctly."""
        targets = {
            "analytics": "postgresql+psycopg://user:pass@host:5432/analytics",
            "metadata": "postgresql+psycopg://user:pass@host:5432/metadata",
        }
        targets_file = tmp_path / "targets.json"
        targets_file.write_text(json.dumps(targets))

        monkeypatch.setenv("EP_PROXY_TARGETS_FILE", str(targets_file))
        result = load_proxy_targets()
        assert result == targets
        assert len(result) == 2
        assert "analytics" in result
        assert "metadata" in result

    def test_invalid_json_raises_error(self, monkeypatch, tmp_path):
        """Malformed JSON raises ProxyConfigurationError."""
        targets_file = tmp_path / "bad.json"
        targets_file.write_text("{not valid json")

        monkeypatch.setenv("EP_PROXY_TARGETS_FILE", str(targets_file))
        with pytest.raises(ProxyConfigurationError, match="Failed to parse"):
            load_proxy_targets()

    def test_non_dict_json_raises_error(self, monkeypatch, tmp_path):
        """A JSON array (not object) raises ProxyConfigurationError."""
        targets_file = tmp_path / "array.json"
        targets_file.write_text(json.dumps(["db1", "db2"]))

        monkeypatch.setenv("EP_PROXY_TARGETS_FILE", str(targets_file))
        with pytest.raises(ProxyConfigurationError, match="must contain a JSON object"):
            load_proxy_targets()

    def test_non_string_values_raises_error(self, monkeypatch, tmp_path):
        """Entries with non-string values raise ProxyConfigurationError."""
        targets_file = tmp_path / "bad_values.json"
        targets_file.write_text(json.dumps({"db1": 12345}))

        monkeypatch.setenv("EP_PROXY_TARGETS_FILE", str(targets_file))
        with pytest.raises(ProxyConfigurationError, match="keys and values must be strings"):
            load_proxy_targets()

    def test_empty_json_object_returns_empty(self, monkeypatch, tmp_path):
        """An empty JSON object returns an empty dict."""
        targets_file = tmp_path / "empty.json"
        targets_file.write_text("{}")

        monkeypatch.setenv("EP_PROXY_TARGETS_FILE", str(targets_file))
        result = load_proxy_targets()
        assert result == {}

    def test_single_entry_file(self, monkeypatch, tmp_path):
        """A file with a single entry loads correctly."""
        targets = {"production": "postgresql+psycopg://user:pass@host/prod"}
        targets_file = tmp_path / "single.json"
        targets_file.write_text(json.dumps(targets))

        monkeypatch.setenv("EP_PROXY_TARGETS_FILE", str(targets_file))
        result = load_proxy_targets()
        assert result == targets
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Tests: Multi-target proxy routing
# ---------------------------------------------------------------------------


class TestMultiTargetRouting:
    """Tests for PostgresProxy multi-target routing."""

    def test_routes_to_correct_database(
        self, conn, engine, setup, key_manager, auth_engine, ep_service_id
    ):
        """In multi-target mode, execution routes to the database named
        in the payload's 'database' field."""
        db_url = _get_db_url()

        # Multi-target config: both 'primary' and 'secondary' point to
        # the same in-memory SQLite DB for testing.
        config = ProxyConfig(
            target_connection_string="",
            proxy_audience="postgres-proxy",
            ep_service_principal_id=ep_service_id,
            targets={
                "primary": db_url,
                "secondary": db_url,
            },
        )

        trans_engine = TransitionEngine(engine, ep_service_id)
        committer = BranchCommitter(engine, ep_service_id)
        proxy = PostgresProxy(
            engine, auth_engine, config, trans_engine, committer, None
        )

        # Propose with database=primary in the payload
        arguments = {"sql": "SELECT 1 as val", "host": "localhost", "database": "primary"}
        transition, token = _propose_and_authorize(
            conn, engine, ep_service_id, setup["agent_id"], setup,
            auth_engine, key_manager, arguments=arguments,
        )
        if token is None:
            pytest.skip("Transition did not reach authorized stage")

        signed = token.to_signed_token(key_manager)
        payload = {"sql": "SELECT 1 as val", "host": "localhost", "database": "primary"}

        result = proxy.execute(
            signed, payload, key_manager.public_key,
            enforcement_capability=_proxy_scoped_capability(),
        )
        conn.commit()
        assert result.success is True
        assert result.exit_status == "success"
        proxy.close()

    def test_routes_to_different_database_name(
        self, conn, engine, setup, key_manager, auth_engine, ep_service_id
    ):
        """Routing to 'secondary' target also works."""
        db_url = _get_db_url()

        config = ProxyConfig(
            target_connection_string="",
            proxy_audience="postgres-proxy",
            ep_service_principal_id=ep_service_id,
            targets={
                "primary": db_url,
                "secondary": db_url,
            },
        )

        trans_engine = TransitionEngine(engine, ep_service_id)
        committer = BranchCommitter(engine, ep_service_id)
        proxy = PostgresProxy(
            engine, auth_engine, config, trans_engine, committer, None
        )

        arguments = {"sql": "SELECT 1 as val", "host": "localhost", "database": "secondary"}
        transition, token = _propose_and_authorize(
            conn, engine, ep_service_id, setup["agent_id"], setup,
            auth_engine, key_manager, arguments=arguments,
        )
        if token is None:
            pytest.skip("Transition did not reach authorized stage")

        signed = token.to_signed_token(key_manager)
        payload = {"sql": "SELECT 1 as val", "host": "localhost", "database": "secondary"}

        result = proxy.execute(
            signed, payload, key_manager.public_key,
            enforcement_capability=_proxy_scoped_capability(),
        )
        conn.commit()
        assert result.success is True
        proxy.close()

    def test_unknown_database_rejected(
        self, conn, engine, setup, key_manager, auth_engine, ep_service_id
    ):
        """A payload with a database name not in the targets map should fail."""
        db_url = _get_db_url()

        config = ProxyConfig(
            target_connection_string="",
            proxy_audience="postgres-proxy",
            ep_service_principal_id=ep_service_id,
            targets={
                "primary": db_url,
                "secondary": db_url,
            },
        )

        trans_engine = TransitionEngine(engine, ep_service_id)
        committer = BranchCommitter(engine, ep_service_id)
        proxy = PostgresProxy(
            engine, auth_engine, config, trans_engine, committer, None
        )

        # The payload uses a database name that is NOT in the targets map.
        # We need to propose with valid SQL first, then send a payload with
        # an unknown database — but the payload hash must match, so we
        # include the unknown database name in both the proposal and payload.
        arguments = {"sql": "SELECT 1", "host": "localhost", "database": "unknown_db"}
        transition, token = _propose_and_authorize(
            conn, engine, ep_service_id, setup["agent_id"], setup,
            auth_engine, key_manager, arguments=arguments,
        )
        if token is None:
            pytest.skip("Transition did not reach authorized stage")

        signed = token.to_signed_token(key_manager)
        payload = {"sql": "SELECT 1", "host": "localhost", "database": "unknown_db"}

        result = proxy.execute(
            signed, payload, key_manager.public_key,
            enforcement_capability=_proxy_scoped_capability(),
        )
        conn.commit()
        assert result.success is False
        assert "not configured" in result.result_summary.lower()
        proxy.close()

    def test_multi_target_no_database_falls_back_to_default(
        self, conn, engine, setup, key_manager, auth_engine, ep_service_id
    ):
        """In multi-target mode with a fallback target_connection_string,
        a payload without a 'database' field falls back to the default."""
        db_url = _get_db_url()

        config = ProxyConfig(
            target_connection_string=db_url,
            proxy_audience="postgres-proxy",
            ep_service_principal_id=ep_service_id,
            targets={
                "primary": db_url,
                "secondary": db_url,
            },
        )

        trans_engine = TransitionEngine(engine, ep_service_id)
        committer = BranchCommitter(engine, ep_service_id)
        proxy = PostgresProxy(
            engine, auth_engine, config, trans_engine, committer, None
        )

        # Payload WITHOUT a 'database' field — should fall back to
        # target_connection_string.
        arguments = {"sql": "SELECT 1 as val", "host": "localhost"}
        transition, token = _propose_and_authorize(
            conn, engine, ep_service_id, setup["agent_id"], setup,
            auth_engine, key_manager, arguments=arguments,
        )
        if token is None:
            pytest.skip("Transition did not reach authorized stage")

        signed = token.to_signed_token(key_manager)
        payload = {"sql": "SELECT 1 as val", "host": "localhost"}

        result = proxy.execute(
            signed, payload, key_manager.public_key,
            enforcement_capability=_proxy_scoped_capability(),
        )
        conn.commit()
        assert result.success is True
        proxy.close()

    def test_multi_target_no_database_no_default_fails(
        self, conn, engine, setup, key_manager, auth_engine, ep_service_id
    ):
        """In multi-target mode without a fallback target_connection_string,
        a payload without a 'database' field should fail."""
        db_url = _get_db_url()

        config = ProxyConfig(
            target_connection_string="",
            proxy_audience="postgres-proxy",
            ep_service_principal_id=ep_service_id,
            targets={
                "primary": db_url,
            },
        )

        trans_engine = TransitionEngine(engine, ep_service_id)
        committer = BranchCommitter(engine, ep_service_id)
        proxy = PostgresProxy(
            engine, auth_engine, config, trans_engine, committer, None
        )

        arguments = {"sql": "SELECT 1", "host": "localhost"}
        transition, token = _propose_and_authorize(
            conn, engine, ep_service_id, setup["agent_id"], setup,
            auth_engine, key_manager, arguments=arguments,
        )
        if token is None:
            pytest.skip("Transition did not reach authorized stage")

        signed = token.to_signed_token(key_manager)
        payload = {"sql": "SELECT 1", "host": "localhost"}

        result = proxy.execute(
            signed, payload, key_manager.public_key,
            enforcement_capability=_proxy_scoped_capability(),
        )
        conn.commit()
        assert result.success is False
        assert "no target database" in result.result_summary.lower()
        proxy.close()

    def test_engine_cache_reuses_engines(
        self, conn, engine, setup, key_manager, auth_engine, ep_service_id
    ):
        """The proxy should cache target engines and reuse them across calls."""
        db_url = _get_db_url()

        config = ProxyConfig(
            target_connection_string="",
            proxy_audience="postgres-proxy",
            ep_service_principal_id=ep_service_id,
            targets={
                "primary": db_url,
                "secondary": db_url,
            },
        )

        trans_engine = TransitionEngine(engine, ep_service_id)
        committer = BranchCommitter(engine, ep_service_id)
        proxy = PostgresProxy(
            engine, auth_engine, config, trans_engine, committer, None
        )

        # Resolve the engine for 'primary' — should create and cache it
        eng1 = proxy._resolve_target_engine({"database": "primary"})
        assert eng1 is not None

        # Resolve again — should return the SAME cached engine object
        eng2 = proxy._resolve_target_engine({"database": "primary"})
        assert eng2 is eng1

        # Resolve 'secondary' — should be a different engine
        eng3 = proxy._resolve_target_engine({"database": "secondary"})
        assert eng3 is not None
        assert eng3 is not eng1

        proxy.close()

    def test_close_disposes_all_engines(
        self, conn, engine, setup, key_manager, auth_engine, ep_service_id
    ):
        """close() should dispose all cached target engines."""
        db_url = _get_db_url()

        config = ProxyConfig(
            target_connection_string="",
            proxy_audience="postgres-proxy",
            ep_service_principal_id=ep_service_id,
            targets={
                "primary": db_url,
                "secondary": db_url,
            },
        )

        trans_engine = TransitionEngine(engine, ep_service_id)
        committer = BranchCommitter(engine, ep_service_id)
        proxy = PostgresProxy(
            engine, auth_engine, config, trans_engine, committer, None
        )

        # Create engines in the cache
        proxy._resolve_target_engine({"database": "primary"})
        proxy._resolve_target_engine({"database": "secondary"})
        assert len(proxy._target_engines) == 2

        # Close should clear the cache
        proxy.close()
        assert len(proxy._target_engines) == 0


# ---------------------------------------------------------------------------
# Tests: Backward compatibility (single-target mode)
# ---------------------------------------------------------------------------


class TestSingleTargetBackwardCompat:
    """Tests that single-target mode (no targets set) still works as before."""

    def test_single_target_ignores_database_field(
        self, conn, engine, setup, key_manager, auth_engine, ep_service_id
    ):
        """In single-target mode, the 'database' field in the payload is
        ignored — execution always goes to target_connection_string."""
        db_url = _get_db_url()

        config = ProxyConfig(
            target_connection_string=db_url,
            proxy_audience="postgres-proxy",
            ep_service_principal_id=ep_service_id,
            targets=None,  # Single-target mode
        )

        trans_engine = TransitionEngine(engine, ep_service_id)
        committer = BranchCommitter(engine, ep_service_id)
        proxy = PostgresProxy(
            engine, auth_engine, config, trans_engine, committer, None
        )

        # Payload includes a 'database' field but it should be ignored
        arguments = {"sql": "SELECT 1 as val", "host": "localhost", "database": "anything"}
        transition, token = _propose_and_authorize(
            conn, engine, ep_service_id, setup["agent_id"], setup,
            auth_engine, key_manager, arguments=arguments,
        )
        if token is None:
            pytest.skip("Transition did not reach authorized stage")

        signed = token.to_signed_token(key_manager)
        payload = {"sql": "SELECT 1 as val", "host": "localhost", "database": "anything"}

        result = proxy.execute(
            signed, payload, key_manager.public_key,
            enforcement_capability=_proxy_scoped_capability(),
        )
        conn.commit()
        assert result.success is True
        proxy.close()

    def test_single_target_no_database_field(
        self, conn, engine, setup, key_manager, auth_engine, ep_service_id
    ):
        """Single-target mode works without a 'database' field (as before)."""
        db_url = _get_db_url()

        config = ProxyConfig(
            target_connection_string=db_url,
            proxy_audience="postgres-proxy",
            ep_service_principal_id=ep_service_id,
            targets=None,
        )

        trans_engine = TransitionEngine(engine, ep_service_id)
        committer = BranchCommitter(engine, ep_service_id)
        proxy = PostgresProxy(
            engine, auth_engine, config, trans_engine, committer, None
        )

        arguments = {"sql": "SELECT 1 as val", "host": "localhost"}
        transition, token = _propose_and_authorize(
            conn, engine, ep_service_id, setup["agent_id"], setup,
            auth_engine, key_manager, arguments=arguments,
        )
        if token is None:
            pytest.skip("Transition did not reach authorized stage")

        signed = token.to_signed_token(key_manager)
        payload = {"sql": "SELECT 1 as val", "host": "localhost"}

        result = proxy.execute(
            signed, payload, key_manager.public_key,
            enforcement_capability=_proxy_scoped_capability(),
        )
        conn.commit()
        assert result.success is True
        proxy.close()

    def test_empty_targets_dict_acts_as_single_target(
        self, conn, engine, setup, key_manager, auth_engine, ep_service_id
    ):
        """An empty targets dict should behave like single-target mode."""
        db_url = _get_db_url()

        config = ProxyConfig(
            target_connection_string=db_url,
            proxy_audience="postgres-proxy",
            ep_service_principal_id=ep_service_id,
            targets={},  # Empty dict — should fall back to single-target
        )

        trans_engine = TransitionEngine(engine, ep_service_id)
        committer = BranchCommitter(engine, ep_service_id)
        proxy = PostgresProxy(
            engine, auth_engine, config, trans_engine, committer, None
        )

        arguments = {"sql": "SELECT 1 as val", "host": "localhost"}
        transition, token = _propose_and_authorize(
            conn, engine, ep_service_id, setup["agent_id"], setup,
            auth_engine, key_manager, arguments=arguments,
        )
        if token is None:
            pytest.skip("Transition did not reach authorized stage")

        signed = token.to_signed_token(key_manager)
        payload = {"sql": "SELECT 1 as val", "host": "localhost"}

        result = proxy.execute(
            signed, payload, key_manager.public_key,
            enforcement_capability=_proxy_scoped_capability(),
        )
        conn.commit()
        assert result.success is True
        proxy.close()