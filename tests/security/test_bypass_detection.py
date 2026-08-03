"""Tests for EP-Governance bypass detection and reconciliation.

Uses SQLite in-memory DB. All external connections (PostgreSQL, network) are
mocked — no real target DB or network is required.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
import sqlalchemy as sa

from ep_governance.bypass_detection import (
    BypassDetector,
    ReconciliationReport,
    check_agent_network_access,
    check_credential_isolation,
    generate_alert,
    reconcile_postgres_activity,
)
from ep_governance.db import run_migrations
from ep_governance.db.postgres import create_engine, is_sqlite
from ep_governance.xid import XID


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _get_db_url() -> str:
    return "sqlite:///:memory:"


@pytest.fixture
def engine():
    """In-memory SQLite engine with migrations applied."""
    eng = create_engine(_get_db_url())
    with eng.connect() as conn:
        dialect = "sqlite" if is_sqlite(conn) else "postgres"
        run_migrations(conn, dialect)
        conn.commit()
    yield eng
    eng.dispose()


@pytest.fixture
def conn(engine):
    """A connection to the in-memory DB."""
    with engine.connect() as c:
        yield c


@pytest.fixture
def lattice_id(conn):
    """Create minimal project/lattice for FK constraints."""
    from ep_governance.db.repositories import (
        LatticeRepository,
        PrincipalRepository,
        ProjectRepository,
    )

    principal_repo = PrincipalRepository(conn)
    p = principal_repo.insert_principal(
        principal_id=str(XID.new()),
        name="EP Service",
        type="service",
        machine=None,
        description="EP service",
    )
    conn.commit()

    proj_repo = ProjectRepository(conn)
    project = proj_repo.create_project("Test", "Bypass detection test")
    lat_repo = LatticeRepository(conn)
    lattice = lat_repo.create_lattice(project["id"], "main")

    # Init audit head
    conn.execute(
        sa.text(
            "INSERT INTO ep_audit_heads (lattice_id, last_sequence, last_hash) "
            "VALUES (:lid, 0, :hash)"
        ),
        {"lid": lattice["id"], "hash": "0" * 64},
    )
    conn.commit()
    return lattice["id"]


def _insert_event(
    conn,
    lattice_id: str,
    event_type: str = "execution_succeeded",
    event_data: dict | None = None,
    sequence: int = 1,
) -> str:
    """Insert a raw row into ep_events for testing."""
    import hashlib
    import json

    from ep_governance.canonical import canonical_json

    event_id = str(XID.new())
    data = event_data or {}
    envelope = {
        "sequence": sequence,
        "event_id": event_id,
        "lattice_id": lattice_id,
        "event_type": event_type,
        "event_data": data,
        "actor_principal_id": None,
        "authenticated_caller_id": None,
        "event_writer_id": None,
        "created_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "previous_hash": "0" * 64,
    }
    event_hash = hashlib.sha256(
        canonical_json(envelope).encode("utf-8")
    ).hexdigest()

    conn.execute(
        sa.text(
            "INSERT INTO ep_events "
            "(id, lattice_id, sequence, event_type, event_data, "
            " previous_hash, event_hash, actor_principal_id, "
            " authenticated_caller_id, event_writer_id, created_at) "
            "VALUES "
            "(:id, :lattice_id, :sequence, :event_type, :event_data, "
            " :previous_hash, :event_hash, :actor_principal_id, "
            " :authenticated_caller_id, :event_writer_id, :created_at)"
        ),
        {
            "id": event_id,
            "lattice_id": lattice_id,
            "sequence": sequence,
            "event_type": event_type,
            "event_data": json.dumps(data),
            "previous_hash": "0" * 64,
            "event_hash": event_hash,
            "actor_principal_id": None,
            "authenticated_caller_id": None,
            "event_writer_id": None,
            "created_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        },
    )
    conn.commit()
    return event_id


# ---------------------------------------------------------------------------
# ReconciliationReport tests
# ---------------------------------------------------------------------------


class TestReconciliationReport:
    def test_creation_with_defaults(self):
        """ReconciliationReport can be created with no arguments."""
        report = ReconciliationReport()
        assert report.matched == []
        assert report.unmatched_target == []
        assert report.unmatched_ep == []
        assert report.bypass_detected is False
        assert report.checked_at == ""
        assert report.summary == ""

    def test_creation_with_fields(self):
        """ReconciliationReport fields can be set."""
        ep_ev = {"id": "evt1", "event_data": {"payload_hash": "abc123"}}
        tgt = {"payload_hash": "abc123", "query": "SELECT 1"}

        report = ReconciliationReport(
            matched=[(ep_ev, tgt)],
            unmatched_target=[{"query": "DROP TABLE users"}],
            unmatched_ep=[],
            bypass_detected=True,
            checked_at="2026-08-02T12:00:00.000000Z",
            summary="Bypass found",
        )
        assert len(report.matched) == 1
        assert report.matched[0] == (ep_ev, tgt)
        assert len(report.unmatched_target) == 1
        assert report.bypass_detected is True
        assert report.checked_at == "2026-08-02T12:00:00.000000Z"
        assert report.summary == "Bypass found"

    def test_bypass_detected_false_when_no_unmatched_target(self):
        """bypass_detected should be False when unmatched_target is empty."""
        report = ReconciliationReport(
            matched=[],
            unmatched_target=[],
            unmatched_ep=[{"id": "phantom"}],
            bypass_detected=False,
        )
        assert report.bypass_detected is False


# ---------------------------------------------------------------------------
# BypassDetector initialization tests
# ---------------------------------------------------------------------------


class TestBypassDetectorInit:
    def test_init_with_engine_only(self, engine):
        """BypassDetector can be created with just a governance engine."""
        detector = BypassDetector(engine)
        assert detector.gov_engine is engine
        assert detector._activity_reader is None

    def test_init_with_callable_reader(self, engine):
        """BypassDetector accepts a callable activity reader."""
        def reader(since=None):
            return []

        detector = BypassDetector(engine, activity_reader=reader)
        assert detector.gov_engine is engine
        assert detector._activity_reader is reader

    def test_init_with_protocol_reader(self, engine):
        """BypassDetector accepts a protocol-style reader with read_activity."""

        class FakeReader:
            def read_activity(self, since=None):
                return []

        reader = FakeReader()
        detector = BypassDetector(engine, activity_reader=reader)
        assert detector._activity_reader is reader


# ---------------------------------------------------------------------------
# Reconciliation tests
# ---------------------------------------------------------------------------


class TestReconciliation:
    def test_clean_state_no_mismatches(self, engine, conn, lattice_id):
        """Reconciliation with matching EP and target actions — no bypass."""
        payload_hash = "sha256:" + ("a" * 64)
        _insert_event(
            conn,
            lattice_id,
            event_data={"payload_hash": payload_hash, "action": "SELECT 1"},
            sequence=1,
        )

        def reader(since=None):
            return [{"payload_hash": payload_hash, "query": "SELECT 1"}]

        detector = BypassDetector(engine, activity_reader=reader)
        report = detector.reconcile_postgres_activity()

        assert len(report.matched) == 1
        assert len(report.unmatched_target) == 0
        assert len(report.unmatched_ep) == 0
        assert report.bypass_detected is False
        assert "0 unmatched target" in report.summary

    def test_bypass_detected_unmatched_target(self, engine, conn, lattice_id):
        """Target action with no EP authorization → bypass detected."""
        # EP has one authorized action.
        auth_hash = "sha256:" + ("b" * 64)
        _insert_event(
            conn,
            lattice_id,
            event_data={"payload_hash": auth_hash, "action": "SELECT 1"},
            sequence=1,
        )

        # Target has the authorized action PLUS an unauthorized one.
        rogue_hash = "sha256:" + ("c" * 64)

        def reader(since=None):
            return [
                {"payload_hash": auth_hash, "query": "SELECT 1"},
                {"payload_hash": rogue_hash, "query": "DROP TABLE users"},
            ]

        detector = BypassDetector(engine, activity_reader=reader)
        report = detector.reconcile_postgres_activity()

        assert len(report.matched) == 1
        assert len(report.unmatched_target) == 1
        assert report.unmatched_target[0]["query"] == "DROP TABLE users"
        assert report.bypass_detected is True
        assert "1 unmatched target" in report.summary

    def test_phantom_authorizations(self, engine, conn, lattice_id):
        """EP authorization with no corresponding target action → phantom."""
        auth_hash = "sha256:" + ("d" * 64)
        _insert_event(
            conn,
            lattice_id,
            event_data={"payload_hash": auth_hash, "action": "INSERT INTO t"},
            sequence=1,
        )

        # Target has no activity at all.
        def reader(since=None):
            return []

        detector = BypassDetector(engine, activity_reader=reader)
        report = detector.reconcile_postgres_activity()

        assert len(report.matched) == 0
        assert len(report.unmatched_target) == 0
        assert len(report.unmatched_ep) == 1
        assert report.bypass_detected is False  # no bypass, just phantom
        assert "1 unmatched EP" in report.summary

    def test_target_action_without_hash_is_flagged(self, engine, conn, lattice_id):
        """Target action with no extractable hash is flagged as bypass."""
        _insert_event(
            conn,
            lattice_id,
            event_data={"payload_hash": "sha256:" + ("e" * 64)},
            sequence=1,
        )

        def reader(since=None):
            return [{"query": "DELETE FROM users WHERE 1=1"}]  # no hash

        detector = BypassDetector(engine, activity_reader=reader)
        report = detector.reconcile_postgres_activity()

        assert len(report.unmatched_target) == 1
        assert report.bypass_detected is True

    def test_since_filter_applied(self, engine, conn, lattice_id):
        """The since parameter filters EP events by created_at."""
        old_hash = "sha256:" + ("f" * 64)
        _insert_event(
            conn,
            lattice_id,
            event_data={"payload_hash": old_hash},
            sequence=1,
        )

        # Query with a future timestamp — should find nothing.
        future = datetime.now(UTC) + timedelta(days=1)

        def reader(since=None):
            return []

        detector = BypassDetector(engine, activity_reader=reader)
        report = detector.reconcile_postgres_activity(since=future)

        assert len(report.matched) == 0
        assert len(report.unmatched_ep) == 0  # EP event is filtered out

    def test_module_level_function(self, engine, conn, lattice_id):
        """The module-level reconcile_postgres_activity works."""
        auth_hash = "sha256:" + ("g" * 64)
        _insert_event(
            conn,
            lattice_id,
            event_data={"payload_hash": auth_hash},
            sequence=1,
        )

        def reader(since=None):
            return [{"payload_hash": auth_hash, "query": "SELECT 1"}]

        # Module-level function does not accept a custom reader, so we patch
        # the default reader to return our test data.
        with patch(
            "ep_governance.bypass_detection._default_pg_activity_reader",
            return_value=[{"payload_hash": auth_hash, "query": "SELECT 1"}],
        ):
            report = reconcile_postgres_activity(
                gov_engine=engine,
                target_conn_params=None,
            )
        assert len(report.matched) == 1
        assert report.bypass_detected is False


# ---------------------------------------------------------------------------
# Alert generation tests
# ---------------------------------------------------------------------------


class TestGenerateAlert:
    def test_alert_for_bypass(self):
        """Alert message is generated when bypass is detected."""
        report = ReconciliationReport(
            matched=[],
            unmatched_target=[
                {"query": "DROP TABLE users", "payload_hash": "abc"},
            ],
            unmatched_ep=[],
            bypass_detected=True,
            checked_at="2026-08-02T12:00:00.000000Z",
            summary="1 bypass",
        )
        alert = generate_alert(report)
        assert "BYPASS DETECTED" in alert
        assert "DROP TABLE users" in alert
        assert "ACTION REQUIRED" in alert

    def test_alert_for_clean_state(self):
        """Alert message for clean state says no bypass."""
        report = ReconciliationReport(
            matched=[({"id": "e1"}, {"query": "SELECT 1"})],
            unmatched_target=[],
            unmatched_ep=[],
            bypass_detected=False,
            checked_at="2026-08-02T12:00:00.000000Z",
            summary="All good",
        )
        alert = generate_alert(report)
        assert "clean" in alert.lower()
        assert "no bypass" in alert.lower()
        assert "ACTION REQUIRED" not in alert

    def test_alert_includes_phantom_info(self):
        """Alert includes phantom authorization details when present."""
        report = ReconciliationReport(
            matched=[],
            unmatched_target=[{"query": "DELETE FROM t", "payload_hash": "x"}],
            unmatched_ep=[{"id": "ev1", "event_data": {"payload_hash": "y"}}],
            bypass_detected=True,
            checked_at="2026-08-02T12:00:00.000000Z",
            summary="Bypass + phantom",
        )
        alert = generate_alert(report)
        assert "Phantom" in alert
        assert "ev1" in alert


# ---------------------------------------------------------------------------
# Network access check tests
# ---------------------------------------------------------------------------


class TestCheckAgentNetworkAccess:
    def test_no_violations_when_all_blocked(self):
        """Returns empty list when no sensitive ports are reachable."""
        with patch(
            "ep_governance.bypass_detection._can_connect",
            return_value=False,
        ):
            result = check_agent_network_access("agent1", [])
        assert result == []

    def test_violations_when_ports_reachable(self):
        """Returns reachable endpoints that should be blocked."""
        def fake_connect(host, port, timeout=1.0):
            return port in (5432, 6379)

        with patch(
            "ep_governance.bypass_detection._can_connect",
            side_effect=fake_connect,
        ):
            result = check_agent_network_access("agent1", [])
        assert "agent1:5432" in result
        assert "agent1:6379" in result
        assert len(result) == 2

    def test_allowed_endpoints_excluded(self):
        """Endpoints in allowed_endpoints are not flagged."""
        def fake_connect(host, port, timeout=1.0):
            return port == 5432

        with patch(
            "ep_governance.bypass_detection._can_connect",
            side_effect=fake_connect,
        ):
            result = check_agent_network_access(
                "agent1", ["agent1:5432"]
            )
        assert result == []  # 5432 is allowed, so not a violation

    def test_can_connect_returns_false_on_error(self):
        """_can_connect returns False on OSError."""
        from ep_governance.bypass_detection import _can_connect

        # Use a non-resolvable hostname to trigger gaierror
        result = _can_connect("nonexistent.invalid.domain.xyz", 9999, timeout=0.5)
        assert result is False


# ---------------------------------------------------------------------------
# Credential isolation check tests
# ---------------------------------------------------------------------------


class TestCheckCredentialIsolation:
    def test_clean_host(self):
        """Returns empty list when no credentials are found."""
        result = check_credential_isolation("agent1", ["DB_PASSWORD", "API_KEY"])
        assert result == []

    def test_credentials_found(self):
        """Returns list of found credentials."""
        import ep_governance.bypass_detection as mod

        def fake_checker(host, cred):
            return cred == "DB_PASSWORD"

        original = mod._credential_checker
        mod._credential_checker = fake_checker
        try:
            result = check_credential_isolation("agent1", ["DB_PASSWORD", "API_KEY"])
        finally:
            mod._credential_checker = original

        assert result == ["DB_PASSWORD"]
        assert len(result) == 1

    def test_all_credentials_found(self):
        """Returns all credentials when checker finds everything."""
        import ep_governance.bypass_detection as mod

        def fake_checker(host, cred):
            return True

        original = mod._credential_checker
        mod._credential_checker = fake_checker
        try:
            result = check_credential_isolation(
                "agent1", ["DB_PASSWORD", "API_KEY", "SECRET_TOKEN"]
            )
        finally:
            mod._credential_checker = original

        assert len(result) == 3
        assert "DB_PASSWORD" in result
        assert "API_KEY" in result
        assert "SECRET_TOKEN" in result

    def test_empty_expected_credentials(self):
        """Returns empty list when no credentials are expected."""
        result = check_credential_isolation("agent1", [])
        assert result == []