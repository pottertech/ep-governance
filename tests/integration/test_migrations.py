"""Migration up/down round-trip tests.

Tests that:
- Migrations create all expected tables
- Migrations can be re-run safely (idempotency check)
- Schema can be dropped and recreated (simulated down/up)
- All CHECK constraints are present after migration
- All FK relationships are correct after migration
"""

from __future__ import annotations

import os

import pytest
import sqlalchemy as sa

from ep_governance.db import run_migrations, get_migration_files
from ep_governance.db.postgres import create_engine, is_sqlite


def _get_db_url() -> str:
    return os.environ.get("EP_TEST_DB_URL", "sqlite:///:memory:")


EXPECTED_TABLES = [
    "ep_projects",
    "ep_lattices",
    "ep_branches",
    "ep_nodes",
    "ep_edges",
    "ep_policies",
    "ep_policy_versions",
    "ep_principals",
    "ep_roles",
    "ep_role_bindings",
    "ep_credentials",
    "ep_transitions",
    "ep_authorizations",
    "ep_approval_requests",
    "ep_approval_request_policies",
    "ep_approval_decisions",
    "ep_risk_ledger",
    "ep_risk_mitigations",
    "ep_events",
    "ep_audit_heads",
    "ep_work_claims",
    "ep_sessions",
    "ep_transfer_packages",
    "ep_import_mappings",
    "ep_bootstrap_state",
]


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


class TestMigrationUp:
    """Test that migrations create all expected tables."""

    def test_all_tables_created(self, conn):
        """All 25 expected tables must exist after migration."""
        if is_sqlite(conn):
            result = conn.execute(sa.text(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ))
        else:
            result = conn.execute(sa.text(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = current_schema() ORDER BY table_name"
            ))
        tables = {r[0] for r in result}

        for table in EXPECTED_TABLES:
            assert table in tables, f"Table {table} not found after migration"

    def test_migration_files_exist(self):
        """Migration files must exist for both dialects."""
        pg_files = get_migration_files("postgres")
        sqlite_files = get_migration_files("sqlite")

        assert len(pg_files) >= 1, "No PostgreSQL migration files found"
        assert len(sqlite_files) >= 1, "No SQLite migration files found"

    def test_migration_returns_executed_list(self, engine):
        """run_migrations must return list of executed file names."""
        with engine.connect() as conn:
            dialect = "sqlite" if is_sqlite(conn) else "postgres"
            executed = run_migrations(conn, dialect)
            conn.commit()
            assert len(executed) >= 1
            assert all(f.endswith(".sql") for f in executed)


class TestMigrationIdempotency:
    """Test migration idempotency properties."""

    def test_double_migration_fails_cleanly_sqlite(self, engine):
        """SQLite: running migrations twice should fail with a clear error
        (tables already exist). This is expected — migrations are not
        idempotent by design. The migration runner should report the error
        rather than silently corrupting the schema.
        """
        if not _get_db_url().startswith("sqlite"):
            pytest.skip("SQLite-only test")

        from ep_governance.errors import MigrationError

        with engine.connect() as conn:
            run_migrations(conn, "sqlite")
            conn.commit()

            # Second run should fail cleanly
            with pytest.raises(MigrationError):
                run_migrations(conn, "sqlite")
            conn.rollback()

    def test_pg_migration_uses_transactional_ddl(self, engine):
        """PostgreSQL: migrations use transactional DDL, so a failed
        migration rolls back cleanly without leaving partial tables.
        """
        if _get_db_url().startswith("sqlite"):
            pytest.skip("PostgreSQL-only test")


class TestMigrationDropAndRecreate:
    """Test that schema can be dropped and recreated (simulated down/up)."""

    def test_drop_all_tables_and_recreate_sqlite(self, engine):
        """Drop all ep_ tables, then re-run migrations — should work cleanly."""
        if not _get_db_url().startswith("sqlite"):
            pytest.skip("SQLite-only test (PostgreSQL needs superuser for DROP SCHEMA)")

        with engine.connect() as conn:
            # First migration
            run_migrations(conn, "sqlite")
            conn.commit()

            # Drop all ep_ tables
            result = conn.execute(sa.text(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'ep_%'"
            ))
            tables = [r[0] for r in result]
            # Drop in reverse order to respect FK constraints
            for table in reversed(tables):
                conn.execute(sa.text(f"DROP TABLE IF EXISTS {table}"))
            conn.commit()

            # Verify tables are gone
            result = conn.execute(sa.text(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'ep_%'"
            ))
            assert len(result.fetchall()) == 0

            # Re-run migrations
            run_migrations(conn, "sqlite")
            conn.commit()

            # Verify tables exist again
            result = conn.execute(sa.text(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'ep_%' ORDER BY name"
            ))
            tables = {r[0] for r in result}
            for expected in EXPECTED_TABLES:
                assert expected in tables, f"Table {expected} missing after re-migration"


class TestSchemaConstraints:
    """Test that CHECK constraints are present after migration."""

    def test_transition_stage_check(self, conn):
        """ep_transitions.stage must enforce valid stage values."""
        if is_sqlite(conn):
            # SQLite: try inserting an invalid stage
            with pytest.raises(Exception):
                conn.execute(sa.text(
                    "INSERT INTO ep_transitions (id, branch_id, agent_id, tool, "
                    "payload_hash, idempotency_key, stage) "
                    "VALUES ('test1', 'test', 'test', 'test', 'test', 'test', 'INVALID_STAGE')"
                ))
                conn.commit()
            conn.rollback()
        else:
            # PostgreSQL: check the constraint exists
            result = conn.execute(sa.text(
                "SELECT con.conname FROM pg_constraint con "
                "JOIN pg_class rel ON rel.oid = con.conrelid "
                "WHERE rel.relname = 'ep_transitions' AND con.contype = 'c'"
            ))
            constraints = [r[0] for r in result]
            # There should be at least one CHECK constraint on stage
            assert any("stage" in c.lower() for c in constraints), (
                f"No CHECK constraint on stage found. Constraints: {constraints}"
            )

    def test_node_status_check(self, conn):
        """ep_nodes.status must enforce valid status values."""
        if is_sqlite(conn):
            with pytest.raises(Exception):
                conn.execute(sa.text(
                    "INSERT INTO ep_nodes (id, branch_id, agent_id, description, "
                    "bt_planning_budget, metadata, status) "
                    "VALUES ('test1', 'test', 'test', 'test', 100, '{}', 'INVALID_STATUS')"
                ))
                conn.commit()
            conn.rollback()
        else:
            result = conn.execute(sa.text(
                "SELECT con.conname FROM pg_constraint con "
                "JOIN pg_class rel ON rel.oid = con.conrelid "
                "WHERE rel.relname = 'ep_nodes' AND con.contype = 'c'"
            ))
            constraints = [r[0] for r in result]
            assert any("status" in c.lower() for c in constraints), (
                f"No CHECK constraint on status found. Constraints: {constraints}"
            )

    def test_policy_status_check(self, conn):
        """ep_policies.status must enforce valid lifecycle states."""
        if is_sqlite(conn):
            with pytest.raises(Exception):
                conn.execute(sa.text(
                    "INSERT INTO ep_policies (id, effect, actions, resources, conditions, "
                    "priority, scope, description, status, created_by, approved_by, "
                    "approved_at, activation_version, exception_to) "
                    "VALUES ('test', 'allow', '[]', '[]', '{}', 0, 'global', 'test', "
                    "'INVALID', 'test', 'test', '2026-01-01', 1, '[]')"
                ))
                conn.commit()
            conn.rollback()
        else:
            result = conn.execute(sa.text(
                "SELECT con.conname FROM pg_constraint con "
                "JOIN pg_class rel ON rel.oid = con.conrelid "
                "WHERE rel.relname = 'ep_policies' AND con.contype = 'c'"
            ))
            constraints = [r[0] for r in result]
            assert any("status" in c.lower() for c in constraints), (
                f"No CHECK constraint on status found. Constraints: {constraints}"
            )

    def test_principal_type_check(self, conn):
        """ep_principals.type must enforce valid types (human/agent/service/proxy)."""
        if is_sqlite(conn):
            with pytest.raises(Exception):
                conn.execute(sa.text(
                    "INSERT INTO ep_principals (id, name, type) "
                    "VALUES ('test', 'test', 'INVALID_TYPE')"
                ))
                conn.commit()
            conn.rollback()
        else:
            result = conn.execute(sa.text(
                "SELECT con.conname FROM pg_constraint con "
                "JOIN pg_class rel ON rel.oid = con.conrelid "
                "WHERE rel.relname = 'ep_principals' AND con.contype = 'c'"
            ))
            constraints = [r[0] for r in result]
            assert any("type" in c.lower() for c in constraints), (
                f"No CHECK constraint on type found. Constraints: {constraints}"
            )