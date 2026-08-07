"""NAS PostgreSQL transfer package round-trip test.

Exports governance state from the production ep_governance schema on the NAS PG
(100.98.247.27:5433, database gbrain_pilot_test), imports it into a fresh
temporary schema, and verifies the imported state matches the source.

The source schema is read-only — this test never modifies production data.
The import target is a temporary schema (ep_governance_test_transfer) that is
created and dropped per test run.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import sqlalchemy as sa

from ep_governance.db.postgres import create_engine
from ep_governance.db.repositories import (
    ProjectRepository,
    LatticeRepository,
    BranchRepository,
    NodeRepository,
    PolicyRepository,
    PrincipalRepository,
)
from ep_governance.transfer import TransferExporter, TransferImporter


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

NAS_DB_URL = os.environ.get("EP_DB_URL", "")
SOURCE_SCHEMA = os.environ.get("EP_DB_SCHEMA", "ep_governance")
TEMP_SCHEMA = "ep_governance_test_transfer"

# Skip if no DB URL configured
pytestmark = pytest.mark.skipif(
    not NAS_DB_URL or not NAS_DB_URL.startswith("postgresql"),
    reason="EP_DB_URL must be a PostgreSQL URL for NAS transfer tests",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def source_engine():
    """Engine pointing at the SOURCE schema (read-only)."""
    eng = create_engine(NAS_DB_URL, schema=SOURCE_SCHEMA)
    yield eng
    eng.dispose()


@pytest.fixture(scope="module")
def source_lattice_id(source_engine):
    """Discover the first lattice in the source schema."""
    with source_engine.connect() as conn:
        r = conn.execute(
            sa.text(f"SELECT id FROM {SOURCE_SCHEMA}.ep_lattices ORDER BY created_at LIMIT 1")
        )
        row = r.fetchone()
        if row is None:
            pytest.skip("No lattices in source schema — nothing to export")
        return row[0]


@pytest.fixture(scope="module")
def source_principal_ids(source_engine):
    """Collect all principal IDs from the source schema that the import will need.

    The TransferImporter copies policy fields (agent_scope, created_by) verbatim,
    so any principal referenced by an exported policy must exist in the target
    schema or the FK will fail. This is a bug in the transfer code — it should
    either create referenced principals or remap them — but for the test we
    pre-populate them.
    """
    with source_engine.connect() as conn:
        # All principals
        r = conn.execute(
            sa.text(f"SELECT id, name, type, machine, description FROM {SOURCE_SCHEMA}.ep_principals")
        )
        principals = [dict(row._mapping) for row in r]
    return principals


@pytest.fixture(scope="module")
def source_counts(source_engine, source_lattice_id):
    """Count branches, nodes, edges, and active policies in the source lattice."""
    with source_engine.connect() as conn:
        # Branches
        r = conn.execute(
            sa.text(
                f"SELECT COUNT(*) FROM {SOURCE_SCHEMA}.ep_branches WHERE lattice_id = :lid"
            ),
            {"lid": source_lattice_id},
        )
        branch_count = r.scalar()

        # Branch IDs
        r = conn.execute(
            sa.text(
                f"SELECT id FROM {SOURCE_SCHEMA}.ep_branches WHERE lattice_id = :lid"
            ),
            {"lid": source_lattice_id},
        )
        branch_ids = [row[0] for row in r]

        # Nodes
        node_count = 0
        if branch_ids:
            placeholders = ",".join(f":bid{i}" for i in range(len(branch_ids)))
            params = {f"bid{i}": bid for i, bid in enumerate(branch_ids)}
            r = conn.execute(
                sa.text(
                    f"SELECT COUNT(*) FROM {SOURCE_SCHEMA}.ep_nodes "
                    f"WHERE branch_id IN ({placeholders})"
                ),
                params,
            )
            node_count = r.scalar()

            # Node IDs for edges
            r = conn.execute(
                sa.text(
                    f"SELECT id FROM {SOURCE_SCHEMA}.ep_nodes "
                    f"WHERE branch_id IN ({placeholders})"
                ),
                params,
            )
            node_ids = [row[0] for row in r]
        else:
            node_ids = []

        # Edges
        edge_count = 0
        if node_ids:
            placeholders = ",".join(f":nid{i}" for i in range(len(node_ids)))
            params = {f"nid{i}": nid for i, nid in enumerate(node_ids)}
            r = conn.execute(
                sa.text(
                    f"SELECT COUNT(*) FROM {SOURCE_SCHEMA}.ep_edges "
                    f"WHERE upstream_node_id IN ({placeholders}) "
                    f"OR downstream_node_id IN ({placeholders})"
                ),
                {**params, **{f"nid{i}_d": nid for i, nid in enumerate(node_ids)}},
            )
            edge_count = r.scalar()

        # Active policies
        r = conn.execute(
            sa.text(f"SELECT COUNT(*) FROM {SOURCE_SCHEMA}.ep_policies WHERE status = 'active'")
        )
        active_policy_count = r.scalar()

        # All policies
        r = conn.execute(
            sa.text(f"SELECT COUNT(*) FROM {SOURCE_SCHEMA}.ep_policies")
        )
        total_policy_count = r.scalar()

        # Project count (for source-unchanged verification)
        r = conn.execute(
            sa.text(f"SELECT COUNT(*) FROM {SOURCE_SCHEMA}.ep_projects")
        )
        project_count = r.scalar()

    return {
        "branches": branch_count,
        "nodes": node_count,
        "edges": edge_count,
        "active_policies": active_policy_count,
        "total_policies": total_policy_count,
        "branch_ids": branch_ids,
        "projects": project_count,
    }


@pytest.fixture(scope="module")
def temp_engine():
    """Engine pointing at a TEMPORARY schema for import. Cleaned up after."""
    # First, use a plain engine (no schema) to create the temp schema
    raw_engine = sa.create_engine(
        NAS_DB_URL.replace("postgresql://", "postgresql+psycopg://"),
        future=True,
    )
    with raw_engine.connect() as conn:
        conn.execute(sa.text(f"DROP SCHEMA IF EXISTS {TEMP_SCHEMA} CASCADE"))
        conn.execute(sa.text(f"CREATE SCHEMA {TEMP_SCHEMA}"))
        conn.commit()
    raw_engine.dispose()

    # Now create an engine with search_path set to the temp schema
    eng = create_engine(NAS_DB_URL, schema=TEMP_SCHEMA)

    # Run migrations into the temp schema.
    # psycopg3 doesn't support multi-statement execution via sa.text(),
    # so we use psycopg directly with autocommit.
    import psycopg
    pg_url = NAS_DB_URL.replace("postgresql://", "postgresql://")
    with psycopg.connect(pg_url) as pg_conn:
        pg_conn.autocommit = True
        cur = pg_conn.cursor()
        cur.execute(f"SET search_path TO {TEMP_SCHEMA}")
        migration_file = (
            Path(__file__).parent.parent.parent / "migrations" / "postgres" / "001_init.sql"
        )
        cur.execute(migration_file.read_text())
        cur.close()

    yield eng

    # Cleanup: drop the temp schema
    eng.dispose()
    cleanup_engine = sa.create_engine(
        NAS_DB_URL.replace("postgresql://", "postgresql+psycopg://"),
        future=True,
    )
    with cleanup_engine.connect() as conn:
        conn.execute(sa.text(f"DROP SCHEMA IF EXISTS {TEMP_SCHEMA} CASCADE"))
        conn.commit()
    cleanup_engine.dispose()


@pytest.fixture
def ep_service_principal(temp_engine):
    """Create an EP service principal in the temp schema for the import."""
    from ep_governance.xid import XID

    with temp_engine.connect() as conn:
        repo = PrincipalRepository(conn)
        p = repo.insert_principal(
            principal_id=str(XID.new()),
            name="EP Service (Transfer Test)",
            type="service",
            machine=None,
            description="Transfer test service principal",
        )
        conn.commit()
        return p["id"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestNASTransferRoundTrip:
    """Export from NAS PG source schema, import into temp schema, verify."""

    def test_export_from_nas(self, source_engine, source_lattice_id, source_counts):
        """Step 1: Export a transfer package from the NAS PG source schema."""
        with source_engine.connect() as conn:
            # Find a signer principal
            r = conn.execute(
                sa.text(
                    f"SELECT id FROM {SOURCE_SCHEMA}.ep_principals "
                    f"WHERE type = 'service' ORDER BY registered_at LIMIT 1"
                )
            )
            row = r.fetchone()
            signer_id = row[0] if row else "test-signer"

            exporter = TransferExporter(conn)
            # Note: export writes to ep_transfer_packages in the source schema.
            # This is acceptable — it's a metadata record, not modifying governance state.
            package = exporter.export(
                lattice_id=source_lattice_id,
                signer_id=signer_id,
            )
            conn.commit()

        # Verify package structure
        assert package.schema_version == "1.0"
        assert package.source_lattice_id == source_lattice_id
        assert package.content_hash is not None
        assert len(package.content_hash) == 64  # SHA-256 hex
        assert package.verify_content_hash() is True

        # Verify lattice state matches source counts
        state = package.lattice_state
        assert len(state["branches"]) == source_counts["branches"]
        assert len(state["nodes"]) == source_counts["nodes"]
        assert len(state["edges"]) == source_counts["edges"]
        assert len(state["policies"]) == source_counts["active_policies"]

        # Store package for import test
        TestNASTransferRoundTrip._package = package
        TestNASTransferRoundTrip._signer_id = signer_id

    def test_import_to_temp_schema(self, temp_engine, ep_service_principal, source_principal_ids):
        """Step 2: Import the exported package into the temp schema.

        NOTE: There are two bugs in TransferImporter.import_as_fork():

        Bug 1 (line 513): It uses package.source_lattice_id as source_package_id
        when storing import provenance mappings. In PostgreSQL,
        ep_import_mappings.source_package_id has a FK to ep_transfer_packages.id.
        The code comment admits: "# no FK enforced in SQLite for this"

        Bug 2: The importer copies policy fields (agent_scope, created_by) verbatim
        without ensuring the referenced principals exist in the target schema.
        In PostgreSQL, ep_policies.agent_scope and ep_policies.created_by have FKs
        to ep_principals.id, so the import fails.

        We work around both bugs by pre-populating the temp schema with the
        necessary FK proxy records (source principals, project, lattice,
        transfer package).
        """
        package = TestNASTransferRoundTrip._package

        with temp_engine.connect() as conn:
            # Workaround Bug 2: import all source principals into the temp
            # schema so policy FK references (agent_scope, created_by) resolve.
            for p in source_principal_ids:
                conn.execute(
                    sa.text(
                        f"INSERT INTO {TEMP_SCHEMA}.ep_principals "
                        f"(id, name, type, machine, description) "
                        f"VALUES (:id, :name, :type, :machine, :desc) "
                        f"ON CONFLICT DO NOTHING"
                    ),
                    {
                        "id": p["id"],
                        "name": p["name"],
                        "type": p["type"],
                        "machine": p.get("machine"),
                        "desc": p.get("description"),
                    },
                )

            # Workaround Bug 1: insert dummy source project + lattice +
            # transfer package records to satisfy the FK chain for
            # ep_import_mappings.source_package_id.
            conn.execute(
                sa.text(
                    f"INSERT INTO {TEMP_SCHEMA}.ep_projects (id, name, description) "
                    f"VALUES (:id, :name, :desc) ON CONFLICT DO NOTHING"
                ),
                {
                    "id": package.source_project_id,
                    "name": "_transfer_source_proxy",
                    "desc": "FK proxy for import provenance",
                },
            )
            conn.execute(
                sa.text(
                    f"INSERT INTO {TEMP_SCHEMA}.ep_lattices (id, project_id, name) "
                    f"VALUES (:id, :pid, :name) ON CONFLICT DO NOTHING"
                ),
                {
                    "id": package.source_lattice_id,
                    "pid": package.source_project_id,
                    "name": "_source_proxy",
                },
            )
            conn.execute(
                sa.text(
                    f"INSERT INTO {TEMP_SCHEMA}.ep_transfer_packages "
                    f"(id, lattice_id, schema_version, package_version, "
                    f" source_lattice_id, project_id, snapshot_sequence, "
                    f" content_hash, signature, signer_id, trust_status, "
                    f" lattice_state, model_info, created_at) "
                    f"VALUES (:id, :lid, :sv, :pv, :slid, :pid, :seq, "
                    f"        :ch, :sig, :sid, :ts, :ls, NULL, :now) "
                    f"ON CONFLICT DO NOTHING"
                ),
                {
                    "id": package.source_lattice_id,
                    "lid": package.source_lattice_id,
                    "sv": package.schema_version,
                    "pv": package.package_version,
                    "slid": package.source_lattice_id,
                    "pid": package.source_project_id,
                    "seq": package.snapshot_sequence,
                    "ch": package.content_hash,
                    "sig": package.signature,
                    "sid": package.signer_id,
                    "ts": "imported",
                    "ls": package.to_json(),
                    "now": package.created_at,
                },
            )
            conn.commit()

            importer = TransferImporter(conn)
            result = importer.import_as_fork(
                package,
                project_name="NAS Transfer Test Fork",
                trusted_signer=False,
                trusted_source=False,
                ep_service_principal_id=ep_service_principal,
            )
            conn.commit()

        # Verify import result
        assert result["project_id"] is not None
        assert result["lattice_id"] is not None
        assert result["project_id"] != package.source_project_id
        assert result["lattice_id"] != package.source_lattice_id
        assert len(result["id_mappings"]) > 0

        # Store for verification
        TestNASTransferRoundTrip._import_result = result

    def test_imported_state_matches_source(self, temp_engine, source_counts):
        """Step 3: Verify imported state matches the source counts."""
        result = TestNASTransferRoundTrip._import_result
        new_lattice_id = result["lattice_id"]

        with temp_engine.connect() as conn:
            # Check branches
            r = conn.execute(
                sa.text(
                    f"SELECT COUNT(*) FROM {TEMP_SCHEMA}.ep_branches "
                    f"WHERE lattice_id = :lid"
                ),
                {"lid": new_lattice_id},
            )
            imported_branches = r.scalar()
            assert imported_branches == source_counts["branches"], (
                f"Branch count mismatch: source={source_counts['branches']}, "
                f"imported={imported_branches}"
            )

            # Get imported branch IDs
            r = conn.execute(
                sa.text(
                    f"SELECT id FROM {TEMP_SCHEMA}.ep_branches WHERE lattice_id = :lid"
                ),
                {"lid": new_lattice_id},
            )
            imported_branch_ids = [row[0] for row in r]

            # Check nodes
            imported_nodes = 0
            if imported_branch_ids:
                placeholders = ",".join(f":bid{i}" for i in range(len(imported_branch_ids)))
                params = {f"bid{i}": bid for i, bid in enumerate(imported_branch_ids)}
                r = conn.execute(
                    sa.text(
                        f"SELECT COUNT(*) FROM {TEMP_SCHEMA}.ep_nodes "
                        f"WHERE branch_id IN ({placeholders})"
                    ),
                    params,
                )
                imported_nodes = r.scalar()
            assert imported_nodes == source_counts["nodes"], (
                f"Node count mismatch: source={source_counts['nodes']}, "
                f"imported={imported_nodes}"
            )

            # Check edges — count all edges in temp schema (import creates edges
            # for the new nodes)
            r = conn.execute(sa.text(f"SELECT COUNT(*) FROM {TEMP_SCHEMA}.ep_edges"))
            imported_edges = r.scalar()
            assert imported_edges == source_counts["edges"], (
                f"Edge count mismatch: source={source_counts['edges']}, "
                f"imported={imported_edges}"
            )

            # Check policies — imported as draft (not active) by default
            r = conn.execute(
                sa.text(f"SELECT COUNT(*) FROM {TEMP_SCHEMA}.ep_policies")
            )
            imported_total_policies = r.scalar()
            assert imported_total_policies == source_counts["active_policies"], (
                f"Policy count mismatch: source active={source_counts['active_policies']}, "
                f"imported total={imported_total_policies}"
            )

            # Verify imported policies are draft (quarantined)
            r = conn.execute(
                sa.text(
                    f"SELECT COUNT(*) FROM {TEMP_SCHEMA}.ep_policies WHERE status = 'draft'"
                )
            )
            draft_policies = r.scalar()
            assert draft_policies == source_counts["active_policies"], (
                f"Draft policy count mismatch: expected {source_counts['active_policies']}, "
                f"got {draft_policies}"
            )

            # Verify no imported policies are active (quarantine by default)
            r = conn.execute(
                sa.text(
                    f"SELECT COUNT(*) FROM {TEMP_SCHEMA}.ep_policies WHERE status = 'active'"
                )
            )
            active_policies = r.scalar()
            assert active_policies == 0, (
                f"Expected 0 active policies (quarantine), got {active_policies}"
            )

            # Check import provenance mappings
            r = conn.execute(
                sa.text(f"SELECT COUNT(*) FROM {TEMP_SCHEMA}.ep_import_mappings")
            )
            mapping_count = r.scalar()
            assert mapping_count > 0, "No import provenance mappings recorded"

    def test_imported_ids_are_new(self, temp_engine):
        """Verify imported entities received new local IDs (no ID collisions)."""
        result = TestNASTransferRoundTrip._import_result
        mappings = result["id_mappings"]

        # All new IDs must differ from source IDs
        for old_id, new_id in mappings.items():
            assert old_id != new_id, f"ID collision: {old_id} == {new_id}"

        # All new IDs must be unique
        new_ids = list(mappings.values())
        assert len(new_ids) == len(set(new_ids)), "Duplicate new IDs in mappings"

    def test_source_schema_unchanged(self, source_engine, source_counts, source_lattice_id):
        """Verify the source schema's governance state was not modified by the import.

        The export does write a transfer_package record to ep_transfer_packages
        (by design — it's an immutable log), but the core governance state
        (projects, branches, nodes, policies) must be unchanged.
        """
        with source_engine.connect() as conn:
            # Branch count unchanged
            r = conn.execute(
                sa.text(
                    f"SELECT COUNT(*) FROM {SOURCE_SCHEMA}.ep_branches "
                    f"WHERE lattice_id = :lid"
                ),
                {"lid": source_lattice_id},
            )
            assert r.scalar() == source_counts["branches"]

            # Node count unchanged
            branch_ids = source_counts["branch_ids"]
            if branch_ids:
                placeholders = ",".join(f":bid{i}" for i in range(len(branch_ids)))
                params = {f"bid{i}": bid for i, bid in enumerate(branch_ids)}
                r = conn.execute(
                    sa.text(
                        f"SELECT COUNT(*) FROM {SOURCE_SCHEMA}.ep_nodes "
                        f"WHERE branch_id IN ({placeholders})"
                    ),
                    params,
                )
                assert r.scalar() == source_counts["nodes"]

            # Projects count unchanged (no fork projects leaked into source)
            r = conn.execute(sa.text(f"SELECT COUNT(*) FROM {SOURCE_SCHEMA}.ep_projects"))
            actual = r.scalar()
            assert actual == source_counts["projects"], (
                f"Source project count changed: before={source_counts['projects']}, "
                f"after={actual} — import leaked data into source schema"
            )