"""Phase 9 integration tests: transfer packages.

Tests export (signed snapshot), import as fork (new IDs, provenance),
imported policy quarantine, and prohibited import rejection.
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
    ProjectRepository,
    LatticeRepository,
    BranchRepository,
    NodeRepository,
    PolicyRepository,
    PrincipalRepository,
)
from ep_governance.xid import XID
from ep_governance.authorizations import KeyManager
from ep_governance.transfer import (
    TransferPackage,
    TransferExporter,
    TransferImporter,
    PROHIBITED_IMPORTS,
)
from ep_governance.errors import TransferImportError


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
        description="EP service",
    )
    conn.commit()
    return p["id"]


@pytest.fixture
def setup(conn, ep_service_id):
    proj_repo = ProjectRepository(conn)
    project = proj_repo.create_project("Source Project", "Original")

    lat_repo = LatticeRepository(conn)
    lattice = lat_repo.create_lattice(project["id"], "main")

    branch_repo = BranchRepository(conn)
    branch = branch_repo.create_branch(lattice["id"], "main")

    # Create a committed node
    node_repo = NodeRepository(conn)
    node = node_repo.insert_node(
        node_id=str(XID.new()),
        branch_id=branch["id"],
        agent_id=ep_service_id,
        description="Initial state",
        bt_planning_budget=100.0,
        metadata={},
    )
    branch_repo.update_head(branch["id"], node["id"], 1)
    conn.commit()

    # Create an active policy
    policy_repo = PolicyRepository(conn)
    policy_repo.insert_policy(
        {
            "id": str(XID.new()),
            "effect": "deny",
            "actions": ["db.drop"],
            "resources": ["postgres://**"],
            "conditions": {},
            "priority": 100,
            "scope": "global",
            "agent_scope": None,
            "description": "Deny drop",
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
    conn.commit()

    return {
        "project": project,
        "lattice": lattice,
        "branch": branch,
        "node": node,
        "ep_service_id": ep_service_id,
    }


class TestExport:
    def test_export_creates_package(self, conn, setup):
        """Export should create a transfer package with all required fields."""
        exporter = TransferExporter(conn)
        package = exporter.export(
            lattice_id=setup["lattice"]["id"],
            signer_id=setup["ep_service_id"],
        )
        conn.commit()

        assert package.schema_version == "1.0"
        assert package.source_lattice_id == setup["lattice"]["id"]
        assert package.source_project_id == setup["project"]["id"]
        assert package.snapshot_sequence == 1
        assert len(package.content_hash) == 64  # SHA-256 hex
        assert package.signer_id == setup["ep_service_id"]
        assert package.trust_status == "trusted"
        assert "branches" in package.lattice_state
        assert "nodes" in package.lattice_state
        assert "policies" in package.lattice_state

    def test_export_content_hash_verifies(self, conn, setup):
        """The content hash must match the lattice state."""
        exporter = TransferExporter(conn)
        package = exporter.export(
            lattice_id=setup["lattice"]["id"],
            signer_id=setup["ep_service_id"],
        )
        conn.commit()
        assert package.verify_content_hash() is True

    def test_export_with_signing(self, conn, setup):
        """Export with a signing key should produce a non-empty signature."""
        km = KeyManager()
        private_key_bytes = bytes(km.private_key)

        exporter = TransferExporter(conn)
        package = exporter.export(
            lattice_id=setup["lattice"]["id"],
            signer_id=setup["ep_service_id"],
            signing_key=private_key_bytes,
        )
        conn.commit()
        assert package.signature != ""
        assert len(package.signature) > 0

    def test_export_does_not_modify_source(self, conn, setup):
        """Export must not modify the source lattice."""
        exporter = TransferExporter(conn)
        exporter.export(
            lattice_id=setup["lattice"]["id"],
            signer_id=setup["ep_service_id"],
        )
        conn.commit()

        # Source project still exists with same name
        proj_repo = ProjectRepository(conn)
        project = proj_repo.get_project(setup["project"]["id"])
        assert project is not None
        assert project["name"] == "Source Project"

    def test_export_to_json_roundtrip(self, conn, setup):
        """Package should survive JSON serialization roundtrip."""
        exporter = TransferExporter(conn)
        package = exporter.export(
            lattice_id=setup["lattice"]["id"],
            signer_id=setup["ep_service_id"],
        )
        conn.commit()

        json_str = package.to_json()
        restored = TransferPackage.from_json(json_str)
        assert restored.source_lattice_id == package.source_lattice_id
        assert restored.content_hash == package.content_hash
        assert restored.verify_content_hash() is True


class TestImport:
    def test_import_creates_new_project(self, conn, setup):
        """Import should create a new project, not overwrite the source."""
        exporter = TransferExporter(conn)
        package = exporter.export(
            lattice_id=setup["lattice"]["id"],
            signer_id=setup["ep_service_id"],
        )
        conn.commit()

        importer = TransferImporter(conn)
        result = importer.import_as_fork(
            package, "Forked Project", ep_service_principal_id=setup["ep_service_id"]
        )
        conn.commit()

        assert result["project_id"] != setup["project"]["id"]
        assert result["lattice_id"] != setup["lattice"]["id"]

    def test_import_generates_new_ids(self, conn, setup):
        """Imported entities should receive new local IDs."""
        exporter = TransferExporter(conn)
        package = exporter.export(
            lattice_id=setup["lattice"]["id"],
            signer_id=setup["ep_service_id"],
        )
        conn.commit()

        importer = TransferImporter(conn)
        result = importer.import_as_fork(
            package, "Forked Project", ep_service_principal_id=setup["ep_service_id"]
        )
        conn.commit()

        # ID mappings should be non-empty
        assert len(result["id_mappings"]) > 0
        # All new IDs should be different from source IDs
        for old_id, new_id in result["id_mappings"].items():
            assert old_id != new_id

    def test_import_preserves_provenance(self, conn, setup):
        """Import provenance mappings should be stored in ep_import_mappings."""
        exporter = TransferExporter(conn)
        package = exporter.export(
            lattice_id=setup["lattice"]["id"],
            signer_id=setup["ep_service_id"],
        )
        conn.commit()

        importer = TransferImporter(conn)
        importer.import_as_fork(
            package, "Forked Project", ep_service_principal_id=setup["ep_service_id"]
        )
        conn.commit()

        # Check import mappings exist
        result = conn.execute(sa.text("SELECT COUNT(*) FROM ep_import_mappings"))
        count = result.scalar()
        assert count > 0

    def test_imported_policies_quarantined_by_default(self, conn, setup):
        """Imported policies should be draft with pending_review when signer/source not trusted."""
        exporter = TransferExporter(conn)
        package = exporter.export(
            lattice_id=setup["lattice"]["id"],
            signer_id=setup["ep_service_id"],
        )
        conn.commit()

        importer = TransferImporter(conn)
        result = importer.import_as_fork(
            package,
            "Forked Project",
            trusted_signer=False,
            trusted_source=False,
            ep_service_principal_id=setup["ep_service_id"],
        )
        conn.commit()

        assert result["policies_imported"] > 0
        assert result["policies_active"] == 0  # none active by default

    def test_imported_policies_active_when_trusted(self, conn, setup):
        """Imported policies should be active when signer and source are trusted."""
        exporter = TransferExporter(conn)
        package = exporter.export(
            lattice_id=setup["lattice"]["id"],
            signer_id=setup["ep_service_id"],
        )
        conn.commit()

        importer = TransferImporter(conn)
        result = importer.import_as_fork(
            package,
            "Forked Project",
            trusted_signer=True,
            trusted_source=True,
            ep_service_principal_id=setup["ep_service_id"],
        )
        conn.commit()

        assert result["policies_active"] > 0

    def test_content_hash_mismatch_rejected(self, conn, setup):
        """Import should fail if content hash does not match."""
        exporter = TransferExporter(conn)
        package = exporter.export(
            lattice_id=setup["lattice"]["id"],
            signer_id=setup["ep_service_id"],
        )
        conn.commit()

        # Tamper with the lattice state
        package.lattice_state["tampered"] = True

        importer = TransferImporter(conn)
        with pytest.raises(TransferImportError):
            importer.import_as_fork(
                package, "Forked", ep_service_principal_id=setup["ep_service_id"]
            )
        conn.rollback()

    def test_prohibited_imports_rejected(self, conn, setup):
        """Import should reject packages containing prohibited items."""
        exporter = TransferExporter(conn)
        package = exporter.export(
            lattice_id=setup["lattice"]["id"],
            signer_id=setup["ep_service_id"],
        )
        conn.commit()

        # Add a prohibited item
        package.lattice_state["active_authorization_tokens"] = [{"token": "secret"}]
        # Fix the content hash so the check passes to the prohibited check
        package.content_hash = __import__(
            "ep_governance.canonical", fromlist=["canonical_hash"]
        ).canonical_hash(package.lattice_state)

        importer = TransferImporter(conn)
        with pytest.raises(TransferImportError, match="Prohibited"):
            importer.import_as_fork(
                package, "Forked", ep_service_principal_id=setup["ep_service_id"]
            )
        conn.rollback()


class TestProhibitedImports:
    def test_prohibited_imports_set(self):
        """The prohibited imports set should contain all specified items."""
        assert "active_authorization_tokens" in PROHIBITED_IMPORTS
        assert "operational_credentials" in PROHIBITED_IMPORTS
        assert "private_signing_keys" in PROHIBITED_IMPORTS
        assert "live_sessions" in PROHIBITED_IMPORTS
        assert "unexpired_approvals" in PROHIBITED_IMPORTS
        assert "runtime_sockets" in PROHIBITED_IMPORTS
        assert "environment_configuration" in PROHIBITED_IMPORTS
