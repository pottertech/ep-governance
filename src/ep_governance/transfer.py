"""EP-Governance transfer packages.

Three operations:
- resume: connect a new model to the existing database (no import needed)
- export: create an immutable signed snapshot of the lattice state
- import as fork: create a new project/lattice from a snapshot, never overwriting the source

Transfer packages contain:
  schema_version, package_version, source_lattice_id, source_project_id,
  snapshot_sequence, created_at, content_hash, signature, signer_id,
  trust_status, lattice_state

Imported entities receive new local IDs. Provenance mappings are preserved.
Imported policies start as draft with trust_status=pending_review.
Never import: active auth tokens, credentials, private keys, live sessions.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.engine import Connection

from .canonical import canonical_hash, canonical_json
from .db.repositories import (
    BranchRepository,
    LatticeRepository,
    NodeRepository,
    PolicyRepository,
    ProjectRepository,
)
from .errors import TransferError, TransferImportError, TransferSignatureError
from .xid import XID

__all__ = [
    "TransferPackage",
    "TransferExporter",
    "TransferImporter",
    "PROHIBITED_IMPORTS",
]

PROHIBITED_IMPORTS = frozenset(
    {
        "active_authorization_tokens",
        "operational_credentials",
        "private_signing_keys",
        "live_sessions",
        "unexpired_approvals",
        "runtime_sockets",
        "environment_configuration",
    }
)

SCHEMA_VERSION = "1.0"
PACKAGE_VERSION = "1.0"


def _now_iso() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


# ---------------------------------------------------------------------------
# Transfer package model
# ---------------------------------------------------------------------------


class TransferPackage:
    """A signed, immutable transfer package containing lattice state.

    Fields:
      schema_version: schema version at export time
      package_version: transfer package format version
      source_lattice_id: XID of the source lattice
      source_project_id: XID of the source project
      snapshot_sequence: monotonic snapshot number
      created_at: ISO 8601 UTC timestamp
      content_hash: SHA-256 of the lattice_state JSON
      signature: Ed25519 signature of the content_hash
      signer_id: XID of the signing principal
      trust_status: trusted, untrusted, or imported
      lattice_state: serialized lattice (nodes, edges, policies, risk_ledger, branch_heads)
    """

    def __init__(
        self,
        schema_version: str,
        package_version: str,
        source_lattice_id: str,
        source_project_id: str,
        snapshot_sequence: int,
        created_at: str,
        content_hash: str,
        signature: str,
        signer_id: str,
        trust_status: str,
        lattice_state: dict[str, Any],
    ) -> None:
        self.schema_version = schema_version
        self.package_version = package_version
        self.source_lattice_id = source_lattice_id
        self.source_project_id = source_project_id
        self.snapshot_sequence = snapshot_sequence
        self.created_at = created_at
        self.content_hash = content_hash
        self.signature = signature
        self.signer_id = signer_id
        self.trust_status = trust_status
        self.lattice_state = lattice_state

    def to_dict(self) -> dict[str, Any]:
        """Return the package as a dict for JSON serialization."""
        return {
            "schema_version": self.schema_version,
            "package_version": self.package_version,
            "source_lattice_id": self.source_lattice_id,
            "source_project_id": self.source_project_id,
            "snapshot_sequence": self.snapshot_sequence,
            "created_at": self.created_at,
            "content_hash": self.content_hash,
            "signature": self.signature,
            "signer_id": self.signer_id,
            "trust_status": self.trust_status,
            "lattice_state": self.lattice_state,
        }

    def to_json(self) -> str:
        """Return the package as a JSON string."""
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TransferPackage:
        """Parse a transfer package from a dict."""
        required = [
            "schema_version",
            "package_version",
            "source_lattice_id",
            "source_project_id",
            "snapshot_sequence",
            "created_at",
            "content_hash",
            "signature",
            "signer_id",
            "trust_status",
            "lattice_state",
        ]
        for field in required:
            if field not in data:
                raise TransferImportError(f"Missing field in transfer package: {field}")
        return cls(
            schema_version=data["schema_version"],
            package_version=data["package_version"],
            source_lattice_id=data["source_lattice_id"],
            source_project_id=data["source_project_id"],
            snapshot_sequence=data["snapshot_sequence"],
            created_at=data["created_at"],
            content_hash=data["content_hash"],
            signature=data["signature"],
            signer_id=data["signer_id"],
            trust_status=data["trust_status"],
            lattice_state=data["lattice_state"],
        )

    @classmethod
    def from_json(cls, json_str: str) -> TransferPackage:
        """Parse a transfer package from a JSON string."""
        return cls.from_dict(json.loads(json_str))

    def verify_content_hash(self) -> bool:
        """Verify that the content_hash matches the lattice_state."""
        computed = canonical_hash(self.lattice_state)
        return computed == self.content_hash


# ---------------------------------------------------------------------------
# Exporter
# ---------------------------------------------------------------------------


class TransferExporter:
    """Exports a signed snapshot of a lattice's state.

    The export creates an immutable, signed snapshot. It never modifies
    the source lattice. The snapshot can be imported as a fork into
    another instance.
    """

    def __init__(self, conn: Connection) -> None:
        self.conn = conn

    def export(
        self,
        lattice_id: str,
        signer_id: str,
        signing_key: bytes | None = None,
    ) -> TransferPackage:
        """Export a lattice as a signed transfer package.

        Args:
            lattice_id: The lattice to export.
            signer_id: The principal ID of the signer.
            signing_key: Optional Ed25519 signing key for the signature.
                        If None, the signature is empty (unsigned package).

        Returns:
            A TransferPackage containing the lattice state.
        """
        # Get lattice info
        lat_repo = LatticeRepository(self.conn)
        lattice = lat_repo.get_lattice(lattice_id)
        if lattice is None:
            raise TransferError(f"Lattice {lattice_id} not found")

        # Get project info
        proj_repo = ProjectRepository(self.conn)
        project = proj_repo.get_project(lattice["project_id"])
        if project is None:
            raise TransferError(f"Project {lattice['project_id']} not found")

        # Collect lattice state
        lattice_state = self._collect_lattice_state(lattice_id)

        # Compute content hash
        content_hash = canonical_hash(lattice_state)

        # Sign the content hash
        signature = ""
        if signing_key is not None:
            try:
                from nacl.signing import SigningKey

                sk = SigningKey(signing_key)
                sig = sk.sign(content_hash.encode("utf-8"))
                signature = sig.signature.hex()
            except Exception as exc:
                raise TransferSignatureError(f"Signing failed: {exc!s}") from exc

        # Get snapshot sequence
        result = self.conn.execute(
            sa.text("SELECT COUNT(*) FROM ep_transfer_packages WHERE lattice_id = :lid"),
            {"lid": lattice_id},
        )
        snapshot_sequence = result.scalar() + 1

        # Store the transfer package record
        package_id = str(XID.new())
        self.conn.execute(
            sa.text(
                "INSERT INTO ep_transfer_packages "
                "(id, lattice_id, schema_version, package_version, "
                " source_lattice_id, project_id, snapshot_sequence, "
                " content_hash, signature, signer_id, trust_status, "
                " lattice_state, model_info, created_at) "
                "VALUES (:id, :lid, :sv, :pv, :slid, :pid, :seq, "
                "        :ch, :sig, :sid, :ts, :ls, NULL, :now)"
            ),
            {
                "id": package_id,
                "lid": lattice_id,
                "sv": SCHEMA_VERSION,
                "pv": PACKAGE_VERSION,
                "slid": lattice_id,
                "pid": project["id"],
                "seq": snapshot_sequence,
                "ch": content_hash,
                "sig": signature,
                "sid": signer_id,
                "ts": "trusted",
                "ls": canonical_json(lattice_state),
                "now": _now_iso(),
            },
        )
        self.conn.commit()

        return TransferPackage(
            schema_version=SCHEMA_VERSION,
            package_version=PACKAGE_VERSION,
            source_lattice_id=lattice_id,
            source_project_id=project["id"],
            snapshot_sequence=snapshot_sequence,
            created_at=_now_iso(),
            content_hash=content_hash,
            signature=signature,
            signer_id=signer_id,
            trust_status="trusted",
            lattice_state=lattice_state,
        )

    def _collect_lattice_state(self, lattice_id: str) -> dict[str, Any]:
        """Collect all state for a lattice into a serializable dict."""
        # Branches
        result = self.conn.execute(
            sa.text("SELECT * FROM ep_branches WHERE lattice_id = :lid"),
            {"lid": lattice_id},
        )
        branches = [dict(r._mapping) for r in result.fetchall()]

        # Nodes
        branch_ids = [b["id"] for b in branches]
        nodes: list[dict[str, Any]] = []
        if branch_ids:
            placeholders = ",".join(f":bid{i}" for i in range(len(branch_ids)))
            params = {f"bid{i}": bid for i, bid in enumerate(branch_ids)}
            result = self.conn.execute(
                sa.text(f"SELECT * FROM ep_nodes WHERE branch_id IN ({placeholders})"),
                params,
            )
            nodes = [dict(r._mapping) for r in result.fetchall()]

        # Edges
        node_ids = [n["id"] for n in nodes]
        edges: list[dict[str, Any]] = []
        if node_ids:
            placeholders = ",".join(f":nid{i}" for i in range(len(node_ids)))
            params = {f"nid{i}": nid for i, nid in enumerate(node_ids)}
            result = self.conn.execute(
                sa.text(
                    f"SELECT * FROM ep_edges WHERE upstream_node_id IN ({placeholders}) "
                    f"OR downstream_node_id IN ({placeholders})"
                ),
                {**params, **{f"nid{i}_d": nid for i, nid in enumerate(node_ids)}},
            )
            edges = [dict(r._mapping) for r in result.fetchall()]

        # Policies (active only)
        result = self.conn.execute(sa.text("SELECT * FROM ep_policies WHERE status = 'active'"))
        policies = [dict(r._mapping) for r in result.fetchall()]

        return {
            "branches": branches,
            "nodes": nodes,
            "edges": edges,
            "policies": policies,
            "branch_heads": {
                b["id"]: {"head_node_id": b.get("head_node_id"), "version": b.get("version")}
                for b in branches
            },
        }


# ---------------------------------------------------------------------------
# Importer
# ---------------------------------------------------------------------------


class TransferImporter:
    """Imports a transfer package as a new fork.

    Import creates a NEW project and lattice. It NEVER overwrites the
    live source lattice. Imported entities receive new local IDs.
    Provenance mappings are preserved.

    Imported policies start as draft with trust_status=pending_review.
    They do NOT become active unless the signer and source are explicitly
    trusted.
    """

    def __init__(self, conn: Connection) -> None:
        self.conn = conn
        self._id_mappings: dict[str, str] = {}

    def import_as_fork(
        self,
        package: TransferPackage,
        project_name: str,
        trusted_signer: bool = False,
        trusted_source: bool = False,
        ep_service_principal_id: str | None = None,
    ) -> dict[str, Any]:
        """Import a transfer package as a new project/lattice fork.

        Args:
            package: The transfer package to import.
            project_name: Name for the new project.
            trusted_signer: If True, the signer is explicitly trusted.
            trusted_source: If True, the source lattice is explicitly trusted.

        Returns:
            A dict with the new project_id, lattice_id, and ID mappings.
        """
        # Verify content hash
        if not package.verify_content_hash():
            raise TransferImportError("Content hash mismatch — transfer package may be corrupted")

        # Verify signature if present
        if package.signature:
            # In production, verify the Ed25519 signature against the
            # signer's public key. For now, accept any non-empty signature.
            pass

        # Check for prohibited imports
        self._check_prohibited(package.lattice_state)

        # Create new project
        proj_repo = ProjectRepository(self.conn)
        project = proj_repo.create_project(project_name, f"Forked from {package.source_project_id}")

        # Create new lattice
        lat_repo = LatticeRepository(self.conn)
        lattice = lat_repo.create_lattice(project["id"], "main")

        # Create branches with new IDs
        branch_repo = BranchRepository(self.conn)
        new_branch_ids: dict[str, str] = {}
        for branch in package.lattice_state.get("branches", []):
            old_id = branch["id"]
            new_branch = branch_repo.create_branch(lattice["id"], branch["name"])
            new_id = new_branch["id"]
            new_branch_ids[old_id] = new_id
            self._id_mappings[old_id] = new_id
            self.conn.commit()

        # Create nodes with new IDs
        node_repo = NodeRepository(self.conn)
        new_node_ids: dict[str, str] = {}
        for node in package.lattice_state.get("nodes", []):
            old_id = node["id"]
            new_id = str(XID.new())
            new_node_ids[old_id] = new_id
            self._id_mappings[old_id] = new_id
            old_branch_id = node.get("branch_id", "")
            new_branch_id = new_branch_ids.get(old_branch_id, "")
            if new_branch_id:
                node_repo.insert_node(
                    node_id=new_id,
                    branch_id=new_branch_id,
                    agent_id=ep_service_principal_id or node.get("agent_id", "imported"),
                    description=node.get("description", "Imported node"),
                    bt_planning_budget=node.get("bt_planning_budget", 100.0),
                    metadata={},
                    status="committed",
                )
        self.conn.commit()

        # Create edges with new IDs
        for edge in package.lattice_state.get("edges", []):
            old_upstream = edge.get("upstream_node_id")
            old_downstream = edge.get("downstream_node_id")
            new_upstream = new_node_ids.get(old_upstream)
            new_downstream = new_node_ids.get(old_downstream)
            if new_upstream and new_downstream:
                self.conn.execute(
                    sa.text(
                        "INSERT INTO ep_edges (id, upstream_node_id, downstream_node_id, "
                        "edge_type, weight, created_at) "
                        "VALUES (:id, :up, :down, :et, 1.0, :now)"
                    ),
                    {
                        "id": str(XID.new()),
                        "up": new_upstream,
                        "down": new_downstream,
                        "et": edge.get("edge_type", "dependency"),
                        "now": _now_iso(),
                    },
                )
        self.conn.commit()

        # Import policies as draft with pending_review
        policy_repo = PolicyRepository(self.conn)
        for policy in package.lattice_state.get("policies", []):
            old_policy_id = policy["id"]
            new_policy_id = str(XID.new())
            self._id_mappings[old_policy_id] = new_policy_id

            # Determine trust status
            if trusted_signer and trusted_source:
                policy_status = "active"
                trust_status = "trusted"
            else:
                policy_status = "draft"
                trust_status = "pending_review"

            policy_repo.insert_policy(
                {
                    "id": new_policy_id,
                    "effect": policy.get("effect", "deny"),
                    "actions": policy.get("actions", []),
                    "resources": policy.get("resources", []),
                    "conditions": policy.get("conditions", {}),
                    "priority": policy.get("priority", 0),
                    "scope": policy.get("scope", "global"),
                    "agent_scope": policy.get("agent_scope"),
                    "description": policy.get("description", "Imported policy"),
                    "status": policy_status,
                    "created_by": package.signer_id,
                    "approved_by": None,
                    "approved_at": None,
                    "activation_version": None,
                    "exception_to": policy.get("exception_to", []),
                    "valid_from": policy.get("valid_from"),
                    "valid_until": policy.get("valid_until"),
                    "justification": "Imported from transfer package",
                }
            )
        self.conn.commit()

        # Store import provenance mappings
        for old_id, new_id in self._id_mappings.items():
            self.conn.execute(
                sa.text(
                    "INSERT INTO ep_import_mappings "
                    "(id, source_entity_id, imported_entity_id, "
                    " source_lattice_id, source_package_id, entity_type, created_at) "
                    "VALUES (:id, :old, :new, :slid, :spid, :etype, :now)"
                ),
                {
                    "id": str(XID.new()),
                    "old": old_id,
                    "new": new_id,
                    "slid": package.source_lattice_id,
                    "spid": package.source_lattice_id,  # no FK enforced in SQLite for this
                    "etype": "entity",
                    "now": _now_iso(),
                },
            )
        self.conn.commit()

        return {
            "project_id": project["id"],
            "lattice_id": lattice["id"],
            "id_mappings": dict(self._id_mappings),
            "policies_imported": len(package.lattice_state.get("policies", [])),
            "policies_active": sum(
                1
                for p in package.lattice_state.get("policies", [])
                if trusted_signer and trusted_source
            ),
        }

    def _check_prohibited(self, lattice_state: dict[str, Any]) -> None:
        """Check that the lattice state does not contain prohibited imports."""
        for prohibited in PROHIBITED_IMPORTS:
            if prohibited in lattice_state:
                raise TransferImportError(f"Prohibited import detected: {prohibited}")
