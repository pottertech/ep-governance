"""EP-Governance repository layer — SQLAlchemy 2.0 Core (no ORM).

Each repository wraps a ``Connection`` and exposes typed methods that
execute raw SQL via ``sqlalchemy.text()``.  All INSERT methods generate
XIDs for primary keys.  SELECT methods return plain dicts (via
``row._mapping``).

Timestamps are generated as ISO 8601 UTC strings (microsecond precision,
Z suffix) to match the canonical JSON format.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import text

from ..xid import XID

if TYPE_CHECKING:
    from sqlalchemy.engine import Connection

__all__ = [
    "Repository",
    "ProjectRepository",
    "LatticeRepository",
    "BranchRepository",
    "NodeRepository",
    "PolicyRepository",
    "PrincipalRepository",
    "TransitionRepository",
    "AuthorizationRepository",
    "ApprovalRepository",
    "RiskLedgerRepository",
    "RiskMitigationRepository",
    "WorkClaimRepository",
    "SessionRepository",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    """Return the current UTC timestamp as ISO 8601 with microseconds + Z."""
    dt = datetime.now(UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _row_to_dict(row: Any) -> dict[str, Any] | None:
    """Convert a SQLAlchemy Row to a plain dict via _mapping."""
    if row is None:
        return None
    return dict(row._mapping)


def _rows_to_dicts(rows: Any) -> list[dict[str, Any]]:
    """Convert a list of SQLAlchemy Rows to a list of dicts."""
    return [dict(r._mapping) for r in rows]


def _json_dumps(obj: Any) -> str:
    """Serialise a value to a JSON string (canonical)."""
    from ..canonical import canonical_json

    return canonical_json(obj)


def _json_loads(s: Any) -> Any:
    """Parse a JSON string (or bytes) back to a Python object."""
    if s is None:
        return None
    if isinstance(s, (bytes, bytearray)):
        s = s.decode("utf-8")
    return json.loads(s)


def _new_id() -> str:
    """Generate a new XID string."""
    return str(XID.new())


# ---------------------------------------------------------------------------
# Base repository
# ---------------------------------------------------------------------------


class Repository:
    """Base repository — holds a SQLAlchemy Connection."""

    def __init__(self, conn: Connection) -> None:
        self.conn = conn


# ---------------------------------------------------------------------------
# Project
# ---------------------------------------------------------------------------


class ProjectRepository(Repository):
    """Repository for ``ep_projects``."""

    def create_project(self, name: str, description: str) -> dict[str, Any]:
        """Insert a new project and return the row as a dict."""
        project_id = _new_id()
        now = _now_iso()
        self.conn.execute(
            text(
                "INSERT INTO ep_projects (id, name, description, created_at) "
                "VALUES (:id, :name, :description, :created_at)"
            ),
            {"id": project_id, "name": name, "description": description, "created_at": now},
        )
        return self.get_project(project_id)

    def get_project(self, project_id: str) -> dict[str, Any] | None:
        """Return a single project by ID, or None."""
        result = self.conn.execute(
            text("SELECT * FROM ep_projects WHERE id = :id"),
            {"id": project_id},
        )
        row = result.fetchone()
        return _row_to_dict(row) if row else None

    def list_projects(self) -> list[dict[str, Any]]:
        """Return all projects."""
        result = self.conn.execute(text("SELECT * FROM ep_projects ORDER BY created_at"))
        return _rows_to_dicts(result.fetchall())


# ---------------------------------------------------------------------------
# Lattice
# ---------------------------------------------------------------------------


class LatticeRepository(Repository):
    """Repository for ``ep_lattices``."""

    def create_lattice(self, project_id: str, name: str) -> dict[str, Any]:
        """Insert a new lattice and return the row as a dict."""
        lattice_id = _new_id()
        now = _now_iso()
        self.conn.execute(
            text(
                "INSERT INTO ep_lattices (id, project_id, name, created_at) "
                "VALUES (:id, :project_id, :name, :created_at)"
            ),
            {"id": lattice_id, "project_id": project_id, "name": name, "created_at": now},
        )
        return self.get_lattice(lattice_id)

    def get_lattice(self, lattice_id: str) -> dict[str, Any] | None:
        """Return a single lattice by ID, or None."""
        result = self.conn.execute(
            text("SELECT * FROM ep_lattices WHERE id = :id"),
            {"id": lattice_id},
        )
        row = result.fetchone()
        return _row_to_dict(row) if row else None

    def get_by_project(self, project_id: str) -> dict[str, Any] | None:
        """Return the first lattice for a given project, or None."""
        result = self.conn.execute(
            text(
                "SELECT * FROM ep_lattices WHERE project_id = :project_id "
                "ORDER BY created_at LIMIT 1"
            ),
            {"project_id": project_id},
        )
        row = result.fetchone()
        return _row_to_dict(row) if row else None


# ---------------------------------------------------------------------------
# Branch
# ---------------------------------------------------------------------------


class BranchRepository(Repository):
    """Repository for ``ep_branches``."""

    def create_branch(
        self,
        lattice_id: str,
        name: str,
        head_node_id: str | None = None,
    ) -> dict[str, Any]:
        """Insert a new branch and return the row as a dict."""
        branch_id = _new_id()
        now = _now_iso()
        self.conn.execute(
            text(
                "INSERT INTO ep_branches "
                "(id, lattice_id, name, head_node_id, version, status, created_at) "
                "VALUES (:id, :lattice_id, :name, :head_node_id, :version, :status, :created_at)"
            ),
            {
                "id": branch_id,
                "lattice_id": lattice_id,
                "name": name,
                "head_node_id": head_node_id,
                "version": 1,
                "status": "active",
                "created_at": now,
            },
        )
        return self.get_branch(branch_id)

    def get_branch(self, branch_id: str) -> dict[str, Any] | None:
        """Return a single branch by ID, or None."""
        result = self.conn.execute(
            text("SELECT * FROM ep_branches WHERE id = :id"),
            {"id": branch_id},
        )
        row = result.fetchone()
        return _row_to_dict(row) if row else None

    def update_head(self, branch_id: str, head_node_id: str, expected_version: int) -> bool:
        """Optimistic-concurrency head update.

        Returns True if exactly one row was affected (success), False if the
        version was stale.
        """
        result = self.conn.execute(
            text(
                "UPDATE ep_branches "
                "SET head_node_id = :head_node_id, version = version + 1 "
                "WHERE id = :id AND version = :expected_version"
            ),
            {
                "id": branch_id,
                "head_node_id": head_node_id,
                "expected_version": expected_version,
            },
        )
        return result.rowcount == 1

    def get_head(self, branch_id: str) -> tuple[str | None, int]:
        """Return (head_node_id, version) for a branch."""
        result = self.conn.execute(
            text("SELECT head_node_id, version FROM ep_branches WHERE id = :id"),
            {"id": branch_id},
        )
        row = result.fetchone()
        if row is None:
            return (None, 0)
        return (row[0], row[1])


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


class NodeRepository(Repository):
    """Repository for ``ep_nodes``."""

    def insert_node(
        self,
        node_id: str,
        branch_id: str,
        agent_id: str,
        description: str,
        bt_planning_budget: int,
        metadata: dict[str, Any],
        status: str = "committed",
    ) -> dict[str, Any]:
        """Insert a new node and return the row as a dict.

        The ``node_id`` is caller-supplied (it must be pre-generated via
        ``XID.new()``) because the commit transaction needs the ID for
        the edge insert before the node insert returns.
        """
        now = _now_iso()
        self.conn.execute(
            text(
                "INSERT INTO ep_nodes "
                "(id, branch_id, agent_id, description, bt_planning_budget, "
                " metadata, status, created_at, committed_at) "
                "VALUES (:id, :branch_id, :agent_id, :description, :bt_planning_budget, "
                "        :metadata, :status, :created_at, :committed_at)"
            ),
            {
                "id": node_id,
                "branch_id": branch_id,
                "agent_id": agent_id,
                "description": description,
                "bt_planning_budget": bt_planning_budget,
                "metadata": _json_dumps(metadata),
                "status": status,
                "created_at": now,
                "committed_at": now if status == "committed" else None,
            },
        )
        return self.get_node(node_id)

    def get_node(self, node_id: str) -> dict[str, Any] | None:
        """Return a single node by ID, or None."""
        result = self.conn.execute(
            text("SELECT * FROM ep_nodes WHERE id = :id"),
            {"id": node_id},
        )
        row = result.fetchone()
        d = _row_to_dict(row) if row else None
        if d and "metadata" in d and isinstance(d["metadata"], str):
            d["metadata"] = _json_loads(d["metadata"])
        return d

    def mark_superseded(self, node_id: str) -> bool:
        """Mark a node as 'superseded'. Returns True if a row was affected."""
        result = self.conn.execute(
            text(
                "UPDATE ep_nodes SET status = 'superseded' WHERE id = :id AND status = 'committed'"
            ),
            {"id": node_id},
        )
        return result.rowcount == 1

    def mark_quarantined(self, node_id: str) -> bool:
        """Mark a node as 'quarantined'. Returns True if a row was affected."""
        result = self.conn.execute(
            text(
                "UPDATE ep_nodes SET status = 'quarantined' "
                "WHERE id = :id AND status IN ('committed', 'at_risk')"
            ),
            {"id": node_id},
        )
        return result.rowcount == 1

    def mark_at_risk(self, node_id: str) -> bool:
        """Mark a node as 'at_risk'. Returns True if a row was affected."""
        result = self.conn.execute(
            text("UPDATE ep_nodes SET status = 'at_risk' WHERE id = :id AND status = 'committed'"),
            {"id": node_id},
        )
        return result.rowcount == 1


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------


class PolicyRepository(Repository):
    """Repository for ``ep_policies``."""

    def insert_policy(self, policy_dict: dict[str, Any]) -> dict[str, Any]:
        """Insert a new policy from a dict and return the stored row.

        The dict should contain the full policy definition.  An ``id`` and
        ``created_at`` are generated if not present.
        """
        policy_id = policy_dict.get("id") or _new_id()
        now = _now_iso()
        # Extract known columns; serialise JSON-like fields
        params: dict[str, Any] = {
            "id": policy_id,
            "effect": policy_dict["effect"],
            "actions": _json_dumps(policy_dict.get("actions", [])),
            "resources": _json_dumps(policy_dict.get("resources", [])),
            "conditions": _json_dumps(policy_dict.get("conditions", {})),
            "priority": policy_dict.get("priority", 0),
            "scope": policy_dict.get("scope"),
            "agent_scope": policy_dict.get("agent_scope")
            if policy_dict.get("agent_scope")
            else None,
            "description": policy_dict.get("description"),
            "created_by": policy_dict.get("created_by"),
            "approved_by": policy_dict.get("approved_by"),
            "approved_at": policy_dict.get("approved_at"),
            "activation_version": policy_dict.get("activation_version"),
            "exception_to": _json_dumps(policy_dict.get("exception_to", [])),
            "valid_from": policy_dict.get("valid_from"),
            "valid_until": policy_dict.get("valid_until"),
            "status": policy_dict.get("status", "draft"),
            "created_at": policy_dict.get("created_at", now),
            "updated_at": now,
        }
        self.conn.execute(
            text(
                "INSERT INTO ep_policies "
                "(id, effect, actions, resources, conditions, priority, scope, "
                " agent_scope, description, created_by, approved_by, approved_at, "
                " activation_version, exception_to, valid_from, valid_until, "
                " status, created_at, updated_at) "
                "VALUES (:id, :effect, :actions, :resources, :conditions, :priority, "
                "        :scope, :agent_scope, :description, :created_by, :approved_by, "
                "        :approved_at, :activation_version, :exception_to, :valid_from, "
                "        :valid_until, :status, :created_at, :updated_at)"
            ),
            params,
        )
        return self.get_policy(policy_id)

    def get_policy(self, policy_id: str) -> dict[str, Any] | None:
        """Return a single policy by ID, or None."""
        result = self.conn.execute(
            text("SELECT * FROM ep_policies WHERE id = :id"),
            {"id": policy_id},
        )
        row = result.fetchone()
        if row is None:
            return None
        d = _row_to_dict(row)
        # Deserialise JSON columns
        for col in ("actions", "resources", "conditions", "agent_scope", "exception_to"):
            if col in d and isinstance(d[col], str):
                d[col] = _json_loads(d[col])
        return d

    def list_active_policies(self) -> list[dict[str, Any]]:
        """Return all policies with status 'active'."""
        result = self.conn.execute(
            text(
                "SELECT * FROM ep_policies WHERE status = 'active' ORDER BY priority DESC, created_at"
            )
        )
        rows = result.fetchall()
        out = []
        for r in rows:
            d = dict(r._mapping)
            for col in ("actions", "resources", "conditions", "agent_scope", "exception_to"):
                if col in d and isinstance(d[col], str):
                    d[col] = _json_loads(d[col])
            out.append(d)
        return out

    def update_status(self, policy_id: str, status: str) -> bool:
        """Update a policy's status. Returns True if a row was affected."""
        now = _now_iso()
        result = self.conn.execute(
            text("UPDATE ep_policies SET status = :status, updated_at = :now WHERE id = :id"),
            {"id": policy_id, "status": status, "now": now},
        )
        return result.rowcount == 1

    def approve_policy(self, policy_id: str, approved_by: str, approved_at: str) -> bool:
        """Set the approved_by, approved_at, and status to 'active' (or
        'pending_approval' if the approver sets it).

        Returns True if a row was affected.
        """
        now = _now_iso()
        result = self.conn.execute(
            text(
                "UPDATE ep_policies "
                "SET approved_by = :approved_by, approved_at = :approved_at, "
                "    status = 'active', updated_at = :now "
                "WHERE id = :id"
            ),
            {
                "id": policy_id,
                "approved_by": approved_by,
                "approved_at": approved_at,
                "now": now,
            },
        )
        return result.rowcount == 1


# ---------------------------------------------------------------------------
# Principal
# ---------------------------------------------------------------------------


class PrincipalRepository(Repository):
    """Repository for ``ep_principals``."""

    def insert_principal(
        self,
        principal_id: str,
        name: str,
        type: str,
        machine: str | None,
        description: str | None,
    ) -> dict[str, Any]:
        """Insert a new principal and return the stored row.

        The ``principal_id`` is caller-supplied (XID).
        """
        now = _now_iso()
        self.conn.execute(
            text(
                "INSERT INTO ep_principals "
                "(id, name, type, machine, description, status, created_at) "
                "VALUES (:id, :name, :type, :machine, :description, :status, :created_at)"
            ),
            {
                "id": principal_id,
                "name": name,
                "type": type,
                "machine": machine,
                "description": description,
                "status": "active",
                "created_at": now,
            },
        )
        return self.get_principal(principal_id)

    def get_principal(self, principal_id: str) -> dict[str, Any] | None:
        """Return a single principal by ID, or None."""
        result = self.conn.execute(
            text("SELECT * FROM ep_principals WHERE id = :id"),
            {"id": principal_id},
        )
        row = result.fetchone()
        return _row_to_dict(row) if row else None

    def update_status(self, principal_id: str, status: str) -> bool:
        """Update a principal's status. Returns True if a row was affected."""
        result = self.conn.execute(
            text("UPDATE ep_principals SET status = :status WHERE id = :id"),
            {"id": principal_id, "status": status},
        )
        return result.rowcount == 1


# ---------------------------------------------------------------------------
# Transition
# ---------------------------------------------------------------------------


class TransitionRepository(Repository):
    """Repository for ``ep_transitions``."""

    def insert_transition(self, transition_dict: dict[str, Any]) -> dict[str, Any]:
        """Insert a new transition from a dict and return the stored row.

        An ``id`` and ``created_at`` are generated if not present.
        """
        transition_id = transition_dict.get("id") or _new_id()
        now = _now_iso()
        params: dict[str, Any] = {
            "id": transition_id,
            "branch_id": transition_dict["branch_id"],
            "agent_id": transition_dict["agent_id"],
            "from_node_id": transition_dict.get("from_node_id"),
            "to_node_id": transition_dict.get("to_node_id"),
            "tool": transition_dict.get("tool"),
            "action": transition_dict.get("action"),
            "resource": transition_dict.get("resource"),
            "payload_hash": transition_dict.get("payload_hash"),
            "payload": _json_dumps(transition_dict.get("payload", {})),
            "expected_head_id": transition_dict.get("expected_head_id"),
            "expected_version": transition_dict.get("expected_version"),
            "bt_planning_budget_before": transition_dict.get("bt_planning_budget_before"),
            "bt_planning_budget_after": transition_dict.get("bt_planning_budget_after"),
            "idempotency_key": transition_dict.get("idempotency_key"),
            "stage": transition_dict.get("stage", "proposed"),
            "exit_status": transition_dict.get("exit_status"),
            "result_summary": transition_dict.get("result_summary"),
            "policy_set_hash": transition_dict.get("policy_set_hash"),
            "matched_policy_versions": _json_dumps(
                transition_dict.get("matched_policy_versions", {})
            ),
            "risk_assessments": _json_dumps(transition_dict.get("risk_assessments", {})),
            "residual_risk_after": _json_dumps(transition_dict.get("residual_risk_after", {})),
            "created_at": transition_dict.get("created_at", now),
            "updated_at": now,
        }
        self.conn.execute(
            text(
                "INSERT INTO ep_transitions "
                "(id, branch_id, agent_id, from_node_id, to_node_id, tool, action, "
                " resource, payload_hash, payload, expected_head_id, expected_version, "
                " bt_planning_budget_before, bt_planning_budget_after, idempotency_key, "
                " stage, exit_status, result_summary, policy_set_hash, "
                " matched_policy_versions, risk_assessments, residual_risk_after, "
                " created_at, updated_at) "
                "VALUES (:id, :branch_id, :agent_id, :from_node_id, :to_node_id, :tool, "
                "        :action, :resource, :payload_hash, :payload, :expected_head_id, "
                "        :expected_version, :bt_planning_budget_before, "
                "        :bt_planning_budget_after, :idempotency_key, :stage, :exit_status, "
                "        :result_summary, :policy_set_hash, :matched_policy_versions, "
                "        :risk_assessments, :residual_risk_after, :created_at, :updated_at)"
            ),
            params,
        )
        return self.get_transition(transition_id)

    def get_transition(self, transition_id: str) -> dict[str, Any] | None:
        """Return a single transition by ID, or None."""
        result = self.conn.execute(
            text("SELECT * FROM ep_transitions WHERE id = :id"),
            {"id": transition_id},
        )
        row = result.fetchone()
        if row is None:
            return None
        d = _row_to_dict(row)
        for col in (
            "payload",
            "matched_policy_versions",
            "risk_assessments",
            "residual_risk_after",
        ):
            if col in d and isinstance(d[col], str):
                d[col] = _json_loads(d[col])
        return d

    def update_stage(
        self,
        transition_id: str,
        stage: str,
        expected_current_stage: str | None = None,
    ) -> bool:
        """Update a transition's stage. Returns True if a row was affected.

        When *expected_current_stage* is provided, the UPDATE only succeeds
        if the row's current stage matches that value (optimistic stage guard).
        This is used when advancing to ``'executing'`` to ensure the transition
        is currently in the ``'authorized'`` stage.  When *None*, the current
        behavior (no stage guard) is preserved.
        """
        now = _now_iso()
        params: dict[str, Any] = {"id": transition_id, "stage": stage, "now": now}
        if expected_current_stage is not None:
            sql = (
                "UPDATE ep_transitions SET stage = :stage, updated_at = :now "
                "WHERE id = :id AND stage = :expected_current_stage"
            )
            params["expected_current_stage"] = expected_current_stage
        else:
            sql = "UPDATE ep_transitions SET stage = :stage, updated_at = :now WHERE id = :id"
        result = self.conn.execute(text(sql), params)
        return result.rowcount == 1

    def update_result(
        self,
        transition_id: str,
        exit_status: str,
        result_summary: str,
        to_node_id: str | None = None,
    ) -> bool:
        """Update a transition's result fields. Returns True if a row was affected."""
        now = _now_iso()
        result = self.conn.execute(
            text(
                "UPDATE ep_transitions "
                "SET exit_status = :exit_status, result_summary = :result_summary, "
                "    to_node_id = :to_node_id, updated_at = :now "
                "WHERE id = :id"
            ),
            {
                "id": transition_id,
                "exit_status": exit_status,
                "result_summary": result_summary,
                "to_node_id": to_node_id,
                "now": now,
            },
        )
        return result.rowcount == 1


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------


class AuthorizationRepository(Repository):
    """Repository for ``ep_authorizations``."""

    def insert_authorization(self, auth_dict: dict[str, Any]) -> dict[str, Any]:
        """Insert a new authorization from a dict and return the stored row."""
        auth_id = auth_dict.get("id") or _new_id()
        now = _now_iso()
        params: dict[str, Any] = {
            "id": auth_id,
            "transition_id": auth_dict["transition_id"],
            "agent_id": auth_dict.get("agent_id"),
            "project_id": auth_dict.get("project_id"),
            "branch_id": auth_dict.get("branch_id"),
            "proxy_audience": auth_dict.get("proxy_audience"),
            "tool": auth_dict.get("tool"),
            "payload_hash": auth_dict.get("payload_hash"),
            "policy_set_hash": auth_dict.get("policy_set_hash"),
            "token_hash": auth_dict.get("token_hash", ""),
            "matched_policy_versions": _json_dumps(auth_dict.get("matched_policy_versions", {})),
            "issued_at": auth_dict.get("issued_at", now),
            "expires_at": auth_dict["expires_at"],
            "nonce": auth_dict.get("nonce"),
            "used": False,
            "used_at": None,
            "created_at": now,
        }
        self.conn.execute(
            text(
                "INSERT INTO ep_authorizations "
                "(id, transition_id, agent_id, project_id, branch_id, proxy_audience, "
                " tool, payload_hash, policy_set_hash, token_hash, matched_policy_versions, "
                " issued_at, expires_at, nonce, used, used_at, created_at) "
                "VALUES (:id, :transition_id, :agent_id, :project_id, :branch_id, "
                "        :proxy_audience, :tool, :payload_hash, :policy_set_hash, "
                "        :token_hash, :matched_policy_versions, "
                "        :issued_at, :expires_at, :nonce, "
                "        :used, :used_at, :created_at)"
            ),
            params,
        )
        return self.get_authorization(auth_id)

    def get_authorization(self, auth_id: str) -> dict[str, Any] | None:
        """Return a single authorization by ID, or None."""
        result = self.conn.execute(
            text("SELECT * FROM ep_authorizations WHERE id = :id"),
            {"id": auth_id},
        )
        row = result.fetchone()
        if row is None:
            return None
        d = _row_to_dict(row)
        if "matched_policy_versions" in d and isinstance(d["matched_policy_versions"], str):
            d["matched_policy_versions"] = _json_loads(d["matched_policy_versions"])
        return d

    def claim_authorization(
        self,
        auth_id: str,
        proxy_principal_id: str,
        token_hash: str | None = None,
    ) -> dict[str, Any] | None:
        """Atomically claim an authorization token.

        Uses ``UPDATE ... WHERE used = FALSE AND expires_at > NOW() RETURNING ...``
        to ensure exactly-once claim semantics.  Returns the claimed row as a
        dict, or None if the token was already used, expired, or not found.

        When *token_hash* is provided, an additional ``AND token_hash = :token_hash``
        guard is added to the WHERE clause, binding the presented token to the
        stored record.  This prevents a validly-signed token from being used if
        the database record has a different ``token_hash``.

        On PostgreSQL, ``NOW()`` resolves to the server's transaction timestamp.
        On SQLite, we pass the current UTC timestamp as a parameter.
        """
        dialect = self.conn.dialect.name
        now = _now_iso()

        token_hash_clause = " AND token_hash = :token_hash" if token_hash is not None else ""

        if dialect == "sqlite":
            # SQLite does not have NOW(); use a parameter.
            params: dict[str, Any] = {"id": auth_id, "now": now, "now2": now}
            if token_hash is not None:
                params["token_hash"] = token_hash
            result = self.conn.execute(
                text(
                    "UPDATE ep_authorizations "
                    "SET used = TRUE, used_at = :now "
                    "WHERE id = :id AND used = FALSE AND expires_at > :now2"
                    f"{token_hash_clause} "
                    "RETURNING id, transition_id, payload_hash, policy_set_hash"
                ),
                params,
            )
        else:
            # PostgreSQL: use NOW() server-side.
            params_pg: dict[str, Any] = {"id": auth_id}
            if token_hash is not None:
                params_pg["token_hash"] = token_hash
            result = self.conn.execute(
                text(
                    "UPDATE ep_authorizations "
                    "SET used = TRUE, used_at = NOW() "
                    "WHERE id = :id AND used = FALSE AND expires_at > NOW()"
                    f"{token_hash_clause} "
                    "RETURNING id, transition_id, payload_hash, policy_set_hash"
                ),
                params_pg,
            )
        row = result.fetchone()
        if row is None:
            return None
        d = _row_to_dict(row)
        return d

    def update_execution_attempt_id(self, auth_id: str, execution_attempt_id: str) -> bool:
        """Store the execution_attempt_id on an authorization record.

        Returns True if a row was affected.  This is used by
        :meth:`AuthorizationEngine.verify_and_claim` to persist the attempt ID
        generated at claim time so that callbacks can be correlated back to the
        authorization.
        """
        result = self.conn.execute(
            text(
                "UPDATE ep_authorizations "
                "SET execution_attempt_id = :execution_attempt_id "
                "WHERE id = :id"
            ),
            {"id": auth_id, "execution_attempt_id": execution_attempt_id},
        )
        return result.rowcount == 1

    def check_stale(self, auth_id: str) -> bool:
        """Check if the authorization is stale (policy set changed).

        Returns True if the stored ``policy_set_hash`` is not empty/null
        (indicating a stale check is possible).  A full stale check requires
        recomputing the current policy-set hash and comparing; this method
        is a placeholder that returns whether the auth has a policy_set_hash
        to compare against.

        .. note:: The actual recomputation of the current policy-set hash
           should be done by the policy engine, not the repository.
        """
        result = self.conn.execute(
            text("SELECT policy_set_hash FROM ep_authorizations WHERE id = :id"),
            {"id": auth_id},
        )
        row = result.fetchone()
        if row is None:
            return False
        stored_hash = row[0]
        # If there is no stored hash, we can't check staleness.
        return stored_hash is not None and stored_hash != ""


# ---------------------------------------------------------------------------
# Approval
# ---------------------------------------------------------------------------


class ApprovalRepository(Repository):
    """Repository for ``ep_approval_requests``."""

    def create_request(
        self,
        transition_id: str,
        policy_id: str,
        requested_by: str,
        justification: str,
    ) -> dict[str, Any]:
        """Create an approval request and return the stored row."""
        request_id = _new_id()
        now = _now_iso()
        self.conn.execute(
            text(
                "INSERT INTO ep_approval_requests "
                "(id, transition_id, policy_id, requested_by, justification, "
                " status, decided_by, decided_at, decision, reason, created_at, updated_at) "
                "VALUES (:id, :transition_id, :policy_id, :requested_by, :justification, "
                "        :status, :decided_by, :decided_at, :decision, :reason, "
                "        :created_at, :updated_at)"
            ),
            {
                "id": request_id,
                "transition_id": transition_id,
                "policy_id": policy_id,
                "requested_by": requested_by,
                "justification": justification,
                "status": "pending",
                "decided_by": None,
                "decided_at": None,
                "decision": None,
                "reason": None,
                "created_at": now,
                "updated_at": now,
            },
        )
        return self.get_request(request_id)

    def get_request(self, request_id: str) -> dict[str, Any] | None:
        """Return a single approval request by ID, or None."""
        result = self.conn.execute(
            text("SELECT * FROM ep_approval_requests WHERE id = :id"),
            {"id": request_id},
        )
        row = result.fetchone()
        return _row_to_dict(row) if row else None

    def find_pending_by_transition(self, transition_id: str) -> dict[str, Any] | None:
        """Return the pending approval request for *transition_id*, or None.

        Queries ``ep_approval_requests`` for the most recent row matching
        ``transition_id = :transition_id AND status = 'pending'``.  At most one
        pending request is expected per transition (enforced by the approval
        workflow); the query orders by ``created_at DESC`` as a tie-breaker
        for defensive robustness.
        """
        result = self.conn.execute(
            text(
                "SELECT * FROM ep_approval_requests "
                "WHERE transition_id = :transition_id AND status = 'pending' "
                "ORDER BY created_at DESC LIMIT 1"
            ),
            {"transition_id": transition_id},
        )
        row = result.fetchone()
        return _row_to_dict(row) if row else None

    def decide(
        self,
        request_id: str,
        decided_by: str,
        decision: str,
        reason: str,
    ) -> dict[str, Any] | None:
        """Record an approval decision and return the updated row.

        ``decision`` should be 'approved' or 'denied'.

        The UPDATE is guarded by ``AND status = 'pending'`` so that two
        concurrent approvers cannot both decide the same request (Issue
        Critical 3).  If no row is updated (the request was already decided
        or does not exist), ``None`` is returned so the caller can detect
        the race and act accordingly.
        """
        now = _now_iso()
        status = "approved" if decision == "approved" else "denied"
        result = self.conn.execute(
            text(
                "UPDATE ep_approval_requests "
                "SET decided_by = :decided_by, decided_at = :decided_at, "
                "    decision = :decision, reason = :reason, status = :status, "
                "    updated_at = :now "
                "WHERE id = :id AND status = 'pending'"
            ),
            {
                "id": request_id,
                "decided_by": decided_by,
                "decided_at": now,
                "decision": decision,
                "reason": reason,
                "status": status,
                "now": now,
            },
        )
        if result.rowcount == 0:
            return None
        return self.get_request(request_id)


# ---------------------------------------------------------------------------
# Risk Ledger
# ---------------------------------------------------------------------------


class RiskLedgerRepository(Repository):
    """Repository for ``ep_risk_ledger``."""

    def get_or_create(self, branch_id: str, domain: str) -> dict[str, Any]:
        """Get an existing risk ledger entry for (branch, domain), or create one.

        Returns the row as a dict.
        """
        result = self.conn.execute(
            text("SELECT * FROM ep_risk_ledger WHERE branch_id = :branch_id AND domain = :domain"),
            {"branch_id": branch_id, "domain": domain},
        )
        row = result.fetchone()
        if row is not None:
            d = _row_to_dict(row)
            return d

        # Create
        ledger_id = _new_id()
        now = _now_iso()
        self.conn.execute(
            text(
                "INSERT INTO ep_risk_ledger "
                "(id, branch_id, domain, inherent_risk, mitigation_credit, "
                " residual_risk, threshold, decision, accepted_by, accepted_at, "
                " expiration, created_at, updated_at) "
                "VALUES (:id, :branch_id, :domain, :inherent_risk, :mitigation_credit, "
                "        :residual_risk, :threshold, :decision, :accepted_by, :accepted_at, "
                "        :expiration, :created_at, :updated_at)"
            ),
            {
                "id": ledger_id,
                "branch_id": branch_id,
                "domain": domain,
                "inherent_risk": 0,
                "mitigation_credit": 0,
                "residual_risk": 0,
                "threshold": 0,
                "decision": None,
                "accepted_by": None,
                "accepted_at": None,
                "expiration": None,
                "created_at": now,
                "updated_at": now,
            },
        )
        return self.get_or_create(branch_id, domain)

    def update_risk(
        self,
        ledger_id: str,
        inherent_risk: int,
        residual_risk: int,
    ) -> dict[str, Any]:
        """Update inherent and residual risk for a ledger entry.

        ``mitigation_credit`` is computed as ``inherent_risk - residual_risk``.
        Returns the updated row as a dict.
        """
        now = _now_iso()
        mitigation_credit = max(0, inherent_risk - residual_risk)
        self.conn.execute(
            text(
                "UPDATE ep_risk_ledger "
                "SET inherent_risk = :inherent_risk, "
                "    mitigation_credit = :mitigation_credit, "
                "    residual_risk = :residual_risk, updated_at = :now "
                "WHERE id = :id"
            ),
            {
                "id": ledger_id,
                "inherent_risk": inherent_risk,
                "mitigation_credit": mitigation_credit,
                "residual_risk": residual_risk,
                "now": now,
            },
        )
        result = self.conn.execute(
            text("SELECT * FROM ep_risk_ledger WHERE id = :id"),
            {"id": ledger_id},
        )
        row = result.fetchone()
        return _row_to_dict(row) if row else None

    def accept_risk(
        self,
        ledger_id: str,
        accepted_by: str,
        accepted_at: str,
        expiration: str,
    ) -> dict[str, Any]:
        """Record risk acceptance for a ledger entry.

        Returns the updated row as a dict.
        """
        now = _now_iso()
        self.conn.execute(
            text(
                "UPDATE ep_risk_ledger "
                "SET accepted_by = :accepted_by, accepted_at = :accepted_at, "
                "    expiration = :expiration, decision = 'accepted', updated_at = :now "
                "WHERE id = :id"
            ),
            {
                "id": ledger_id,
                "accepted_by": accepted_by,
                "accepted_at": accepted_at,
                "expiration": expiration,
                "now": now,
            },
        )
        result = self.conn.execute(
            text("SELECT * FROM ep_risk_ledger WHERE id = :id"),
            {"id": ledger_id},
        )
        row = result.fetchone()
        return _row_to_dict(row) if row else None


# ---------------------------------------------------------------------------
# Risk Mitigation
# ---------------------------------------------------------------------------


class RiskMitigationRepository(Repository):
    """Repository for ``ep_risk_mitigations``."""

    def add_mitigation(
        self,
        risk_ledger_id: str,
        mitigation_type: str,
        credit: int,
        evidence: str,
        evidence_type: str | None = None,
        evidence_uri: str | None = None,
        evidence_hash: str | None = None,
        verified_by: str | None = None,
        verified_at: str | None = None,
        expires_at: str | None = None,
        scope: str | None = None,
    ) -> dict[str, Any]:
        """Add a risk mitigation record and return the stored row."""
        mitigation_id = _new_id()
        now = _now_iso()
        self.conn.execute(
            text(
                "INSERT INTO ep_risk_mitigations "
                "(id, risk_ledger_id, mitigation_type, credit, evidence, "
                " evidence_type, evidence_uri, evidence_hash, verified_by, verified_at, "
                " expires_at, scope, created_at) "
                "VALUES (:id, :risk_ledger_id, :mitigation_type, :credit, :evidence, "
                "        :evidence_type, :evidence_uri, :evidence_hash, :verified_by, "
                "        :verified_at, :expires_at, :scope, :created_at)"
            ),
            {
                "id": mitigation_id,
                "risk_ledger_id": risk_ledger_id,
                "mitigation_type": mitigation_type,
                "credit": credit,
                "evidence": evidence,
                "evidence_type": evidence_type,
                "evidence_uri": evidence_uri,
                "evidence_hash": evidence_hash,
                "verified_by": verified_by,
                "verified_at": verified_at,
                "expires_at": expires_at,
                "scope": scope,
                "created_at": now,
            },
        )
        result = self.conn.execute(
            text("SELECT * FROM ep_risk_mitigations WHERE id = :id"),
            {"id": mitigation_id},
        )
        row = result.fetchone()
        return _row_to_dict(row) if row else None


# ---------------------------------------------------------------------------
# Work Claim
# ---------------------------------------------------------------------------


class WorkClaimRepository(Repository):
    """Repository for ``ep_work_claims``."""

    def claim(self, agent_id: str, branch_id: str, region: str) -> dict[str, Any] | None:
        """Atomically claim a work region for an agent on a branch.

        Returns the claim row as a dict, or None if the region is already
        claimed (INSERT ... ON CONFLICT DO NOTHING / conditional INSERT).
        """
        claim_id = _new_id()
        now = _now_iso()
        dialect = self.conn.dialect.name

        if dialect == "sqlite":
            # SQLite: use INSERT OR IGNORE
            result = self.conn.execute(
                text(
                    "INSERT OR IGNORE INTO ep_work_claims "
                    "(id, agent_id, branch_id, region, status, claimed_at, released_at) "
                    "VALUES (:id, :agent_id, :branch_id, :region, :status, :claimed_at, :released_at)"
                ),
                {
                    "id": claim_id,
                    "agent_id": agent_id,
                    "branch_id": branch_id,
                    "region": region,
                    "status": "active",
                    "claimed_at": now,
                    "released_at": None,
                },
            )
        else:
            # PostgreSQL: use INSERT ... ON CONFLICT DO NOTHING
            result = self.conn.execute(
                text(
                    "INSERT INTO ep_work_claims "
                    "(id, agent_id, branch_id, region, status, claimed_at, released_at) "
                    "VALUES (:id, :agent_id, :branch_id, :region, :status, :claimed_at, :released_at) "
                    "ON CONFLICT (branch_id, region) WHERE status = 'active' DO NOTHING"
                ),
                {
                    "id": claim_id,
                    "agent_id": agent_id,
                    "branch_id": branch_id,
                    "region": region,
                    "status": "active",
                    "claimed_at": now,
                    "released_at": None,
                },
            )

        if result.rowcount == 0:
            # Conflict — region already claimed
            return None

        result = self.conn.execute(
            text("SELECT * FROM ep_work_claims WHERE id = :id"),
            {"id": claim_id},
        )
        row = result.fetchone()
        return _row_to_dict(row) if row else None

    def release(self, claim_id: str) -> bool:
        """Release a work claim. Returns True if a row was affected."""
        now = _now_iso()
        result = self.conn.execute(
            text(
                "UPDATE ep_work_claims "
                "SET status = 'released', released_at = :now "
                "WHERE id = :id AND status = 'active'"
            ),
            {"id": claim_id, "now": now},
        )
        return result.rowcount == 1

    def list_active(self, branch_id: str) -> list[dict[str, Any]]:
        """Return all active work claims for a branch."""
        result = self.conn.execute(
            text(
                "SELECT * FROM ep_work_claims "
                "WHERE branch_id = :branch_id AND status = 'active' "
                "ORDER BY claimed_at"
            ),
            {"branch_id": branch_id},
        )
        return _rows_to_dicts(result.fetchall())


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------


class SessionRepository(Repository):
    """Repository for ``ep_sessions``."""

    def create_session(
        self, agent_id: str, branch_id: str, model_info: dict[str, Any]
    ) -> dict[str, Any]:
        """Create a new agent session and return the stored row."""
        session_id = _new_id()
        now = _now_iso()
        self.conn.execute(
            text(
                "INSERT INTO ep_sessions "
                "(id, agent_id, branch_id, model_info, status, started_at, ended_at) "
                "VALUES (:id, :agent_id, :branch_id, :model_info, :status, :started_at, :ended_at)"
            ),
            {
                "id": session_id,
                "agent_id": agent_id,
                "branch_id": branch_id,
                "model_info": _json_dumps(model_info),
                "status": "active",
                "started_at": now,
                "ended_at": None,
            },
        )
        result = self.conn.execute(
            text("SELECT * FROM ep_sessions WHERE id = :id"),
            {"id": session_id},
        )
        row = result.fetchone()
        if row is None:
            return None
        d = _row_to_dict(row)
        if "model_info" in d and isinstance(d["model_info"], str):
            d["model_info"] = _json_loads(d["model_info"])
        return d

    def end_session(self, session_id: str) -> bool:
        """End an active session. Returns True if a row was affected."""
        now = _now_iso()
        result = self.conn.execute(
            text(
                "UPDATE ep_sessions "
                "SET status = 'ended', ended_at = :now "
                "WHERE id = :id AND status = 'active'"
            ),
            {"id": session_id, "now": now},
        )
        return result.rowcount == 1
