"""EP-Governance branch commit engine.

Implements the 9-step branch commit transaction from the concurrency model
(docs/concurrency-model.md, EP-CONCURRENCY-006):

1. verify transition stage (must be 'executing' or 'succeeded')
2. verify branch head and version
3. insert the realized node
4. insert the dependency edge
5. mark prior head superseded when appropriate
6. update branch head
7. increment branch version
8. record transition result AND advance stage to 'succeeded' atomically
9. append audit event through trusted audit writer

All steps run in a single transaction. If any step fails, the entire
transaction rolls back and the transition remains at 'executing'.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.engine import Connection

from .audit import AuditWriter
from .db.repositories import BranchRepository, NodeRepository, TransitionRepository
from .db.transactions import transaction
from .errors import IllegalTransitionError, StaleHeadError
from .xid import XID

__all__ = ["BranchCommitter", "commit_branch_head"]


def _now_iso() -> str:
    """Return current UTC time as ISO 8601 with microseconds and Z suffix."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


class BranchCommitter:
    """Handles atomic branch head advancement with the 9-step commit.

    Each call to commit() runs all 9 steps in a single database transaction.
    If any step fails, the entire transaction rolls back.
    """

    def __init__(self, conn: Connection, ep_service_principal_id: str) -> None:
        self.conn = conn
        self.ep_service_principal_id = ep_service_principal_id
        self.audit_writer = AuditWriter(conn, ep_service_principal_id)
        self.branch_repo = BranchRepository(conn)
        self.node_repo = NodeRepository(conn)
        self.transition_repo = TransitionRepository(conn)

    def commit(
        self,
        transition_id: str,
        branch_id: str,
        agent_id: str,
        description: str,
        bt_planning_budget: float,
        metadata: dict[str, Any],
        expected_head_id: str | None,
        expected_version: int,
        lattice_id: str,
    ) -> dict[str, Any]:
        """Execute the 9-step branch commit transaction.

        Args:
            transition_id: The transition that succeeded.
            branch_id: The branch to advance.
            agent_id: The agent that performed the action.
            description: Description of the realized state.
            bt_planning_budget: Planning budget at this state.
            metadata: Arbitrary state metadata.
            expected_head_id: The head node the agent expected.
            expected_version: The branch version the agent expected.
            lattice_id: The lattice for audit event tracking.

        Returns:
            A dict with the new node_id, branch_id, and new version.

        Raises:
            IllegalTransitionError: If the transition is not in 'executing' or
                'succeeded' stage.  'executing' is the normal pre-commit stage;
                'succeeded' is accepted for backward compatibility with callers
                that already advanced the stage.
            StaleHeadError: If the branch head has advanced since the proposal.
        """
        # All 9 steps run inside a single explicit transaction.  If any step
        # raises, the context manager rolls back and the transition stays at
        # 'executing'.  On success it commits atomically.
        with transaction(self.conn):
            # Step 1: Verify transition stage is 'executing' (normal path) or
            # 'succeeded' (legacy path where the caller already advanced the stage).
            # We accept 'executing' so that the stage advancement to 'succeeded'
            # happens atomically inside this transaction — if any later step fails,
            # the transaction rolls back and the transition stays at 'executing'.
            transition = self.transition_repo.get_transition(transition_id)
            if transition is None:
                raise IllegalTransitionError(f"Transition {transition_id} not found")
            stage = transition.get("stage", "")
            if stage not in ("executing", "succeeded"):
                raise IllegalTransitionError(
                    f"Transition {transition_id} is in stage '{stage}', "
                    "must be 'executing' or 'succeeded' to commit"
                )

            # Step 2: Verify branch head and version (optimistic concurrency)
            head_node_id, current_version = self.branch_repo.get_head(branch_id)
            if expected_head_id is not None and head_node_id != expected_head_id:
                raise StaleHeadError(
                    f"Branch head mismatch: expected {expected_head_id}, got {head_node_id}"
                )
            if current_version != expected_version:
                raise StaleHeadError(
                    f"Branch version mismatch: expected {expected_version}, got {current_version}"
                )

            # Step 3: Insert the realized node
            new_node_id = str(XID.new())
            now = _now_iso()
            node = self.node_repo.insert_node(
                node_id=new_node_id,
                branch_id=branch_id,
                agent_id=agent_id,
                description=description,
                bt_planning_budget=bt_planning_budget,
                metadata=metadata,
                status="committed",
            )

            # Step 4: Insert dependency edge (from old head to new node)
            if head_node_id is not None:
                self.conn.execute(
                    sa.text(
                        "INSERT INTO ep_edges (id, upstream_node_id, downstream_node_id, "
                        "edge_type, weight, created_at) "
                        "VALUES (:id, :upstream, :downstream, 'dependency', 1.0, :now)"
                    ),
                    {
                        "id": str(XID.new()),
                        "upstream": head_node_id,
                        "downstream": new_node_id,
                        "now": now,
                    },
                )

            # Step 5: Mark prior head superseded (if there was one)
            if head_node_id is not None:
                self.node_repo.mark_superseded(head_node_id)

            # Step 6: Update branch head
            new_version = expected_version + 1
            updated = self.branch_repo.update_head(branch_id, new_node_id, expected_version)
            if not updated:
                raise StaleHeadError(
                    f"Branch head update failed: another agent committed first "
                    f"(branch {branch_id}, expected version {expected_version})"
                )

            # Step 7: Branch version is incremented as part of step 6
            # (update_head does UPDATE ... WHERE version = :expected, sets new head)

            # Step 8: Record transition result (link to_node_id) AND advance the
            # stage to 'succeeded' atomically as part of this same transaction.
            # If the transition is still in 'executing' (the normal path), we
            # advance it to 'succeeded' with an optimistic stage guard so that
            # a concurrent record_result(failure) cannot race with us.  If it is
            # already 'succeeded' (legacy caller), we skip the stage update.
            self.transition_repo.update_result(
                transition_id,
                exit_status="success",
                result_summary=description,
                to_node_id=new_node_id,
            )
            if stage == "executing":
                updated_stage = self.transition_repo.update_stage(
                    transition_id,
                    "succeeded",
                    expected_current_stage="executing",
                )
                if not updated_stage:
                    raise IllegalTransitionError(
                        f"Transition {transition_id} stage advanced concurrently; "
                        "could not advance to 'succeeded'"
                    )

            # Step 9: Append audit event through trusted audit writer
            self.audit_writer.write_event(
                lattice_id=lattice_id,
                event_type="branch_committed",
                event_data={
                    "transition_id": transition_id,
                    "branch_id": branch_id,
                    "new_node_id": new_node_id,
                    "old_head_id": head_node_id,
                    "new_version": new_version,
                },
                actor_principal_id=agent_id,
                authenticated_caller_id=self.ep_service_principal_id,
            )

            return {
                "node_id": new_node_id,
                "branch_id": branch_id,
                "version": new_version,
            }


def commit_branch_head(
    conn: Connection,
    ep_service_principal_id: str,
    transition_id: str,
    branch_id: str,
    agent_id: str,
    description: str,
    bt_planning_budget: float,
    metadata: dict[str, Any],
    expected_head_id: str | None,
    expected_version: int,
    lattice_id: str,
) -> dict[str, Any]:
    """Convenience function to commit a branch head.

    Creates a BranchCommitter and calls commit() in a single call.
    """
    committer = BranchCommitter(conn, ep_service_principal_id)
    return committer.commit(
        transition_id=transition_id,
        branch_id=branch_id,
        agent_id=agent_id,
        description=description,
        bt_planning_budget=bt_planning_budget,
        metadata=metadata,
        expected_head_id=expected_head_id,
        expected_version=expected_version,
        lattice_id=lattice_id,
    )
