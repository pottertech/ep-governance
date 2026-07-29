"""EP-Governance transition engine — the full state machine driver.

This module implements the transition lifecycle state machine defined in:
  - docs/state-machines.md
  - docs/normative-spec.md (EP-TRANSITION-001 through EP-TRANSITION-015)
  - tests/contracts/test_transition_lifecycle.py

The :class:`TransitionEngine` is the single entry point for proposing,
authorising, approving, cancelling, executing, and reconciling transitions.
Every state change is validated against :data:`LEGAL_TRANSITIONS` and
recorded as an immutable audit event.
"""

from __future__ import annotations

import datetime
import hashlib
import json
from typing import TYPE_CHECKING, Any

from .audit import AuditWriter
from .canonical import canonical_hash
from .classification import (
    ClassificationConfidence,
    ClassificationResult,
    get_classifier,
)
from .db.repositories import (
    ApprovalRepository,
    AuthorizationRepository,
    BranchRepository,
    NodeRepository,
    PolicyRepository,
    PrincipalRepository,
    TransitionRepository,
)
from .db.transactions import transaction
from .errors import (
    ApprovalAlreadyDecidedError,
    IllegalTransitionError,
    SeparationOfDutiesError,
)
from .policy_engine import PolicyEngine, PolicyResolution

if TYPE_CHECKING:
    from sqlalchemy.engine import Connection

    from .branches import BranchCommitter

__all__ = [
    "LEGAL_TRANSITIONS",
    "TERMINAL_STAGES",
    "IDEMPOTENT_RETURN_EXISTING",
    "IDEMPOTENT_RETURN_RESULT",
    "IDEMPOTENT_ALLOW_NEW",
    "is_legal_transition",
    "TransitionEngine",
]


# --------------------------------------------------------------------------- #
# Legal transitions — mirrors tests/contracts/test_transition_lifecycle.py
# --------------------------------------------------------------------------- #

LEGAL_TRANSITIONS: frozenset[tuple[str, str]] = frozenset(
    {
        # proposed
        ("proposed", "denied"),
        ("proposed", "pending_approval"),
        ("proposed", "authorized"),
        ("proposed", "cancelled"),
        # pending_approval
        ("pending_approval", "authorized"),
        ("pending_approval", "denied"),
        ("pending_approval", "expired"),
        ("pending_approval", "cancelled"),
        # authorized
        ("authorized", "executing"),
        ("authorized", "expired"),
        ("authorized", "cancelled"),
        # executing
        ("executing", "succeeded"),
        ("executing", "failed"),
        ("executing", "execution_uncertain"),
        # execution_uncertain
        ("execution_uncertain", "succeeded"),
        ("execution_uncertain", "failed"),
    }
)


# --------------------------------------------------------------------------- #
# Terminal stages
# --------------------------------------------------------------------------- #

TERMINAL_STAGES: frozenset[str] = frozenset(
    {
        "succeeded",
        "failed",
        "cancelled",
        "expired",
        "denied",
    }
)


# --------------------------------------------------------------------------- #
# Idempotency categories — mirrors the contract test
# --------------------------------------------------------------------------- #

IDEMPOTENT_RETURN_EXISTING: frozenset[str] = frozenset(
    {
        "proposed",
        "authorized",
        "pending_approval",
    }
)

IDEMPOTENT_RETURN_RESULT: frozenset[str] = frozenset(
    {
        "executing",
        "succeeded",
    }
)

IDEMPOTENT_ALLOW_NEW: frozenset[str] = frozenset(
    {
        "failed",
        "cancelled",
        "expired",
        "denied",
        "execution_uncertain",
    }
)


# --------------------------------------------------------------------------- #
# Public helpers
# --------------------------------------------------------------------------- #


def is_legal_transition(from_stage: str, to_stage: str) -> bool:
    """Return ``True`` if the transition *from_stage* → *to_stage* is legal.

    Args:
        from_stage: The current stage of the transition.
        to_stage:   The desired target stage.

    Returns:
        ``True`` if ``(from_stage, to_stage)`` is in :data:`LEGAL_TRANSITIONS`.
    """
    return (from_stage, to_stage) in LEGAL_TRANSITIONS


# --------------------------------------------------------------------------- #
# TransitionEngine
# --------------------------------------------------------------------------- #


class TransitionEngine:
    """Drives the full transition state machine.

    The engine wraps a SQLAlchemy ``Connection`` and orchestrates the
    classification, policy evaluation, persistence, and audit-logging of
    every state change.

    Attributes:
        conn:                    The active SQLAlchemy connection.
        ep_service_principal_id: XID of the EP service principal (trusted writer).
        policy_engine:           Optional :class:`PolicyEngine` for policy evaluation.
        audit:                   :class:`AuditWriter` instance.
        transition_repo:         :class:`TransitionRepository`.
        branch_repo:             :class:`BranchRepository`.
        node_repo:               :class:`NodeRepository`.
        policy_repo:             :class:`PolicyRepository`.
        approval_repo:           :class:`ApprovalRepository`.
        principal_repo:          :class:`PrincipalRepository`.
        authorization_repo:      :class:`AuthorizationRepository`.
    """

    def __init__(
        self,
        conn: Connection,
        ep_service_principal_id: str,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        """Initialise the engine and its repositories.

        Args:
            conn:                    Active SQLAlchemy connection.
            ep_service_principal_id: XID of the EP service principal.
            policy_engine:           Optional :class:`PolicyEngine`.  If ``None``,
                                      policy evaluation is skipped and all
                                      actions default to ``pending_approval``.
        """
        self.conn = conn
        self.ep_service_principal_id = ep_service_principal_id
        self.policy_engine = policy_engine
        self.audit = AuditWriter(conn, ep_service_principal_id)
        self.transition_repo = TransitionRepository(conn)
        self.branch_repo = BranchRepository(conn)
        self.node_repo = NodeRepository(conn)
        self.policy_repo = PolicyRepository(conn)
        self.approval_repo = ApprovalRepository(conn)
        self.principal_repo = PrincipalRepository(conn)
        self.authorization_repo = AuthorizationRepository(conn)

    # ------------------------------------------------------------------ #
    # Propose
    # ------------------------------------------------------------------ #

    def propose(
        self,
        agent_id: str,
        branch_id: str,
        tool: str,
        arguments: dict[str, Any],
        idempotency_key: str,
        expected_head_id: str | None = None,
        expected_version: int | None = None,
    ) -> dict[str, Any]:
        """Propose a new transition.

        This is the primary entry point for creating a transition.  The
        method:

          1. Checks idempotency — if a transition with the same
             *idempotency_key* already exists in a non-terminal stage,
             the existing transition is returned.
          2. Classifies the action via :func:`get_classifier`.
          3. Computes the payload hash from canonical JSON of *arguments*.
          4. Evaluates policies (if a :class:`PolicyEngine` is configured).
          5. Determines the verification result: ``denied``,
             ``pending_approval``, or ``admissible``.
          6. Inserts the transition row with ``stage='proposed'``.
          7. Advances the stage based on the verification result.

        Args:
            agent_id:         XID of the agent proposing the action.
            branch_id:         XID of the branch this transition belongs to.
            tool:             Tool name (e.g. ``"postgres.execute"``).
            arguments:        Tool arguments dict.
            idempotency_key:  Client-supplied idempotency key.
            expected_head_id: Optional branch head for optimistic concurrency.
            expected_version: Optional branch version for optimistic concurrency.

        Returns:
            The transition row as a dict.
        """
        # ----------------------------------------------------------------
        # 1. Idempotency check
        # ----------------------------------------------------------------
        existing = self._get_by_idempotency_key(idempotency_key)
        if existing is not None:
            stage = existing.get("stage", "")
            if stage in IDEMPOTENT_RETURN_EXISTING or stage in IDEMPOTENT_RETURN_RESULT:
                # Return the existing transition / result
                return existing
            # stage in IDEMPOTENT_ALLOW_NEW → fall through to create a new one

        # ----------------------------------------------------------------
        # 2. Classify the action
        # ----------------------------------------------------------------
        classifier = get_classifier(tool)
        if classifier is None:
            # No classifier registered for this tool → opaque, requires approval
            classification = ClassificationResult(
                action_type="opaque",
                canonical_resources=[],
                risk_domain="",
                classification_method="no_classifier",
                classification_confidence=ClassificationConfidence.low,
                opaque=True,
                requires_approval=True,
            )
        else:
            classification = classifier.classify(tool, arguments)

        # ----------------------------------------------------------------
        # 3. Compute payload hash
        # ----------------------------------------------------------------
        payload_hash = canonical_hash(arguments)

        # ----------------------------------------------------------------
        # 4. Evaluate policies (if engine available)
        # ----------------------------------------------------------------
        verification_result: str = "pending_approval"  # fail-closed default
        matched_policy_versions: dict[str, Any] = {}
        policy_set_hash: str | None = None

        if self.policy_engine is not None:
            resolution: PolicyResolution = self.policy_engine.evaluate(
                action_type=classification.action_type,
                canonical_resources=classification.canonical_resources,
            )
            if resolution.effect == "deny":
                verification_result = "denied"
            elif resolution.effect == "require_approval":
                verification_result = "pending_approval"
            elif resolution.effect in ("allow", "warn"):
                verification_result = "admissible"
            else:
                # Unknown effect → fail closed
                verification_result = "pending_approval"

            # Record matched policy info
            matched_policy_versions = {
                m.policy.id: m.policy.priority for m in resolution.matched_policies
            }
            # Compute a simple policy-set hash from matched policy ids
            if resolution.matched_policies:
                policy_ids = sorted(m.policy.id for m in resolution.matched_policies)
                policy_set_hash = hashlib.sha256(json.dumps(policy_ids).encode("utf-8")).hexdigest()
        else:
            # No policy engine → use classification's requires_approval flag
            if classification.requires_approval:
                verification_result = "pending_approval"
            else:
                verification_result = "admissible"

        # ----------------------------------------------------------------
        # 5. Insert transition with stage='proposed'
        # ----------------------------------------------------------------
        transition_dict: dict[str, Any] = {
            "branch_id": branch_id,
            "agent_id": agent_id,
            "tool": tool,
            "payload": arguments,
            "payload_hash": payload_hash,
            "expected_head_id": expected_head_id,
            "expected_version": expected_version,
            "idempotency_key": idempotency_key,
            "stage": "proposed",
            "action": classification.action_type,
            "resource": classification.canonical_resources[0]
            if classification.canonical_resources
            else None,
            "policy_set_hash": policy_set_hash,
            "matched_policy_versions": matched_policy_versions,
        }

        transition = self.transition_repo.insert_transition(transition_dict)

        # ----------------------------------------------------------------
        # 6. Advance stage based on verification result
        # ----------------------------------------------------------------
        transition_id: str = transition["id"]

        if verification_result == "denied":
            # Advance to denied
            transition = self.advance_stage(transition_id, "denied")
            self._write_audit_event(
                transition_id=transition_id,
                branch_id=branch_id,
                event_type="transition.denied",
                actor_principal_id=agent_id,
                event_data={
                    "transition_id": transition_id,
                    "tool": tool,
                    "action": classification.action_type,
                    "verification_result": verification_result,
                    "reason": "policy_deny",
                },
            )
        elif verification_result == "pending_approval":
            # Advance to pending_approval and create approval request
            transition = self.advance_stage(transition_id, "pending_approval")
            # Create an approval request
            self.approval_repo.create_request(
                transition_id=transition_id,
                policy_id=policy_set_hash or "default",
                requested_by=agent_id,
                justification=f"Action '{classification.action_type}' requires approval",
            )
            self._write_audit_event(
                transition_id=transition_id,
                branch_id=branch_id,
                event_type="transition.pending_approval",
                actor_principal_id=agent_id,
                event_data={
                    "transition_id": transition_id,
                    "tool": tool,
                    "action": classification.action_type,
                    "verification_result": verification_result,
                    "reason": "requires_approval",
                },
            )
        else:
            # admissible → advance to authorized
            transition = self.advance_stage(transition_id, "authorized")
            self._write_audit_event(
                transition_id=transition_id,
                branch_id=branch_id,
                event_type="transition.authorized",
                actor_principal_id=agent_id,
                event_data={
                    "transition_id": transition_id,
                    "tool": tool,
                    "action": classification.action_type,
                    "verification_result": verification_result,
                    "reason": "policy_allow",
                },
            )

        return transition

    # ------------------------------------------------------------------ #
    # Approve
    # ------------------------------------------------------------------ #

    def approve(
        self,
        transition_id: str,
        approver_id: str,
        approver_type: str,
        reason: str,
    ) -> dict[str, Any]:
        """Approve a pending transition.

        Args:
            transition_id: XID of the transition to approve.
            approver_id:   XID of the principal approving the transition.
            approver_type: Type of approver (``"human"`` or ``"agent"``).
            reason:        Human-readable approval reason.

        Returns:
            The updated transition row as a dict.

        Raises:
            IllegalTransitionError:  If the transition is not in ``pending_approval``.
            SeparationOfDutiesError: If the approver is the same as the requester,
                                     or if an agent attempts to approve.
            ApprovalAlreadyDecidedError: If the approval request was already
                                          decided by another approver (race).
        """
        # All operations (read transition, decide approval request, advance
        # stage, write audit event) must run in a single transaction so that a
        # failure in any step rolls back the entire state change atomically
        # (Issue Critical 2).  transaction() requires a clean connection, so
        # commit any pending autobegun reads first (Issue High 6).
        if self.conn.in_transaction():
            self.conn.commit()
        with transaction(self.conn):
            transition = self.transition_repo.get_transition(transition_id)
            if transition is None:
                raise IllegalTransitionError(f"Transition '{transition_id}' not found")

            current_stage = transition.get("stage", "")
            if current_stage != "pending_approval":
                raise IllegalTransitionError(
                    f"Cannot approve transition in stage '{current_stage}'; must be 'pending_approval'"
                )

            # Separation of duties: requester cannot approve their own action
            agent_id: str = transition.get("agent_id", "")
            if approver_id == agent_id:
                raise SeparationOfDutiesError("The requester cannot approve their own action")

            # Sensitive operations require a human approver
            if approver_type == "agent":
                raise SeparationOfDutiesError(
                    "Sensitive operations require a human approver; agents cannot approve transitions"
                )

            branch_id: str = transition.get("branch_id", "")

            # Decide the EXISTING pending approval request for this transition.
            # The request was created during propose(); we must NOT create a new
            # one — that would leave the original pending forever while a new
            # request gets decided (Issue Critical 2).
            approval = self.approval_repo.find_pending_by_transition(transition_id)
            if approval is None:
                raise IllegalTransitionError(
                    f"No pending approval request found for transition '{transition_id}'"
                )
            # decide() returns None when its `WHERE status = 'pending'` guard
            # fails — i.e. a concurrent approver already decided this request
            # (Issue Critical 3).  Detect the race and abort atomically; the
            # surrounding transaction rolls back any partial work.
            decided = self.approval_repo.decide(
                request_id=approval["id"],
                decided_by=approver_id,
                decision="approved",
                reason=reason,
            )
            if decided is None:
                raise ApprovalAlreadyDecidedError(
                    f"Approval request '{approval['id']}' for transition "
                    f"'{transition_id}' was already decided by another approver"
                )

            # Advance transition to authorized
            transition = self.advance_stage(transition_id, "authorized")

            self._write_audit_event(
                transition_id=transition_id,
                branch_id=branch_id,
                event_type="transition.approved",
                actor_principal_id=approver_id,
                event_data={
                    "transition_id": transition_id,
                    "approver_id": approver_id,
                    "approver_type": approver_type,
                    "reason": reason,
                },
                in_transaction=True,
            )

            return transition

    # ------------------------------------------------------------------ #
    # Deny approval
    # ------------------------------------------------------------------ #

    def deny_approval(
        self,
        transition_id: str,
        approver_id: str,
        reason: str,
    ) -> dict[str, Any]:
        """Deny a pending transition.

        Args:
            transition_id: XID of the transition to deny.
            approver_id:   XID of the principal denying the transition.
            reason:        Human-readable denial reason.

        Returns:
            The updated transition row as a dict.

        Raises:
            IllegalTransitionError:  If the transition is not in ``pending_approval``.
            SeparationOfDutiesError: If the approver is the same as the requester.
            ApprovalAlreadyDecidedError: If the approval request was already
                                          decided by another approver (race).
        """
        # All operations (read transition, decide approval request, advance
        # stage, write audit event) must run in a single transaction so that a
        # failure in any step rolls back the entire state change atomically
        # (Issue Critical 2).  transaction() requires a clean connection, so
        # commit any pending autobegun reads first (Issue High 6).
        if self.conn.in_transaction():
            self.conn.commit()
        with transaction(self.conn):
            transition = self.transition_repo.get_transition(transition_id)
            if transition is None:
                raise IllegalTransitionError(f"Transition '{transition_id}' not found")

            current_stage = transition.get("stage", "")
            if current_stage != "pending_approval":
                raise IllegalTransitionError(
                    f"Cannot deny transition in stage '{current_stage}'; must be 'pending_approval'"
                )

            # Separation of duties
            agent_id: str = transition.get("agent_id", "")
            if approver_id == agent_id:
                raise SeparationOfDutiesError("The requester cannot deny their own action")

            branch_id: str = transition.get("branch_id", "")

            # Decide the EXISTING pending approval request for this transition.
            # The request was created during propose(); we must NOT create a new
            # one — that would leave the original pending forever while a new
            # request gets decided (Issue Critical 2).
            approval = self.approval_repo.find_pending_by_transition(transition_id)
            if approval is None:
                raise IllegalTransitionError(
                    f"No pending approval request found for transition '{transition_id}'"
                )
            # decide() returns None when its `WHERE status = 'pending'` guard
            # fails — i.e. a concurrent approver already decided this request
            # (Issue Critical 3).  Detect the race and abort atomically; the
            # surrounding transaction rolls back any partial work.
            decided = self.approval_repo.decide(
                request_id=approval["id"],
                decided_by=approver_id,
                decision="denied",
                reason=reason,
            )
            if decided is None:
                raise ApprovalAlreadyDecidedError(
                    f"Approval request '{approval['id']}' for transition "
                    f"'{transition_id}' was already decided by another approver"
                )

            # Advance transition to denied
            transition = self.advance_stage(transition_id, "denied")

            self._write_audit_event(
                transition_id=transition_id,
                branch_id=branch_id,
                event_type="transition.denied_approval",
                actor_principal_id=approver_id,
                event_data={
                    "transition_id": transition_id,
                    "approver_id": approver_id,
                    "reason": reason,
                },
                in_transaction=True,
            )

            return transition

    # ------------------------------------------------------------------ #
    # Cancel
    # ------------------------------------------------------------------ #

    def cancel(
        self,
        transition_id: str,
        agent_id: str,
    ) -> dict[str, Any]:
        """Cancel a transition that is not yet executing.

        Args:
            transition_id: XID of the transition to cancel.
            agent_id:     XID of the agent requesting the cancellation.

        Returns:
            The updated transition row as a dict.

        Raises:
            IllegalTransitionError: If the transition is in a stage that
                                    cannot be cancelled.
        """
        transition = self.transition_repo.get_transition(transition_id)
        if transition is None:
            raise IllegalTransitionError(f"Transition '{transition_id}' not found")

        current_stage = transition.get("stage", "")
        cancellable_stages = {"proposed", "pending_approval", "authorized"}
        if current_stage not in cancellable_stages:
            raise IllegalTransitionError(
                f"Cannot cancel transition in stage '{current_stage}'; "
                f"must be one of {sorted(cancellable_stages)}"
            )

        branch_id: str = transition.get("branch_id", "")

        transition = self.advance_stage(transition_id, "cancelled")

        self._write_audit_event(
            transition_id=transition_id,
            branch_id=branch_id,
            event_type="transition.cancelled",
            actor_principal_id=agent_id,
            event_data={
                "transition_id": transition_id,
                "agent_id": agent_id,
            },
        )

        return transition

    # ------------------------------------------------------------------ #
    # Advance stage (generic)
    # ------------------------------------------------------------------ #

    def advance_stage(
        self,
        transition_id: str,
        to_stage: str,
    ) -> dict[str, Any]:
        """Advance a transition to a new stage.

        Validates that the transition is legal, updates the stage via
        the repository, writes an audit event, and returns the updated
        transition.

        Args:
            transition_id: XID of the transition.
            to_stage:     Target stage.

        Returns:
            The updated transition row as a dict.

        Raises:
            IllegalTransitionError: If the transition is not legal.
        """
        transition = self.transition_repo.get_transition(transition_id)
        if transition is None:
            raise IllegalTransitionError(f"Transition '{transition_id}' not found")

        from_stage: str = transition.get("stage", "")
        if not is_legal_transition(from_stage, to_stage):
            raise IllegalTransitionError(f"Illegal transition: '{from_stage}' → '{to_stage}'")

        self.transition_repo.update_stage(transition_id, to_stage)

        # Re-read the updated transition
        updated = self.transition_repo.get_transition(transition_id)
        if updated is None:
            raise IllegalTransitionError(
                f"Transition '{transition_id}' disappeared after stage update"
            )

        return updated

    # ------------------------------------------------------------------ #
    # Record result
    # ------------------------------------------------------------------ #

    def record_result(
        self,
        transition_id: str,
        exit_status: str,
        result_summary: str,
        to_node_id: str | None = None,
    ) -> dict[str, Any]:
        """Record the execution result of a transition.

        The transition must be in the ``executing`` stage (i.e. it must
        have been claimed by an executor).

        Args:
            transition_id:  XID of the transition.
            exit_status:    One of ``"success"``, ``"failure"``, ``"timeout"``.
            result_summary: Human-readable result summary.
            to_node_id:     Optional XID of the resulting node (for success).

        Returns:
            The updated transition row as a dict.

        Raises:
            IllegalTransitionError: If the transition is not in ``executing``.
        """
        # All operations (read, set flag, update result, change stage, write
        # audit event) must run in a single transaction so that a failure in
        # any step rolls back the entire state change atomically.
        #
        # Issue High 6: transaction() now requires a clean connection (it no
        # longer silently commits pending autobegun work).  Commit any pending
        # reads so the connection is clean before we begin.
        if self.conn.in_transaction():
            self.conn.commit()
        with transaction(self.conn):
            transition = self.transition_repo.get_transition(transition_id)
            if transition is None:
                raise IllegalTransitionError(f"Transition '{transition_id}' not found")

            current_stage: str = transition.get("stage", "")
            if current_stage != "executing":
                raise IllegalTransitionError(
                    f"Cannot record result for transition in stage '{current_stage}'; "
                    f"must be 'executing'"
                )

            branch_id: str = transition.get("branch_id", "")
            agent_id: str = transition.get("agent_id", "")

            if exit_status == "success":
                # Update result fields and advance to succeeded
                self.transition_repo.update_result(
                    transition_id=transition_id,
                    exit_status=exit_status,
                    result_summary=result_summary,
                    to_node_id=to_node_id,
                )
                transition = self.advance_stage(transition_id, "succeeded")
                self._write_audit_event(
                    transition_id=transition_id,
                    branch_id=branch_id,
                    event_type="transition.succeeded",
                    actor_principal_id=agent_id,
                    event_data={
                        "transition_id": transition_id,
                        "exit_status": exit_status,
                        "result_summary": result_summary,
                        "to_node_id": to_node_id,
                    },
                    in_transaction=True,
                )
            elif exit_status == "failure":
                # Update result fields and advance to failed
                self.transition_repo.update_result(
                    transition_id=transition_id,
                    exit_status=exit_status,
                    result_summary=result_summary,
                    to_node_id=to_node_id,
                )
                transition = self.advance_stage(transition_id, "failed")
                self._write_audit_event(
                    transition_id=transition_id,
                    branch_id=branch_id,
                    event_type="transition.failed",
                    actor_principal_id=agent_id,
                    event_data={
                        "transition_id": transition_id,
                        "exit_status": exit_status,
                        "result_summary": result_summary,
                    },
                    in_transaction=True,
                )
            else:
                # timeout or uncertain → advance to execution_uncertain
                # Set requires_manual_reconciliation flag
                self._set_requires_manual_reconciliation(transition_id, True)
                self.transition_repo.update_result(
                    transition_id=transition_id,
                    exit_status=exit_status,
                    result_summary=result_summary,
                    to_node_id=to_node_id,
                )
                transition = self.advance_stage(transition_id, "execution_uncertain")
                self._write_audit_event(
                    transition_id=transition_id,
                    branch_id=branch_id,
                    event_type="transition.execution_uncertain",
                    actor_principal_id=agent_id,
                    event_data={
                        "transition_id": transition_id,
                        "exit_status": exit_status,
                        "result_summary": result_summary,
                        "requires_manual_reconciliation": True,
                    },
                    in_transaction=True,
                )

            return transition

    # ------------------------------------------------------------------ #
    # Reconcile
    # ------------------------------------------------------------------ #

    def reconcile(
        self,
        transition_id: str,
        final_status: str,
        result_summary: str,
        *,
        branch_committer: BranchCommitter | None = None,
        branch_description: str | None = None,
        bt_planning_budget: float = 0.0,
        metadata: dict[str, Any] | None = None,
        expected_head_id: str | None = None,
        expected_version: int | None = None,
        lattice_id: str | None = None,
    ) -> dict[str, Any]:
        """Reconcile a transition in the ``execution_uncertain`` stage.

        After manual investigation, the operator determines the final
        outcome and records it.

        When *final_status* is ``"succeeded"``, a *branch_committer* MUST
        be provided.  This method attempts branch commitment — creating a
        graph node and advancing the branch head atomically.  If branch
        commitment fails, the transition remains at ``execution_uncertain``
        with ``requires_manual_reconciliation=True`` so the operator can
        retry.

        When *final_status* is ``"succeeded"`` and *branch_committer* is
        ``None``, this method raises ``IllegalTransitionError`` — successful
        reconciliation always requires atomic graph commitment.

        When *final_status* is ``"failed"``, the transition advances to
        ``failed`` without creating a node (no graph state to realize).

        Args:
            transition_id:        XID of the transition.
            final_status:         Either ``"succeeded"`` or ``"failed"``.
            result_summary:       Human-readable reconciliation summary.
            branch_committer:     Optional :class:`BranchCommitter` for node
                                  creation on successful reconciliation.
            branch_description:   Description for the realized node
                                  (defaults to *result_summary*).
            bt_planning_budget:   Planning budget at this state.
            metadata:             Arbitrary state metadata for the node.
            expected_head_id:     Branch head the caller expects.
            expected_version:     Branch version the caller expects.
            lattice_id:           Lattice for audit event tracking.

        Returns:
            The updated transition row as a dict.

        Raises:
            IllegalTransitionError: If the transition is not in ``execution_uncertain``.
        """
        transition = self.transition_repo.get_transition(transition_id)
        if transition is None:
            raise IllegalTransitionError(f"Transition '{transition_id}' not found")

        current_stage: str = transition.get("stage", "")
        if current_stage != "execution_uncertain":
            raise IllegalTransitionError(
                f"Cannot reconcile transition in stage '{current_stage}'; "
                f"must be 'execution_uncertain'"
            )

        branch_id: str = transition.get("branch_id", "")
        agent_id: str = transition.get("agent_id", "")

        if final_status == "succeeded":
            # If a branch committer is provided, attempt full branch
            # commitment (node creation + head advancement) the same way
            # the proxy does.  If it fails, revert to execution_uncertain.
            if branch_committer is not None:
                # The transition is in 'execution_uncertain'. BranchCommitter.commit()
                # will be called and it needs to advance the stage to 'succeeded'.
                # We pass the current stage so commit() knows it's a reconciliation.
                # Resolve branch context parameters from the transition /
                # branch state, falling back to caller-supplied values.
                commit_description = (
                    branch_description if branch_description is not None else result_summary
                )
                commit_metadata = metadata if metadata is not None else {}

                # Resolve expected_head_id / expected_version
                stored_head_id: str | None = transition.get("expected_head_id")
                stored_version_raw = transition.get("expected_version")
                current_head, current_version = self.branch_repo.get_head(branch_id)
                commit_expected_head = (
                    expected_head_id
                    if expected_head_id is not None
                    else (stored_head_id if stored_head_id is not None else current_head)
                )
                commit_expected_version = (
                    expected_version
                    if expected_version is not None
                    else (
                        int(stored_version_raw)
                        if stored_version_raw is not None
                        else current_version
                    )
                )

                # Resolve lattice_id
                if lattice_id is not None:
                    commit_lattice_id = lattice_id
                else:
                    branch = self.branch_repo.get_branch(branch_id)
                    commit_lattice_id = (
                        branch.get("lattice_id", branch_id) if branch is not None else branch_id
                    )

                try:
                    branch_committer.commit(
                        transition_id=transition_id,
                        branch_id=branch_id,
                        agent_id=agent_id,
                        description=commit_description,
                        bt_planning_budget=bt_planning_budget,
                        metadata=commit_metadata,
                        expected_head_id=commit_expected_head,
                        expected_version=commit_expected_version,
                        lattice_id=commit_lattice_id,
                    )
                except Exception as exc:
                    # Branch commitment failed — the transition is still at
                    # 'execution_uncertain' (commit() rolls back on failure).
                    # Record the failure atomically: set reconciliation flag
                    # and write audit event in one transaction.
                    if self.conn.in_transaction():
                        self.conn.rollback()
                    with transaction(self.conn):
                        self._set_requires_manual_reconciliation(transition_id, True)
                        self._write_audit_event(
                            transition_id=transition_id,
                            branch_id=branch_id,
                            event_type="transition.reconcile_commit_failed",
                            actor_principal_id=agent_id,
                            event_data={
                                "transition_id": transition_id,
                                "final_status": final_status,
                                "requires_manual_reconciliation": True,
                            },
                            in_transaction=True,
                        )
                    # Re-read the (still execution_uncertain) transition
                    transition = self.transition_repo.get_transition(transition_id)
                    if transition is None:
                        raise IllegalTransitionError(
                            f"Transition '{transition_id}' disappeared after "
                            f"reconcile commit failure"
                        )
                    return transition

                # Branch commitment succeeded — re-read the transition
                # (BranchCommitter.commit() advances the stage to succeeded
                # and writes its own audit event).
                transition = self.transition_repo.get_transition(transition_id)
                if transition is None:
                    raise IllegalTransitionError(
                        f"Transition '{transition_id}' disappeared after "
                        f"successful reconcile commit"
                    )
            else:
                # No branch committer — successful reconciliation requires
                # atomic branch commitment. Do NOT advance to succeeded
                # without creating a node and advancing the branch head.
                raise IllegalTransitionError(
                    f"Successful reconciliation of transition '{transition_id}' "
                    f"requires a branch_committer for atomic graph commitment. "
                    f"Cannot advance to 'succeeded' without creating a node."
                )
        elif final_status == "failed":
            transition = self.advance_stage(transition_id, "failed")
        else:
            raise IllegalTransitionError(
                f"Invalid final_status '{final_status}'; must be 'succeeded' or 'failed'"
            )

        # Clear requires_manual_reconciliation flag
        self._set_requires_manual_reconciliation(transition_id, False)

        self._write_audit_event(
            transition_id=transition_id,
            branch_id=branch_id,
            event_type="transition.reconciled",
            actor_principal_id=agent_id,
            event_data={
                "transition_id": transition_id,
                "final_status": final_status,
                "result_summary": result_summary,
                "requires_manual_reconciliation": False,
            },
        )

        return transition

    # ------------------------------------------------------------------ #
    # Get transition
    # ------------------------------------------------------------------ #

    def get_transition(self, transition_id: str) -> dict[str, Any] | None:
        """Return a transition by ID, or ``None`` if not found.

        Args:
            transition_id: XID of the transition.

        Returns:
            The transition row as a dict, or ``None``.
        """
        return self.transition_repo.get_transition(transition_id)

    # ------------------------------------------------------------------ #
    # Private helpers
    # ------------------------------------------------------------------ #

    def _get_by_idempotency_key(self, idempotency_key: str) -> dict[str, Any] | None:
        """Look up a transition by its idempotency key.

        Args:
            idempotency_key: The idempotency key to search for.

        Returns:
            The transition row as a dict, or ``None`` if not found.
        """
        from sqlalchemy import text

        result = self.conn.execute(
            text(
                "SELECT * FROM ep_transitions WHERE idempotency_key = :key "
                "ORDER BY created_at DESC LIMIT 1"
            ),
            {"key": idempotency_key},
        )
        row = result.fetchone()
        if row is None:
            return None
        d = dict(row._mapping)
        # Deserialise JSON columns (mirror TransitionRepository.get_transition)
        for col in (
            "payload",
            "matched_policy_versions",
            "risk_assessments",
            "residual_risk_after",
        ):
            if col in d and isinstance(d[col], str):
                try:
                    d[col] = json.loads(d[col])
                except (json.JSONDecodeError, TypeError):
                    pass
        return d

    def _write_audit_event(
        self,
        transition_id: str,
        branch_id: str,
        event_type: str,
        actor_principal_id: str,
        event_data: dict[str, Any],
        *,
        in_transaction: bool = False,
    ) -> None:
        """Write an audit event for a transition state change.

        The ``lattice_id`` for the audit event is derived from the branch's
        lattice.  If the branch or lattice cannot be found, the event is
        written with the branch_id as the lattice_id fallback.

        Args:
            transition_id:        XID of the transition.
            branch_id:           XID of the branch.
            event_type:           Audit event type string.
            actor_principal_id:  XID of the actor responsible.
            event_data:           Event payload dict.
            in_transaction:      If ``True``, the caller already owns a
                                  transaction and the no-commit
                                  :meth:`AuditWriter.write_event_in_transaction`
                                  is used.  If ``False`` (default), the
                                  standalone :meth:`AuditWriter.write_event`
                                  is used, which manages its own transaction.
        """
        # Derive lattice_id from the branch
        branch = self.branch_repo.get_branch(branch_id)
        if branch is not None:
            lattice_id: str = branch.get("lattice_id", branch_id)
        else:
            lattice_id = branch_id

        if in_transaction:
            self.audit.write_event_in_transaction(
                lattice_id=lattice_id,
                event_type=event_type,
                event_data=event_data,
                actor_principal_id=actor_principal_id,
                authenticated_caller_id=actor_principal_id,
            )
        else:
            self.audit.write_event(
                lattice_id=lattice_id,
                event_type=event_type,
                event_data=event_data,
                actor_principal_id=actor_principal_id,
                authenticated_caller_id=actor_principal_id,
            )

    def _set_requires_manual_reconciliation(
        self,
        transition_id: str,
        value: bool,
    ) -> None:
        """Set or clear the ``requires_manual_reconciliation`` flag.

        Args:
            transition_id: XID of the transition.
            value:         ``True`` to set the flag, ``False`` to clear it.
        """
        from sqlalchemy import text

        # SQLite stores booleans as 0/1; PostgreSQL uses TRUE/FALSE
        dialect = self.conn.dialect.name
        if dialect == "sqlite":
            flag = 1 if value else 0
        else:
            flag = value  # type: ignore[assignment]

        now = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"

        self.conn.execute(
            text(
                "UPDATE ep_transitions "
                "SET requires_manual_reconciliation = :flag, updated_at = :now "
                "WHERE id = :id"
            ),
            {"id": transition_id, "flag": flag, "now": now},
        )
