"""Contract tests for EP-Governance transition lifecycle.

These tests validate the formal state machine defined in:
- docs/state-machines.md
- docs/normative-spec.md (EP-TRANSITION-001 through EP-TRANSITION-015)

They test the contract (legal/illegal transitions, terminal states,
idempotency semantics) using pure data structures, not runtime infrastructure.

References: directive section 9.1, v1.1.1 section 2
"""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# Contract: transition stage vocabulary
# ---------------------------------------------------------------------------

LEGAL_STAGES = frozenset({
    "proposed",
    "pending_approval",
    "authorized",
    "executing",
    "succeeded",
    "failed",
    "execution_uncertain",
    "cancelled",
    "expired",
    "denied",
})


# ---------------------------------------------------------------------------
# Contract: legal transitions
# ---------------------------------------------------------------------------

LEGAL_TRANSITIONS: frozenset[tuple[str, str]] = frozenset({
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
    # requires_manual_reconciliation is a flag, not a stage.
    # See docs/state-machines.md.
})

TERMINAL_STAGES = frozenset({
    "succeeded",
    "failed",
    "cancelled",
    "expired",
    "denied",
})


class TestTransitionVocabulary:
    """EP-TRANSITION-001: stage vocabulary MUST match the normative set."""

    def test_legal_stages_are_exactly_the_specified_set(self):
        assert LEGAL_STAGES == {
            "proposed",
            "pending_approval",
            "authorized",
            "executing",
            "succeeded",
            "failed",
            "execution_uncertain",
            "cancelled",
            "expired",
            "denied",
        }

    def test_no_extra_stages(self):
        # If someone adds a stage, they must update the contract explicitly.
        assert len(LEGAL_STAGES) == 10

    @pytest.mark.parametrize("stage", sorted(LEGAL_STAGES))
    def test_every_stage_is_a_string(self, stage: str):
        assert isinstance(stage, str) and stage


class TestLegalTransitions:
    """EP-TRANSITION-002 through EP-TRANSITION-006: legal transition table."""

    @pytest.mark.parametrize("from_stage,to_stage", sorted(LEGAL_TRANSITIONS))
    def test_legal_transition_is_allowed(self, from_stage: str, to_stage: str):
        assert (from_stage, to_stage) in LEGAL_TRANSITIONS

    def test_proposed_can_reach_denied(self):
        assert ("proposed", "denied") in LEGAL_TRANSITIONS

    def test_proposed_can_reach_pending_approval(self):
        assert ("proposed", "pending_approval") in LEGAL_TRANSITIONS

    def test_proposed_can_reach_authorized(self):
        assert ("proposed", "authorized") in LEGAL_TRANSITIONS

    def test_proposed_can_reach_cancelled(self):
        assert ("proposed", "cancelled") in LEGAL_TRANSITIONS

    def test_pending_approval_can_reach_authorized(self):
        assert ("pending_approval", "authorized") in LEGAL_TRANSITIONS

    def test_pending_approval_can_reach_denied(self):
        assert ("pending_approval", "denied") in LEGAL_TRANSITIONS

    def test_authorized_can_reach_executing(self):
        assert ("authorized", "executing") in LEGAL_TRANSITIONS

    def test_executing_can_reach_succeeded(self):
        assert ("executing", "succeeded") in LEGAL_TRANSITIONS

    def test_executing_can_reach_failed(self):
        assert ("executing", "failed") in LEGAL_TRANSITIONS

    def test_executing_can_reach_execution_uncertain(self):
        assert ("executing", "execution_uncertain") in LEGAL_TRANSITIONS

    def test_execution_uncertain_can_reach_succeeded(self):
        assert ("execution_uncertain", "succeeded") in LEGAL_TRANSITIONS

    def test_execution_uncertain_can_reach_failed(self):
        assert ("execution_uncertain", "failed") in LEGAL_TRANSITIONS


class TestIllegalTransitions:
    """EP-TRANSITION-007: illegal transitions MUST fail and generate an audit event."""

    ILLEGAL_EXAMPLES = [
        ("succeeded", "proposed"),
        ("succeeded", "executing"),
        ("succeeded", "denied"),
        ("failed", "proposed"),
        ("failed", "executing"),
        ("failed", "succeeded"),
        ("denied", "proposed"),
        ("denied", "authorized"),
        ("denied", "executing"),
        ("cancelled", "proposed"),
        ("cancelled", "authorized"),
        ("expired", "authorized"),
        ("expired", "executing"),
        ("executing", "proposed"),
        ("executing", "pending_approval"),
        ("executing", "authorized"),
        ("authorized", "proposed"),
        ("authorized", "denied"),
        ("proposed", "succeeded"),  # MUST go through authorized and executing
        ("proposed", "executing"),  # MUST go through authorized
        ("pending_approval", "executing"),  # MUST go through authorized
    ]

    @pytest.mark.parametrize("from_stage,to_stage", ILLEGAL_EXAMPLES)
    def test_illegal_transition_not_in_legal_set(self, from_stage: str, to_stage: str):
        assert (from_stage, to_stage) not in LEGAL_TRANSITIONS

    def test_no_self_transitions(self):
        for stage in LEGAL_STAGES:
            assert (stage, stage) not in LEGAL_TRANSITIONS

    def test_terminal_stages_have_no_outgoing_legal_transitions(self):
        # More precisely: no legal transition FROM a terminal stage
        for terminal in TERMINAL_STAGES:
            outgoing = [t for (f, t) in LEGAL_TRANSITIONS if f == terminal]
            assert outgoing == [], (
                f"Terminal stage {terminal} has outgoing legal transitions: {outgoing}"
            )


class TestTerminalStates:
    """EP-TRANSITION-008: terminal states MUST be defined explicitly."""

    def test_succeeded_is_terminal(self):
        assert "succeeded" in TERMINAL_STAGES

    def test_failed_is_terminal(self):
        assert "failed" in TERMINAL_STAGES

    def test_cancelled_is_terminal(self):
        assert "cancelled" in TERMINAL_STAGES

    def test_expired_is_terminal(self):
        assert "expired" in TERMINAL_STAGES

    def test_denied_is_terminal(self):
        assert "denied" in TERMINAL_STAGES

    def test_execution_uncertain_is_not_terminal(self):
        # execution_uncertain can transition to succeeded or failed
        assert "execution_uncertain" not in TERMINAL_STAGES

    def test_non_terminal_stages_have_outgoing_transitions(self):
        non_terminal = LEGAL_STAGES - TERMINAL_STAGES
        for stage in non_terminal:
            outgoing = [(f, t) for (f, t) in LEGAL_TRANSITIONS if f == stage]
            assert len(outgoing) > 0, f"Non-terminal stage {stage} has no outgoing transitions"


class TestIdempotencyContract:
    """
    EP-TRANSITION-014: idempotency key behavior.

    - Same key + stage in proposed/authorized: return existing transition.
    - Same key + stage in executing/succeeded: return existing result.
    - Same key + stage in failed/cancelled/expired: allow new proposal.
    """

    IDEMPOTENT_RETURN_EXISTING = frozenset({"proposed", "authorized", "pending_approval"})
    IDEMPOTENT_RETURN_RESULT = frozenset({"executing", "succeeded"})
    IDEMPOTENT_ALLOW_NEW = frozenset({"failed", "cancelled", "expired", "denied", "execution_uncertain"})

    def test_all_stages_covered_by_idempotency_rule(self):
        all_stages = (
            self.IDEMPOTENT_RETURN_EXISTING
            | self.IDEMPOTENT_RETURN_RESULT
            | self.IDEMPOTENT_ALLOW_NEW
        )
        assert all_stages == LEGAL_STAGES

    def test_no_overlap_between_idempotency_categories(self):
        assert self.IDEMPOTENT_RETURN_EXISTING.isdisjoint(self.IDEMPOTENT_RETURN_RESULT)
        assert self.IDEMPOTENT_RETURN_EXISTING.isdisjoint(self.IDEMPOTENT_ALLOW_NEW)
        assert self.IDEMPOTENT_RETURN_RESULT.isdisjoint(self.IDEMPOTENT_ALLOW_NEW)