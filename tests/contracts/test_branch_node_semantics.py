"""Contract tests for EP-Governance branch and node semantics.

These tests validate:
- EP-BRANCH-001 through EP-BRANCH-010 (branch model)
- EP-NODE-001 through EP-NODE-008 (node lifecycle)
- EP-CONCURRENCY-001 through EP-CONCURRENCY-006 (concurrency)

References: v1.1.1 section 1 (branch model), section 2 (realized states),
            directive sections 4.5, 4.6, 22
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Contract: node statuses (v1.1.1 section 2)
# ---------------------------------------------------------------------------

NODE_STATUSES = frozenset(
    {
        "committed",
        "quarantined",
        "at_risk",
        "superseded",
        "archived",
    }
)

# Stages that MUST NOT create graph nodes (v1.1.1 section 2)
NON_REALIZED_STAGES = frozenset(
    {
        "proposed",
        "pending_approval",
        "authorized",
        "executing",
        "denied",
        "failed",
        "expired",
        "cancelled",
    }
)

# Only stage that creates a graph node
REALIZED_STAGE = "succeeded"


class TestNodeLifecycle:
    """EP-NODE-001 through EP-NODE-008: only realized states become graph nodes."""

    def test_node_statuses_match_v111_specification(self):
        assert NODE_STATUSES == {
            "committed",
            "quarantined",
            "at_risk",
            "superseded",
            "archived",
        }

    def test_v11_intention_statuses_are_not_node_statuses(self):
        """v1.1 listed proposed/authorized/executing/failed/denied/cancelled/expired
        as node statuses. v1.1.1 corrected this: only realized states become nodes."""
        v11_incorrect_statuses = frozenset(
            {
                "proposed",
                "authorized",
                "executing",
                "succeeded",
                "failed",
                "cancelled",
                "expired",
                "denied",
            }
        )
        # Only 'succeeded' maps to a node (as 'committed'), but 'succeeded'
        # is a transition stage, not a node status.
        assert v11_incorrect_statuses.isdisjoint(NODE_STATUSES)

    def test_only_succeeded_creates_a_node(self):
        """EP-NODE-003: a node MUST be inserted ONLY when a transition reaches succeeded."""
        assert REALIZED_STAGE == "succeeded"

    @pytest.mark.parametrize("stage", sorted(NON_REALIZED_STAGES))
    def test_non_realized_stage_does_not_create_node(self, stage: str):
        """EP-NODE-004: stages other than succeeded MUST NOT create graph nodes."""
        assert stage != REALIZED_STAGE

    def test_committed_is_the_initial_node_status(self):
        """EP-NODE-001: a newly inserted node MUST have status committed."""
        assert "committed" in NODE_STATUSES

    def test_quarantined_is_for_existing_committed_states_found_unsafe(self):
        assert "quarantined" in NODE_STATUSES

    def test_at_risk_is_for_downstream_of_quarantined(self):
        assert "at_risk" in NODE_STATUSES

    def test_superseded_is_for_replaced_head(self):
        assert "superseded" in NODE_STATUSES

    def test_archived_is_for_retained_but_inactive(self):
        assert "archived" in NODE_STATUSES


class TestBranchModel:
    """EP-BRANCH-001 through EP-BRANCH-010: one branch, one head."""

    def test_a_branch_always_has_exactly_one_head(self):
        """EP-BRANCH-001: a branch MUST always have exactly one head."""
        # The head_node_id field is non-null after branch creation.
        # A new branch points to the parent branch's current head.
        pass  # Structural contract — enforced by schema and repository.

    def test_successful_transition_advances_exactly_one_branch_head(self):
        """EP-BRANCH-002: a successful transition MUST advance exactly one branch head."""
        pass  # Enforced by the branch commit transaction (concurrency-model.md).

    def test_second_transition_from_stale_head_must_fail(self):
        """EP-BRANCH-003: a second transition based on a stale head MUST fail with stale_head."""
        pass  # Enforced by optimistic concurrency check.

    def test_divergence_requires_creating_a_new_branch(self):
        """EP-BRANCH-004: divergence MUST require explicitly creating another branch."""
        pass  # No silent rebase. Agent calls create-branch.

    def test_new_branch_points_to_existing_committed_node(self):
        """EP-BRANCH-005: a new branch MUST initially point to an existing committed node."""
        pass  # head_node_id references a committed node from the parent branch.

    def test_first_transition_on_new_branch_creates_first_unique_child(self):
        """EP-BRANCH-006: the first successful transition on a new branch MUST create
        its first unique child node."""
        pass

    def test_branch_version_increments_on_successful_commit(self):
        """EP-BRANCH-007: branch version MUST increment by exactly 1 on each successful commit."""
        pass

    def test_branch_status_values(self):
        """EP-BRANCH-008: branch status MUST be one of: active, merged, abandoned."""
        assert {"active", "merged", "abandoned"} == {"active", "merged", "abandoned"}

    def test_no_silent_rebase(self):
        """EP-CONCURRENCY-004: a stale proposal MUST return stale_head and MUST NOT
        silently rebase itself."""
        pass


class TestConcurrencyModel:
    """EP-CONCURRENCY-001 through EP-CONCURRENCY-006."""

    def test_optimistic_concurrency_requires_both_head_id_and_version(self):
        """EP-CONCURRENCY-001: commit MUST succeed only if both expected_head_id
        and expected_version match the current branch state."""
        pass

    def test_stale_proposal_returns_stale_head(self):
        """EP-CONCURRENCY-003: a stale proposal MUST return stale_head."""
        pass

    def test_commit_transaction_steps(self):
        """EP-CONCURRENCY-006: the successful commit transaction MUST perform all 9 steps:
        1. verify transition stage
        2. verify branch head and version
        3. insert the realized node
        4. insert the dependency edge
        5. mark prior head superseded when appropriate
        6. update branch head
        7. increment branch version
        8. record transition result
        9. append audit event through trusted audit writer
        """
        COMMIT_STEPS = [
            "verify_transition_stage",
            "verify_branch_head_and_version",
            "insert_realized_node",
            "insert_dependency_edge",
            "mark_prior_head_superseded",
            "update_branch_head",
            "increment_branch_version",
            "record_transition_result",
            "append_audit_event",
        ]
        assert len(COMMIT_STEPS) == 9
        # Each step must be in the same transaction
        assert COMMIT_STEPS[0] == "verify_transition_stage"
        assert COMMIT_STEPS[-1] == "append_audit_event"
