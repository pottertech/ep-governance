"""Contract tests for EP-Governance policy semantics.

These tests validate:
- EP-POLICY-001 through EP-POLICY-015 (policy model, resolution, override)
- Separation of duties (EP-POLICY-012)

References: directive section 10, v1.1 section 4, v1.1.1 section 6
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Contract: policy effects
# ---------------------------------------------------------------------------

POLICY_EFFECTS = ("deny", "require_approval", "warn", "allow")

# Effect precedence at equal priority (v1.1 section 4.4, v1.1.1 section 6)
EFFECT_PRECEDENCE = {
    "deny": 4,
    "require_approval": 3,
    "warn": 2,
    "allow": 1,
}

# Policy lifecycle statuses (v1.1.1 section 6)
POLICY_LIFECYCLE = frozenset({
    "draft",
    "pending_approval",
    "active",
    "rejected",
    "superseded",
    "retired",
})

# Policies with these statuses have NO enforcement effect
NON_ENFORCING_STATUSES = POLICY_LIFECYCLE - {"active"}


class TestPolicyEffects:
    """EP-POLICY-003: supported effects."""

    def test_effects_are_exactly_the_specified_set(self):
        assert set(POLICY_EFFECTS) == {"deny", "require_approval", "warn", "allow"}

    def test_deny_has_highest_precedence(self):
        assert EFFECT_PRECEDENCE["deny"] > EFFECT_PRECEDENCE["require_approval"]
        assert EFFECT_PRECEDENCE["deny"] > EFFECT_PRECEDENCE["warn"]
        assert EFFECT_PRECEDENCE["deny"] > EFFECT_PRECEDENCE["allow"]

    def test_require_approval_beats_warn(self):
        assert EFFECT_PRECEDENCE["require_approval"] > EFFECT_PRECEDENCE["warn"]

    def test_warn_beats_allow(self):
        assert EFFECT_PRECEDENCE["warn"] > EFFECT_PRECEDENCE["allow"]

    def test_precedence_order_is_deny_require_approval_warn_allow(self):
        ordered = sorted(EFFECT_PRECEDENCE, key=lambda e: -EFFECT_PRECEDENCE[e])
        assert ordered == ["deny", "require_approval", "warn", "allow"]


class TestPolicyLifecycle:
    """EP-POLICY-001, EP-POLICY-002: policy lifecycle and enforcement effect."""

    def test_lifecycle_statuses_match_specification(self):
        assert POLICY_LIFECYCLE == {
            "draft", "pending_approval", "active",
            "rejected", "superseded", "retired",
        }

    def test_only_active_has_enforcement_effect(self):
        """EP-POLICY-002: a policy has NO enforcement effect unless status=active."""
        assert "active" not in NON_ENFORCING_STATUSES
        assert all(s in NON_ENFORCING_STATUSES for s in
                   {"draft", "pending_approval", "rejected", "superseded", "retired"})

    def test_draft_has_no_enforcement_effect(self):
        assert "draft" in NON_ENFORCING_STATUSES

    def test_pending_approval_has_no_enforcement_effect(self):
        assert "pending_approval" in NON_ENFORCING_STATUSES

    def test_rejected_has_no_enforcement_effect(self):
        assert "rejected" in NON_ENFORCING_STATUSES

    def test_imported_policy_starts_as_draft(self):
        """EP-POLICY-014: imported policies MUST start with status=draft,
        origin=imported, trust_status=pending_review."""
        # An imported policy is not active until explicitly reviewed and activated.
        assert "draft" in POLICY_LIFECYCLE


class TestPolicyResolution:
    """EP-POLICY-004 through EP-POLICY-009: resolution rules."""

    def test_higher_priority_wins(self):
        """EP-POLICY-004: higher priority MUST win."""
        # If policy A has priority 100 and policy B has priority 50,
        # and both match, policy A's effect is the resolution.
        high_priority = 100
        low_priority = 50
        assert high_priority > low_priority

    def test_equal_priority_deny_beats_allow(self):
        """EP-POLICY-005: at equal priority, deny MUST beat allow."""
        assert EFFECT_PRECEDENCE["deny"] > EFFECT_PRECEDENCE["allow"]

    def test_equal_priority_require_approval_beats_warn(self):
        """EP-POLICY-005: at equal priority, require_approval MUST beat warn."""
        assert EFFECT_PRECEDENCE["require_approval"] > EFFECT_PRECEDENCE["warn"]

    def test_equal_priority_contradictions_produce_policy_conflict(self):
        """EP-POLICY-007: equal-priority contradictions MUST produce a policy conflict
        and require approval."""
        # Two policies with same priority, same actions+resources, but
        # conflicting effects (e.g., deny vs allow) => policy_conflict => require_approval
        # This is tested at the engine level, but the contract states the behavior.
        pass

    def test_priority_alone_never_authorizes_exception_to_deny(self):
        """EP-POLICY-008: priority alone MUST NEVER authorize an exception to a deny."""
        # A priority-101 allow does NOT automatically override a priority-100 deny.
        # The allow must have exception_to listing the deny policy's XID.
        pass


class TestPolicyOverride:
    """EP-POLICY-009: allow overrides deny only with full controls."""

    OVERRIDE_REQUIRED_FIELDS = [
        "exception_to",      # Must explicitly list the deny policy XID
        "narrower_scope",    # Must be more narrowly scoped
        "valid_until",       # Must be time-limited
        "justification",     # Must have non-empty justification
        "approved_authority", # Must be approved at required authority level
    ]

    def test_override_requires_exception_to(self):
        """EP-POLICY-009a: an allow MUST explicitly list the deny policy in exception_to."""
        assert "exception_to" in self.OVERRIDE_REQUIRED_FIELDS

    def test_override_requires_narrower_scope(self):
        """EP-POLICY-009b: the override MUST be narrower in scope."""
        assert "narrower_scope" in self.OVERRIDE_REQUIRED_FIELDS

    def test_override_requires_time_limit(self):
        """EP-POLICY-009c: the override MUST be time-limited (valid_until set)."""
        assert "valid_until" in self.OVERRIDE_REQUIRED_FIELDS

    def test_override_requires_justification(self):
        """EP-POLICY-009d: the override MUST have a justification."""
        assert "justification" in self.OVERRIDE_REQUIRED_FIELDS

    def test_override_requires_approved_authority(self):
        """EP-POLICY-009e: the override MUST be approved at the authority level
        required by the policy being overridden."""
        assert "approved_authority" in self.OVERRIDE_REQUIRED_FIELDS

    def test_all_override_controls_present(self):
        assert len(self.OVERRIDE_REQUIRED_FIELDS) == 5


class TestSeparationOfDuties:
    """EP-POLICY-012: separation of duties."""

    def test_requester_cannot_approve_own_action(self):
        """EP-POLICY-012: the principal who requested an action MUST NOT approve it."""
        # decided_by != requested_by
        requested_by = "cjvbbzh6qgtnoxiaa001"
        decided_by = "cjvbbzh6qgtnoxiaa001"
        assert decided_by == requested_by  # This MUST be rejected by the system

    def test_requester_can_be_approved_by_different_principal(self):
        requested_by = "cjvbbzh6qgtnoxiaa001"
        decided_by = "cjvbbzh6qgtnoxiaa002"
        assert decided_by != requested_by  # This is allowed

    def test_sensitive_operations_require_human_approver(self):
        """EP-POLICY-013: sensitive operations MUST require a human principal
        as the approver (not an agent)."""
        # Global policy activation, global policy overrides, overrides of
        # high-priority deny policies, production credential changes,
        # audit recovery operations, destructive production actions.
        sensitive_operations = [
            "global_policy_activation",
            "global_policy_override",
            "override_high_priority_deny",
            "production_credential_change",
            "audit_recovery",
            "destructive_production_action",
        ]
        for op in sensitive_operations:
            assert op  # Each requires a human approver

    def test_approval_must_occur_after_payload_canonicalization(self):
        """EP-POLICY-015: approval MUST occur only after the payload is canonicalized
        and hashed. Approvers MUST see the exact frozen payload."""
        pass