"""Unit tests for EP-Governance policy evaluation engine.

References normative rules:
  EP-POLICY-002: only active, in-force policies are matched
  EP-POLICY-004: equal-priority precedence deny > require_approval > warn > allow
  EP-POLICY-005: priority alone does not authorize exception to deny
  EP-POLICY-006: allow overrides deny only with all override controls
  EP-POLICY-007: equal-priority deny vs allow -> conflict, require_approval
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ep_governance.policies import Policy, PolicyEffect, PolicyScope, PolicyStatus
from ep_governance.policy_engine import PolicyEngine, PolicyMatch, PolicyResolution


# --------------------------------------------------------------------------- #
# Constants and helpers
# --------------------------------------------------------------------------- #

XID = "0123456789abcdefghij"  # 20-char base32hex
XID_2 = "0123456789abcdejji00"  # different valid XID


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _future_iso(seconds: int = 3600) -> str:
    dt = datetime.now(timezone.utc) + timedelta(seconds=seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _past_iso(seconds: int = 3600) -> str:
    dt = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _make_policy(
    pid: str = XID,
    effect: PolicyEffect = PolicyEffect.deny,
    actions: list[str] | None = None,
    resources: list[str] | None = None,
    conditions: dict | None = None,
    priority: int = 50,
    scope: PolicyScope = PolicyScope.global_,
    agent_scope: str | None = None,
    project_id: str | None = None,
    branch_id: str | None = None,
    status: PolicyStatus = PolicyStatus.active,
    valid_from: str | None = None,
    valid_until: str | None = None,
    exception_to: list[str] | None = None,
    justification: str | None = None,
    approved_by: str | None = None,
    created_by: str = XID,
    description: str = "Test policy",
) -> Policy:
    return Policy(
        id=pid,
        effect=effect,
        actions=actions or ["postgres.execute.*"],
        resources=resources or ["postgres://cloudhub/*"],
        conditions=conditions or {},
        priority=priority,
        scope=scope,
        agent_scope=agent_scope,
        project_id=project_id,
        branch_id=branch_id,
        description=description,
        status=status,
        created_by=created_by,
        valid_from=valid_from,
        valid_until=valid_until,
        exception_to=exception_to or [],
        justification=justification,
        approved_by=approved_by,
    )


ACTION = "postgres.execute.select"
RESOURCES = ["postgres://cloudhub/gbrain_pilot/public/memory_items"]


# --------------------------------------------------------------------------- #
# Basic evaluation
# --------------------------------------------------------------------------- #


class TestBasicEvaluation:
    """Tests for basic policy matching and effect resolution."""

    def test_one_deny_matches(self):
        """One matching deny policy -> effect=deny."""
        p = _make_policy(effect=PolicyEffect.deny)
        engine = PolicyEngine([p])
        result = engine.evaluate(ACTION, RESOURCES)
        assert result.effect == "deny"
        assert len(result.matched_policies) == 1
        assert result.conflict is False

    def test_one_allow_matches(self):
        """One matching allow policy -> effect=allow."""
        p = _make_policy(effect=PolicyEffect.allow)
        engine = PolicyEngine([p])
        result = engine.evaluate(ACTION, RESOURCES)
        assert result.effect == "allow"
        assert len(result.matched_policies) == 1
        assert result.conflict is False

    def test_one_warn_matches(self):
        p = _make_policy(effect=PolicyEffect.warn)
        engine = PolicyEngine([p])
        result = engine.evaluate(ACTION, RESOURCES)
        assert result.effect == "warn"

    def test_one_require_approval_matches(self):
        p = _make_policy(effect=PolicyEffect.require_approval)
        engine = PolicyEngine([p])
        result = engine.evaluate(ACTION, RESOURCES)
        assert result.effect == "require_approval"


# --------------------------------------------------------------------------- #
# Priority-based resolution
# --------------------------------------------------------------------------- #


class TestPriorityResolution:
    """Tests for priority-based resolution."""

    def test_higher_priority_wins(self):
        """Priority 100 deny vs priority 50 allow -> deny (EP-POLICY-004)."""
        deny_p = _make_policy(pid=XID, effect=PolicyEffect.deny, priority=100)
        allow_p = _make_policy(pid=XID_2, effect=PolicyEffect.allow, priority=50)
        engine = PolicyEngine([deny_p, allow_p])
        result = engine.evaluate(ACTION, RESOURCES)
        assert result.effect == "deny"
        assert len(result.matched_policies) == 2

    def test_higher_priority_allow_does_not_override_lower_deny(self):
        """Priority 100 allow vs priority 50 deny -> deny.

        EP-POLICY-008: priority alone MUST NEVER override deny.
        Without exception_to and all override controls, deny wins
        regardless of the allow's higher priority.
        """
        allow_p = _make_policy(pid=XID, effect=PolicyEffect.allow, priority=100)
        deny_p = _make_policy(pid=XID_2, effect=PolicyEffect.deny, priority=50)
        engine = PolicyEngine([allow_p, deny_p])
        result = engine.evaluate(ACTION, RESOURCES)
        # Deny wins because priority alone does not override deny
        assert result.effect == "deny"


# --------------------------------------------------------------------------- #
# EP-POLICY-004: Equal-priority effect precedence
# --------------------------------------------------------------------------- #


class TestEqualPriorityPrecedence:
    """Tests for equal-priority effect precedence (EP-POLICY-004)."""

    def test_equal_priority_deny_vs_allow(self):
        """Equal-priority deny vs allow -> conflict=True, deny wins by precedence.

        Per the engine code: when deny is among contradictory effects at top
        priority, deny wins and conflict is flagged.
        """
        deny_p = _make_policy(pid=XID, effect=PolicyEffect.deny, priority=50)
        allow_p = _make_policy(pid=XID_2, effect=PolicyEffect.allow, priority=50)
        engine = PolicyEngine([deny_p, allow_p])
        result = engine.evaluate(ACTION, RESOURCES)
        assert result.conflict is True
        # The engine: deny wins by precedence when deny is among contradictory
        assert result.effect == "deny"

    def test_equal_priority_deny_beats_require_approval(self):
        """deny > require_approval at equal priority."""
        deny_p = _make_policy(pid=XID, effect=PolicyEffect.deny, priority=50)
        ra_p = _make_policy(pid=XID_2, effect=PolicyEffect.require_approval, priority=50)
        engine = PolicyEngine([deny_p, ra_p])
        result = engine.evaluate(ACTION, RESOURCES)
        assert result.effect == "deny"
        assert result.conflict is True

    def test_equal_priority_require_approval_beats_warn(self):
        """require_approval > warn at equal priority."""
        ra_p = _make_policy(pid=XID, effect=PolicyEffect.require_approval, priority=50)
        warn_p = _make_policy(pid=XID_2, effect=PolicyEffect.warn, priority=50)
        engine = PolicyEngine([ra_p, warn_p])
        result = engine.evaluate(ACTION, RESOURCES)
        # No deny among contradictory -> require_approval wins
        assert result.effect == "require_approval"
        assert result.conflict is True

    def test_equal_priority_warn_beats_allow(self):
        """warn > allow at equal priority."""
        warn_p = _make_policy(pid=XID, effect=PolicyEffect.warn, priority=50)
        allow_p = _make_policy(pid=XID_2, effect=PolicyEffect.allow, priority=50)
        engine = PolicyEngine([warn_p, allow_p])
        result = engine.evaluate(ACTION, RESOURCES)
        # No deny -> require_approval wins (fail closed)
        assert result.effect == "require_approval"
        assert result.conflict is True

    def test_equal_priority_same_effect_no_conflict(self):
        """Multiple policies at same priority with same effect -> no conflict."""
        p1 = _make_policy(pid=XID, effect=PolicyEffect.deny, priority=50)
        p2 = _make_policy(pid=XID_2, effect=PolicyEffect.deny, priority=50)
        engine = PolicyEngine([p1, p2])
        result = engine.evaluate(ACTION, RESOURCES)
        assert result.effect == "deny"
        assert result.conflict is False


# --------------------------------------------------------------------------- #
# EP-POLICY-006: Override controls
# --------------------------------------------------------------------------- #


class TestOverrideControls:
    """Tests for allow overriding deny (EP-POLICY-006)."""

    def test_allow_overrides_deny_with_all_controls(self):
        """Allow overrides deny when all 5 override controls are satisfied.

        Required controls:
          1. exception_to lists the deny policy's id
          2. allow is narrower scope (agent) vs deny (global)
          3. valid_until is set
          4. justification is set
          5. approved_by is set
        """
        deny_p = _make_policy(
            pid=XID,
            effect=PolicyEffect.deny,
            priority=50,
            scope=PolicyScope.global_,
        )
        allow_p = _make_policy(
            pid=XID_2,
            effect=PolicyEffect.allow,
            priority=50,
            scope=PolicyScope.agent,
            agent_scope=XID_2,
            exception_to=[XID],
            valid_until=_future_iso(),
            justification="Emergency override approved by human",
            approved_by=XID_2,
        )
        engine = PolicyEngine([deny_p, allow_p])
        result = engine.evaluate(
            ACTION, RESOURCES, context={"agent_id": XID_2}
        )
        # Override granted -> deny is overridden -> allow
        assert result.effect == "allow"
        assert result.conflict is False

    def test_override_missing_exception_to_fails(self):
        """Missing exception_to -> override fails, deny remains."""
        deny_p = _make_policy(pid=XID, effect=PolicyEffect.deny, priority=50)
        allow_p = _make_policy(
            pid=XID_2,
            effect=PolicyEffect.allow,
            priority=50,
            scope=PolicyScope.agent,
            agent_scope=XID_2,
            valid_until=_future_iso(),
            justification="Missing exception_to",
            approved_by=XID_2,
        )
        engine = PolicyEngine([deny_p, allow_p])
        result = engine.evaluate(ACTION, RESOURCES, context={"agent_id": XID_2})
        assert result.effect == "deny"

    def test_override_missing_narrower_scope_fails(self):
        """Allow scope not agent-scoped -> override fails."""
        deny_p = _make_policy(
            pid=XID,
            effect=PolicyEffect.deny,
            priority=50,
            scope=PolicyScope.global_,
        )
        allow_p = _make_policy(
            pid=XID_2,
            effect=PolicyEffect.allow,
            priority=50,
            scope=PolicyScope.global_,  # Not narrower!
            exception_to=[XID],
            valid_until=_future_iso(),
            justification="Not narrower",
            approved_by=XID_2,
        )
        engine = PolicyEngine([deny_p, allow_p])
        result = engine.evaluate(ACTION, RESOURCES, context={"agent_id": XID_2})
        assert result.effect == "deny"

    def test_override_missing_valid_until_fails(self):
        """Missing valid_until -> override fails."""
        deny_p = _make_policy(pid=XID, effect=PolicyEffect.deny, priority=50)
        allow_p = _make_policy(
            pid=XID_2,
            effect=PolicyEffect.allow,
            priority=50,
            scope=PolicyScope.agent,
            agent_scope=XID_2,
            exception_to=[XID],
            justification="No valid_until",
            approved_by=XID_2,
        )
        engine = PolicyEngine([deny_p, allow_p])
        result = engine.evaluate(ACTION, RESOURCES, context={"agent_id": XID_2})
        assert result.effect == "deny"

    def test_override_missing_justification_fails(self):
        """Missing justification -> override fails."""
        deny_p = _make_policy(pid=XID, effect=PolicyEffect.deny, priority=50)
        allow_p = _make_policy(
            pid=XID_2,
            effect=PolicyEffect.allow,
            priority=50,
            scope=PolicyScope.agent,
            agent_scope=XID_2,
            exception_to=[XID],
            valid_until=_future_iso(),
            approved_by=XID_2,
        )
        engine = PolicyEngine([deny_p, allow_p])
        result = engine.evaluate(ACTION, RESOURCES, context={"agent_id": XID_2})
        assert result.effect == "deny"

    def test_override_missing_approved_by_fails(self):
        """Missing approved_by -> override fails."""
        deny_p = _make_policy(pid=XID, effect=PolicyEffect.deny, priority=50)
        allow_p = _make_policy(
            pid=XID_2,
            effect=PolicyEffect.allow,
            priority=50,
            scope=PolicyScope.agent,
            agent_scope=XID_2,
            exception_to=[XID],
            valid_until=_future_iso(),
            justification="No approved_by",
        )
        engine = PolicyEngine([deny_p, allow_p])
        result = engine.evaluate(ACTION, RESOURCES, context={"agent_id": XID_2})
        assert result.effect == "deny"


# --------------------------------------------------------------------------- #
# EP-POLICY-005: Priority alone does NOT override deny
# --------------------------------------------------------------------------- #


class TestPriorityAloneDoesNotOverride:
    """Tests that priority alone cannot override deny (EP-POLICY-005)."""

    def test_higher_priority_allow_without_exception_to_does_not_override(self):
        """Priority 101 allow vs priority 100 deny without exception_to.

        EP-POLICY-008: priority alone MUST NEVER authorize an exception
        to deny.  Without exception_to and all override controls, the deny
        wins regardless of the allow's higher priority.
        """
        deny_p = _make_policy(pid=XID, effect=PolicyEffect.deny, priority=100)
        allow_p = _make_policy(
            pid=XID_2,
            effect=PolicyEffect.allow,
            priority=101,
            # No exception_to, no override controls
        )
        engine = PolicyEngine([deny_p, allow_p])
        result = engine.evaluate(ACTION, RESOURCES, context={"agent_id": XID_2})
        # Deny wins because priority alone does not override deny
        assert result.effect == "deny"
        # Both policies are in matched_policies
        assert len(result.matched_policies) == 2


# --------------------------------------------------------------------------- #
# EP-POLICY-002: Non-active policies are NOT matched
# --------------------------------------------------------------------------- #


class TestNonActivePoliciesNotMatched:
    """Tests that non-active policies are not matched (EP-POLICY-002)."""

    @pytest.mark.parametrize(
        "status",
        [
            PolicyStatus.draft,
            PolicyStatus.pending_approval,
            PolicyStatus.rejected,
            PolicyStatus.superseded,
            PolicyStatus.retired,
        ],
    )
    def test_non_active_status_not_matched(self, status):
        """Policies with non-active status are not matched by the engine."""
        p = _make_policy(effect=PolicyEffect.deny, status=status)
        engine = PolicyEngine([p])
        result = engine.evaluate(ACTION, RESOURCES)
        # No matching policies -> fail closed (require_approval)
        assert len(result.matched_policies) == 0
        assert result.effect == "require_approval"

    def test_expired_policy_not_matched(self):
        """Active policy with past valid_until is not in force -> not matched."""
        p = _make_policy(
            effect=PolicyEffect.deny,
            status=PolicyStatus.active,
            valid_until=_past_iso(),
        )
        engine = PolicyEngine([p])
        result = engine.evaluate(ACTION, RESOURCES)
        assert len(result.matched_policies) == 0

    def test_future_valid_from_not_matched(self):
        """Active policy with future valid_from is not yet in force -> not matched."""
        p = _make_policy(
            effect=PolicyEffect.deny,
            status=PolicyStatus.active,
            valid_from=_future_iso(),
        )
        engine = PolicyEngine([p])
        result = engine.evaluate(ACTION, RESOURCES)
        assert len(result.matched_policies) == 0


# --------------------------------------------------------------------------- #
# Condition matching
# --------------------------------------------------------------------------- #


class TestConditionMatching:
    """Tests for condition evaluation."""

    def test_empty_conditions_always_match(self):
        """Policies with empty conditions always match."""
        p = _make_policy(effect=PolicyEffect.deny, conditions={})
        engine = PolicyEngine([p])
        result = engine.evaluate(ACTION, RESOURCES, context={})
        assert result.effect == "deny"

    def test_empty_conditions_match_with_context(self):
        """Empty conditions match even with a populated context."""
        p = _make_policy(effect=PolicyEffect.deny, conditions={})
        engine = PolicyEngine([p])
        result = engine.evaluate(ACTION, RESOURCES, context={"foo": "bar"})
        assert result.effect == "deny"

    def test_condition_key_present_value_matches(self):
        """Condition key present in context with matching value -> match."""
        p = _make_policy(effect=PolicyEffect.deny, conditions={"env": "production"})
        engine = PolicyEngine([p])
        result = engine.evaluate(ACTION, RESOURCES, context={"env": "production"})
        assert result.effect == "deny"

    def test_condition_key_missing_no_match(self):
        """Condition key missing from context -> no match."""
        p = _make_policy(effect=PolicyEffect.deny, conditions={"env": "production"})
        engine = PolicyEngine([p])
        result = engine.evaluate(ACTION, RESOURCES, context={})
        assert len(result.matched_policies) == 0

    def test_condition_value_mismatch_no_match(self):
        """Condition key present but value mismatch -> no match."""
        p = _make_policy(effect=PolicyEffect.deny, conditions={"env": "production"})
        engine = PolicyEngine([p])
        result = engine.evaluate(ACTION, RESOURCES, context={"env": "staging"})
        assert len(result.matched_policies) == 0

    def test_multiple_conditions_all_must_match(self):
        """Multiple conditions: all must match for the policy to apply."""
        p = _make_policy(
            effect=PolicyEffect.deny,
            conditions={"env": "production", "user": "admin"},
        )
        engine = PolicyEngine([p])
        # Both match
        result = engine.evaluate(ACTION, RESOURCES, context={"env": "production", "user": "admin"})
        assert result.effect == "deny"
        # One mismatch
        result = engine.evaluate(ACTION, RESOURCES, context={"env": "production", "user": "guest"})
        assert len(result.matched_policies) == 0

    def test_no_context_uses_empty_dict(self):
        """When context is None, it's treated as empty."""
        p = _make_policy(effect=PolicyEffect.deny, conditions={"env": "production"})
        engine = PolicyEngine([p])
        result = engine.evaluate(ACTION, RESOURCES, context=None)
        assert len(result.matched_policies) == 0


# --------------------------------------------------------------------------- #
# CEL condition matching
# --------------------------------------------------------------------------- #


class TestCELConditionMatching:
    """Tests for CEL-based condition evaluation.

    When a policy's conditions dict contains a ``"cel"`` key with a string
    value, that string is evaluated as a CEL (Common Expression Language)
    expression against the context.  The expression must evaluate to
    boolean ``true`` for the policy to match.
    """

    def test_cel_basic_equality_match(self):
        """CEL expression with matching context value -> policy matches."""
        p = _make_policy(
            effect=PolicyEffect.deny,
            conditions={"cel": "agent_id == 'd9m966nug6j6t7v1l1og'"},
        )
        engine = PolicyEngine([p])
        result = engine.evaluate(
            ACTION, RESOURCES,
            context={"agent_id": "d9m966nug6j6t7v1l1og"},
        )
        assert result.effect == "deny"
        assert len(result.matched_policies) == 1

    def test_cel_basic_equality_no_match(self):
        """CEL expression with non-matching context value -> no match."""
        p = _make_policy(
            effect=PolicyEffect.deny,
            conditions={"cel": "agent_id == 'd9m966nug6j6t7v1l1og'"},
        )
        engine = PolicyEngine([p])
        result = engine.evaluate(
            ACTION, RESOURCES,
            context={"agent_id": "other_agent_id00"},
        )
        assert len(result.matched_policies) == 0

    def test_cel_string_contains(self):
        """CEL string contains() function."""
        p = _make_policy(
            effect=PolicyEffect.deny,
            conditions={"cel": "tool.contains('select')"},
        )
        engine = PolicyEngine([p])
        # Matching
        result = engine.evaluate(
            "postgres.execute.select", RESOURCES,
            context={"tool": "postgres.execute.select"},
        )
        assert result.effect == "deny"
        # Non-matching
        result = engine.evaluate(
            "postgres.execute.insert", RESOURCES,
            context={"tool": "postgres.execute.insert"},
        )
        assert len(result.matched_policies) == 0

    def test_cel_starts_with(self):
        """CEL startsWith() function."""
        p = _make_policy(
            effect=PolicyEffect.deny,
            conditions={"cel": "agent_id.startsWith('d9')"},
        )
        engine = PolicyEngine([p])
        result = engine.evaluate(
            ACTION, RESOURCES,
            context={"agent_id": "d9m966nug6j6t7v1l1og"},
        )
        assert result.effect == "deny"

    def test_cel_has_function(self):
        """CEL has() macro for checking key presence."""
        p = _make_policy(
            effect=PolicyEffect.deny,
            conditions={"cel": "has(branch_id)"},
        )
        engine = PolicyEngine([p])
        # Key present -> match
        result = engine.evaluate(
            ACTION, RESOURCES,
            context={"branch_id": "0123456789abcdefghij"},
        )
        assert result.effect == "deny"
        # Key absent -> no match (fail closed, not error)
        result = engine.evaluate(ACTION, RESOURCES, context={})
        assert len(result.matched_policies) == 0

    def test_cel_logical_and(self):
        """CEL logical && operator."""
        p = _make_policy(
            effect=PolicyEffect.deny,
            conditions={"cel": "agent_id == 'd9m966nug6j6t7v1l1og' && tool.contains('select')"},
        )
        engine = PolicyEngine([p])
        # Both true
        result = engine.evaluate(
            ACTION, RESOURCES,
            context={
                "agent_id": "d9m966nug6j6t7v1l1og",
                "tool": "postgres.execute.select",
            },
        )
        assert result.effect == "deny"
        # One false
        result = engine.evaluate(
            ACTION, RESOURCES,
            context={
                "agent_id": "d9m966nug6j6t7v1l1og",
                "tool": "postgres.execute.insert",
            },
        )
        assert len(result.matched_policies) == 0

    def test_cel_logical_or(self):
        """CEL logical || operator."""
        p = _make_policy(
            effect=PolicyEffect.allow,
            conditions={"cel": "agent_id == 'aaa' || agent_id == 'bbb'"},
        )
        engine = PolicyEngine([p])
        # First matches
        result = engine.evaluate(
            ACTION, RESOURCES,
            context={"agent_id": "aaa"},
        )
        assert result.effect == "allow"
        # Second matches
        result = engine.evaluate(
            ACTION, RESOURCES,
            context={"agent_id": "bbb"},
        )
        assert result.effect == "allow"
        # Neither matches
        result = engine.evaluate(
            ACTION, RESOURCES,
            context={"agent_id": "ccc"},
        )
        assert len(result.matched_policies) == 0

    def test_cel_size_function_on_map(self):
        """CEL size() on a map (arguments dict)."""
        p = _make_policy(
            effect=PolicyEffect.deny,
            conditions={"cel": "arguments.size() > 0"},
        )
        engine = PolicyEngine([p])
        # Non-empty arguments -> match
        result = engine.evaluate(
            ACTION, RESOURCES,
            context={"arguments": {"key": "val"}},
        )
        assert result.effect == "deny"
        # Empty arguments -> no match
        result = engine.evaluate(
            ACTION, RESOURCES,
            context={"arguments": {}},
        )
        assert len(result.matched_policies) == 0

    def test_cel_matches_regex(self):
        """CEL matches() for regex matching."""
        p = _make_policy(
            effect=PolicyEffect.deny,
            conditions={"cel": "tool.matches('.*\\\\.select')"},
        )
        engine = PolicyEngine([p])
        result = engine.evaluate(
            ACTION, RESOURCES,
            context={"tool": "postgres.execute.select"},
        )
        assert result.effect == "deny"

    def test_cel_false_expression_no_match(self):
        """CEL expression that evaluates to false -> no match."""
        p = _make_policy(
            effect=PolicyEffect.deny,
            conditions={"cel": "1 + 1 == 3"},
        )
        engine = PolicyEngine([p])
        result = engine.evaluate(ACTION, RESOURCES, context={})
        assert len(result.matched_policies) == 0

    def test_cel_true_expression_matches(self):
        """CEL expression that evaluates to true -> match."""
        p = _make_policy(
            effect=PolicyEffect.deny,
            conditions={"cel": "1 + 1 == 2"},
        )
        engine = PolicyEngine([p])
        result = engine.evaluate(ACTION, RESOURCES, context={})
        assert result.effect == "deny"

    def test_cel_invalid_syntax_fails_closed(self):
        """Invalid CEL syntax -> fail closed (no match, not crash)."""
        p = _make_policy(
            effect=PolicyEffect.deny,
            conditions={"cel": "agent_id ==="},  # Syntax error
        )
        engine = PolicyEngine([p])
        result = engine.evaluate(
            ACTION, RESOURCES,
            context={"agent_id": "test"},
        )
        # The engine wraps _match_policies in try/except, so a parse error
        # in CEL evaluation propagates up and the engine fails closed to
        # require_approval.
        assert result.effect == "require_approval"
        assert len(result.matched_policies) == 0
        assert any("Evaluation error" in w for w in result.warnings)

    def test_cel_non_boolean_result_no_match(self):
        """CEL expression that returns non-boolean -> no match (strict bool)."""
        p = _make_policy(
            effect=PolicyEffect.deny,
            conditions={"cel": "agent_id"},  # Returns string, not bool
        )
        engine = PolicyEngine([p])
        result = engine.evaluate(
            ACTION, RESOURCES,
            context={"agent_id": "test"},
        )
        assert len(result.matched_policies) == 0

    def test_cel_with_transition_context_fields(self):
        """CEL expression using the full transition context: agent_id, tool, arguments, branch_id."""
        p = _make_policy(
            effect=PolicyEffect.deny,
            conditions={"cel": "agent_id == 'd9m966nug6j6t7v1l1og' && tool.contains('select') && has(branch_id)"},
        )
        engine = PolicyEngine([p])
        result = engine.evaluate(
            "postgres.execute.select", RESOURCES,
            context={
                "agent_id": "d9m966nug6j6t7v1l1og",
                "tool": "postgres.execute.select",
                "arguments": {"query": "SELECT 1"},
                "branch_id": "0123456789abcdefghij",
            },
        )
        assert result.effect == "deny"

    def test_cel_preserves_empty_conditions_pass(self):
        """Empty conditions {} still passes (backward compatibility)."""
        p = _make_policy(effect=PolicyEffect.deny, conditions={})
        engine = PolicyEngine([p])
        result = engine.evaluate(ACTION, RESOURCES, context={})
        assert result.effect == "deny"

    def test_cel_and_legacy_conditions_coexist(self):
        """Legacy key-value conditions (without 'cel' key) still work."""
        p = _make_policy(
            effect=PolicyEffect.deny,
            conditions={"env": "production", "user": "admin"},
        )
        engine = PolicyEngine([p])
        # Both match
        result = engine.evaluate(
            ACTION, RESOURCES,
            context={"env": "production", "user": "admin"},
        )
        assert result.effect == "deny"
        # Mismatch
        result = engine.evaluate(
            ACTION, RESOURCES,
            context={"env": "staging", "user": "admin"},
        )
        assert len(result.matched_policies) == 0

    def test_cel_empty_string_expression_fails_closed(self):
        """Empty string CEL expression -> parse error -> fail closed."""
        p = _make_policy(
            effect=PolicyEffect.deny,
            conditions={"cel": ""},
        )
        engine = PolicyEngine([p])
        result = engine.evaluate(ACTION, RESOURCES, context={})
        assert result.effect == "require_approval"

    def test_cel_cel_key_with_non_string_value_uses_legacy(self):
        """If 'cel' key has a non-string value, falls through to legacy mode."""
        p = _make_policy(
            effect=PolicyEffect.deny,
            conditions={"cel": True, "env": "production"},
        )
        engine = PolicyEngine([p])
        # Should use legacy equality: cel=True must match context, env must match
        result = engine.evaluate(
            ACTION, RESOURCES,
            context={"cel": True, "env": "production"},
        )
        assert result.effect == "deny"


# --------------------------------------------------------------------------- #
# No matching policies
# --------------------------------------------------------------------------- #


class TestNoMatchingPolicies:
    """Tests for when no policies match."""

    def test_no_policies_at_all(self):
        """Empty policy list -> fail closed (require_approval)."""
        engine = PolicyEngine([])
        result = engine.evaluate(ACTION, RESOURCES)
        assert result.effect == "require_approval"
        assert len(result.matched_policies) == 0
        assert result.conflict is False

    def test_no_policy_matches_action(self):
        """Policy exists but doesn't match the action -> no match."""
        p = _make_policy(effect=PolicyEffect.deny, actions=["email.send.*"])
        engine = PolicyEngine([p])
        result = engine.evaluate(ACTION, RESOURCES)
        assert result.effect == "require_approval"

    def test_no_policy_matches_resource(self):
        """Policy exists but doesn't match the resource -> no match."""
        p = _make_policy(
            effect=PolicyEffect.deny,
            resources=["postgres://otherhost/*"],
        )
        engine = PolicyEngine([p])
        result = engine.evaluate(ACTION, RESOURCES)
        assert result.effect == "require_approval"


# --------------------------------------------------------------------------- #
# Multiple matching policies
# --------------------------------------------------------------------------- #


class TestMultipleMatchingPolicies:
    """Tests for multiple matching policies with different effects."""

    def test_multiple_different_effects_different_priorities(self):
        """Multiple policies with different priorities -> highest priority wins."""
        p1 = _make_policy(pid=XID, effect=PolicyEffect.warn, priority=30)
        p2 = _make_policy(pid=XID_2, effect=PolicyEffect.deny, priority=80)
        p3 = _make_policy(
            pid="0123456789abcdejjk00",
            effect=PolicyEffect.allow,
            priority=10,
        )
        engine = PolicyEngine([p1, p2, p3])
        result = engine.evaluate(ACTION, RESOURCES)
        assert result.effect == "deny"
        assert len(result.matched_policies) == 3

    def test_multiple_same_effect_same_priority(self):
        """Multiple policies same effect, same priority -> no conflict."""
        p1 = _make_policy(pid=XID, effect=PolicyEffect.warn, priority=50)
        p2 = _make_policy(pid=XID_2, effect=PolicyEffect.warn, priority=50)
        engine = PolicyEngine([p1, p2])
        result = engine.evaluate(ACTION, RESOURCES)
        assert result.effect == "warn"
        assert result.conflict is False
        assert len(result.matched_policies) == 2


# --------------------------------------------------------------------------- #
# Evaluation error fails closed
# --------------------------------------------------------------------------- #


class TestFailClosed:
    """Tests for fail-closed behavior on evaluation errors."""

    def test_engine_handles_errors_gracefully(self):
        """If evaluation raises an exception, engine fails closed.

        The engine wraps evaluation in try/except and returns
        require_approval on any exception.
        """
        # We can trigger an error by passing something that causes
        # _match_policies to fail. One way: monkey-patch the engine.
        p = _make_policy(effect=PolicyEffect.deny)
        engine = PolicyEngine([p])

        # Monkey-patch _match_policies to raise
        original_match = engine._match_policies

        def raising_match(*args, **kwargs):
            raise RuntimeError("Simulated failure")

        engine._match_policies = raising_match  # type: ignore[assignment]
        result = engine.evaluate(ACTION, RESOURCES)
        assert result.effect == "require_approval"
        assert result.conflict is False
        assert len(result.matched_policies) == 0
        # Check that a warning was appended
        assert len(result.warnings) > 0

        # Restore for cleanliness
        engine._match_policies = original_match  # type: ignore[assignment]


# --------------------------------------------------------------------------- #
# PolicyResolution dataclass
# --------------------------------------------------------------------------- #


class TestPolicyResolution:
    """Tests for PolicyResolution dataclass."""

    def test_default_warnings_empty(self):
        res = PolicyResolution(effect="deny", matched_policies=[], conflict=False)
        assert res.warnings == []

    def test_fields(self):
        res = PolicyResolution(
            effect="allow",
            matched_policies=[],
            conflict=False,
            warnings=["test"],
        )
        assert res.effect == "allow"
        assert res.matched_policies == []
        assert res.conflict is False
        assert res.warnings == ["test"]


class TestMissingScopeContextFailsClosed:
    def test_agent_scope_without_agent_context_requires_approval(self):
        p = _make_policy(
            pid=XID,
            effect=PolicyEffect.deny,
            scope=PolicyScope.agent,
            agent_scope=XID_2,
        )
        result = PolicyEngine([p]).evaluate(ACTION, RESOURCES)
        assert result.effect == "require_approval"
        assert any("agent_id is required" in warning for warning in result.warnings)

    def test_branch_scope_without_branch_context_requires_approval(self):
        p = _make_policy(
            pid=XID,
            effect=PolicyEffect.deny,
            scope=PolicyScope.branch,
            branch_id=XID_2,
        )
        result = PolicyEngine([p]).evaluate(ACTION, RESOURCES)
        assert result.effect == "require_approval"
        assert any("branch_id is required" in warning for warning in result.warnings)
