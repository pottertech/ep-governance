"""Unit tests for EP-Governance policy models.

References normative rules:
  EP-POLICY-001: policy status values (draft, pending_approval, active, rejected, superseded, retired)
  EP-POLICY-002: policy is only in force when status==active and valid_from/valid_until satisfied
  EP-POLICY-003: policy effect values (deny, require_approval, warn, allow)
  EP-POLICY-004: effect precedence deny > require_approval > warn > allow
  EP-POLICY-008: policy fields
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from ep_governance.policies import (
    EFFECT_PRECEDENCE,
    Policy,
    PolicyEffect,
    PolicyScope,
    PolicyStatus,
)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

VALID_XID = "0123456789abcdefghij"  # 20-char base32hex


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _future_iso(seconds: int = 3600) -> str:
    from datetime import timedelta

    dt = datetime.now(timezone.utc) + timedelta(seconds=seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _past_iso(seconds: int = 3600) -> str:
    from datetime import timedelta

    dt = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _make_policy(**overrides) -> Policy:
    """Build a valid Policy with sensible defaults, allowing overrides."""
    defaults = dict(
        id=VALID_XID,
        effect=PolicyEffect.deny,
        actions=["postgres.execute.*"],
        resources=["postgres://cloudhub/*"],
        conditions={},
        priority=50,
        scope=PolicyScope.global_,
        agent_scope=None,
        description="Test policy",
        status=PolicyStatus.active,
        created_by=VALID_XID,
    )
    defaults.update(overrides)
    return Policy(**defaults)


# --------------------------------------------------------------------------- #
# EP-POLICY-003: PolicyEffect enum values
# --------------------------------------------------------------------------- #


class TestPolicyEffect:
    """Tests for PolicyEffect enum (EP-POLICY-003)."""

    def test_deny_value(self):
        assert PolicyEffect.deny.value == "deny"

    def test_require_approval_value(self):
        assert PolicyEffect.require_approval.value == "require_approval"

    def test_warn_value(self):
        assert PolicyEffect.warn.value == "warn"

    def test_allow_value(self):
        assert PolicyEffect.allow.value == "allow"

    @pytest.mark.parametrize("effect", list(PolicyEffect))
    def test_all_effects_are_str_enum(self, effect):
        assert isinstance(effect, str)
        assert isinstance(effect, PolicyEffect)


# --------------------------------------------------------------------------- #
# EP-POLICY-001: PolicyStatus enum values
# --------------------------------------------------------------------------- #


class TestPolicyStatus:
    """Tests for PolicyStatus enum (EP-POLICY-001)."""

    def test_draft_value(self):
        assert PolicyStatus.draft.value == "draft"

    def test_pending_approval_value(self):
        assert PolicyStatus.pending_approval.value == "pending_approval"

    def test_active_value(self):
        assert PolicyStatus.active.value == "active"

    def test_rejected_value(self):
        assert PolicyStatus.rejected.value == "rejected"

    def test_superseded_value(self):
        assert PolicyStatus.superseded.value == "superseded"

    def test_retired_value(self):
        assert PolicyStatus.retired.value == "retired"

    @pytest.mark.parametrize("status", list(PolicyStatus))
    def test_all_statuses_are_str_enum(self, status):
        assert isinstance(status, str)
        assert isinstance(status, PolicyStatus)


# --------------------------------------------------------------------------- #
# PolicyScope enum values
# --------------------------------------------------------------------------- #


class TestPolicyScope:
    """Tests for PolicyScope enum."""

    def test_global_value(self):
        assert PolicyScope.global_.value == "global"

    def test_agent_value(self):
        assert PolicyScope.agent.value == "agent"

    @pytest.mark.parametrize("scope", list(PolicyScope))
    def test_all_scopes_are_str_enum(self, scope):
        assert isinstance(scope, str)
        assert isinstance(scope, PolicyScope)


# --------------------------------------------------------------------------- #
# EP-POLICY-004: EFFECT_PRECEDENCE
# --------------------------------------------------------------------------- #


class TestEffectPrecedence:
    """Tests for EFFECT_PRECEDENCE ordering (EP-POLICY-004)."""

    def test_deny_has_highest_precedence(self):
        assert EFFECT_PRECEDENCE["deny"] == 4

    def test_require_approval_second(self):
        assert EFFECT_PRECEDENCE["require_approval"] == 3

    def test_warn_third(self):
        assert EFFECT_PRECEDENCE["warn"] == 2

    def test_allow_lowest(self):
        assert EFFECT_PRECEDENCE["allow"] == 1

    def test_deny_greater_than_require_approval(self):
        assert EFFECT_PRECEDENCE["deny"] > EFFECT_PRECEDENCE["require_approval"]

    def test_require_approval_greater_than_warn(self):
        assert EFFECT_PRECEDENCE["require_approval"] > EFFECT_PRECEDENCE["warn"]

    def test_warn_greater_than_allow(self):
        assert EFFECT_PRECEDENCE["warn"] > EFFECT_PRECEDENCE["allow"]

    def test_full_ordering(self):
        assert (
            EFFECT_PRECEDENCE["deny"]
            > EFFECT_PRECEDENCE["require_approval"]
            > EFFECT_PRECEDENCE["warn"]
            > EFFECT_PRECEDENCE["allow"]
        )


# --------------------------------------------------------------------------- #
# EP-POLICY-002: Policy.is_in_force()
# --------------------------------------------------------------------------- #


class TestPolicyIsInForce:
    """Tests for Policy.is_in_force() (EP-POLICY-002)."""

    def test_active_no_time_constraints_is_in_force(self):
        """Active policy with no valid_from/valid_until is in force."""
        p = _make_policy(status=PolicyStatus.active, valid_from=None, valid_until=None)
        assert p.is_in_force() is True

    def test_active_with_future_valid_from_not_in_force(self):
        """Active policy with future valid_from is NOT in force."""
        p = _make_policy(status=PolicyStatus.active, valid_from=_future_iso())
        assert p.is_in_force() is False

    def test_active_with_past_valid_from_is_in_force(self):
        p = _make_policy(status=PolicyStatus.active, valid_from=_past_iso())
        assert p.is_in_force() is True

    def test_active_with_future_valid_until_is_in_force(self):
        p = _make_policy(status=PolicyStatus.active, valid_until=_future_iso())
        assert p.is_in_force() is True

    def test_active_with_past_valid_until_not_in_force(self):
        """Active policy with past valid_until is NOT in force (EP-POLICY-002)."""
        p = _make_policy(status=PolicyStatus.active, valid_until=_past_iso())
        assert p.is_in_force() is False

    def test_active_with_valid_until_equal_now_not_in_force(self):
        """valid_until == now means expired (valid_until > now is required)."""
        now = _now_iso()
        p = _make_policy(status=PolicyStatus.active, valid_until=now)
        assert p.is_in_force() is False

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
    def test_non_active_statuses_not_in_force(self, status):
        """Non-active statuses are never in force (EP-POLICY-002)."""
        p = _make_policy(status=status)
        assert p.is_in_force() is False

    def test_is_in_force_with_explicit_now(self):
        """is_in_force accepts an explicit now parameter."""
        now = _now_iso()
        p = _make_policy(
            status=PolicyStatus.active,
            valid_from=_past_iso(7200),
            valid_until=_future_iso(3600),
        )
        assert p.is_in_force(now=now) is True

    def test_is_in_force_with_explicit_now_in_past(self):
        """is_in_force with now before valid_from returns False."""
        past = _past_iso(7200)
        p = _make_policy(
            status=PolicyStatus.active,
            valid_from=_past_iso(3600),
        )
        assert p.is_in_force(now=past) is False

    def test_is_in_force_with_explicit_now_after_valid_until(self):
        """is_in_force with now after valid_until returns False."""
        future = _future_iso(7200)
        p = _make_policy(
            status=PolicyStatus.active,
            valid_until=_future_iso(3600),
        )
        assert p.is_in_force(now=future) is False


# --------------------------------------------------------------------------- #
# Policy validation
# --------------------------------------------------------------------------- #


class TestPolicyValidation:
    """Tests for Policy model validation."""

    def test_priority_must_be_non_negative(self):
        """priority >= 0 is enforced (EP-POLICY-008)."""
        with pytest.raises(ValidationError):
            _make_policy(priority=-1)

    def test_priority_zero_is_valid(self):
        p = _make_policy(priority=0)
        assert p.priority == 0

    def test_priority_positive_is_valid(self):
        p = _make_policy(priority=100)
        assert p.priority == 100

    def test_invalid_id_format_raises(self):
        with pytest.raises(ValidationError):
            _make_policy(id="too-short")

    def test_invalid_created_by_raises(self):
        with pytest.raises(ValidationError):
            _make_policy(created_by="bad")

    def test_invalid_approved_by_raises(self):
        with pytest.raises(ValidationError):
            _make_policy(approved_by="bad")

    def test_extra_fields_rejected(self):
        """model_config has extra='forbid'."""
        with pytest.raises(ValidationError):
            Policy(
                id=VALID_XID,
                effect=PolicyEffect.allow,
                actions=["*"],
                resources=["*"],
                priority=0,
                scope=PolicyScope.global_,
                description="test",
                status=PolicyStatus.active,
                created_by=VALID_XID,
                extra_field="bad",  # type: ignore[call-arg]
            )


# --------------------------------------------------------------------------- #
# EP-POLICY-008: model_config with use_enum_values
# --------------------------------------------------------------------------- #


class TestModelConfig:
    """Tests for model_config behavior."""

    def test_use_enum_values_stores_strings(self):
        """With use_enum_values=True, enum fields store their string values."""
        p = _make_policy(
            effect=PolicyEffect.deny,
            status=PolicyStatus.active,
            scope=PolicyScope.global_,
        )
        assert p.effect == "deny"
        assert p.status == "active"
        assert p.scope == "global"

    def test_use_enum_values_effect_string(self):
        p = _make_policy(effect=PolicyEffect.require_approval)
        assert p.effect == "require_approval"

    def test_validate_assignment(self):
        """validate_assignment=True means setting a field re-validates."""
        p = _make_policy(priority=10)
        with pytest.raises(ValidationError):
            p.priority = -5

    def test_status_can_be_string_value(self):
        """Policy accepts string values for enum fields."""
        p = _make_policy(status="active")
        assert p.status == "active"

    def test_effect_can_be_string_value(self):
        p = _make_policy(effect="allow")
        assert p.effect == "allow"
