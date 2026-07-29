"""Unit tests for EP-Governance risk assessment.

References normative rules:
  EP-RISK-001: risk assessments scoped per domain
  EP-RISK-002: initial risk domains (production_database, external_communications, deployment, data_privacy, security)
  EP-RISK-003: per-domain tracking (risk_increment, inherent_risk, mitigation_credit, residual_risk, threshold, decision)
  EP-RISK-004: verified evidence for mitigations
  EP-RISK-005: agents must not assign their own mitigation credit
  EP-RISK-006: expired mitigations contribute 0 credit
  EP-RISK-007: risk acceptance is scoped, time-limited, audited
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ep_governance.risk import (
    RiskAssessment,
    RiskDecision,
    RiskDomain,
    Mitigation,
    assess_risk,
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _future_iso(seconds: int = 3600) -> str:
    dt = datetime.now(timezone.utc) + timedelta(seconds=seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _past_iso(seconds: int = 3600) -> str:
    dt = datetime.now(timezone.utc) - timedelta(seconds=seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _make_mitigation(
    credit: float = 20.0,
    expires_at: str | None = None,
) -> Mitigation:
    return Mitigation(
        evidence_type="test_result",
        evidence_uri="file://localhost/evidence/test.json",
        evidence_hash="abcdef1234567890",
        verified_by="0123456789abcdefghij",
        verified_at=_now_iso(),
        expires_at=expires_at,
        scope="global",
        credit=credit,
    )


# --------------------------------------------------------------------------- #
# EP-RISK-002: RiskDomain enum values
# --------------------------------------------------------------------------- #


class TestRiskDomain:
    """Tests for RiskDomain enum (EP-RISK-002)."""

    def test_production_database(self):
        assert RiskDomain.production_database.value == "production_database"

    def test_external_communications(self):
        assert RiskDomain.external_communications.value == "external_communications"

    def test_deployment(self):
        assert RiskDomain.deployment.value == "deployment"

    def test_data_privacy(self):
        assert RiskDomain.data_privacy.value == "data_privacy"

    def test_security(self):
        assert RiskDomain.security.value == "security"

    @pytest.mark.parametrize("domain", list(RiskDomain))
    def test_all_domains_are_str_enum(self, domain):
        assert isinstance(domain, str)
        assert isinstance(domain, RiskDomain)

    def test_all_five_initial_domains(self):
        """EP-RISK-002: exactly 5 initial risk domains."""
        assert len(list(RiskDomain)) == 5


# --------------------------------------------------------------------------- #
# RiskDecision enum values
# --------------------------------------------------------------------------- #


class TestRiskDecision:
    """Tests for RiskDecision enum."""

    def test_deny(self):
        assert RiskDecision.deny.value == "deny"

    def test_require_approval(self):
        assert RiskDecision.require_approval.value == "require_approval"

    def test_warn(self):
        assert RiskDecision.warn.value == "warn"

    def test_allow(self):
        assert RiskDecision.allow.value == "allow"

    @pytest.mark.parametrize("decision", list(RiskDecision))
    def test_all_decisions_are_str_enum(self, decision):
        assert isinstance(decision, str)
        assert isinstance(decision, RiskDecision)


# --------------------------------------------------------------------------- #
# assess_risk: decision logic
# --------------------------------------------------------------------------- #


class TestAssessRiskDecisions:
    """Tests for assess_risk decision logic."""

    def test_low_residual_allows(self):
        """Low residual risk -> allow (EP-RISK-003)."""
        result = assess_risk(
            domain=RiskDomain.production_database,
            inherent_risk=10.0,
            threshold=80.0,
            mitigations=[],
            risk_increment=5.0,
        )
        assert result.decision == RiskDecision.allow
        assert result.residual_risk == 15.0

    def test_residual_above_threshold_requires_approval(self):
        """residual > threshold -> require_approval (EP-RISK-003)."""
        result = assess_risk(
            domain=RiskDomain.production_database,
            inherent_risk=70.0,
            threshold=50.0,
            mitigations=[],
            risk_increment=10.0,
        )
        assert result.decision == RiskDecision.require_approval
        assert result.residual_risk == 80.0
        assert result.residual_risk > result.threshold

    def test_residual_in_warn_zone_warns(self):
        """residual > threshold * 0.8 (but <= threshold) -> warn (EP-RISK-003)."""
        threshold = 50.0
        # residual = 45.0 which is > threshold*0.8 = 40.0 but <= threshold = 50.0
        result = assess_risk(
            domain=RiskDomain.production_database,
            inherent_risk=40.0,
            threshold=threshold,
            mitigations=[],
            risk_increment=5.0,
        )
        assert result.decision == RiskDecision.warn
        assert result.residual_risk == 45.0
        assert result.residual_risk > threshold * 0.8
        assert result.residual_risk <= threshold

    def test_high_inherent_and_high_residual_denies(self):
        """inherent >= 90 AND residual >= 80 -> deny (EP-RISK-003)."""
        result = assess_risk(
            domain=RiskDomain.production_database,
            inherent_risk=95.0,
            threshold=70.0,
            mitigations=[],
            risk_increment=10.0,
        )
        assert result.decision == RiskDecision.deny
        assert result.inherent_risk >= 90.0
        assert result.residual_risk >= 80.0

    def test_high_inherent_low_residual_does_not_deny(self):
        """inherent >= 90 but residual < 80 -> not deny."""
        result = assess_risk(
            domain=RiskDomain.production_database,
            inherent_risk=95.0,
            threshold=50.0,
            mitigations=[_make_mitigation(credit=50.0)],
            risk_increment=10.0,
        )
        # residual = 95 + 10 - 50 = 55, which is < 80
        assert result.decision != RiskDecision.deny
        assert result.residual_risk == 55.0

    def test_low_inherent_high_residual_does_not_deny(self):
        """inherent < 90 but residual >= 80 -> not deny (deny requires both)."""
        result = assess_risk(
            domain=RiskDomain.production_database,
            inherent_risk=70.0,
            threshold=50.0,
            mitigations=[],
            risk_increment=20.0,
        )
        # residual = 90, but inherent < 90, so not deny
        assert result.decision == RiskDecision.require_approval
        assert result.residual_risk == 90.0


# --------------------------------------------------------------------------- #
# Mitigation credit
# --------------------------------------------------------------------------- #


class TestMitigationCredit:
    """Tests for mitigation credit (EP-RISK-004, EP-RISK-006)."""

    def test_mitigation_credit_reduces_residual(self):
        """Mitigation credit reduces residual_risk (EP-RISK-003)."""
        without_mit = assess_risk(
            domain=RiskDomain.production_database,
            inherent_risk=60.0,
            threshold=80.0,
            mitigations=[],
            risk_increment=10.0,
        )
        with_mit = assess_risk(
            domain=RiskDomain.production_database,
            inherent_risk=60.0,
            threshold=80.0,
            mitigations=[_make_mitigation(credit=30.0)],
            risk_increment=10.0,
        )
        assert with_mit.residual_risk < without_mit.residual_risk
        assert with_mit.residual_risk == 40.0
        assert with_mit.mitigation_credit == 30.0

    def test_expired_mitigation_contributes_zero_credit(self):
        """Expired mitigations contribute 0 credit (EP-RISK-006)."""
        expired_mit = _make_mitigation(credit=50.0, expires_at=_past_iso())
        result = assess_risk(
            domain=RiskDomain.production_database,
            inherent_risk=60.0,
            threshold=80.0,
            mitigations=[expired_mit],
            risk_increment=10.0,
        )
        assert result.mitigation_credit == 0.0
        assert result.residual_risk == 70.0  # no credit applied

    def test_non_expired_mitigation_contributes_credit(self):
        """Non-expired mitigation contributes full credit."""
        active_mit = _make_mitigation(credit=50.0, expires_at=_future_iso())
        result = assess_risk(
            domain=RiskDomain.production_database,
            inherent_risk=60.0,
            threshold=80.0,
            mitigations=[active_mit],
            risk_increment=10.0,
        )
        assert result.mitigation_credit == 50.0
        assert result.residual_risk == 20.0

    def test_mitigation_no_expiry_contributes_credit(self):
        """Mitigation with no expires_at never expires -> contributes credit."""
        mit = _make_mitigation(credit=40.0, expires_at=None)
        result = assess_risk(
            domain=RiskDomain.production_database,
            inherent_risk=60.0,
            threshold=80.0,
            mitigations=[mit],
            risk_increment=10.0,
        )
        assert result.mitigation_credit == 40.0

    def test_multiple_mitigations_credit_sums(self):
        """Multiple valid mitigations sum their credit."""
        m1 = _make_mitigation(credit=20.0)
        m2 = _make_mitigation(credit=30.0)
        result = assess_risk(
            domain=RiskDomain.production_database,
            inherent_risk=60.0,
            threshold=80.0,
            mitigations=[m1, m2],
            risk_increment=10.0,
        )
        assert result.mitigation_credit == 50.0
        assert result.residual_risk == 20.0

    def test_mixed_expired_and_active_mitigations(self):
        """Expired mitigations contribute 0, active ones contribute credit."""
        expired = _make_mitigation(credit=50.0, expires_at=_past_iso())
        active = _make_mitigation(credit=20.0, expires_at=_future_iso())
        result = assess_risk(
            domain=RiskDomain.production_database,
            inherent_risk=60.0,
            threshold=80.0,
            mitigations=[expired, active],
            risk_increment=10.0,
        )
        assert result.mitigation_credit == 20.0
        assert result.residual_risk == 50.0

    def test_expired_mitigation_with_explicit_now(self):
        """Expiry check uses the now parameter."""
        mit = _make_mitigation(credit=50.0, expires_at="2026-07-29T12:00:00.000000Z")
        # now is after expiry -> expired
        result = assess_risk(
            domain=RiskDomain.production_database,
            inherent_risk=60.0,
            threshold=80.0,
            mitigations=[mit],
            risk_increment=10.0,
            now="2026-07-29T13:00:00.000000Z",
        )
        assert result.mitigation_credit == 0.0

    def test_not_yet_expired_with_explicit_now(self):
        """Mitigation not expired relative to now -> credit applies."""
        mit = _make_mitigation(credit=50.0, expires_at="2026-07-29T14:00:00.000000Z")
        result = assess_risk(
            domain=RiskDomain.production_database,
            inherent_risk=60.0,
            threshold=80.0,
            mitigations=[mit],
            risk_increment=10.0,
            now="2026-07-29T13:00:00.000000Z",
        )
        assert result.mitigation_credit == 50.0


# --------------------------------------------------------------------------- #
# Residual risk floor
# --------------------------------------------------------------------------- #


class TestResidualRiskFloor:
    """Tests that residual_risk never goes below 0."""

    def test_residual_risk_never_negative(self):
        """residual_risk = max(0, ...) — never negative."""
        result = assess_risk(
            domain=RiskDomain.production_database,
            inherent_risk=10.0,
            threshold=80.0,
            mitigations=[_make_mitigation(credit=100.0)],
            risk_increment=5.0,
        )
        assert result.residual_risk == 0.0
        assert result.residual_risk >= 0.0

    def test_residual_zero_with_large_mitigation(self):
        result = assess_risk(
            domain=RiskDomain.security,
            inherent_risk=5.0,
            threshold=80.0,
            mitigations=[_make_mitigation(credit=200.0)],
            risk_increment=0.0,
        )
        assert result.residual_risk == 0.0

    def test_residual_risk_calculation(self):
        """residual = max(0, inherent + increment - credit)."""
        result = assess_risk(
            domain=RiskDomain.deployment,
            inherent_risk=40.0,
            threshold=70.0,
            mitigations=[_make_mitigation(credit=15.0)],
            risk_increment=10.0,
        )
        assert result.residual_risk == 35.0  # 40 + 10 - 15


# --------------------------------------------------------------------------- #
# RiskAssessment model fields (EP-RISK-003)
# --------------------------------------------------------------------------- #


class TestRiskAssessmentFields:
    """Tests for RiskAssessment model fields (EP-RISK-003)."""

    def test_all_fields_present(self):
        """RiskAssessment has all required per-domain fields (EP-RISK-003)."""
        result = assess_risk(
            domain=RiskDomain.production_database,
            inherent_risk=50.0,
            threshold=70.0,
            mitigations=[],
            risk_increment=10.0,
        )
        assert hasattr(result, "domain")
        assert hasattr(result, "risk_increment")
        assert hasattr(result, "inherent_risk")
        assert hasattr(result, "mitigation_credit")
        assert hasattr(result, "residual_risk")
        assert hasattr(result, "threshold")
        assert hasattr(result, "decision")
        assert hasattr(result, "accepted_by")
        assert hasattr(result, "accepted_at")
        assert hasattr(result, "expiration")

    def test_domain_is_stored(self):
        result = assess_risk(
            domain=RiskDomain.security,
            inherent_risk=50.0,
            threshold=70.0,
            mitigations=[],
            risk_increment=10.0,
        )
        # With use_enum_values, domain is stored as its string value
        assert result.domain == "security"

    def test_decision_is_stored(self):
        result = assess_risk(
            domain=RiskDomain.production_database,
            inherent_risk=10.0,
            threshold=80.0,
            mitigations=[],
            risk_increment=5.0,
        )
        assert result.decision == "allow"

    def test_risk_increment_stored(self):
        result = assess_risk(
            domain=RiskDomain.production_database,
            inherent_risk=10.0,
            threshold=80.0,
            mitigations=[],
            risk_increment=7.5,
        )
        assert result.risk_increment == 7.5


# --------------------------------------------------------------------------- #
# Mitigation model validation (EP-RISK-004, EP-RISK-005)
# --------------------------------------------------------------------------- #


class TestMitigationModel:
    """Tests for Mitigation model validation."""

    def test_mitigation_requires_verified_by(self):
        """EP-RISK-004: verified evidence required."""
        with pytest.raises(Exception):
            Mitigation(
                evidence_type="test_result",
                evidence_uri="file://localhost/evidence/test.json",
                evidence_hash="abcdef1234567890",
                # verified_by missing
                verified_at=_now_iso(),
                scope="global",
                credit=20.0,
            )

    def test_mitigation_credit_must_be_non_negative(self):
        with pytest.raises(Exception):
            Mitigation(
                evidence_type="test_result",
                evidence_uri="file://localhost/evidence/test.json",
                evidence_hash="abcdef1234567890",
                verified_by="0123456789abcdefghij",
                verified_at=_now_iso(),
                scope="global",
                credit=-10.0,
            )

    def test_mitigation_extra_fields_rejected(self):
        with pytest.raises(Exception):
            Mitigation(
                evidence_type="test_result",
                evidence_uri="file://localhost/evidence/test.json",
                evidence_hash="abcdef1234567890",
                verified_by="0123456789abcdefghij",
                verified_at=_now_iso(),
                scope="global",
                credit=20.0,
                extra_field="bad",  # type: ignore[call-arg]
            )
