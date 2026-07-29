"""Risk assessment models for EP-Governance.

Pydantic v2 models representing risk domains, mitigations, and assessments.
The :func:`assess_risk` function computes residual risk from inherent risk,
a risk increment, and verified mitigation credits.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "RiskDomain",
    "RiskDecision",
    "Mitigation",
    "RiskAssessment",
    "assess_risk",
]


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #


class RiskDomain(StrEnum):
    """The risk domain an action falls under."""

    production_database = "production_database"
    external_communications = "external_communications"
    deployment = "deployment"
    data_privacy = "data_privacy"
    security = "security"


class RiskDecision(StrEnum):
    """The risk decision derived from the residual risk vs. threshold."""

    deny = "deny"
    require_approval = "require_approval"
    warn = "warn"
    allow = "allow"


# --------------------------------------------------------------------------- #
# Models
# --------------------------------------------------------------------------- #


class Mitigation(BaseModel):
    """A verified mitigation that provides risk credit.

    Mitigations come from verified sources only — agents must NOT assign
    their own mitigation credit.  This is enforced by design: the
    ``verified_by`` and ``verified_at`` fields are required, and credit
    is only counted when the mitigation is non-expired.

    Attributes:
        evidence_type: Type of evidence (e.g. ``"test_result"``, ``"scan_report"``).
        evidence_uri:  URI to the evidence artifact.
        evidence_hash: Hash of the evidence artifact (for integrity).
        verified_by:   XID of the principal that verified this mitigation.
        verified_at:   ISO 8601 UTC timestamp of verification.
        expires_at:    Optional expiry timestamp; expired mitigations
                       contribute 0 credit.
        scope:          Scope of the mitigation (e.g. ``"global"``, ``"project:xxx"``).
        credit:        Risk credit provided by this mitigation (0–100).
    """

    model_config = ConfigDict(use_enum_values=True, validate_assignment=True, extra="forbid")

    evidence_type: str = Field(..., description="Type of evidence.")
    evidence_uri: str = Field(..., description="URI to the evidence artifact.")
    evidence_hash: str = Field(..., description="Hash of the evidence artifact.")
    verified_by: str = Field(..., description="XID of the verifying principal.")
    verified_at: str = Field(..., description="ISO 8601 UTC timestamp of verification.")
    expires_at: str | None = Field(default=None, description="Optional expiry timestamp.")
    scope: str = Field(..., description="Scope of the mitigation.")
    credit: float = Field(..., ge=0, description="Risk credit (0–100).")


class RiskAssessment(BaseModel):
    """The result of a risk assessment.

    Attributes:
        domain:            The risk domain assessed.
        risk_increment:    Additional risk introduced by the action.
        inherent_risk:     The base risk of the domain/action before mitigation.
        mitigation_credit: Total credit from valid (non-expired) mitigations.
        residual_risk:     ``max(0, inherent_risk + risk_increment - mitigation_credit)``.
        threshold:         The decision threshold for the domain.
        decision:          The resulting :class:`RiskDecision`.
        accepted_by:       XID of the principal that accepted the risk, if any.
        accepted_at:       Timestamp of acceptance, if any.
        expiration:        When the acceptance expires, if any.
    """

    model_config = ConfigDict(use_enum_values=True, validate_assignment=True, extra="forbid")

    domain: RiskDomain = Field(..., description="The risk domain.")
    risk_increment: float = Field(..., description="Additional risk from the action.")
    inherent_risk: float = Field(..., description="Base risk before mitigation.")
    mitigation_credit: float = Field(..., description="Total credit from valid mitigations.")
    residual_risk: float = Field(..., description="Residual risk after mitigation.")
    threshold: float = Field(..., description="Decision threshold.")
    decision: RiskDecision = Field(..., description="Resulting decision.")
    accepted_by: str | None = Field(default=None, description="Accepting principal XID.")
    accepted_at: str | None = Field(default=None, description="Acceptance timestamp.")
    expiration: str | None = Field(default=None, description="Acceptance expiry.")


# --------------------------------------------------------------------------- #
# Assessment function
# --------------------------------------------------------------------------- #


def _now_iso() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _is_expired(expires_at: str | None, now: str | None = None) -> bool:
    """Return True if *expires_at* is in the past relative to *now*."""
    if expires_at is None:
        return False
    cmp_now = (now or _now_iso()).rstrip("Z")
    cmp_exp = expires_at.rstrip("Z")
    return cmp_exp < cmp_now


def assess_risk(
    domain: RiskDomain,
    inherent_risk: float,
    threshold: float,
    mitigations: list[Mitigation],
    risk_increment: float,
    *,
    now: str | None = None,
) -> RiskAssessment:
    """Assess risk for a proposed action.

    The calculation:

    1. ``mitigation_credit`` = sum of credit from non-expired mitigations.
    2. ``residual_risk`` = ``max(0.0, inherent_risk + risk_increment - mitigation_credit)``.
    3. Decision:
       - If ``inherent_risk >= 90`` AND ``residual_risk >= 80`` → ``deny``.
       - If ``residual_risk > threshold`` → ``require_approval``.
       - If ``residual_risk > threshold * 0.8`` → ``warn``.
       - Otherwise → ``allow``.

    Expired mitigations (``expires_at < now``) contribute **0** credit.
    Agents must NOT assign their own mitigation credit — mitigations come
    from verified sources only.

    Args:
        domain:         The risk domain.
        inherent_risk:  Base risk before mitigation (0–100).
        threshold:      Decision threshold for the domain (0–100).
        mitigations:    List of verified mitigations.
        risk_increment: Additional risk from the proposed action.
        now:            Optional current timestamp for expiry checks.

    Returns:
        A :class:`RiskAssessment`.
    """
    # Calculate mitigation credit from non-expired mitigations
    mitigation_credit = 0.0
    for mit in mitigations:
        if _is_expired(mit.expires_at, now):
            continue
        mitigation_credit += mit.credit

    # Residual risk
    residual = inherent_risk + risk_increment - mitigation_credit
    residual = max(0.0, residual)

    # Decision
    if inherent_risk >= 90.0 and residual >= 80.0:
        decision = RiskDecision.deny
    elif residual > threshold:
        decision = RiskDecision.require_approval
    elif residual > threshold * 0.8:
        decision = RiskDecision.warn
    else:
        decision = RiskDecision.allow

    return RiskAssessment(
        domain=domain,
        risk_increment=risk_increment,
        inherent_risk=inherent_risk,
        mitigation_credit=mitigation_credit,
        residual_risk=residual,
        threshold=threshold,
        decision=decision,
    )
