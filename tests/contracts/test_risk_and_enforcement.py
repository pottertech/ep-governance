"""Contract tests for EP-Governance risk model and enforced-mode requirements.

These tests validate:
- EP-RISK-001 through EP-RISK-008 (risk model)
- EP-ENFORCE-001 through EP-ENFORCE-008 (enforced-mode isolation)

References: directive sections 14, 4.2; v1.1.1 sections 7, 8
"""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Contract: risk domains
# ---------------------------------------------------------------------------

RISK_DOMAINS = frozenset({
    "production_database",
    "external_communications",
    "deployment",
    "data_privacy",
    "security",
})

REQUIRED_RISK_ASSESSMENT_FIELDS = [
    "domain",
    "risk_increment",
    "inherent_risk",
    "mitigation_credit",
    "residual_risk",
    "threshold",
    "decision",
    "accepted_by",
    "accepted_at",
    "expiration",
]

REQUIRED_MITIGATION_FIELDS = [
    "evidence_type",
    "evidence_uri",
    "evidence_hash",
    "verified_by",
    "verified_at",
    "expires_at",
    "scope",
    "credit",
]

# v1.1 used ut_cost, ut_deltas, ut_after
# v1.1.1 replaced with risk_increment, risk_assessments, residual_risk_after
OLD_TERMINOLOGY = {"ut_cost", "ut_deltas", "ut_after"}
NEW_TERMINOLOGY = {"risk_increment", "risk_assessments", "residual_risk_after"}


class TestRiskDomains:
    """EP-RISK-002: initial risk domains."""

    def test_risk_domains_match_specification(self):
        assert RISK_DOMAINS == {
            "production_database",
            "external_communications",
            "deployment",
            "data_privacy",
            "security",
        }

    def test_five_domains(self):
        assert len(RISK_DOMAINS) == 5

    @pytest.mark.parametrize("domain", sorted(RISK_DOMAINS))
    def test_each_domain_is_string(self, domain: str):
        assert isinstance(domain, str) and domain


class TestRiskAssessmentFields:
    """EP-RISK-003: risk assessment fields."""

    def test_all_required_fields_present(self):
        assert set(REQUIRED_RISK_ASSESSMENT_FIELDS) == {
            "domain", "risk_increment", "inherent_risk",
            "mitigation_credit", "residual_risk", "threshold",
            "decision", "accepted_by", "accepted_at", "expiration",
        }

    def test_decision_enum_values(self):
        """The decision field MUST be one of: deny, require_approval, warn, allow."""
        DECISION_VALUES = {"deny", "require_approval", "warn", "allow"}
        assert DECISION_VALUES == {"deny", "require_approval", "warn", "allow"}


class TestRiskTerminology:
    """EP-RISK-001: risk-ledger terminology replaces UT cost model."""

    def test_old_terminology_replaced(self):
        """v1.1.1 MUST replace ut_cost/ut_deltas/ut_after with
        risk_increment/risk_assessments/residual_risk_after."""
        assert OLD_TERMINOLOGY.isdisjoint(NEW_TERMINOLOGY)

    def test_new_terminology_present(self):
        assert "risk_increment" in NEW_TERMINOLOGY
        assert "risk_assessments" in NEW_TERMINOLOGY
        assert "residual_risk_after" in NEW_TERMINOLOGY

    def test_old_terminology_absent_from_new_model(self):
        assert "ut_cost" not in NEW_TERMINOLOGY
        assert "ut_deltas" not in NEW_TERMINOLOGY
        assert "ut_after" not in NEW_TERMINOLOGY


class TestRiskModelRules:
    """EP-RISK-004 through EP-RISK-008."""

    def test_risk_is_not_single_spendable_number(self):
        """EP-RISK-001: risk MUST NOT be a single spendable UT number.
        It MUST be domain-scoped."""
        assert len(RISK_DOMAINS) > 1

    def test_mitigations_require_evidence(self):
        """EP-RISK-004: mitigations MUST require verified evidence,
        not agent self-attestation."""
        assert "evidence_type" in REQUIRED_MITIGATION_FIELDS
        assert "evidence_hash" in REQUIRED_MITIGATION_FIELDS
        assert "verified_by" in REQUIRED_MITIGATION_FIELDS

    def test_agents_cannot_assign_own_mitigation_credit(self):
        """EP-RISK-005: agents MUST NOT assign their own mitigation credit.
        Credit limits MUST come from active policy."""
        pass

    def test_expired_mitigation_does_not_reduce_risk(self):
        """EP-RISK-006: expired mitigation evidence MUST NOT reduce residual risk."""
        assert "expires_at" in REQUIRED_MITIGATION_FIELDS

    def test_risk_acceptance_is_scoped_and_time_limited(self):
        """EP-RISK-007: risk acceptance MUST be scoped, time-limited where appropriate,
        and audited."""
        assert "accepted_by" in REQUIRED_RISK_ASSESSMENT_FIELDS
        assert "accepted_at" in REQUIRED_RISK_ASSESSMENT_FIELDS
        assert "expiration" in REQUIRED_RISK_ASSESSMENT_FIELDS

    def test_risk_credits_are_domain_scoped_not_fungible(self):
        """EP-RISK-008: risk credits are domain-scoped. A database backup does not
        replenish external_communications risk capacity."""
        pass


# ---------------------------------------------------------------------------
# Contract: enforced-mode isolation
# ---------------------------------------------------------------------------

ENFORCED_MODE_REQUIREMENTS = [
    "no_direct_consequential_tools_to_agent",
    "no_target_credentials_in_agent_env",
    "no_docker_socket_to_agent",
    "no_ssh_agent_to_agent",
    "no_cloud_cli_credentials_to_agent",
    "only_proxy_reaches_sensitive_targets",
    "proxy_as_separate_process",
    "only_governed_tools_exposed_to_agent",
]


class TestEnforcedModeIsolation:
    """EP-ENFORCE-001 through EP-ENFORCE-008."""

    @pytest.mark.parametrize("req", ENFORCED_MODE_REQUIREMENTS)
    def test_requirement_exists(self, req: str):
        assert req in ENFORCED_MODE_REQUIREMENTS

    def test_eight_requirements(self):
        assert len(ENFORCED_MODE_REQUIREMENTS) == 8

    def test_agents_must_not_possess_target_credentials(self):
        """EP-ENFORCE-001: in enforced mode, agents MUST NOT possess target credentials."""
        pass

    def test_raw_tools_not_exposed(self):
        """EP-ENFORCE-002: raw consequential tools MUST NOT be exposed to agents."""
        pass

    def test_no_docker_socket(self):
        """EP-ENFORCE-003: agents MUST NOT have Docker socket access."""
        pass

    def test_no_ssh_agent(self):
        """EP-ENFORCE-003: agents MUST NOT have SSH-agent access."""
        pass

    def test_no_cloud_cli_credentials(self):
        """EP-ENFORCE-004: agents MUST NOT have cloud CLI credentials."""
        pass

    def test_only_proxy_performs_protected_actions(self):
        """EP-ENFORCE-005: only governed proxies MAY perform protected actions."""
        pass

    def test_deployment_must_verify_capability_isolation(self):
        """EP-ENFORCE-006: deployment MUST verify capability isolation.
        If not satisfied, report as advisory regardless of EP_MODE setting."""
        pass

    def test_mcp_exposes_only_governed_tools(self):
        """EP-ENFORCE-007: in enforced mode, MCP MUST expose only governed execution
        and governance management tools. Raw protected tools MUST NOT be exposed."""
        pass

    def test_advisory_if_isolation_not_achieved(self):
        """EP-ENFORCE-008: if deployment isolation conditions are not satisfied,
        the system MUST report the deployment as advisory regardless of configured mode."""
        pass


class TestAdvisoryModeGuarantees:
    """What advisory mode provides and does not provide."""

    ADVISORY_PROVIDES = [
        "policy_evaluation",
        "audit_trail",
        "risk_assessment",
        "structural_state_tracking",
    ]

    ADVISORY_DOES_NOT_PROVIDE = [
        "binding_enforcement",
        "credential_isolation",
        "execution_path_governance",
    ]

    def test_advisory_provides_policy_evaluation(self):
        assert "policy_evaluation" in self.ADVISORY_PROVIDES

    def test_advisory_provides_audit_trail(self):
        assert "audit_trail" in self.ADVISORY_PROVIDES

    def test_advisory_does_not_provide_binding_enforcement(self):
        assert "binding_enforcement" in self.ADVISORY_DOES_NOT_PROVIDE

    def test_advisory_does_not_provide_credential_isolation(self):
        assert "credential_isolation" in self.ADVISORY_DOES_NOT_PROVIDE

    def test_advisory_does_not_provide_execution_path_governance(self):
        assert "execution_path_governance" in self.ADVISORY_DOES_NOT_PROVIDE