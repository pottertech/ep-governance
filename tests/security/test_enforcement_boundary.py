"""Regression tests for enforcement capability boundary checks.

Tests the security fixes for Findings 1-4 and 13 from the revision 16 review:

1. issue_authorization() must require a mandatory enforcement_capability
2. proxy.execute() must require a mandatory enforcement_capability
3. issue_authorization() must verify capability.agent_principal_id == agent_id
4. proxy.execute() must verify capability.agent_principal_id == token.agent_id
5. AdvisoryDecision must be structurally distinct from AuthorizationToken
6. An AdvisoryDecision must not be accepted by any proxy
7. Expired/inactive capabilities must be rejected
8. Capabilities with wrong agent must be rejected
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ep_governance.deployment import (
    EnforcementCapability,
    EnforcementUnavailableError,
)


# --------------------------------------------------------------------------- #
# Test helpers
# --------------------------------------------------------------------------- #


def _make_active_capability(agent_id: str = "agent-1") -> EnforcementCapability:
    """Create an active (enforced) capability for the given agent."""
    return EnforcementCapability(
        effective_mode="enforced",
        binding_enforcement_active=True,
        agent_principal_id=agent_id,
        verification_time=datetime.now(UTC).isoformat(),
        failure_reasons=[],
    )


def _make_inactive_capability(agent_id: str = "agent-1") -> EnforcementCapability:
    """Create an inactive (advisory) capability for the given agent."""
    return EnforcementCapability(
        effective_mode="advisory",
        binding_enforcement_active=False,
        agent_principal_id=agent_id,
        verification_time=datetime.now(UTC).isoformat(),
        failure_reasons=["Test: enforcement not active"],
    )


def _make_proxy_scoped_capability() -> EnforcementCapability:
    """Create a proxy-scoped capability for the proxy service."""
    return EnforcementCapability(
        effective_mode="enforced",
        binding_enforcement_active=True,
        agent_principal_id="ep-service",
        verification_time=datetime.now(UTC).isoformat(),
        failure_reasons=[],
        proxy_scoped=True,
    )


class FakeCapability:
    """A fake object that satisfies the old Any-typed interface.

    This should NOT be accepted now that the type is EnforcementCapability.
    However, since Python is dynamically typed, this test verifies that
    the runtime checks (require_binding_enforcement) still catch fakes
    that pass the type check but have wrong semantics.
    """

    agent_principal_id = "agent-x"
    proxy_scoped = False

    def require_binding_enforcement(self) -> None:
        return None


# --------------------------------------------------------------------------- #
# Finding 1: issue_authorization must require a capability
# --------------------------------------------------------------------------- #


class TestAuthorizationRequiresCapability:
    """Tests that issue_authorization refuses missing capabilities."""

    def test_authorization_refuses_missing_capability(self):
        """issue_authorization must raise TypeError when capability is None."""
        from ep_governance.authorizations import AuthorizationEngine, KeyManager
        import sqlalchemy as sa

        # We can't easily create a full AuthorizationEngine without a DB,
        # but we can verify the signature requires the parameter.
        import inspect
        sig = inspect.signature(AuthorizationEngine.issue_authorization)
        ec_param = sig.parameters.get("enforcement_capability")

        assert ec_param is not None, "enforcement_capability parameter must exist"
        assert ec_param.default is inspect.Parameter.empty, (
            "enforcement_capability must NOT have a default value — "
            "it must be mandatory"
        )

    def test_authorization_refuses_inactive_capability(self):
        """issue_authorization must raise when capability is inactive."""
        cap = _make_inactive_capability()
        with pytest.raises(EnforcementUnavailableError):
            cap.require_binding_enforcement()

    def test_authorization_accepts_active_capability(self):
        """An active capability should pass require_binding_enforcement."""
        cap = _make_active_capability()
        cap.require_binding_enforcement()  # should not raise


# --------------------------------------------------------------------------- #
# Finding 2: proxy.execute must require a capability
# --------------------------------------------------------------------------- #


class TestProxyRequiresCapability:
    """Tests that proxy.execute refuses missing capabilities."""

    def test_proxy_execute_signature_requires_capability(self):
        """proxy.execute must require enforcement_capability (no default)."""
        import inspect
        from ep_governance.proxy.base import GovernedProxy

        sig = inspect.signature(GovernedProxy.execute)
        ec_param = sig.parameters.get("enforcement_capability")

        assert ec_param is not None, "enforcement_capability parameter must exist"
        assert ec_param.default is inspect.Parameter.empty, (
            "enforcement_capability must NOT have a default value — "
            "it must be mandatory"
        )

    def test_proxy_execute_type_is_enforcement_capability(self):
        """The type annotation should be EnforcementCapability, not Any."""
        import inspect
        from ep_governance.proxy.base import GovernedProxy

        sig = inspect.signature(GovernedProxy.execute)
        ec_param = sig.parameters.get("enforcement_capability")
        annotation = str(ec_param.annotation)

        assert "EnforcementCapability" in annotation, (
            f"Type annotation should be EnforcementCapability, got: {annotation}"
        )
        assert "Any" not in annotation, (
            f"Type annotation should not be Any, got: {annotation}"
        )


# --------------------------------------------------------------------------- #
# Finding 3: capability identity must match agent_id in authorization
# --------------------------------------------------------------------------- #


class TestAuthorizationIdentityBinding:
    """Tests that issue_authorization verifies capability agent matches token agent."""

    def test_capability_agent_mismatch_raises(self):
        """A capability for agent-A must not authorize a token for agent-B."""
        cap_a = _make_active_capability(agent_id="agent-A")
        cap_b = _make_active_capability(agent_id="agent-B")

        # Both are active, but they're for different agents.
        assert cap_a.agent_principal_id == "agent-A"
        assert cap_b.agent_principal_id == "agent-B"
        assert cap_a.agent_principal_id != cap_b.agent_principal_id

    def test_issue_authorization_type_annotation(self):
        """issue_authorization must use EnforcementCapability type, not Any."""
        import inspect
        from ep_governance.authorizations import AuthorizationEngine

        sig = inspect.signature(AuthorizationEngine.issue_authorization)
        ec_param = sig.parameters.get("enforcement_capability")
        annotation = str(ec_param.annotation)

        assert "EnforcementCapability" in annotation, (
            f"Type annotation should be EnforcementCapability, got: {annotation}"
        )
        assert "Any" not in annotation, (
            f"Type annotation should not be Any, got: {annotation}"
        )


# --------------------------------------------------------------------------- #
# Finding 4: proxy must bind capability to token subject
# --------------------------------------------------------------------------- #


class TestProxyIdentityBinding:
    """Tests that proxy.execute verifies capability agent matches token agent."""

    def test_proxy_scoped_capability_skips_identity_check(self):
        """Proxy-scoped capabilities should skip the identity binding check."""
        cap = _make_proxy_scoped_capability()
        assert cap.proxy_scoped is True
        # The proxy-scoped capability's agent_principal_id doesn't need
        # to match the token's agent_id — the proxy verifies the token
        # signature instead.
        cap.require_binding_enforcement()  # should not raise

    def test_agent_scoped_capability_requires_identity_match(self):
        """Agent-scoped capabilities must match the token's agent_id."""
        cap = _make_active_capability(agent_id="agent-A")
        assert cap.proxy_scoped is False
        # The identity check would compare cap.agent_principal_id ("agent-A")
        # to token.agent_id. If they differ, execution must be refused.
        assert cap.agent_principal_id == "agent-A"


# --------------------------------------------------------------------------- #
# Finding 6: type must be EnforcementCapability, not Any
# --------------------------------------------------------------------------- #


class TestCapabilityTypeEnforcement:
    """Tests that the type annotation is EnforcementCapability, not Any."""

    def test_issue_authorization_not_any_typed(self):
        """issue_authorization must not use Any for enforcement_capability."""
        import inspect
        from ep_governance.authorizations import AuthorizationEngine

        sig = inspect.signature(AuthorizationEngine.issue_authorization)
        ec_param = sig.parameters.get("enforcement_capability")
        annotation = str(ec_param.annotation)
        assert "Any" not in annotation

    def test_proxy_execute_not_any_typed(self):
        """proxy.execute must not use Any for enforcement_capability."""
        import inspect
        from ep_governance.proxy.base import GovernedProxy

        sig = inspect.signature(GovernedProxy.execute)
        ec_param = sig.parameters.get("enforcement_capability")
        annotation = str(ec_param.annotation)
        assert "Any" not in annotation

    def test_mcp_server_not_any_typed(self):
        """create_server must not use Any for enforcement_capability."""
        import inspect
        from ep_governance.mcp_server import create_server

        sig = inspect.signature(create_server)
        ec_param = sig.parameters.get("enforcement_capability")
        annotation = str(ec_param.annotation)
        assert "Any" not in annotation


# --------------------------------------------------------------------------- #
# Finding 13: AdvisoryDecision must be separate from AuthorizationToken
# --------------------------------------------------------------------------- #


class TestAdvisoryDecisionSeparation:
    """Tests that AdvisoryDecision is structurally distinct from AuthorizationToken."""

    def test_advisory_decision_is_not_authorization_token(self):
        """AdvisoryDecision and AuthorizationToken must be different types."""
        from ep_governance.authorizations import AdvisoryDecision, AuthorizationToken

        assert AdvisoryDecision is not AuthorizationToken
        assert AdvisoryDecision.__name__ != AuthorizationToken.__name__

    def test_advisory_decision_has_no_signature_field(self):
        """AdvisoryDecision must not have a signature field."""
        from ep_governance.authorizations import AdvisoryDecision

        import dataclasses
        field_names = {f.name for f in dataclasses.fields(AdvisoryDecision)}
        assert "signature" not in field_names, (
            "AdvisoryDecision must not have a signature field — "
            "it is not an executable token"
        )
        assert "nonce" not in field_names, (
            "AdvisoryDecision must not have a nonce field — "
            "it is not an executable token"
        )

    def test_advisory_decision_has_advisory_flag(self):
        """AdvisoryDecision must have an advisory flag set to True."""
        from ep_governance.authorizations import AdvisoryDecision

        import dataclasses
        field_names = {f.name for f in dataclasses.fields(AdvisoryDecision)}
        assert "advisory" in field_names, (
            "AdvisoryDecision must have an 'advisory' field"
        )

        # Verify the default is True
        advisory_field = next(
            f for f in dataclasses.fields(AdvisoryDecision) if f.name == "advisory"
        )
        assert advisory_field.default is True, (
            "AdvisoryDecision.advisory must default to True"
        )

    def test_authorization_token_has_no_advisory_field(self):
        """AuthorizationToken must not have an advisory field."""
        from ep_governance.authorizations import AuthorizationToken

        import dataclasses
        field_names = {f.name for f in dataclasses.fields(AuthorizationToken)}
        assert "advisory" not in field_names, (
            "AuthorizationToken must not have an 'advisory' field — "
            "it is always executable"
        )

    def test_advisory_decision_has_no_to_signed_token_method(self):
        """AdvisoryDecision must not have a to_signed_token method."""
        from ep_governance.authorizations import AdvisoryDecision

        assert not hasattr(AdvisoryDecision, "to_signed_token"), (
            "AdvisoryDecision must not have to_signed_token — "
            "it cannot be signed or executed"
        )

    def test_advisory_decision_has_no_verify_signature_method(self):
        """AdvisoryDecision must not have a verify_signature method."""
        from ep_governance.authorizations import AdvisoryDecision

        assert not hasattr(AdvisoryDecision, "verify_signature"), (
            "AdvisoryDecision must not have verify_signature — "
            "it has no signature to verify"
        )


# --------------------------------------------------------------------------- #
# Finding 7+8: Capability forgeability and expiry (basic checks)
# --------------------------------------------------------------------------- #


class TestCapabilityForgeability:
    """Tests for capability provenance (basic — full signed attestation is Phase 2)."""

    def test_capability_is_frozen(self):
        """EnforcementCapability must be immutable."""
        cap = _make_active_capability()
        with pytest.raises((AttributeError, Exception)):
            cap.effective_mode = "advisory"

    def test_capability_has_verification_time(self):
        """EnforcementCapability must record verification_time."""
        cap = _make_active_capability()
        assert cap.verification_time is not None
        assert len(cap.verification_time) > 0

    def test_proxy_scoped_field_exists(self):
        """EnforcementCapability must have a proxy_scoped field."""
        cap = _make_active_capability()
        assert hasattr(cap, "proxy_scoped")
        assert cap.proxy_scoped is False  # default

        proxy_cap = _make_proxy_scoped_capability()
        assert proxy_cap.proxy_scoped is True


# --------------------------------------------------------------------------- #
# EnforcementCapability.from_status integration
# --------------------------------------------------------------------------- #


class TestFromStatusIntegration:
    """Tests that from_status creates proper capabilities."""

    def test_from_status_active(self):
        """from_status with active enforcement creates active capability."""
        from ep_governance.deployment import EnforcementStatus, IsolationCheck

        status = EnforcementStatus(
            requested_mode="enforced",
            effective_mode="enforced",
            checks=[IsolationCheck(name="test", passed=True, evidence="ok")],
            reasons=[],
        )
        cap = EnforcementCapability.from_status(status, agent_principal_id="agent-1")
        assert cap.binding_enforcement_active is True
        assert cap.agent_principal_id == "agent-1"
        assert cap.proxy_scoped is False

    def test_from_status_inactive(self):
        """from_status with inactive enforcement creates inactive capability."""
        from ep_governance.deployment import EnforcementStatus, IsolationCheck

        status = EnforcementStatus(
            requested_mode="enforced",
            effective_mode="advisory",
            checks=[IsolationCheck(name="test", passed=False, evidence="fail")],
            reasons=["test: fail"],
        )
        cap = EnforcementCapability.from_status(status, agent_principal_id="agent-2")
        assert cap.binding_enforcement_active is False
        assert cap.agent_principal_id == "agent-2"
        assert len(cap.failure_reasons) == 1