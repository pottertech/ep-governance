"""Negative tests for EnforcementCapability.from_signed_attestation validation.

Tests that the attestation parser correctly rejects:
- Missing supported_action_types
- Empty or malformed action lists
- Empty action names
- Duplicate action types
- Advisory effective_mode
- String values instead of booleans
- Non-proxy scope
- Incorrect proxy identity
- Missing identifier fields
- Future issuance
- Expiration before issuance
- Excessive lifetime
- Missing timezone in timestamps
- Exact expiration rejected
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from ep_governance.deployment import EnforcementCapability, EnforcementUnavailableError


def _make_valid_attestation_data(**overrides) -> dict:
    """Create a valid attestation data dict with optional overrides."""
    now = datetime.now(UTC)
    data = {
        "effective_mode": "enforced",
        "binding_enforcement_active": True,
        "agent_principal_id": "proxy",
        "proxy_scoped": True,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=1800)).isoformat(),
        "proxy_principal_id": "proxy-001",
        "proxy_audience": "postgres-proxy",
        "deployment_id": "dep-001",
        "target_id": "target-001",
        "supported_action_types": ["postgres.execute"],
        "signature": "deadbeef",
    }
    data.update(overrides)
    return data


def _make_signed_attestation(data: dict, signer=None) -> str:
    """Create a signed attestation JSON string.

    If signer is provided, it signs the canonical payload.
    Otherwise, it uses a mock signature that will pass verification
    with a mock key.
    """
    if signer is not None:
        from ep_governance.canonical import canonical_json_bytes
        payload = {k: v for k, v in data.items() if k != "signature"}
        message = canonical_json_bytes(payload)
        sig = signer.sign(message)
        data["signature"] = sig.signature.hex()
    return json.dumps(data, default=str)


def _mock_verify_key():
    """Create a mock VerifyKey that accepts any signature."""
    mock = MagicMock()
    mock.verify = MagicMock(return_value=None)
    return mock


class TestAttestationActionTypes:
    """Tests for supported_action_types validation."""

    def test_missing_supported_action_types_rejected(self):
        data = _make_valid_attestation_data()
        del data["supported_action_types"]
        attestation = _make_signed_attestation(data)
        with pytest.raises(EnforcementUnavailableError, match="missing required fields"):
            EnforcementCapability.from_signed_attestation(attestation, _mock_verify_key())

    def test_empty_list_rejected(self):
        data = _make_valid_attestation_data(supported_action_types=[])
        attestation = _make_signed_attestation(data)
        with pytest.raises(EnforcementUnavailableError, match="nonempty list"):
            EnforcementCapability.from_signed_attestation(attestation, _mock_verify_key())

    def test_non_list_rejected(self):
        data = _make_valid_attestation_data(supported_action_types="postgres.execute")
        attestation = _make_signed_attestation(data)
        with pytest.raises(EnforcementUnavailableError, match="nonempty list"):
            EnforcementCapability.from_signed_attestation(attestation, _mock_verify_key())

    def test_empty_string_in_list_rejected(self):
        data = _make_valid_attestation_data(supported_action_types=["postgres.execute", ""])
        attestation = _make_signed_attestation(data)
        with pytest.raises(EnforcementUnavailableError, match="invalid entries"):
            EnforcementCapability.from_signed_attestation(attestation, _mock_verify_key())

    def test_duplicate_entries_rejected(self):
        data = _make_valid_attestation_data(
            supported_action_types=["postgres.execute", "postgres.execute"]
        )
        attestation = _make_signed_attestation(data)
        with pytest.raises(EnforcementUnavailableError, match="duplicates"):
            EnforcementCapability.from_signed_attestation(attestation, _mock_verify_key())

    def test_valid_unique_entries_accepted(self):
        data = _make_valid_attestation_data(
            supported_action_types=["postgres.execute", "shell.exec"]
        )
        attestation = _make_signed_attestation(data)
        cap = EnforcementCapability.from_signed_attestation(attestation, _mock_verify_key())
        assert cap.supports_action_type("postgres.execute")
        assert cap.supports_action_type("shell.exec")


class TestAttestationSemanticValidation:
    """Tests for strict field validation."""

    def test_advisory_effective_mode_rejected(self):
        data = _make_valid_attestation_data(effective_mode="advisory")
        attestation = _make_signed_attestation(data)
        with pytest.raises(EnforcementUnavailableError, match="effective_mode"):
            EnforcementCapability.from_signed_attestation(attestation, _mock_verify_key())

    def test_string_true_rejected(self):
        data = _make_valid_attestation_data(binding_enforcement_active="true")
        attestation = _make_signed_attestation(data)
        with pytest.raises(EnforcementUnavailableError, match="binding_enforcement_active"):
            EnforcementCapability.from_signed_attestation(attestation, _mock_verify_key())

    def test_string_false_for_proxy_scoped_rejected(self):
        data = _make_valid_attestation_data(proxy_scoped="false")
        attestation = _make_signed_attestation(data)
        with pytest.raises(EnforcementUnavailableError, match="proxy_scoped"):
            EnforcementCapability.from_signed_attestation(attestation, _mock_verify_key())

    def test_non_proxy_agent_id_rejected(self):
        data = _make_valid_attestation_data(agent_principal_id="agent-001")
        attestation = _make_signed_attestation(data)
        with pytest.raises(EnforcementUnavailableError, match="agent_principal_id"):
            EnforcementCapability.from_signed_attestation(attestation, _mock_verify_key())

    def test_empty_proxy_principal_id_rejected(self):
        data = _make_valid_attestation_data(proxy_principal_id="")
        attestation = _make_signed_attestation(data)
        with pytest.raises(EnforcementUnavailableError, match="nonempty string"):
            EnforcementCapability.from_signed_attestation(attestation, _mock_verify_key())

    def test_empty_deployment_id_rejected(self):
        data = _make_valid_attestation_data(deployment_id="")
        attestation = _make_signed_attestation(data)
        with pytest.raises(EnforcementUnavailableError, match="nonempty string"):
            EnforcementCapability.from_signed_attestation(attestation, _mock_verify_key())


class TestAttestationTimestamps:
    """Tests for timestamp validation."""

    def test_missing_timezone_rejected(self):
        now = datetime.now(UTC)
        data = _make_valid_attestation_data(
            issued_at=now.replace(tzinfo=None).isoformat(),
            expires_at=(now + timedelta(seconds=1800)).replace(tzinfo=None).isoformat(),
        )
        attestation = _make_signed_attestation(data)
        with pytest.raises(EnforcementUnavailableError, match="timezone"):
            EnforcementCapability.from_signed_attestation(attestation, _mock_verify_key())

    def test_expired_attestation_rejected(self):
        past = datetime.now(UTC) - timedelta(seconds=3600)
        data = _make_valid_attestation_data(
            issued_at=past.isoformat(),
            expires_at=(past + timedelta(seconds=1800)).isoformat(),
        )
        attestation = _make_signed_attestation(data)
        with pytest.raises(EnforcementUnavailableError, match="expired"):
            EnforcementCapability.from_signed_attestation(attestation, _mock_verify_key())

    def test_future_issuance_rejected(self):
        future = datetime.now(UTC) + timedelta(seconds=600)
        data = _make_valid_attestation_data(
            issued_at=future.isoformat(),
            expires_at=(future + timedelta(seconds=1800)).isoformat(),
        )
        attestation = _make_signed_attestation(data)
        with pytest.raises(EnforcementUnavailableError, match="future"):
            EnforcementCapability.from_signed_attestation(attestation, _mock_verify_key())

    def test_expiration_before_issuance_rejected(self):
        now = datetime.now(UTC)
        data = _make_valid_attestation_data(
            issued_at=(now + timedelta(seconds=1800)).isoformat(),
            expires_at=now.isoformat(),
        )
        attestation = _make_signed_attestation(data)
        with pytest.raises(EnforcementUnavailableError, match="after issued_at|expired"):
            EnforcementCapability.from_signed_attestation(attestation, _mock_verify_key())

    def test_excessive_lifetime_rejected(self):
        now = datetime.now(UTC)
        data = _make_valid_attestation_data(
            issued_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=7200)).isoformat(),  # 2 hours
        )
        attestation = _make_signed_attestation(data)
        with pytest.raises(EnforcementUnavailableError, match="lifetime"):
            EnforcementCapability.from_signed_attestation(attestation, _mock_verify_key())

    def test_valid_attestation_accepted(self):
        """A properly formed attestation should be accepted."""
        data = _make_valid_attestation_data()
        attestation = _make_signed_attestation(data)
        cap = EnforcementCapability.from_signed_attestation(attestation, _mock_verify_key())
        assert cap.effective_mode == "enforced"
        assert cap.binding_enforcement_active is True
        assert cap.proxy_scoped is True
        assert cap.trust_level == "signed_attestation"
        assert cap.proxy_audience == "postgres-proxy"
        assert cap.deployment_id == "dep-001"
        assert cap.supports_action_type("postgres.execute")


class TestAttestationRealSignatures:
    """Tests using real PyNaCl signing and verification keys."""

    def test_valid_signed_attestation_accepted(self):
        from nacl.signing import SigningKey
        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key

        data = _make_valid_attestation_data()
        attestation = _make_signed_attestation(data, signer=signing_key)
        cap = EnforcementCapability.from_signed_attestation(attestation, verify_key)
        assert cap is not None
        assert cap.trust_level == "signed_attestation"

    def test_modified_field_rejected(self):
        from nacl.signing import SigningKey
        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key

        data = _make_valid_attestation_data()
        attestation = _make_signed_attestation(data, signer=signing_key)

        # Tamper with the attestation after signing
        tampered = json.loads(attestation)
        tampered["target_id"] = "wrong-target"
        tampered_attestation = json.dumps(tampered)

        with pytest.raises(EnforcementUnavailableError, match="signature"):
            EnforcementCapability.from_signed_attestation(tampered_attestation, verify_key)

    def test_wrong_verify_key_rejected(self):
        from nacl.signing import SigningKey
        signing_key = SigningKey.generate()
        wrong_key = SigningKey.generate().verify_key

        data = _make_valid_attestation_data()
        attestation = _make_signed_attestation(data, signer=signing_key)

        with pytest.raises(EnforcementUnavailableError, match="signature"):
            EnforcementCapability.from_signed_attestation(attestation, wrong_key)

    def test_malformed_hex_signature_rejected(self):
        data = _make_valid_attestation_data(signature="not-valid-hex")
        attestation = json.dumps(data)
        with pytest.raises(EnforcementUnavailableError, match="signature"):
            EnforcementCapability.from_signed_attestation(attestation, _mock_verify_key())