"""Tests for proxy startup attestation binding requirements.

Tests that load_proxy_capability() correctly:
- Requires all four binding variables
- Rejects missing bindings with SystemExit
- Rejects whitespace-only values
- Accepts all four configured values (when attestation is valid)
- Does not consult EP_PRODUCTION_MODE
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from ep_governance.deployment import EnforcementCapability


def _make_valid_attestation_data() -> dict:
    now = datetime.now(UTC)
    return {
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


def _mock_verify_key():
    mock = MagicMock()
    mock.verify = MagicMock(return_value=None)
    return mock


class TestProxyBindingRequirements:
    """Tests for mandatory binding enforcement in load_proxy_capability()."""

    def test_missing_proxy_principal_id_exits(self, monkeypatch, tmp_path):
        """Missing EP_PROXY_PRINCIPAL_ID should cause startup failure."""
        from ep_governance.proxy_service import load_proxy_capability, ProxyConfigurationError
        monkeypatch.setenv("EP_PROXY_AUDIENCE", "postgres-proxy")
        monkeypatch.setenv("EP_DEPLOYMENT_ID", "dep-001")
        monkeypatch.setenv("EP_PROXY_TARGET_ID", "target-001")
        monkeypatch.delenv("EP_PROXY_PRINCIPAL_ID", raising=False)
        monkeypatch.setenv("EP_PROXY_ATTESTATION_PATH", str(tmp_path / "attestation.json"))
        monkeypatch.setenv("EP_CONTROLLER_PUBLIC_KEY", "abcd1234")
        with pytest.raises(ProxyConfigurationError):
            load_proxy_capability("postgres-proxy")

    def test_missing_deployment_id_exits(self, monkeypatch, tmp_path):
        """Missing EP_DEPLOYMENT_ID should cause startup failure."""
        from ep_governance.proxy_service import load_proxy_capability, ProxyConfigurationError
        monkeypatch.setenv("EP_PROXY_AUDIENCE", "postgres-proxy")
        monkeypatch.setenv("EP_PROXY_PRINCIPAL_ID", "proxy-001")
        monkeypatch.setenv("EP_PROXY_TARGET_ID", "target-001")
        monkeypatch.delenv("EP_DEPLOYMENT_ID", raising=False)
        monkeypatch.setenv("EP_PROXY_ATTESTATION_PATH", str(tmp_path / "attestation.json"))
        monkeypatch.setenv("EP_CONTROLLER_PUBLIC_KEY", "abcd1234")
        with pytest.raises(ProxyConfigurationError):
            load_proxy_capability("postgres-proxy")

    def test_missing_target_id_exits(self, monkeypatch, tmp_path):
        """Missing EP_PROXY_TARGET_ID should cause startup failure."""
        from ep_governance.proxy_service import load_proxy_capability, ProxyConfigurationError
        monkeypatch.setenv("EP_PROXY_AUDIENCE", "postgres-proxy")
        monkeypatch.setenv("EP_PROXY_PRINCIPAL_ID", "proxy-001")
        monkeypatch.setenv("EP_DEPLOYMENT_ID", "dep-001")
        monkeypatch.delenv("EP_PROXY_TARGET_ID", raising=False)
        monkeypatch.setenv("EP_PROXY_ATTESTATION_PATH", str(tmp_path / "attestation.json"))
        monkeypatch.setenv("EP_CONTROLLER_PUBLIC_KEY", "abcd1234")
        with pytest.raises(ProxyConfigurationError):
            load_proxy_capability("postgres-proxy")

    def test_missing_audience_exits(self, monkeypatch, tmp_path):
        """Missing EP_PROXY_AUDIENCE should cause startup failure."""
        from ep_governance.proxy_service import load_proxy_capability, ProxyConfigurationError
        monkeypatch.setenv("EP_PROXY_PRINCIPAL_ID", "proxy-001")
        monkeypatch.setenv("EP_DEPLOYMENT_ID", "dep-001")
        monkeypatch.setenv("EP_PROXY_TARGET_ID", "target-001")
        monkeypatch.delenv("EP_PROXY_AUDIENCE", raising=False)
        monkeypatch.setenv("EP_PROXY_ATTESTATION_PATH", str(tmp_path / "attestation.json"))
        monkeypatch.setenv("EP_CONTROLLER_PUBLIC_KEY", "abcd1234")
        with pytest.raises(ProxyConfigurationError):
            load_proxy_capability("postgres-proxy")

    def test_whitespace_only_values_rejected(self, monkeypatch, tmp_path):
        """Whitespace-only values should be treated as missing."""
        from ep_governance.proxy_service import load_proxy_capability, ProxyConfigurationError
        monkeypatch.setenv("EP_PROXY_AUDIENCE", "postgres-proxy")
        monkeypatch.setenv("EP_PROXY_PRINCIPAL_ID", "   ")
        monkeypatch.setenv("EP_DEPLOYMENT_ID", "dep-001")
        monkeypatch.setenv("EP_PROXY_TARGET_ID", "target-001")
        monkeypatch.setenv("EP_PROXY_ATTESTATION_PATH", str(tmp_path / "attestation.json"))
        monkeypatch.setenv("EP_CONTROLLER_PUBLIC_KEY", "abcd1234")
        with pytest.raises(ProxyConfigurationError):
            load_proxy_capability("postgres-proxy")

    def test_does_not_consult_ep_production_mode(self, monkeypatch, tmp_path):
        """EP_PRODUCTION_MODE should not affect binding enforcement."""
        from ep_governance.proxy_service import load_proxy_capability, ProxyConfigurationError
        # Set EP_PRODUCTION_MODE=false but omit bindings -- should still fail
        monkeypatch.setenv("EP_PRODUCTION_MODE", "false")
        monkeypatch.delenv("EP_PROXY_PRINCIPAL_ID", raising=False)
        monkeypatch.setenv("EP_PROXY_AUDIENCE", "postgres-proxy")
        monkeypatch.setenv("EP_DEPLOYMENT_ID", "dep-001")
        monkeypatch.setenv("EP_PROXY_TARGET_ID", "target-001")
        monkeypatch.setenv("EP_PROXY_ATTESTATION_PATH", str(tmp_path / "attestation.json"))
        monkeypatch.setenv("EP_CONTROLLER_PUBLIC_KEY", "abcd1234")
        with pytest.raises(ProxyConfigurationError):
            load_proxy_capability("postgres-proxy")

    def test_all_four_bindings_present_proceeds(self, monkeypatch, tmp_path):
        """All four bindings present with a valid signed attestation should succeed."""
        from nacl.signing import SigningKey
        from ep_governance.proxy_service import load_proxy_capability, ProxyConfigurationError
        from ep_governance.canonical import canonical_json_bytes

        # Generate a real controller signing key
        signing_key = SigningKey.generate()
        verify_key_hex = bytes(signing_key.verify_key).hex()

        # Create a valid signed attestation
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
        }
        # Sign the attestation
        payload = {k: v for k, v in data.items() if k != "signature"}
        message = canonical_json_bytes(payload)
        signature = signing_key.sign(message).signature.hex()
        data["signature"] = signature

        attestation_path = tmp_path / "attestation.json"
        attestation_path.write_text(json.dumps(data))

        # Set all required env vars
        monkeypatch.setenv("EP_PROXY_AUDIENCE", "postgres-proxy")
        monkeypatch.setenv("EP_PROXY_PRINCIPAL_ID", "proxy-001")
        monkeypatch.setenv("EP_DEPLOYMENT_ID", "dep-001")
        monkeypatch.setenv("EP_PROXY_TARGET_ID", "target-001")
        monkeypatch.setenv("EP_PROXY_ATTESTATION_PATH", str(attestation_path))
        monkeypatch.setenv("EP_CONTROLLER_PUBLIC_KEY", verify_key_hex)

        # This should succeed and return a real capability
        capability = load_proxy_capability("postgres-proxy")
        assert capability is not None
        assert capability.proxy_principal_id == "proxy-001"
        assert capability.deployment_id == "dep-001"
        assert capability.target_id == "target-001"
        assert capability.proxy_audience == "postgres-proxy"
        assert capability.trust_level == "signed_attestation"