"""Shared fixtures for EP-Governance tests."""

import pytest


@pytest.fixture
def sample_xid():
    """A valid 20-char base32hex XID for testing."""
    return "cjvbbvh6qgtnoiaaa001"


@pytest.fixture
def sample_xid_2():
    return "cjvbbvh6qgtnoiaaa002"


@pytest.fixture
def genesis_hash():
    """The all-zeros hash used as previous_hash for the first audit event in a chain."""
    return "0" * 64


@pytest.fixture
def sample_policy():
    """A valid policy dictionary matching schemas/policy.schema.json."""
    return {
        "id": "cjvbbzh6qgtnoxiaa001",
        "effect": "deny",
        "actions": ["db.drop", "db.delete"],
        "resources": ["postgres://cloudhub/gbrain_pilot/**"],
        "conditions": {},
        "priority": 100,
        "scope": "global",
        "agent_scope": None,
        "description": "Never delete production gbrain_pilot data",
        "status": "active",
        "created_by": "cjvbbzh6qgtnoxiaa010",
        "approved_by": "cjvbbzh6qgtnoxiaa011",
        "approved_at": "2026-07-28T12:00:00.000000Z",
        "activation_version": 1,
        "exception_to": [],
        "valid_from": "2026-07-28T12:00:00.000000Z",
        "valid_until": None,
        "justification": None,
    }


@pytest.fixture
def sample_risk_assessment():
    """A valid risk assessment matching schemas/risk-assessment.schema.json."""
    return {
        "domain": "deployment",
        "risk_increment": 25.0,
        "inherent_risk": 80.0,
        "mitigation_credit": 25.0,
        "residual_risk": 55.0,
        "threshold": 50.0,
        "decision": "require_approval",
        "accepted_by": None,
        "accepted_at": None,
        "expiration": None,
    }


@pytest.fixture
def sample_authorization_token():
    """A valid authorization token matching schemas/authorization.schema.json."""
    return {
        "authorization_id": "cjvbbzh6qgtnoxiaa002",
        "transition_id": "cjvbbzh6qgtnoxiaa003",
        "agent_id": "cjvbbzh6qgtnoxiaa004",
        "project_id": "cjvbbzh6qgtnoxiaa005",
        "branch_id": "cjvbbzh6qgtnoxiaa006",
        "proxy_audience": "postgres-proxy",
        "tool": "postgres.execute",
        "payload_hash": "sha256:" + "a" * 64,
        "policy_set_hash": "sha256:" + "b" * 64,
        "matched_policy_versions": {"cjvbbzh6qgtnoxiaa001": 1},
        "issued_at": "2026-07-28T12:00:00.000000Z",
        "expires_at": "2026-07-28T12:05:00.000000Z",
        "nonce": "random-nonce-value-12345",
        "signature": "ed25519:" + "c" * 128,
    }
