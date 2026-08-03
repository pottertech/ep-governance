"""Comprehensive tests for the EP-Governance deployment verification module.

These tests exercise the enforcement-attestation layer that verifies
deployment isolation conditions before allowing enforced mode.  No real
files, network, Docker, or SSH agent are required — everything is mocked.
"""

from __future__ import annotations

import io
from unittest.mock import MagicMock, mock_open, patch

import pytest

from ep_governance.deployment import (
    EnforcementAttestation,
    EnforcementStatus,
    EnforcementUnavailableError,
    IsolationCheck,
    check_agent_tool_manifest,
    check_runtime_environment,
    format_enforcement_report,
    verify_deployment,
    _load_attestation_from_env,
    _check_proxy_health,
)
from ep_governance.deployment import (
    _CREDENTIAL_ENV_VARS,
    _CLOUD_CREDENTIAL_ENV_VARS,
    _CREDENTIAL_FILE_PATHS,
    _RAW_TOOLS,
    _ASSERTION_VARS,
)
from ep_governance.errors import EPError


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _full_attestation() -> EnforcementAttestation:
    """Return an attestation with every assertion set to True."""
    return EnforcementAttestation(
        proxy_separate_process=True,
        proxy_identity_verified=True,
        agent_has_no_target_credentials=True,
        agent_has_no_docker_socket=True,
        agent_has_no_ssh_agent=True,
        agent_has_no_cloud_credentials=True,
        raw_tools_removed=True,
        target_network_restricted_to_proxy=True,
        proxy_health_verified=True,
    )


def _clean_env() -> dict[str, str]:
    """Return an environment with no credential vars / SSH agent."""
    return {"PATH": "/usr/bin:/bin"}


def _mock_no_files(monkeypatch):
    """Make os.path.exists return False for all credential paths."""
    real_exists = __import__("os").path.exists

    def _fake_exists(path: str) -> bool:
        if path in _CREDENTIAL_FILE_PATHS:
            return False
        return real_exists(path)

    monkeypatch.setattr("os.path.exists", _fake_exists)


# --------------------------------------------------------------------------- #
# Test 1: Advisory mode requested -> effective_mode advisory, no checks
# --------------------------------------------------------------------------- #


def test_advisory_mode_requested_returns_advisory_no_checks(monkeypatch):
    """Advisory mode short-circuits — no isolation checks are run."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://evil")
    _mock_no_files(monkeypatch)
    status = verify_deployment("advisory", env={"DATABASE_URL": "postgresql://evil"})
    assert status.requested_mode == "advisory"
    assert status.effective_mode == "advisory"
    assert status.checks == []
    assert "Advisory mode requested" in status.reasons[0]


# --------------------------------------------------------------------------- #
# Test 2: Enforced mode with no attestation -> downgrades to advisory
# --------------------------------------------------------------------------- #


def test_enforced_mode_no_attestation_downgrades_to_advisory(monkeypatch):
    """With a default (all-False) attestation, enforced mode cannot hold."""
    _mock_no_files(monkeypatch)
    status = verify_deployment("enforced", env=_clean_env())
    assert status.requested_mode == "enforced"
    assert status.effective_mode == "advisory"
    assert not status.binding_enforcement_active
    # At least the attestation-derived checks should have failed
    failed_names = {c.name for c in status.failed_required_checks}
    assert "proxy_separate_process" in failed_names
    assert "proxy_identity_verified" in failed_names


# --------------------------------------------------------------------------- #
# Test 3: Enforced mode with all checks passing -> stays enforced
# --------------------------------------------------------------------------- #


def test_enforced_mode_all_checks_pass_stays_enforced(monkeypatch):
    """Full attestation + clean env + no raw tools -> effective enforced."""
    _mock_no_files(monkeypatch)
    status = verify_deployment(
        "enforced",
        env=_clean_env(),
        agent_tools=["ep_execute", "ep_check", "ep_status"],
        attestation=_full_attestation(),
    )
    assert status.requested_mode == "enforced"
    assert status.effective_mode == "enforced"
    assert status.binding_enforcement_active is True
    assert status.failed_required_checks == []


# --------------------------------------------------------------------------- #
# Test 4: Docker socket present -> forces advisory
# --------------------------------------------------------------------------- #


def test_docker_socket_present_forces_advisory(monkeypatch):
    """If /var/run/docker.sock exists, enforced mode downgrades."""
    monkeypatch.setattr("os.path.exists", lambda p: p == "/var/run/docker.sock")
    status = verify_deployment(
        "enforced",
        env=_clean_env(),
        attestation=_full_attestation(),
    )
    assert status.effective_mode == "advisory"
    failed_names = {c.name for c in status.failed_required_checks}
    assert "no_docker_socket" in failed_names


# --------------------------------------------------------------------------- #
# Test 5: Target credentials in env -> forces advisory
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("cred_var", ["DATABASE_URL", "POSTGRES_PASSWORD", "PGPASSWORD", "TARGET_DB_URL"])
def test_target_credentials_in_env_force_advisory(monkeypatch, cred_var):
    """Any single target-credential env var forces advisory."""
    _mock_no_files(monkeypatch)
    env = dict(_clean_env())
    env[cred_var] = "some-secret-value"
    status = verify_deployment(
        "enforced",
        env=env,
        attestation=_full_attestation(),
    )
    assert status.effective_mode == "advisory"
    failed_names = {c.name for c in status.failed_required_checks}
    assert "no_target_credentials_in_env" in failed_names


# --------------------------------------------------------------------------- #
# Test 6: Raw tools in manifest -> forces advisory
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("raw_tool", list(_RAW_TOOLS))
def test_raw_tools_in_manifest_force_advisory(monkeypatch, raw_tool):
    """Any raw bypass tool in the manifest forces advisory."""
    _mock_no_files(monkeypatch)
    status = verify_deployment(
        "enforced",
        env=_clean_env(),
        agent_tools=["ep_execute", raw_tool],
        attestation=_full_attestation(),
    )
    assert status.effective_mode == "advisory"
    failed_names = {c.name for c in status.failed_required_checks}
    assert "no_raw_tools_in_manifest" in failed_names


# --------------------------------------------------------------------------- #
# Test 7: Clean manifest with only governed tools -> passes
# --------------------------------------------------------------------------- #


def test_clean_manifest_only_governed_tools_passes(monkeypatch):
    """A manifest containing only ep_* tools passes the tool check."""
    _mock_no_files(monkeypatch)
    tools = ["ep_execute", "ep_check", "ep_status", "ep_log", "ep_audit"]
    status = verify_deployment(
        "enforced",
        env=_clean_env(),
        agent_tools=tools,
        attestation=_full_attestation(),
    )
    assert status.effective_mode == "enforced"
    tool_checks = [c for c in status.checks if c.name == "no_raw_tools_in_manifest"]
    assert tool_checks and tool_checks[0].passed is True


# --------------------------------------------------------------------------- #
# Test 8: Proxy health check failure -> forces advisory
# --------------------------------------------------------------------------- #


def test_proxy_health_check_failure_forces_advisory(monkeypatch):
    """A failing proxy health endpoint downgrades enforced mode."""
    _mock_no_files(monkeypatch)
    with patch("ep_governance.deployment._check_proxy_health", return_value=False):
        status = verify_deployment(
            "enforced",
            env=_clean_env(),
            attestation=_full_attestation(),
            proxy_health_url="http://proxy:8201/health",
        )
    assert status.effective_mode == "advisory"
    failed_names = {c.name for c in status.failed_required_checks}
    assert "proxy_health_active" in failed_names


# --------------------------------------------------------------------------- #
# Test 9: Proxy health check success -> passes (mock urllib)
# --------------------------------------------------------------------------- #


def test_proxy_health_check_success_passes(monkeypatch):
    """A successful proxy health check keeps enforced mode (when all else OK)."""
    _mock_no_files(monkeypatch)
    fake_resp = MagicMock()
    fake_resp.status = 200
    fake_resp.__enter__ = MagicMock(return_value=fake_resp)
    fake_resp.__exit__ = MagicMock(return_value=False)
    with patch("urllib.request.urlopen", return_value=fake_resp):
        status = verify_deployment(
            "enforced",
            env=_clean_env(),
            attestation=_full_attestation(),
            proxy_health_url="http://proxy:8201/health",
        )
    assert status.effective_mode == "enforced"
    proxy_checks = [c for c in status.checks if c.name == "proxy_health_active"]
    assert proxy_checks and proxy_checks[0].passed is True


# --------------------------------------------------------------------------- #
# Test 10: format_enforcement_report output formatting
# --------------------------------------------------------------------------- #


def test_format_enforcement_report_contains_key_sections(monkeypatch):
    """The human-readable report contains all expected sections."""
    _mock_no_files(monkeypatch)
    status = verify_deployment("enforced", env=_clean_env())
    report = format_enforcement_report(status)
    assert "EP-Governance enforcement validation" in report
    assert "Requested mode: enforced" in report
    assert "Effective mode: advisory" in report
    assert "Binding enforcement is NOT active" in report
    # Each check should be present with a PASS/FAIL/WARN tag
    for check in status.checks:
        assert check.name in report


def test_format_enforcement_report_enforced_mode_says_active(monkeypatch):
    """When binding enforcement is active, the report says so."""
    _mock_no_files(monkeypatch)
    status = verify_deployment(
        "enforced",
        env=_clean_env(),
        agent_tools=["ep_execute"],
        attestation=_full_attestation(),
    )
    report = format_enforcement_report(status)
    assert "Binding enforcement IS active" in report
    assert "Effective mode: enforced" in report


# --------------------------------------------------------------------------- #
# Test 11: EnforcementStatus.binding_enforcement_active property
# --------------------------------------------------------------------------- #


def test_binding_enforcement_active_true_when_enforced_all_pass():
    """Property is True only when effective is enforced and all required pass."""
    status = EnforcementStatus(
        requested_mode="enforced",
        effective_mode="enforced",
        checks=[
            IsolationCheck("a", True, "ok"),
            IsolationCheck("b", True, "ok"),
        ],
    )
    assert status.binding_enforcement_active is True


def test_binding_enforcement_active_false_when_advisory():
    """If effective mode is advisory, binding enforcement is not active."""
    status = EnforcementStatus(
        requested_mode="enforced",
        effective_mode="advisory",
        checks=[IsolationCheck("a", True, "ok")],
    )
    assert status.binding_enforcement_active is False


def test_binding_enforcement_active_false_when_required_check_fails():
    """Even in enforced mode, a failed required check deactivates binding."""
    status = EnforcementStatus(
        requested_mode="enforced",
        effective_mode="enforced",
        checks=[
            IsolationCheck("a", True, "ok"),
            IsolationCheck("b", False, "fail", required=True),
        ],
    )
    # Note: effective_mode is "enforced" but a required check failed.
    # Per implementation, property checks effective_mode == enforced AND all required pass.
    assert status.binding_enforcement_active is False


def test_binding_enforcement_active_ignores_optional_check_failure():
    """A failed optional (required=False) check does not deactivate binding."""
    status = EnforcementStatus(
        requested_mode="enforced",
        effective_mode="enforced",
        checks=[
            IsolationCheck("a", True, "ok", required=True),
            IsolationCheck("b", False, "warn", required=False),
        ],
    )
    assert status.binding_enforcement_active is True


def test_failed_required_checks_property():
    """failed_required_checks returns only required+failed checks."""
    status = EnforcementStatus(
        requested_mode="enforced",
        effective_mode="advisory",
        checks=[
            IsolationCheck("pass1", True, "ok", required=True),
            IsolationCheck("fail1", False, "nope", required=True),
            IsolationCheck("opt_fail", False, "warn", required=False),
        ],
    )
    failed = status.failed_required_checks
    assert len(failed) == 1
    assert failed[0].name == "fail1"


# --------------------------------------------------------------------------- #
# Test 12: EnforcementAttestation defaults (all False)
# --------------------------------------------------------------------------- #


def test_attestation_defaults_all_false():
    """A freshly-constructed attestation has every field False."""
    att = EnforcementAttestation()
    assert att.proxy_separate_process is False
    assert att.proxy_identity_verified is False
    assert att.agent_has_no_target_credentials is False
    assert att.agent_has_no_docker_socket is False
    assert att.agent_has_no_ssh_agent is False
    assert att.agent_has_no_cloud_credentials is False
    assert att.raw_tools_removed is False
    assert att.target_network_restricted_to_proxy is False
    assert att.proxy_health_verified is False


# --------------------------------------------------------------------------- #
# Test 13: _load_attestation_from_env with EP_ASSERT_* vars set
# --------------------------------------------------------------------------- #


def test_load_attestation_from_env_all_set():
    """All EP_ASSERT_* vars set to 'true' produce a full attestation."""
    env = {var: "true" for var in _ASSERTION_VARS.values()}
    att = _load_attestation_from_env(env)
    assert att.proxy_separate_process is True
    assert att.proxy_identity_verified is True
    assert att.agent_has_no_target_credentials is True
    assert att.agent_has_no_docker_socket is True
    assert att.agent_has_no_ssh_agent is True
    assert att.agent_has_no_cloud_credentials is True
    assert att.raw_tools_removed is True
    assert att.target_network_restricted_to_proxy is True
    assert att.proxy_health_verified is True


def test_load_attestation_from_env_none_set():
    """Empty environment yields all-False attestation."""
    att = _load_attestation_from_env({})
    assert att.proxy_separate_process is False
    assert att.proxy_health_verified is False


@pytest.mark.parametrize("val", ["true", "1", "yes", "TRUE", "Yes"])
def test_load_attestation_from_env_truthy_values(val):
    """Various truthy strings set the assertion."""
    env = {_ASSERTION_VARS["proxy_separate_process"]: val}
    att = _load_attestation_from_env(env)
    assert att.proxy_separate_process is True


@pytest.mark.parametrize("val", ["false", "0", "no", "", "maybe"])
def test_load_attestation_from_env_falsy_values(val):
    """Non-truthy strings leave the assertion False."""
    env = {_ASSERTION_VARS["proxy_separate_process"]: val}
    att = _load_attestation_from_env(env)
    assert att.proxy_separate_process is False


# --------------------------------------------------------------------------- #
# Test 14: EnforcementUnavailableError is subclass of EPError
# --------------------------------------------------------------------------- #


def test_enforcement_unavailable_error_is_eperror_subclass():
    """EnforcementUnavailableError derives from EPError."""
    assert issubclass(EnforcementUnavailableError, EPError)
    err = EnforcementUnavailableError("test")
    assert isinstance(err, EPError)
    assert isinstance(err, Exception)


# --------------------------------------------------------------------------- #
# Test 15: Multiple failures listed in reasons
# --------------------------------------------------------------------------- #


def test_multiple_failures_listed_in_reasons(monkeypatch):
    """When several checks fail, each appears in the reasons list."""
    monkeypatch.setattr("os.path.exists", lambda p: p == "/var/run/docker.sock")
    env = dict(_clean_env())
    env["DATABASE_URL"] = "postgresql://secret"
    status = verify_deployment(
        "enforced",
        env=env,
        agent_tools=["shell.exec"],
        attestation=EnforcementAttestation(),  # all False
    )
    assert status.effective_mode == "advisory"
    # Reasons should mention each failed check
    reason_text = "\n".join(status.reasons)
    assert "no_target_credentials_in_env" in reason_text
    assert "no_docker_socket" in reason_text
    assert "no_raw_tools_in_manifest" in reason_text
    assert "proxy_separate_process" in reason_text
    assert len(status.reasons) >= 4


# --------------------------------------------------------------------------- #
# Test 16: Advisory mode with env checks still returns no checks
# --------------------------------------------------------------------------- #


def test_advisory_mode_with_dirty_env_still_no_checks(monkeypatch):
    """Even with credentials present, advisory mode returns empty checks."""
    env = dict(_clean_env())
    env["DATABASE_URL"] = "postgresql://secret"
    env["AWS_SECRET_ACCESS_KEY"] = "AKIA..."
    monkeypatch.setattr("os.path.exists", lambda p: p == "/var/run/docker.sock")
    status = verify_deployment("advisory", env=env)
    assert status.checks == []
    assert status.effective_mode == "advisory"


# --------------------------------------------------------------------------- #
# Test 17: check_runtime_environment individual checks
# --------------------------------------------------------------------------- #


def test_check_runtime_environment_clean(monkeypatch):
    """A clean environment with no files produces all-passing checks."""
    _mock_no_files(monkeypatch)
    checks = check_runtime_environment(_clean_env())
    assert len(checks) == 5
    assert all(c.passed for c in checks)
    names = {c.name for c in checks}
    assert names == {
        "no_target_credentials_in_env",
        "no_cloud_credentials_in_env",
        "no_docker_socket",
        "no_ssh_agent",
        "no_credential_files",
    }


def test_check_runtime_environment_cloud_creds(monkeypatch):
    """Cloud credential env vars trigger a failed check."""
    _mock_no_files(monkeypatch)
    env = dict(_clean_env())
    env["AWS_SECRET_ACCESS_KEY"] = "secret"
    checks = check_runtime_environment(env)
    cloud_check = [c for c in checks if c.name == "no_cloud_credentials_in_env"][0]
    assert cloud_check.passed is False
    assert "AWS_SECRET_ACCESS_KEY" in cloud_check.evidence


def test_check_runtime_environment_ssh_agent(monkeypatch):
    """SSH_AUTH_SOCK pointing to an existing socket triggers a failed check."""
    monkeypatch.setattr(
        "os.path.exists",
        lambda p: p == "/tmp/ssh-agent.sock",
    )
    env = dict(_clean_env())
    env["SSH_AUTH_SOCK"] = "/tmp/ssh-agent.sock"
    checks = check_runtime_environment(env)
    ssh_check = [c for c in checks if c.name == "no_ssh_agent"][0]
    assert ssh_check.passed is False


def test_check_runtime_environment_ssh_agent_not_existing(monkeypatch):
    """SSH_AUTH_SOCK set but socket missing still passes."""
    _mock_no_files(monkeypatch)
    env = dict(_clean_env())
    env["SSH_AUTH_SOCK"] = "/nonexistent/sock"
    checks = check_runtime_environment(env)
    ssh_check = [c for c in checks if c.name == "no_ssh_agent"][0]
    assert ssh_check.passed is True


# --------------------------------------------------------------------------- #
# Test 18: check_agent_tool_manifest variants
# --------------------------------------------------------------------------- #


def test_check_agent_tool_manifest_raw_tool_fails():
    """A raw tool in the manifest fails the check."""
    check = check_agent_tool_manifest(["ep_execute", "docker.exec"])
    assert check.passed is False
    assert "docker.exec" in check.evidence
    assert check.required is True


def test_check_agent_tool_manifest_clean_passes():
    """Only governed tools -> pass."""
    check = check_agent_tool_manifest(["ep_execute", "ep_check", "ep_status"])
    assert check.passed is True


def test_check_agent_tool_manifest_unclassified_warns_but_passes():
    """Unknown (non-raw) tools pass but mention the unclassified set."""
    check = check_agent_tool_manifest(["ep_execute", "custom_tool"])
    assert check.passed is True
    assert "unclassified" in check.evidence


def test_check_agent_tool_manifest_empty_list():
    """An empty tool list passes."""
    check = check_agent_tool_manifest([])
    assert check.passed is True


def test_check_agent_tool_manifest_custom_allowed_tools():
    """A custom allowed_tools set is respected."""
    check = check_agent_tool_manifest(
        ["my_governed_tool"],
        allowed_tools=frozenset({"my_governed_tool"}),
    )
    assert check.passed is True


# --------------------------------------------------------------------------- #
# Test 19: _check_proxy_health direct tests
# --------------------------------------------------------------------------- #


def test_check_proxy_health_success():
    """urllib returning HTTP 200 -> True."""
    fake_resp = MagicMock()
    fake_resp.status = 200
    fake_resp.__enter__ = MagicMock(return_value=fake_resp)
    fake_resp.__exit__ = MagicMock(return_value=False)
    with patch("urllib.request.urlopen", return_value=fake_resp):
        assert _check_proxy_health("http://proxy/health") is True


def test_check_proxy_health_non_200():
    """urllib returning HTTP 503 -> False."""
    fake_resp = MagicMock()
    fake_resp.status = 503
    fake_resp.__enter__ = MagicMock(return_value=fake_resp)
    fake_resp.__exit__ = MagicMock(return_value=False)
    with patch("urllib.request.urlopen", return_value=fake_resp):
        assert _check_proxy_health("http://proxy/health") is False


def test_check_proxy_health_connection_error():
    """Any exception from urlopen -> False (no raise)."""
    with patch("urllib.request.urlopen", side_effect=ConnectionError("refused")):
        assert _check_proxy_health("http://proxy/health") is False


def test_check_proxy_health_timeout():
    """A timeout (socket.timeout) -> False."""
    import socket as _socket
    with patch("urllib.request.urlopen", side_effect=_socket.timeout("timed out")):
        assert _check_proxy_health("http://proxy/health") is False


# --------------------------------------------------------------------------- #
# Test 20: IsolationCheck dataclass
# --------------------------------------------------------------------------- #


def test_isolation_check_defaults_required_true():
    """IsolationCheck.required defaults to True."""
    check = IsolationCheck("test", True, "evidence")
    assert check.required is True
    assert check.name == "test"
    assert check.passed is True
    assert check.evidence == "evidence"


def test_isolation_check_optional():
    """An optional check can be constructed with required=False."""
    check = IsolationCheck("warn", False, "evidence", required=False)
    assert check.required is False


# --------------------------------------------------------------------------- #
# Test 21: verify_deployment uses explicit attestation over env
# --------------------------------------------------------------------------- #


def test_verify_deployment_explicit_attestation_overrides_env(monkeypatch):
    """When attestation is passed explicitly, env EP_ASSERT_* are ignored."""
    _mock_no_files(monkeypatch)
    # Env says everything is asserted...
    env = {var: "true" for var in _ASSERTION_VARS.values()}
    # ...but we pass an all-False attestation explicitly.
    status = verify_deployment(
        "enforced",
        env=env,
        attestation=EnforcementAttestation(),
    )
    # Should downgrade because explicit attestation is all-False.
    assert status.effective_mode == "advisory"


# --------------------------------------------------------------------------- #
# Test 22: verify_deployment loads attestation from env when not explicit
# --------------------------------------------------------------------------- #


def test_verify_deployment_loads_attestation_from_env(monkeypatch):
    """When no explicit attestation, EP_ASSERT_* vars are used."""
    _mock_no_files(monkeypatch)
    env = dict(_clean_env())
    env.update({var: "true" for var in _ASSERTION_VARS.values()})
    status = verify_deployment("enforced", env=env)
    assert status.effective_mode == "enforced"
    assert status.binding_enforcement_active is True


# --------------------------------------------------------------------------- #
# Test 23: Proxy health URL provided but no attestation -> still fails
# --------------------------------------------------------------------------- #


def test_proxy_health_ok_but_attestation_missing_fails(monkeypatch):
    """A healthy proxy cannot compensate for missing attestations."""
    _mock_no_files(monkeypatch)
    fake_resp = MagicMock()
    fake_resp.status = 200
    fake_resp.__enter__ = MagicMock(return_value=fake_resp)
    fake_resp.__exit__ = MagicMock(return_value=False)
    with patch("urllib.request.urlopen", return_value=fake_resp):
        status = verify_deployment(
            "enforced",
            env=_clean_env(),
            attestation=EnforcementAttestation(),  # all False
            proxy_health_url="http://proxy/health",
        )
    assert status.effective_mode == "advisory"
    # proxy_health_active passed, but attestation checks failed
    proxy_checks = [c for c in status.checks if c.name == "proxy_health_active"]
    assert proxy_checks and proxy_checks[0].passed is True


# --------------------------------------------------------------------------- #
# Test 24: Report shows WARN for optional failed checks
# --------------------------------------------------------------------------- #


def test_format_enforcement_report_warn_for_optional_failed():
    """Optional checks that fail show as WARN, not FAIL."""
    status = EnforcementStatus(
        requested_mode="enforced",
        effective_mode="enforced",
        checks=[
            IsolationCheck("req_ok", True, "ok", required=True),
            IsolationCheck("opt_fail", False, "warn", required=False),
        ],
    )
    report = format_enforcement_report(status)
    assert "[WARN]" in report
    assert "opt_fail" in report
    assert "[FAIL]" not in report


# --------------------------------------------------------------------------- #
# Test 25: Credential file paths trigger failure
# --------------------------------------------------------------------------- #


def test_credential_file_present_forces_advisory(monkeypatch):
    """A credential file (e.g. ~/.aws/credentials) forces advisory."""
    monkeypatch.setattr(
        "os.path.exists",
        lambda p: p == _CREDENTIAL_FILE_PATHS[0],  # ~/.aws/credentials
    )
    status = verify_deployment(
        "enforced",
        env=_clean_env(),
        attestation=_full_attestation(),
    )
    assert status.effective_mode == "advisory"
    failed_names = {c.name for c in status.failed_required_checks}
    assert "no_credential_files" in failed_names


# --------------------------------------------------------------------------- #
# Test 26: passed_checks property
# --------------------------------------------------------------------------- #


def test_passed_checks_property():
    """passed_checks returns all checks that passed (required + optional)."""
    status = EnforcementStatus(
        requested_mode="enforced",
        effective_mode="enforced",
        checks=[
            IsolationCheck("a", True, "ok", required=True),
            IsolationCheck("b", False, "no", required=True),
            IsolationCheck("c", True, "ok", required=False),
        ],
    )
    passed = status.passed_checks
    assert {c.name for c in passed} == {"a", "c"}