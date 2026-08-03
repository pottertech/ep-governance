"""EP-Governance deployment verification and enforcement attestation.

This module implements the enforcement-attestation layer that verifies
deployment isolation conditions before allowing enforced mode.

The key insight is that EP_MODE=enforced is a *request*, not a guarantee.
The *effective* mode depends on whether the deployment actually satisfies
the isolation requirements that make binding enforcement real:

    requested_mode = enforced  (from config)
    effective_mode = enforced  (only when all required checks pass)
    effective_mode = advisory  (when any required check fails)

Without this verification, a deployment can report itself as "enforced"
even though the agent can bypass governance completely.

Three sources of verification:

1. Runtime checks — EP can directly inspect its environment for known
   bypass indicators (Docker socket, SSH agent, cloud credentials,
   raw tool exposure).

2. Deployment assertions — the orchestrator provides signed or protected
   assertions via environment variables (EP_ASSERT_*).  These are weak
   alone but useful when combined with runtime checks.

3. Active verification — the deployment test process attempts prohibited
   actions from the agent environment (connecting to target DB, accessing
   Docker socket, etc.).  These must run from the actual agent container
   or process namespace, not merely from the EP server.
"""

from __future__ import annotations

import os
import socket
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Mapping

from .errors import EPError

__all__ = [
    "IsolationCheck",
    "EnforcementStatus",
    "EnforcementAttestation",
    "EnforcementUnavailableError",
    "verify_deployment",
    "check_runtime_environment",
    "check_agent_tool_manifest",
    "format_enforcement_report",
]


# --------------------------------------------------------------------------- #
# Error
# --------------------------------------------------------------------------- #


class EnforcementUnavailableError(EPError):
    """Raised when binding enforcement is requested but not achievable.

    This error means the deployment has not satisfied the isolation
    requirements for enforced mode.  The system should operate in
    advisory mode instead.
    """


# --------------------------------------------------------------------------- #
# Data structures
# --------------------------------------------------------------------------- #


@dataclass
class IsolationCheck:
    """A single isolation verification check.

    Attributes:
        name: Human-readable name of the check.
        passed: Whether the check passed.
        evidence: Description of what was checked and what was found.
        required: If True, a failed check downgrades to advisory mode.
            If False, a failed check is a warning but does not downgrade.
    """

    name: str
    passed: bool
    evidence: str
    required: bool = True


@dataclass
class EnforcementStatus:
    """Result of deployment verification.

    The effective_mode is what the system should actually use, based on
    whether all required isolation checks passed.  The requested_mode is
    what the configuration asked for.

    Use ``binding_enforcement_active`` to determine whether enforced-mode
    operations (ep_execute, authorization issuance) should be allowed.
    """

    requested_mode: str
    effective_mode: str
    checks: list[IsolationCheck] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    @property
    def binding_enforcement_active(self) -> bool:
        """True only when effective mode is enforced and all required checks pass."""
        if self.effective_mode != "enforced":
            return False
        return all(c.passed for c in self.checks if c.required)

    @property
    def failed_required_checks(self) -> list[IsolationCheck]:
        """Required checks that failed."""
        return [c for c in self.checks if c.required and not c.passed]

    @property
    def passed_checks(self) -> list[IsolationCheck]:
        """All checks that passed (required and optional)."""
        return [c for c in self.checks if c.passed]


@dataclass
class EnforcementAttestation:
    """Deployment attestation provided by the orchestrator.

    These are assertions from the deployment system (Docker Compose,
    Kubernetes, systemd, etc.) that certain isolation conditions hold.
    They are combined with runtime checks to determine effective mode.

    Plain environment variables are weak — a compromised agent could
    set them.  In production, these should come from signed deployment
    manifests or a trusted deployment controller.  But they are still
    better than nothing, and they document intent.
    """

    proxy_separate_process: bool = False
    proxy_identity_verified: bool = False
    agent_has_no_target_credentials: bool = False
    agent_has_no_docker_socket: bool = False
    agent_has_no_ssh_agent: bool = False
    agent_has_no_cloud_credentials: bool = False
    raw_tools_removed: bool = False
    target_network_restricted_to_proxy: bool = False
    proxy_health_verified: bool = False


# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

# Environment variables that commonly contain target DB credentials.
# If any of these are present in the agent's environment, the agent
# has direct target access and enforced mode is not real.
_CREDENTIAL_ENV_VARS = [
    "EP_PROXY_TARGET_URL",
    "DATABASE_URL",
    "POSTGRES_URL",
    "POSTGRES_PASSWORD",
    "PGPASSWORD",
    "DB_PASSWORD",
    "TARGET_DB_URL",
]

# Environment variables that contain cloud provider credentials.
_CLOUD_CREDENTIAL_ENV_VARS = [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AZURE_CLIENT_SECRET",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GCLOUD_SERVICE_KEY",
    "ARM_CLIENT_SECRET",
]

# Common credential file paths that should not be accessible.
_CREDENTIAL_FILE_PATHS = [
    os.path.expanduser("~/.aws/credentials"),
    os.path.expanduser("~/.aws/config"),
    os.path.expanduser("~/.ssh/id_rsa"),
    os.path.expanduser("~/.ssh/id_ed25519"),
    os.path.expanduser("~/.kube/config"),
    os.path.expanduser("~/.docker/config.json"),
    "/var/run/docker.sock",
]

# Tools that are considered "raw" — if present in the agent's tool
# manifest, enforced mode is not real because the agent can bypass
# the governed proxy.
_RAW_TOOLS = frozenset({
    "shell.exec",
    "shell",
    "postgres.execute",
    "postgres",
    "psql",
    "docker.exec",
    "docker",
    "docker.run",
    "ssh.exec",
    "ssh",
    "python.exec",
    "python",
    "terminal",
    "filesystem.write",
    "filesystem.delete",
})

# Assertion environment variables (from orchestrator)
_ASSERTION_VARS = {
    "proxy_separate_process": "EP_ASSERT_PROXY_SEPARATE_PROCESS",
    "proxy_identity_verified": "EP_ASSERT_PROXY_IDENTITY_VERIFIED",
    "agent_has_no_target_credentials": "EP_ASSERT_NO_TARGET_CREDENTIALS",
    "agent_has_no_docker_socket": "EP_ASSERT_NO_DOCKER_SOCKET",
    "agent_has_no_ssh_agent": "EP_ASSERT_NO_SSH_AGENT",
    "agent_has_no_cloud_credentials": "EP_ASSERT_NO_CLOUD_CREDENTIALS",
    "raw_tools_removed": "EP_ASSERT_RAW_TOOLS_REMOVED",
    "target_network_restricted_to_proxy": "EP_ASSERT_TARGET_NETWORK_ISOLATED",
    "proxy_health_verified": "EP_ASSERT_PROXY_HEALTH_VERIFIED",
}


# --------------------------------------------------------------------------- #
# Runtime checks
# --------------------------------------------------------------------------- #


def check_runtime_environment(env: Mapping[str, str] | None = None) -> list[IsolationCheck]:
    """Inspect the local environment for known bypass indicators.

    This function performs runtime checks that EP can do by introspection.
    It does not cover all isolation properties — some require active
    verification from the agent container (see the deployment guide).

    Args:
        env: Environment dict (defaults to os.environ).

    Returns:
        List of IsolationCheck results.
    """
    e = env if env is not None else os.environ
    checks: list[IsolationCheck] = []

    # Check 1: No target DB credentials in environment
    found_creds = [v for v in _CREDENTIAL_ENV_VARS if e.get(v)]
    if found_creds:
        checks.append(IsolationCheck(
            name="no_target_credentials_in_env",
            passed=False,
            evidence=f"Found target credential env vars: {', '.join(found_creds)}",
        ))
    else:
        checks.append(IsolationCheck(
            name="no_target_credentials_in_env",
            passed=True,
            evidence="No recognized target credential env vars found",
        ))

    # Check 2: No cloud credentials in environment
    found_cloud = [v for v in _CLOUD_CREDENTIAL_ENV_VARS if e.get(v)]
    if found_cloud:
        checks.append(IsolationCheck(
            name="no_cloud_credentials_in_env",
            passed=False,
            evidence=f"Found cloud credential env vars: {', '.join(found_cloud)}",
        ))
    else:
        checks.append(IsolationCheck(
            name="no_cloud_credentials_in_env",
            passed=True,
            evidence="No recognized cloud credential env vars found",
        ))

    # Check 3: No Docker socket
    docker_sock = "/var/run/docker.sock"
    if os.path.exists(docker_sock):
        checks.append(IsolationCheck(
            name="no_docker_socket",
            passed=False,
            evidence=f"Docker socket found at {docker_sock}",
        ))
    else:
        checks.append(IsolationCheck(
            name="no_docker_socket",
            passed=True,
            evidence="Docker socket not found",
        ))

    # Check 4: No SSH agent
    ssh_auth_sock = e.get("SSH_AUTH_SOCK")
    if ssh_auth_sock and os.path.exists(ssh_auth_sock):
        checks.append(IsolationCheck(
            name="no_ssh_agent",
            passed=False,
            evidence=f"SSH agent socket found at {ssh_auth_sock}",
        ))
    else:
        checks.append(IsolationCheck(
            name="no_ssh_agent",
            passed=True,
            evidence="SSH agent socket not found or not set",
        ))

    # Check 5: No credential files accessible
    found_files = [p for p in _CREDENTIAL_FILE_PATHS if os.path.exists(p)]
    if found_files:
        checks.append(IsolationCheck(
            name="no_credential_files",
            passed=False,
            evidence=f"Credential files found: {', '.join(found_files)}",
        ))
    else:
        checks.append(IsolationCheck(
            name="no_credential_files",
            passed=True,
            evidence="No recognized credential files found",
        ))

    return checks


def check_agent_tool_manifest(
    tools: list[str],
    allowed_tools: frozenset[str] | None = None,
) -> IsolationCheck:
    """Check the agent's complete tool manifest for raw bypass tools.

    The tool manifest should come from the orchestrator, not from the
    agent itself (a compromised agent could lie about its tools).

    Args:
        tools: List of tool names the agent has access to.
        allowed_tools: Set of tools that are governed (ep_execute, etc.).
            If None, uses the default governed tool set.

    Returns:
        IsolationCheck result.
    """
    if allowed_tools is None:
        allowed_tools = frozenset({
            "ep_execute",
            "ep_check",
            "ep_status",
            "ep_list_policies",
            "ep_log",
            "ep_audit",
            "ep_pending_approvals",
            "ep_approve",
            "ep_deny",
            "ep_claim",
            "ep_release_claim",
        })

    tool_set = set(tools)
    raw_found = tool_set & _RAW_TOOLS
    non_governed = tool_set - allowed_tools - _RAW_TOOLS

    if raw_found:
        return IsolationCheck(
            name="no_raw_tools_in_manifest",
            passed=False,
            evidence=(
                f"Raw bypass tools in agent manifest: {', '.join(sorted(raw_found))}. "
                f"These tools allow direct access to protected targets."
            ),
        )

    if non_governed:
        # In enforced mode, unknown tools must fail closed.
        # A generic browser, Python runner, automation tool, or custom
        # plugin may provide a bypass even if its name is not in _RAW_TOOLS.
        # Known governed tool -> pass
        # Known prohibited tool -> fail
        # Unknown tool -> fail pending review
        unknown_list = sorted(list(non_governed)[:5])
        return IsolationCheck(
            name="no_raw_tools_in_manifest",
            passed=False,
            evidence=(
                f"{len(non_governed)} unclassified tool(s) not in the governed "
                f"tool set: {', '.join(unknown_list)}. "
                f"In enforced mode, unknown tools must be reviewed and either "
                f"added to the governed set or removed. Fail-closed pending review."
            ),
        )

    return IsolationCheck(
        name="no_raw_tools_in_manifest",
        passed=True,
        evidence=f"Agent manifest contains only governed tools ({len(tools)} tools)",
    )


# --------------------------------------------------------------------------- #
# Attestation loading
# --------------------------------------------------------------------------- #


def _load_attestation_from_env(env: Mapping[str, str] | None = None) -> EnforcementAttestation:
    """Load deployment assertions from environment variables.

    These are EP_ASSERT_* variables set by the orchestrator.  They are
    weak alone (an agent could set them) but useful when combined with
    runtime checks.
    """
    e = env if env is not None else os.environ

    def _bool(var_name: str) -> bool:
        return e.get(var_name, "").lower() in ("true", "1", "yes")

    return EnforcementAttestation(
        proxy_separate_process=_bool(_ASSERTION_VARS["proxy_separate_process"]),
        proxy_identity_verified=_bool(_ASSERTION_VARS["proxy_identity_verified"]),
        agent_has_no_target_credentials=_bool(_ASSERTION_VARS["agent_has_no_target_credentials"]),
        agent_has_no_docker_socket=_bool(_ASSERTION_VARS["agent_has_no_docker_socket"]),
        agent_has_no_ssh_agent=_bool(_ASSERTION_VARS["agent_has_no_ssh_agent"]),
        agent_has_no_cloud_credentials=_bool(_ASSERTION_VARS["agent_has_no_cloud_credentials"]),
        raw_tools_removed=_bool(_ASSERTION_VARS["raw_tools_removed"]),
        target_network_restricted_to_proxy=_bool(_ASSERTION_VARS["target_network_restricted_to_proxy"]),
        proxy_health_verified=_bool(_ASSERTION_VARS["proxy_health_verified"]),
    )


# --------------------------------------------------------------------------- #
# Main verification function
# --------------------------------------------------------------------------- #


def verify_deployment(
    requested_mode: str,
    env: Mapping[str, str] | None = None,
    agent_tools: list[str] | None = None,
    attestation: EnforcementAttestation | None = None,
    proxy_health_url: str | None = None,
) -> EnforcementStatus:
    """Verify deployment isolation and determine effective enforcement mode.

    This is the main entry point.  It combines:

    1. Runtime environment checks (credential env vars, Docker socket, etc.)
    2. Deployment assertions (EP_ASSERT_* from orchestrator)
    3. Agent tool manifest check (if provided)
    4. Proxy health check (if URL provided)

    The effective mode is "enforced" only when:
    - requested_mode is "enforced"
    - All required runtime checks pass
    - All required attestation assertions are present
    - Agent tool manifest contains no raw tools (if provided)
    - Proxy health check passes (if URL provided)

    Otherwise the effective mode is "advisory" with reasons explaining
    which checks failed.

    Args:
        requested_mode: The configured mode ("enforced" or "advisory").
        env: Environment dict (defaults to os.environ).
        agent_tools: List of tools the agent has access to (from orchestrator).
        attestation: Explicit attestation object (overrides env-based loading).
        proxy_health_url: URL to check proxy health (e.g., http://proxy:8201/health).

    Returns:
        EnforcementStatus with effective_mode, checks, and reasons.
    """
    # Load attestation from env if not provided explicitly
    if attestation is None:
        attestation = _load_attestation_from_env(env)

    # If advisory was requested, that's fine — no checks needed.
    if requested_mode == "advisory":
        return EnforcementStatus(
            requested_mode="advisory",
            effective_mode="advisory",
            checks=[],
            reasons=["Advisory mode requested — no isolation checks required"],
        )

    checks: list[IsolationCheck] = []

    # --- Runtime checks (EP server environment) ---
    # These verify the EP server's own environment. They do NOT verify
    # the agent's environment — that requires a signed attestation from
    # the agent runtime (see agent-side attestation checks below).
    runtime_checks = check_runtime_environment(env)
    checks.extend(runtime_checks)

    # --- Agent tool manifest check (REQUIRED in enforced mode) ---
    # In enforced mode, the complete tool manifest MUST be supplied.
    # Without it, the most important bypass check — whether the agent
    # has shell, Python, PostgreSQL, Docker, SSH, or filesystem tools —
    # is skipped. This would allow a false claim of enforced mode.
    if agent_tools is not None:
        tool_check = check_agent_tool_manifest(agent_tools)
        checks.append(tool_check)
    else:
        checks.append(IsolationCheck(
            name="agent_tool_manifest_supplied",
            passed=False,
            evidence=(
                "Complete agent capability manifest was not supplied. "
                "In enforced mode, the manifest must come from the trusted "
                "orchestrator, not from the agent."
            ),
        ))

    # --- Attestation checks (all 9 fields) ---
    # Every required attestation property must become an explicit
    # IsolationCheck. Previously, only 4 of the 9 fields were enforced.
    attestation_checks = [
        ("proxy_separate_process", attestation.proxy_separate_process,
         "Proxy must run as a separate process from the agent"),
        ("proxy_identity_verified", attestation.proxy_identity_verified,
         "Proxy identity must be verified"),
        ("target_network_restricted", attestation.target_network_restricted_to_proxy,
         "Target network must be restricted to proxy only"),
        ("proxy_health_verified", attestation.proxy_health_verified,
         "Proxy health must be verified by the orchestrator"),
        # Agent-side assertions — these are distinct from the EP server
        # runtime checks above. The EP server cannot inspect the agent's
        # environment directly; these assertions must come from a signed
        # attestation produced inside the agent runtime.
        ("agent_no_target_credentials_attested",
         attestation.agent_has_no_target_credentials,
         "Agent must not possess target DB credentials (attested from agent runtime)"),
        ("agent_no_docker_socket_attested",
         attestation.agent_has_no_docker_socket,
         "Agent must not have Docker socket access (attested from agent runtime)"),
        ("agent_no_ssh_agent_attested",
         attestation.agent_has_no_ssh_agent,
         "Agent must not have SSH agent access (attested from agent runtime)"),
        ("agent_no_cloud_credentials_attested",
         attestation.agent_has_no_cloud_credentials,
         "Agent must not have cloud CLI credentials (attested from agent runtime)"),
        ("agent_no_raw_tools_attested",
         attestation.raw_tools_removed,
         "Agent must not have raw bypass tools (attested from agent runtime)"),
    ]

    for name, asserted, description in attestation_checks:
        checks.append(IsolationCheck(
            name=name,
            passed=bool(asserted),
            evidence=(
                f"{description} — attested by orchestrator"
                if asserted
                else f"{description} — NOT attested"
            ),
        ))

    # --- Active proxy health check (REQUIRED in enforced mode) ---
    # In enforced mode, proxy health must be actively verified, not
    # merely asserted. A mere HTTP 200 response is necessary but not
    # sufficient — in production, the health response should be signed
    # or protected by mTLS. For now, we require the URL to be provided
    # and the HTTP check to succeed.
    if proxy_health_url:
        proxy_ok = _check_proxy_health(proxy_health_url)
        checks.append(IsolationCheck(
            name="proxy_health_active",
            passed=proxy_ok,
            evidence=(
                f"Proxy health check passed at {proxy_health_url}"
                if proxy_ok
                else f"Proxy health check FAILED at {proxy_health_url}"
            ),
        ))
    else:
        # In enforced mode, proxy health URL is required.
        checks.append(IsolationCheck(
            name="proxy_health_active",
            passed=False,
            evidence=(
                "Active proxy health check was not performed — "
                "proxy URL not provided. In enforced mode, proxy health "
                "must be actively verified, not merely asserted."
            ),
        ))

    # --- Determine effective mode ---
    failed_required = [c for c in checks if c.required and not c.passed]
    reasons = [f"{c.name}: {c.evidence}" for c in failed_required]

    if failed_required:
        effective_mode = "advisory"
    else:
        effective_mode = "enforced"

    return EnforcementStatus(
        requested_mode=requested_mode,
        effective_mode=effective_mode,
        checks=checks,
        reasons=reasons,
    )


def _check_proxy_health(url: str, timeout: float = 5.0) -> bool:
    """Attempt to reach the proxy health endpoint.

    Args:
        url: Health check URL (e.g., http://100.64.0.20:8201/health).
        timeout: Connection timeout in seconds.

    Returns:
        True if the proxy responded with HTTP 200, False otherwise.
    """
    try:
        import urllib.request
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status == 200
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #


def format_enforcement_report(status: EnforcementStatus) -> str:
    """Format an enforcement status as a human-readable report for startup output.

    This is what should be printed when EP-Governance starts, showing
    which checks passed and which failed, and the resulting effective mode.

    Example output:

        EP-Governance enforcement validation

        [PASS] no_target_credentials_in_env — No recognized target credential env vars found
        [PASS] no_cloud_credentials_in_env — No recognized cloud credential env vars found
        [FAIL] no_docker_socket — Docker socket found at /var/run/docker.sock
        [PASS] no_ssh_agent — SSH agent socket not found or not set
        [PASS] no_credential_files — No recognized credential files found
        [FAIL] proxy_separate_process — Proxy must run as a separate process — NOT attested

        Requested mode: enforced
        Effective mode: advisory

        Binding enforcement is NOT active.
        Failed checks: no_docker_socket, proxy_separate_process
    """
    lines: list[str] = ["EP-Governance enforcement validation", ""]

    for check in status.checks:
        tag = "PASS" if check.passed else ("WARN" if not check.required else "FAIL")
        lines.append(f"  [{tag}] {check.name} — {check.evidence}")

    lines.append("")
    lines.append(f"  Requested mode: {status.requested_mode}")
    lines.append(f"  Effective mode: {status.effective_mode}")
    lines.append("")

    if status.binding_enforcement_active:
        lines.append("  Binding enforcement IS active.")
    else:
        lines.append("  Binding enforcement is NOT active.")
        if status.failed_required_checks:
            failed_names = [c.name for c in status.failed_required_checks]
            lines.append(f"  Failed checks: {', '.join(failed_names)}")

    return "\n".join(lines)