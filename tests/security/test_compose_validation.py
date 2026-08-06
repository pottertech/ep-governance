"""Tests for Docker Compose configuration validation.

Tests that the proxy Docker Compose file is structurally valid
and contains all required environment variables.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


COMPOSE_FILE = Path(__file__).parent.parent.parent / "docker" / "proxy" / "docker-compose.proxy.yml"


def _has_docker_compose() -> bool:
    """Check if docker compose is available."""
    try:
        subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True,
            timeout=5,
        )
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# Required env vars that must appear in the Compose file
REQUIRED_ENV_VARS = [
    "EP_DB_URL",
    "EP_PROXY_TARGET_URL",
    "EP_PROXY_AUDIENCE",
    "EP_PROXY_PRINCIPAL_ID",
    "EP_DEPLOYMENT_ID",
    "EP_PROXY_TARGET_ID",
    "EP_EP_SERVICE_ID",
    "EP_PUBLIC_KEY",
    "EP_CONTROLLER_PUBLIC_KEY",
    "EP_PROXY_ATTESTATION_PATH",
]


class TestComposeFile:
    """Static validation of the Docker Compose file."""

    def test_compose_file_exists(self):
        """The Compose file exists."""
        assert COMPOSE_FILE.exists(), f"Compose file not found at {COMPOSE_FILE}"

    def test_compose_file_has_volumes(self):
        """The Compose file mounts the attestation file."""
        content = COMPOSE_FILE.read_text()
        assert "volumes:" in content, "Compose file missing volumes section"
        assert "proxy-attestation.json" in content, "Compose file missing attestation mount"

    def test_compose_file_uses_required_syntax(self):
        """All critical variables use ${VAR:?required} syntax."""
        content = COMPOSE_FILE.read_text()
        for var in ["EP_DB_URL", "EP_PROXY_TARGET_URL", "EP_PROXY_AUDIENCE",
                     "EP_PROXY_PRINCIPAL_ID", "EP_DEPLOYMENT_ID",
                     "EP_PROXY_TARGET_ID", "EP_EP_SERVICE_ID", "EP_PUBLIC_KEY",
                     "EP_CONTROLLER_PUBLIC_KEY", "EP_PROXY_ATTESTATION_FILE"]:
            assert f"${{{var}:?required}}" in content, (
                f"Variable {var} does not use ${{VAR:?required}} syntax in Compose file"
            )

    def test_compose_file_has_all_required_env_vars(self):
        """All required env vars appear in the Compose file."""
        content = COMPOSE_FILE.read_text()
        for var in REQUIRED_ENV_VARS:
            assert var in content, f"Variable {var} missing from Compose file"

    def test_compose_file_has_security_hardening(self):
        """The Compose file includes security hardening."""
        content = COMPOSE_FILE.read_text()
        assert "no-new-privileges" in content, "Missing no-new-privileges security opt"
        assert "cap_drop" in content, "Missing cap_drop"
        assert "ALL" in content, "cap_drop should drop ALL capabilities"

    def test_compose_file_has_healthcheck(self):
        """The Compose file includes a health check."""
        content = COMPOSE_FILE.read_text()
        assert "healthcheck" in content, "Missing healthcheck"
        assert "/health" in content, "Healthcheck should check /health endpoint"


@pytest.mark.skipif(not _has_docker_compose(), reason="docker compose not available")
class TestComposeValidation:
    """Live validation of the Docker Compose file with docker compose config."""

    def test_compose_config_succeeds(self, tmp_path):
        """docker compose config validates the file structure."""
        env = {
            "EP_DB_URL": "postgresql://test:test@localhost/test",
            "EP_PROXY_TARGET_URL": "postgresql://test:test@localhost/test",
            "EP_PROXY_AUDIENCE": "postgres-proxy",
            "EP_PROXY_PRINCIPAL_ID": "proxy-test",
            "EP_DEPLOYMENT_ID": "deployment-test",
            "EP_PROXY_TARGET_ID": "target-test",
            "EP_EP_SERVICE_ID": "service-test",
            "EP_PUBLIC_KEY": "00" * 32,
            "EP_CONTROLLER_PUBLIC_KEY": "11" * 32,
            "EP_PROXY_ATTESTATION_FILE": str(tmp_path / "test-attestation.json"),
        }

        # Create a dummy attestation file
        (tmp_path / "test-attestation.json").write_text('{"test": true}')

        full_env = {**os.environ, **env}
        result = subprocess.run(
            ["docker", "compose", "-f", str(COMPOSE_FILE), "config"],
            capture_output=True,
            text=True,
            env=full_env,
            timeout=10,
        )
        assert result.returncode == 0, f"docker compose config failed: {result.stderr}"