"""Phase 6 integration tests: CLI.

Tests CLI commands via Typer's CliRunner for machine-readable JSON output,
human-readable output, and no secret leakage.
"""

from __future__ import annotations

import json
import os
import tempfile

import pytest
from typer.testing import CliRunner

from ep_governance.cli import app

runner = CliRunner()


@pytest.fixture
def temp_db_env(monkeypatch, tmp_path):
    """Set up a temporary SQLite database for CLI tests."""
    db_path = str(tmp_path / "test_ep.db")
    monkeypatch.setenv("EP_DB_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("EP_MODE", "enforced")
    yield db_path


class TestCLIInit:
    def test_init_creates_schema(self, temp_db_env):
        """ep-governance init should create the schema and return JSON."""
        result = runner.invoke(app, ["init", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["status"] == "initialized"
        assert "ep_service_principal_id" in data

    def test_init_human_readable(self, temp_db_env):
        """ep-governance init without --json should produce human-readable output."""
        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        assert "initialized" in result.stdout


class TestCLIRegister:
    def test_register_human(self, temp_db_env):
        """Register a human principal."""
        runner.invoke(app, ["init", "--json"])
        result = runner.invoke(
            app,
            [
                "register",
                "--name",
                "Skip Potter",
                "--type",
                "human",
                "--json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["name"] == "Skip Potter"
        assert data["type"] == "human"
        assert len(data["principal_id"]) == 20

    def test_register_agent(self, temp_db_env):
        """Register an agent principal."""
        runner.invoke(app, ["init", "--json"])
        result = runner.invoke(
            app,
            [
                "register",
                "--name",
                "Mary Wise",
                "--type",
                "agent",
                "--json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["type"] == "agent"


class TestCLIProject:
    def test_create_project(self, temp_db_env):
        """Create a project with lattice and branch."""
        runner.invoke(app, ["init", "--json"])
        result = runner.invoke(
            app,
            [
                "project",
                "create",
                "NAS Migration",
                "--description",
                "Migrating GBrain",
                "--json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["name"] == "NAS Migration"
        assert "project_id" in data
        assert "lattice_id" in data
        assert "branch_id" in data

    def test_list_projects(self, temp_db_env):
        """List projects after creating one."""
        runner.invoke(app, ["init", "--json"])
        runner.invoke(app, ["project", "create", "Test Project", "--json"])
        result = runner.invoke(app, ["project", "list", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert len(data) >= 1

    def test_create_branch(self, temp_db_env):
        """Create a branch from an existing project."""
        runner.invoke(app, ["init", "--json"])
        proj_result = runner.invoke(
            app,
            [
                "project",
                "create",
                "Test",
                "--json",
            ],
        )
        proj_data = json.loads(proj_result.stdout)
        result = runner.invoke(
            app,
            [
                "project",
                "create-branch",
                "--project",
                proj_data["project_id"],
                "--name",
                "experimental",
                "--json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["name"] == "experimental"


class TestCLIPolicy:
    def test_add_policy(self, temp_db_env):
        """Add a policy in draft status."""
        runner.invoke(app, ["init", "--json"])
        result = runner.invoke(
            app,
            [
                "policy",
                "add",
                "--effect",
                "deny",
                "--actions",
                '["db.drop"]',
                "--resources",
                '["postgres://cloudhub/**"]',
                "--scope",
                "global",
                "--priority",
                "100",
                "--description",
                "Never drop production",
                "--json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["status"] == "draft"
        assert data["effect"] == "deny"

    def test_submit_policy(self, temp_db_env):
        """Submit a draft policy for approval."""
        runner.invoke(app, ["init", "--json"])
        add_result = runner.invoke(
            app,
            [
                "policy",
                "add",
                "--effect",
                "deny",
                "--actions",
                '["db.drop"]',
                "--resources",
                '["postgres://**"]',
                "--json",
            ],
        )
        policy_id = json.loads(add_result.stdout)["policy_id"]
        result = runner.invoke(app, ["policy", "submit", policy_id, "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["status"] == "pending_approval"

    def test_list_policies(self, temp_db_env):
        """List active policies (should be empty after init)."""
        runner.invoke(app, ["init", "--json"])
        result = runner.invoke(app, ["policy", "list", "--json"])
        assert result.exit_code == 0

    def test_retire_policy(self, temp_db_env):
        """Retire a policy."""
        runner.invoke(app, ["init", "--json"])
        add_result = runner.invoke(
            app,
            [
                "policy",
                "add",
                "--effect",
                "allow",
                "--actions",
                '["db.select"]',
                "--resources",
                '["postgres://**"]',
                "--json",
            ],
        )
        policy_id = json.loads(add_result.stdout)["policy_id"]
        result = runner.invoke(app, ["policy", "retire", policy_id, "--json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["status"] == "retired"


class TestCLIAudit:
    def test_audit_verify_empty(self, temp_db_env):
        """Verify an empty lattice's audit chain."""
        runner.invoke(app, ["init", "--json"])
        result = runner.invoke(
            app,
            [
                "audit",
                "verify",
                "--lattice",
                "nonexistent",
                "--json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["valid"] is True


class TestCLIStatus:
    def test_status_no_branch(self, temp_db_env):
        """Status without --branch should show a message."""
        runner.invoke(app, ["init", "--json"])
        result = runner.invoke(app, ["status", "--json"])
        assert result.exit_code == 0


class TestCLILog:
    def test_log_empty(self, temp_db_env):
        """Log should work even when empty."""
        runner.invoke(app, ["init", "--json"])
        result = runner.invoke(app, ["log", "--json"])
        assert result.exit_code == 0


class TestCLINoSecretLeakage:
    def test_init_output_has_no_password(self, temp_db_env):
        """CLI output must not contain passwords or secrets."""
        runner.invoke(app, ["init", "--json"])
        result = runner.invoke(app, ["register", "--name", "Test", "--type", "agent", "--json"])
        assert "password" not in result.stdout.lower()
        assert "secret" not in result.stdout.lower()
        assert "token" not in result.stdout.lower() or "enrollment" not in result.stdout.lower()

    def test_status_output_has_no_credentials(self, temp_db_env):
        """Status output must not contain database URLs or credentials."""
        runner.invoke(app, ["init", "--json"])
        result = runner.invoke(app, ["status", "--json"])
        assert "postgresql://" not in result.stdout
        assert "password" not in result.stdout.lower()
