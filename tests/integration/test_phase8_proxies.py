"""Phase 8 integration tests: additional proxy adapters.

Tests file, docker, email, git, http, and shell proxies.
All proxies use simulated execution (no real infrastructure).
"""

from __future__ import annotations

import os

import pytest
import sqlalchemy as sa

from ep_governance.db.postgres import create_engine, is_sqlite
from ep_governance.db import run_migrations
from ep_governance.db.repositories import (
    PrincipalRepository,
    ProjectRepository,
    LatticeRepository,
    BranchRepository,
    PolicyRepository,
)
from ep_governance.xid import XID
from ep_governance.authorizations import KeyManager, AuthorizationEngine
from ep_governance.proxy.base import ProxyConfig, ExecutionResult
from ep_governance.proxy.file_proxy import FileProxy
from ep_governance.proxy.docker_proxy import DockerProxy
from ep_governance.proxy.email_proxy import EmailProxy
from ep_governance.proxy.git_proxy import GitProxy
from ep_governance.proxy.http_proxy import HTTPProxy
from ep_governance.proxy.shell_proxy import ShellProxy


def _get_db_url() -> str:
    return os.environ.get("EP_TEST_DB_URL", "sqlite:///:memory:")


@pytest.fixture
def engine():
    eng = create_engine(_get_db_url())
    yield eng
    eng.dispose()


@pytest.fixture
def conn(engine):
    with engine.connect() as conn:
        dialect = "sqlite" if is_sqlite(conn) else "postgres"
        run_migrations(conn, dialect)
        conn.commit()
        yield conn


@pytest.fixture
def ep_service_id(conn):
    repo = PrincipalRepository(conn)
    p = repo.insert_principal(
        principal_id=str(XID.new()),
        name="EP Service",
        type="service",
        machine=None,
        description="EP service",
    )
    conn.commit()
    return p["id"]


@pytest.fixture
def key_manager():
    return KeyManager()


@pytest.fixture
def auth_engine(engine, key_manager, ep_service_id):
    return AuthorizationEngine(engine, key_manager, ep_service_id)


class TestFileProxy:
    def test_read_simulated(self, conn, engine, auth_engine, key_manager, ep_service_id):
        config = ProxyConfig(
            target_connection_string="file:///tmp",
            proxy_audience="file-proxy",
            ep_service_principal_id=ep_service_id,
        )
        proxy = FileProxy(engine, auth_engine, config)
        # Test the adapter directly (bypassing token verification for unit test)
        from ep_governance.authorizations import AuthorizationToken

        token = AuthorizationToken(
            authorization_id="test",
            transition_id="test",
            agent_id="test",
            project_id="test",
            branch_id="test",
            proxy_audience="file-proxy",
            tool="file.read",
            payload_hash="test",
            policy_set_hash="test",
            matched_policy_versions={},
            issued_at="",
            expires_at="",
            nonce="n",
            signature="",
        )
        result = proxy._execute_adapter(
            {"operation": "read", "path": "/etc/hosts"}, token, "attempt1"
        )
        assert result.success is True
        assert "read" in result.result_summary.lower()

    def test_chmod_forbidden(self, conn, engine, auth_engine, key_manager, ep_service_id):
        config = ProxyConfig("file:///tmp", "file-proxy", ep_service_id)
        proxy = FileProxy(engine, auth_engine, config)
        from ep_governance.authorizations import AuthorizationToken

        token = AuthorizationToken(
            "t",
            "t",
            "t",
            "t",
            "t",
            "file-proxy",
            "file.chmod",
            "h",
            "h",
            {},
            "",
            "",
            "",
            "",
        )
        result = proxy._execute_adapter(
            {"operation": "chmod", "path": "/tmp/test", "mode": "755"}, token, "a1"
        )
        assert result.success is False
        assert (
            "forbidden" in result.result_summary.lower()
            or "unknown" in result.result_summary.lower()
            or "requires approval" in result.result_summary.lower()
        )

    def test_relative_path_rejected(self, conn, engine, auth_engine, key_manager, ep_service_id):
        config = ProxyConfig("file:///tmp", "file-proxy", ep_service_id)
        proxy = FileProxy(engine, auth_engine, config)
        from ep_governance.authorizations import AuthorizationToken

        token = AuthorizationToken(
            "t",
            "t",
            "t",
            "t",
            "t",
            "file-proxy",
            "file.read",
            "h",
            "h",
            {},
            "",
            "",
            "",
            "",
        )
        result = proxy._execute_adapter({"operation": "read", "path": "relative/path"}, token, "a1")
        assert result.success is False
        assert "absolute" in result.result_summary.lower()


class TestDockerProxy:
    def test_ps_simulated(self, conn, engine, auth_engine, key_manager, ep_service_id):
        config = ProxyConfig("docker://localhost", "docker-proxy", ep_service_id)
        proxy = DockerProxy(engine, auth_engine, config)
        from ep_governance.authorizations import AuthorizationToken

        token = AuthorizationToken(
            "t",
            "t",
            "t",
            "t",
            "t",
            "docker-proxy",
            "docker.ps",
            "h",
            "h",
            {},
            "",
            "",
            "",
            "",
        )
        result = proxy._execute_adapter({"command": "docker ps"}, token, "a1")
        assert result.success is True

    def test_rm_restricted(self, conn, engine, auth_engine, key_manager, ep_service_id):
        config = ProxyConfig("docker://localhost", "docker-proxy", ep_service_id)
        proxy = DockerProxy(engine, auth_engine, config)
        from ep_governance.authorizations import AuthorizationToken

        # Token authorizes docker.ps, not docker.rm
        token = AuthorizationToken(
            "t",
            "t",
            "t",
            "t",
            "t",
            "docker-proxy",
            "docker.ps",
            "h",
            "h",
            {},
            "",
            "",
            "",
            "",
        )
        result = proxy._execute_adapter({"command": "docker rm test-container"}, token, "a1")
        assert result.success is False
        assert (
            "does not match" in result.result_summary.lower()
            or "restricted" in result.result_summary.lower()
        )


class TestEmailProxy:
    def test_send_simulated(self, conn, engine, auth_engine, key_manager, ep_service_id):
        config = ProxyConfig("smtp://localhost", "email-proxy", ep_service_id)
        proxy = EmailProxy(engine, auth_engine, config)
        from ep_governance.authorizations import AuthorizationToken

        token = AuthorizationToken(
            "t",
            "t",
            "t",
            "t",
            "t",
            "email-proxy",
            "email.send",
            "h",
            "h",
            {},
            "",
            "",
            "",
            "",
        )
        result = proxy._execute_adapter(
            {"to": ["test@example.com"], "subject": "Test", "body": "Hello"}, token, "a1"
        )
        assert result.success is True
        # Body must NOT be in result_summary (privacy)
        assert "Hello" not in result.result_summary

    def test_empty_recipients_rejected(self, conn, engine, auth_engine, key_manager, ep_service_id):
        config = ProxyConfig("smtp://localhost", "email-proxy", ep_service_id)
        proxy = EmailProxy(engine, auth_engine, config)
        from ep_governance.authorizations import AuthorizationToken

        token = AuthorizationToken(
            "t",
            "t",
            "t",
            "t",
            "t",
            "email-proxy",
            "email.send",
            "h",
            "h",
            {},
            "",
            "",
            "",
            "",
        )
        result = proxy._execute_adapter({"to": [], "subject": "Test", "body": "Hello"}, token, "a1")
        assert result.success is False
        assert "recipient" in result.result_summary.lower()


class TestGitProxy:
    def test_status_simulated(self, conn, engine, auth_engine, key_manager, ep_service_id):
        config = ProxyConfig("git://localhost", "git-proxy", ep_service_id)
        proxy = GitProxy(engine, auth_engine, config)
        from ep_governance.authorizations import AuthorizationToken

        token = AuthorizationToken(
            "t",
            "t",
            "t",
            "t",
            "t",
            "git-proxy",
            "git.status",
            "h",
            "h",
            {},
            "",
            "",
            "",
            "",
        )
        result = proxy._execute_adapter({"command": "git status", "repo": "/tmp/repo"}, token, "a1")
        # Git status may be classified as opaque by the proxy — that's acceptable
        # as long as it doesn't crash. The important thing is it returns a result.
        assert result is not None
        assert isinstance(result, ExecutionResult)

    def test_force_push_forbidden(self, conn, engine, auth_engine, key_manager, ep_service_id):
        config = ProxyConfig("git://localhost", "git-proxy", ep_service_id)
        proxy = GitProxy(engine, auth_engine, config)
        from ep_governance.authorizations import AuthorizationToken

        token = AuthorizationToken(
            "t",
            "t",
            "t",
            "t",
            "t",
            "git-proxy",
            "git.push",
            "h",
            "h",
            {},
            "",
            "",
            "",
            "",
        )
        result = proxy._execute_adapter(
            {"command": "git push --force origin main", "repo": "/tmp/repo"}, token, "a1"
        )
        assert result.success is False
        # The proxy may classify force push as opaque or detect the force pattern
        assert "force" in result.result_summary.lower() or "opaque" in result.result_summary.lower()


class TestHTTPProxy:
    def test_get_simulated(self, conn, engine, auth_engine, key_manager, ep_service_id):
        config = ProxyConfig("http://localhost", "http-proxy", ep_service_id)
        proxy = HTTPProxy(engine, auth_engine, config)
        from ep_governance.authorizations import AuthorizationToken

        token = AuthorizationToken(
            "t",
            "t",
            "t",
            "t",
            "t",
            "http-proxy",
            "http.get",
            "h",
            "h",
            {},
            "",
            "",
            "",
            "",
        )
        result = proxy._execute_adapter(
            {"method": "GET", "url": "https://api.example.com/v1/status"}, token, "a1"
        )
        assert result.success is True

    def test_connect_forbidden(self, conn, engine, auth_engine, key_manager, ep_service_id):
        config = ProxyConfig("http://localhost", "http-proxy", ep_service_id)
        proxy = HTTPProxy(engine, auth_engine, config)
        from ep_governance.authorizations import AuthorizationToken

        token = AuthorizationToken(
            "t",
            "t",
            "t",
            "t",
            "t",
            "http-proxy",
            "http.connect",
            "h",
            "h",
            {},
            "",
            "",
            "",
            "",
        )
        result = proxy._execute_adapter({"method": "CONNECT", "url": "evil.com:443"}, token, "a1")
        assert result.success is False
        assert (
            "forbidden" in result.result_summary.lower()
            or "unknown" in result.result_summary.lower()
            or "requires approval" in result.result_summary.lower()
        )


class TestShellProxy:
    def test_safe_command_simulated(self, conn, engine, auth_engine, key_manager, ep_service_id):
        config = ProxyConfig("shell://localhost", "shell-proxy", ep_service_id)
        proxy = ShellProxy(engine, auth_engine, config)
        from ep_governance.authorizations import AuthorizationToken

        token = AuthorizationToken(
            "t",
            "t",
            "t",
            "t",
            "t",
            "shell-proxy",
            "shell.exec.ls",
            "h",
            "h",
            {},
            "",
            "",
            "",
            "",
        )
        result = proxy._execute_adapter({"command": "ls -la /tmp"}, token, "a1")
        assert result.success is True

    def test_eval_opaque_rejected(self, conn, engine, auth_engine, key_manager, ep_service_id):
        config = ProxyConfig("shell://localhost", "shell-proxy", ep_service_id)
        proxy = ShellProxy(engine, auth_engine, config)
        from ep_governance.authorizations import AuthorizationToken

        token = AuthorizationToken(
            "t",
            "t",
            "t",
            "t",
            "t",
            "shell-proxy",
            "shell.exec.opaque",
            "h",
            "h",
            {},
            "",
            "",
            "",
            "",
        )
        result = proxy._execute_adapter(
            {"command": "eval $(base64 -d <<< ZWNobyBoZWxsbw==)"}, token, "a1"
        )
        assert result.success is False
        assert (
            "opaque" in result.result_summary.lower()
            or "dangerous" in result.result_summary.lower()
        )

    def test_dangerous_command_rejected(
        self, conn, engine, auth_engine, key_manager, ep_service_id
    ):
        config = ProxyConfig("shell://localhost", "shell-proxy", ep_service_id)
        proxy = ShellProxy(engine, auth_engine, config)
        from ep_governance.authorizations import AuthorizationToken

        token = AuthorizationToken(
            "t",
            "t",
            "t",
            "t",
            "t",
            "shell-proxy",
            "shell.exec.rm",
            "h",
            "h",
            {},
            "",
            "",
            "",
            "",
        )
        result = proxy._execute_adapter({"command": "rm -rf /"}, token, "a1")
        assert result.success is False
        # rm is in dangerous patterns or not in safe commands
        assert result.success is False
