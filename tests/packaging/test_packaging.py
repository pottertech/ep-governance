"""Packaging regression tests -- verify the package installs and CLI works.

These tests verify that:
1. pyproject.toml is valid and parseable
2. The package metadata is correct
3. The CLI entry point is defined
4. All required dependencies are listed
5. The package can be imported after installation
6. The CLI --help works
7. The migrations are present
"""

import os
import subprocess
import sys
import tempfile

import pytest


REPO_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")


def test_pyproject_toml_exists():
    """pyproject.toml exists at repo root."""
    path = os.path.join(REPO_ROOT, "pyproject.toml")
    assert os.path.isfile(path), f"pyproject.toml not found at {path}"


def test_pyproject_toml_parseable():
    """pyproject.toml can be parsed."""
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib

    path = os.path.join(REPO_ROOT, "pyproject.toml")
    with open(path, "rb") as f:
        data = tomllib.load(f)

    assert "project" in data, "Missing [project] section"
    assert data["project"]["name"] == "ep-governance"
    assert "version" in data["project"]
    assert "python_requires" in data["project"] or "requires-python" in data["project"]


def test_cli_entry_point_defined():
    """CLI entry point is defined in pyproject.toml."""
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib

    path = os.path.join(REPO_ROOT, "pyproject.toml")
    with open(path, "rb") as f:
        data = tomllib.load(f)

    scripts = data.get("project", {}).get("scripts", {})
    assert "ep-governance" in scripts, "Missing ep-governance CLI entry point"
    assert "ep_governance.cli" in scripts["ep-governance"]


def test_dependencies_listed():
    """Required dependencies are listed in pyproject.toml."""
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib

    path = os.path.join(REPO_ROOT, "pyproject.toml")
    with open(path, "rb") as f:
        data = tomllib.load(f)

    deps = data.get("project", {}).get("dependencies", [])
    dep_names = [d.split(">=")[0].split("==")[0].split("<")[0].strip() for d in deps]

    # Core dependencies that must be present
    required = ["sqlalchemy", "pydantic"]
    for req in required:
        assert any(req in d.lower() for d in dep_names), f"Missing dependency: {req}"


def test_optional_dependencies_listed():
    """Optional dependency groups are defined."""
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib

    path = os.path.join(REPO_ROOT, "pyproject.toml")
    with open(path, "rb") as f:
        data = tomllib.load(f)

    optional = data.get("project", {}).get("optional-dependencies", {})
    assert "postgres" in optional, "Missing [postgres] optional dependency group"
    assert "crypto" in optional, "Missing [crypto] optional dependency group"


def test_package_importable():
    """The ep_governance package can be imported."""
    # Add src to path
    src_path = os.path.join(REPO_ROOT, "src")
    sys.path.insert(0, src_path)
    try:
        import ep_governance
        assert hasattr(ep_governance, "__name__")
    finally:
        sys.path.remove(src_path)


def test_cli_help_works():
    """The CLI --help command works."""
    src_path = os.path.join(REPO_ROOT, "src")
    env = {**os.environ, "PYTHONPATH": src_path}
    result = subprocess.run(
        [sys.executable, "-m", "ep_governance.cli", "--help"],
        capture_output=True, text=True, timeout=10, env=env,
        cwd=REPO_ROOT,
    )
    assert result.returncode == 0, f"CLI --help failed: {result.stderr}"
    assert "ep-governance" in result.stdout.lower() or "Usage" in result.stdout


def test_migrations_present():
    """Migration files are present."""
    pg_migrations = os.path.join(REPO_ROOT, "migrations", "postgres")
    sqlite_migrations = os.path.join(REPO_ROOT, "migrations", "sqlite")

    assert os.path.isdir(pg_migrations), "PostgreSQL migrations directory missing"
    assert os.path.isdir(sqlite_migrations), "SQLite migrations directory missing"

    pg_files = [f for f in os.listdir(pg_migrations) if f.endswith(".sql")]
    sqlite_files = [f for f in os.listdir(sqlite_migrations) if f.endswith(".sql")]

    assert len(pg_files) >= 2, f"Expected at least 2 PostgreSQL migrations, got {pg_files}"
    assert len(sqlite_files) >= 1, f"Expected at least 1 SQLite migration, got {sqlite_files}"


def test_requirements_lock_exists():
    """requirements.lock file exists for reproducible installs."""
    path = os.path.join(REPO_ROOT, "requirements.lock")
    assert os.path.isfile(path), "requirements.lock not found"

    with open(path) as f:
        content = f.read()
    # Should contain at least some pinned versions
    assert "==" in content, "requirements.lock should contain pinned versions"


def test_env_example_exists():
    """env.example file exists for configuration reference."""
    path = os.path.join(REPO_ROOT, ".env.example")
    assert os.path.isfile(path), ".env.example not found"

    with open(path) as f:
        content = f.read()
    assert "EP_DB_URL" in content, ".env.example should document EP_DB_URL"
    assert "EP_MODE" in content, ".env.example should document EP_MODE"


def test_docker_files_present():
    """Docker proxy files are present."""
    dockerfile = os.path.join(REPO_ROOT, "docker", "proxy", "Dockerfile")
    compose = os.path.join(REPO_ROOT, "docker", "proxy", "docker-compose.proxy.yml")
    requirements = os.path.join(REPO_ROOT, "docker", "proxy", "requirements-proxy.txt")

    assert os.path.isfile(dockerfile), "Proxy Dockerfile not found"
    assert os.path.isfile(compose), "docker-compose.proxy.yml not found"
    assert os.path.isfile(requirements), "requirements-proxy.txt not found"