#!/usr/bin/env bash
# EP-Governance verification script
# Fails on any required test, lint, type, schema, or migration error.
set -euo pipefail

echo "=== Ruff lint ==="
ruff check .

echo "=== Ruff format check ==="
ruff format --check .

echo "=== Mypy type check ==="
mypy src

echo "=== Unit tests ==="
pytest tests/unit -v

echo "=== Property tests ==="
pytest tests/property -v

echo "=== Contract tests ==="
pytest tests/contracts -v

echo "=== Integration tests (PostgreSQL on :5432 via CI service, or :5433 for local NAS) ==="
pytest tests/integration -v

echo "=== Concurrency tests ==="
pytest tests/concurrency -v

echo "=== Security tests ==="
pytest tests/security -v

echo ""
echo "ALL VERIFICATION CHECKS PASSED"