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

echo "=== Integration tests (requires PostgreSQL on :5433) ==="
pytest tests/integration -v

echo "=== Concurrency tests ==="
pytest tests/concurrency -v

echo "=== Security tests ==="
pytest tests/security -v

echo ""
echo "ALL VERIFICATION CHECKS PASSED"