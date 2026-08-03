# EP-Governance

A binding governance system for AI agents. It maintains a persistent directed acyclic state graph (DAG) with inherited policies and transactional transitions. The graph exists outside any LLM. It governs the execution path, not merely the agent's intentions.

## Status

Enforced mode verified (July 30, 2026). Full pipeline tested:
propose, policy evaluation, Ed25519 token issuance, governed proxy execution,
graph node creation, branch head advancement. Token reuse and payload tampering
rejected. 984 tests collected: 973 passed, 11 skipped (10 require `EP_TEST_DB_URL`,
1 requires PostgreSQL). 4 end-to-end enforced mode tests pass.

## Governing Documents

1. [docs/specification/design-v1.1.md](docs/specification/design-v1.1.md) — architectural specification (v1.1)
2. [docs/specification/formal-semantics-v1.1.1.md](docs/specification/formal-semantics-v1.1.1.md) — controlling formal-semantics addendum (v1.1.1)

Where the two conflict, v1.1.1 governs.

## Documentation

| Document | Description |
|----------|-------------|
| [Getting Started](docs/getting-started.md) | Complete tutorial: zero to first governed execution |
| [Architecture](docs/architecture.md) | System design, components, data flow |
| [Threat Model](docs/threat-model.md) | Assets, trust boundaries, attacks resisted and not resisted |
| [Enforced Mode Deployment](docs/deployment/enforced-mode.md) | Production deployment guide with secrets, networking, TLS |
| [Configuration Reference](docs/reference/configuration.md) | Every environment variable with component, default, description |
| [Operational Runbooks](docs/operations/runbooks.md) | Procedures for production incidents |
| [Security Review Package](docs/security-review-package.md) | Independent review checklist with file locations and questions |

## What EP-Governance Does

- Maintains a persistent DAG outside any LLM that binds any connected model
- Evaluates deterministic policies before authorizing actions
- Issues signed, payload-bound, short-lived, single-use authorization tokens
- Requires a governed proxy to execute consequential actions
- Records all transitions in an append-only hash-chained audit log
- Supports multi-agent concurrency with optimistic branch-head locking
- Exports signed, versioned transfer packages for model switching

## What EP-Governance Does Not Do

- Does not provide cryptographic guarantees against a determined adversary with database access
- Does not allow advisory mode in production (rejected at config load time)
- Does not enforce real compute quotas (BT is a planning budget)
- Does not store operational target credentials (those belong to the proxy)
- Does not replace human judgment for novel situations

## Installation

```bash
git clone https://github.com/pottertech/ep-governance.git
cd ep-governance
pip install -e ".[postgres,crypto,dev]"
ep-governance init
```

See [Getting Started](docs/getting-started.md) for a complete walkthrough including
database setup, signing key generation, principal registration, and your first
governed action.

## Enforced Mode Deployment Requirements

To achieve binding enforcement (not merely advisory):

1. Run the governed proxy as a separate process with access to target credentials.
2. Remove target credentials from the agent's environment.
3. Do not mount Docker sockets, SSH agents, or cloud CLI configs to the agent.
4. Configure network policy so only the proxy can reach sensitive services.
5. Expose only `ep_execute` and governance management tools to the agent.
6. Do not expose raw shell, database, email, Docker, or Git tools to the agent.
7. Lock down the agent runtime (read-only root FS, no credential mounts, non-root, dropped capabilities).
8. Protect the launcher and configuration from agent modification (read-only mounts, admin-owned files).
9. Use narrowly-scoped proxies with least-privilege credentials (separate read-only, write, email, deployment proxies).
10. Run bypass detection reconciliation (target activity log vs EP audit log).
11. In production, advisory mode is rejected at config load time. Set `EP_MODE=enforced`, `EP_ALLOW_ADVISORY_EXECUTION=false`, `EP_REQUIRE_SIGNED_AUTHORIZATION=true`, `EP_FAIL_CLOSED=true`.

Without these deployment measures, EP-Governance operates in advisory mode regardless of the `EP_MODE=enforced` setting. See [Enforced Mode Deployment](docs/deployment/enforced-mode.md) for a complete guide.

## Verification

```bash
./scripts/verify.sh
```

### Test Reproducibility

| Item | Value |
|------|-------|
| Tested commit | pending (this commit) |
| Python | 3.12+ |
| PostgreSQL | 17 (Docker container for PG integration tests) |
| SQLite | Built-in (default for unit/property/contract tests) |
| Total tests collected | 1010 |
| Test results (without PG) | 999 passed, 11 skipped |
| PG integration tests | 10 (skipped without `EP_TEST_DB_URL`; pass with it set) |
| 11th skip | `test_pg_migration_uses_transactional_ddl` (requires PostgreSQL, not just `EP_TEST_DB_URL`) |
| E2e tests | 4 (standalone scripts, run against live PostgreSQL) |
| Test categories | unit (418), property (38), contract (298), integration (154), security (99), concurrency (4) |
| Duration | ~29 seconds (SQLite), ~55 seconds (with PG integration) |
| Skipped tests | PostgreSQL-only tests that require `EP_TEST_DB_URL` environment variable |
| PG integration tests | Set `EP_TEST_DB_URL=postgresql://user:pass@host:port/db` and run `pytest tests/integration/test_pg_integration.py` |
| CI | Not yet configured |

## License

MIT — see LICENSE file.