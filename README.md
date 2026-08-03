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

## Security Boundaries and Responsibilities Outside EP-Governance

EP-Governance is the **decision and accountability layer**. Several capabilities are intentionally delegated to other layers rather than omitted.

### Tamper evidence vs. database administrator

EP-Governance uses Ed25519 signatures, payload hashes, single-use authorization tokens, and hash-chained audit records to detect tampering and prove internal consistency. This provides tamper evidence under its stated trust model — not cryptographic guarantees against an adversary who controls the database, application, and keys. Stronger guarantees require external trust anchors: HSM-held signing keys, audit checkpoints published to immutable external storage, append-only WORM logging, remote transparency logs, independent timestamping, or replicas controlled by different administrators.

### Advisory mode is for development only

Advisory mode tells the agent what it should do but does not place EP-Governance in the execution path. An agent can ignore the recommendation and act directly. Advisory mode is available only in development (EP_DEV=true + EP_ALLOW_ADVISORY_EXECUTION=true) and is rejected at config load time in production. Actual prevention requires enforced mode, where the agent lacks direct access to the operational target and must go through an EP-controlled proxy.

EP_MODE=enforced is a request, not a guarantee. The deployment verification module (deployment.py) checks isolation conditions at startup and computes an effective mode. If any required check fails (target credentials in env, Docker socket accessible, raw tools in manifest, proxy not separate, network not restricted), the effective mode downgrades to advisory with reasons. The CLI serve command prints the enforcement report and uses the effective mode, not the requested mode.

### BT is a planning budget, not a compute quota

EP-Governance can assign a proposed action a budget value and reject actions that exceed the planned allowance. It cannot measure or enforce actual CPU, GPU, RAM, API tokens, network bandwidth, storage I/O, or cloud spending. Real enforcement requires infrastructure-specific controls: Linux cgroups, Kubernetes resource limits, Docker constraints, cloud-provider budget APIs, LLM token metering, database statement limits, process timeouts, network quotas, GPU schedulers.

### Operational credentials belong to proxies, not EP-Governance

EP-Governance decides whether an action is authorized. It does not store database passwords, API keys, SSH keys, cloud credentials, or service tokens. Each proxy holds the minimum credential needed for its category of action. This prevents the governance database from becoming a high-value centralized secrets vault. In production, proxies should obtain credentials from Vault, AWS Secrets Manager, Azure Key Vault, Google Secret Manager, an HSM, workload identity, or short-lived credentials.

### Human judgment for novel situations

Policies work well when conditions can be represented in advance. They are less reliable when the situation is unprecedented, consequences are unclear, policies conflict, context is missing, or ethical/legal interpretation is required. EP-Governance can deny known-dangerous actions, require approval, preserve evidence, enforce separation of duties, detect policy conflicts, and route uncertainty to humans. It cannot guarantee good judgment in every novel circumstance. Uncertainty should produce escalation, not a false claim that the policy engine can resolve every situation.

### Layered architecture

```text
EP-Governance          — determines permission, records governance state
Trusted proxies        — enforce approved actions, hold target credentials
Infrastructure         — enforces CPU, memory, network, storage, process limits
Secret manager         — protects operational credentials
External audit anchor  — protects against database-level tampering
Human reviewers        — resolve novelty, ambiguity, ethics, exceptional risk
```

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
12. Provide deployment assertions (EP_ASSERT_* env vars) or an explicit EnforcementAttestation so the deployment verifier can confirm isolation. Without attestation, effective mode downgrades to advisory even when EP_MODE=enforced.

Without these deployment measures, EP-Governance operates in advisory mode regardless of the `EP_MODE=enforced` setting. See [Enforced Mode Deployment](docs/deployment/enforced-mode.md) for a complete guide.

## Verification

```bash
./scripts/verify.sh
```

### Test Reproducibility

| Item | Value |
|------|-------|
| Tested commit | `569af01` (August 2, 2026) |
| Python | 3.12+ |
| PostgreSQL | 17 (Docker container for PG integration tests) |
| SQLite | Built-in (default for unit/property/contract tests) |
| Total tests collected | 1118 |
| Test results (without PG) | 1107 passed, 11 skipped |
| PG integration tests | 10 (skipped without `EP_TEST_DB_URL`; pass with it set) |
| 11th skip | `test_pg_migration_uses_transactional_ddl` (requires PostgreSQL, not just `EP_TEST_DB_URL`) |
| E2e tests | 4 (standalone scripts, run against live PostgreSQL) |
| Test categories | unit (418), property (38), contract (310), integration (154), security (169), concurrency (4) |
| Duration | ~29 seconds (SQLite), ~55 seconds (with PG integration) |
| Skipped tests | PostgreSQL-only tests that require `EP_TEST_DB_URL` environment variable |
| PG integration tests | Set `EP_TEST_DB_URL=postgresql://user:pass@host:port/db` and run `pytest tests/integration/test_pg_integration.py` |
| CI | Not yet configured |

## License

MIT — see LICENSE file.