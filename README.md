# EP-Governance

A binding governance system for AI agents. It maintains a persistent directed acyclic state graph (DAG) with inherited policies and transactional transitions. The graph exists outside any LLM. It governs the execution path, not merely the agent's intentions.

## Status

Enforced mode verified (July 30, 2026). Full pipeline tested against NAS PostgreSQL:
propose, policy evaluation, Ed25519 token issuance, governed proxy execution,
graph node creation, branch head advancement. Token reuse and payload tampering
rejected. 861 unit/property/contract tests pass, 4 end-to-end enforced mode tests pass.

## Governing Documents

1. `ep-governance-design-v1.1.md` — architectural specification (v1.1)
2. `ep-governance-design-v1.1.1.md` — controlling formal-semantics addendum (v1.1.1)

Where the two conflict, v1.1.1 governs.

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
- Does not prevent an agent from bypassing governance in advisory mode
- Does not enforce real compute quotas (BT is a planning budget)
- Does not store operational target credentials (those belong to the proxy)
- Does not replace human judgment for novel situations

## Installation

```bash
git clone git@github.com:pottertech/ep-governance.git
cd ep-governance
pip install -e ".[postgres,crypto,dev]"
ep-governance init
```

## Enforced Mode Deployment Requirements

To achieve binding enforcement (not merely advisory):

1. Run the governed proxy as a separate process with access to target credentials.
2. Remove target credentials from the agent's environment.
3. Do not mount Docker sockets, SSH agents, or cloud CLI configs to the agent.
4. Configure network policy so only the proxy can reach sensitive services.
5. Expose only `ep_execute` and governance management tools to the agent.
6. Do not expose raw shell, database, email, Docker, or Git tools to the agent.

Without these deployment measures, EP-Governance operates in advisory mode regardless of the `EP_MODE=enforced` setting.

## Verification

```bash
./scripts/verify.sh
```

## License

MIT — see LICENSE file.