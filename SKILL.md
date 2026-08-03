# EP-Governance — Hermes Skill

## Binding governance for AI agents

This skill provides the integration point between Hermes agents and the EP-Governance system.

## Deployment

- Mode: enforced (verified July 30, 2026)
- Database: NAS PostgreSQL at 100.98.247.27:5433 (ep_governance schema in gbrain_pilot_test)
- CLI wrapper: `/usr/local/bin/ep-governance`
- MCP server: configured in Hermes config.yaml
- Ed25519 signing key: `ep_signing_test.key` (EP holds private key, proxies hold public key)

## Registered entities

- Agent: Mary Wise (d9ll46fug6j0mqovnr0g)
- Human admin: Skip Potter (d9ln1j7ug6j43bbhclsg)
- EP Service: d9ll4o7ug6j0oak02ck0
- Project: EP-Governance Deployment (d9ll4c7ug6j0neitrvmg)
- Branch: main (d9ll4c7ug6j0neitrvng)
- 6 active governance policies (deny prod DB drops, require approval for deployments/shell/email, warn on git mutations, allow read-only)

## Session bootstrap

At the start of every session, load the current governance state:

```bash
ep-governance status --branch d9ll4c7ug6j0neitrvng --json
```

This gives you:
- Active policy count
- Branch head and version
- Any quarantines or at-risk nodes

## Before consequential actions

Before ANY of the following action types, run `ep-governance check`:

- Database mutations (INSERT, UPDATE, DELETE, DROP)
- Shell execution on production servers
- Docker container operations (stop, rm, restart)
- Git mutations (push, force-push, reset)
- Email sending
- Deployments

```bash
ep-governance check \
  --tool <tool-name> \
  --arguments '<json-arguments>' \
  --branch d9ll4c7ug6j0neitrvng \
  --agent d9ll46fug6j0mqovnr0g \
  --json
```

## Rules

1. If denied: read the policy details, do not proceed, propose an alternative.
2. If pending_approval: wait for human decision.
3. If execution_uncertain: do not assume success or failure. Request reconciliation.
4. Never attempt to bypass the governed proxy in enforced mode.
5. Never attempt to approve your own action.
6. Embeddings are for policy authoring and discovery only -- never for enforcement.
7. Read-only operations (SELECT, ls, cat, status checks) do not require ep_check.

## Operating modes

- Enforced (current): consequential tools available only through ep_execute via the governed proxy. Ed25519-signed authorization tokens, atomic claims, payload verification, credential isolation. Advisory mode is rejected in production (config load time).
- Advisory: agent calls ep_check before actions. No enforcement. Only available in development (EP_DEV=true + EP_ALLOW_ADVISORY_EXECUTION=true).

## Enforced mode pipeline

The full execution path in enforced mode:

1. Agent proposes action via ep_check or ep_execute
2. EP classifies the action server-side (SQL AST, shell parse, etc.)
3. EP evaluates deterministic policies
4. If denied: action rejected, audit event written
5. If require_approval: EP creates approval request, agent waits for human decision
6. If allow/warn or approved: EP issues Ed25519-signed authorization token
   - Token is payload-bound, agent-bound, branch-bound, proxy-bound, single-use, short-lived (5 min TTL)
7. Agent sends token + payload to governed proxy
8. Proxy verifies token signature (Ed25519 public key)
9. Proxy computes payload hash from actual payload, verifies match
10. Proxy verifies transition is in 'authorized' stage (stale authorization guard)
11. Proxy revalidates current policy state (stale authorization detection)
12. Proxy atomically claims token (single UPDATE...WHERE used=FALSE...RETURNING)
13. Proxy executes using its own credentials (agent never sees target credentials)
14. On success: EP creates graph node, advances branch head, appends audit event
15. On failure: EP records failure, no node created
16. On timeout: EP marks execution_uncertain for manual reconciliation

## Verified test results (July 30, 2026)

End-to-end enforced mode test against NAS PostgreSQL:

- TEST 1 PASS: SELECT 1 -> propose -> authorized -> Ed25519 token issued -> proxy verified, claimed, executed -> graph node created -> branch head advanced (v1->v2) -> transition succeeded
- TEST 2 PASS: DROP TABLE -> denied by deny policy (priority 100)
- TEST 3 PASS: Token reuse -> rejected (authorization already claimed)
- TEST 4 PASS: Payload tampering -> hash mismatch detected, execution refused

Total tests: 972 passed, 1 skipped, 0 failed

## MCP tools

The following MCP tools are available (via the ep-governance MCP server):

- ep_check: evaluate a proposed action
- ep_execute: request authorization and execute through governed proxy (enforced mode)
- ep_status: current branch head, policies, BT, risk ledger
- ep_list_policies: list active policies
- ep_log: transition history
- ep_audit: hash-chained event log
- ep_pending_approvals: list pending approval requests
- ep_approve / ep_deny: approve or deny a pending request (human only)
- ep_claim / ep_release_claim: work region management

## Guarantees by mode

### Enforced mode provides:
- Binding enforcement (agent cannot bypass proxy)
- Credential isolation (agent never sees target credentials)
- Ed25519-signed, payload-bound, single-use authorization tokens
- Atomic token claiming (race-free)
- Stale authorization detection (policy set hash comparison)
- Payload tampering detection (hash verification)
- Execution path governance (proxy executes, not agent)
- Policy evaluation and recommendations
- Audit trail (hash-chained, append-only)
- Risk assessment
- Structural state tracking (DAG with branch heads)

### Advisory mode provides:
- Policy evaluation and recommendations
- Audit trail (hash-chained, append-only)
- Risk assessment
- Structural state tracking (DAG with branch heads)

### Advisory mode does NOT provide:
- Binding enforcement (agent can bypass the gate)
- Credential isolation
- Execution path governance