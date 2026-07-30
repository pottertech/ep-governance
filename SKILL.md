# EP-Governance — Hermes Skill

## Binding governance for AI agents

This skill provides the integration point between Hermes agents and the EP-Governance system.

## Deployment

- Mode: advisory
- Database: NAS PostgreSQL (ep_governance schema)
- CLI wrapper: `/usr/local/bin/ep-governance`
- MCP server: configured in Hermes config.yaml

## Registered entities

- Agent: Mary Wise (d9ll46fug6j0mqovnr0g)
- Human admin: Skip Potter (d9ln1j7ug6j43bbhclsg)
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

- Advisory (current): agent calls ep_check before actions. No enforcement.
- Enforced (future): consequential tools available only through ep_execute via the governed proxy.

## Guarantees by mode

### Advisory mode provides:
- Policy evaluation and recommendations
- Audit trail (hash-chained, append-only)
- Risk assessment
- Structural state tracking (DAG with branch heads)

### Advisory mode does NOT provide:
- Binding enforcement (agent can bypass the gate)
- Credential isolation
- Execution path governance

## MCP tools

The following MCP tools are available (via the ep-governance MCP server):

- ep_check: evaluate a proposed action
- ep_status: current branch head, policies, BT, risk ledger
- ep_list_policies: list active policies
- ep_log: transition history
- ep_audit: hash-chained event log
- ep_pending_approvals: list pending approval requests
- ep_approve / ep_deny: approve or deny a pending request (human only)
- ep_claim / ep_release_claim: work region management