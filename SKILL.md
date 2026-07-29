# EP-Governance — Hermes Skill

## Binding governance for AI agents

This skill provides the integration point between Hermes agents and the EP-Governance system.

## When to use

- Before any consequential action (advisory mode): call `ep_check`
- To execute a governed action (enforced mode): call `ep_execute`
- To manage policies, branches, approvals, and state: use the CLI or MCP tools

## Setup

1. Initialize: `ep-governance init`
2. Register: `ep-governance register --name "Mary Wise" --type agent --enrollment-token <token>`
3. Resume or create project: `ep-governance resume --project <id> --branch <id>` or `ep-governance create-project "Project Name"`
4. Bootstrap loads active policies, branch head, BT, risk ledger, quarantines, work claims, and pending approvals from the database.

## Operating modes

- **Advisory**: agent calls `ep_check` before actions. No enforcement.
- **Enforced**: consequential tools available only through `ep_execute` via the governed proxy. Agent has no direct infrastructure credentials.

## Guarantees by mode

### Advisory mode provides:
- Policy evaluation and recommendations
- Audit trail
- Risk assessment
- Structural state tracking

### Advisory mode does NOT provide:
- Binding enforcement (agent can bypass the gate)
- Credential isolation
- Execution path governance

### Enforced mode (with deployment isolation) additionally provides:
- Binding execution-path governance
- Credential isolation
- Atomic authorization claiming
- Stale authorization detection
- Authenticated proxy results

## Rules

1. If denied: read the policy details, do not proceed, propose an alternative.
2. If `pending_approval`: wait for human decision.
3. If `execution_uncertain`: do not assume success or failure. Request reconciliation.
4. Never attempt to bypass the governed proxy in enforced mode.
5. Never attempt to approve your own action.
6. Embeddings are for policy authoring and discovery only — never for enforcement.