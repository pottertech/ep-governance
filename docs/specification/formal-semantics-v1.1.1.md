# EP-Governance: v1.1.1 Formal-Semantics Addendum

## Version: 1.1.1
## Date: July 28, 2026
## Status: Clarification addendum to v1.1
## Purpose: Resolve 8 specific items before implementation begins

---

## 1. Branch Model: One Branch, One Head

### Problem

v1.1 said two transitions from the same parent could both commit to the same branch. But a branch has one `head_node_id`, and each node has one `branch_id`. Two children of the same parent cannot both be the head of the same branch.

### Correction

A branch always has exactly one head. A successful transition advances exactly one branch head. Divergence requires creating a new branch.

When two transitions originate from the same head:

1. The first may advance the existing branch: `branch.head_node_id = new_node`, `branch.version += 1`.
2. The second must fail with `stale_head` (expected_head_id or expected_version mismatch).
3. To proceed, the second agent explicitly creates a new branch: `ep-governance create-branch --project <id> --name "experimental" --from-branch main`.

Rule:

```
A branch always has one head.
A successful transition advances exactly one branch head.
Divergence requires creation of another branch.
```

### Schema Change

No schema change needed. The existing `ep_branches` table with `head_node_id` and `version` already supports this. The `ep_governance create-branch` command creates a new branch row and a new edge from the parent branch's head to the new branch's first node.

### CLI Change

```
ep-governance create-branch --project <id> --name "experimental" --from-branch main
```

This creates a new branch, sets its head to the parent branch's current head, and links the new branch to the project. The first transition on the new branch advances from that head.

---

## 2. Only Realized States Become Graph Nodes

### Problem

v1.1 listed `proposed`, `authorized`, `executing`, `failed`, `denied`, `cancelled`, `expired` as node statuses in `ep_nodes`. But denied proposals never enter the graph, and only successfully executed states become committed nodes. Intention states should not be stored as graph nodes.

### Correction

**`ep_transitions`** holds proposed and executing actions (the full lifecycle: proposed -> authorized -> executing -> succeeded/failed/cancelled/expired/denied/pending_approval).

**`ep_nodes`** represents only realized or historically committed states:

| Status | Meaning |
|--------|---------|
| `committed` | Execution succeeded. This is an active state in the graph. |
| `quarantined` | An existing committed state later found unsafe. Under repair. |
| `at_risk` | Downstream of a quarantined node. Requires review. |
| `superseded` | Replaced by a newer committed node on the same branch. |
| `archived` | No longer active but retained for audit. |

A new `ep_node` row is inserted ONLY when a transition reaches `succeeded`. The transition's `to_node_id` links the transition to the realized node.

### Schema Change

`ep_nodes.status` CHECK constraint changes to:

```sql
CHECK (status IN ('committed', 'quarantined', 'at_risk', 'superseded', 'archived'))
```

Transition stages remain in `ep_transitions.stage`:

```sql
CHECK (stage IN ('proposed', 'authorized', 'executing', 'succeeded', 'failed',
                 'cancelled', 'expired', 'denied', 'pending_approval'))
```

### Transition Record Shape

A transition contains the proposed state inline rather than as a graph node:

```json
{
  "transition_id": "cjvbbzh6qgtnoxiaa003",
  "stage": "succeeded",
  "proposed_state": {
    "description": "Run docker stop open-webui on cloudhub",
    "bt_delta": -10.0,
    "metadata": {"host": "cloudhub", "action": "docker stop open-webui"}
  },
  "expected_effect": {
    "action_type": "deployment",
    "target": "host:cloudhub/container:open-webui",
    "risk_domain": "deployment"
  },
  "resulting_state": {
    "node_id": "cjvbbzh6qgtnoxiaa007",
    "bt_after": 90.0,
    "committed_at": "2026-07-28T12:00:02Z"
  }
}
```

Only `resulting_state.node_id` references an `ep_node` row, and only when `stage = succeeded`.

---

## 3. Authorization-Token Claiming Is Atomic

### Problem

v1.1 said the token is single-use with a `used` boolean. Two proxy requests could read `used = false` simultaneously and both execute.

### Correction

Token claiming is an atomic database operation:

```sql
UPDATE ep_authorizations
SET used = TRUE,
    used_at = NOW()
WHERE id = :authorization_id
  AND used = FALSE
  AND expires_at > NOW()
RETURNING id, transition_id, payload_hash, policy_set_hash;
```

If no row is returned, execution must stop. The token is either already used, expired, or does not exist.

This UPDATE is atomic in PostgreSQL -- the row lock prevents concurrent claims. In SQLite, the same statement works under `BEGIN IMMEDIATE` serialization.

The claim occurs in the same transaction that advances the transition to `executing`:

```sql
BEGIN;
-- 1. Atomically claim the authorization token
UPDATE ep_authorizations SET used = TRUE, used_at = NOW()
WHERE id = :auth_id AND used = FALSE AND expires_at > NOW()
RETURNING id, transition_id, payload_hash;

-- If no row returned: ROLLBACK, return "token invalid or expired"

-- 2. Advance transition to executing
UPDATE ep_transitions SET stage = 'executing',
    execution_started_at = NOW(),
    executor_id = :proxy_principal_id
WHERE id = :transition_id AND stage = 'authorized';

-- 3. COMMIT
COMMIT;
```

---

## 4. Audit Hashing Includes the Full Canonical Event Envelope

### Problem

v1.1 hashed `SHA-256(event_data || previous_hash)`. This does not protect `event_type`, `principal_id`, `created_at`, or `sequence`. Someone could alter metadata without breaking the chain.

### Correction

The event hash covers the complete immutable event envelope using canonical JSON serialization:

```python
canonical_envelope = canonical_json({
    "sequence": event.sequence,
    "event_id": event.id,
    "event_type": event.event_type,
    "event_data": event.event_data,
    "principal_id": event.principal_id,
    "created_at": event.created_at,  # ISO 8601 UTC, no timezone offset
    "previous_hash": event.previous_hash
})

event.event_hash = sha256(canonical_envelope.encode("utf-8")).hexdigest()
```

### Canonical JSON Serialization Rules

1. **UTF-8** encoding throughout.
2. **Sorted object keys** (alphabetical, recursive).
3. **No insignificant whitespace** (no spaces after separators).
4. **Timestamp format**: ISO 8601 UTC (`YYYY-MM-DDTHH:MM:SS.ffffffZ`), no timezone offset.
5. **Number representation**: integers as integers, floats with full precision, no trailing zeros.
6. **Null**: represented as `null`.
7. **Booleans**: `true` or `false`.
8. **Arrays**: preserve insertion order (arrays are ordered, objects are not).
9. **No duplicate keys** in objects.
10. **No comments**.

### Verification

Any party can verify the chain by recomputing each event hash from the canonical envelope and checking that each `previous_hash` matches the preceding event's `event_hash`.

---

## 5. Audit Insertion Is Serialized and Performed Only by Trusted EP Code

### Problem

v1.1 said agents and proxies can INSERT into `ep_events` but not UPDATE or DELETE. Append-only does not mean trustworthy -- a malicious agent could insert fabricated events.

### Correction

**Only the EP-Governance service writes audit events.** Agents and proxies submit operations to EP. EP authenticates the caller, performs the operation, and writes the resulting audit event.

### Actor Separation

Each audit event records three identities:

| Field | Description |
|-------|-------------|
| `actor_principal_id` | The agent or human responsible for the operation |
| `authenticated_caller_id` | The principal that authenticated to EP for this call |
| `event_writer_id` | Always the EP service principal (trusted writer) |

This separates the entity responsible for the action from the trusted service that recorded it.

### Serialization: Per-Lattice Audit Heads

A global sequence and hash chain require each event to know the immediately preceding event. Two concurrent writers cannot independently insert the next event.

Solution: per-lattice audit heads with row locking.

```sql
CREATE TABLE ep_audit_heads (
    lattice_id   TEXT PRIMARY KEY,  -- FK to ep_lattices
    last_sequence   BIGINT NOT NULL DEFAULT 0,
    last_hash       TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000'
);
```

Insert procedure (PostgreSQL):

```sql
BEGIN;
-- 1. Lock the audit head for this lattice
SELECT last_sequence, last_hash FROM ep_audit_heads
WHERE lattice_id = :lattice_id
FOR UPDATE;

-- 2. Compute next sequence and hash
-- next_sequence = last_sequence + 1
-- canonical_envelope = canonical_json({...previous_hash: last_hash...})
-- event_hash = sha256(canonical_envelope)

-- 3. Insert the event
INSERT INTO ep_events (id, sequence, event_type, event_data, previous_hash,
                        event_hash, actor_principal_id, authenticated_caller_id,
                        event_writer_id, lattice_id, created_at)
VALUES (...);

-- 4. Update the audit head
UPDATE ep_audit_heads SET last_sequence = :next_sequence, last_hash = :event_hash
WHERE lattice_id = :lattice_id;

COMMIT;
```

For SQLite: `BEGIN IMMEDIATE` provides the equivalent serialization.

Per-lattice chains reduce contention compared to one global chain. Each lattice has its own independent hash chain.

### Database Permissions

- `ep_events`: only the EP service role can INSERT. No role can UPDATE or DELETE.
- `ep_audit_heads`: only the EP service role can SELECT (FOR UPDATE), INSERT, and UPDATE.
- Agents and proxies authenticate to EP via API key or token. EP validates the credential, performs the operation, and writes the event. The agent never touches `ep_events` directly.

---

## 6. Policy Activation and Approval Separation

### Problem

v1.1 said global policies require human co-approval, but the schema allows a policy to be inserted directly as `active`. There is no activation workflow. Also, a `policy_approver` could approve their own request (separation of duties not defined).

### Correction

### Policy Lifecycle

Policies have their own lifecycle:

```
draft -> pending_approval -> active -> superseded -> retired
                      \-> rejected
```

| Status | Meaning |
|--------|---------|
| `draft` | Created but not submitted for approval. No enforcement effect. |
| `pending_approval` | Submitted for approval. No enforcement effect yet. |
| `active` | Approved and effective. Enforced by the gate. |
| `rejected` | Approval was denied. Never takes effect. |
| `superseded` | Replaced by a newer active policy. |
| `retired` | Explicitly retired. No longer enforced. |

A policy has NO enforcement effect until it reaches `active`.

### Policy Schema Additions

| Field | Type | Description |
|-------|------|-------------|
| `created_by` | TEXT (XID) | FK to ep_principals (who authored the policy) |
| `approved_by` | TEXT (XID) | FK to ep_principals (who approved it, nullable) |
| `approved_at` | TIMESTAMPTZ | When approved (nullable) |
| `activation_version` | INTEGER | Policy version set this policy belongs to when activated |
| `exception_to` | JSONB | Array of policy XIDs this policy explicitly overrides (nullable) |
| `valid_from` | TIMESTAMPTZ | When the policy takes effect (nullable = immediate upon activation) |
| `valid_until` | TIMESTAMPTZ | When the policy expires (nullable = permanent) |

CHECK constraint: `status IN ('draft', 'pending_approval', 'active', 'rejected', 'superseded', 'retired')`

### Approval Workflow

1. `policy_author` creates a policy in `draft` status.
2. `policy_author` submits it: `ep-governance submit-policy <xid>`. Status becomes `pending_approval`.
3. For agent-scoped policies: `policy_approver` can approve. Status becomes `active`.
4. For global policies: a `human` principal must co-approve. Status becomes `active` only after human approval.
5. `policy_approver` can reject: status becomes `rejected`.

### Separation of Duties

For all approval and override actions:

```sql
CHECK (decided_by != requested_by)
```

The principal who requested an action cannot approve or override it. This applies to:
- `ep_approval_requests`: `decided_by != requested_by`
- `ep_override_records`: `overridden_by !=` the principal who proposed the transition

For especially sensitive operations (global policy changes, overrides of `deny` policies with priority >= 100):
- Require a `human` principal as the approver (not an agent).
- The payload must be frozen and hashed before approval (the approver sees exactly what they are approving).

### Override Restrictions

An `allow` policy overrides a `deny` only when:

1. `exception_to` explicitly lists the policy XID being overridden.
2. The override policy is created by a `policy_author` or higher.
3. The override is more narrowly scoped (fewer resources or more specific actions).
4. `valid_until` is set (time-limited, not permanent).
5. The overridden policy's approval requirements are satisfied (if the original required human approval, the override requires human approval).
6. `justification` field is non-empty.

Priority alone does not confer authority. A `priority: 101` allow does not automatically override a `priority: 100` deny without the above controls.

---

## 7. Risk-Ledger Terminology Replaces Remaining UT Cost Model

### Problem

v1.1 redefined UT as a per-domain risk ledger but the schema and API still used `ut_cost`, `ut_deltas`, `ut_after` terminology from the old single-number model.

### Correction

### Terminology Mapping

| Old (v1.1) | New (v1.1.1) |
|-----------|-------------|
| `ut_cost` | `risk_increment` |
| `ut_deltas` | `risk_assessments` |
| `ut_after` | `residual_risk_after` |

### API Representation

Replace the v1.1 execute output:

```json
{
  "ut_after": {
    "deployment": 55.0,
    "production_database": 70.0
  }
}
```

With:

```json
{
  "risk_assessment": {
    "domain": "deployment",
    "inherent_risk": 80.0,
    "mitigation_credit": 25.0,
    "residual_risk": 55.0,
    "threshold": 50.0,
    "decision": "require_approval",
    "accepted_by": null,
    "accepted_at": null,
    "expiration": null
  },
  "residual_risk_after": {
    "deployment": 55.0,
    "production_database": 70.0
  }
}
```

### Schema Changes

`ep_transitions`:

| Old Column | New Column | Description |
|-----------|-----------|-------------|
| `ut_deltas` | `risk_assessments` | JSONB: per-domain risk assessment at proposal time |
| (none) | `residual_risk_after` | JSONB: per-domain residual risk after execution |

`risk_assessments` JSONB shape:

```json
{
  "deployment": {
    "risk_increment": 25.0,
    "inherent_risk": 80.0,
    "mitigation_credit": 0.0,
    "residual_risk": 80.0,
    "threshold": 50.0,
    "decision": "require_approval"
  }
}
```

### Mitigation Verification

Mitigations require verified evidence, not agent self-attestation.

`ep_risk_mitigations` additions:

| Field | Type | Description |
|-------|------|-------------|
| `evidence_type` | TEXT | 'backup_verified', 'audit_completed', 'test_passed', 'external_verification' |
| `evidence_uri` | TEXT | URI to the evidence (e.g., backup log path, test report) |
| `evidence_hash` | TEXT | Hash of the evidence content (for integrity verification) |
| `verified_by` | TEXT (XID) | FK to ep_principals (who verified this mitigation) |
| `verified_at` | TIMESTAMPTZ | When verified |
| `expires_at` | TIMESTAMPTZ | When this mitigation expires (must be re-verified) |
| `scope` | TEXT | Risk domain this mitigation applies to |

Mitigation credit limits come from policy, not from the submitting agent. An agent cannot claim "backup_verified, credit 50" -- a `policy_approver` or `operator` must verify the evidence and set the credit.

---

## 8. Enforced Mode Requires Runtime Capability Isolation

### Problem

v1.1 said the governed proxy holds credentials, but enforcement depends on actual capability separation. An agent with local shell access, Docker socket, SSH keys, or cloud CLI credentials can bypass the proxy entirely.

### Correction

### Deployment Rule for Enforced Mode

In enforced mode, the following must be true:

1. **Direct consequential tools are not exposed to the agent.** The agent's MCP tools and CLI do not include raw `shell.exec`, `postgres.execute`, `email.send`, `docker.*`, or `git.*` tools. Only `ep_check`, `ep_execute`, and governance management tools are available.

2. **Target credentials are absent from the agent process.** SSH keys, database passwords, email credentials, API tokens, and cloud CLI configuration are not present in the agent's environment variables, files, or mounted volumes.

3. **Docker sockets and SSH agents are not mounted.** The agent process cannot reach `docker.sock` or an SSH agent socket.

4. **Network access to protected services is restricted.** Where feasible, network policy (firewall, Tailscale ACLs, service mesh) restricts which identities can reach sensitive targets. Only the proxy's network identity can reach the database, SSH endpoints, or email servers.

5. **Only the proxy network identity can reach sensitive targets.** The proxy runs as a separate process or container with its own network identity and credentials.

### Implementation Notes

This is a deployment constraint, not purely a software constraint. EP-Governance cannot enforce capability isolation by itself -- it depends on the runtime environment.

The SKILL.md and README.md should document the deployment requirements clearly:

```text
## Enforced Mode Deployment Requirements

To achieve binding enforcement (not merely advisory):

1. Run the governed proxy as a separate process with access to target credentials.
2. Remove target credentials from the agent's environment.
3. Do not mount Docker sockets, SSH agents, or cloud CLI configs to the agent.
4. Configure network policy so only the proxy can reach sensitive services.
5. Expose only ep_execute and governance management tools to the agent.
6. Do not expose raw shell, database, email, Docker, or Git tools to the agent.

Without these deployment measures, EP-Governance operates in advisory mode
regardless of the EP_MODE=enforced setting.
```

### Advisory Mode Acknowledgment

In advisory mode (or enforced mode without deployment isolation), the system provides:
- Policy evaluation and recommendations
- Audit trail
- Risk assessment
- Structural state tracking

But it does NOT provide:
- Binding enforcement (agent can bypass the gate)
- Credential isolation (agent has direct infrastructure access)
- Execution path governance (agent can call tools directly)

The SKILL.md should be explicit about which guarantees hold in which mode.

---

## Summary of All Changes

| # | Issue | Resolution |
|---|-------|-----------|
| 1 | Branch model inconsistency | One branch, one head. Divergence creates a new branch. |
| 2 | Proposed states as graph nodes | Only realized states become ep_nodes. Transitions hold proposed/intermediate states. |
| 3 | Non-atomic token claiming | Atomic UPDATE ... WHERE used = FALSE ... RETURNING. Same transaction as stage advancement. |
| 4 | Incomplete audit hashing | Full canonical envelope: sequence, event_id, event_type, event_data, principal_id, created_at, previous_hash. Canonical JSON rules defined. |
| 5 | Concurrent audit insertion | Per-lattice audit heads with row locking. Only EP service writes events. Actor separation: actor, authenticated_caller, event_writer. |
| 6 | Policy activation workflow | Policy lifecycle: draft -> pending_approval -> active -> rejected/superseded/retired. Separation of duties: decided_by != requested_by. Override restrictions: exception_to, narrow scope, time-limited, justified. |
| 7 | UT terminology inconsistency | Replace ut_cost/ut_deltas/ut_after with risk_increment/risk_assessments/residual_risk_after. Mitigations require verified evidence. |
| 8 | Runtime capability isolation | Enforced mode requires: no direct tools to agent, no credentials in agent env, no Docker/SSH sockets, network policy, proxy as separate process. Documented as deployment requirements. |

---

## Additional Corrections from Review (incorporated above)

- Policy-version checking: include matched_policy_ids and matched_policy_versions in authorization, not just a single version integer.
- Imported policies start as `imported_pending_review`, not `active`. Only activate when signer and source are explicitly trusted.
- XID import mapping: store source_entity_id and imported_entity_id to preserve provenance.
- `ep_lattices` to `ep_projects`: add UNIQUE(project_id) or clarify the one-to-one relationship.
- Work-claim uniqueness: partial index `WHERE status = 'active'` for PostgreSQL.
- Cleanup: audit events never garbage-collected. Expired tokens redacted but retained. Failed/denied transitions retained per audit policy.
- Token signing: use Ed25519 asymmetric signatures (EP signs with private key, proxies verify with public key). A compromised proxy cannot mint authorizations.
- Proxy result reporting: authenticated proxy identity, unique execution-attempt ID, one terminal result per attempt, duplicate callbacks return stored result, unknown outcome becomes `execution_uncertain`.
- Shell parsing: do not promise complete semantic classification. Use escalating treatment: known safe commands parsed, opaque scripts classified as high-risk `shell.exec.opaque`, unrecognized commands require approval or deny by default.
- Resource canonicalization: policies match canonical resource identities (e.g., `postgres://cloudhub/gbrain_pilot/public/memory_items`), not raw agent-supplied strings.
- Condition language: evaluate CEL and Cedar before Phase 2. Do not build a custom policy language casually.

---

## Updated Verdict

v1.1.1 resolves all 8 items identified by the reviewer as required before implementation. The design is now ready for Phase 1 formalization and prototyping.