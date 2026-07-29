# EP-Governance State Machines

**Version:** 1.0 (Phase 1)
**Date:** July 29, 2026
**Governing Sources:** v1.1 §5.1, v1.1.1 §2, §6. Where they conflict, v1.1.1 governs.

---

## 1. Transition Lifecycle State Machine

### 1.1 Stages

| Stage | Description |
|-------|-------------|
| `proposed` | Agent has submitted a structured action request. EP has not yet evaluated policies. |
| `pending_approval` | Policy evaluation returned `require_approval`. Waiting for human decision. |
| `authorized` | Policy evaluation returned `allow` or `warn`, or human approved a `pending_approval` request. EP has issued a signed authorization token. |
| `executing` | Proxy has atomically claimed the authorization token and is running the action. |
| `succeeded` | Proxy reported successful execution. A new node is committed. |
| `failed` | Proxy reported failed execution. No node is committed. Agent may retry. |
| `execution_uncertain` | Proxy callback failed, network dropped, connection closed, or proxy timed out. Outcome unknown. Requires manual reconciliation. |
| `cancelled` | Agent explicitly cancelled the proposal before execution. |
| `expired` | Authorization token expired before execution, or relevant governance changed (stale authorization). |
| `denied` | Policy evaluation returned `deny`. Action is blocked. |

### 1.2 Terminal States

The following stages are **terminal** — no further transitions are permitted from these states:

- `succeeded`
- `failed`
- `execution_uncertain`
- `cancelled`
- `expired`
- `denied`

A transition in a terminal state MUST NOT be moved to any other stage. The `execution_uncertain` state requires a reconciliation procedure (see `failure-recovery.md`) that produces a **new** audit event and, if appropriate, a manual state correction — but the stage value itself is not directly mutated to `succeeded` or `failed` via the normal transition lifecycle. Instead, a reconciliation record is created that documents the resolved outcome. (See §1.5 below for the recommendation on `requires_manual_reconciliation`.)

### 1.3 Legal Transitions

| From | To | Legal? | Trigger |
|------|-----|--------|---------|
| `proposed` | `pending_approval` | ✅ Legal | Policy evaluation returns `require_approval` |
| `proposed` | `denied` | ✅ Legal | Policy evaluation returns `deny` |
| `proposed` | `authorized` | ✅ Legal | Policy evaluation returns `allow` or `warn` |
| `proposed` | `cancelled` | ✅ Legal | Agent explicitly cancels before evaluation |
| `pending_approval` | `authorized` | ✅ Legal | Human approves the request |
| `pending_approval` | `denied` | ✅ Legal | Human denies the request |
| `pending_approval` | `expired` | ✅ Legal | Approval request expires (timeout) |
| `pending_approval` | `cancelled` | ✅ Legal | Agent cancels while waiting |
| `authorized` | `executing` | ✅ Legal | Proxy atomically claims token (same transaction) |
| `authorized` | `expired` | ✅ Legal | Token expires before claim, or stale authorization detected |
| `authorized` | `cancelled` | ✅ Legal | Agent cancels before execution |
| `executing` | `succeeded` | ✅ Legal | Proxy reports successful execution |
| `executing` | `failed` | ✅ Legal | Proxy reports failed execution |
| `executing` | `execution_uncertain` | ✅ Legal | Callback failed / network dropped / proxy timeout |
| `succeeded` | *(any)* | ❌ Illegal | Terminal state |
| `failed` | *(any)* | ❌ Illegal | Terminal state |
| `execution_uncertain` | *(any)* | ❌ Illegal | Terminal state (reconciliation via separate procedure) |
| `cancelled` | *(any)* | ❌ Illegal | Terminal state |
| `expired` | *(any)* | ❌ Illegal | Terminal state |
| `denied` | *(any)* | ❌ Illegal | Terminal state |
| `proposed` | `executing` | ❌ Illegal | Must pass through `authorized` first |
| `proposed` | `succeeded` | ❌ Illegal | Must pass through `authorized` and `executing` |
| `proposed` | `failed` | ❌ Illegal | Must pass through `authorized` and `executing` |
| `pending_approval` | `executing` | ❌ Illegal | Must pass through `authorized` first |
| `pending_approval` | `succeeded` | ❌ Illegal | Must pass through `authorized` and `executing` |
| `authorized` | `succeeded` | ❌ Illegal | Must pass through `executing` first |
| `authorized` | `failed` | ❌ Legal* | Only if execution attempt fails to start (edge case — see note) |
| `authorized` | `denied` | ❌ Illegal | Already authorized; cannot retroactively deny |
| `executing` | `authorized` | ❌ Illegal | Cannot reverse execution |
| `executing` | `denied` | ❌ Illegal | Execution already in progress |
| `executing` | `cancelled` | ❌ Illegal | Cannot cancel during execution |
| `executing` | `expired` | ❌ Illegal | Token already claimed; expiry not applicable |
| `executing` | `pending_approval` | ❌ Illegal | Cannot reverse to pending |

> **Note on `authorized → failed`:** This edge case is marked illegal in the general table. If the proxy fails to begin execution (e.g., infrastructure unreachable after claim), the proxy MUST report `failed` back to EP, which records it as `executing → failed`. The `authorized → executing` transition happens atomically with the token claim; once the token is claimed, the stage is `executing`. A proxy that cannot execute after claiming MUST report a `failed` result, not retroactively change the stage.

### 1.4 Illegal Transition Handling

- Any stage change not listed as Legal in the table above MUST be rejected.
- The rejection MUST generate an audit event of type `illegal_transition_attempt` recording the attempted from-stage, to-stage, transition ID, and caller identity.
- The transition's stage MUST NOT change as a result of an illegal attempt.

### 1.5 `requires_manual_reconciliation`: Stage vs Flag

**Recommendation: `requires_manual_reconciliation` is a BOOLEAN FLAG on the transition record, not a stage.**

**Rationale:**

- `execution_uncertain` is already a terminal stage representing unknown outcome.
- Adding `requires_manual_reconciliation` as a stage would conflate the *outcome state* with the *action needed*.
- A transition may be `execution_uncertain` with `requires_manual_reconciliation = TRUE`, and after reconciliation, the flag is set to `FALSE` while the stage remains `execution_uncertain` (with a reconciliation record documenting the resolved outcome).
- This design allows the audit trail to preserve the original uncertain state while recording the reconciliation decision separately.

**Field Definition:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `requires_manual_reconciliation` | BOOLEAN | FALSE | Set to TRUE when transition reaches `execution_uncertain`. Set to FALSE after reconciliation procedure completes. |

**Reconciliation Procedure:**

1. Operator reviews the transition and proxy state.
2. Operator determines the actual outcome (succeeded, failed, or indeterminate).
3. Operator creates a reconciliation record with: `transition_id`, `determined_outcome`, `evidence`, `reconciled_by`, `reconciled_at`.
4. The reconciliation record is appended to the audit log.
5. `requires_manual_reconciliation` is set to FALSE.
6. If the outcome is determined to be `succeeded`, a node MAY be inserted at this point (via a separate reconciliation transaction, not via normal transition lifecycle).
7. If the outcome is `failed` or indeterminate, no node is inserted.

### 1.6 Idempotency Interaction

| Prior Transition Stage | Same Idempotency Key Resubmitted |
|------------------------|----------------------------------|
| `proposed` | Return existing transition |
| `pending_approval` | Return existing transition |
| `authorized` | Return existing transition |
| `executing` | Return existing result (if available) or existing transition |
| `succeeded` | Return existing result |
| `failed` | Allow new proposal |
| `execution_uncertain` | Return existing transition (do not auto-retry) |
| `cancelled` | Allow new proposal |
| `expired` | Allow new proposal |
| `denied` | Allow new proposal |

---

## 2. Node Lifecycle State Machine

### 2.1 Statuses

| Status | Description |
|--------|-------------|
| `committed` | Execution succeeded. This is an active state in the graph. |
| `quarantined` | An existing committed state was later found unsafe. Under repair. |
| `at_risk` | Downstream of a quarantined node. Requires review. |
| `superseded` | Replaced by a newer committed node on the same branch. No longer the active head. |
| `archived` | No longer active but retained for audit history. |

### 2.2 Entry Conditions

| Status | When Entered |
|--------|--------------|
| `committed` | A transition reaches `succeeded`. The new `ep_node` row is inserted with `status = committed` and `committed_at` is set. |
| `quarantined` | An existing committed node is found unsafe (e.g., a policy change retroactively invalidates a prior action, or an external audit identifies a violation). The node's status is changed from `committed` to `quarantined`. |
| `at_risk` | A forward blast radius computation marks all downstream nodes of a quarantined node as `at_risk`. |
| `superseded` | A new transition succeeds on the same branch, advancing the branch head. The prior head node is marked `superseded`. |
| `archived` | An operator or administrator explicitly archives a node that is no longer active (e.g., after branch merge or project completion). |

### 2.3 Legal Transitions

| From | To | Legal? | Trigger |
|------|-----|--------|---------|
| *(new)* | `committed` | ✅ Legal | Transition reaches `succeeded` |
| `committed` | `quarantined` | ✅ Legal | Node found unsafe |
| `committed` | `superseded` | ✅ Legal | New head advances on same branch |
| `committed` | `archived` | ✅ Legal | Explicit archive by operator/admin |
| `quarantined` | `committed` | ✅ Legal | Repair completed (operator action) |
| `quarantined` | `archived` | ✅ Legal | Quarantine resolved, node archived |
| `at_risk` | `committed` | ✅ Legal | Parent quarantine lifted, risk cleared |
| `at_risk` | `quarantined` | ✅ Legal | At-risk node itself found unsafe |
| `at_risk` | `archived` | ✅ Legal | Explicit archive |
| `superseded` | `archived` | ✅ Legal | Explicit archive |
| `superseded` | `committed` | ❌ Illegal | Cannot un-supersede |
| `superseded` | `quarantined` | ❌ Illegal | Superseded nodes are not active |
| `quarantined` | `superseded` | ❌ Illegal | Quarantine must be resolved first |
| `quarantined` | `at_risk` | ❌ Illegal | Quarantined is a terminal-for-repair state |
| `at_risk` | `superseded` | ❌ Legal* | If parent is repaired and a newer head exists (edge case — see note) |
| `archived` | *(any)* | ❌ Illegal | Terminal state |

> **Note on `at_risk → superseded`:** This edge case is theoretically legal if the parent's quarantine is lifted (restoring the at-risk node to `committed`) and then a new head advances. In practice, the system should first transition `at_risk → committed` (quarantine lifted) and then `committed → superseded` (new head), as two separate steps.

### 2.4 Forward Blast Radius

When a node is quarantined:

1. Find all edges where `upstream_node_id = quarantined_node_id`.
2. For each downstream node:
   - If not already `at_risk` or `archived`: mark as `at_risk`.
   - Recursively apply blast radius to downstream nodes of the at-risk node.
3. The blast radius computation is recorded in the audit log.

### 2.5 Quarantine Repair

When an operator repairs a quarantined node:

1. Operator records the repair action and evidence.
2. Node status changes from `quarantined` to `committed`.
3. All `at_risk` downstream nodes whose only quarantined ancestor was the repaired node are changed from `at_risk` to `committed`.
4. The repair is recorded in the audit log.

---

## 3. Policy Lifecycle State Machine

### 3.1 Statuses

| Status | Description |
|--------|-------------|
| `draft` | Created but not submitted for approval. No enforcement effect. |
| `pending_approval` | Submitted for approval. No enforcement effect yet. |
| `active` | Approved and effective. Enforced by the gate. |
| `rejected` | Approval was denied. Never takes effect. |
| `superseded` | Replaced by a newer active policy. |
| `retired` | Explicitly retired. No longer enforced. |

### 3.2 Entry Conditions

| Status | When Entered |
|--------|--------------|
| `draft` | A `policy_author` creates a new policy. Also the entry point for imported policies (with `origin=imported`, `trust_status=pending_review`). |
| `pending_approval` | A `policy_author` submits a draft policy for approval via `submit-policy`. |
| `active` | A `policy_approver` approves an agent-scoped policy, or a `human` principal co-approves a global policy. For imported policies: only when signer and source are explicitly trusted and the policy goes through the approval workflow. |
| `rejected` | A `policy_approver` (or human for global) denies the approval request. |
| `superseded` | A newer policy version is activated that replaces this policy. The `supersedes` field of the new policy references this policy's XID. |
| `retired` | A `policy_author` or higher explicitly retires an active or superseded policy. |

### 3.3 Legal Transitions

| From | To | Legal? | Trigger |
|------|-----|--------|---------|
| *(new)* | `draft` | ✅ Legal | Policy created by `policy_author` |
| *(new, imported)* | `draft` | ✅ Legal | Policy imported from transfer package (`origin=imported`, `trust_status=pending_review`) |
| `draft` | `pending_approval` | ✅ Legal | `submit-policy` command |
| `draft` | `retired` | ✅ Legal | Policy author retires before submission |
| `pending_approval` | `active` | ✅ Legal | Approval granted (agent-scoped: `policy_approver`; global: human co-approval) |
| `pending_approval` | `rejected` | ✅ Legal | Approval denied |
| `pending_approval` | `draft` | ✅ Legal | Withdrawn from approval (by author) |
| `pending_approval` | `expired` | N/A | Approval requests may expire; policy returns to `draft` or is rejected. (Implementation detail: the approval request expires, not the policy itself. The policy MAY be returned to `draft` or left in `pending_approval` with an expired approval request.) |
| `active` | `superseded` | ✅ Legal | New policy version activated that replaces this one |
| `active` | `retired` | ✅ Legal | Explicit retirement by `policy_author` or higher |
| `rejected` | `draft` | ✅ Legal | Author revises and resubmits |
| `rejected` | `retired` | ✅ Legal | Author abandons the rejected policy |
| `superseded` | `retired` | ✅ Legal | Explicit cleanup |
| `superseded` | `active` | ❌ Illegal | Cannot un-supersede |
| `retired` | *(any)* | ❌ Illegal | Terminal state |
| `draft` | `active` | ❌ Illegal | Must pass through `pending_approval` |
| `active` | `draft` | ❌ Legal* | Policy may be revised (edge case — see note) |

> **Note on `active → draft`:** This is not a standard transition. If a policy needs to be revised, the correct procedure is: create a new policy version in `draft`, submit it, approve it, and the old policy is `superseded` by the new one. Directly reverting an active policy to draft is not supported.

### 3.4 Imported Policy Entry Point

Imported policies enter the lifecycle at `draft` with additional metadata:

| Field | Value for Imported Policies |
|-------|-----------------------------|
| `status` | `draft` |
| `origin` | `imported` |
| `trust_status` | `pending_review` |
| `source_entity_id` | XID from source lattice |
| `imported_entity_id` | New local XID |
| `source_lattice_id` | Source lattice XID |
| `source_package_id` | Transfer package XID |

**Activation path for imported policies:**

1. Import creates the policy with `status=draft`, `trust_status=pending_review`.
2. An operator or administrator reviews the imported policy.
3. If the signer and source are explicitly trusted, the policy MAY be submitted for approval.
4. The policy follows the normal approval workflow: `draft → pending_approval → active`.
5. If the signer or source is not trusted, the policy remains in `draft` with `trust_status=pending_review` until trust is established or the policy is retired.

### 3.5 Separation of Duties

- The principal who creates a policy (`created_by`) MUST NOT be the same principal who approves it (`approved_by`).
- For global policies: a `human` principal must co-approve.
- For agent-scoped policies: a `policy_approver` can approve.
- The `decided_by != requested_by` constraint applies to all approval and override decisions.

### 3.6 Tension Detection

- Tensions are detected at policy creation time (when status would become `active`), not at action proposal time.
- A tension exists when two active policies with the same priority and conflicting effects match the same action and resource selectors.
- If a new policy creates a tension with an existing active policy, the system reports it and requires resolution (adjust priority, retire one, or add scoping to differentiate).
- The pairwise simulation method from v1.0 is removed (it produced false positives).