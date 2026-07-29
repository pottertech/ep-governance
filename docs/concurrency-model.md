# EP-Governance Concurrency Model

**Version:** 1.0 (Phase 1)
**Date:** July 29, 2026
**Governing Sources:** v1.1 §7.5; v1.1.1 §1, §3, §5. Where they conflict, v1.1.1 governs.

---

## 1. Optimistic Concurrency

### 1.1 Branch Head Tracking

Each branch maintains:
- `head_node_id`: the XID of the current head node.
- `version`: an integer counter incremented on each head advancement.

### 1.2 Proposal Submission

When an agent proposes a transition, it MUST include:
- `expected_head_id`: the XID of the branch head the agent observed.
- `expected_version`: the version counter the agent observed.

### 1.3 Commit Conditions

A commit succeeds only if ALL of the following are true:

1. The current `ep_branches.head_node_id` equals the proposal's `expected_head_id`.
2. The current `ep_branches.version` equals the proposal's `expected_version`.
3. The transition's stage is `succeeded` (proxy has reported successful execution).

If any condition fails, the commit MUST fail and the transaction MUST roll back.

### 1.4 Stale Head

If `expected_head_id` or `expected_version` does not match the current branch state:

- The proposal MUST fail with error code `stale_head`.
- The error response MUST include the current `head_node_id` and `version`.
- The agent MUST re-read the branch state and retry with updated values.
- The system MUST NOT silently rebase the proposal onto the new head.

### 1.5 Divergence

- Two transitions from the same parent node CANNOT both advance the same branch.
- The first to commit succeeds (advances head, increments version).
- The second MUST fail with `stale_head`.
- To proceed, the second agent MUST explicitly create a new branch:
  ```
  ep-governance create-branch --project <id> --name "experimental" --from-branch main
  ```
- The new branch's head is set to the parent branch's current head. The first transition on the new branch advances from that head.

---

## 2. Atomic Token Claim Transaction

### 2.1 Full SQL Pseudocode (from v1.1.1 §3)

```sql
BEGIN;

-- 1. Atomically claim the authorization token
UPDATE ep_authorizations
SET used = TRUE,
    used_at = NOW()
WHERE id = :authorization_id
  AND used = FALSE
  AND expires_at > NOW()
RETURNING id, transition_id, payload_hash, policy_set_hash;

-- Application check:
-- If no row returned: ROLLBACK, return "token invalid or expired"

-- 2. Advance transition to executing
UPDATE ep_transitions
SET stage = 'executing',
    execution_started_at = NOW(),
    executor_id = :proxy_principal_id
WHERE id = :transition_id
  AND stage = 'authorized';

-- Application check:
-- If no row affected (transition not in 'authorized' stage): ROLLBACK

-- 3. COMMIT
COMMIT;
```

### 2.2 Guarantees

- The `UPDATE ... WHERE used = FALSE ... RETURNING` is atomic in PostgreSQL (row lock prevents concurrent claims).
- In SQLite, the same statement works under `BEGIN IMMEDIATE` serialization.
- Exactly one row MUST be affected by the token claim UPDATE. If zero rows are affected, the token is either already used, expired, or nonexistent.
- The transition stage advance and token claim occur in the same transaction. If either fails, both roll back.

### 2.3 Failure Modes

| Condition | Result |
|-----------|--------|
| Token already used (used = TRUE) | No row returned → ROLLBACK → "token already used" |
| Token expired (expires_at <= NOW()) | No row returned → ROLLBACK → "token expired" |
| Token does not exist | No row returned → ROLLBACK → "token not found" |
| Transition not in `authorized` stage | Stage update affects 0 rows → ROLLBACK → "transition not authorized" |
| Database error | Automatic ROLLBACK → error returned to caller |

---

## 3. Branch Commit Transaction

### 3.1 Nine-Step Transaction (from v1.1.1 §1, v1.1 §7.5)

When a proxy reports successful execution and the transition reaches `succeeded`, the following steps execute in a single database transaction:

```sql
BEGIN;

-- Step 1: Verify transition stage is 'succeeded'
SELECT stage FROM ep_transitions
WHERE id = :transition_id;
-- Application check: stage MUST be 'succeeded'. If not: ROLLBACK.

-- Step 2: Verify branch head matches expected_head_id and expected_version
SELECT head_node_id, version FROM ep_branches
WHERE id = :branch_id;
-- Application check:
--   head_node_id MUST equal :expected_head_id
--   version MUST equal :expected_version
-- If not: ROLLBACK, return 'stale_head'

-- Step 3: Insert new ep_node with status 'committed'
INSERT INTO ep_nodes (id, branch_id, agent_id, description, bt_planning_budget,
                      metadata, status, created_at, committed_at)
VALUES (:new_node_id, :branch_id, :agent_id, :description, :bt_after,
        :metadata, 'committed', NOW(), NOW());

-- Step 4: Insert new ep_edge from parent node to new node
INSERT INTO ep_edges (id, upstream_node_id, downstream_node_id, edge_type, weight, created_at)
VALUES (:new_edge_id, :expected_head_id, :new_node_id, 'dependency', 1.0, NOW());

-- Step 5: Mark prior head node as 'superseded'
UPDATE ep_nodes SET status = 'superseded'
WHERE id = :expected_head_id AND status = 'committed';
-- Application check: exactly 1 row affected

-- Step 6: Update branch head to new node
UPDATE ep_branches SET head_node_id = :new_node_id, version = version + 1
WHERE id = :branch_id
  AND head_node_id = :expected_head_id
  AND version = :expected_version;
-- Application check: exactly 1 row affected (optimistic concurrency)

-- Step 7: Increment version (done in Step 6 via 'version + 1')

-- Step 8: Record transition result
UPDATE ep_transitions
SET stage = 'succeeded',
    to_node_id = :new_node_id,
    execution_completed_at = NOW(),
    exit_status = 'success',
    result_summary = :result_summary,
    residual_risk_after = :residual_risk_after
WHERE id = :transition_id;

-- Step 9: Append audit event
-- (See audit insertion procedure in audit-format.md / concurrency-model.md §4)
INSERT INTO ep_events (id, sequence, event_type, event_data, previous_hash,
                      event_hash, actor_principal_id, authenticated_caller_id,
                      event_writer_id, lattice_id, created_at)
VALUES (:event_id, :next_sequence, 'transition_committed', :event_data,
        :previous_hash, :event_hash, :agent_id, :caller_id, :ep_service_id,
        :lattice_id, NOW());

-- Update audit head
UPDATE ep_audit_heads
SET last_sequence = :next_sequence, last_hash = :event_hash
WHERE lattice_id = :lattice_id;

COMMIT;
```

### 3.2 Atomicity Guarantee

All nine steps execute in a single transaction. If any step fails:
- The transaction rolls back.
- No node is inserted.
- No edge is inserted.
- No node is superseded.
- No branch head is updated.
- No audit event is written.
- The transition remains in its prior state.

### 3.3 Cycle Prevention

Before inserting the edge (Step 4), the system MUST perform a forward BFS from the downstream node to verify the upstream node is not reachable. If a cycle would be created, the edge insertion MUST fail and the transaction MUST roll back.

---

## 4. Concurrent Audit Insertion

### 4.1 Per-Lattice Audit Heads

Each lattice has its own independent hash chain. A global sequence is not used.

```sql
CREATE TABLE ep_audit_heads (
    lattice_id       TEXT PRIMARY KEY,  -- FK to ep_lattices
    last_sequence    BIGINT NOT NULL DEFAULT 0,
    last_hash        TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000'
);
```

### 4.2 Insertion Procedure (PostgreSQL)

```sql
BEGIN;

-- 1. Lock the audit head for this lattice
SELECT last_sequence, last_hash FROM ep_audit_heads
WHERE lattice_id = :lattice_id
FOR UPDATE;

-- Application: 
--   next_sequence = last_sequence + 1
--   canonical_envelope = canonical_json({
--     "sequence": next_sequence,
--     "event_id": :event_id,
--     "event_type": :event_type,
--     "event_data": :event_data,
--     "actor_principal_id": :actor_principal_id,
--     "created_at": :created_at,  -- ISO 8601 UTC
--     "previous_hash": last_hash
--   })
--   event_hash = sha256(canonical_envelope.encode("utf-8")).hexdigest()

-- 2. Insert the event
INSERT INTO ep_events (id, sequence, event_type, event_data, previous_hash,
                        event_hash, actor_principal_id, authenticated_caller_id,
                        event_writer_id, lattice_id, created_at)
VALUES (:event_id, :next_sequence, :event_type, :event_data,
        :last_hash, :event_hash, :actor_principal_id, :caller_id,
        :ep_service_id, :lattice_id, :created_at);

-- 3. Update the audit head
UPDATE ep_audit_heads
SET last_sequence = :next_sequence, last_hash = :event_hash
WHERE lattice_id = :lattice_id;

COMMIT;
```

### 4.3 Insertion Procedure (SQLite)

```sql
BEGIN IMMEDIATE;

-- Same logic as PostgreSQL, but using BEGIN IMMEDIATE for serialization.
-- SELECT does not need FOR UPDATE (BEGIN IMMEDIATE acquires a write lock).

SELECT last_sequence, last_hash FROM ep_audit_heads WHERE lattice_id = :lattice_id;
-- ... compute next_sequence and event_hash ...
INSERT INTO ep_events (...);
UPDATE ep_audit_heads SET last_sequence = :next_sequence, last_hash = :event_hash WHERE lattice_id = :lattice_id;

COMMIT;
```

### 4.4 Concurrency Guarantee

- The `FOR UPDATE` row lock (PostgreSQL) or `BEGIN IMMEDIATE` (SQLite) ensures that two concurrent writers cannot both read the same `last_sequence` and `last_hash`.
- The second writer blocks until the first commits, then reads the updated head.
- Per-lattice chains reduce contention compared to a single global chain. Each lattice's audit log progresses independently.

---

## 5. Stale Authorization Detection

### 5.1 Policy-Set Hash

At authorization time, EP computes a `policy_set_hash` — a SHA-256 hash of the canonical JSON of all matched policy IDs and their versions:

```json
{
  "matched_policies": [
    {"policy_id": "cjvb...", "version": 3},
    {"policy_id": "cjvc...", "version": 1}
  ]
}
```

The hash of this canonical JSON is stored in `ep_authorizations.policy_set_hash`.

### 5.2 Matched Policy Versions

The `matched_policy_versions` field in the authorization token records the specific policy IDs and versions that were matched at authorization time:

```
matched_policy_versions = {
  "cjvb...": 3,
  "cjvc...": 1
}
```

### 5.3 Detection at Execution Time

When the proxy claims the token (or just before), EP (or the proxy via EP) checks:

1. **Recompute the current policy-set hash** for the same action and resource.
2. **Compare** with the stored `policy_set_hash`.
3. **If they differ**: the authorization is stale.
4. **If they match**: the authorization is valid.

### 5.4 Relevant vs. Unrelated Changes

| Change Type | Description | Invalidates Auth? |
|-------------|-------------|-------------------|
| **Relevant change** | A policy that matched the authorized action has been created, retired, superseded, or its version has advanced. | YES — token invalidated, transition moves to `expired` |
| **Unrelated change** | A policy that did NOT match the authorized action has changed. | NO — token remains valid |

### 5.5 Detection Algorithm

```
1. At authorization time:
   - matched_policies = [policies matching action + resource + conditions]
   - policy_set_hash = sha256(canonical_json(matched_policies with versions))
   - Store policy_set_hash and matched_policy_versions in ep_authorizations

2. At execution time (before or during atomic claim):
   - Re-evaluate policies against the same action + resource
   - current_matched = [currently matching policies with versions]
   - current_hash = sha256(canonical_json(current_matched))

3. Compare:
   - If current_hash == policy_set_hash:
     → Authorization is valid. Proceed.
   - If current_hash != policy_set_hash:
     → A relevant policy has changed.
     → Transition moves to 'expired'.
     → Agent must re-request authorization.

4. Granular check (optional, for diagnostics):
   - Compare matched_policy_versions field-by-field with current_matched.
   - Identify which specific policies changed.
   - Log the specific policy changes in the audit event.
```

### 5.6 Timing

- The stale authorization check SHOULD be performed at token claim time (in the same transaction or immediately before).
- If the check is performed outside the atomic claim transaction, there is a TOCTOU window. The recommended approach is to perform the check within the claim transaction or immediately before it, accepting that the check is advisory if not in the same transaction.
- For maximum safety, the `policy_set_hash` comparison can be added as an additional `WHERE` clause on the atomic claim UPDATE:

```sql
UPDATE ep_authorizations
SET used = TRUE, used_at = NOW()
WHERE id = :authorization_id
  AND used = FALSE
  AND expires_at > NOW()
  AND policy_set_hash = :current_policy_set_hash
RETURNING id, transition_id, payload_hash;
```

This ensures that if the policy set has changed, the claim fails atomically.