# EP-Governance Failure and Recovery

**Version:** 1.0 (Phase 1)
**Date:** July 29, 2026
**Governing Sources:** v1.1 §5; v1.1.1 §3, §5, additional corrections. Where they conflict, v1.1.1 governs.

---

## 1. Execution Uncertain

### 1.1 When It Applies

The `execution_uncertain` stage is entered when the proxy has claimed the authorization token and started execution, but EP cannot confirm the outcome:

| Scenario | Description |
|----------|-------------|
| **Callback failed** | The proxy executed the action but the callback to EP failed (network error, EP was unreachable). |
| **Network dropped** | The network connection between EP and the proxy was lost during execution. |
| **Connection closed** | The connection between EP and the proxy was closed before the result was received. |
| **Proxy timeout** | The proxy did not respond within the expected timeout window. |

### 1.2 Rules

- **DO NOT auto-fail.** The system MUST NOT automatically move a transition from `execution_uncertain` to `failed`.
- **DO NOT auto-succeed.** The system MUST NOT automatically move a transition from `execution_uncertain` to `succeeded`.
- The transition MUST remain in `execution_uncertain` until reconciliation.
- `requires_manual_reconciliation` flag MUST be set to `TRUE`.
- The transition is terminal (no normal lifecycle transitions from this state).

### 1.3 Reconciliation Procedure

1. An operator reviews the transition and proxy state.
2. The operator contacts the proxy or checks the target system to determine the actual outcome.
3. The operator creates a reconciliation record:
   - `transition_id`: the uncertain transition
   - `determined_outcome`: `succeeded`, `failed`, or `indeterminate`
   - `evidence`: documentation of how the outcome was determined
   - `reconciled_by`: operator principal ID
   - `reconciled_at`: timestamp
4. The reconciliation record is appended to the audit log.
5. `requires_manual_reconciliation` is set to `FALSE`.
6. If `determined_outcome = succeeded`: a node MAY be inserted via a separate reconciliation transaction.
7. If `determined_outcome = failed` or `indeterminate`: no node is inserted.
8. The original `execution_uncertain` stage is preserved in the audit trail; the reconciliation record documents the resolved outcome separately.

---

## 2. Partial Transaction Rollback

### 2.1 Atomic Claim + Stage Advance

The token claim and stage advancement occur in a single database transaction (see `concurrency-model.md` §2).

```
BEGIN;
  1. UPDATE ep_authorizations SET used = TRUE ... WHERE ... RETURNING ...
  2. UPDATE ep_transitions SET stage = 'executing' ... WHERE ...
COMMIT;
```

### 2.2 Rollback Behavior

| Failure Point | Rollback Result |
|---------------|-----------------|
| Step 1 fails (no row returned) | ROLLBACK → token not claimed, transition remains `authorized` |
| Step 2 fails (transition not in `authorized`) | ROLLBACK → token claim undone, transition unchanged |
| Database error during either step | Automatic ROLLBACK → both operations undone |
| Network error after BEGIN, before COMMIT | Database rolls back on connection loss |

### 2.3 Guarantee

After a rollback, the system is in a consistent state:
- The authorization token remains unused (`used = FALSE`).
- The transition remains in its prior stage (`authorized`).
- No partial state is visible to other transactions.

---

## 3. Proxy Crash Recovery

### 3.1 Scenario

The proxy process crashes or is killed after claiming the authorization token but before reporting the result.

### 3.2 State After Crash

- The authorization token is marked `used = TRUE` (claim was committed).
- The transition is in `executing` stage (stage advance was committed).
- No result has been reported.

### 3.3 Recovery

1. The transition remains in `executing` with `requires_manual_reconciliation = TRUE` (or transitions to `execution_uncertain` after a timeout).
2. An operator must determine whether the action was executed before the crash:
   - Check the target system (e.g., database state, container status).
   - Check proxy logs if available.
3. Follow the reconciliation procedure (§1.3 above).
4. The token cannot be reused (it is marked `used = TRUE`).
5. If the action was not executed, the agent must submit a new proposal with a new authorization.

### 3.4 Timeout to execution_uncertain

The system SHOULD implement a configurable timeout: if a transition remains in `executing` for longer than the timeout without a callback, the transition MAY be moved to `execution_uncertain`. This timeout MUST be configurable and SHOULD default to a value significantly longer than the expected execution time (e.g., 10x the token TTL).

---

## 4. EP Service Crash Recovery

### 4.1 Scenario

The EP service process crashes or is killed while a database transaction is in-flight.

### 4.2 Database Behavior

- PostgreSQL: In-flight transactions are automatically rolled back by the database when the connection is lost.
- SQLite: In-flight transactions are rolled back when the process terminates.

### 4.3 State After Recovery

| Transaction Type | State After EP Crash |
|------------------|---------------------|
| Branch commit (9-step) | Fully rolled back. No node, no edge, no head update. Transition remains in prior stage. |
| Token claim + stage advance | Fully rolled back. Token unused. Transition in `authorized`. |
| Audit insertion | Fully rolled back. No event inserted. Audit head unchanged. |
| Policy creation | Fully rolled back. No policy created. |

### 4.4 Recovery Procedure

1. EP service restarts.
2. EP reads current state from the database.
3. Any transitions in `executing` stage with no callback received are candidates for timeout-based `execution_uncertain` transition (see §3.4).
4. No manual intervention is needed for transactions that were rolled back — the database handles this automatically.
5. The operator should review transitions stuck in `executing` after EP restart.

---

## 5. Network Partition Handling

### 5.1 Partition Between EP and Proxy

| Scenario | Impact | Resolution |
|----------|--------|------------|
| EP cannot reach proxy to send token | Token not claimed. Transition remains `authorized`. Token may expire. | Agent re-requests after token expiry. |
| Proxy executed but cannot report result to EP | Transition stuck in `executing`. | Moves to `execution_uncertain` after timeout. Requires reconciliation. |
| EP cannot reach database | All operations fail. No state changes. | Retry when database is reachable. |

### 5.2 Partition Between Proxy and Target

| Scenario | Impact | Resolution |
|----------|--------|------------|
| Proxy cannot reach target system | Execution fails. Proxy reports `failed` to EP. | Transition moves to `failed`. Agent may retry. |
| Proxy reached target but result is ambiguous | Proxy may report `execution_uncertain` or timeout. | Reconciliation needed. |

### 5.3 Partition Between Agent and EP

| Scenario | Impact | Resolution |
|----------|--------|------------|
| Agent cannot submit proposal | No transition created. | Agent retries when EP is reachable. |
| Agent submitted proposal but cannot receive response | Transition may be created but agent doesn't know. | Agent uses idempotency key on retry to get existing result. |

---

## 6. Clock Skew Handling

### 6.1 Token Expiry

| Scenario | Handling |
|----------|----------|
| EP clock ahead of proxy clock | Token appears expired to proxy earlier than expected. Proxy rejects. Transition moves to `expired`. Agent re-requests. |
| Proxy clock ahead of EP clock | Token appears valid to proxy but expired at EP. The `expires_at > NOW()` check in the atomic claim uses the database clock, not the proxy clock. If the database (PostgreSQL) clock is authoritative, the claim fails correctly. |
| Recommended: use database clock | The `expires_at > NOW()` check in the atomic claim SQL uses the database's `NOW()` function, which is the database server's clock. This is the authoritative clock for token expiry. The proxy's local clock is not used for expiry checks. |

### 6.2 Audit Timestamps

- Audit event timestamps (`created_at`) MUST be generated by the EP service, not by callers (EP-AUDIT-008).
- The EP service SHOULD use the database `NOW()` function for timestamps to ensure consistency with the database clock.
- Clock skew between EP service and database is mitigated by using database-generated timestamps.
- Clock skew between different database nodes (in a replicated setup) is out of scope for this specification. In production, use a single authoritative database or NTP-synchronized clocks.

### 6.3 Tolerance

- The system SHOULD tolerate small clock skew (seconds) by using a grace period on token expiry (e.g., accept tokens up to 5 seconds past expiry).
- The grace period MUST be configurable and SHOULD default to 0 (no grace) for strict security.
- Large clock skew (minutes or more) is a deployment issue that must be resolved with NTP.

---

## 7. Key Rotation Procedure

### 7.1 Ed25519 Key Pair Rotation

The EP service holds the Ed25519 private signing key. Proxies hold the public verification key. Rotation:

1. **Generate new key pair.** EP generates a new Ed25519 key pair.
2. **Distribute new public key.** EP distributes the new public key to all proxies.
3. **Sign with new key.** EP starts signing new authorization tokens with the new private key.
4. **Accept old and new during transition.** Proxies MUST accept tokens signed with both the old and new private keys during a configurable transition period.
5. **Remove old public key.** After the transition period, proxies remove the old public key. Old tokens signed with the old key are no longer valid (they would have expired anyway due to short TTL).
6. **Destroy old private key.** EP securely destroys the old private key.

### 7.2 Transition Period

- The transition period MUST be at least as long as the maximum token TTL (default 5 minutes, configurable).
- Recommended transition period: 1 hour (to allow for operational delays).
- The transition period is configurable via `EP_KEY_ROTATION_TRANSITION_SECONDS`.

### 7.3 Audit

- Key rotation events MUST be logged to the audit trail with: old key fingerprint, new key fingerprint, rotation timestamp, and the principal who performed the rotation.
- Event type: `key_rotated`.

---

## 8. Duplicate Callback Handling

### 8.1 Idempotent Callbacks

When the proxy reports a result to EP, the callback is idempotent:

1. Each execution attempt has a unique `execution_attempt_id`.
2. The proxy sends the `execution_attempt_id` with each callback.
3. EP checks if a result has already been recorded for this `execution_attempt_id`:
   - **If yes**: return the stored result. Do not process the callback again.
   - **If no**: process the callback, store the result, return the result.

### 8.2 Conflicting Callbacks

If two callbacks arrive for the same `execution_attempt_id` with **different** results:

1. The first callback's result is stored and returned.
2. The second callback with a different result MUST be rejected.
3. A security event MUST be generated (audit event type: `duplicate_callback_conflict`).
4. The conflict MUST include: `execution_attempt_id`, first result, second result, proxy identity, timestamp.
5. An operator should investigate the conflict.

### 8.3 Guarantees

- One terminal result per execution attempt: exactly one result is stored.
- Duplicate callbacks with the same result: idempotent, return stored result.
- Duplicate callbacks with different results: rejected, security event logged.

---

## 9. Failed Migration Recovery

### 9.1 Scenario

A database migration (schema change) fails partway through.

### 9.2 Recovery Procedure

1. **Use transactional migrations.** Each migration MUST run in a transaction. If the migration fails, the transaction rolls back.
2. **Down migration.** Each migration MUST have a corresponding down migration that reverses the changes.
3. **Verify state.** After rollback, verify the schema is in a consistent state:
   - Run `ep-governance verify-schema` (or equivalent).
   - Check that all CHECK constraints are satisfied.
   - Verify audit chain integrity (`ep-governance audit --verify`).
4. **Manual intervention.** If automatic rollback fails, an operator must manually repair the schema. This SHOULD be rare with transactional migrations.
5. **PostgreSQL:** Use `CREATE TYPE`, `ALTER TABLE`, etc. within a transaction. Most DDL in PostgreSQL is transactional.
6. **SQLite:** Most DDL is transactional, but some operations (e.g., `ALTER TABLE` limitations) may require table rebuilds. Use the migration framework to handle this.

### 9.3 Data Integrity Check

After any migration failure and recovery:
1. Verify all `ep_nodes.status` values are in the allowed set.
2. Verify all `ep_transitions.stage` values are in the allowed set.
3. Verify all `ep_policies.status` values are in the allowed set.
4. Verify audit chain: `ep-governance audit --verify`.
5. Verify branch head consistency: each branch's `head_node_id` points to an existing node.

---

## 10. Audit Chain Repair

### 10.1 Detected Tampering

The audit chain verification command (`ep-governance audit --verify`) recomputes each event hash from the canonical envelope and checks that each `previous_hash` matches the preceding event's `event_hash`.

### 10.2 Detection Results

| Verification Result | Meaning |
|---------------------|---------|
| All hashes match | Chain is intact. No tampering detected. |
| A hash mismatch at event N | Event N's content has been modified after insertion. |
| A `previous_hash` mismatch at event N | Event N-1 was deleted, inserted, or reordered. |
| A sequence gap | An event was deleted from the chain. |

### 10.3 Repair Procedure

**Audit chain repair is a manual, operator-only procedure.** The system MUST NOT automatically repair the audit chain.

1. **Identify the breach point.** The verification command reports the first event where the chain is broken.
2. **Investigate.** An operator determines what happened: was the event modified, deleted, or inserted?
3. **Quarantine.** The affected lattice's audit chain is marked as `compromised` (a new field on `ep_audit_heads` or a separate tracking table).
4. **Preserve evidence.** The current state of the audit table is preserved (export, backup) for forensic analysis.
5. **Rebuild chain (if possible).** If the original event data is recoverable (e.g., from backups), the operator may:
   - Export the current audit table.
   - Restore from backup to a point before the tampering.
   - Re-apply any legitimate events that occurred after the backup.
   - This is a manual, error-prone process and MUST be performed by a qualified operator.
6. **Report.** The tampering event and repair action MUST be documented and logged.
7. **Security review.** The tampering indicates database access by an unauthorized party. A full security review is required.

### 10.4 Prevention

- Database permissions: only the EP service role can INSERT into `ep_events`. No role can UPDATE or DELETE.
- The hash chain provides detection, not prevention. A determined adversary with direct database write access can modify the chain (and would need to recompute all subsequent hashes).
- For additional protection: periodically export signed checkpoints of the current audit head (`last_sequence`, `last_hash`) to an external, write-once system (e.g., a notarization service, a separate log server). This provides external verifiability.

### 10.5 Checkpoint Procedure

```
1. At regular intervals (configurable, e.g., every hour or every 1000 events):
   - Read the current audit head for each lattice.
   - Create a signed checkpoint: canonical_json({lattice_id, last_sequence, last_hash, timestamp}).
   - Sign with the EP service key.
   - Export to an external system (file, API, notarization service).

2. During verification:
   - Compare the current audit head with the last checkpoint.
   - If they match: the chain has not been tampered with since the last checkpoint.
   - If they differ: tampering occurred after the last checkpoint.
```