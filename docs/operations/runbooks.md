# EP-Governance Operational Runbooks

**Version:** 1.0
**Date:** July 31, 2026
**Audience:** Production operators on-call for EP-Governance deployments.

## Deployment Topology

| Component | Host | Notes |
|-----------|------|-------|
| EP Service | EP service host | Runs `ep-governance serve`, holds Ed25519 signing key, writes audit events. |
| Governed Proxy | Proxy host (Docker) | Separate process/container with target credentials; verifies tokens, executes actions. |
| Agents | Agent hosts | Submit proposals via `ep_execute`; have no target credentials. |
| Database | Database host (PostgreSQL) | Shared by EP service and proxy. SQLite acceptable for dev only. |

## Transition Stage Reference

```
proposed → denied / pending_approval / authorized / cancelled
pending_approval → authorized / denied / expired / cancelled
authorized → executing / expired / cancelled
executing → succeeded / failed / execution_uncertain
execution_uncertain → succeeded / failed   (via reconcile only)
```

Terminal stages: `succeeded`, `failed`, `cancelled`, `expired`, `denied`.

## Key Commands Quick Reference

| Command | Purpose |
|---------|---------|
| `ep-governance status --transition <id>` | Inspect a transition's current stage and metadata. |
| `ep-governance log --transition <id>` | View audit events for a transition. |
| `ep-governance audit verify --lattice <id>` | Verify hash-chain integrity for a lattice. |
| `ep-governance audit list --lattice <id>` | List all audit events for a lattice ordered by sequence. |
| `ep-governance pending-approvals` | List all pending approval requests. |
| `ep-governance execute ...` | Execute a governed action through the proxy (agent-side). |

---

## RB-01: Authorization Stuck in `executing`

### Symptoms
- A transition has been in the `executing` stage longer than the proxy timeout window (default 30 seconds, controlled by `ProxyConfig.timeout_seconds`).
- `ep-governance status --transition <id>` shows `stage=executing` with no result fields populated.
- The agent that submitted the action is blocked waiting for a result.
- The authorization token for this transition shows `used=TRUE` in the database.

### Diagnosis
1. Check whether the proxy process is still running on the proxy host:
   ```bash
   docker ps | grep ep-governance-proxy
   ```
2. Check proxy container logs for errors or hangs:
   ```bash
   docker logs --tail 100 ep-governance-proxy
   ```
3. Query the transition to confirm it is stuck:
   ```sql
   SELECT id, stage, exit_status, result_summary, requires_manual_reconciliation,
          updated_at
   FROM ep_transitions WHERE id = '<transition_id>';
   ```
4. Check the authorization record:
   ```sql
   SELECT id, used, claimed_at, expires_at
   FROM ep_authorizations WHERE transition_id = '<transition_id>';
   ```
5. Determine whether the underlying target action actually completed (check the target system — e.g., database rows, container state).

### Immediate Action
1. **Do NOT attempt to reuse the authorization token.** It is already marked `used=TRUE` and cannot be claimed again.
2. If the proxy process is hung or crashed, restart it:
   ```bash
   docker restart ep-governance-proxy
   ```
3. If the transition has been stuck for more than a few minutes and the proxy is not going to report a result, manually advance it to `execution_uncertain` by calling `record_result` with `exit_status="timeout"`:
   ```bash
   ep-governance mark-uncertain --transition <TRANSITION_ID> --reason "Operator intervention"
   ```
   This sets `requires_manual_reconciliation=TRUE` and moves the stage to `execution_uncertain`.
4. Follow **RB-02** (execution_uncertain) to reconcile.

### Follow-up
- Investigate why the proxy failed to report a result (network issue, target system hang, OOM kill).
- File an issue if the proxy crashed without reporting — the proxy code has a `TimeoutError` handler that should produce `exit_status="uncertain"`, so a silent hang indicates a bug or infrastructure failure.
- If the target action did execute successfully, reconcile as `succeeded` (see RB-02).

### Prevention
- Monitor proxy health with a liveness check; alert if the proxy container is unhealthy or restarted frequently.
- Set up a periodic job that scans for transitions in `executing` longer than 90 seconds (30s default timeout + 60s grace) and alerts operators.
- Ensure the proxy host has adequate resources (CPU, memory) for the proxy container.

---

## RB-02: Transition Marked `execution_uncertain`

### Symptoms
- `ep-governance status --transition <id>` shows `stage=execution_uncertain`.
- `requires_manual_reconciliation=TRUE` on the transition row.
- An audit event `transition.execution_uncertain` was written.
- The agent received an `exit_status="uncertain"` result or a "manual reconciliation required" message.

### Diagnosis
1. Review the audit trail for the transition:
   ```bash
   ep-governance log --transition <transition_id>
   ```
2. Read the `result_summary` field — it contains the attempt ID and reason (timeout, governance commit failure, or proxy callback failure).
3. Determine the actual outcome by checking the target system directly:
   - For database actions: query the target database for the expected changes.
   - For Docker actions: `docker ps -a` or `docker inspect <container>`.
   - For SSH/shell actions: check the remote system's state.
4. Check proxy logs using the attempt ID from the result summary:
   ```bash
   docker logs ep-governance-proxy 2>&1 | grep <attempt_id>
   ```

### Immediate Action
1. **Determine the true outcome:** did the action succeed or fail on the target system?
2. **Reconcile as succeeded** (only if the action truly completed and the target state is correct):
   ```bash
   ep-governance reconcile --transition <TRANSITION_ID> --outcome succeeded --reason "Operator confirmed" --branch <BRANCH_ID>
   ```
   Successful reconciliation atomically creates a graph node and advances the branch head.
3. **Reconcile as failed** (if the action did not complete or the target is in an inconsistent state):
   ```bash
   ep-governance reconcile --transition <TRANSITION_ID> --outcome failed --reason "Operator confirmed"
   ```
   No graph node is created. The transition advances to `failed`.

### Follow-up
- Document the investigation findings and the evidence used to determine the outcome.
- If the uncertainty was caused by a governance commit failure (the action succeeded but `branch_committer.commit()` failed), investigate why the commit failed — commonly a stale branch head (see RB-11) or a database connectivity issue (see RB-04).
- If reconcile-as-succeeded fails because branch commitment fails again, the transition stays at `execution_uncertain` with `requires_manual_reconciliation=TRUE`. Retry after resolving the branch conflict.

### Prevention
- Ensure network reliability between the proxy host and EP service host.
- Monitor for `transition.execution_uncertain` audit events and alert immediately.
- Keep the reconciliation queue empty — every uncertain transition is a governance gap.

---

## RB-03: Proxy Unreachable

### Symptoms
- Agents receive connection errors or timeouts when calling `ep_execute`.
- The proxy container on the proxy host is not responding to health checks.
- `docker ps` shows the proxy container as `Exited`, `Restarting`, or not listed at all.
- Transitions are stuck in `authorized` (never advancing to `executing`).

### Diagnosis
1. Check container status on the proxy host:
   ```bash
   docker ps -a | grep ep-governance-proxy
   ```
2. If the container is running, check health:
   ```bash
   docker inspect --format='{{.State.Health.Status}}' ep-governance-proxy
   ```
3. Check container logs for crash reasons:
   ```bash
   docker logs --tail 200 ep-governance-proxy
   ```
4. Verify network connectivity from the EP service host to the proxy port:
   ```bash
   nc -zv <proxy-host> <proxy-port>
   ```
5. Check the proxy host Docker daemon:
   ```bash
   docker info
   ```
6. Verify the database is reachable from the proxy container (see RB-04 if the DB is also down).

### Immediate Action
1. If the container is stopped, start it:
   ```bash
   docker start ep-governance-proxy
   ```
2. If the container is in a crash loop, inspect the logs for the root cause (missing config, DB connection failure, invalid key file). Fix the underlying issue before restarting.
3. If the container is healthy but unreachable from the EP service host, check:
   - proxy host firewall rules.
   - Mesh VPN/network connectivity between EP service host and proxy host.
   - Docker port mappings (`docker port ep-governance-proxy`).
4. If the proxy cannot be revived quickly, transitions in `authorized` will remain there. They are not lost — once the proxy is back, agents can retry `ep_execute` with the same authorization token (if it has not expired, TTL default 5 min). If tokens have expired, agents must re-propose.

### Follow-up
- Set up external monitoring (e.g., Prometheus blackbox exporter, Uptime Kuma) to alert on proxy unavailability.
- Configure Docker `restart: unless-stopped` or use a process manager (systemd, Docker Swarm) for automatic recovery.
- Document the proxy startup procedure and required environment variables / config files.

### Prevention
- Run the proxy under Docker with `--restart unless-stopped` or equivalent.
- Implement a health check endpoint in the proxy and configure Docker `HEALTHCHECK`.
- Alert on any transition in `authorized` for more than 10 minutes (likely indicates proxy is down).
- Keep a runbook for proxy host maintenance windows so operators can gracefully drain the proxy before planned downtime.

---

## RB-04: Database Unavailable

### Symptoms
- EP service and/or proxy raise `OperationalError` or `DatabaseError` exceptions.
- `ep-governance` CLI commands fail with connection errors.
- All governance operations (propose, approve, execute, audit) are blocked.
- Audit events cannot be written; transitions cannot change stage.

### Diagnosis
1. Check PostgreSQL container on the proxy host:
   ```bash
   docker ps | grep postgres
   ```
2. Attempt a direct connection:
   ```bash
   psql -h <database-host> -U ep_governance -d ep_governance -c "SELECT 1;"
   ```
3. Check PostgreSQL logs:
   ```bash
   docker logs --tail 100 ep-governance-postgres
   ```
4. Check disk space on the proxy host (PostgreSQL will refuse connections if the WAL volume is full):
   ```bash
   df -h
   ```
5. Check database host system resources (memory, CPU):
   ```bash
   free -h && top -bn1 | head -5
   ```

### Immediate Action
1. If PostgreSQL is stopped, restart it:
   ```bash
   docker restart ep-governance-postgres
   ```
   Wait for it to accept connections before restarting the EP service and proxy.
2. If disk is full, free space (trim WAL, remove old logs, vacuum) and restart PostgreSQL.
3. If PostgreSQL is running but refusing connections due to `max_connections` or resource exhaustion, increase limits or kill stale connections.
4. If the database is corrupted, restore from the most recent backup. See RB-12 if migrations are needed after restore.
5. **Do NOT force-write transitions or audit events while the database is unavailable.** The hash chain depends on sequential writes; out-of-band writes will break integrity (see RB-05).
6. Once the database is back, restart the EP service and proxy in order:
   ```bash
   # 1. Verify DB
   psql -h <database-host> -U ep_governance -d ep_governance -c "SELECT 1;"
   # 2. Restart proxy
   docker restart ep-governance-proxy
   # 3. Restart EP service
   # (depends on your launch method — systemd, etc.)
   ```
7. After recovery, verify audit chain integrity:
   ```bash
   ep-governance audit verify --lattice <lattice_id>
   ```
   Repeat for each lattice. Investigate any failures (see RB-05).

### Follow-up
- Review PostgreSQL configuration for connection pooling (pgbouncer) to prevent future exhaustion.
- Set up database monitoring (connection count, disk usage, replication lag).
- Schedule regular PostgreSQL backups (pg_dump or WAL archiving).
- Document the backup restore procedure and test it quarterly.

### Prevention
- Use Docker `--restart unless-stopped` for the PostgreSQL container.
- Configure WAL archiving and point-in-time recovery.
- Monitor disk usage on the proxy host — alert at 80%.
- Run periodic `ep-governance audit verify` checks as a health probe.

---

## RB-05: Audit Verification Failure

### Symptoms
- `ep-governance audit verify --lattice <id>` returns `valid: false`.
- An `AuditChainError` is raised during verification.
- A recomputed event hash does not match the stored `event_hash`, or `previous_hash` linkage is broken.

### Diagnosis
1. Run verification for the affected lattice to confirm:
   ```bash
   ep-governance audit verify --lattice <lattice_id> --json
   ```
2. List all events for the lattice to find the break point:
   ```bash
   ep-governance audit list --lattice <lattice_id> --json
   ```
3. Compare the stored `event_hash` and `previous_hash` for each event. The `AuditVerifier` checks:
   - Recomputed SHA-256 of the canonical envelope matches the stored `event_hash`.
   - Each event's `previous_hash` matches the preceding event's `event_hash` (or `GENESIS_HASH` for the first event).
4. The canonical envelope includes: `sequence`, `event_id`, `lattice_id`, `event_type`, `event_data`, `actor_principal_id`, `authenticated_caller_id`, `event_writer_id`, `created_at`, `previous_hash`. Any tampering with these fields will cause a mismatch.
5. Identify the first event where the chain breaks. Events before it are intact; events from the break onward are suspect.

### Immediate Action
1. **Treat this as a potential security incident.** A broken audit chain may indicate tampering, database corruption, or a bug in the audit writer.
2. **Quarantine the database.** Stop the EP service and proxy to prevent further writes:
   ```bash
   # Stop EP service on EP service host
   # Stop proxy on the proxy host
   docker stop ep-governance-proxy
   ```
3. **Export the current audit table** for forensic analysis:
   ```sql
   SELECT id, lattice_id, sequence, event_type, event_data,
          previous_hash, event_hash, actor_principal_id,
          authenticated_caller_id, event_writer_id, created_at
   FROM ep_events
   WHERE lattice_id = '<lattice_id>'
   ORDER BY sequence;
   ```
4. **Determine the cause:**
   - If a single event's `event_data` was modified (JSON differs), this is likely direct database tampering — escalate to security.
   - If the `previous_hash` linkage is broken but individual hashes are valid, an event may have been deleted or inserted out of order — the `ep_events` table is supposed to be append-only.
   - If the `event_writer_id` differs from the EP service principal ID, an unauthorized writer injected events — escalate to security.
5. **If the cause is database corruption** (not malicious), restore from a known-good backup and replay any missing events if possible.
6. **If the cause is a software bug** in `AuditWriter`, identify the code path and patch it. The audit writer uses `canonical_json` for deterministic serialization — a change in serialization logic between write and verify would cause false failures.

### Follow-up
- Conduct a full security review if tampering is confirmed.
- File a critical issue if the cause is a software bug.
- Run `ep-governance audit verify` for all lattices after recovery to confirm full chain integrity.
- Consider adding a periodic automated verification job (cron) that checks all lattices and alerts on failure.

### Prevention
- Run `ep-governance audit verify` daily for all lattices. The `AuditVerifier.verify_all()` method returns a `{lattice_id: bool}` mapping.
- Enforce append-only at the database level (revoke UPDATE/DELETE on `ep_events` for the application role).
- Restrict direct database access — only the EP service and proxy should have write access.
- Monitor for direct database modifications outside of EP-Governance.

---

## RB-06: Policy Deployment Rollback

### Symptoms
- A recently deployed policy change is causing actions to be incorrectly denied or approved.
- Agents report "Action blocked by current policy" or "Stale authorization: effective policy set has changed" errors from the proxy.
- The policy change was activated and is now affecting live transitions.

### Diagnosis
1. Identify the policy that was recently changed:
   ```sql
   SELECT id, effect, priority, lifecycle_state, activation_version, updated_at
   FROM ep_policies
   ORDER BY updated_at DESC
   LIMIT 10;
   ```
2. Check which transitions are being affected:
   ```sql
   SELECT id, stage, action, matched_policy_versions, policy_set_hash
   FROM ep_transitions
   WHERE stage IN ('denied', 'pending_approval', 'authorized')
   ORDER BY updated_at DESC
   LIMIT 20;
   ```
3. Review the policy's current effect and scope to confirm it is causing the problem.
4. Check if any transitions in `executing` are failing with "stale authorization" in the proxy — the proxy revalidates policies at execution time and compares `policy_set_hash`.

### Immediate Action
1. **Deactivate or revert the problematic policy.** Set its `lifecycle_state` back to `inactive` (or revert the effect/scope):
   ```sql
   UPDATE ep_policies
   SET lifecycle_state = 'inactive', updated_at = NOW()
   WHERE id = '<policy_id>';
   ```
   This must be done through the EP governance management interface or directly via SQL if the management API is unavailable.
2. **Re-propose affected transitions.** Transitions that were denied due to the bad policy need to be re-proposed by the agent with a new idempotency key. The old denied transitions are terminal and cannot be retried.
3. **For transitions stuck with "stale authorization":** the proxy rejected execution because `policy_set_hash` changed between authorization and execution. After reverting the policy, the agent must obtain a fresh authorization (re-propose) since the token's embedded `policy_set_hash` no longer matches the reverted policy set. Alternatively, if the revert restores the exact same policy set hash, existing unexpired tokens may work — but this is unreliable; prefer re-proposal.
4. **Verify the rollback** by proposing a test action that was previously blocked:
   ```bash
   ep-governance check --tool <tool> --arguments '<json>'
   ```

### Follow-up
- Review the policy change process — was the policy tested in `check` mode before activation?
- Implement a policy staging environment where new policies are evaluated against historical action traces before going live.
- Document the incorrect policy and its impact for the post-mortem.
- Consider adding a policy "canary" mode that applies the policy to a subset of actions before full activation.

### Prevention
- Always test policy changes with `ep-governance check` before activating.
- Use policy activation versions to stage rollouts.
- Maintain a policy change log and require approval for policy modifications.
- Keep a rapid-rollback procedure documented and tested.

---

## RB-07: Expired Authorization

### Symptoms
- An agent receives `TokenExpiredError` when attempting to execute via `ep_execute`.
- The proxy returns "Token verification failed: invalid signature or expired".
- A transition is in `authorized` stage but the authorization token's `expires_at` has passed (default TTL: 300 seconds / 5 minutes).
- Transitions may also be in `pending_approval` or `authorized` with `expired` as the next legal stage.

### Diagnosis
1. Check the transition's current stage:
   ```bash
   ep-governance status --transition <transition_id>
   ```
2. Check the authorization record:
   ```sql
   SELECT id, issued_at, expires_at, used, claimed_at
   FROM ep_authorizations WHERE transition_id = '<transition_id>';
   ```
3. Compare `expires_at` with the current time. The default TTL is `DEFAULT_TOKEN_TTL_SECONDS = 300` (5 minutes).
4. Determine why the token expired before execution:
   - Agent delayed execution too long after authorization.
   - Proxy was unreachable (see RB-03) so the agent could not execute in time.
   - The approval process took too long, leaving little TTL for execution.

### Immediate Action
1. **If the transition is still in `authorized`:** The transition can be expired to clean up:
   ```bash
   ep-governance expire --transition <TRANSITION_ID> --reason "Operator advancing stale transition"
   ```
   This is a legal transition: `authorized → expired`.
2. **If the transition is in `pending_approval`:** Similarly, it can be expired:
   ```bash
   ep-governance expire --transition <TRANSITION_ID> --reason "Operator advancing stale transition"
   ```
   Legal transition: `pending_approval → expired`.
3. **The agent must re-propose** the action with a new idempotency key. The old transition is terminal (`expired`) and cannot be re-authorized.
4. **If the expiration was caused by proxy unavailability**, resolve RB-03 first, then have the agent re-propose.

### Follow-up
- Review whether the 5-minute default TTL is sufficient for your operational tempo. If approvals frequently take longer, consider increasing `DEFAULT_TOKEN_TTL_SECONDS` or streamlining the approval workflow.
- If expirations are frequent due to slow proxy response, investigate proxy performance.
- Set up monitoring for transitions in `authorized` approaching their expiry time.

### Prevention
- Alert on transitions in `authorized` or `pending_approval` for more than 4 minutes (80% of default TTL).
- Ensure the proxy is healthy and responsive so agents can execute promptly after authorization.
- For workflows with long approval cycles, consider a two-phase approach: approve first, then authorize with a fresh token.
- Run a periodic cleanup job to expire stale `authorized`/`pending_approval` transitions.

---

## RB-08: Lost Signing Key

### Symptoms
- The EP service cannot sign new authorization tokens — `KeyManager` fails to load the private key file.
- Error: file not found, or `TokenInvalidError: Private key file must contain 32 bytes`.
- Existing tokens cannot be verified by the proxy (if the old public key is also lost).
- New `ep_execute` calls fail at the signature verification step in the proxy.

### Diagnosis
1. Check if the signing key file exists:
   ```bash
   ls -la /var/lib/ep-governance/ep_signing.key
   ```
   (Or whatever path is configured for the EP service.)
2. Check file permissions and size — the key file should be exactly 32 bytes, mode `0600`.
3. Check EP service logs for `KeyManager` or `TokenInvalidError` errors.
4. Check if the key file was deleted, moved, or corrupted (e.g., truncated by a disk full event).

### Immediate Action
1. **Generate a new Ed25519 keypair:**
   ```bash
   # Generate a new 32-byte Ed25519 private key
   python3 -c "from ep_governance.authorizations import KeyManager; km = KeyManager(); km.save_private_key('/var/lib/ep-governance/ep_signing.key')"
   ```
   Ensure the file is written with mode `0600` (`save_private_key` does this automatically).
2. **Update the proxy's public key.** The proxy needs the new public key to verify tokens signed by the new private key. Distribute the new public key to the proxy configuration and restart the proxy:
   ```bash
   docker restart ep-governance-proxy
   ```
3. **Old tokens remain verifiable during the transition window** if the proxy still has the old public key. However, if the old key is completely lost, old unclaimed tokens cannot be verified and are effectively dead. Agents holding expired or unclaimable tokens must re-propose.
4. **Restart the EP service** so it loads the new signing key.
5. **Expire any orphaned authorizations** that were signed with the old key and cannot be verified:
   ```sql
   UPDATE ep_transitions SET stage = 'expired'
   WHERE stage = 'authorized' AND id IN (
       SELECT transition_id FROM ep_authorizations
       WHERE used = FALSE
   );
   ```
   (Use the transition engine's `advance_stage` for proper audit logging rather than direct SQL.)

### Follow-up
- **Back up the new signing key** to a secure, off-host location (e.g., encrypted backup, hardware security module, or a secrets manager like HashiCorp Vault).
- Document the key rotation procedure and store it with the runbooks.
- Audit who has access to the signing key file.
- Review file system monitoring to alert on deletion or modification of the key file.

### Prevention
- Store the signing key in a secure key management system (HSM, Vault) rather than a plain file.
- Maintain encrypted backups of the signing key in at least two locations.
- Monitor the key file with file integrity monitoring (FIM) — alert on any change.
- Test key rotation periodically (quarterly) so the procedure is practiced.

---

## RB-09: Compromised Agent Credential

### Symptoms
- An agent's credentials (API key, mTLS cert, or authentication token) are suspected or confirmed compromised.
- Unauthorized actions may have been proposed or executed under the agent's identity.
- The agent's `agent_id` appears in audit events for actions the agent did not perform.

### Diagnosis
1. Review all recent transitions and audit events for the compromised agent:
   ```sql
   SELECT id, stage, tool, action, created_at, updated_at
   FROM ep_transitions
   WHERE agent_id = '<compromised_agent_id>'
   ORDER BY created_at DESC
   LIMIT 50;
   ```
2. Check audit events:
   ```bash
   ep-governance audit list --lattice <lattice_id> --json
   ```
   Filter for `actor_principal_id` matching the compromised agent.
3. Identify any transitions that were authorized and executed that should not have been.
4. Check if any tokens were issued for the compromised agent after the suspected compromise time.

### Immediate Action
1. **Revoke the agent's credentials.** Update the agent registry / identity provider to disable the compromised agent. This prevents new proposals from being authenticated.
2. **Expire all non-terminal transitions** for the compromised agent:
   ```bash
   # For transitions in authorized or pending_approval stage:
   ep-governance expire --transition <TRANSITION_ID> --reason "Credential compromise — operator cleanup"
   ```
   Repeat for each affected transition ID.
3. **Expire any authorized-but-unclaimed tokens** for the agent to prevent proxy execution:
   ```bash
   ep-governance expire --transition <TRANSITION_ID> --reason "Credential compromise — expiring unclaimed token"
   ```
4. **Do NOT expire transitions in `executing`** — these may have already been claimed by the proxy and the action may be in progress. Instead, monitor them and reconcile once complete (see RB-02).
5. **Review all executed actions** by the compromised agent. If any caused harmful side effects on target systems, initiate remediation on those systems directly (rollback database changes, stop containers, etc.).
6. **Verify audit chain integrity** to ensure the attacker did not tamper with the audit log:
   ```bash
   ep-governance audit verify --lattice <lattice_id>
   ```

### Follow-up
- Conduct a full security incident review. Determine how the credential was compromised.
- Rotate all agent credentials, not just the compromised one, if the compromise method could have exposed others.
- Review policy configurations — were the policies too permissive for the agent? Tighten scope.
- File an incident report documenting the timeline, impact, and remediation.
- Consider adding agent credential rotation as a regular operational practice.

### Prevention
- Use short-lived, automatically rotated credentials for agents (never long-lived static API keys).
- Implement least-privilege policies so a compromised agent can only affect its scoped resources.
- Monitor for anomalous agent behavior (unusual action patterns, off-hours activity, unexpected tools).
- Alert on any transition proposed by a disabled/revoked agent.

---

## RB-10: Compromised Proxy Credential

### Symptoms
- The proxy's credentials (target system credentials: database password, SSH key, API token) are suspected or confirmed compromised.
- The proxy's own identity (used to authenticate to EP) may also be compromised.
- Unauthorized actions may have been executed on target systems using the proxy's credentials.
- The proxy container on the proxy host may have been accessed by an unauthorized party.

### Diagnosis
1. Review proxy access logs and Docker container logs for unusual activity:
   ```bash
   docker logs --since 24h ep-governance-proxy
   ```
2. Check all transitions that were executed through the proxy in the suspected compromise window:
   ```sql
   SELECT t.id, t.stage, t.tool, t.agent_id, t.exit_status, t.result_summary, t.updated_at
   FROM ep_transitions t
   WHERE t.stage IN ('succeeded', 'failed', 'execution_uncertain', 'executing')
     AND t.updated_at > '<suspected_compromise_time>'
   ORDER BY t.updated_at;
   ```
3. Check the target systems for unauthorized changes (unexpected database modifications, new containers, SSH login logs).
4. Review proxy host access logs for unauthorized SSH or Docker API access.

### Immediate Action
1. **Stop the proxy container immediately** to prevent further unauthorized executions:
   ```bash
   docker stop ep-governance-proxy
   ```
2. **Rotate all target credentials** that the proxy had access to:
   - Database passwords: change the PostgreSQL user password.
   - SSH keys: generate new keys and update `authorized_keys` on target hosts.
   - API tokens: revoke and reissue all cloud API tokens the proxy held.
   - Docker credentials: rotate Docker registry passwords if applicable.
3. **Rotate the proxy's EP authentication credentials.** The proxy authenticates to EP — if those credentials are compromised, an attacker could submit fraudulent results. Generate new proxy credentials and update EP's configuration.
4. **Re-verify all recent audit events.** A compromised proxy could have submitted false execution results. Cross-check `result_summary` fields against actual target system state.
5. **Review all transitions in `executing` or `execution_uncertain`** from the compromise window — these may have been executed by the attacker. Manually verify each one against the target system.
6. **Deploy a clean proxy container** with the new credentials:
   ```bash
   docker run -d --name ep-governance-proxy --restart unless-stopped \
     -v /path/to/new/config:/config \
     ep-governance-proxy:latest
   ```
7. **Verify the new proxy is healthy** before allowing agents to resume execution.

### Follow-up
- Conduct a full security incident investigation. Determine how the proxy credentials were compromised (proxy host breach, Docker daemon compromise, configuration leak).
- Review proxy host security posture — SSH access controls, Docker socket permissions, firewall rules.
- Audit all target systems for persistent backdoors or unauthorized changes.
- File an incident report.

### Prevention
- Store proxy credentials in a secrets manager (Vault, Docker secrets) — never in environment variables or config files in plaintext.
- Restrict proxy host SSH access to specific keys and IP ranges.
- Run the proxy container with minimal privileges (no Docker socket mount, read-only filesystem where possible).
- Monitor proxy container for unauthorized configuration changes.
- Rotate proxy credentials regularly (monthly or quarterly).

---

## RB-11: Branch-Head Conflict

### Symptoms
- The proxy returns an error like "Execution succeeded but governance commit failed — manual reconciliation required."
- `StaleHeadError` is raised during `branch_committer.commit()`.
- A transition is stuck in `execution_uncertain` because the branch head advanced between proposal and execution.
- `ep-governance status --transition <id>` shows `stage=execution_uncertain` with `requires_manual_reconciliation=TRUE`.

### Diagnosis
1. Check the transition's `expected_head_id` and `expected_version`:
   ```sql
   SELECT id, branch_id, expected_head_id, expected_version, stage
   FROM ep_transitions WHERE id = '<transition_id>';
   ```
2. Check the current branch head:
   ```sql
   SELECT head_node_id, version FROM ep_branches WHERE id = '<branch_id>';
   ```
3. If `expected_head_id` does not match the current `head_node_id`, another transition committed a node between this transition's proposal and execution — the branch head moved.
4. Review the branch's recent commits to find the conflicting transition:
   ```sql
   SELECT id, transition_id, parent_node_id, created_at
   FROM ep_nodes
   WHERE branch_id = '<branch_id>'
   ORDER BY created_at DESC
   LIMIT 10;
   ```
5. Determine whether the action actually executed successfully on the target system (the branch-head conflict occurs *after* the adapter succeeded — the action is done, only the governance graph failed to record it).

### Immediate Action
1. **Confirm the action succeeded on the target system** (same as RB-02 diagnosis).
2. **Reconcile with updated branch head expectations.** Use the `reconcile` command with the current branch head:
   ```bash
   ep-governance reconcile --transition <TRANSITION_ID> --outcome succeeded --reason "Operator confirmed" --branch <BRANCH_ID>
   ```
   The command reads the current branch head to ensure the commit targets the correct state.
3. **If reconcile-as-succeeded fails again** (another concurrent commit moved the head), retry with the updated head. The transition remains at `execution_uncertain` between retries.
4. **If the conflict cannot be resolved** (e.g., the action's effects are incompatible with the newer branch state), reconcile as `failed` and have the agent re-propose.

### Follow-up
- Review the concurrency model — multiple agents committing to the same branch simultaneously will cause frequent head conflicts.
- Consider serializing commits to a single branch, or use separate branches for parallel work.
- Document which branches are hot spots for conflicts.

### Prevention
- Use `expected_head_id` and `expected_version` when proposing transitions to detect conflicts early (at proposal time rather than after execution).
- Limit the number of agents concurrently executing on the same branch.
- Consider a branch-level commit queue or lock for high-contention branches.
- Monitor for `transition.execution_uncertain` events caused by commit failures and alert immediately.

---

## RB-12: Migration Failure

### Symptoms
- `ep-governance` CLI commands fail with `MigrationError` or schema-related `OperationalError`.
- `run_migrations()` raises an exception during EP service or proxy startup.
- The database schema is in an inconsistent state — some tables exist, others are missing or have wrong columns.
- Application errors reference missing tables or columns.

### Diagnosis
1. Check the migration error message — `MigrationError` from `ep_governance.errors` indicates a failed migration.
2. Check the database's migration history table (if applicable) to see which migrations were applied:
   ```sql
   SELECT * FROM ep_schema_migrations ORDER BY version;
   ```
3. Check whether the failure was partial — some DDL may have succeeded before the error, leaving the schema inconsistent.
4. Check PostgreSQL logs for constraint violations or syntax errors during migration:
   ```bash
   docker logs --tail 50 ep-governance-postgres
   ```

### Immediate Action
1. **Stop the EP service and proxy** to prevent further operations against a partially migrated database:
   ```bash
   docker stop ep-governance-proxy
   # Stop EP service on EP service host
   ```
2. **Assess the damage.** Determine which migrations succeeded and which failed:
   ```sql
   -- List all tables to see current schema state
   SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename;
   ```
3. **If the failure is in a single migration** and no data was lost:
   - Manually fix the failing DDL (e.g., add a missing constraint, fix a column type).
   - Mark the migration as applied if the fix is complete.
4. **If the schema is severely inconsistent:**
   - Restore the database from the most recent backup taken before the migration attempt.
   ```bash
   # Restore from backup
   psql -h <database-host> -U ep_governance -d ep_governance < backup.sql
   ```
   - Re-run migrations after fixing the migration script.
5. **If the migration includes data transformations** (not just DDL) and the data transform failed partway:
   - Restore from backup if possible.
   - If backup restore is not feasible, manually identify and fix the partial data transformation.
6. **After fixing, re-run migrations:**
   ```bash
   ep-governance serve  # migrations run automatically on startup via _get_conn_with_migrations()
   ```
   Or run migrations explicitly if the CLI supports it.
7. **Verify the schema is complete** by running a test governance operation.

### Follow-up
- Review the failing migration script and fix the bug.
- Add migration tests to the CI pipeline — run migrations against a copy of the production database before deploying.
- Implement migration rollback scripts (down migrations) for critical schema changes.
- Document the migration procedure, including backup and rollback steps.

### Prevention
- **Always take a database backup before running migrations.** Automate this:
  ```bash
  pg_dump -h <database-host> -U ep_governance ep_governance > emergency_backup_$(date +%Y%m%d_%H%M%S).sql
  ```
- Test migrations on a staging database that mirrors production before deploying.
- Run migrations in a transaction so partial failures roll back automatically (PostgreSQL supports transactional DDL).
- Version the migration scripts and never modify applied migrations — always write new ones.
- Monitor the migration process during deployment and alert on failures.

---

## RB-13: Network Partition

### Symptoms
- The EP service (EP service host) cannot reach the proxy (proxy host) or the database (database host).
- The proxy (proxy host) cannot reach the EP service (EP service host) to report results.
- Agents (EP service host, agent host) cannot reach the EP service to propose or execute.
- Operations fail with connection timeouts or `OperationalError`.
- Some components are functioning normally while others are isolated.

### Diagnosis
1. Test connectivity from each component to every other component:
   ```bash
   # EP service host → proxy host (proxy)
   nc -zv <proxy-host> <proxy-port>
   # EP service host → database host (database)
   nc -zv <database-host> 5432
   # proxy host → EP service host (EP service)
   ssh <proxy-host> nc -zv <ep-service-host> <ep-service-port>
   # agent host → EP service host (EP service)
   ssh <agent-host> nc -zv <ep-service-host> <ep-service-port>
   ```
2. Check if the VPN or mesh network is connected:
   ```bash
   # Example: check VPN / mesh network status
   # (command depends on your network setup)
   ```
3. Check for asymmetric partitions — the EP service host might reach the proxy host but not vice versa.
4. Check for DNS resolution failures if hostnames are used.
5. Determine the partition scope: is it a single host down, a network segment isolated, or a broader outage?

### Immediate Action
1. **Identify and fix the network issue:**
   - If the VPN/mesh network is down: restart it or wait for it to reconnect.
   - If a switch or router is down: escalate to network operations.
   - If a host is down: see RB-03 (proxy) or RB-04 (database).
2. **During the partition, the system degrades as follows:**
   - **EP service host ↔ proxy host partition:** EP service cannot write audit events or transitions. Proxy cannot report results. Transitions in `executing` will eventually become `execution_uncertain` (see RB-02). No new proposals can be made.
   - **agent host ↔ EP service host partition:** Agent-host agents cannot propose or execute. EP service host agents continue normally. No impact on governance state.
   - **proxy host internal (proxy ↔ database):** Proxy cannot claim authorizations or record results. Transitions stay in `authorized`. See RB-03 and RB-04.
3. **Do NOT attempt to force operations during a partition.** Writing to a disconnected component may cause split-brain or data loss.
4. **Once connectivity is restored:**
   - Restart the EP service and proxy to re-establish connections.
   - Check for transitions left in `executing` and advance stale ones to `execution_uncertain` (see RB-01).
   - Reconcile any `execution_uncertain` transitions (see RB-02).
   - Verify audit chain integrity (see RB-05).
5. **If the partition is prolonged** (hours), consider:
   - Expiring all `authorized` transitions since their tokens will have expired.
   - Notifying agents that governance is temporarily unavailable.

### Follow-up
- Document the partition cause and duration.
- Review network redundancy — consider multiple network paths or a backup VPN.
- Set up network monitoring that alerts on partition detection (e.g., synthetic checks between hosts).
- Test the recovery procedure after a simulated partition.

### Prevention
- Use a mesh VPN or resilient network connectivity between EP service host, proxy host, and agent host.
- Configure DNS with short TTLs and multiple resolvers.
- Implement health checks between all components and alert on failures within 60 seconds.
- Have a documented escalation path for network issues.
- Practice network partition recovery in a staging environment.

---

## RB-14: Emergency Shutdown

### Symptoms
- A critical security incident, unrecoverable system failure, or external mandate requires immediate cessation of all EP-Governance operations.
- All governance activity must be halted to prevent further actions on target systems.
- This is the "kill switch" — used only when continued operation poses greater risk than shutdown.

### Diagnosis
1. Confirm that an emergency shutdown is warranted. This decision should be made by an on-call operator with authority to halt operations, or in response to:
   - Confirmed audit chain tampering (RB-05).
   - Compromised signing key with active exploitation (RB-08).
   - Compromised proxy or agent credentials with active unauthorized actions (RB-09, RB-10).
   - Unrecoverable database corruption (RB-04).
   - External security mandate or legal hold.
2. Assess whether a partial shutdown (stopping only the proxy) is sufficient, or whether a full shutdown (EP service + proxy + agents) is required.

### Immediate Action
1. **Stop the governed proxy first** — this is the single most critical step. The proxy is the only path to target system execution. Stopping it immediately prevents all consequential actions:
   ```bash
   docker stop ep-governance-proxy
   ```
2. **Stop the EP service** to prevent new authorizations from being issued:
   ```bash
   # On EP service host — depends on your launch method:
   # systemd:  systemctl stop ep-governance
   # manual:   kill <ep-service-pid>
   ```
3. **Stop or suspend agents** to prevent them from retrying `ep_execute` calls:
   - EP service host agents: stop the agent processes.
   - Agent-host agents: `ssh <agent-host> '<stop-command>'`
4. **Record the shutdown time** — all transitions in non-terminal stages will remain in their current state. This is correct and expected; they will be reconciled during recovery.
5. **Do NOT modify the database directly** during shutdown. The audit chain and transition state must be preserved for investigation.
6. **Take a database backup** for forensic analysis (if the database is still accessible):
   ```bash
   pg_dump -h <database-host> -U ep_governance ep_governance > emergency_backup_$(date +%Y%m%d_%H%M%S).sql
   ```
7. **Notify all stakeholders:**
   - Operators and on-call team.
   - Users/agents that depend on governance.
   - Security team (if incident-related).
8. **Post a status message** indicating governance is down for emergency maintenance.

### Follow-up
- **Before resuming operations**, complete the investigation that triggered the shutdown.
- Fix the root cause (rotate keys, patch vulnerabilities, restore database, etc.).
- **On restart, follow this order:**
  1. Verify the database is healthy and audit chains are intact (RB-05).
  2. Start the EP service.
  3. Start the proxy (RB-03).
  4. Reconcile any transitions left in `executing` or `execution_uncertain` (RB-01, RB-02).
  5. Expire any stale `authorized` transitions whose tokens have expired (RB-07).
  6. Resume agents.
- **Conduct a post-incident review** documenting:
  - Timeline of the incident and shutdown.
  - Root cause.
  - Impact (transitions affected, actions blocked, data at risk).
  - Recovery steps taken.
  - Preventive measures implemented.
- **Update this runbook** with any lessons learned from the incident.

### Prevention
- Maintain a tested emergency shutdown procedure and ensure all operators are trained on it.
- Implement a "maintenance mode" flag in the EP service that rejects new proposals without requiring a full process stop — this allows faster, cleaner shutdowns.
- Keep the shutdown procedure accessible offline (printed or in a local file) in case the documentation system is also affected.
- Conduct quarterly tabletop exercises simulating emergency shutdown scenarios.
- Ensure the database backup procedure is automated and verified so forensic backups are always available.