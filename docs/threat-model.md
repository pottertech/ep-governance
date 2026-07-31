# EP-Governance Threat Model

**Version:** 1.0
**Date:** July 30, 2026

## 1. Protected Assets

| Asset | Location | Impact if Compromised |
|-------|----------|----------------------|
| Governance DAG (nodes, edges, branches) | PostgreSQL | State history corrupted, false nodes inserted |
| Audit chain | PostgreSQL (ep_events) | Tampered history, undetected actions |
| Active policies | PostgreSQL (ep_policies) | Bypassed controls, unauthorized actions allowed |
| Ed25519 signing key | EP service filesystem | Forged authorization tokens, arbitrary execution |
| Proxy target credentials | Proxy environment | Direct database access bypassing governance |
| Authorization tokens (in transit) | Network | Replayed actions, if not yet claimed |
| Agent credentials | Agent environment | Impersonation, unauthorized proposals |

## 2. Trust Boundaries

```
┌─────────────────────────────────────────────────────────┐
│  TRUSTED ZONE (EP Service + Governance DB)              │
│                                                         │
│  ┌───────────┐    ┌──────────────┐    ┌─────────────┐   │
│  │ EP Service │    │ Governance   │    │ Signing Key │   │
│  │ (Python)   │◄──►│ DB (Postgres)│    │ (filesystem)│   │
│  └─────┬─────┘    └──────────────┘    └─────────────┘   │
│        │                                               │
└────────┼───────────────────────────────────────────────┘
         │ Signed token (crosses boundary)
┌────────┼───────────────────────────────────────────────┐
│        ▼                                               │
│  ┌───────────┐    ┌──────────────┐                     │
│  │  Proxy    │───►│ Target DB    │   SEMI-TRUSTED      │
│  │ (Docker)  │    │ (Postgres)   │                     │
│  └───────────┘    └──────────────┘                     │
└─────────────────────────────────────────────────────────┘
         ▲
         │ Signed token (crosses boundary)
┌────────┼───────────────────────────────────────────────┐
│        │          UNTRUSTED ZONE (Agent)                │
│  ┌───────────┐                                        │
│  │  Agent    │  No target DB credentials               │
│  │  (LLM)    │  No direct DB access                    │
│  └───────────┘                                        │
└─────────────────────────────────────────────────────────┘
```

## 3. Trusted Components

| Component | Trust Level | Rationale |
|-----------|------------|-----------|
| EP Service | Trusted | Holds signing key, writes audit, evaluates policies |
| Governance DB (PostgreSQL) | Trusted | Authoritative state, protected by roles |
| Audit chain | Trusted | Append-only, hash-chained, role-protected |

## 4. Partially Trusted Components

| Component | Trust Level | Rationale |
|-----------|------------|-----------|
| Proxy | Semi-trusted | Holds target credentials but NOT signing key; can execute SQL but cannot mint tokens |
| Agent | Semi-trusted | Can propose actions and receive tokens but cannot execute without proxy |
| MCP Server | Semi-trusted | Exposes governance tools to agents; authentication is interim |

## 5. Untrusted Components

| Component | Trust Level | Rationale |
|-----------|------------|-----------|
| Network | Untrusted | Tokens in transit could be intercepted (mitigated by TLS in production) |
| Agent filesystem | Untrusted | Agent may have access to its own files but NOT signing key or proxy credentials |

## 6. Assumed Attacker Capabilities

| Capability | Assumed? | Mitigation |
|-----------|----------|------------|
| Read network traffic | Yes (without TLS) | TLS for MCP HTTP transport; tokens are single-use and short-lived |
| Intercept and replay tokens | Yes | Atomic claim (UPDATE WHERE used=FALSE), 5-minute TTL, nonce per token |
| Modify tokens in transit | Yes | Ed25519 signature verification by proxy |
| Agent bypasses EP and connects to DB directly | Yes | Network isolation: agent has no target DB credentials, pg_hba.conf restricts access |
| Agent supplies fake identity | Yes | MCP server uses authenticated_principal_id from session, not caller-supplied |
| Agent attempts self-approval | Yes | Separation of duties: requester != approver, agents cannot approve |
| Database admin modifies audit | Yes | Hash chain detects tampering; but DB admin can drop tables (residual risk) |
| Compromised proxy replays tokens | Yes | Tokens are single-use; proxy can only claim once |
| Compromised proxy alters payload | Yes | Payload hash verified by proxy from actual payload, not caller-supplied |
| Signing key stolen | No (assumed protected) | Key file 0600, on trusted host; if stolen, all tokens forgeable |
| PostgreSQL superuser access | No (assumed protected) | Superuser can modify any table including audit; residual risk |

## 7. Attacks Explicitly Resisted

| Attack | Mitigation | Test Coverage |
|--------|-----------|---------------|
| Token replay | Atomic claim, single-use, TTL | test_two_claims_one_token, test_token_reuse_rejected, test_50_simultaneous_claims |
| Payload tampering | Proxy computes hash from actual payload | test_altered_payload_rejected, test_payload_tampering |
| Stale authorization | policy_set_hash comparison before execution | test_stale_authorization |
| Multi-statement SQL injection | Multi-statement detection in classifier | test_select_then_drop, test_multi_statement_always_opaque |
| Shell command evasion | Dangerous pattern detection, opaque classification | test_eval_injection, test_python_interpreter, test_sudo_escalation |
| Audit chain tampering | Hash chain with previous_hash linkage | test_tamper_detected_by_verifier |
| Branch head race | Optimistic concurrency (expected_head_id + expected_version) | test_20_concurrent_commits, test_stale_head_detected |
| Self-approval | Separation of duties (approver != requester, human-only) | test_agent_cannot_approve_own_action |
| Denied action creates node | Node creation only after successful execution | test_denied_transition_no_node |
| Token expiry during partition | TTL enforced in claim (expires_at > NOW()) | test_expired_token_cannot_be_claimed |
| Duplicate result reporting | Terminal state enforcement (IllegalTransitionError) | test_duplicate_success_rejected |
| Conflicting results | Terminal state blocks conflicting reports | test_success_then_conflicting_failure_rejected |
| Proxy crash | execution_uncertain stage, manual reconciliation | test_crash_leaves_executing_then_timeout_to_uncertain |

## 8. Attacks Explicitly NOT Resisted

| Attack | Why Not | Residual Risk |
|--------|---------|---------------|
| PostgreSQL superuser drops audit table | No defense against DB superuser | Audit history lost; use backups and log forwarding |
| Signing key compromise | Assumes key is protected by filesystem permissions | All tokens forgeable; rotate key immediately |
| Agent host compromise (full root) | Agent could intercept signing key if co-located with EP | Separate EP from agent in production |
| Network-level DoS | No rate limiting on proxy HTTP endpoint | Proxy unavailable; transitions stuck in executing |
| Side-channel attacks on Ed25519 | Not in scope for this implementation | Theoretical timing leaks; use HSM in high-security deployments |
| Social engineering of human approver | Out of scope | Unauthorized approval; log all approval decisions |

## 9. STRIDE Analysis

| Threat | Component | Risk | Mitigation |
|--------|-----------|------|------------|
| **S**poofing | Agent impersonates another | High | MCP authenticated_principal_id from session context |
| **S**poofing | Proxy impersonates EP | Medium | Proxy has no signing key; cannot mint tokens |
| **T**ampering | Token payload modified | High | Ed25519 signature + payload hash verification |
| **T**ampering | Audit event modified | High | Hash chain + DB role enforcement (ep_agent cannot write) |
| **R**epudiation | Agent denies action | Medium | All actions logged in append-only audit with actor_principal_id |
| **I**nformation disclosure | Credentials in logs | Medium | Error redaction (High fix 12), no secret in CLI output |
| **I**nformation disclosure | Proxy output leaks secrets | Medium | Output redaction, 1000-row SELECT cap, output size limit |
| **D**enial of service | Flood proxy with requests | Medium | No rate limiting (TODO: production hardening) |
| **E**levation of privilege | Agent gains proxy credentials | High | Credential isolation: agent has no target DB credentials |
| **E**levation of privilege | Allow policy overrides deny | High | Override requires exception_to, narrower scope, time limit, justification |

## 10. Key Compromise Scenarios

### Signing Key Compromised

**Impact:** Attacker can mint authorization tokens for any action, any agent, any branch.

**Detection:** No automated detection. Compare token issuance logs with audit events.

**Response:**
1. Generate new signing key: `python -c "from ep_governance.authorizations import KeyManager; km = KeyManager(); km.save_private_key('ep_signing_new.key')"`
2. Update proxy with new public key
3. Revoke all active authorizations: `UPDATE ep_authorizations SET expires_at = NOW() WHERE used = FALSE`
4. Review audit log for suspicious transitions
5. Rotate all proxy credentials

### Proxy Credential Compromised

**Impact:** Attacker can connect directly to target database, bypassing governance.

**Detection:** Monitor for direct DB connections from unexpected IPs.

**Response:**
1. Rotate ep_proxy_user password
2. Update proxy .env.proxy with new credentials
3. Restart proxy container
4. Review database query logs for unauthorized access

### Agent Credential Compromised

**Impact:** Attacker can propose actions as the agent.

**Detection:** Monitor for proposals from unexpected sources or at unusual times.

**Response:**
1. Suspend agent principal: `UPDATE ep_principals SET status = 'suspended' WHERE id = '<agent_id>'`
2. Revoke all pending approvals for that agent
3. Review recent transitions by that agent
4. Re-register agent with new credentials