# EP-Governance Threat Model

**Version:** 1.0 (Phase 1)
**Date:** July 29, 2026
**Governing Sources:** v1.1 §23; v1.1.1 §8, additional corrections. Directive section 26 threats.

---

## Overview

This document covers all threats listed in the design directive section 26 (Security §23.1 and §23.2, v1.1.1 §8, and additional corrections). For each threat: asset, attacker, entry point, mitigation, detection, residual risk, and required test ID.

---

## T-001: Compromised Agent

| Field | Description |
|-------|-------------|
| **Asset** | Authorization tokens, policy state, branch integrity, audit trail |
| **Attacker** | An adversary who has gained control of an agent process |
| **Entry Point** | Agent process compromise (memory access, environment variables, local files) |
| **Mitigation** | Agents hold no target credentials (EP-ENFORCE-001). Agents receive only signed, short-lived, single-use, payload-bound tokens. Agents cannot mint tokens (Ed25519 private key is held by EP only). Separation of duties prevents self-approval. Agents cannot write audit events (EP-AUDIT-001). |
| **Detection** | Audit trail analysis: anomalous proposal patterns, rapid token requests, proposals from unexpected agents. Stale authorization detection catches replayed tokens. Duplicate callback detection catches replay attempts. |
| **Residual Risk** | A compromised agent can read active policies and branch state (not sensitive). A compromised agent can submit proposals within its authorized scope. Cannot bypass deny policies, cannot mint tokens, cannot directly access infrastructure in enforced mode. |
| **Required Test ID** | `TEST-SEC-001: Compromised agent cannot mint authorization tokens` |

---

## T-002: Compromised Proxy

| Field | Description |
|-------|-------------|
| **Asset** | Target infrastructure credentials, authorization tokens at claim time |
| **Attacker** | An adversary who has gained control of the governed proxy process |
| **Entry Point** | Proxy process compromise (network exploit, container escape, credential theft) |
| **Mitigation** | Proxy holds only the Ed25519 public verification key, not the private signing key (EP-AUTH-002). A compromised proxy cannot mint authorizations. Proxy validates token signature, expiry, payload hash, and single-use claim before executing. Atomic token claim prevents double-execution. |
| **Detection** | Audit trail: proxy executing actions not authorized by EP (would require forged tokens, which fail signature verification). Duplicate callback conflicts indicate potential proxy compromise. Monitoring proxy network traffic for unauthorized connections. |
| **Residual Risk** | A compromised proxy can execute actions that were authorized by EP (it holds the target credentials). It cannot mint new authorizations. It can replay a claimed token's result (detected by duplicate callback handling). It can refuse to execute (denial of service). |
| **Required Test ID** | `TEST-SEC-002: Compromised proxy cannot forge authorization tokens` |

---

## T-003: Compromised Agent Credential

| Field | Description |
|-------|-------------|
| **Asset** | Agent's API key / authentication credential |
| **Attacker** | An adversary who has stolen an agent's API key |
| **Entry Point** | Credential theft from agent configuration, environment variables, or logs |
| **Mitigation** | Credentials are hashed (not stored raw) (EP-IDENTITY-006). Constant-time comparison prevents timing attacks. Credential rotation and revocation supported. Short-lived authorization tokens limit the window of misuse. |
| **Detection** | Audit trail: proposals from unexpected hosts, unusual timing, proposals that the legitimate agent did not make. Credential revocation invalidates the stolen credential. |
| **Residual Risk** | Until the credential is revoked, the adversary can authenticate as the agent and submit proposals. They cannot bypass policies or access infrastructure directly (enforced mode). |
| **Required Test ID** | `TEST-SEC-003: Revoked agent credential is rejected` |

---

## T-004: Compromised Proxy Credential

| Field | Description |
|-------|-------------|
| **Asset** | Proxy's authentication credential to EP, target infrastructure credentials |
| **Attacker** | An adversary who has stolen proxy credentials |
| **Entry Point** | Credential theft from proxy configuration or environment |
| **Mitigation** | Proxy credentials to EP are separate from target infrastructure credentials. Proxy credentials are hashed. Target credentials are not stored in the EP database. Credential rotation supported. |
| **Detection** | Audit trail: callbacks from unexpected proxy identities. Proxy authentication failures. |
| **Residual Risk** | Adversary can impersonate the proxy and report false results (detected by execution_uncertain handling and reconciliation). Adversary with target credentials can access infrastructure directly (outside EP governance — this is a deployment security issue). |
| **Required Test ID** | `TEST-SEC-004: False proxy result report is detected via reconciliation` |

---

## T-005: Replayed Token

| Field | Description |
|-------|-------------|
| **Asset** | Authorization token |
| **Attacker** | An adversary who has intercepted a valid authorization token |
| **Entry Point** | Network interception, agent memory access, log exposure |
| **Mitigation** | Tokens are single-use (atomic claim with `used = FALSE` check). Tokens are short-lived (default 5-minute TTL). Tokens are payload-bound (proxy verifies payload hash matches). Tokens are agent-bound, project-bound, branch-bound, and proxy-bound. Token hash is stored, not the reusable token. |
| **Detection** | Atomic claim returns no row if token already used. Audit event for failed claim attempts. |
| **Residual Risk** | If the adversary intercepts the token before the legitimate proxy claims it, they could race to claim it first. The proxy-bound property limits this (the token specifies which proxy can use it). |
| **Required Test ID** | `TEST-SEC-005: Replayed token is rejected by atomic claim` |

---

## T-006: Altered Payload

| Field | Description |
|-------|-------------|
| **Asset** | Action payload integrity |
| **Attacker** | An adversary who modifies the action payload between authorization and execution |
| **Entry Point** | Man-in-the-middle between agent and proxy, or agent-level payload tampering |
| **Mitigation** | Token is payload-bound: `payload_hash` (SHA-256 of canonical arguments) is stored at authorization time. Proxy verifies that the executed payload hash matches the authorized payload hash. Mismatch → execution rejected. |
| **Detection** | Payload hash mismatch at proxy. Audit event for payload mismatch. |
| **Residual Risk** | None if the payload hash is correctly computed and verified. The SHA-256 hash is cryptographically strong. |
| **Required Test ID** | `TEST-SEC-006: Altered payload is rejected by proxy hash verification` |

---

## T-007: Stale Authorization

| Field | Description |
|-------|-------------|
| **Asset** | Authorization validity after policy changes |
| **Attacker** | An agent who obtains authorization and waits for policy changes before executing |
| **Entry Point** | Time gap between authorization and execution |
| **Mitigation** | Policy-set hash comparison at execution time (EP-AUTH-010, EP-AUTH-011). If relevant policies changed, token is invalidated and transition moves to `expired`. Short token TTL limits the window. |
| **Detection** | Policy-set hash mismatch at claim time. Audit event for stale authorization. |
| **Residual Risk** | Unrelated policy changes do not invalidate the token (by design). The agent must re-request if relevant policies changed. |
| **Required Test ID** | `TEST-SEC-007: Stale authorization is invalidated when relevant policy changes` |

---

## T-008: Direct Infrastructure Bypass

| Field | Description |
|-------|-------------|
| **Asset** | Target infrastructure (databases, servers, containers) |
| **Attacker** | An agent with direct infrastructure access |
| **Entry Point** | Agent environment with Docker socket, SSH keys, cloud CLI, database access |
| **Mitigation** | Enforced mode requires capability isolation (EP-ENFORCE-001 through EP-ENFORCE-008). Agent must not possess target credentials. No Docker socket, SSH-agent, or cloud CLI access. Network policy restricts access to sensitive targets. Only proxy can reach sensitive services. |
| **Detection** | Deployment verification checklist. If isolation is not achieved, system reports advisory and operates in advisory mode. |
| **Residual Risk** | EP-Governance cannot enforce capability isolation by itself — it depends on the runtime environment. If the deployment does not achieve isolation, the system operates in advisory mode regardless of `EP_MODE=enforced`. |
| **Required Test ID** | `TEST-SEC-008: Agent without credentials cannot bypass governed proxy` |

---

## T-009: Database Tampering

| Field | Description |
|-------|-------------|
| **Asset** | All governance state (nodes, edges, policies, transitions, audit events) |
| **Attacker** | An adversary with direct database write access (e.g., DBA) |
| **Entry Point** | Direct database access (SQL client, admin tools) |
| **Mitigation** | Database permissions: only EP service role can INSERT into `ep_events`. No role can UPDATE or DELETE audit records. Per-lattice hash-chained audit log provides tamper detection. External checkpoints provide additional verification. |
| **Detection** | Audit chain verification command recomputes all event hashes and checks chain integrity. Hash mismatch, sequence gap, or `previous_hash` mismatch indicates tampering. |
| **Residual Risk** | EP-Governance is detect-tamper, not prevent-tamper. A determined adversary with direct database write access can modify tables and recompute hashes (if they know the canonical JSON rules). External checkpoints limit the undetectable window. |
| **Required Test ID** | `TEST-SEC-009: Audit chain verification detects tampering` |

---

## T-010: Audit Log Tampering

| Field | Description |
|-------|-------------|
| **Asset** | Audit event records |
| **Attacker** | An adversary who modifies, deletes, or inserts fabricated audit events |
| **Entry Point** | Direct database access to `ep_events` table |
| **Mitigation** | Append-only: no UPDATE or DELETE permitted (EP-AUDIT-009). Only EP service writes events (EP-AUDIT-001). Hash chain: each event's `event_hash` covers the full canonical envelope including `previous_hash`. Per-lattice audit heads with row locking prevent race conditions. |
| **Detection** | Verification command: recompute all hashes, check chain integrity. External checkpoints detect tampering after the last checkpoint. |
| **Residual Risk** | Same as T-009: detect-tamper, not prevent-tamper. An adversary who can write to `ep_events` AND knows the canonical JSON rules AND has the previous event's hash can fabricate events. The `event_writer_id` field (always EP service) provides an additional check. |
| **Required Test ID** | `TEST-SEC-010: Fabricated audit event with wrong event_writer_id is detected` |

---

## T-011: Imported Malicious Policy

| Field | Description |
|-------|-------------|
| **Asset** | Policy enforcement integrity |
| **Attacker** | An adversary who crafts a malicious transfer package with harmful policies |
| **Entry Point** | Transfer package import |
| **Mitigation** | Imported policies start as `draft` with `trust_status=pending_review` (EP-TRANSFER-005). Not automatically active. Activation requires trusted signer and trusted source (EP-POLICY-012). Normal approval workflow applies. Tension detection at creation time catches conflicting policies. |
| **Detection** | Policy review process: operator reviews imported policies before submission. Tension detection flags conflicts. Audit trail records import source and signer. |
| **Residual Risk** | If the signer and source are explicitly trusted, the imported policy can be activated. If the trust was misplaced, the malicious policy takes effect. Mitigation: trust must be established through out-of-band verification. |
| **Required Test ID** | `TEST-SEC-011: Imported policy with untrusted signer is not activated` |

---

## T-012: SQL Parser Evasion

| Field | Description |
|-------|-------------|
| **Asset** | Action classification accuracy |
| **Attacker** | An agent who crafts SQL to evade classification (obfuscation, encoding, dialect tricks) |
| **Entry Point** | SQL payload in `postgres.execute` tool call |
| **Mitigation** | Server-side classification uses actual SQL parser with AST analysis (EP-CLASSIFY-002). Detects multi-statement payloads and transaction-control commands (EP-CLASSIFY-003). Parser failures treated as high risk (EP-CLASSIFY-004). |
| **Detection** | Classification result includes `classification_method` and `classification_confidence`. Low-confidence or parser-failure classifications are flagged. Audit trail records classification details. |
| **Residual Risk** | SQL parsers may not cover all dialects or edge cases. Parser evasion could misclassify an action. Mitigation: parser failures fail closed (high risk → require_approval or deny). |
| **Required Test ID** | `TEST-SEC-012: SQL parser evasion attempt is classified as high risk` |

---

## T-013: Opaque Shell Behavior

| Field | Description |
|-------|-------------|
| **Asset** | Shell command classification accuracy |
| **Attacker** | An agent who crafts shell commands with obfuscated or piped operations to evade classification |
| **Entry Point** | Shell command payload in `shell.exec` tool call |
| **Mitigation** | EP does not claim complete semantic understanding of shell commands (EP-CLASSIFY-005). Opaque/unrecognized shell scripts classified as `shell.exec.opaque` (EP-CLASSIFY-006). Opaque classification requires approval or deny. Escalating treatment: known safe → parsed, opaque → high risk. |
| **Detection** | Classification result records `shell.exec.opaque` for unrecognized commands. Audit trail records classification. |
| **Residual Risk** | Legitimate opaque commands are unnecessarily delayed (false positive). Acceptable trade-off for security. |
| **Required Test ID** | `TEST-SEC-013: Opaque shell command requires approval` |

---

## T-014: Network Partition

| Field | Description |
|-------|-------------|
| **Asset** | Transition completion, execution result reporting |
| **Attacker** | Network failure (not adversarial, but threat to consistency) |
| **Entry Point** | Network partition between EP, proxy, database, or agent |
| **Mitigation** | `execution_uncertain` state for unknown outcomes (EP-TRANSITION-008). Does not auto-fail or auto-succeed. Requires reconciliation. Idempotency keys for agent retries. Atomic transactions prevent partial state. |
| **Detection** | Transitions stuck in `executing` for longer than timeout. `execution_uncertain` stage in audit trail. |
| **Residual Risk** | Transitions may remain in `execution_uncertain` until manual reconciliation. The action may or may not have been executed. |
| **Required Test ID** | `TEST-SEC-014: Network partition results in execution_uncertain, not auto-fail` |

---

## T-015: Proxy Crash

| Field | Description |
|-------|-------------|
| **Asset** | Execution result delivery |
| **Attacker** | Process failure (not adversarial, but threat to consistency) |
| **Entry Point** | Proxy process crash or kill |
| **Mitigation** | Token is marked `used` (cannot be replayed). Transition remains in `executing` and moves to `execution_uncertain` after timeout. Reconciliation procedure determines actual outcome. |
| **Detection** | Transition in `executing` with no callback. Timeout triggers `execution_uncertain`. |
| **Residual Risk** | The action may have partially or fully executed before the crash. Reconciliation is manual. |
| **Required Test ID** | `TEST-SEC-015: Proxy crash leaves transition in execution_uncertain` |

---

## T-016: EP Service Crash

| Field | Description |
|-------|-------------|
| **Asset** | Transaction integrity |
| **Attacker** | Process failure (not adversarial, but threat to consistency) |
| **Entry Point** | EP service process crash or kill |
| **Mitigation** | All state changes are in database transactions. In-flight transactions are rolled back by the database. No authoritative state in memory (stateless module design). |
| **Detection** | Transitions stuck in `executing` after EP restart. Database consistency checks. |
| **Residual Risk** | In-flight transactions are lost (rolled back). No data corruption. Transitions stuck in `executing` need timeout-based reconciliation. |
| **Required Test ID** | `TEST-SEC-016: EP service crash rolls back in-flight transactions` |

---

## T-017: Partial Transaction

| Field | Description |
|-------|-------------|
| **Asset** | Database consistency |
| **Attacker** | Transaction failure (not adversarial) |
| **Entry Point** | Database error during multi-step transaction |
| **Mitigation** | All multi-step operations (token claim, branch commit, audit insertion) execute in a single database transaction. Any failure rolls back the entire transaction. |
| **Detection** | Transaction failure returns error to caller. No partial state visible. |
| **Residual Risk** | None if database transactions are used correctly. The atomicity guarantee is provided by the database. |
| **Required Test ID** | `TEST-SEC-017: Partial transaction failure leaves no partial state` |

---

## T-018: Clock Skew

| Field | Description |
|-------|-------------|
| **Asset** | Token expiry validation, audit timestamp ordering |
| **Attacker** | Clock drift between EP, proxy, and database (not adversarial) |
| **Entry Point** | System clock differences |
| **Mitigation** | Token expiry uses database `NOW()` function (authoritative clock). Audit timestamps generated by EP service (not callers). Recommended NTP synchronization. Configurable grace period on token expiry. |
| **Detection** | Token expiry mismatches. Audit timestamps out of order. |
| **Residual Risk** | Small clock skew (seconds) is tolerated with a grace period. Large clock skew (minutes+) is a deployment issue requiring NTP. |
| **Required Test ID** | `TEST-SEC-018: Clock skew does not cause incorrect token expiry` |

---

## T-019: Key Rotation

| Field | Description |
|-------|-------------|
| **Asset** | Ed25519 signing key continuity |
| **Attacker** | Key compromise necessitating rotation |
| **Entry Point** | Key rotation procedure |
| **Mitigation** | Transition period where both old and new keys are accepted (see `failure-recovery.md` §7). Old key destroyed after transition. Key rotation events audited. |
| **Detection** | Audit event `key_rotated`. Proxies reject tokens signed with unknown keys. |
| **Residual Risk** | During the transition period, both keys are valid. If the old key was compromised, the adversary can mint tokens until the transition period ends. Mitigation: keep transition period short (but long enough for operational reliability). |
| **Required Test ID** | `TEST-SEC-019: Key rotation maintains token validity during transition` |

---

## T-020: Insider Threat

| Field | Description |
|-------|-------------|
| **Asset** | Policy integrity, approval integrity |
| **Attacker** | A privileged insider (administrator, policy_approver, operator) |
| **Entry Point** | Legitimate access to EP governance functions |
| **Mitigation** | Separation of duties: `decided_by != requested_by` (EP-POLICY-009). Human co-approval for global policies (EP-POLICY-010). All actions audited with `actor_principal_id`, `authenticated_caller_id`, `event_writer_id` (EP-AUDIT-007). Override restrictions: scoped, justified, time-limited (EP-POLICY-006). |
| **Detection** | Audit trail analysis: patterns of self-approval (impossible due to separation of duties), unusual override patterns, policy changes without justification. |
| **Residual Risk** | A colluding pair of insiders can approve any policy. An administrator with database access can tamper with state (detect-tamper, not prevent-tamper). Mitigation: external audit review, principle of least privilege, regular access reviews. |
| **Required Test ID** | `TEST-SEC-020: Separation of duties prevents self-approval` |

---

## T-021: Duplicate Callback

| Field | Description |
|-------|-------------|
| **Asset** | Execution result integrity |
| **Attacker** | Network retry or proxy bug causing duplicate callbacks |
| **Entry Point** | Proxy callback to EP |
| **Mitigation** | Idempotent callbacks: `execution_attempt_id` deduplication. First result stored and returned. Duplicate with same result: return stored. Duplicate with different result: rejected, security event logged. |
| **Detection** | Audit event `duplicate_callback_conflict` for conflicting duplicates. |
| **Residual Risk** | None for same-result duplicates. Conflicting duplicates are rejected and flagged. |
| **Required Test ID** | `TEST-SEC-021: Duplicate callback with conflicting result is rejected` |

---

## T-022: Malicious Policy Author

| Field | Description |
|-------|-------------|
| **Asset** | Policy enforcement integrity |
| **Attacker** | A principal with `policy_author` role who creates malicious policies |
| **Entry Point** | Policy creation via `ep_add_policy` or CLI |
| **Mitigation** | Policies require approval before activation (EP-POLICY-001). Global policies require human co-approval (EP-POLICY-010). Separation of duties: author cannot approve own policy (EP-POLICY-009). Tension detection at creation time (EP-POLICY-013). Override restrictions limit the scope of harmful policies (EP-POLICY-006). |
| **Detection** | Tension detection flags conflicting policies. Audit trail records policy author, approver, and activation. Policy review process. |
| **Residual Risk** | A policy_author can create agent-scoped policies that bind their own agents. A policy_approver who colludes can approve harmful policies. Mitigation: human co-approval for global policies, regular policy audits. |
| **Required Test ID** | `TEST-SEC-022: Policy author cannot approve own policy` |

---

## T-023: Malicious Approver

| Field | Description |
|-------|-------------|
| **Asset** | Approval integrity |
| **Attacker** | A principal with `policy_approver` role who approves harmful actions |
| **Entry Point** | Approval decision via `ep_approve` or CLI |
| **Mitigation** | Separation of duties: approver cannot be the requester (EP-POLICY-009). For sensitive operations (global policy, priority >= 100 deny overrides): human principal required, payload frozen and hashed before approval (EP-POLICY-015). All approvals audited. Override restrictions: scoped, time-limited, justified. |
| **Detection** | Audit trail: approval patterns, override patterns, unusual approval timing. External audit review. |
| **Residual Risk** | A policy_approver can approve actions within their authority. For global/sensitive operations, human co-approval provides an additional check. Collusion between approver and requester is possible but requires two parties. |
| **Required Test ID** | `TEST-SEC-023: Sensitive operation requires human co-approval` |

---

## T-024: Resource Canonicalization Evasion

| Field | Description |
|-------|-------------|
| **Asset** | Policy resource matching accuracy |
| **Attacker** | An agent who uses non-canonical resource references to evade policy matching |
| **Entry Point** | Resource references in tool call arguments |
| **Mitigation** | Server-side resource canonicalization (EP-RESOURCE-001 through EP-RESOURCE-006). Policies match canonical resource identities, not raw agent-supplied strings. Uncanonicalizable targets classified as `unresolved` requiring approval or deny. |
| **Detection** | Classification result includes canonical resource identity. Audit trail records both raw and canonical forms. Uncanonicalizable targets flagged. |
| **Residual Risk** | If canonicalization rules are incomplete, an agent could use an alternative form that doesn't match a policy. Mitigation: conservative canonicalization, uncanonicalizable → require approval. |
| **Required Test ID** | `TEST-SEC-024: Non-canonical resource is canonicalized before policy matching` |

---

## Summary Table

| ID | Threat | Required Test ID |
|----|--------|-----------------|
| T-001 | Compromised Agent | TEST-SEC-001 |
| T-002 | Compromised Proxy | TEST-SEC-002 |
| T-003 | Compromised Agent Credential | TEST-SEC-003 |
| T-004 | Compromised Proxy Credential | TEST-SEC-004 |
| T-005 | Replayed Token | TEST-SEC-005 |
| T-006 | Altered Payload | TEST-SEC-006 |
| T-007 | Stale Authorization | TEST-SEC-007 |
| T-008 | Direct Infrastructure Bypass | TEST-SEC-008 |
| T-009 | Database Tampering | TEST-SEC-009 |
| T-010 | Audit Log Tampering | TEST-SEC-010 |
| T-011 | Imported Malicious Policy | TEST-SEC-011 |
| T-012 | SQL Parser Evasion | TEST-SEC-012 |
| T-013 | Opaque Shell Behavior | TEST-SEC-013 |
| T-014 | Network Partition | TEST-SEC-014 |
| T-015 | Proxy Crash | TEST-SEC-015 |
| T-016 | EP Service Crash | TEST-SEC-016 |
| T-017 | Partial Transaction | TEST-SEC-017 |
| T-018 | Clock Skew | TEST-SEC-018 |
| T-019 | Key Rotation | TEST-SEC-019 |
| T-020 | Insider Threat | TEST-SEC-020 |
| T-021 | Duplicate Callback | TEST-SEC-021 |
| T-022 | Malicious Policy Author | TEST-SEC-022 |
| T-023 | Malicious Approver | TEST-SEC-023 |
| T-024 | Resource Canonicalization Evasion | TEST-SEC-024 |