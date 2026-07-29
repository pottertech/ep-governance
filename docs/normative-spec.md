# EP-Governance Normative Specification

**Version:** 1.0 (Phase 1)
**Date:** July 29, 2026
**Governing Sources:** `ep-governance-design-v1.1.md` (v1.1) and `ep-governance-design-v1.1.1.md` (v1.1.1). Where they conflict, v1.1.1 governs.
**Purpose:** Convert every major design requirement into numbered, testable normative rules.

**Rule Format:** `EP-XXX-NNN: [MUST/MUST NOT] [requirement statement]. (Source: section reference)`

---

## Table of Contents

1. [Branch Model (EP-BRANCH)](#1-branch-model-ep-branch)
2. [Node Lifecycle (EP-NODE)](#2-node-lifecycle-ep-node)
3. [Transition Lifecycle (EP-TRANSITION)](#3-transition-lifecycle-ep-transition)
4. [Policy Model (EP-POLICY)](#4-policy-model-ep-policy)
5. [Authorization (EP-AUTH)](#5-authorization-ep-auth)
6. [Audit (EP-AUDIT)](#6-audit-ep-audit)
7. [Risk Model (EP-RISK)](#7-risk-model-ep-risk)
8. [Enforced Mode (EP-ENFORCE)](#8-enforced-mode-ep-enforce)
9. [Resource Canonicalization (EP-RESOURCE)](#9-resource-canonicalization-ep-resource)
10. [Classification (EP-CLASSIFY)](#10-classification-ep-classify)
11. [Identity (EP-IDENTITY)](#11-identity-ep-identity)
12. [Transfer Packages (EP-TRANSFER)](#12-transfer-packages-ep-transfer)
13. [Concurrency (EP-CONCURRENCY)](#13-concurrency-ep-concurrency)

---

## 1. Branch Model (EP-BRANCH)

**EP-BRANCH-001:** MUST ensure that each branch has exactly one head node at all times. (Source: v1.1.1 §1)

**EP-BRANCH-002:** MUST advance exactly one branch head when a transition succeeds on that branch. (Source: v1.1.1 §1)

**EP-BRANCH-003:** MUST require that divergence from the same parent node creates a new branch rather than allowing two children of the same parent to be heads of the same branch. (Source: v1.1.1 §1)

**EP-BRANCH-004:** MUST use `expected_head_id` and `expected_version` for optimistic concurrency on every branch transition proposal. (Source: v1.1 §7.5)

**EP-BRANCH-005:** MUST fail a proposal with `stale_head` when the current branch head does not match both `expected_head_id` and `expected_version`. (Source: v1.1 §7.5, v1.1.1 §1)

**EP-BRANCH-006:** MUST increment the branch `version` counter by exactly one on each successful head advancement. (Source: v1.1 §7.5, v1.1.1 §1)

**EP-BRANCH-007:** MUST set a new branch's head to an existing committed node (the parent branch's current head) at creation time. (Source: v1.1.1 §1)

**EP-BRANCH-008:** MUST restrict branch `status` to the values `active`, `merged`, or `abandoned`. (Source: v1.1 §11.2 ep_branches)

**EP-BRANCH-009:** MUST NOT allow a branch to have zero head nodes after its first transition has committed. (Source: v1.1.1 §1)

**EP-BRANCH-010:** MUST create the first unique child node when the first transition on a new branch succeeds, advancing the branch head from the inherited parent node to the new child. (Source: v1.1.1 §1)

---

## 2. Node Lifecycle (EP-NODE)

**EP-NODE-001:** MUST insert an `ep_node` row only when a transition reaches the `succeeded` stage. (Source: v1.1.1 §2)

**EP-NODE-002:** MUST NOT create `ep_node` rows for transitions in `proposed`, `pending_approval`, `authorized`, `executing`, `denied`, `failed`, `expired`, or `cancelled` stages. (Source: v1.1.1 §2)

**EP-NODE-003:** MUST restrict `ep_nodes.status` to the values `committed`, `quarantined`, `at_risk`, `superseded`, or `archived`. (Source: v1.1.1 §2)

**EP-NODE-004:** MUST set a newly inserted node's status to `committed` at creation time. (Source: v1.1.1 §2)

**EP-NODE-005:** MUST link `ep_transitions.to_node_id` to the realized `ep_node` row only when `stage = succeeded`. (Source: v1.1.1 §2)

**EP-NODE-006:** MUST mark a prior branch head node as `superseded` when a new head advances the branch. (Source: v1.1.1 §2)

**EP-NODE-007:** MUST set `committed_at` to the timestamp when execution succeeded. (Source: v1.1.1 §2)

**EP-NODE-008:** MUST NOT store intention states (proposed, pending, authorized, executing, denied, failed, expired, cancelled) as `ep_nodes` rows; those states live exclusively in `ep_transitions.stage`. (Source: v1.1.1 §2)

---

## 3. Transition Lifecycle (EP-TRANSITION)

**EP-TRANSITION-001:** MUST restrict `ep_transitions.stage` to the values: `proposed`, `pending_approval`, `authorized`, `executing`, `succeeded`, `failed`, `execution_uncertain`, `cancelled`, `expired`, `denied`. (Source: v1.1.1 §2)

**EP-TRANSITION-002:** MUST allow a transition to move from `proposed` to `pending_approval` when policy evaluation returns `require_approval`. (Source: v1.1 §5.1)

**EP-TRANSITION-003:** MUST allow a transition to move from `proposed` to `denied` when policy evaluation returns `deny`. (Source: v1.1 §5.1)

**EP-TRANSITION-004:** MUST allow a transition to move from `proposed` to `authorized` when policy evaluation returns `allow` or `warn`, or when human approval is granted for a `pending_approval` transition. (Source: v1.1 §5.1)

**EP-TRANSITION-005:** MUST allow a transition to move from `authorized` to `executing` when the proxy atomically claims the authorization token. (Source: v1.1.1 §3)

**EP-TRANSITION-006:** MUST allow a transition to move from `executing` to `succeeded` when the proxy reports successful execution. (Source: v1.1 §5.1)

**EP-TRANSITION-007:** MUST allow a transition to move from `executing` to `failed` when the proxy reports failed execution. (Source: v1.1 §5.1)

**EP-TRANSITION-008:** MUST allow a transition to move from `executing` to `execution_uncertain` when the proxy callback fails, the network drops, the connection closes, or the proxy times out. (Source: v1.1.1 additional corrections)

**EP-TRANSITION-009:** MUST allow a transition to move from `authorized` to `expired` when the authorization token expires before execution. (Source: v1.1 §5.1)

**EP-TRANSITION-010:** MUST allow a transition to move from `proposed` to `cancelled` when the agent explicitly cancels the proposal before execution. (Source: v1.1 §5.1)

**EP-TRANSITION-011:** MUST reject any transition stage change not listed as legal in the transition table (see `state-machines.md`) and MUST generate an audit event for the illegal transition attempt. (Source: v1.1 §5.1)

**EP-TRANSITION-012:** MUST treat `succeeded`, `failed`, `execution_uncertain`, `cancelled`, `expired`, and `denied` as terminal states from which no further stage transitions are permitted. (Source: v1.1 §5.1, v1.1.1 §2)

**EP-TRANSITION-013:** MUST accept an idempotency key on each proposal and return the existing transition if the same key is resubmitted while the first is `proposed`, `authorized`, `executing`, or `succeeded`. (Source: v1.1 §5.3)

**EP-TRANSITION-014:** MUST allow a new proposal with the same idempotency key if the prior transition reached `failed`, `cancelled`, `expired`, or `denied`. (Source: v1.1 §5.3)

**EP-TRANSITION-015:** MUST include `expected_head_id` and `expected_version` in every transition proposal for optimistic concurrency validation against the current branch head. (Source: v1.1 §7.5)

---

## 4. Policy Model (EP-POLICY)

**EP-POLICY-001:** MUST restrict policy `status` to the values: `draft`, `pending_approval`, `active`, `rejected`, `superseded`, `retired`. (Source: v1.1.1 §6)

**EP-POLICY-002:** MUST NOT allow a policy to have any enforcement effect unless its status is `active` and it is in-force (satisfies `valid_from` and `valid_until` constraints). (Source: v1.1.1 §6)

**EP-POLICY-003:** MUST restrict policy `effect` to the values: `deny`, `require_approval`, `warn`, `allow`. (Source: v1.1 §4.2)

**EP-POLICY-004:** MUST resolve effect precedence at equal priority as: `deny` > `require_approval` > `warn` > `allow`. (Source: v1.1 §4.4)

**EP-POLICY-005:** MUST NOT allow priority alone to authorize an exception to a `deny` policy; a higher-priority `allow` does not automatically override a `deny` without explicit override controls. (Source: v1.1.1 §6)

**EP-POLICY-006:** MUST allow an `allow` policy to override a `deny` policy only when all of the following are true: the `allow` policy's `exception_to` field explicitly lists the `deny` policy's XID; the override is more narrowly scoped (fewer resources or more specific actions); `valid_until` is set (time-limited); a `justification` field is non-empty; and the creating principal has `policy_author` role or higher with the required approval authority level. (Source: v1.1.1 §6)

**EP-POLICY-007:** MUST produce a policy conflict and return `require_approval` when two active policies with the same priority and conflicting effects match the same action and resource at policy creation time. (Source: v1.1 §4.4, v1.1.1 §6)

**EP-POLICY-008:** MUST include the following fields in every policy record: `policy_id`, `effect`, `actions`, `resources`, `conditions`, `priority`, `scope`, `agent_scope`, `description`, `created_by`, `approved_by`, `approved_at`, `activation_version`, `exception_to`, `valid_from`, `valid_until`. (Source: v1.1 §4.2, v1.1.1 §6)

**EP-POLICY-009:** MUST enforce separation of duties: the principal who requested an approval or override (`requested_by`) MUST NOT be the same principal who decides it (`decided_by`). (Source: v1.1.1 §6)

**EP-POLICY-010:** MUST require human co-approval for global policy activation; a `human` principal must approve before status becomes `active`. (Source: v1.1.1 §6)

**EP-POLICY-011:** MUST set imported policies to status `draft` with `origin=imported` and `trust_status=pending_review` upon import; imported policies MUST NOT be automatically active. (Source: v1.1.1 additional corrections)

**EP-POLICY-012:** MUST activate an imported policy only when both the signer and the source are explicitly trusted. (Source: v1.1.1 additional corrections)

**EP-POLICY-013:** MUST detect policy tensions at policy creation time, not at action proposal time, by checking for contradictory effects, incompatible conditions, or conflicting obligations between active policies with the same priority. (Source: v1.1 §8.4, v1.1.1 additional corrections)

**EP-POLICY-014:** MUST NOT use the pairwise simulation method from v1.0 for tension detection. (Source: v1.1 §8.4)

**EP-POLICY-015:** MUST require that for especially sensitive operations (global policy changes, overrides of `deny` policies with priority >= 100), a `human` principal is the approver and the payload is frozen and hashed before approval. (Source: v1.1.1 §6)

---

## 5. Authorization (EP-AUTH)

**EP-AUTH-001:** MUST sign authorization tokens using Ed25519 asymmetric signatures. (Source: v1.1.1 additional corrections, ADR-0003)

**EP-AUTH-002:** MUST hold the Ed25519 private signing key exclusively within the EP service; proxies MUST hold only the public verification key. (Source: v1.1.1 additional corrections, ADR-0003)

**EP-AUTH-003:** MUST NOT transmit the Ed25519 private key to agents or proxies under any circumstances. (Source: v1.1.1 additional corrections, ADR-0003)

**EP-AUTH-004:** MUST ensure each authorization token is short-lived, payload-bound, agent-bound, project-bound, branch-bound, proxy-bound, and single-use. (Source: v1.1 §5.2, v1.1.1 additional corrections)

**EP-AUTH-005:** MUST include the following fields in each authorization token: `authorization_id`, `transition_id`, `agent_id`, `project_id`, `branch_id`, `proxy_audience`, `tool`, `payload_hash` (SHA-256), `policy_set_hash` (SHA-256), `matched_policy_versions` (mapping), `issued_at`, `expires_at`, `nonce`. (Source: v1.1.1 §17, ADR-0003)

**EP-AUTH-006:** MUST store only the hash of the authorization token in the database, not a reusable token value. (Source: v1.1.1 additional corrections, ADR-0003)

**EP-AUTH-007:** MUST claim an authorization token atomically using `UPDATE ep_authorizations SET used = TRUE, used_at = NOW() WHERE id = :authorization_id AND used = FALSE AND expires_at > NOW() RETURNING id, transition_id, payload_hash, policy_set_hash`. (Source: v1.1.1 §3)

**EP-AUTH-008:** MUST advance the transition to `executing` in the same database transaction as the atomic token claim. (Source: v1.1.1 §3)

**EP-AUTH-009:** MUST ensure exactly one row is affected by the atomic claim UPDATE; if no row is returned, execution MUST stop and the transaction MUST roll back. (Source: v1.1.1 §3)

**EP-AUTH-010:** MUST detect stale authorizations by comparing the `policy_set_hash` and matched policy versions at execution time against those captured at authorization time. (Source: v1.1 §5.4, v1.1.1 additional corrections)

**EP-AUTH-011:** MUST invalidate an authorization when relevant governance has changed between authorization and execution by moving the transition to `expired`. (Source: v1.1 §5.4)

**EP-AUTH-012:** MUST distinguish relevant governance changes (changes to policies that matched the authorized action) from unrelated changes (changes to policies that did not match); only relevant changes invalidate the authorization. (Source: v1.1.1 additional corrections)

---

## 6. Audit (EP-AUDIT)

**EP-AUDIT-001:** MUST ensure that only EP service code writes audit events to `ep_events`. (Source: v1.1.1 §5)

**EP-AUDIT-002:** MUST NOT allow agents or proxies to directly INSERT, UPDATE, or DELETE records in `ep_events` or `ep_audit_heads`. (Source: v1.1.1 §5)

**EP-AUDIT-003:** MUST maintain per-lattice audit chains, where each lattice has its own independent sequence and hash chain. (Source: v1.1.1 §5)

**EP-AUDIT-004:** MUST use an `ep_audit_heads` table with row locking (`FOR UPDATE` in PostgreSQL, `BEGIN IMMEDIATE` in SQLite) to serialize concurrent audit insertions per lattice. (Source: v1.1.1 §5)

**EP-AUDIT-005:** MUST compute the event hash over the full canonical event envelope, including: `sequence`, `event_id`, `event_type`, `event_data`, `principal_id` (or `actor_principal_id`), `created_at`, and `previous_hash`. (Source: v1.1.1 §4)

**EP-AUDIT-006:** MUST serialize the event envelope using canonical JSON rules as defined in v1.1.1 §4 (UTF-8, sorted keys, no insignificant whitespace, ISO 8601 UTC timestamps, no trailing zeros, null as `null`, booleans as `true`/`false`, array order preserved, no duplicate keys, no comments). (Source: v1.1.1 §4, ADR-0002)

**EP-AUDIT-007:** MUST record three separate identities per audit event: `actor_principal_id` (the agent or human responsible for the operation), `authenticated_caller_id` (the principal that authenticated to EP), and `event_writer_id` (always the EP service principal). (Source: v1.1.1 §5)

**EP-AUDIT-008:** MUST generate `event_id`, `sequence`, `timestamp`, and `event_hash` exclusively from trusted EP service code; MUST NOT accept caller-supplied timestamps. (Source: v1.1.1 §5)

**EP-AUDIT-009:** MUST enforce append-only semantics on `ep_events`: no role may UPDATE or DELETE audit records, and MUST NOT perform garbage collection on audit events. (Source: v1.1.1 §5, additional corrections)

**EP-AUDIT-010:** MUST provide a verification command that recomputes each event hash from the canonical envelope and verifies that each `previous_hash` matches the preceding event's `event_hash`. (Source: v1.1.1 §4)

---

## 7. Risk Model (EP-RISK)

**EP-RISK-001:** MUST scope risk assessments per risk domain, not as a single spendable number. (Source: v1.1 §9.2, v1.1.1 §7)

**EP-RISK-002:** MUST include the initial risk domains: `production_database`, `external_communications`, `deployment`, `data_privacy`, and `security`. (Source: v1.1 §9.2)

**EP-RISK-003:** MUST track per-domain: `risk_increment`, `inherent_risk`, `mitigation_credit`, `residual_risk`, `threshold`, and `decision`. (Source: v1.1.1 §7)

**EP-RISK-004:** MUST require verified evidence for all mitigations; mitigations MUST NOT be based on agent self-attestation. (Source: v1.1.1 §7)

**EP-RISK-005:** MUST NOT allow agents to assign their own mitigation credit; mitigation credit limits come from policy and are set by a `policy_approver` or `operator`. (Source: v1.1.1 §7)

**EP-RISK-006:** MUST NOT reduce residual risk using mitigation evidence that has expired; expired mitigation evidence MUST be treated as providing zero credit. (Source: v1.1.1 §7)

**EP-RISK-007:** MUST ensure risk acceptance is scoped to a specific risk domain, time-limited, and audited with `accepted_by`, `accepted_at`, and `expiration` fields. (Source: v1.1 §9.2)

**EP-RISK-008:** MUST use the terminology `risk_increment`, `risk_assessments`, and `residual_risk_after` in place of the deprecated `ut_cost`, `ut_deltas`, and `ut_after`. (Source: v1.1.1 §7)

---

## 8. Enforced Mode (EP-ENFORCE)

**EP-ENFORCE-001:** MUST NOT allow agents to possess target credentials (SSH keys, database passwords, email credentials, API tokens, cloud CLI configuration) in enforced mode. (Source: v1.1.1 §8)

**EP-ENFORCE-002:** MUST NOT expose raw consequential tools (`shell.exec`, `postgres.execute`, `email.send`, `docker.*`, `git.*`) to agents in enforced mode. (Source: v1.1.1 §8)

**EP-ENFORCE-003:** MUST NOT mount Docker sockets or SSH-agent sockets to the agent process in enforced mode. (Source: v1.1.1 §8)

**EP-ENFORCE-004:** MUST NOT allow cloud CLI credentials to be present in the agent's environment in enforced mode. (Source: v1.1.1 §8)

**EP-ENFORCE-005:** MUST ensure only governed proxies perform protected actions in enforced mode; the proxy MUST run as a separate process with its own network identity and credentials. (Source: v1.1.1 §8)

**EP-ENFORCE-006:** MUST verify capability isolation at deployment time; if verification fails, the system MUST report an advisory and operate in advisory mode regardless of the `EP_MODE=enforced` setting. (Source: v1.1.1 §8)

**EP-ENFORCE-007:** MUST report an advisory when enforced-mode deployment conditions are not satisfied, and MUST NOT claim binding enforcement in that case. (Source: v1.1.1 §8)

**EP-ENFORCE-008:** MUST expose only `ep_execute` and governance management tools to the agent via MCP in enforced mode; MUST NOT expose raw shell, database, email, Docker, or Git tools. (Source: v1.1.1 §8)

---

## 9. Resource Canonicalization (EP-RESOURCE)

**EP-RESOURCE-001:** MUST define canonical resource formats for `postgres`, `host`, `container`, `file`, `email`, and `git` resource types. (Source: v1.1.1 additional corrections)

**EP-RESOURCE-002:** MUST canonicalize hostnames by resolving aliases to canonical names, normalizing case to lowercase, and including standard ports only when non-default. (Source: v1.1.1 additional corrections)

**EP-RESOURCE-003:** MUST canonicalize database resources as `postgres://<host>/<database>/<schema>/<table>/<column>` with case normalization and explicit schema resolution. (Source: v1.1.1 additional corrections)

**EP-RESOURCE-004:** MUST canonicalize file paths to absolute paths with symlink resolution, URL normalization (percent-decoding, trailing separator removal), and IPv4/IPv6 address normalization. (Source: v1.1.1 additional corrections)

**EP-RESOURCE-005:** MUST canonicalize email addresses to a normalized form (lowercase domain, trimmed) and git remotes to a canonical URL form. (Source: v1.1.1 additional corrections)

**EP-RESOURCE-006:** MUST classify uncanonicalizable targets as `unresolved` and MUST require approval or deny for actions targeting unresolved resources. (Source: v1.1.1 additional corrections)

---

## 10. Classification (EP-CLASSIFY)

**EP-CLASSIFY-001:** MUST classify all actions server-side; agent-supplied categories MUST be treated as hints only and MUST be overridden by server-side classification when available. (Source: v1.1 §4.4, §10.1)

**EP-CLASSIFY-002:** MUST use an actual SQL parser with AST analysis to classify SQL actions, identifying operation type (SELECT, INSERT, UPDATE, DELETE, DROP) and target objects (tables, schemas, databases). (Source: v1.1 §10.1)

**EP-CLASSIFY-003:** MUST detect multi-statement SQL payloads and transaction-control commands (COMMIT, ROLLBACK, BEGIN) during classification. (Source: v1.1 §10.1)

**EP-CLASSIFY-004:** MUST treat SQL parser failures as high-risk classifications requiring approval or deny. (Source: v1.1.1 additional corrections)

**EP-CLASSIFY-005:** MUST NOT claim complete semantic understanding of shell commands; known safe commands MAY be parsed, but opaque or unrecognized shell scripts MUST be classified as `shell.exec.opaque` requiring approval or deny. (Source: v1.1.1 additional corrections)

**EP-CLASSIFY-006:** MUST classify opaque shell commands with escalating treatment: known safe commands parsed, opaque scripts classified as high-risk `shell.exec.opaque`, unrecognized commands requiring approval or deny by default. (Source: v1.1.1 additional corrections)

---

## 11. Identity (EP-IDENTITY)

**EP-IDENTITY-001:** MUST support principal types: `human`, `agent`, `service`, and `proxy`. (Source: v1.1 §6.1, v1.1.1 §5)

**EP-IDENTITY-002:** MUST support roles: `observer`, `agent`, `policy_author`, `policy_approver`, `operator`, `auditor`, and `administrator`. (Source: v1.1 §6.2)

**EP-IDENTITY-003:** MUST authenticate the principal and authorize the exact operation for every mutation request. (Source: v1.1 §6.1)

**EP-IDENTITY-004:** MUST require an administrator action or enrollment token for production principal registration; MUST NOT allow self-registration in production. (Source: v1.1 §6.3)

**EP-IDENTITY-005:** MUST allow self-registration only when `EP_DEV=true` is explicitly set (development mode). (Source: v1.1 §6.3)

**EP-IDENTITY-006:** MUST NOT store raw credentials; MUST store only credential hashes and MUST use constant-time comparisons for secret verification; MUST support credential rotation and revocation. (Source: v1.1 §11.2 ep_credentials, v1.1.1 additional corrections)

---

## 12. Transfer Packages (EP-TRANSFER)

**EP-TRANSFER-001:** MUST support three transfer operations: `resume` (connect to existing database), `export` (create immutable signed snapshot), and `import-as-fork` (create new project/lattice from snapshot). (Source: v1.1 §12.1)

**EP-TRANSFER-002:** MUST create an immutable, signed snapshot when exporting; the snapshot MUST include a `content_hash` (SHA-256 of `lattice_state` JSON) and a digital signature. (Source: v1.1 §12.2)

**EP-TRANSFER-003:** MUST create a new project and lattice on import; MUST NOT overwrite or modify the source lattice. (Source: v1.1 §12.3)

**EP-TRANSFER-004:** MUST generate new local XIDs for all imported entities and MUST store provenance mappings (`source_entity_id`, `imported_entity_id`, `source_lattice_id`, `source_package_id`). (Source: v1.1.1 additional corrections)

**EP-TRANSFER-005:** MUST NOT automatically activate imported policies; imported policies MUST start with `status=draft`, `origin=imported`, `trust_status=pending_review`, and MUST be activated only when the signer and source are explicitly trusted. (Source: v1.1.1 additional corrections)

**EP-TRANSFER-006:** MUST NOT import active authorization tokens, credentials, private keys, live sessions, or unexpired approvals. (Source: v1.1.1 additional corrections)

---

## 13. Concurrency (EP-CONCURRENCY)

**EP-CONCURRENCY-001:** MUST use optimistic concurrency with `expected_head_id` and `expected_version` for all branch transition proposals. (Source: v1.1 §7.5, v1.1.1 §1)

**EP-CONCURRENCY-002:** MUST succeed a commit only if both `expected_head_id` matches the current branch head AND `expected_version` matches the current branch version. (Source: v1.1 §7.5)

**EP-CONCURRENCY-003:** MUST return `stale_head` for a proposal whose `expected_head_id` or `expected_version` does not match; MUST NOT silently rebase the proposal onto the new head. (Source: v1.1 §7.5)

**EP-CONCURRENCY-004:** MUST execute the following steps in a single database transaction on successful commit: (1) verify transition stage is `succeeded`, (2) verify branch head matches `expected_head_id` and `expected_version`, (3) insert new `ep_node` with status `committed`, (4) insert new `ep_edge` from parent to new node, (5) mark prior head node as `superseded`, (6) update branch `head_node_id` to new node, (7) increment branch `version`, (8) record transition result, (9) append audit event. (Source: v1.1.1 §1, v1.1 §7.5)

**EP-CONCURRENCY-005:** MUST require explicit branch creation for divergence; MUST NOT allow two transitions from the same parent to both commit to the same branch. (Source: v1.1.1 §1)

**EP-CONCURRENCY-006:** MUST NOT allow silent rebase of a stale proposal; the agent MUST re-read branch state and retry with updated `expected_head_id` and `expected_version`. (Source: v1.1 §7.5, v1.1.1 §1)

---

## Appendix: Rule Summary by Category

| Category | Rule Count | Section |
|----------|-----------|---------|
| EP-BRANCH | 10 | §1 |
| EP-NODE | 8 | §2 |
| EP-TRANSITION | 15 | §3 |
| EP-POLICY | 15 | §4 |
| EP-AUTH | 12 | §5 |
| EP-AUDIT | 10 | §6 |
| EP-RISK | 8 | §7 |
| EP-ENFORCE | 8 | §8 |
| EP-RESOURCE | 6 | §9 |
| EP-CLASSIFY | 6 | §10 |
| EP-IDENTITY | 6 | §11 |
| EP-TRANSFER | 6 | §12 |
| EP-CONCURRENCY | 6 | §13 |
| **Total** | **116** | |

---

## Appendix: Conflict Resolution Notes

The following conflicts between v1.1 and v1.1.1 are resolved in favor of v1.1.1 throughout this specification:

1. **Branch model:** One branch, one head (v1.1.1 §1) — not two transitions to the same branch.
2. **Node lifecycle:** Only realized states become `ep_nodes` (v1.1.1 §2) — not intention states.
3. **Token claiming:** Atomic `UPDATE...WHERE...RETURNING` (v1.1.1 §3) — not non-atomic `used` boolean check.
4. **Audit hashing:** Full canonical envelope (v1.1.1 §4) — not `event_data + previous_hash` only.
5. **Audit writers:** Only EP service writes audit events (v1.1.1 §5) — not agents/proxies.
6. **Policy lifecycle:** Draft → pending_approval → active with separation of duties (v1.1.1 §6) — not direct insertion as active.
7. **Risk terminology:** `risk_increment`/`risk_assessments`/`residual_risk_after` (v1.1.1 §7) — not `ut_cost`/`ut_deltas`/`ut_after`.
8. **Enforced mode:** Requires runtime capability isolation (v1.1.1 §8) — not merely setting `EP_MODE=enforced`.
9. **Token signing:** Ed25519 asymmetric signatures (v1.1.1 additional corrections) — not HMAC-SHA256.