# EP-Governance Traceability Matrix

## Version

1.0 — Phase 0 Specification Intake

## Date

2026-07-29

## Purpose

This document maps every major section of the governing design documents — `ep-governance-design-v1.1.md` (v1.1) and `ep-governance-design-v1.1.1.md` (v1.1.1) — to the implementation components that will satisfy them. Where v1.1 and v1.1.1 conflict, v1.1.1 governs; this matrix reflects the v1.1.1-corrected requirements.

Status legend: Planned (not yet implemented), In Progress (active development), Blocked (waiting on a decision or dependency).

---

## v1.1 Architectural Sections

| Design Section | Source Doc | Requirement Summary | Implementation Component | Phase | Status |
|---|---|---|---|---|---|
| 1. Overview | v1.1 | Defines EP-Governance as a binding governance system for AI agents: persistent DAG, inherited policies, transactional transitions, model-agnostic, multi-agent. | Project README, SKILL.md, pyproject.toml (package definition) | 0 | Planned |
| 1.2 Conceptual Model (Energetic Paradigm) | v1.1 | Invariants, dependencies, energy, verification pulse, structural quarantine. Engineering implementation is a DAG; EP terminology is conceptual only. | models.py (formal dataclasses), gate.py (verification pulse), docs/formal-semantics (Phase 1 spec) | 0–1 | Planned |
| 1.3 Goals | v1.1 | Standalone installable Python package; Hermes skill + MCP server + CLI; governed proxy; multi-agent; PostgreSQL/SQLite; pluggable embeddings; signed transfer packages; rs/xid IDs. | pyproject.toml, cli.py, mcp_server.py, proxy.py, SKILL.md, xid.py, transfer.py | 0–8 | Planned |
| 1.4 Non-Goals | v1.1 | Not a memory replacement, not a framework, not human-judgment replacement, not compute quota, not cryptographic guarantee. | README.md, SKILL.md (non-goal documentation) | 0 | Planned |
| 2.1 High-Level Architecture | v1.1 | Agents connect via CLI/MCP to governed proxy; proxy holds creds; database is authoritative; embeddings and notifications are peripheral. | Architecture diagram in docs, db.py, proxy.py, mcp_server.py, cli.py | 0 | Planned |
| 2.2 Core Principles | v1.1 | Seven principles: execution-path governance, DB-as-authoritative-graph, stateless module, deterministic policy evaluation, model-agnostic, multi-agent, append-only audit. | All modules (each principle constrains design); audit.py, policy.py, gate.py, db.py | 0–4 | Planned |
| 3.1 Advisory Mode | v1.1 | Agents voluntarily call the gate; no enforcement; EP returns a recommendation. | config.py (EP_MODE=advisory), gate.py, cli.py (check command), mcp_server.py (ep_check tool) | 2–4 | Planned |
| 3.2 Enforced Mode | v1.1 | Consequential tools accessible only through governed proxy; signed short-lived token; proxy validates and executes. | proxy.py, tokens.py, lifecycle.py, config.py (EP_MODE=enforced) | 4–5 | Planned |
| 3.3 Mode Selection | v1.1 | EP_MODE environment variable selects advisory or enforced; tool surface differs by mode. | config.py, mcp_server.py (tool registration by mode) | 2 | Planned |
| 4.1–4.2 Structured Policies | v1.1 | Typed policy schema: policy_id, effect, actions, resources, conditions, priority, scope, agent_scope, description. | models.py (Policy dataclass), policy.py, migrations (ep_policies table) | 1–2 | Planned |
| 4.3 Effects | v1.1 | Four effects: deny, require_approval, warn, allow. Priority-based resolution; ties broken by severity. | policy.py (effect resolution engine) | 2 | Planned |
| 4.4 Policy Evaluation | v1.1 | Server-side classification, policy lookup, condition evaluation, effect resolution, tension detection. Agent-supplied categories are hints only. | classify.py, policy.py, gate.py | 2 | Planned |
| 4.5 Role of Embeddings | v1.1 | Embeddings for authoring assistance, policy discovery, and audit search only — never enforcement. EP_EMBEDDING_PROVIDER=none is fully functional. | embeddings.py (pluggable: ollama/openai/cohere/sst/none) | 8 | Planned |
| 5.1 Transition Lifecycle Stages | v1.1 | Multi-stage: proposed -> authorized -> executing -> succeeded/failed/cancelled/expired/denied/pending_approval. | lifecycle.py, migrations (ep_transitions table with stage CHECK) | 4 | Planned |
| 5.2 Authorization Token | v1.1 | Signed short-lived payload-bound single-use token. (v1.1 specified HMAC-SHA256; v1.1.1 corrects to Ed25519 — see AMB-002.) | tokens.py, migrations (ep_authorizations table) | 4 | Planned |
| 5.3 Idempotency | v1.1 | Each proposal includes client-generated XID idempotency key; duplicate submissions return existing transition or result. | lifecycle.py, migrations (ep_transitions.idempotency_key UNIQUE index) | 4 | Planned |
| 5.4 Stale Authorization Detection | v1.1 | Proxy checks policy version before executing; if version advanced, token invalidated, transition moves to expired. | tokens.py, proxy.py, policy.py (policy_set_hash) | 4 | Planned |
| 6.1 Principals and Roles | v1.1 | ep_principals, ep_roles, ep_role_bindings, ep_credentials, ep_approval_requests, ep_approval_decisions. | auth.py, migrations (identity and authorization tables) | 3 | Planned |
| 6.2 Roles | v1.1 | Seven roles: observer, agent, policy_author, policy_approver, operator, auditor, administrator. | auth.py (role definitions and permission checks) | 3 | Planned |
| 6.3 Agent Registration | v1.1 | No self-registration in production; enrollment token or admin insertion; self-registration in dev mode. | auth.py, cli.py (register command), config.py (EP_DEV flag) | 3 | Planned |
| 6.4 Override Authority | v1.1 | Overrides are scoped, justified, time-limited, and audited. (v1.1.1 adds separation of duties and override restrictions — see §6 addendum.) | auth.py, migrations (ep_override_records), policy.py (override validation) | 3–4 | Planned |
| 7.1 Graph Model Definition | v1.1 | Persistent DAG: nodes are states, edges are dependency struts, acyclic. | lattice.py, models.py, migrations (ep_nodes, ep_edges) | 3 | Planned |
| 7.2 First-Class Entities | v1.1 | ep_lattices, ep_projects, ep_branches, ep_sessions, ep_branch_heads, ep_policy_versions. | lattice.py, models.py, migrations | 3 | Planned |
| 7.3 Active State | v1.1 | Active state keyed by (project_id, branch_id), not by agent. Multiple agents can work on same branch. | lattice.py, migrations (ep_branches.head_node_id) | 3 | Planned |
| 7.4 Branching | v1.1 | Two agents may produce parallel admissible transitions from same parent. (v1.1.1 corrects: one branch one head; divergence requires new branch — see §1 addendum.) | lattice.py, cli.py (create-branch command) | 3–6 | Planned |
| 7.5 Optimistic Concurrency | v1.1 | Each branch has head_node_id and version; proposals include expected_head_id and expected_version. | lattice.py, migrations (ep_branches.version) | 3–6 | Planned |
| 7.6 Cycle Prevention | v1.1 | Forward BFS from downstream node before inserting edge; if upstream reachable, reject. | lattice.py (cycle check) | 3 | Planned |
| 8.1 Backward Pulse | v1.1 | Verification pulse: backward BFS from proposed node, evaluate applicable policies at each ancestor, collect denied/warnings/violations. | gate.py (backward pulse implementation) | 2–4 | Planned |
| 8.2 Forward Blast Radius | v1.1 | Forward BFS from violated committed nodes to mark downstream at_risk. Only applies to existing committed states, not denied proposals. | gate.py (forward blast radius) | 3–4 | Planned |
| 8.3 Quarantine vs Denial | v1.1 | Denied proposals never enter graph; quarantine applies to existing committed states found unsafe; at_risk for downstream; revoked for expired authorization. | gate.py, lifecycle.py, migrations (ep_nodes.status) | 4 | Planned |
| 8.4 Tension Detection | v1.1 | Policy conflicts checked at creation time (not proposal time). Contradictory effects at same priority, incompatible conditions, conflicting obligations. | policy.py (tension detection at policy creation) | 2 | Planned |
| 9.1 BT (Planning Budget) | v1.1 | BT is a planning/accounting mechanism, not a compute quota. Initial configurable (default 100.0), consumed by transitions, replenished by operator. | risk.py (BT tracking), migrations (ep_nodes.bt_planning_budget) | 4 | Planned |
| 9.2 UT (Risk Ledger) | v1.1 | UT is a per-domain risk ledger: production_database, external_communications, deployment, data_privacy, security. Each tracks inherent_risk, mitigations, residual_risk, required_approval_level, accepted_by/at, expiration. (v1.1.1 renames UT terminology — see §7 addendum.) | risk.py, migrations (ep_risk_ledger, ep_risk_mitigations) | 4 | Planned |
| 10. Action Classification | v1.1 | Server-side classification: SQL AST parse, shell parse, HTTP method/host/path, Docker command, email recipients, git command, file path. Classification result includes action_type, target, risk_domain, bt_cost, ut_cost, confidence, method. | classify.py, migrations (ep_transitions.classification JSONB) | 2 | Planned |
| 10.3 Action Categories | v1.1 | Default BT/UT costs and risk domains for 14 action categories. | classify.py (category defaults table), config (overridable defaults) | 2 | Planned |
| 11. Database Schema | v1.1 | Full schema: core graph, policies, transitions/authorizations, risk ledger, identity/auth, approvals/overrides, audit, work management, transfer packages, sessions, embeddings. | migrations/postgres/001_init.sql, migrations/sqlite/001_init.sql | 3 | Planned |
| 11.1 Database Support | v1.1 | PostgreSQL production (LISTEN/NOTIFY, FOR UPDATE, pgvector, cross-machine); SQLite development only (WAL, BEGIN IMMEDIATE, single-machine). | db.py (dual backend), migrations (separate directories) | 3 | Planned |
| 12. Transfer Packages | v1.1 | Three operations: resume (connect to existing DB), export snapshot (signed, versioned, immutable), import/fork (new lattice from snapshot, never touches live). | transfer.py, migrations (ep_transfer_packages) | 7 | Planned |
| 13. Notifications | v1.1 | PostgreSQL LISTEN/NOTIFY for state changes; NATS optional for cross-machine. Notifications are hints; agents re-read from DB. | db.py (LISTEN/NOTIFY), optional NATS client | 6 | Planned |
| 14. XID Implementation | v1.1 | Pure Python rs/xid generator: 12 bytes -> 20-char base32hex. Time-sortable, probabilistically unique, collision retry, fork safety, clock rollback handling. | xid.py | 1 | Planned |
| 15. Configuration | v1.1 | .env file: EP_MODE, EP_DB_URL, EP_EMBEDDING_*, EP_MCP_*, EP_NOTIFY, EP_TOKEN_TTL_SECONDS, EP_TOKEN_SIGNING_KEY, EP_MCP_TLS_*, EP_DEV. | config.py, .env.example | 1 | Planned |
| 15.2 Secret Management | v1.1 | EP does not store operational target credentials; service credentials via env vars or secret manager; .env mode 0600. | config.py, README.md (secret management guidance) | 1 | Planned |
| 16. Governed Proxy | v1.1 | Proxy holds credentials; validates token, checks payload hash, checks policy version, executes, records result. Wrappers: shell, postgres, email, docker, git. | proxy.py, src/ep_governance/proxy/ (wrapper modules) | 5 | Planned |
| 16.4 HTTP MCP Security | v1.1 | Private interface bind, TLS, per-agent API keys, request IDs, idempotency, payload size limits, secret redaction, rate limiting. | mcp_server.py (HTTP transport security), config.py | 5–6 | Planned |
| 17. CLI Interface | v1.1 | Full CLI: init, register, create-project, create-branch, add-policy, list-policies, retire-policy, supersede-policy, check, execute, status, log, audit, claim, release-claim, claims, pending-approvals, approve, deny, export, import, resume, serve. | cli.py | 2–7 | Planned |
| 18. MCP Server | v1.1 | MCP tools: ep_check, ep_execute, ep_add_policy, ep_list_policies, ep_retire_policy, ep_supersede_policy, ep_status, ep_log, ep_audit, ep_claim, ep_release_claim, ep_claims, ep_pending_approvals, ep_approve, ep_deny, ep_export, ep_import, ep_resume, ep_tensions, ep_quarantine_status, ep_repair, ep_override. stdio or HTTP transport. | mcp_server.py | 4–6 | Planned |
| 19. Hermes Skill Integration | v1.1 | SKILL.md instructs agent on init, register, resume, check, execute, denial handling, approval waiting, export. Bootstrap loads active policies, branch head, BT, risk ledger, quarantines, claims, approvals from DB. | SKILL.md, bootstrap.py | 4–6 | Planned |
| 20. Installation | v1.1 | GitHub clone, pip install -e, ep-governance init. Hermes skill symlink. Distribution via NAS skill registry. Requirements: Python 3.12+, PostgreSQL/SQLite, optional embeddings/NATS/TLS. | pyproject.toml, scripts/install.sh, README.md | 0 | Planned |
| 21. Repository Structure | v1.1 | Package layout: src/ep_governance/ modules, migrations/, scripts/, SKILL.md, README.md, pyproject.toml, .env.example. | pyproject.toml (package config), existing directory structure | 0 | Planned |
| 22. Implementation Phases | v1.1 | 8 phases: formal semantics, policy engine, DB event/state, transition lifecycle, governed proxy, multi-agent concurrency, transfer packages, embeddings. | work-plan.md (expanded phase definitions) | 0–8 | Planned |
| 23. Security | v1.1 | What EP does (execution-path governance, deterministic policies, audit, quarantine, signed tokens, stale detection, human approval, scoped overrides) and does not do (crypto guarantees against DBA, advisory bypass, compute quotas, credential storage, human judgment). | audit.py, tokens.py, proxy.py, SECURITY.md, README.md | 3–5 | Planned |
| 23.3 Audit Integrity | v1.1 | Append-only hash-chained audit log. (v1.1 formula SHA-256(event_data || previous_hash) corrected by v1.1.1 — see §4 addendum.) | audit.py, migrations (ep_events, ep_audit_heads) | 3 | Planned |
| 24. v1.0 vs v1.1 Comparison | v1.1 | Historical comparison table. No implementation requirement — documentation reference. | docs/ (reference document) | 0 | Planned |
| 25. Open Questions | v1.1 | Ten open questions for team review: policy language, SQL parser, shell parser, signing keys, token signing, risk defaults, branch merge, cleanup/GC, testing strategy, versioning. | ambiguity-register.md (tracks resolution status) | 0 | Planned |

---

## v1.1.1 Addendum Corrections

| Addendum Section | Source Doc | Requirement Summary | Implementation Component | Phase | Status |
|---|---|---|---|---|---|
| §1 Branch Model: One Branch, One Head | v1.1.1 | A branch always has exactly one head. A successful transition advances exactly one branch head. Divergence requires creating a new branch. No schema change needed — existing ep_branches with head_node_id and version supports this. New CLI command: create-branch. | lattice.py (branch head advancement logic), cli.py (create-branch command) | 3–6 | Planned |
| §2 Only Realized States Become Graph Nodes | v1.1.1 | ep_transitions holds proposed/executing actions (full lifecycle). ep_nodes represents only realized/committed states. ep_nodes.status CHECK changes to: committed, quarantined, at_risk, superseded, archived. New ep_node row inserted ONLY when transition reaches succeeded. Transition stores proposed_state inline. | migrations (ep_nodes.status CHECK constraint), lifecycle.py, models.py (Transition shape) | 1–3 | Planned |
| §3 Authorization-Token Claiming Is Atomic | v1.1.1 | Token claiming is an atomic UPDATE ... WHERE used = FALSE AND expires_at > NOW() RETURNING. Claim occurs in same transaction that advances transition to executing. PostgreSQL FOR UPDATE row lock; SQLite BEGIN IMMEDIATE serialization. | tokens.py (atomic claim), lifecycle.py, db.py (transaction management) | 4 | Planned |
| §4 Audit Hashing Includes Full Canonical Event Envelope | v1.1.1 | Event hash covers sequence, event_id, event_type, event_data, principal_id, created_at, previous_hash — all canonical JSON serialized. 10 canonical JSON rules defined (UTF-8, sorted keys, no whitespace, ISO 8601 UTC timestamps, integer/float representation, null/boolean, array order, no duplicate keys, no comments). | audit.py (canonical_json function, hash computation), ADR-0002 (canonical JSON accepted) | 3 | Planned |
| §5 Audit Insertion Is Serialized and Performed Only by Trusted EP Code | v1.1.1 | Only EP-Governance service writes audit events. Agents and proxies submit operations to EP; EP authenticates and writes the event. Actor separation: actor_principal_id, authenticated_caller_id, event_writer_id. Per-lattice audit heads with row locking (ep_audit_heads table). DB permissions: ep_events only EP service role INSERT, no UPDATE/DELETE. | audit.py, auth.py (caller authentication), migrations (ep_audit_heads, ep_events columns), db.py (role-based permissions) | 3 | Planned |
| §6 Policy Activation and Approval Separation | v1.1.1 | Policy lifecycle: draft -> pending_approval -> active -> superseded/retired/rejected. No enforcement effect until active. Policy schema additions: created_by, approved_by, approved_at, activation_version, exception_to, valid_from, valid_until. Separation of duties: decided_by != requested_by. Override restrictions: exception_to must list XID, narrow scope, time-limited, justified, original approval requirements satisfied. | policy.py (policy lifecycle), auth.py (separation of duties check), migrations (ep_policies additional columns, CHECK constraints) | 2–3 | Planned |
| §7 Risk-Ledger Terminology Replaces UT Cost Model | v1.1.1 | Replace ut_cost -> risk_increment, ut_deltas -> risk_assessments, ut_after -> residual_risk_after. API representation includes risk_assessment object (domain, inherent_risk, mitigation_credit, residual_risk, threshold, decision, accepted_by/at, expiration). Mitigations require verified evidence (evidence_type, evidence_uri, evidence_hash, verified_by, verified_at, expires_at, scope). Mitigation credit from policy, not agent self-attestation. | risk.py (risk ledger with new terminology), migrations (ep_transitions risk_assessments/residual_risk_after columns, ep_risk_mitigations additions), cli.py/mcp_server.py (updated API output) | 4 | Planned |
| §8 Enforced Mode Requires Runtime Capability Isolation | v1.1.1 | Enforced mode requires: no direct consequential tools exposed to agent, no target credentials in agent environment, no Docker/SSH sockets mounted, network access restricted, proxy as separate process. This is a deployment constraint, not purely software. Without these measures, EP operates in advisory mode regardless of EP_MODE setting. | SKILL.md, README.md (deployment requirements documentation), proxy.py (separate process), config.py (mode verification) | 5 | Planned |

---

## v1.1.1 Additional Corrections (Review Notes)

| Correction | Source Doc | Requirement Summary | Implementation Component | Phase | Status |
|---|---|---|---|---|---|
| Policy-version checking | v1.1.1 (additional corrections) | Authorization includes matched_policy_ids and matched_policy_versions, not just a single version integer. | tokens.py, migrations (ep_authorizations matched_policy_versions), proxy.py (stale detection) | 4 | Planned |
| Imported policies start as imported_pending_review | v1.1.1 (additional corrections) | Imported policies start as imported_pending_review, not active. Only activate when signer and source are explicitly trusted. | transfer.py (import logic), policy.py (trust verification) | 7 | Planned |
| XID import mapping | v1.1.1 (additional corrections) | Store source_entity_id and imported_entity_id to preserve provenance during import. | transfer.py, migrations (import mapping table or columns) | 7 | Planned |
| Lattice-to-project one-to-one | v1.1.1 (additional corrections) | Add UNIQUE(project_id) on ep_lattices or clarify the one-to-one relationship. | migrations (UNIQUE constraint), lattice.py | 3 | Planned |
| Work-claim uniqueness | v1.1.1 (additional corrections) | Partial index WHERE status = 'active' for PostgreSQL work-claim uniqueness. | migrations/postgres (partial index), lattice.py | 3 | Planned |
| Cleanup and retention | v1.1.1 (additional corrections) | Audit events never garbage-collected. Expired tokens redacted but retained. Failed/denied transitions retained per audit policy. | audit.py (retention policy), tokens.py (redaction), lifecycle.py | 4 | Planned |
| Token signing: Ed25519 | v1.1.1 (additional corrections) | Use Ed25519 asymmetric signatures (EP signs with private key, proxies verify with public key). Compromised proxy cannot mint authorizations. | tokens.py (Ed25519 via PyNaCl), ADR-0003 (accepted) | 4 | Planned |
| Proxy result reporting | v1.1.1 (additional corrections) | Authenticated proxy identity, unique execution-attempt ID, one terminal result per attempt, duplicate callbacks return stored result, unknown outcome becomes execution_uncertain. | proxy.py (result reporting), lifecycle.py (execution_uncertain stage), migrations (ep_transitions.stage CHECK) | 5 | Planned |
| Shell parsing: escalating treatment | v1.1.1 (additional corrections) | Do not promise complete semantic classification. Known safe commands parsed; opaque scripts classified as high-risk shell.exec.opaque; unrecognized commands require approval or deny by default. | classify.py (escalating shell classification) | 2 | Planned |
| Resource canonicalization | v1.1.1 (additional corrections) | Policies match canonical resource identities (e.g., postgres://prod-server/production_db/public/memory_items), not raw agent-supplied strings. | classify.py (resource canonicalization), policy.py (resource matching) | 2 | Planned |
| Condition language: evaluate CEL and Cedar | v1.1.1 (additional corrections) | Evaluate CEL and Cedar before Phase 2. Do not build a custom policy language casually. | ADR-0001 (proposed, pending evaluation), policy.py (condition engine) | 2 | Blocked |

---

## Coverage Verification

All major sections of v1.1 (sections 1–25) and all 8 addendum corrections from v1.1.1 (sections 1–8) plus the additional review corrections are mapped above. Every implementation component in the repository structure (section 21) is referenced. The matrix will be updated as phases progress and components transition from Planned to In Progress to Completed.