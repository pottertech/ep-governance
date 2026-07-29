# EP-Governance Work Plan

## Version

1.0 — Phase 0 Specification Intake

## Date

2026-07-29

## Purpose

This document defines the phased implementation plan for EP-Governance, covering Phases 0 through 11. The phase definitions reference the governing design documents: `ep-governance-design-v1.1.md` (v1.1 §22) and `ep-governance-design-v1.1.1.md` (v1.1.1), plus the project directive's expanded phase structure. Where v1.1 and v1.1.1 conflict, v1.1.1 governs.

Phases 0 and 1 are defined by the project directive (repository/specification intake and normative specification/executable contracts). Phases 2–8 correspond to the v1.1 §22 implementation phases. Phases 9–11 extend the plan to cover CLI/MCP integration, security hardening, and production release.

---

## Phase Summary

| Phase | Name | Dependencies |
|---|---|---|
| 0 | Repository and Specification Intake | None |
| 1 | Normative Specification and Executable Contracts | Phase 0 |
| 2 | Deterministic Policy Engine | Phase 1 |
| 3 | PostgreSQL Event and State Model | Phase 1 |
| 4 | Transition Lifecycle | Phases 2, 3 |
| 5 | Governed Tool Wrapper | Phases 3, 4 |
| 6 | Multi-Agent Concurrency | Phases 3, 4 |
| 7 | Transfer Packages | Phases 3, 4 |
| 8 | Semantic Assistance | Phase 2 |
| 9 | CLI and MCP Server Integration | Phases 2–7 |
| 10 | Security Hardening and Deployment Validation | Phases 5, 9 |
| 11 | Production Release and Documentation | Phases 0–10 |

---

## Phase 0: Repository and Specification Intake

| Field | Value |
|---|---|
| Phase | 0 |
| Name | Repository and Specification Intake |
| Scope Summary | Establish the repository, ingest the governing design documents (v1.1 and v1.1.1), produce Phase 0 specification artifacts (traceability matrix, ambiguity register, risk register, work plan), and prepare the project skeleton for Phase 1. No runtime code. |
| Deliverables | Repository structure (pyproject.toml, src/ep_governance/, migrations/, tests/, scripts/); governing design documents ingested; traceability-matrix.md; ambiguity-register.md; risk-register.md; work-plan.md (this document); ADR-0001 through ADR-0004 (proposed/accepted); README.md and SKILL.md with mode documentation. |
| Gate Criteria | All four Phase 0 documents complete and reviewed. Ambiguity register identifies all conflicts between v1.1 and v1.1.1. Risk register has at least 15 risks with mitigations. Traceability matrix covers all v1.1 sections and all 8 v1.1.1 addendum corrections. ADRs for condition language, canonical JSON, signature format, and database boundaries exist. |
| Estimated Effort | 1–2 days |
| Dependencies | None |

---

## Phase 1: Normative Specification and Executable Contracts

| Field | Value |
|---|---|
| Phase | 1 |
| Name | Normative Specification and Executable Contracts |
| Scope Summary | Define the formal models for all governance entities: project, lattice, branch, node, transition lifecycle stages, policy schema, effect types, condition evaluation, authorization token, stale detection, idempotency, risk domain, risk ledger, mitigations, quarantine/denial/at-risk/revocation semantics, BT (planning budget), UT (risk ledger) semantics. Produce executable contracts (type signatures, protocol definitions, schema DDL) that codify the formal semantics. No runtime behavior — only type definitions, schema, and contracts. Resolve open ambiguities from the ambiguity register that block Phase 2 (AMB-008, AMB-009, AMB-010, AMB-011, AMB-019). This corresponds to v1.1 §22 Phase 1 (Formal Semantics) extended with executable contract definitions. |
| Deliverables | Formal specification document (docs/formal-semantics.md); Python type definitions and dataclasses (models.py); database schema DDL for both PostgreSQL and SQLite (migrations/postgres/001_init.sql, migrations/sqlite/001_init.sql) incorporating all v1.1.1 corrections; XID generator (xid.py) with collision handling, fork safety, and clock rollback; config loader (config.py); canonical JSON serialization module with property-based tests; executable contract tests (tests/contracts/); ADR-0001 condition language decision finalized; ADR for SQL parser (AMB-009); ADR for shell parser (AMB-010); risk domain defaults documented (AMB-011); versioning policy ADR (AMB-019). |
| Gate Criteria | Formal specification document covers all governance entities and is unambiguous. Database schema DDL incorporates all v1.1.1 corrections (ep_nodes.status CHECK, ep_transitions.stage CHECK, ep_audit_heads table, ep_policies lifecycle columns, risk_assessments/residual_risk_after columns, matched_policy_versions). XID generator passes property-based tests (uniqueness, monotonicity, fork safety, clock rollback). Canonical JSON passes property-based tests (determinism, sorted keys, timestamp format, float representation). All blocking ambiguities from the ambiguity register are resolved or have ADRs with decisions. Contract tests pass. |
| Estimated Effort | 3–5 days |
| Dependencies | Phase 0 |

---

## Phase 2: Deterministic Policy Engine

| Field | Value |
|---|---|
| Phase | 2 |
| Name | Deterministic Policy Engine |
| Scope Summary | Implement the structured policy model: policy CRUD (create, read, retire, supersede) with the v1.1.1 §6 lifecycle (draft -> pending_approval -> active -> superseded/retired/rejected); server-side action classification (SQL AST parsing, shell parsing with escalating treatment, HTTP method/host/path, Docker command, email recipients, git command, file path); deterministic condition evaluation using the language selected in ADR-0001; effect resolution with priority ordering and severity tie-breaking; tension detection at policy creation time; resource canonicalization. No embeddings. No enforcement yet. This corresponds to v1.1 §22 Phase 2. |
| Deliverables | classify.py (server-side classification for SQL, shell, HTTP, Docker, email, git, file); policy.py (policy CRUD, lifecycle management, condition evaluation, effect resolution, tension detection, override validation with v1.1.1 §6 restrictions); risk.py (risk domain defaults, risk ledger per domain); unit tests with deterministic cases (tests/unit/); property-based tests for policy evaluation edge cases (tests/property/). |
| Gate Criteria | All 14 action categories from v1.1 §10.3 classified correctly with correct BT/UT (risk_increment) defaults. SQL classifier parses DROP, DELETE, INSERT, UPDATE, SELECT with correct target extraction using the chosen parser (AMB-009). Shell classifier follows escalating treatment model (known safe -> parsed, opaque -> shell.exec.opaque, unrecognized -> require_approval/deny). Condition engine evaluates the ADR-0001 language correctly and fails closed on errors. Policy lifecycle enforces draft -> pending_approval -> active with separation of duties (decided_by != requested_by). Tension detection catches contradictory effects at same priority. Override restrictions enforced (exception_to, narrow scope, time-limited, justified). All unit tests pass. No embeddings used in any enforcement path. |
| Estimated Effort | 5–8 days |
| Dependencies | Phase 1 |

---

## Phase 3: PostgreSQL Event and State Model

| Field | Value |
|---|---|
| Phase | 3 |
| Name | PostgreSQL Event and State Model |
| Scope Summary | Implement the database schema for PostgreSQL, the append-only hash-chained audit log with v1.1.1 §4 canonical envelope hashing and §5 per-lattice serialized insertion, node/edge/branch operations with optimistic concurrency, cycle prevention, and event recording. This corresponds to v1.1 §22 Phase 3. |
| Deliverables | db.py (PostgreSQL connection management, transaction context); migrations/postgres/001_init.sql (full schema with all v1.1.1 corrections); audit.py (canonical JSON serialization, event hash computation, per-lattice audit head locking, actor separation, event insertion); lattice.py (DAG operations: add node, add edge, cycle check via forward BFS, branch head management, optimistic concurrency with expected_head_id/expected_version); auth.py (principal/role/binding/credential management); PostgreSQL integration tests via Testcontainers (tests/integration/). |
| Gate Criteria | Schema DDL creates all tables with correct CHECK constraints (ep_nodes.status: committed/quarantined/at_risk/superseded/archived; ep_transitions.stage: all 10 stages; ep_policies.status: all 6 lifecycle states). Audit hash chain is verifiable: any party can recompute each event hash from the canonical envelope and verify previous_hash linkage. Per-lattice audit heads serialize concurrent writes correctly (10+ concurrent writers test). Cycle prevention rejects edges that create cycles via forward BFS. Optimistic concurrency: two concurrent branch head updates — one succeeds, one fails with stale_head. Only EP service role can INSERT into ep_events; no role can UPDATE/DELETE. Actor separation columns present (actor_principal_id, authenticated_caller_id, event_writer_id). Migration up/down tested. All PostgreSQL integration tests pass. |
| Estimated Effort | 5–8 days |
| Dependencies | Phase 1 |

---

## Phase 4: Transition Lifecycle

| Field | Value |
|---|---|
| Phase | 4 |
| Name | Transition Lifecycle |
| Scope Summary | Implement the full transition state machine: proposed -> authorized -> executing -> succeeded/failed/cancelled/expired/denied/pending_approval/execution_uncertain. Authorization token issuance with Ed25519 signing, atomic claiming (v1.1.1 §3), single-use enforcement, expiry. Stale authorization detection via matched_policy_versions. Idempotency keys. BT (planning budget) consumption and exhaustion. Risk ledger (UT) evaluation with v1.1.1 §7 terminology. This corresponds to v1.1 §22 Phase 4. |
| Deliverables | lifecycle.py (transition state machine, all stage transitions, idempotency handling); tokens.py (Ed25519 token signing/verification via PyNaCl, atomic claim via UPDATE ... RETURNING, expiry checking, key rotation support); risk.py (risk ledger per domain, risk_increment tracking, residual_risk_after computation, mitigation evidence verification); integration tests for the full lifecycle (tests/integration/); concurrency tests for atomic token claiming (tests/concurrency/). |
| Gate Criteria | All transition stage transitions implemented and tested: proposed->denied, proposed->pending_approval, proposed->authorized, authorized->executing, executing->succeeded, executing->failed, executing->execution_uncertain, authorized->expired (stale detection), authorized->cancelled. Ed25519 token signing and verification pass round-trip tests. Atomic token claiming: two concurrent claims — one succeeds, one is rejected (no double execution). Stale authorization: policy version advance invalidates token. Idempotency: duplicate key returns existing transition/result. BT exhaustion: transition rejected with resource_exhausted. Risk ledger: per-domain residual_risk computed correctly, thresholds enforced, mitigation evidence required (not self-attested). Key rotation: new key signs, old key still verifies during transition window. All integration and concurrency tests pass. |
| Estimated Effort | 8–12 days |
| Dependencies | Phases 2, 3 |

---

## Phase 5: Governed Tool Wrapper

| Field | Value |
|---|---|
| Phase | 5 |
| Name | Governed Tool Wrapper |
| Scope Summary | Demonstrate real enforcement with one tool category. Start with postgres.proxy (SQL execution against a specified database). The proxy holds database credentials, validates the Ed25519 token, checks payload hash, checks matched_policy_versions (stale detection), executes using proxy credentials, records the authenticated result to EP. Integration test proving the agent cannot bypass the proxy to access the database directly. This corresponds to v1.1 §22 Phase 5. |
| Deliverables | proxy.py (governed proxy framework: token validation, payload hash verification, stale detection, execution, result reporting with authenticated proxy identity and execution-attempt ID); src/ep_governance/proxy/postgres_proxy.py (SQL execution wrapper); integration test: agent proposes SQL -> EP authorizes -> proxy validates and executes -> result recorded; security test: agent without proxy access cannot reach the database; deployment documentation for proxy as separate process (v1.1.1 §8 requirements). |
| Gate Criteria | End-to-end flow works: agent proposes SQL action -> EP classifies, evaluates policies, issues Ed25519 token -> proxy validates token (signature, expiry, used flag via atomic claim, payload hash match, policy version match) -> proxy executes SQL using its own credentials -> proxy reports result to EP -> EP updates transition to succeeded/failed/execution_uncertain. Token replay attack fails (single-use enforced). Payload swap attack fails (hash mismatch). Stale token (policy changed) is rejected. Agent without direct database credentials cannot execute SQL. Proxy crash leaves transition in execution_uncertain after timeout. All integration and security tests pass. |
| Estimated Effort | 8–10 days |
| Dependencies | Phases 3, 4 |

---

## Phase 6: Multi-Agent Concurrency

| Field | Value |
|---|---|
| Phase | 6 |
| Name | Multi-Agent Concurrency |
| Scope Summary | Add branch heads with optimistic concurrency, stale-head detection and retry, work claims, LISTEN/NOTIFY for state change notifications, branch creation and independent advancement, and integration tests with two agents committing to the same branch. This corresponds to v1.1 §22 Phase 6. |
| Deliverables | lattice.py (branch creation via create-branch, work claim management with partial unique index); db.py (LISTEN/NOTIFY for ep_state_changed and ep_policy_changed channels); cli.py (create-branch, claim, release-claim, claims commands); integration tests with two agents on the same branch (one succeeds, one gets stale_head); integration tests with two agents on separate branches (both succeed); concurrency stress tests (tests/concurrency/). |
| Gate Criteria | Two agents proposing transitions from the same branch head: first succeeds (advances head, increments version), second fails with stale_head and can retry or create a new branch. Work claims prevent two agents from claiming the same region simultaneously (partial index WHERE status = 'active'). LISTEN/NOTIFY fires on transition commit and policy change; subscribers re-read from DB. Branch creation via create-branch sets new branch head to parent's current head and links to project. Agents on separate branches operate independently without interference. All concurrency tests pass. Merge semantics deferred (AMB-007 remains open — not a gate for this phase). |
| Estimated Effort | 5–8 days |
| Dependencies | Phases 3, 4 |

---

## Phase 7: Transfer Packages

| Field | Value |
|---|---|
| Phase | 7 |
| Name | Transfer Packages |
| Scope Summary | Add export (signed, versioned snapshot), import/fork (creates new lattice, never touches live data), resume (connect to existing database), schema versioning, content hash and signature verification. Imported policies start as imported_pending_review (v1.1.1 additional corrections). XID import mapping preserves provenance. This corresponds to v1.1 §22 Phase 7. |
| Deliverables | transfer.py (export: serialize lattice state to canonical JSON, compute content_hash, sign with Ed25519; import: create new lattice with new XIDs, map source_entity_id to imported_entity_id, mark policies as imported_pending_review; resume: connect to existing DB); cli.py (export, import, resume commands); migrations (ep_transfer_packages table); integration tests for export/import/resume round-trip; security tests for signature verification and untrusted package handling. |
| Gate Criteria | Export produces a signed, versioned JSON document with content_hash (SHA-256 of canonical lattice_state), Ed25519 signature, signer_id, and trust_status. Import creates a new lattice with new XIDs for all entities (no ID collision). Imported policies have status imported_pending_review, not active. Import never touches the original lattice. Source entity provenance preserved (source_entity_id -> imported_entity_id mapping). Resume connects to existing DB without export/import. Signature verification fails for tampered packages. Untrusted packages are rejected or imported with all policies pending review. All integration tests pass. |
| Estimated Effort | 5–8 days |
| Dependencies | Phases 3, 4 |

---

## Phase 8: Semantic Assistance

| Field | Value |
|---|---|
| Phase | 8 |
| Name | Semantic Assistance |
| Scope Summary | Add embeddings for policy authoring assistance (suggest structured policy from natural language), policy discovery (suggest relevant policies for proposed action), and audit search (find similar past transitions). Re-embedding on model change. Embeddings never participate in enforcement decisions. This corresponds to v1.1 §22 Phase 8. |
| Deliverables | embeddings.py (pluggable backends: ollama, openai, cohere, sentence-transformers, none); migrations (ep_policy_embeddings table with pgvector for PostgreSQL); policy authoring assistance (suggest template from intent); policy discovery (semantic similarity for proposed action); audit search (semantic similarity); re-embedding on model change (old embeddings retained, marked superseded); unit tests with EP_EMBEDDING_PROVIDER=none (all enforcement fully functional without embeddings). |
| Gate Criteria | EP_EMBEDDING_PROVIDER=none: all enforcement features work identically (embeddings are purely additive). Policy authoring: given natural language intent, suggests structured policy template using semantic matching. Policy discovery: given proposed action, surfaces semantically relevant policies as hints (enforcement decision is still deterministic). Audit search: finds similar past transitions by semantic similarity. Re-embedding: when model changes, all active policies re-embedded; old embeddings retained for audit; new embeddings have correct model_name and source_text_hash. No enforcement decision path touches embeddings. All unit tests pass with and without embeddings. |
| Estimated Effort | 5–7 days |
| Dependencies | Phase 2 |

---

## Phase 9: CLI and MCP Server Integration

| Field | Value |
|---|---|
| Phase | 9 |
| Name | CLI and MCP Server Integration |
| Scope Summary | Complete the full CLI interface (v1.1 §17) and MCP server (v1.1 §18) with all commands and tools. Integrate all prior phase functionality into the CLI and MCP tool surface. Support stdio and HTTP transports. Mode-dependent tool registration (advisory vs enforced). |
| Deliverables | cli.py (all commands: init, register, create-project, create-branch, add-policy, submit-policy, list-policies, retire-policy, supersede-policy, check, execute, status, log, audit, claim, release-claim, claims, pending-approvals, approve, deny, export, import, resume, serve, rotate-signing-key, reconcile); mcp_server.py (all MCP tools: ep_check, ep_execute, ep_add_policy, ep_list_policies, ep_retire_policy, ep_supersede_policy, ep_status, ep_log, ep_audit, ep_claim, ep_release_claim, ep_claims, ep_pending_approvals, ep_approve, ep_deny, ep_export, ep_import, ep_resume, ep_tensions, ep_quarantine_status, ep_repair, ep_override); stdio transport (default, for Hermes integration); HTTP transport (with TLS, per-agent API keys, request IDs, idempotency, payload limits, secret redaction, rate limiting); bootstrap.py (session bootstrap: load active policies, branch head, BT, risk ledger, quarantines, claims, pending approvals); integration tests for CLI and MCP. |
| Gate Criteria | All CLI commands from v1.1 §17.1 implemented and tested. All MCP tools from v1.1 §18.1 implemented and tested. Mode-dependent tool registration: advisory mode exposes governance management tools (ep_check, not ep_execute); enforced mode exposes ep_execute and governance tools, not raw shell/db/email/docker/git tools. stdio transport works for Hermes integration. HTTP transport enforces TLS, per-agent authentication, replay protection, and rate limiting. Bootstrap loads all required state from DB and injects into agent context. SKILL.md updated with final tool list and usage instructions. All CLI and MCP integration tests pass. |
| Estimated Effort | 8–10 days |
| Dependencies | Phases 2–7 |

---

## Phase 10: Security Hardening and Deployment Validation

| Field | Value |
|---|---|
| Phase | 10 |
| Name | Security Hardening and Deployment Validation |
| Scope Summary | Harden the system against identified security risks (RSK-001 through RSK-020). Validate deployment isolation for enforced mode (v1.1.1 §8). Perform adversarial testing: classifier evasion, token forgery, audit tampering, sandbox escape. Validate key rotation. Test network partition and proxy crash scenarios. Security audit of the codebase. |
| Deliverables | Adversarial test suite (tests/security/): SQL classifier evasion attempts, shell classifier evasion, token forgery attempts, audit tampering detection, condition engine sandbox testing; deployment validation checklist and guide (docs/deployment-guide.md) covering v1.1.1 §8 requirements; startup isolation checker (warns if EP_MODE=enforced but isolation indicators suggest advisory); network partition and proxy crash recovery tests (execution_uncertain reconciliation); key rotation integration test; security review report. |
| Gate Criteria | SQL classifier: adversarial test cases (multi-statement, obfuscation, dialect tricks, comments) all classified to highest-risk when ambiguous. Shell classifier: opaque scripts classified as shell.exec.opaque, dangerous executables denylisted. Token forgery: Ed25519 signature verification rejects all forgery attempts. Audit tampering: any modification to ep_events breaks the hash chain detectably. Condition engine: no network/filesystem/shell access from within policy evaluation. Deployment validation: v1.1.1 §8 all 5 requirements documented and testable. Isolation checker warns when enforced mode is configured but isolation is not detected. Key rotation: verified with transition window, old and new keys accepted. Network partition: execution_uncertain state reached and operator reconciliation works. All security tests pass. Security review report produced with no critical findings. |
| Estimated Effort | 5–8 days |
| Dependencies | Phases 5, 9 |

---

## Phase 11: Production Release and Documentation

| Field | Value |
|---|---|
| Phase | 11 |
| Name | Production Release and Documentation |
| Scope Summary | Finalize all documentation, package the release, validate the full system end-to-end, and prepare for production deployment. Complete README.md, SKILL.md, SECURITY.md, deployment guide, and API documentation. Verify all phase gate criteria are met. Tag the release. |
| Deliverables | Final README.md (installation, usage, modes, non-goals, deployment requirements); final SKILL.md (agent integration instructions, mode guarantees, rules); final SECURITY.md (security properties, limitations, audit integrity); docs/deployment-guide.md (enforced mode deployment, proxy setup, credential isolation, network policy); docs/api-reference.md (CLI commands and MCP tools); docs/formal-semantics.md (complete formal specification); release tag in git; full end-to-end test run passing; changelog. |
| Gate Criteria | All Phase 0–10 gate criteria met. All ambiguities in ambiguity-register.md are resolved or have documented safe interpretations. All risks in risk-register.md are mitigating, closed, or accepted with documented rationale. End-to-end test: full lifecycle from init -> register -> create-project -> create-branch -> add-policy -> submit-policy -> approve -> check -> execute -> audit -> export -> import -> resume. Documentation is complete and reviewed. Release tag created. No critical or high-severity bugs open. |
| Estimated Effort | 3–5 days |
| Dependencies | Phases 0–10 |

---

## Effort Summary

| Phase | Name | Estimated Effort | Cumulative |
|---|---|---|---|
| 0 | Repository and Specification Intake | 1–2 days | 1–2 days |
| 1 | Normative Specification and Executable Contracts | 3–5 days | 4–7 days |
| 2 | Deterministic Policy Engine | 5–8 days | 9–15 days |
| 3 | PostgreSQL Event and State Model | 5–8 days | 14–23 days |
| 4 | Transition Lifecycle | 8–12 days | 22–35 days |
| 5 | Governed Tool Wrapper | 8–10 days | 30–45 days |
| 6 | Multi-Agent Concurrency | 5–8 days | 35–53 days |
| 7 | Transfer Packages | 5–8 days | 40–61 days |
| 8 | Semantic Assistance | 5–7 days | 45–68 days |
| 9 | CLI and MCP Server Integration | 8–10 days | 53–78 days |
| 10 | Security Hardening and Deployment Validation | 5–8 days | 58–86 days |
| 11 | Production Release and Documentation | 3–5 days | 61–91 days |

Total estimated effort: 61–91 days (approximately 12–18 weeks).

---

## Phase Dependencies (Directed)

```
Phase 0 -> Phase 1
Phase 1 -> Phase 2
Phase 1 -> Phase 3
Phase 2 -> Phase 4
Phase 3 -> Phase 4
Phase 3 -> Phase 5
Phase 4 -> Phase 5
Phase 3 -> Phase 6
Phase 4 -> Phase 6
Phase 3 -> Phase 7
Phase 4 -> Phase 7
Phase 2 -> Phase 8
Phase 2..7 -> Phase 9
Phase 5 -> Phase 10
Phase 9 -> Phase 10
Phase 0..10 -> Phase 11
```

Phases 2 and 3 can proceed in parallel after Phase 1. Phase 8 (Semantic Assistance) can proceed in parallel with Phases 4–7 as it only depends on Phase 2. Phase 9 requires Phases 2–7 as it integrates all prior functionality into the CLI and MCP server. Phase 10 requires Phases 5 and 9 (enforcement proxy and CLI/MCP for security testing). Phase 11 requires all prior phases.