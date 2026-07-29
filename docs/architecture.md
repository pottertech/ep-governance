# EP-Governance Architecture Overview

**Version:** 1.0 (Phase 1)
**Date:** July 29, 2026
**Governing Sources:** v1.1 §2, §3, §16, §18, §20.4. v1.1.1 §8.

---

## 1. High-Level Design Diagram

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   Agent (Mary)   │     │  Agent (Brodie)  │     │  Agent (Arty)    │
│   on Mac (local) │     │  on cloudhub     │     │  on Mac (local)  │
└───┬──────────┬───┘     └───┬──────────┬───┘     └───┬──────────┬───┘
    │          │              │          │              │          │
    │ EP CLI   │ EP MCP       │ EP CLI   │ EP MCP       │ EP CLI   │ EP MCP
    │          │              │          │              │          │
    └──────────┴──────┬───────┴──────────┴──────┬───────┴──────────┘
                     │                         │
             ┌───────┴─────────┐               │
             │  EP Service     │               │
             │  (Python)       │               │
             │  - Policy eval  │               │
             │  - Token signing│               │
             │  - Audit writing │               │
             │  - DAG operations│              │
             └───┬──────┬───┬──┘               │
                 │      │   │                   │
         ┌───────┘      │   └───────┐    ┌──────┴──────────┐
         │              │           │    │  Governed Proxy  │
         ▼              ▼           ▼    │  (separate proc) │
    ┌─────────┐   ┌──────────┐  ┌──────┐│  - Holds creds    │
    │Database  │   │Notificat.│  │Embed.││  - shell/db/email │
    │(Postgres │   │(PG LISTEN│  │(Oll. ││  - deploy/git     │
    │ or SQLite│   │/NOTIFY or│  │OpenAI││  - Validates token│
    │ dev-only)│   │  NATS)   │  │/none)││  - Executes action │
    └─────────┘   └──────────┘  └──────┘└───────────────────┘
```

### Data Flow (Enforced Mode)

```
Agent
  → EP authorization request (structured tool call + arguments)
  → EP classifies action server-side (SQL AST, shell parse, etc.)
  → EP evaluates policies (deterministic, server-side)
  → If denied: action rejected, logged → RETURN to agent
  → If require_approval: EP creates approval request → agent waits
  → If allow/warn or approved: EP issues signed Ed25519 authorization token
  → Agent sends token + exact payload to governed proxy
  → Proxy validates token signature (Ed25519 public key)
  → Proxy checks payload hash matches authorization
  → Proxy atomically claims token (UPDATE...WHERE used=FALSE...RETURNING)
  → Proxy executes using its own credentials
  → Proxy records execution result (succeeded/failed) back to EP
  → EP updates transition lifecycle
  → EP commits node to DAG (if succeeded)
  → EP appends audit event
  → Node becomes committed active state only after execution succeeds
```

---

## 2. Core Principles

### 2.1 Governance Governs the Execution Path

Agents do not hold infrastructure credentials. The governed proxy holds them. Agents request authorization, receive a signed short-lived Ed25519 token, and the proxy executes only if the token is valid and the action matches the authorized payload. (v1.1 §2.2.1)

### 2.2 The Database Is the Authoritative Graph

No agent has a local copy. All nodes, edges, policies, and state live in the database. Every operation is a transaction. (v1.1 §2.2.2)

### 2.3 Stateless Python Module

Every function takes a DB connection, does its work in a transaction, and returns. No instance state, no in-memory caches, no authoritative local files. (v1.1 §2.2.3)

### 2.4 Deterministic Policy Evaluation

Enforcement decisions come from structured machine-evaluated policies, not embeddings or natural language. Embeddings assist in policy authoring and discovery only. (v1.1 §2.2.4)

### 2.5 Model-Agnostic

The governance state exists outside any LLM. Export it as a signed transfer package, ingest it into a new model, and the new model inherits the full binding state. (v1.1 §2.2.5)

### 2.6 Multi-Agent by Design

Multiple agents read and write the same graph. PostgreSQL optimistic concurrency ensures atomic transitions. Agents can work in parallel on different branches. (v1.1 §2.2.6)

### 2.7 Append-Only Audit

Transition history is immutable and hash-chained. An agent with database write access cannot silently alter governance history without detection. (v1.1 §2.2.7, v1.1.1 §4–5)

---

## 3. Operating Modes

### 3.1 Advisory Mode

| Aspect | Description |
|--------|-------------|
| **Configuration** | `EP_MODE=advisory` or deployment isolation not achieved |
| **Agent behavior** | Agent voluntarily calls `ep_check` before actions |
| **Enforcement** | None — agent can bypass the gate |
| **Provides** | Policy evaluation, audit trail, risk assessment, structural state tracking |
| **Does NOT provide** | Binding enforcement, credential isolation, execution path governance |
| **Use case** | Development, testing, single-agent experiments |

### 3.2 Enforced Mode

| Aspect | Description |
|--------|-------------|
| **Configuration** | `EP_MODE=enforced` AND all deployment requirements satisfied |
| **Agent behavior** | Consequential tools accessible only through `ep_execute` via governed proxy |
| **Enforcement** | Binding — agent cannot bypass proxy (no credentials, no direct access) |
| **Provides** | All advisory features PLUS binding enforcement, credential isolation, atomic token claiming, stale authorization detection, authenticated proxy results |
| **Use case** | Production, multi-agent, any environment where constraints must bind |

### 3.3 Mode Selection

```
EP_MODE=enforced      # desired mode
EP_MODE=advisory      # advisory mode
EP_DEV=true           # enables self-registration and advisory mode (development)
```

If `EP_MODE=enforced` but deployment requirements are not met, the system operates in advisory mode and reports an advisory.

---

## 4. Execution Path in Enforced Mode

The full execution pipeline (from v1.1 §3.2):

```
1. Agent submits structured action request
   → tool name + arguments (e.g., postgres.execute + SQL statement)

2. EP receives request and classifies server-side
   → SQL: parse AST, determine operation type and target objects
   → Shell: parse command, identify executable and arguments
   → HTTP: evaluate method, host, path, payload
   → Docker: parse command (stop/start/rm/exec/build)
   → Email: inspect recipients and subject
   → Git: parse command (push/reset/merge/force-push)
   → Agent-supplied categories are hints, never authoritative

3. EP evaluates policies
   → Find all active, in-force policies matching action type and resource
   → Evaluate deterministic conditions
   → Resolve effects (deny > require_approval > warn > allow at equal priority)

4. If denied:
   → Action rejected, logged to audit
   → Transition stage = denied (terminal)
   → Return to agent: denied + matched policies

5. If require_approval:
   → EP creates approval request
   → Transition stage = pending_approval
   → Agent waits for human decision

6. If allow or warn (or approval granted):
   → EP issues signed Ed25519 authorization token
   → Transition stage = authorized
   → Token is: short-lived, payload-bound, agent-bound, project-bound,
     branch-bound, proxy-bound, single-use

7. Agent sends token + exact payload to governed proxy

8. Proxy validates token
   → Check Ed25519 signature (using public key)
   → Check token expiry
   → Verify payload hash matches authorized payload hash
   → Check policy-set hash for stale authorization detection

9. Proxy atomically claims token
   → UPDATE ep_authorizations SET used=TRUE WHERE used=FALSE AND expires_at>NOW() RETURNING
   → Same transaction: advance transition to executing
   → Exactly one row must be affected

10. Proxy executes using its own credentials
    → SSH key, database password, email credential, etc.
    → No agent credentials involved

11. Proxy records result to EP
    → Result: succeeded / failed
    → Authenticated proxy identity
    → Execution attempt ID (for dedup)

12. EP updates transition lifecycle
    → If succeeded: transition stage = succeeded
    → If failed: transition stage = failed
    → If callback failed/timeout: transition stage = execution_uncertain

13. EP commits node to DAG (if succeeded)
    → Single transaction (9 steps):
      verify stage, verify branch head, insert node, insert edge,
      mark prior head superseded, update branch head, increment version,
      record result, append audit event

14. EP appends audit event
    → Only EP service writes audit events
    → Full canonical envelope hash
    → Per-lattice hash chain
    → Actor separation: actor_principal_id / authenticated_caller_id / event_writer_id
```

---

## 5. Component Overview

### 5.1 EP Service

| Aspect | Description |
|--------|-------------|
| **Role** | The central governance authority |
| **Responsibilities** | Policy evaluation, action classification, token signing, DAG operations, audit writing, authorization management |
| **Holds** | Ed25519 private signing key, database credentials |
| **Does NOT hold** | Target infrastructure credentials, agent credentials |
| **Stateless** | Every function takes a DB connection, does work in a transaction, returns. No in-memory state. |
| **Technology** | Python 3.12+, SQLAlchemy 2.0+, Pydantic 2.0+, PyNaCl (Ed25519) |

### 5.2 Governed Proxy

| Aspect | Description |
|--------|-------------|
| **Role** | The only path to consequential infrastructure in enforced mode |
| **Responsibilities** | Validate tokens, check payload hashes, execute actions, report results |
| **Holds** | Target infrastructure credentials (SSH, DB, email, cloud), Ed25519 public verification key, EP API key |
| **Does NOT hold** | Ed25519 private signing key, EP database credentials |
| **Deployment** | Separate process or container with its own network identity |
| **Wrappers** | `shell.proxy`, `postgres.proxy`, `email.proxy`, `docker.proxy`, `git.proxy` (Phase 5+) |

### 5.3 Database

| Aspect | Description |
|--------|-------------|
| **Role** | The authoritative graph store |
| **Production** | PostgreSQL (required for multi-agent, LISTEN/NOTIFY, row-level locking, pgvector optional) |
| **Development** | SQLite (single-agent, single-machine, no LISTEN/NOTIFY, no pgvector) |
| **Schema** | Separate migrations: `migrations/postgres/`, `migrations/sqlite/` |
| **All operations** | Transactional — no state outside the database |

### 5.4 MCP Server

| Aspect | Description |
|--------|-------------|
| **Role** | Tool interface for agents |
| **Transport** | stdio (default, for direct Hermes integration) or HTTP (optional, requires TLS + auth) |
| **Tools (advisory)** | `ep_check`, `ep_add_policy`, `ep_list_policies`, `ep_status`, `ep_log`, `ep_audit`, approvals, claims, transfer, quarantine |
| **Tools (enforced)** | `ep_execute` (in addition to advisory tools). Raw infrastructure tools NOT exposed. |
| **Security** | Per-agent API key authentication, request IDs, idempotency keys, payload size limits, rate limiting |

### 5.5 CLI

| Aspect | Description |
|--------|-------------|
| **Role** | Human and script interface for management operations |
| **Commands** | init, register, create-project, create-branch, add-policy, submit-policy, list-policies, retire-policy, check, execute, status, log, audit, claim, release-claim, pending-approvals, approve, deny, export, import, resume, serve, verify-deployment |
| **Technology** | Typer 0.12+ / Click 8.1+ |

---

## 6. Database Authority

### 6.1 PostgreSQL (Production)

| Feature | Support | Notes |
|---------|---------|-------|
| Multi-agent | ✅ | Cross-machine, concurrent transactions |
| LISTEN/NOTIFY | ✅ | Real-time state change notifications |
| Row-level locking | ✅ | `FOR UPDATE` for atomic token claims and audit insertion |
| Partial indexes | ✅ | `WHERE status = 'active'` for work-claim uniqueness |
| pgvector | ✅ (optional) | For policy embeddings (authoring/discovery only) |
| Transactional DDL | ✅ | Most schema changes are transactional |

### 6.2 SQLite (Development Only)

| Feature | Support | Notes |
|---------|---------|-------|
| Multi-agent | ❌ | Single-machine, single-agent only |
| LISTEN/NOTIFY | ❌ | Not supported |
| Row-level locking | ⚠️ | Uses `BEGIN IMMEDIATE` for serialization |
| Partial indexes | ⚠️ | Limited support |
| pgvector | ❌ | Not available |
| WAL mode | ✅ | Concurrent reads supported |

### 6.3 Separate Migrations

```
migrations/
  postgres/
    001_init.sql
  sqlite/
    001_init.sql
```

All integration and concurrency tests MUST run against PostgreSQL (via Testcontainers). SQLite-only tests are labeled and do not substitute for PostgreSQL integration tests.

---

## 7. Technology Baseline

| Component | Technology | Version |
|-----------|-----------|---------|
| Language | Python | 3.12+ |
| Database ORM | SQLAlchemy | 2.0+ |
| Migrations | Alembic | 1.13+ |
| Validation | Pydantic | 2.0+ |
| CLI | Typer | 0.12+ |
| CLI (fallback) | Click | 8.1+ |
| Testing | pytest | 8.0+ |
| Property testing | Hypothesis | 6.100+ |
| Integration testing | Testcontainers (PostgreSQL) | 4.0+ |
| Crypto (Ed25519) | PyNaCl | 1.5+ |
| Crypto (additional) | cryptography | 42.0+ |
| SQL parsing | sqlglot | 23.0+ |
| JSON validation | jsonschema | 4.20+ |
| YAML | PyYAML | 6.0+ |
| MCP | mcp | 0.9+ (optional) |
| Linting | ruff | 0.4+ |
| Type checking | mypy | 1.10+ (strict mode) |

### 7.1 No External ID Dependencies

- XIDs (20-char base32hex, probabilistically unique) are generated by a pure Python implementation.
- No dependency on the PyPI `xid` package.
- XID format: 12 bytes → 20-char lowercase base32hex (timestamp + machine ID + PID + counter).

### 7.2 Embeddings (Optional)

- Embedding providers: Ollama, OpenAI, Cohere, sentence-transformers, or none.
- Used for policy authoring assistance and discovery only — NEVER for enforcement.
- `EP_EMBEDDING_PROVIDER=none` disables all semantic features; enforcement is fully functional.