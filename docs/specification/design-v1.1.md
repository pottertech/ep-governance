# EP-Governance: Design Document v1.1

## Version: 1.1
## Date: July 28, 2026
## Status: Draft for Team Review (incorporates v1.0 review feedback)
## Supersedes: v1.0

---

## 1. Overview

### 1.1 What is EP-Governance?

EP-Governance is a binding governance system for AI agents. It solves a fundamental problem: as AI agents operate over longer time horizons and across multiple sessions, rules and constraints established early in a project lose their force. Context windows compress, sessions end, models get swapped, and the original governing constraints evaporate.

EP-Governance maintains a persistent directed acyclic state graph (DAG) with inherited policies and transactional transitions. The graph exists outside any LLM. It binds any model that connects to it. It governs the execution path, not merely the agent's intentions.

### 1.2 Conceptual Model: The Energetic Paradigm

The Energetic Paradigm (EP) provides the conceptual vocabulary:

- **Invariants** are rigid outer boundaries: absolute rules that no transition may violate.
- **Dependencies** are load-bearing struts: directed edges that trace the lineage of every decision.
- **Energy** is operational resistance: the degree to which a past decision restricts future available states.
- **Verification pulse**: when an agent proposes an action, a backward-traversing check tests the proposal against the full dependency lineage.
- **Structural quarantine**: violations are repelled and isolated to the affected region of the graph, preserving the rest.

The engineering implementation is a DAG with policies, resources, and transitions. The EP terminology describes the conceptual model; it does not substitute for formal definitions.

### 1.3 Goals

- Provide a standalone, installable Python package (private GitHub repo: pottertech/ep-governance)
- Work as a Hermes skill + MCP server + CLI tool
- Govern the execution path: consequential tools are accessible only through a governed proxy
- Support multiple AI agents running in parallel on same or different hardware
- Store all authoritative governance state in a database (PostgreSQL for production, SQLite for development only)
- Use pluggable embedding backends (Ollama, OpenAI, Cohere, sentence-transformers, or none) for policy discovery and authoring assistance only -- never for enforcement
- Export/import model-agnostic, signed, versioned transfer packages for LLM switching mid-project
- Use rs/xid format IDs (20-char base32hex, probabilistically unique) generated consistently by a Python implementation

### 1.4 Non-Goals

- Not a replacement for Hermes memory or the NAS memory_items system
- Not a general-purpose agent framework -- it is a governance layer
- Not a substitute for human approval of dangerous actions -- it complements, not replaces, human-in-the-loop
- Not a compute quota system -- BT is a planning budget, not a real infrastructure limit
- Not a cryptographic guarantee -- it is a governance and audit system that makes bypassing constraints structurally difficult, not cryptographically impossible

---

## 2. Architecture

### 2.1 High-Level Design

```
+-------------------+     +-------------------+     +-------------------+
|   Agent (Mary)    |     |  Agent (Brodie)   |     |  Agent (Arty)    |
|  on Mac (local)   |     |  on cloudhub      |     |  on Mac (local)  |
+---+----------+----+     +---+----------+----+     +---+----------+---+
    |          |              |          |              |          |
    | EP CLI   | EP MCP       | EP CLI   | EP MCP       | EP CLI   | EP MCP
    |          |              |          |              |          |
    +----------+---------+----+----------+---------+----+----------+
                       |                          |
               +-------+----------+               |
               |  Governed Proxy  |               |
               |  (holds creds)    |               |
               |  shell/db/email/  |               |
               |  deploy wrappers   |               |
               +---+---------+-----+               |
                   |         |                     |
           +-------+--+   +-+-------+    +--------+--------+
           | Database |   | Embeds  |    | Notifications   |
           | (Postgres|   | (Ollama/|    | (PG LISTEN/NOTIFY|
           | or SQLite)|   | OpenAI/ |    | or NATS)        |
           +----------+   | Cohere/ |    +-----------------+
                          | SST/none)|
                          +---------+
```

### 2.2 Core Principles

1. **Governance governs the execution path.** Agents do not hold infrastructure credentials. The governed proxy holds them. Agents request authorization, receive a signed short-lived token, and the proxy executes only if the token is valid and the action matches the authorized payload.

2. **The database is the authoritative graph.** No agent has a local copy. All nodes, edges, policies, and state live in the database. Every operation is a transaction.

3. **Stateless Python module.** Every function takes a DB connection, does its work in a transaction, and returns. No instance state, no in-memory caches, no authoritative local files.

4. **Deterministic policy evaluation.** Enforcement decisions come from structured machine-evaluated policies, not embeddings or natural language. Embeddings assist in policy authoring and discovery only.

5. **Model-agnostic.** The governance state exists outside any LLM. Export it as a signed transfer package, ingest it into a new model, and the new model inherits the full binding state.

6. **Multi-agent by design.** Multiple agents read and write the same graph. Postgres optimistic concurrency ensures atomic transitions. Agents can work in parallel on different branches.

7. **Append-only audit.** Transition history is immutable and hash-chained. An agent with database write access cannot silently alter governance history.

---

## 3. Operating Modes

### 3.1 Advisory Mode

Agents voluntarily call the gate before actions. The gate evaluates the proposal against policies and returns a recommendation. The agent may proceed or not. No enforcement.

Use case: development, testing, single-agent experiments.

### 3.2 Enforced Mode

Consequential tools are accessible only through a governed proxy. The execution path:

```
Agent
  -> EP authorization request (structured tool call + arguments)
  -> EP evaluates policies server-side
  -> If denied: action rejected, logged
  -> If approved: EP issues signed short-lived authorization token
  -> Agent sends token + exact payload to governed proxy
  -> Proxy validates token, checks payload hash matches authorization
  -> Proxy executes using its own credentials
  -> Proxy records execution result (succeeded/failed) back to EP
  -> EP updates transition lifecycle
  -> Node becomes committed active state only after execution succeeds
```

The underlying credentials (SSH keys, database passwords, email credentials, API tokens) belong to the proxy, not the agent. The agent cannot bypass governance because it does not have direct access to the infrastructure.

Use case: production, multi-agent, any environment where constraints must bind.

### 3.3 Mode Selection

Configured in `.env`:

```env
EP_MODE=enforced     # or: advisory
```

In enforced mode, the agent receives MCP tools that route through the proxy. In advisory mode, the agent receives governance management tools and is expected to call `ep_check` before actions.

---

## 4. Policy Model

### 4.1 Structured Policies

Policies are machine-evaluated, deterministic rules. They use a typed schema:

```json
{
  "policy_id": "cjvbbzh6qgtnoxiaa001",
  "effect": "deny",
  "actions": ["db.delete", "db.drop", "file.delete"],
  "resources": ["env:production/**"],
  "conditions": {
    "backup_verified": false
  },
  "priority": 100,
  "scope": "global",
  "agent_scope": null,
  "description": "Never delete production data without verified backup"
}
```

### 4.2 Policy Fields

| Field | Type | Description |
|-------|------|-------------|
| policy_id | XID | Unique identifier |
| effect | enum | `deny`, `require_approval`, `warn`, `allow` |
| actions | array | Action type selectors: `db.delete`, `db.drop`, `file.delete`, `shell.exec`, `email.send`, `deployment`, `git.mutation`, `http.post`, etc. |
| resources | array | Resource selectors using glob patterns: `env:production/**`, `host:cloudhub`, `db:gbrain_pilot`, `container:open-webui` |
| conditions | object | Additional conditions evaluated against the action context: `{"backup_verified": false}`, `{"business_hours": true}` |
| priority | int | Conflict resolution order. Higher priority wins. Default 0. |
| scope | enum | `global` (binds all agents) or `agent` (binds only the establishing agent) |
| agent_scope | XID or null | If scope=agent, which agent this binds. Null if global. |
| description | string | Human-readable explanation (for audit and authoring) |

### 4.3 Effects

| Effect | Behavior |
|--------|----------|
| `deny` | Action is blocked. Transition is denied. Logged. |
| `require_approval` | Action requires human approval. EP creates an approval request. Agent waits or proceeds to a different action. |
| `warn` | Action proceeds but warning is logged. Agent is notified. |
| `allow` | Explicitly permitted. Overrides lower-priority deny/warn policies. |

### 4.4 Policy Evaluation

When an action is proposed:

1. **Server-side classification.** EP receives a structured tool call (tool name + arguments). EP classifies the action server-side by inspecting the payload:
   - SQL: parse the AST to determine operation type (SELECT, INSERT, UPDATE, DELETE, DROP) and target objects (tables, schemas, databases)
   - Shell: parse the command to identify the executable and arguments
   - HTTP: evaluate method, host, path, and payload class
   - Docker: parse the command (stop, start, rm, exec, build)
   - Email: inspect recipients and subject
   Agent-supplied categories are hints, never authoritative.

2. **Policy lookup.** Find all active policies whose `actions` match the classified action type and whose `resources` match the classified target.

3. **Condition evaluation.** For each matching policy, evaluate `conditions` against the action context. Conditions are deterministic JSON expressions (not embeddings).

4. **Effect resolution.** If multiple policies match:
   - Highest priority wins
   - If equal priority: `deny` > `require_approval` > `warn` > `allow`
   - If two policies with the same priority and conflicting effects: log a policy conflict (tension) and return `require_approval`

5. **Result.** Return the resolved effect, the matched policies, and the classification details.

### 4.5 Role of Embeddings

Embeddings are never used for enforcement. They are used for:

- **Policy authoring assistance**: when a human says "never delete production data," the system suggests a structured policy template by semantically matching the intent against known policy patterns.
- **Policy discovery**: when an agent proposes an action, the system can suggest "this action may be relevant to these policies" using semantic similarity. The agent can review the policies. But the enforcement decision is deterministic.
- **Audit search**: searching transition history by semantic similarity to find "actions like this one."

When `EP_EMBEDDING_PROVIDER=none`, the system works with exact and pattern matching only. No semantic features. All enforcement is fully functional.

---

## 5. Transition Lifecycle

### 5.1 Stages

A transition is not a single event. It is a multi-stage lifecycle:

```
proposed -> authorized -> executing -> succeeded
                                   -> failed
                                   -> cancelled
                      -> expired
         -> denied
         -> pending_approval
```

| Stage | Meaning |
|-------|---------|
| `proposed` | Agent has submitted a structured action request. EP has not yet evaluated. |
| `denied` | Policy evaluation returned `deny`. Action is blocked. Not committed. |
| `pending_approval` | Policy evaluation returned `require_approval`. Waiting for human decision. |
| `authorized` | Policy evaluation returned `allow` or `warn`, or human approved a `require_approval`. EP issues a signed short-lived authorization token. |
| `expired` | Authorization token expired before execution. Agent must re-request. |
| `cancelled` | Agent explicitly cancelled the proposal before execution. |
| `executing` | Proxy is running the action. |
| `succeeded` | Action completed successfully. Node becomes committed active state. |
| `failed` | Action execution failed. Node does not become committed. Agent may retry or propose alternative. |

### 5.2 Authorization Token

When a transition is authorized, EP issues a signed token:

```json
{
  "token_id": "cjvbbzh6qgtnoxiaa002",
  "transition_id": "cjvbbzh6qgtnoxiaa003",
  "agent_id": "cjvbbzh6qgtnoxiaa004",
  "project_id": "cjvbbzh6qgtnoxiaa005",
  "branch_id": "cjvbbzh6qgtnoxiaa006",
  "tool": "postgres.execute",
  "payload_hash": "sha256:abc123...",
  "issued_at": "2026-07-28T12:00:00Z",
  "expires_at": "2026-07-28T12:05:00Z",
  "signature": " HMAC-SHA256..."
}
```

Properties:
- **Short-lived**: default 5-minute expiry. Configurable per policy.
- **Payload-bound**: the proxy verifies that the executed payload hash matches the authorized payload hash. The agent cannot swap the action.
- **Single-use**: each token is valid for one execution attempt.
- **Signed**: HMAC-SHA256 with a key known only to EP and the proxy (not the agent).

### 5.3 Idempotency

Each proposal includes an idempotency key (client-generated XID). If the same key is submitted twice:

- If the first is still `proposed` or `authorized`: return the existing transition.
- If the first is `executing` or `succeeded`: return the existing result without re-executing.
- If the first is `failed` or `cancelled` or `expired`: allow a new proposal.

### 5.4 Stale Authorization Detection

If relevant policies change between authorization and execution:

- The proxy checks the policy version before executing.
- If the policy version has advanced since authorization, the token is invalidated. The transition moves to `expired`. The agent must re-request.
- This prevents an agent from obtaining authorization and then waiting for a policy change before executing.

---

## 6. Authorization and Roles

### 6.1 Principals and Roles

| Entity | Description |
|--------|-------------|
| `ep_principals` | Authenticated identities: agents and humans |
| `ep_roles` | Role definitions |
| `ep_role_bindings` | Principal-to-role mappings |
| `ep_credentials` | Authentication credentials (API keys, tokens) |
| `ep_approval_requests` | Pending human approval requests |
| `ep_approval_decisions` | Recorded human decisions |

### 6.2 Roles

| Role | Permissions |
|------|------------|
| `observer` | Read policies, transitions, state. Cannot propose actions or modify policies. |
| `agent` | Propose actions. Read policies and state. Cannot create/retire/supersede policies. |
| `policy_author` | Everything `agent` can do, plus create/retire/supersede agent-scoped policies. |
| `policy_approver` | Everything `policy_author` can do, plus approve/deny `require_approval` requests and create/retire global policies (with human co-approval). |
| `operator` | Everything `policy_approver` can do, plus repair quarantines and manage branches. |
| `auditor` | Read-only access to everything including audit logs and approval history. |
| `administrator` | Full access including agent registration, credential management, and lattice creation. |

### 6.3 Agent Registration

Agents do not self-register in production. Registration requires:

1. An enrollment token issued by an administrator.
2. Or direct database insertion by an administrator.

In development mode (`EP_MODE=advisory`, `EP_DEV=true`), self-registration is permitted for convenience.

### 6.4 Override Authority

Overrides are scoped, justified, time-limited, and audited:

- A `deny` policy can be overridden only by a `policy_approver` or `administrator`.
- The override must include a justification string.
- The override is time-limited (default 1 hour).
- The override is logged to the audit trail with the principal, justification, and expiry.
- Global invariants require human approval to override. Agent-scoped policies can be overridden by the agent's `policy_author`.

---

## 7. Graph Model

### 7.1 Precise Definition

EP-Governance maintains a **persistent directed acyclic state graph (DAG)** with inherited policies and transactional transitions.

- **Nodes** represent states of a project at a point in time.
- **Edges** (dependency struts) are directed from upstream to downstream, tracing decision lineage.
- **Invariants** (policies) are attached to the graph and evaluated against proposed transitions.
- The graph is acyclic: edges that would create a cycle are rejected.

### 7.2 First-Class Entities

```
ep_lattices        -- one per project
ep_projects        -- logical project (e.g., "NAS migration", "OpenCut rewrite")
ep_branches        -- parallel work streams within a project
ep_sessions        -- agent sessions (connects an agent to a branch)
ep_branch_heads    -- current active node per branch (optimistic concurrency)
ep_policy_versions -- versioned policy sets for stale-authorization detection
```

### 7.3 Active State

Active state is keyed by `(project_id, branch_id)`, not by agent. Multiple agents can work on the same branch. An agent session points to the branch it is working on.

### 7.4 Branching

Two agents may produce parallel admissible transitions from the same parent:

1. Agent A proposes a transition from node N.
2. Agent B proposes a transition from node N.
3. Both are evaluated against the policies active at N.
4. Both may be authorized and committed, creating two children of N.
5. This is a branch, not a conflict.
6. A merge operation can reconcile branches when needed.

### 7.5 Optimistic Concurrency

Each branch has a `head_node_id` and a `version` counter:

- When an agent proposes a transition, it includes `expected_head_id` and `expected_version`.
- The transaction succeeds only if the current head matches both.
- If another agent committed a transition in the meantime, the version has advanced. The proposal fails with `stale_head`. The agent re-reads the branch state and retries.

### 7.6 Cycle Prevention

Before inserting an edge, the system checks whether the edge would create a cycle by performing a forward BFS from the downstream node. If the upstream node is reachable, the edge is rejected.

---

## 8. Verification Pulse

### 8.1 Backward Pulse (Extended from Reference)

```
INPUT: proposed_node, classified_action, branch_id, project_id
OUTPUT: admissible (bool), violations (list), denied (list), warnings (list)

1. Initialize visited = {}, queue = [(proposed_node, 0)]
2. violations = [], denied = [], warnings = []

3. Collect applicable policies:
   a. All active policies with scope=global
   b. All active policies with scope=agent and agent_id matches
   c. Filter by actions matching classified_action.type
   d. Filter by resources matching classified_action.target
   e. Only policies with matching action+resource selectors are evaluated

4. WHILE queue is not empty:
   a. Pop (current_node, depth) from queue
   b. Log: "Pulse depth {depth} -> Checking node {current_node.id}"

   c. FOR each applicable policy:
      i. If policy is superseded or retired: SKIP
      ii. Evaluate conditions against current_node context + action context
      iii. If conditions match and effect=deny:
         - Record: {policy_id, node_id, depth, effect}
         - Add to denied list
      iv. If conditions match and effect=warn:
         - Record: {policy_id, node_id, depth, effect}
         - Add to warnings list
      v. If conditions match and effect=require_approval:
         - Record: {policy_id, node_id, depth, effect}
         - Add to violations list (pending approval)

   d. FOR each dependency edge from current_node:
      i. If upstream_node_id not in visited:
         - Add to visited
         - If upstream_node exists and status not in ('quarantined', 'revoked'):
            - Append (upstream_node, depth+1) to queue

5. IF denied list is non-empty:
   a. RETURN: admissible=False, denied, warnings, violations
   b. Transition is denied (not committed, not quarantined -- it never entered the graph)

6. IF violations (pending approval) and no denied:
   a. RETURN: admissible=False, [], warnings, violations
   b. Transition is pending_approval (create approval request, wait)

7. IF only warnings and no denied and no pending:
   a. RETURN: admissible=True, [], warnings, []
   b. Transition proceeds with logged warnings

8. IF no violations at all:
   a. RETURN: admissible=True, [], [], []
```

### 8.2 Forward Blast Radius (for discovered violations, not denied proposals)

Forward blast radius applies only when an **existing committed state** is found to be unsafe -- not when a proposed action is denied. A denied proposal never entered the graph; there is nothing to quarantine.

```
INPUT: violated_node_ids (existing committed nodes found unsafe)
OUTPUT: at_risk_node_ids

1. at_risk = {}
2. queue = violated_node_ids

3. WHILE queue is not empty:
   a. Pop node_id from queue
   b. Find all edges where upstream_node_id = node_id
   c. FOR each edge:
      i. downstream_id = edge.downstream_node_id
      ii. If downstream_id not in at_risk:
         - Add to at_risk
         - Mark node status as 'at_risk'
         - Append downstream_id to queue

4. RETURN: list(at_risk)
```

### 8.3 Quarantine vs Denial

| Result | When | Graph Effect |
|--------|------|-------------|
| `denied` | Proposed action violates a `deny` policy before execution | Nothing enters the graph. Proposal is logged. No quarantine. |
| `pending_approval` | Proposed action requires human approval | Nothing enters the graph. Approval request created. |
| `quarantined` | An existing committed state is later found unsafe | Existing node is marked quarantined. Forward blast radius computed. Downstream nodes marked at_risk. |
| `at_risk` | Downstream of a quarantined node | Node is marked at_risk. Agent is notified. Review needed. |
| `revoked` | Prior authorization is no longer valid (policy changed) | The authorized transition is moved to expired. Agent must re-request. |

### 8.4 Tension Detection (Revised)

True policy conflicts are identified through:

- Two active policies with the same `actions` and `resources` but conflicting `effects` (e.g., one says `deny`, one says `allow`) at the same priority.
- Incompatible `conditions` that cannot be simultaneously satisfied.
- Conflicting obligations (one policy requires action A, another prohibits action A).

Tension is checked at policy creation time, not at action proposal time. If a new policy creates a tension with an existing one, the system reports it and requires resolution (adjust priority, retire one, or add scoping to differentiate).

The pairwise simulation method from v1.0 is removed. It produced false positives.

---

## 9. BT and UT Resources

### 9.1 BT (Planning Budget)

BT is a planning and accounting mechanism, not an enforceable compute quota. It tracks the agent's remaining capacity for complex operations within a project branch.

- **Initial value**: configurable per project (default 100.0).
- **Consumed by**: transitions (amount varies by action category).
- **Replenished by**: explicit project configuration or operator action.
- **Behavior when exhausted**: transition is rejected with `resource_exhausted`. Agent must request a budget increase or reduce scope.
- **Does not** actually limit CPU, tokens, disk, or API calls outside EP.

Renamed from "compute budget" to "planning budget" to avoid implying infrastructure enforcement.

### 9.2 UT (Risk Ledger)

UT is not a single global number. It is a scoped risk ledger per risk domain:

| Risk Domain | Description |
|-------------|-------------|
| `production_database` | Actions affecting production databases |
| `external_communications` | Email, Slack, public posts |
| `deployment` | Container, server, infrastructure changes |
| `data_privacy` | Actions involving PII or sensitive data |
| `security` | Authentication, authorization, credential changes |

Each risk domain tracks:

| Field | Description |
|-------|-------------|
| `inherent_risk` | Base risk level for this domain (configured) |
| `mitigations` | Applied mitigations (e.g., "backup verified", "audit completed") |
| `residual_risk` | inherent_risk - sum(mitigation credits) |
| `required_approval_level` | What level of approval is needed for this risk domain |
| `accepted_by` | Who accepted the residual risk |
| `accepted_at` | When |
| `expiration` | When the acceptance expires |

An action is blocked in a risk domain if `residual_risk` exceeds the threshold for that domain, unless an approval is on record.

A database backup does not replenish `external_communications` risk capacity. Risk credits are domain-scoped, not fungible.

---

## 10. Action Classification

### 10.1 Server-Side Classification

The agent submits a structured tool call:

```json
{
  "tool": "postgres.execute",
  "arguments": {
    "database": "gbrain_pilot",
    "statement": "DROP TABLE memory_items"
  }
}
```

EP-Governance classifies it server-side:

| Tool | Classification Method |
|------|----------------------|
| `postgres.execute` | Parse SQL AST: operation type (SELECT/INSERT/UPDATE/DELETE/DROP), target objects |
| `shell.execute` | Parse command: executable, flags, arguments |
| `email.send` | Inspect: recipients, subject, attachment presence |
| `docker.*` | Parse Docker command: stop/start/rm/exec/build, target container |
| `http.request` | Evaluate: method (GET/POST/PUT/DELETE), host, path |
| `git.*` | Parse git command: push/reset/merge/force-push |
| `file.write` | Inspect: target path, write mode (create/overwrite/append) |

### 10.2 Classification Result

```json
{
  "action_type": "db.drop",
  "target": "db:gbrain_pilot/table:memory_items",
  "risk_domain": "production_database",
  "bt_cost": 5.0,
  "ut_cost": 15.0,
  "classification_confidence": "high",
  "classification_method": "sql_ast_parse"
}
```

Agent-supplied categories are accepted as hints but always overridden by server-side classification when available.

### 10.3 Action Categories

| Category | Default BT Cost | Default UT Cost | Risk Domain |
|----------|----------------|-----------------|-------------|
| `file.delete` | 5.0 | 15.0 | deployment |
| `db.delete` | 5.0 | 15.0 | production_database |
| `db.drop` | 8.0 | 25.0 | production_database |
| `db.insert` | 3.0 | 5.0 | production_database |
| `db.update` | 3.0 | 10.0 | production_database |
| `shell.exec` | 8.0 | 20.0 | deployment |
| `email.send` | 3.0 | 5.0 | external_communications |
| `deployment` | 10.0 | 25.0 | deployment |
| `code.execution` | 5.0 | 15.0 | security |
| `git.mutation` | 5.0 | 10.0 | deployment |
| `file.write` | 2.0 | 3.0 | deployment |
| `http.post` | 2.0 | 5.0 | external_communications |
| `read.only` | 0.5 | 0.0 | (none) |
| `nats.publish` | 1.0 | 1.0 | external_communications |
| `mcp.tool_call` | 1.0 | 1.0 | (depends on tool) |

---

## 11. Database Schema

### 11.1 Database Support

- **PostgreSQL**: Production backend. Required for multi-agent, cross-machine, LISTEN/NOTIFY, row-level locking, pgvector (optional embeddings).
- **SQLite**: Development only. Single-agent, single-machine. No cross-machine support. No LISTEN/NOTIFY. WAL mode for concurrent reads. Documented limitations.

Separate migration directories:

```
migrations/postgres/001_init.sql
migrations/sqlite/001_init.sql
```

### 11.2 Tables

#### Core Graph

**ep_lattices**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT (XID) | Primary key |
| project_id | TEXT (XID) | FK to ep_projects |
| name | TEXT | Lattice name |
| created_at | TIMESTAMPTZ | Creation timestamp |

**ep_projects**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT (XID) | Primary key |
| name | TEXT | Project name |
| description | TEXT | Project description |
| status | TEXT | 'active', 'completed', 'archived' |
| created_at | TIMESTAMPTZ | Creation timestamp |

**ep_branches**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT (XID) | Primary key |
| lattice_id | TEXT (XID) | FK to ep_lattices |
| name | TEXT | Branch name |
| head_node_id | TEXT (XID) | FK to ep_nodes (current head) |
| version | INTEGER | Optimistic concurrency version counter |
| status | TEXT | 'active', 'merged', 'abandoned' |
| created_at | TIMESTAMPTZ | Creation timestamp |

**ep_nodes**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT (XID) | Primary key |
| branch_id | TEXT (XID) | FK to ep_branches |
| agent_id | TEXT (XID) | FK to ep_principals |
| description | TEXT | What this state represents |
| bt_planning_budget | FLOAT | Planning budget at this state |
| metadata | JSONB | Arbitrary state data |
| status | TEXT | 'proposed', 'authorized', 'executing', 'succeeded', 'failed', 'cancelled', 'expired', 'denied', 'quarantined', 'at_risk', 'revoked' |
| created_at | TIMESTAMPTZ | Creation timestamp |
| committed_at | TIMESTAMPTZ | When execution succeeded (nullable) |

CHECK constraint: `bt_planning_budget >= 0`

**ep_edges**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT (XID) | Primary key |
| upstream_node_id | TEXT (XID) | FK to ep_nodes |
| downstream_node_id | TEXT (XID) | FK to ep_nodes |
| edge_type | TEXT | 'dependency', 'establishes', 'requires', 'conflicts_with' |
| weight | FLOAT | Edge strength (default 1.0) |
| created_at | TIMESTAMPTZ | Creation timestamp |

CHECK constraint: `upstream_node_id <> downstream_node_id`

Indexes:
```sql
CREATE INDEX ep_edges_downstream_idx ON ep_edges(downstream_node_id);
CREATE INDEX ep_edges_upstream_idx ON ep_edges(upstream_node_id);
```

#### Policies

**ep_policies**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT (XID) | Primary key |
| agent_id | TEXT (XID) | FK to ep_principals (who created this policy) |
| scope | TEXT | 'global' or 'agent' |
| agent_scope | TEXT (XID) | FK to ep_principals (if scope=agent) |
| effect | TEXT | 'deny', 'require_approval', 'warn', 'allow' |
| actions | JSONB | Array of action type selectors |
| resources | JSONB | Array of resource selectors (glob patterns) |
| conditions | JSONB | Deterministic condition expressions |
| priority | INTEGER | Conflict resolution order (higher wins) |
| description | TEXT | Human-readable explanation |
| status | TEXT | 'active', 'superseded', 'retired' |
| supersedes | TEXT (XID) | FK to ep_policies (nullable) |
| policy_version | INTEGER | Version of the policy set this belongs to |
| established_at | TIMESTAMPTZ | When activated |
| retired_at | TIMESTAMPTZ | When retired (nullable) |

CHECK constraint: `effect IN ('deny', 'require_approval', 'warn', 'allow')`
CHECK constraint: `scope IN ('global', 'agent')`
CHECK constraint: `priority >= 0`

Indexes:
```sql
CREATE INDEX ep_policies_active_scope_idx ON ep_policies(status, scope, agent_scope);
CREATE INDEX ep_policies_actions_idx ON ep_policies USING gin (actions);
```

**ep_policy_versions**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT (XID) | Primary key |
| version | INTEGER | Monotonically increasing version number |
| branch_id | TEXT (XID) | FK to ep_branches |
| policy_count | INTEGER | Number of active policies in this version |
| created_at | TIMESTAMPTZ | When this version was created |

#### Transitions and Authorizations

**ep_transitions**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT (XID) | Primary key |
| agent_id | TEXT (XID) | FK to ep_principals |
| branch_id | TEXT (XID) | FK to ep_branches |
| from_node_id | TEXT (XID) | FK to ep_nodes (parent) |
| to_node_id | TEXT (XID) | FK to ep_nodes (proposed, nullable if denied) |
| tool | TEXT | Tool name (e.g., 'postgres.execute') |
| arguments | JSONB | Canonical action payload |
| payload_hash | TEXT | SHA-256 hash of canonical arguments |
| classification | JSONB | Server-side classification result |
| bt_delta | FLOAT | Planning budget change |
| ut_deltas | JSONB | Per-risk-domain UT changes |
| verification_result | TEXT | 'admissible', 'denied', 'pending_approval', 'resource_exhausted' |
| pulse_trace | JSONB | Full verification trace |
| matched_policies | JSONB | Policies that matched |
| stage | TEXT | Lifecycle stage: 'proposed', 'authorized', 'executing', 'succeeded', 'failed', 'cancelled', 'expired', 'denied' |
| expected_head_id | TEXT (XID) | Optimistic concurrency check |
| expected_version | INTEGER | Optimistic concurrency check |
| idempotency_key | TEXT (XID) | Client-generated dedup key |
| executor_id | TEXT (XID) | FK to ep_principals (proxy identity, nullable) |
| execution_started_at | TIMESTAMPTZ | When proxy started executing (nullable) |
| execution_completed_at | TIMESTAMPTZ | When proxy finished (nullable) |
| exit_status | TEXT | 'success', 'failure', 'timeout' (nullable) |
| result_summary | TEXT | Execution result (nullable) |
| created_at | TIMESTAMPTZ | When proposed |

CHECK constraint: `stage IN ('proposed', 'authorized', 'executing', 'succeeded', 'failed', 'cancelled', 'expired', 'denied')`

Indexes:
```sql
CREATE INDEX ep_transitions_agent_created_idx ON ep_transitions(agent_id, created_at DESC);
CREATE INDEX ep_transitions_branch_idx ON ep_transitions(branch_id, created_at DESC);
CREATE INDEX ep_transitions_result_idx ON ep_transitions(verification_result);
CREATE UNIQUE INDEX ep_transitions_idempotency_idx ON ep_transitions(idempotency_key);
```

**ep_authorizations**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT (XID) | Primary key |
| transition_id | TEXT (XID) | FK to ep_transitions |
| token_hash | TEXT | Hash of the signed token (not the token itself) |
| payload_hash | TEXT | Hash of the authorized payload (must match on execution) |
| policy_version | INTEGER | Policy version at authorization time (for stale detection) |
| issued_at | TIMESTAMPTZ | When token was issued |
| expires_at | TIMESTAMPTZ | When token expires |
| used | BOOLEAN | Whether this token has been used (single-use) |
| used_at | TIMESTAMPTZ | When it was used (nullable) |

#### Risk Ledger

**ep_risk_ledger**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT (XID) | Primary key |
| branch_id | TEXT (XID) | FK to ep_branches |
| risk_domain | TEXT | 'production_database', 'external_communications', 'deployment', 'data_privacy', 'security' |
| inherent_risk | FLOAT | Base risk level |
| residual_risk | FLOAT | Current residual risk |
| required_approval_level | TEXT | 'none', 'agent', 'policy_approver', 'human' |
| accepted_by | TEXT (XID) | FK to ep_principals (nullable) |
| accepted_at | TIMESTAMPTZ | When risk was accepted (nullable) |
| expiration | TIMESTAMPTZ | When acceptance expires (nullable) |
| updated_at | TIMESTAMPTZ | Last update |

**ep_risk_mitigations**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT (XID) | Primary key |
| risk_ledger_id | TEXT (XID) | FK to ep_risk_ledger |
| mitigation_type | TEXT | 'backup_verified', 'audit_completed', 'test_passed', etc. |
| credit | FLOAT | Risk reduction amount |
| evidence | TEXT | What proves this mitigation |
| applied_at | TIMESTAMPTZ | When the mitigation was applied |

#### Identity and Authorization

**ep_principals**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT (XID) | Primary key |
| name | TEXT | Display name |
| type | TEXT | 'agent' or 'human' |
| machine | TEXT | Hostname (for agents) |
| description | TEXT | What this principal is |
| status | TEXT | 'active', 'suspended', 'revoked' |
| registered_at | TIMESTAMPTZ | Registration timestamp |

**ep_roles**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT (XID) | Primary key |
| name | TEXT | Role name (observer, agent, policy_author, etc.) |
| permissions | JSONB | List of permissions |

**ep_role_bindings**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT (XID) | Primary key |
| principal_id | TEXT (XID) | FK to ep_principals |
| role_id | TEXT (XID) | FK to ep_roles |
| project_id | TEXT (XID) | FK to ep_projects (nullable = global) |
| bound_at | TIMESTAMPTZ | When this binding was created |

**ep_credentials**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT (XID) | Primary key |
| principal_id | TEXT (XID) | FK to ep_principals |
| credential_type | TEXT | 'api_key', 'enrollment_token', 'tls_cert' |
| credential_hash | TEXT | Hash of the credential (never store the credential itself) |
| expires_at | TIMESTAMPTZ | When this credential expires |
| created_at | TIMESTAMPTZ | When this credential was issued |

#### Approvals and Overrides

**ep_approval_requests**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT (XID) | Primary key |
| transition_id | TEXT (XID) | FK to ep_transitions |
| policy_id | TEXT (XID) | FK to ep_policies (which policy triggered the approval) |
| requested_by | TEXT (XID) | FK to ep_principals |
| justification | TEXT | Why this action should be approved |
| status | TEXT | 'pending', 'approved', 'denied', 'expired' |
| created_at | TIMESTAMPTZ | When requested |
| decided_at | TIMESTAMPTZ | When decided (nullable) |

**ep_approval_decisions**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT (XID) | Primary key |
| approval_request_id | TEXT (XID) | FK to ep_approval_requests |
| decided_by | TEXT (XID) | FK to ep_principals |
| decision | TEXT | 'approved' or 'denied' |
| reason | TEXT | Justification for the decision |
| decided_at | TIMESTAMPTZ | When decided |

**ep_override_records**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT (XID) | Primary key |
| policy_id | TEXT (XID) | FK to ep_policies (which policy was overridden) |
| transition_id | TEXT (XID) | FK to ep_transitions (which transition) |
| overridden_by | TEXT (XID) | FK to ep_principals |
| justification | TEXT | Why the override was granted |
| expires_at | TIMESTAMPTZ | When the override expires |
| created_at | TIMESTAMPTZ | When the override was recorded |

#### Audit

**ep_events** (append-only, hash-chained)

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT (XID) | Primary key |
| sequence | BIGINT | Monotonically increasing sequence number |
| event_type | TEXT | 'transition_proposed', 'transition_authorized', 'transition_executed', 'policy_created', 'policy_retired', 'quarantine_declared', 'override_granted', etc. |
| event_data | JSONB | Canonical event payload |
| previous_hash | TEXT | Hash of the previous event (hash chain) |
| event_hash | TEXT | SHA-256(event_data || previous_hash) |
| principal_id | TEXT (XID) | FK to ep_principals (who triggered this event) |
| created_at | TIMESTAMPTZ | When this event occurred |

Index: `CREATE UNIQUE INDEX ep_events_sequence_idx ON ep_events(sequence);`

The audit log uses a restricted database role. Agents and proxies can INSERT into ep_events but cannot UPDATE or DELETE. The hash chain allows detection of tampering.

#### Work Management

**ep_work_claims**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT (XID) | Primary key |
| agent_id | TEXT (XID) | FK to ep_principals |
| branch_id | TEXT (XID) | FK to ep_branches |
| region | TEXT | Problem region name |
| status | TEXT | 'active', 'completed', 'released' |
| claimed_at | TIMESTAMPTZ | When claimed |
| released_at | TIMESTAMPTZ | When released (nullable) |

Unique constraint: one active claim per (branch_id, region) at a time.

#### Transfer Packages

**ep_transfer_packages**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT (XID) | Primary key |
| lattice_id | TEXT (XID) | FK to ep_lattices |
| schema_version | TEXT | Schema version at export time |
| package_version | TEXT | Transfer package format version |
| source_lattice_id | TEXT (XID) | XID of the source lattice |
| project_id | TEXT (XID) | FK to ep_projects |
| snapshot_sequence | INTEGER | Monotonic snapshot number for this lattice |
| content_hash | TEXT | SHA-256 hash of the lattice_state JSON |
| signature | TEXT | Digital signature of the content_hash |
| signer_id | TEXT (XID) | FK to ep_principals (who signed it) |
| trust_status | TEXT | 'trusted', 'untrusted', 'imported' |
| lattice_state | JSONB | Full serialized lattice: nodes, edges, policies, risk ledger, active state |
| model_info | TEXT | LLM model running at export (audit trail) |
| created_at | TIMESTAMPTZ | When the export was created |

#### Sessions

**ep_sessions**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT (XID) | Primary key |
| agent_id | TEXT (XID) | FK to ep_principals |
| branch_id | TEXT (XID) | FK to ep_branches |
| model_info | TEXT | LLM model identifier |
| started_at | TIMESTAMPTZ | When the session started |
| ended_at | TIMESTAMPTZ | When the session ended (nullable) |

#### Embeddings (optional, Postgres with pgvector)

**ep_policy_embeddings**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT (XID) | Primary key |
| policy_id | TEXT (XID) | FK to ep_policies |
| embedding | VECTOR(dim) | Embedding vector (dimension configured at install) |
| model_name | TEXT | Which embedding model produced this |
| source_text_hash | TEXT | Hash of the text that was embedded |
| distance_metric | TEXT | 'cosine' (default) |
| created_at | TIMESTAMPTZ | When the embedding was generated |

One active embedding model per deployment. When the model changes, re-embed all active policies. Old embeddings are retained for audit but marked as superseded.

---

## 12. Transfer Package

### 12.1 Three Operations

| Operation | Description |
|-----------|-------------|
| **Resume** | Connect a new model to the existing database. No import needed. The new model reads the same graph. |
| **Export snapshot** | Create a portable, immutable, signed snapshot of the lattice state. |
| **Import/fork** | Create a new lattice or project from a snapshot. Never import blindly into the authoritative live lattice. |

### 12.2 Export

`ep-governance export --project <id> --branch <id> > transfer.json`

Produces a JSON document containing:
- Schema version
- Package version
- Source lattice ID
- Project ID
- Snapshot sequence
- Timestamp
- Content hash (SHA-256 of the lattice_state JSON)
- Digital signature (signed by the exporting principal)
- Signer identity
- Trust status
- Lattice state: all nodes, edges, active policies, risk ledger, branch heads, policy versions

### 12.3 Import/Fork

`ep-governance import transfer.json --project-name "OpenCut rewrite fork"`

Creates a **new** lattice and project from the snapshot:
- Generates new XIDs for all imported entities (no ID collision)
- Marks all imported policies with trust_status='imported'
- Imported policies are active but the importer can review and retire them
- The original lattice is untouched

### 12.4 Resume

`ep-governance resume --project <id> --branch <id>`

Connects the current model to the existing database. No export/import needed. The model reads the current graph state, loads active policies, and begins operating. This is the normal case for model switching when the database is shared.

---

## 13. Notifications

### 13.1 PostgreSQL LISTEN/NOTIFY

When a transition is committed, a policy is created, or a quarantine is declared:

```sql
NOTIFY ep_state_changed, '{"branch_id": "...", "event": "transition_committed"}';
NOTIFY ep_policy_changed, '{"branch_id": "...", "policy_version": 42}';
```

Agents subscribe to these channels and re-read authoritative state from the database on notification.

### 13.2 NATS (optional)

For cross-machine agents that don't share the same database connection:

- Publish to `ep-governance.events` subject
- Notifications are hints, not authoritative. Agents must always re-read state from the database.

### 13.3 Implementation Priority

1. PostgreSQL LISTEN/NOTIFY (implemented first)
2. NATS (added only after demonstrated need)

---

## 14. XID Implementation

### 14.1 Python Generator (ep_governance/xid.py)

A clean Python implementation of the rs/xid format. No external dependency on the broken PyPI xid package.

**Format:** 12 bytes -> 20-char lowercase base32hex string
- Bytes 0-3: timestamp (seconds since epoch, big-endian)
- Bytes 4-6: machine ID (MD5 hash of hostname, first 3 bytes)
- Bytes 7-8: PID (big-endian)
- Bytes 9-11: counter (thread-safe incrementing, big-endian)

**Properties:**
- Probabilistically unique (not guaranteed)
- Time-sortable (lexicographic order approximates chronological order)
- No central coordinator needed
- 20 chars (vs 36 for UUID)

### 14.2 Collision Handling

On primary-key violation during INSERT, the system retries with a new XID (up to 3 attempts). If all attempts collide, the operation fails with an error.

### 14.3 Fork Safety

On process fork, the child process re-seeds the counter with a random value to avoid generating the same XIDs as the parent.

### 14.4 Clock Rollback

If the current time is less than the last-used timestamp, the system uses the last-used timestamp + 1 instead. This maintains monotonicity.

### 14.5 Consistency

The Python XID generator is the sole source of truth for ID generation. The database stores XIDs as TEXT. No server-side ID generation. Every insert provides its own XID from the Python generator.

---

## 15. Configuration

### 15.1 .env File

```env
# Operating mode
EP_MODE=enforced
# EP_MODE=advisory

# Database
EP_DB_URL=postgresql://user:pass@host:5433/dbname
# EP_DB_URL=sqlite:///path/to/ep-governance.db

# Embeddings (optional, for policy authoring assistance only)
EP_EMBEDDING_PROVIDER=ollama
EP_EMBEDDING_MODEL=bge-m3
EP_EMBEDDING_HOST=localhost:11434
# EP_EMBEDDING_PROVIDER=openai
# EP_EMBEDDING_API_KEY=sk-...
# EP_EMBEDDING_PROVIDER=none

# MCP transport
EP_MCP_TRANSPORT=stdio
# EP_MCP_TRANSPORT=http
# EP_MCP_PORT=8200

# Notifications
EP_NOTIFY=native
# EP_NOTIFY=nats
# EP_NATS_URL=nats://host:4222
# EP_NOTIFY=none

# Authorization token
EP_TOKEN_TTL_SECONDS=300
EP_TOKEN_SIGNING_KEY=<random-64-char-hex>

# HTTP MCP security (when EP_MCP_TRANSPORT=http)
# EP_MCP_TLS_CERT=/path/to/cert.pem
# EP_MCP_TLS_KEY=/path/to/key.pem
# EP_MCP_ALLOWED_HOSTS=100.96.163.59,127.0.0.1

# Development
# EP_DEV=true  (enables self-registration, advisory mode)
```

### 15.2 Secret Management

EP-Governance does not store operational target credentials (SSH keys, database passwords, email credentials) in its database or transfer packages. These belong to the governed proxy.

Service credentials required by EP-Governance itself (database URL, embedding API key, token signing key) are supplied through environment variables or an external secret manager. The `.env` file should have mode 0600. For production, recommend a secret manager or OS credential store rather than a repository-adjacent `.env`.

---

## 16. Governed Proxy

### 16.1 Purpose

In enforced mode, the governed proxy is the only path to consequential infrastructure. It holds the credentials. Agents request authorization from EP, receive a signed token, and send the token + payload to the proxy. The proxy validates the token, verifies the payload hash, executes using its own credentials, and records the result.

### 16.2 Proxy Architecture

```
Agent -> EP authorization request -> EP returns signed token
Agent -> Proxy: token + payload
Proxy -> Validate token (check signature, expiry, used flag, payload hash)
Proxy -> Check policy version (stale authorization detection)
Proxy -> Execute using proxy credentials
Proxy -> Record result to EP (succeeded/failed)
EP -> Update transition lifecycle
```

### 16.3 Supported Tool Wrappers (Phase 5+)

| Wrapper | What It Governs |
|---------|-----------------|
| `shell.proxy` | SSH commands, local shell execution |
| `postgres.proxy` | SQL execution against specified databases |
| `email.proxy` | Email sending with recipient validation |
| `docker.proxy` | Container management (stop/start/rm/exec) |
| `git.proxy` | Git operations (push/reset/merge) |

Each wrapper classifies the action server-side, obtains authorization, and executes through the proxy.

### 16.4 HTTP MCP Security

When the MCP server uses HTTP transport:

- Bind to private interface (Tailscale IP or localhost)
- Use TLS (certificate configured in .env)
- Per-agent credentials (API key per principal)
- Request IDs and idempotency keys
- Payload size limits
- Secret redaction in logs
- Rate limiting on mutation operations

---

## 17. CLI Interface

### 17.1 Commands

```
# Setup
ep-governance init                              # create database schema, write .env template
ep-governance register --name "Mary Wise" --type agent --enrollment-token <token>
ep-governance register --name "Skip Potter" --type human   # admin registration

# Project and branch management
ep-governance create-project "NAS Migration" --description "Migrating GBrain to NAS"
ep-governance create-branch --project <id> --name "main"
ep-governance create-branch --project <id> --name "experimental" --from-branch main

# Policy management
ep-governance add-policy --effect deny \
    --actions '["db.drop", "db.delete"]' \
    --resources '["db:gbrain_pilot/**"]' \
    --description "Never delete production gbrain_pilot data" \
    --scope global --priority 100

ep-governance list-policies                      # list all active policies
ep-governance list-policies --agent <xid>        # list policies for a specific agent
ep-governance retire-policy <xid>               # retire a policy
ep-governance supersede-policy <old_xid> --effect warn --description "Relaxed rule"

# Pre-action check (advisory mode)
ep-governance check --tool postgres.execute \
    --arguments '{"database": "gbrain_pilot", "statement": "SELECT 1"}'

# Governed execution (enforced mode)
ep-governance execute --tool shell.exec \
    --arguments '{"command": "docker stop open-webui", "host": "cloudhub"}'

# State and audit
ep-governance status                             # current branch head, BT, UT per domain, policy count
ep-governance log                                # recent transitions
ep-governance log --agent <xid>                  # transitions by a specific agent
ep-governance log --violations                  # only denials, quarantines, and overrides
ep-governance audit                             # hash-chained event log

# Work management
ep-governance claim "database-migration" --branch <id>
ep-governance release-claim <xid>
ep-governance claims                             # list active work claims

# Approvals
ep-governance pending-approvals                 # list pending approval requests
ep-governance approve <xid> --reason "Authorized for maintenance window"
ep-governance deny <xid> --reason "Outside maintenance window"

# Transfer
ep-governance export --project <id> --branch <id> > transfer.json
ep-governance import transfer.json --project-name "OpenCut rewrite fork"
ep-governance resume --project <id> --branch <id>

# MCP server
ep-governance serve                              # stdio transport
ep-governance serve --http --port 8200           # HTTP transport
```

### 17.2 Check Output (Advisory Mode)

When admissible:

```json
{
  "result": "admissible",
  "transition_id": "cjvbbzh6qgtnoxiaaabc",
  "classification": {
    "action_type": "db.select",
    "target": "db:gbrain_pilot",
    "risk_domain": "production_database",
    "bt_cost": 0.5,
    "ut_cost": 0.0
  },
  "bt_after": 95.5,
  "warnings": []
}
```

When denied:

```json
{
  "result": "denied",
  "transition_id": "cjvbbzh6qgtnoxiaaabd",
  "classification": {
    "action_type": "db.drop",
    "target": "db:gbrain_pilot/table:memory_items",
    "risk_domain": "production_database",
    "bt_cost": 8.0,
    "ut_cost": 25.0
  },
  "denied_policies": [
    {
      "policy_id": "cjvb9...",
      "description": "Never delete production gbrain_pilot data",
      "effect": "deny",
      "priority": 100,
      "pulse_depth": 3
    }
  ],
  "message": "Proposed action denied by policy 'Never delete production gbrain_pilot data'."
}
```

### 17.3 Execute Output (Enforced Mode)

```json
{
  "result": "succeeded",
  "transition_id": "cjvbbzh6qgtnoxiaaabe",
  "authorization_id": "cjvbbzh6qgtnoxiaaabf",
  "classification": {
    "action_type": "shell.exec",
    "target": "host:cloudhub",
    "risk_domain": "deployment"
  },
  "execution": {
    "exit_status": "success",
    "result_summary": "docker stop open-webui completed",
    "started_at": "2026-07-28T12:00:00Z",
    "completed_at": "2026-07-28T12:00:02Z"
  },
  "bt_after": 90.0,
  "ut_after": {
    "deployment": 55.0,
    "production_database": 70.0
  }
}
```

---

## 18. MCP Server

### 18.1 Tools

| Tool | Description |
|------|-------------|
| `ep_check` | Evaluate a proposed action without executing. Returns admissible/denied/pending. |
| `ep_execute` | Request authorization and execute through the governed proxy. (Enforced mode only.) |
| `ep_add_policy` | Create a new policy. Requires policy_author role or higher. |
| `ep_list_policies` | List active policies. Optional agent filter. |
| `ep_retire_policy` | Retire a policy. Requires policy_author role or higher. |
| `ep_supersede_policy` | Supersede a policy with a new one. |
| `ep_status` | Current branch head, BT, UT per domain, policy count, quarantine count. |
| `ep_log` | Transition history. Optional filters: agent, violations only. |
| `ep_audit` | Hash-chained event log. |
| `ep_claim` | Claim a work region on a branch. |
| `ep_release_claim` | Release a work claim. |
| `ep_claims` | List active work claims. |
| `ep_pending_approvals` | List pending approval requests. |
| `ep_approve` | Approve a pending request. Requires policy_approver role. |
| `ep_deny` | Deny a pending request. Requires policy_approver role. |
| `ep_export` | Export a signed transfer package. |
| `ep_import` | Import/fork from a transfer package. Creates new lattice. |
| `ep_resume` | Connect to an existing lattice (resume after model switch). |
| `ep_tensions` | List policy tensions (conflicts at creation time). |
| `ep_quarantine_status` | List quarantined and at-risk nodes. |
| `ep_repair` | Lift a quarantine after repair. Requires operator role. |
| `ep_override` | Override a denied policy. Requires policy_approver role. Scoped, justified, time-limited. |

### 18.2 Transport

- **stdio** (default): for direct Hermes integration.
- **HTTP** (optional): for network access. Requires TLS, per-agent authentication, replay protection, and rate limiting.

---

## 19. Hermes Skill Integration

### 19.1 SKILL.md

The repo includes a SKILL.md that Hermes agents load. The skill instructs the agent to:

1. On first use: `ep-governance init` (creates schema)
2. Register with enrollment token: `ep-governance register`
3. On session start: `ep-governance resume --project <id> --branch <id>` (connect to existing lattice) or `ep-governance create-project` (new project)
4. Before any consequential action (advisory mode): `ep-governance check`
5. To execute (enforced mode): `ep-governance execute`
6. If denied: read the policy details, do not proceed, propose alternative
7. If pending_approval: wait for human decision
8. On session end: optionally `ep-governance export` to create a snapshot

### 19.2 Bootstrap

Session bootstrap loads from the database:
- All active policies for this agent (and global policies)
- Current branch head and version
- BT planning budget remaining
- UT risk ledger per domain
- Any active quarantines or at-risk nodes
- Current work claims
- Pending approval requests for this agent

These are injected into the agent's context as binding rules and current state, not memories or preferences.

---

## 20. Installation

### 20.1 From GitHub (private repo)

```bash
git clone git@github.com:pottertech/ep-governance.git
cd ep-governance
pip install -e .
ep-governance init
```

### 20.2 As a Hermes Skill

```bash
ln -s /path/to/ep-governance ~/.hermes/skills/ep-governance
```

Or register via the NAS skill registry.

### 20.3 Distribution

- **Development machines**: SSH deploy keys for the private repo
- **Production**: NAS skill registry as the controlled distribution mechanism
- **No long-lived GitHub tokens** embedded in agent configuration

### 20.4 Requirements

- Python 3.12+
- PostgreSQL (production) or SQLite (development only)
- Optional: Ollama, OpenAI API key, or Cohere API key for embeddings
- Optional: NATS for cross-machine notifications
- Optional: TLS certificate for HTTP MCP transport

---

## 21. Repository Structure

```
pottertech/ep-governance/
  SKILL.md
  README.md
  pyproject.toml
  .env.example

  src/ep_governance/
    __init__.py
    xid.py                          # XID generator (rs/xid-compatible, pure Python)
    config.py                       # load config from .env or env vars
    db.py                           # database connection (Postgres or SQLite)
    models.py                       # Principal, Node, Edge, Policy, Transition dataclasses
    embeddings.py                   # pluggable: ollama/openai/cohere/sst/none
    classify.py                     # server-side action classification (SQL AST, shell parse, etc.)
    policy.py                       # deterministic policy evaluation engine
    gate.py                         # verification gate (backward pulse + forward blast + tension)
    lattice.py                      # DAG operations (add node, add edge, cycle check, branch head)
    lifecycle.py                    # transition lifecycle (proposed -> authorized -> executing -> succeeded/failed)
    risk.py                         # risk ledger per domain
    auth.py                         # authentication, roles, enrollment tokens
    tokens.py                       # signed short-lived authorization tokens
    transfer.py                     # export/import/resume (signed, versioned packages)
    audit.py                        # append-only hash-chained event log
    proxy.py                        # governed proxy for enforced mode (shell/db/email/docker/git)
    bootstrap.py                    # session bootstrap (load active policies + state)
    cli.py                           # CLI entry point
    mcp_server.py                   # MCP server (stdio or HTTP)

  migrations/
    postgres/
      001_init.sql
    sqlite/
      001_init.sql

  scripts/
    install.sh                      # one-command install
```

---

## 22. Implementation Phases

### Phase 1: Formal Semantics

Define the formal models:
- Project, lattice, branch, node, transition lifecycle stages
- Policy schema, effect types, condition evaluation
- Authorization token, stale detection, idempotency
- Risk domain, risk ledger, mitigations
- Quarantine, denial, at-risk, revocation semantics
- BT (planning budget), UT (risk ledger) semantics

No coding until these are unambiguous.

### Phase 2: Deterministic Policy Engine

Implement the structured policy model:
- Policy CRUD (create, read, retire, supersede)
- Server-side action classification (SQL AST parsing, shell parsing)
- Deterministic condition evaluation
- Effect resolution with priority ordering
- Tension detection at policy creation time

No embeddings. No enforcement yet. Unit tests with deterministic cases.

### Phase 3: PostgreSQL Event and State Model

Implement:
- Database schema (Postgres only for now)
- Append-only hash-chained audit log
- Node, edge, branch operations with optimistic concurrency
- Cycle prevention
- Event recording

### Phase 4: Transition Lifecycle

Implement the full state machine:
- Proposed -> authorized -> executing -> succeeded/failed
- Authorization token issuance, validation, single-use, expiry
- Stale authorization detection (policy version check)
- Idempotency keys
- Resource exhaustion (BT) and risk ledger (UT) evaluation

### Phase 5: Governed Tool Wrapper

Demonstrate real enforcement with one tool category:
- Start with `postgres.proxy` (SQL execution against a specified database)
- The proxy holds the database credentials
- The agent requests authorization, receives a token, sends payload to proxy
- Proxy validates, classifies server-side, executes, records result
- Integration test: agent cannot bypass the proxy to access the database directly

### Phase 6: Multi-Agent Concurrency

Add:
- Branch heads with optimistic concurrency
- Stale-head detection and retry
- Work claims
- LISTEN/NOTIFY for state change notifications
- Branching and merge operations
- Integration tests with two agents committing to the same branch

### Phase 7: Transfer Packages

Add:
- Export (signed, versioned snapshot)
- Import/fork (creates new lattice, never touches live data)
- Resume (connect to existing database)
- Schema versioning
- Content hash and signature verification

### Phase 8: Semantic Assistance

Add embeddings:
- Policy authoring assistance (suggest structured policy from natural language)
- Policy discovery (suggest relevant policies for a proposed action)
- Audit search (find similar past transitions)
- Re-embedding on model change

Embeddings never participate in enforcement decisions.

---

## 23. Security

### 23.1 What EP-Governance Does

- Governs the execution path through a proxy that holds infrastructure credentials
- Evaluates deterministic policies before authorizing actions
- Records all transitions in an append-only hash-chained audit log
- Quarantines unsafe states and computes blast radius
- Issues signed short-lived authorization tokens that are payload-bound and single-use
- Detects stale authorizations when policies change
- Requires human approval for `require_approval` policies
- Scopes overrides with justification, expiry, and audit

### 23.2 What EP-Governance Does Not Do

- Does not provide cryptographic guarantees against a determined adversary with database access
- Does not prevent an agent from refusing to use the governed proxy (in advisory mode)
- Does not enforce real compute quotas (BT is a planning budget)
- Does not store or manage operational target credentials (those belong to the proxy)
- Does not replace human judgment for novel situations

### 23.3 Audit Integrity

The audit log is append-only with hash chaining:
- Each event includes `previous_hash` and `event_hash = SHA-256(event_data || previous_hash)`
- A restricted database role can INSERT but not UPDATE or DELETE
- Tampering with any event breaks the hash chain and is detectable
- Optional signed checkpoints provide external verifiability

### 23.4 HTTP MCP Security

For remote MCP access:
- Bind to private interface (Tailscale or localhost)
- TLS required (certificate in .env)
- Per-agent API key authentication
- Request IDs for tracing
- Idempotency keys for mutation operations
- Payload size limits
- Secret redaction in logs
- Rate limiting on mutation operations

---

## 24. Comparison: v1.0 vs v1.1

| Feature | v1.0 | v1.1 |
|---------|------|------|
| Enforcement | Advisory only | Advisory + Enforced (governed proxy) |
| Transition lifecycle | Single event (check = commit) | Multi-stage (proposed -> authorized -> executing -> succeeded/failed) |
| Policy model | Natural language + embeddings | Deterministic structured policies (effect, actions, resources, conditions) |
| Role of embeddings | Could decide enforcement | Authoring/discovery assistance only. Never enforcement. |
| Action classification | Agent-supplied | Server-side (SQL AST, shell parse, etc.). Agent hints accepted but overridden. |
| Energy | Single float, 0.8 threshold | Separated: effect (deny/approve/warn/allow), priority, confidence, strength |
| BT | "Compute budget" (implies real quota) | "Planning budget" (accounting only) |
| UT | Single global number | Risk ledger per domain (production_database, external_communications, etc.) |
| Active state | Per agent | Per (project, branch) -- supports branching and multi-agent |
| Concurrency | "Retry" | Optimistic concurrency with expected_head_id and expected_version |
| Database migrations | One SQL for both PG and SQLite | Separate migrations per dialect |
| Audit | Mutable tables | Append-only hash-chained event log |
| Quarantine | Applied to denied proposals | Applied only to existing committed states found unsafe. Denied proposals never enter graph. |
| Tension detection | Pairwise simulation (false positives) | At policy creation time: contradictory effects, incompatible conditions |
| Authorization | None (agent proceeds if admissible) | Signed short-lived, payload-bound, single-use tokens. Stale detection. |
| Override | Undefined | Scoped, justified, time-limited, audited. Requires policy_approver role. |
| Transfer packages | Simple JSON export | Signed, versioned, with provenance. Import creates new lattice (fork), never touches live. |
| Agent registration | Self-registration | Enrollment token or admin registration in production. Self-registration in dev mode only. |
| Roles | None | observer, agent, policy_author, policy_approver, operator, auditor, administrator |
| Graph structure | "3D geometric lattice" (metaphorical) | Directed acyclic graph (DAG) with cycle prevention |
| Edge constraints | None | CHECK: upstream <> downstream. Cycle prevention via forward BFS. |
| SQLite support | Claimed equal to Postgres | Development only. No cross-machine. Documented limitations. |
| XID | "Globally unique" | "Probabilistically unique" with collision retry and fork safety |
| "No files on disk" | Absolute | "No authoritative runtime state in local files" (config and exports are files) |
| Embedding storage | Fixed VECTOR(dim) | Per-model table with version, source hash, distance metric, re-embedding status |
| Implementation phases | Not sequenced | 8 phases: semantics -> policy -> DB -> lifecycle -> proxy -> multi-agent -> transfer -> embeddings |

---

## 25. Open Questions for Team Review

1. **Policy language choice.** The design uses a custom typed JSON schema for policies. Should we evaluate CEL, Rego/OPA, Cedar, or JSON Logic as alternatives before committing?

2. **SQL AST parsing.** For server-side classification of database actions, which Python SQL parser? Options: `sqlglot`, `sqlparse`, `moSQL`. `sqlglot` supports the most dialects and produces a proper AST.

3. **Shell command parsing.** For classifying shell actions, which approach? Options: `shlex` (basic), `bashlex` (full bash AST), or a custom classifier. `shlex` is simpler but may miss piped commands and redirects.

4. **Signing keys for transfer packages.** Should signing use HMAC-SHA256 (shared key) or asymmetric (RSA/Ed25519)? Asymmetric allows verifying packages without sharing the signing key.

5. **Token signing.** Authorization tokens use HMAC-SHA256. Should the signing key be per-project or per-deployment? Per-project isolates projects but requires more key management.

6. **Risk domain defaults.** What are the default `inherent_risk` values and thresholds for each risk domain? Should they be configurable per project?

7. **Branch merge semantics.** When two branches are merged, how are conflicting transitions resolved? Last-writer-wins, manual resolution, or policy-based?

8. **Cleanup and GC.** Old transitions, expired tokens, and retired policies accumulate over time. Should there be a cleanup process? What is the retention policy?

9. **Testing strategy.** The design calls for unit tests, property-based tests, and integration tests. What coverage targets? What concurrency test scenarios?

10. **Versioning.** The design versions the schema, policy schema, event schema, transfer package format, and API/MCP contract. Should these be independent or coupled? What is the backward compatibility policy?