# EP-Governance — Getting Started

This tutorial takes you from a clean machine to your first successful governed execution through the full enforced-mode pipeline. By the end you will have:

- Installed EP-Governance and initialized its database schema
- Generated an Ed25519 signing keypair
- Registered a human administrator and an agent principal
- Created a project with a `main` branch
- Loaded two governance policies (allow SELECT, deny DROP)
- Started the governed PostgreSQL proxy
- Submitted `SELECT 1` end-to-end through the pipeline
- Verified the DAG node and audit event
- Confirmed that token reuse is rejected
- Confirmed that an unauthorized `DROP TABLE` is denied

All example values in this guide are neutral placeholders. Replace them with your own hostnames, credentials, and XIDs.

---

## 1. Prerequisites

| Requirement | Details |
|-------------|---------|
| **Python** | 3.12 or later (`python3 --version`) |
| **PostgreSQL** | 14+ recommended for production. SQLite works for local single-agent development but does not support multi-agent concurrency, `LISTEN/NOTIFY`, or row-level locking. |
| **pip / venv** | Standard Python packaging tools |
| **Git** | For cloning the repository |

### 1.1 PostgreSQL setup (example)

If you do not already have a PostgreSQL instance, create a dedicated database and user:

```sql
-- Run as a PostgreSQL superuser
CREATE DATABASE ep_governance_dev;
CREATE USER ep_governance WITH PASSWORD 'change-me-in-production';
GRANT ALL PRIVILEGES ON DATABASE ep_governance_dev TO ep_governance;
```

You will also need a **target database** that the proxy will execute SQL against. For this tutorial, any PostgreSQL database you can connect to will work — even the same instance with a different database name.

### 1.2 Verify Python version

```bash
python3 --version
# Expected: Python 3.12.x or higher
```

---

## 2. Installation

### 2.1 Clone and install

```bash
git clone git@github.com:pottertech/ep-governance.git
cd ep-governance
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[postgres,crypto,dev]"
```

This installs the `ep-governance` CLI entry point plus PostgreSQL drivers (`psycopg`), crypto libraries (`pynacl`, `cryptography`), and development tools (`ruff`, `mypy`, `pytest`).

Verify the CLI is on your PATH:

```bash
ep-governance --help
```

You should see the top-level command list: `init`, `register`, `project`, `policy`, `check`, `execute`, `status`, `log`, `audit`, `serve`, and more.

### 2.2 Configure environment variables

EP-Governance reads all configuration from environment variables. Create a `.env` file in the repo root (this file is gitignored — never commit it):

```bash
# .env — EP-Governance configuration

# --- Governance database ---
# PostgreSQL connection string for the governance DB
EP_DB_URL=postgresql+psycopg://ep_governance:change-me-in-production@postgres.example.internal:5432/ep_governance_dev
EP_DB_SCHEMA=ep_governance

# --- Operating mode ---
EP_MODE=enforced

# --- Proxy (set these when starting the proxy in Step 7) ---
# EP_PROXY_TARGET_URL=postgresql+psycopg://ep_governance:change-me-in-production@postgres.example.internal:5432/target_dev
# EP_PROXY_AUDIENCE=postgres-proxy
# EP_PUBLIC_KEY=<hex public key — generated in Step 4>
# EP_EP_SERVICE_ID=<XID — printed by init in Step 3>
# EP_PROXY_PORT=8201

# --- Optional: disable embeddings (enforcement works without them) ---
EP_EMBEDDING_PROVIDER=none
```

Load the environment before running CLI commands:

```bash
set -a; source .env; set +a
```

> **Note:** If you use the wrapper script at `/usr/local/bin/ep-governance`, it automatically loads `.env` from the repo root. For manual `python -m ep_governance.cli` invocations, source the file yourself.

### 2.3 Run database migrations

The `init` command runs all migrations and creates the EP service principal:

```bash
ep-governance init
```

Expected output (human-readable):

```
  status: initialized
  ep_service_principal_id: <20-char XID>
```

Save the `ep_service_principal_id` — you will need it when starting the proxy. Add it to your `.env`:

```bash
EP_EP_SERVICE_ID=<the XID from init output>
```

> **What happened:** `init` executed the SQL migration files in `migrations/postgres/` (or `migrations/sqlite/` for SQLite), creating all governance tables (principals, projects, lattices, branches, nodes, transitions, policies, authorizations, audit events, etc.) and inserted a singleton "EP Service" service principal.

---

## 3. Generate the Signing Key

EP-Governance uses Ed25519 to sign authorization tokens. The EP service holds the **private signing key**; proxies receive only the **public verification key**.

Generate a keypair and save the private key to a file:

```bash
python -c 'from ep_governance.authorizations import KeyManager; km = KeyManager(); km.save_private_key("ep_signing.key")'
```

This creates `ep_signing.key` — a 32-byte raw Ed25519 private key file with mode `0600`.

Extract the **public key** in hex (the proxy needs this):

```bash
python -c '
from ep_governance.authorizations import KeyManager
km = KeyManager()
km.load_private_key("ep_signing.key")
print(km.public_key.encode().hex())
'
```

Copy the printed hex string into your `.env`:

```bash
EP_PUBLIC_KEY=<32-byte Ed25519 public key encoded as 64 hexadecimal characters>
```

> **Security:** The private key file (`ep_signing.key`) must never be shared with proxies, agents, or any process other than the EP service. Store it with restrictive file permissions (`chmod 600 ep_signing.key`) and back it up securely — if you lose it, all previously issued tokens become unverifiable.

---

## 4. Register Principals

EP-Governance distinguishes between principal types: `human`, `agent`, `service`, and `proxy`. You need at least one human (to approve policies) and one agent (to submit actions).

### 4.1 Register a human administrator

```bash
ep-governance register --name "Alice Admin" --type human
```

Output:

```
  principal_id: <20-char XID>
  name: Alice Admin
  type: human
```

Save this XID — it is the approver for policy activation.

### 4.2 Register an agent

```bash
ep-governance register --name "Tutorial Agent" --type agent
```

Output:

```
  principal_id: <20-char XID>
  name: Tutorial Agent
  type: agent
```

Save this XID — you will pass it as `--agent` when proposing and executing actions.

> For the rest of this tutorial, we will use these placeholder variables:
>
> ```bash
> HUMAN_ID=<human XID from step 4.1>
> AGENT_ID=<agent XID from step 4.2>
> EP_SERVICE_ID=<EP service XID from step 2.3>
> ```
>
> Set them in your shell:
>
> ```bash
> HUMAN_ID=xxxxxxxxxxxxxxxxxxxx
> AGENT_ID=xxxxxxxxxxxxxxxxxxxx
> EP_SERVICE_ID=xxxxxxxxxxxxxxxxxxxx
> ```

---

## 5. Create a Project and Branch

### 5.1 Create the project

Creating a project automatically creates a lattice and a `main` branch:

```bash
ep-governance project create "Tutorial Project" --description "Getting started tutorial"
```

Output:

```
  project_id: <20-char XID>
  lattice_id: <20-char XID>
  branch_id: <20-char XID>
  name: Tutorial Project
```

Save the `branch_id` — you will pass it as `--branch` for every `check` and `execute` call.

```bash
BRANCH_ID=<branch XID from project create>
LATTICE_ID=<lattice XID from project create>
PROJECT_ID=<project XID from project create>
```

### 5.2 (Optional) Create a feature branch

```bash
ep-governance project create-branch --project "$PROJECT_ID" --name feature-x --from-branch main
```

For this tutorial, we will stay on `main`.

### 5.3 Verify branch status

```bash
ep-governance status --branch "$BRANCH_ID"
```

Output:

```
  branch_id: <XID>
  head_node_id: None
  version: 1
  active_policies: 0
```

The branch starts at version 1 with no head node (empty DAG) and no policies. This will change after we load policies and execute our first action.

---

## 6. Load Initial Policies

Policies govern which actions are allowed, denied, require approval, or generate warnings. Each policy has an **effect** (`allow`, `deny`, `require_approval`, `warn`), a set of **actions** (action types like `postgres.execute.select`), a set of **resources** (patterns like `*` or `schema.public.table.*`), a **scope**, and a **priority** (higher priority wins at equal specificity).

Policies are created in `draft` status, then submitted for approval, then approved by a human principal to become `active`.

### 6.1 Allow SELECT (read-only queries)

```bash
ep-governance policy add \
  --effect allow \
  --actions '["postgres.execute.select"]' \
  --resources '["*"]' \
  --scope global \
  --priority 10 \
  --description "Allow read-only SELECT queries"
```

Output:

```
  policy_id: <20-char XID>
  status: draft
  effect: allow
```

Save the policy ID, then submit and approve it:

```bash
ALLOW_POLICY_ID=<policy XID from above>

ep-governance policy submit "$ALLOW_POLICY_ID"
ep-governance policy approve "$ALLOW_POLICY_ID" --approver "$HUMAN_ID"
```

After approval, the policy status becomes `active`.

### 6.2 Deny DROP (destructive DDL)

```bash
ep-governance policy add \
  --effect deny \
  --actions '["postgres.execute.drop"]' \
  --resources '["*"]' \
  --scope global \
  --priority 100 \
  --description "Deny all DROP operations"
```

Output:

```
  policy_id: <20-char XID>
  status: draft
  effect: deny
```

Submit and approve:

```bash
DENY_POLICY_ID=<policy XID from above>

ep-governance policy submit "$DENY_POLICY_ID"
ep-governance policy approve "$DENY_POLICY_ID" --approver "$HUMAN_ID"
```

### 6.3 Verify active policies

```bash
ep-governance policy list
```

You should see both policies listed with `status: active`. The deny policy has priority 100 (higher), so it will always override the allow policy (priority 10) when both match.

### 6.4 Re-check branch status

```bash
ep-governance status --branch "$BRANCH_ID"
```

Now `active_policies` should show `2`.

---

## 7. Start the Governed Proxy

The proxy is a separate HTTP server that holds the **target database credentials** and executes SQL on behalf of agents. The agent never sees these credentials — it sends a signed token and payload to the proxy, and the proxy verifies, claims, and executes.

### 7.1 Set proxy environment variables

Ensure your `.env` has these set (fill in the values from previous steps):

```bash
# Target database the proxy will execute SQL against
EP_PROXY_TARGET_URL=postgresql+psycopg://ep_governance:change-me-in-production@postgres.example.internal:5432/target_dev

# Token audience — must match what EP issues
EP_PROXY_AUDIENCE=postgres-proxy

# EP's Ed25519 public key (hex) — from Step 3
EP_PUBLIC_KEY=<32-byte Ed25519 public key encoded as 64 hexadecimal characters>

# EP service principal XID — from Step 2.3
EP_EP_SERVICE_ID=<EP service XID>

# Proxy listen port
EP_PROXY_PORT=8201
```

### 7.2 Start the proxy

In a **separate terminal** (the proxy runs as a long-lived server):

```bash
cd /path/to/ep-governance
source .venv/bin/activate
set -a; source .env; set +a
python -m ep_governance.proxy_service
```

Expected output on stderr:

```
EP-Governance proxy listening on port 8201
  Audience: postgres-proxy
  Target: postgres.example.internal:5432/target_dev
  Governance DB: postgres.example.internal:5432/ep_governance_dev
```

### 7.3 Health check

```bash
curl http://localhost:8201/health
```

Expected:

```json
{"status": "ok", "service": "ep-governance-proxy"}
```

```bash
curl http://localhost:8201/info
```

Expected:

```json
{"service": "ep-governance-proxy", "audience": "postgres-proxy", "target": "postgresql"}
```

The proxy is now running and ready to accept token-based execution requests.

---

## 8. Submit `SELECT 1` Through the Pipeline

Now we will walk through the full enforced-mode execution path: propose → policy evaluation → token issuance → proxy execution → graph node creation → audit event.

### 8.1 Propose the action (advisory check first)

Use `ep-governance check` to evaluate the action without executing it. This classifies the SQL server-side, evaluates policies, and returns the decision:

```bash
ep-governance check \
  --tool postgres.execute \
  --arguments '{"sql": "SELECT 1"}' \
  --branch "$BRANCH_ID" \
  --agent "$AGENT_ID" \
  --json
```

Expected output (abbreviated):

```json
{
  "transition_id": "<20-char XID>",
  "stage": "authorized",
  ...
}
```

The `stage: authorized` means the policy engine matched the allow policy, the deny policy did not apply (this is a SELECT, not a DROP), and the transition was admitted. No token is issued yet — `check` is advisory.

### 8.2 Authorize the action (request authorization token)

Use `ep-governance execute` to propose the action and request authorization:

```bash
ep-governance execute \
  --tool postgres.execute \
  --arguments '{"sql": "SELECT 1"}' \
  --branch "$BRANCH_ID" \
  --agent "$AGENT_ID" \
  --json
```

This command:
1. Proposes the transition (classifies SQL → `postgres.execute.select`)
2. Evaluates policies (allow policy matches, deny does not → admissible)
3. Returns the transition with `stage: authorized`

> **Important:** The CLI `execute` command proposes and authorizes the transition. It does **not** call the proxy. To complete the full pipeline, the EP service issues a signed Ed25519 authorization token (payload-bound, agent-bound, branch-bound, single-use, 5-minute TTL). The caller then forwards that exact token and payload to the proxy's `/execute` HTTP endpoint. See the next step.

### 8.3 Send the token to the proxy

The transition output from `execute` includes the signed token. To submit it to the proxy:

```bash
# The transition output includes the signed token JSON.
# Submit it to the proxy along with the original payload:

TRANSITION_JSON=$(ep-governance execute \
  --tool postgres.execute \
  --arguments '{"sql": "SELECT 1"}' \
  --branch "$BRANCH_ID" \
  --agent "$AGENT_ID" \
  --json)

# Extract the signed token and authorization ID from the transition
SIGNED_TOKEN=$(echo "$TRANSITION_JSON" | python -c "import sys, json; d=json.load(sys.stdin); print(d.get('signed_token',''))")
AUTH_ID=$(echo "$TRANSITION_JSON" | python -c "import sys, json; d=json.load(sys.stdin); print(d.get('authorization_id',''))")

# Submit to the proxy
curl -X POST http://localhost:8201/execute \
  -H "Content-Type: application/json" \
  -d "{\"signed_token\": $SIGNED_TOKEN, \"payload\": {\"sql\": \"SELECT 1\"}}"
```

Expected response from the proxy:

```json
{
  "success": true,
  "exit_status": "success",
  "result_summary": "SELECT returned 1 rows",
  "rows_affected": 1,
  "output": "[{'1': 1}]",
  "execution_attempt_id": "<20-char XID>",
  "started_at": "2026-07-31T...",
  "completed_at": "2026-07-31T...",
  "redacted": true
}
```

> **What happened inside the proxy:**
> 1. Verified the Ed25519 token signature using EP's public key
> 2. Computed the SHA-256 payload hash from the actual `{"sql": "SELECT 1"}` payload and verified it matched the token's `payload_hash`
> 3. Verified the token audience matched `postgres-proxy`
> 4. Revalidated current policy state (stale authorization detection via `policy_set_hash`)
> 5. Atomically claimed the authorization (`UPDATE ... WHERE used = FALSE ... RETURNING`)
> 6. Executed `SELECT 1` against the target database
> 7. Recorded the execution result back to EP
> 8. EP created a graph node, advanced the branch head (v1 → v2), and appended an audit event

---

## 9. Verify the DAG Node and Audit Event

### 9.1 Check branch status — head should have advanced

```bash
ep-governance status --branch "$BRANCH_ID"
```

Expected:

```
  branch_id: <XID>
  head_node_id: <20-char XID>
  version: 2
  active_policies: 2
```

The version advanced from 1 to 2, and `head_node_id` is no longer `None` — the first real node has been committed to the DAG.

### 9.2 View the transition log

```bash
ep-governance log
```

You should see a transition with `stage: succeeded` (or `executing` → `succeeded` if you catch it in flight) for the `postgres.execute` tool.

### 9.3 Verify the audit chain

```bash
ep-governance audit verify --lattice "$LATTICE_ID"
```

Expected:

```
  lattice_id: <XID>
  valid: True
```

### 9.4 List audit events

```bash
ep-governance audit list --lattice "$LATTICE_ID"
```

You should see a sequence of hash-chained audit events, including:
- `transition.authorized` — the action was admitted by policy
- `transition.executing` — the proxy claimed the token and began execution
- `transition.succeeded` — execution completed successfully
- `node.committed` — a graph node was committed to the DAG

Each event has a `sequence` number, `previous_hash`, and `event_hash` forming the tamper-evident chain.

---

## 10. Attempt Token Reuse (Should Fail)

Authorization tokens are **single-use**. Once the proxy claims a token, any subsequent submission of the same token must be rejected.

Using the same signed token from Step 8.3, submit it again:

```bash
curl -X POST http://localhost:8201/execute \
  -H "Content-Type: application/json" \
  -d "{\"signed_token\": $SIGNED_TOKEN, \"payload\": {\"sql\": \"SELECT 1\"}}"
```

Expected response:

```json
{
  "success": false,
  "exit_status": "failure",
  "result_summary": "Authorization claim failed: token already used, expired, or not found",
  "execution_attempt_id": "<20-char XID>",
  ...
}
```

The proxy rejects the reused token because the atomic `claim_authorization` call finds `used = TRUE` in the database and returns `None`. No SQL is executed. No second node is created.

---

## 11. Attempt an Unauthorized DROP (Should Be Denied)

Now we will attempt a `DROP TABLE` operation, which is covered by the deny policy (priority 100).

### 11.1 Check the action (advisory)

```bash
ep-governance check \
  --tool postgres.execute \
  --arguments '{"sql": "DROP TABLE IF EXISTS tutorial_test"}' \
  --branch "$BRANCH_ID" \
  --agent "$AGENT_ID" \
  --json
```

Expected output (abbreviated):

```json
{
  "transition_id": "<20-char XID>",
  "stage": "denied",
  ...
}
```

The `stage: denied` means the policy engine matched the deny policy for `postgres.execute.drop` and rejected the action.

### 11.2 Attempt execution

```bash
ep-governance execute \
  --tool postgres.execute \
  --arguments '{"sql": "DROP TABLE IF EXISTS tutorial_test"}' \
  --branch "$BRANCH_ID" \
  --agent "$AGENT_ID" \
  --json
```

Expected output:

```json
{
  "transition_id": "<20-char XID>",
  "stage": "denied",
  ...
}
```

**No authorization token is issued.** The transition reaches the `denied` terminal stage. No proxy submission is possible because there is no signed token to send.

### 11.3 Verify the denial was audited

```bash
ep-governance audit list --lattice "$LATTICE_ID"
```

You should see a `transition.denied` audit event appended to the chain, recording the denied action, the matched policy, and the actor.

---

## 12. Summary — What You Just Did

| Step | What happened | Key concept |
|------|--------------|-------------|
| Install | Cloned repo, installed CLI, ran migrations | Stateless Python + PostgreSQL as authoritative graph |
| Key generation | Generated Ed25519 keypair | EP holds private key, proxy holds public key |
| Register | Created human + agent principals | Identity model (human, agent, service, proxy) |
| Project | Created project with `main` branch | DAG with branch heads and versioning |
| Policies | Loaded allow SELECT + deny DROP | Deterministic policy evaluation, priority-based resolution |
| Proxy | Started governed PostgreSQL proxy | Credential isolation — proxy holds target DB credentials |
| SELECT 1 | Full pipeline: propose → authorize → token → proxy → execute → node → audit | Enforced mode execution path |
| Verify | Confirmed branch head advanced, audit chain valid | Tamper-evident append-only audit log |
| Token reuse | Same token rejected | Single-use atomic claiming |
| DROP TABLE | Denied by policy, no token issued | Deny > allow at higher priority, no execution path |

---

## Next Steps

- **Read the architecture overview:** `docs/architecture.md` for the full system design, component model, and data flow diagrams.
- **Explore the CLI:** `ep-governance --help` for all commands, including `pending-approvals`, `approve`, `deny`, `serve` (MCP server), and `bootstrap-admin`.
- **Set up the MCP server:** Run `ep-governance serve` to expose governance tools (`ep_check`, `ep_execute`, `ep_status`, etc.) to AI agents via the Model Context Protocol.
- **Read the design specification:** `docs/specification/design-v1.1.md` for the normative architectural spec.
- **Run the test suite:** `./scripts/verify.sh` to run lint, type checks, unit, property, contract, integration, concurrency, and security tests.
- **Configure additional policies:** Explore `require_approval` and `warn` effects, agent-scoped policies, and time-bounded exceptions.
- **Multi-agent setup:** Register additional agents and create feature branches to work in parallel on the same project.

---

## Troubleshooting

### `EP_DB_URL is required`

The environment variable is not set. Ensure you sourced `.env` before running the CLI:

```bash
set -a; source .env; set +a
```

### `EP_PUBLIC_KEY is required (Ed25519 public key in hex)`

The proxy cannot start without the EP public key. Generate it from the private key file (Step 3) and set `EP_PUBLIC_KEY` in your environment.

### `EP_EP_SERVICE_ID is required`

The proxy needs the EP service principal XID. Run `ep-governance init` and copy the `ep_service_principal_id` from the output into `EP_EP_SERVICE_ID`.

### Proxy returns `Token verification failed: invalid signature or expired`

- The `EP_PUBLIC_KEY` does not match the private key that signed the token. Regenerate the public key hex from the same `ep_signing.key` file.
- The token has expired (default 5-minute TTL). Request a new authorization.

### Proxy returns `Payload hash mismatch`

The payload sent to the proxy does not match the payload that was authorized. The proxy computes the hash from the **actual payload you send**, not a caller-supplied hash. Ensure the `payload` field in your `/execute` request exactly matches the `--arguments` JSON passed to `ep-governance execute`.

### Proxy returns `Token audience mismatch`

The `EP_PROXY_AUDIENCE` environment variable does not match the `proxy_audience` field in the token. Ensure both are set to the same value (default: `postgres-proxy`).

### `No lattice found for project <XID>`

The project XID is wrong or the project was not created. Run `ep-governance project list` to verify, and use the `project_id` (not the name) when creating branches.

### `stage: denied` when you expected `authorized`

A deny policy with higher priority is matching the action. Check active policies with `ep-governance policy list` and verify the action type and resource patterns. Remember: at equal priority, `deny > require_approval > warn > allow`.

### Migrations fail with `permission denied for schema ep_governance`

The database user does not have `CREATE` privilege on the schema. Grant it:

```sql
GRANT USAGE, CREATE ON SCHEMA ep_governance TO ep_governance;
```

### SQLite limitations

If you are using SQLite (`EP_DB_URL=sqlite:///ep.db`), note that:
- Multi-agent concurrency is not supported
- `LISTEN/NOTIFY` is not available
- Row-level locking uses `BEGIN IMMEDIATE` instead of `SELECT ... FOR UPDATE`
- pgvector embeddings are not available

For anything beyond local single-agent development, use PostgreSQL.