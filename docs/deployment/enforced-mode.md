# EP-Governance Enforced-Mode Deployment Guide

This guide covers deploying EP-Governance in **enforced mode**, where the governed proxy is the only path to the target database. The agent process has no target-DB credentials; the proxy owns them. All SQL execution is token-gated, audited, and policy-checked.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Prerequisites](#2-prerequisites)
3. [Secrets Management](#3-secrets-management)
4. [Networking](#4-networking)
5. [Database Roles](#5-database-roles)
6. [Proxy Deployment](#6-proxy-deployment)
7. [EP Service Deployment](#7-ep-service-deployment)
8. [MCP Server Configuration](#8-mcp-server-configuration)
9. [Verification](#9-verification)
10. [Environment Variable Reference](#10-environment-variable-reference)

---

## 1. Architecture Overview

```
 ┌───────────-───┐         ┌───────────────────-──┐         ┌────────-──────────┐
 │  EP Service   │  token  │   Governed Proxy     │  SQL    │   Target DB       │
 │  (MCP server) │────────▶│   (Docker, port 8201)│────────▶│   (PostgreSQL)    │
 │  No target DB │         │   Owns DB creds      │         │   TLS enabled     │
 └───────────-───┘         └──────────────────-───┘         └───────-───────────┘
        │                          │
        │                          ▼
        │                 ┌──────────────────-───┐
        │                 │  Governance DB       │
        └────────────────▶│  (ep_governance      │
                          │   schema)            │
                          └──────────────────-───┘
```

**Key invariant:** In enforced mode, the agent cannot reach the target database directly — not via credentials, not via network. Every SQL statement flows through the proxy, which validates a signed Ed25519 token, checks governance policy, executes against the target DB, and records the audit event.

---

## 2. Prerequisites

### Infrastructure

| Component | Requirement |
|-----------|-------------|
| NAS / host | Docker 24+ and Docker Compose v2 |
| PostgreSQL | 14+ (target DB and governance DB may co-locate or be separate) |
| Network | Tailscale (or equivalent VPN) on both the EP-service host and the proxy host |
| Python | 3.12+ (for local key generation and CLI tooling) |

### EP-Governance artifacts

- Proxy Docker image (built from `docker/proxy/Dockerfile`)
- `docker-compose.proxy.yml` (at repo root or `docker/proxy/`)
- Database migrations applied: `002_roles.sql` and `003_proxy_role.sql`
- Ed25519 keypair generated (public key for proxy, private key for EP service)

### Generate the Ed25519 keypair

```bash
python -c "
from ep_governance.authorizations import KeyManager
km = KeyManager()
print('PUBLIC (hex):', bytes(km.public_key).hex())
print('PRIVATE (hex):', bytes(km.private_key).hex())
"
```

- The **public key** goes to the proxy (env `EP_PUBLIC_KEY`).
- The **private key** stays with the EP service (never on the proxy host).

---

## 3. Secrets Management

### Rules

1. **Never commit `.env` files.** The repo ships `.env.proxy.template` — copy it locally, fill in values, and keep it out of git (it is in `.gitignore`).
2. **File permissions `0600`.** Any local `.env` file or key material on disk must be readable only by the owning user:
   ```bash
   chmod 0600 .env.proxy
   ```
3. **Prefer Docker secrets or HashiCorp Vault.** For production, do not rely on plaintext `.env` files. Use Docker secrets (`docker secret create`) or Vault to inject credentials at runtime:
   ```yaml
   # docker-compose snippet using Docker secrets
   secrets:
     ep_db_url:
       external: true
     target_db_url:
       external: true
   ```
4. **URL-encode passwords.** If a password contains special characters (`@`, `:`, `/`, `%`, `#`, `?`), URL-encode them in the connection string:
   ```
   # password "p@ss:w0rd" → "p%40ss%3Aw0rd"
   EP_PROXY_TARGET_URL=postgresql://ep_proxy_user:p%40ss%3Aw0rd@10.0.0.10:5432/target_db
   ```
5. **Separate governance and target DB accounts.** The governance DB connection (`EP_DB_URL`) and the target DB connection (`EP_PROXY_TARGET_URL`) must use different credentials. The governance account has access to the `ep_governance` schema; the target account (`ep_proxy_user`) has access to target databases but **not** the governance schema. If an attacker compromises one credential, they do not get the other.

### What the proxy needs

|       Secret          |              Purpose                                  |
|-----------------------|-------------------------------------------------------|
| `EP_DB_URL`           | Connects to governance DB (audit log, policy tables)  |
| `EP_PROXY_TARGET_URL` | Connects to target DB (executes agent SQL)            |
| `EP_PUBLIC_KEY`       | Ed25519 public key (verifies tokens, can't mint them) |
| `EP_EP_SERVICE_ID`    | XID of the EP service principal                       |

### What the proxy must NOT have

- The Ed25519 **private key** — the proxy can only verify tokens, never mint them.
- Any credential beyond `ep_proxy_user` and the governance-DB account.

---

## 4. Networking

### Tailscale

Both the EP-service host and the proxy host should run Tailscale. The proxy listens on port `8201`; restrict access to the Tailscale interface only.

```
# Proxy host: Tailscale IP example 100.64.0.20
# EP-service host: Tailscale IP example 100.64.0.30
```

### Firewall rules (proxy host)

Restrict the proxy's listening socket to the Tailscale interface so that only VPN peers can reach it:

```bash
# Allow EP service (over Tailscale) to reach proxy
ufw allow in on tailscale0 from 100.64.0.30 to any port 8201 proto tcp

# Deny all other inbound to 8201
ufw deny in on eth0 to any port 8201 proto tcp
ufw deny in on wlan0 to any port 8201 proto tcp
```

### Firewall rules (target DB host)

The target PostgreSQL instance must accept connections **only** from the proxy host — never from the EP-service host or any agent machine:

```bash
# Allow only the proxy host (over Tailscale)
ufw allow in on tailscale0 from 100.64.0.20 to any port 5432 proto tcp

# Explicitly deny the EP-service host
ufw deny in on tailscale0 from 100.64.0.30 to any port 5432 proto tcp
```

### PostgreSQL TLS

Enable TLS on the target PostgreSQL server so that proxy-to-DB traffic is encrypted even on the private network:

**`postgresql.conf` (target DB):**
```conf
ssl = on
ssl_cert_file = '/etc/postgresql/tls/server.crt'
ssl_key_file = '/etc/postgresql/tls/server.key'
ssl_min_protocol_version = 'TLSv1.2'
```

**`pg_hba.conf` (target DB):**
```conf
# Only the proxy user, only over TLS, only from the proxy host
hostssl target_db  ep_proxy_user  100.64.0.20/32  scram-sha-256

# Reject everything else to target_db
host    target_db  all           0.0.0.0/0        reject
```

### Docker networking

The `docker-compose.proxy.yml` uses `network_mode: host` so the proxy container binds directly to the host's Tailscale interface. If you prefer bridge networking, publish the port on the Tailscale IP only:

```yaml
ports:
  - "100.64.0.20:8201:8201"
```

---

## 5. Database Roles

Two migrations define the role hierarchy. Apply them in order before starting the proxy.

### `002_roles.sql` — governance roles

| Role | Login? | Purpose |
|------|--------|---------|
| `ep_service` | NOLOGIN | Full CRUD on governance tables (`ep_projects`, `ep_lattices`, `ep_branches`, etc.). INSERT-only on `ep_events` (audit log is immutable — no UPDATE or DELETE). |
| `ep_agent` | NOLOGIN | Read-only on a small subset: `ep_policies`, `ep_transitions`, `ep_branches`, `ep_nodes`. Explicitly revoked from `ep_events`, `ep_audit_heads`, `ep_authorizations`, and all other internal tables. |

Both roles are created `NOLOGIN` — no passwords in migrations. Credentials are injected at deployment time.

**Key immutability guarantee:** Only `ep_service` can INSERT into `ep_events`. No role can UPDATE or DELETE. This is enforced at the database level, not via application code.

### `003_proxy_role.sql` — proxy roles

| Role | Login? | Purpose |
|------|--------|---------|
| `ep_proxy` | NOLOGIN | Group role. Granted `CONNECT` on target databases. Explicitly denied access to the `ep_governance` schema (`REVOKE ALL ON SCHEMA ep_governance`). |
| `ep_proxy_user` | LOGIN | Login role that inherits `ep_proxy`. This is the account the proxy uses to connect to target databases. |

**Security properties:**

- `ep_proxy_user` can connect to target databases but **cannot** see the governance schema.
- The agent must **not** have the `ep_proxy` role and must **not** have `ep_proxy_user` credentials.
- The migration ships with a placeholder password (`change_me_in_production`). **Change it before deploying.** In production, inject the real password via a secret manager or certificate-based auth.

### Applying the migrations

```bash
# Apply 002_roles.sql (connected to the governance DB)
psql "postgresql://admin_user:***@10.0.0.10:5432/governance_db" \
  -f migrations/postgres/002_roles.sql

# Apply 003_proxy_role.sql (connected to the governance DB)
psql "postgresql://admin_user:***@10.0.0.10:5432/governance_db" \
  -f migrations/postgres/003_proxy_role.sql

# Grant schema-level access on each target database
# (connect to each target DB individually)
psql "postgresql://admin_user:***@10.0.0.10:5432/target_db" <<'SQL'
GRANT USAGE ON SCHEMA public TO ep_proxy;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ep_proxy;
SQL
```

### Setting the production password for `ep_proxy_user`

```sql
-- Run as a superuser on the governance DB
ALTER ROLE ep_proxy_user PASSWORD 's3cur3-pr0d-p%40ssw0rd';
```

---

## 6. Proxy Deployment

### Build the image

```bash
cd /path/to/ep-governance
docker build -f docker/proxy/Dockerfile -t ep-governance-proxy:latest .
```

### Prepare the environment file

```bash
cp .env.proxy.template .env.proxy
chmod 0600 .env.proxy
# Edit .env.proxy with real values (see §10 for full reference)
```

Example `.env.proxy` (neutral values):

```dotenv
EP_DB_URL=postgresql://gov_user:gov%40ssword@100.64.0.10:5432/governance_db
EP_DB_SCHEMA=ep_governance
EP_MODE=enforced
EP_PROXY_TARGET_URL=postgresql://ep_proxy_user:tgt%40ssword@100.64.0.10:5432/target_db
EP_PROXY_AUDIENCE=postgres-proxy
EP_PROXY_PORT=8201
EP_EP_SERVICE_ID=d9ll4o7ug6j0oak02ck0
EP_PUBLIC_KEY=<hex-encoded Ed25519 public key>
```

### Launch with docker-compose

```bash
docker compose -f docker/proxy/docker-compose.proxy.yml --env-file .env.proxy up -d
```

The `docker-compose.proxy.yml` defines:

```yaml
services:
  ep-proxy:
    build:
      context: .
      dockerfile: docker/proxy/Dockerfile
    container_name: ep-governance-proxy
    restart: unless-stopped
    network_mode: host
    environment:
      EP_DB_URL: "${EP_DB_URL}"
      EP_DB_SCHEMA: ep_governance
      EP_MODE: enforced
      EP_PROXY_TARGET_URL: "${EP_PROXY_TARGET_URL}"
      EP_PROXY_AUDIENCE: postgres-proxy
      EP_PROXY_PORT: "8201"
      EP_EP_SERVICE_ID: "${EP_EP_SERVICE_ID}"
      EP_PUBLIC_KEY: "${EP_PUBLIC_KEY}"
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8201/health')"]
      interval: 30s
      timeout: 5s
      retries: 3
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
```

### Health check

The built-in health check polls `http://127.0.0.1:8201/health` every 30 seconds. Verify manually:

```bash
curl http://100.64.0.20:8201/health
# Expected: 200 OK with JSON status
```

Check container status:

```bash
docker inspect --format='{{.State.Health.Status}}' ep-governance-proxy
# Expected: healthy
```

### Restart policy

`restart: unless-stopped` ensures the proxy survives reboots and crashes. The container will **not** restart if you explicitly stop it with `docker compose down`.

### Security hardening

The compose file includes:

- **`security_opt: no-new-privileges:true`** — prevents the process from gaining additional capabilities via `setuid` binaries.
- **`cap_drop: ALL`** — drops all Linux capabilities. The proxy needs none.

---

## 7. EP Service Deployment

The EP service runs the MCP server and connects to the governance DB (not the target DB). It holds the Ed25519 **private key** and mints tokens that the proxy verifies.

### Environment

```dotenv
# EP service .env (on the EP-service host, NOT the proxy host)
EP_MODE=enforced
EP_DB_URL=postgresql://ep_service_user:svc%40ssword@100.64.0.10:5432/governance_db
EP_DB_SCHEMA=ep_governance
EP_MCP_TRANSPORT=stdio
EP_MCP_PORT=8200
EP_TOKEN_TTL_SECONDS=300
EP_EP_SERVICE_ID=d9ll4o7ug6j0oak02ck0
EP_PUBLIC_KEY=<hex-encoded Ed25519 public key>
# EP_PRIVATE_KEY is held in-memory or via Vault — never in a plaintext env file
```

### Key points

- The EP service connects to the **governance DB** only — it has no `EP_PROXY_TARGET_URL`.
- The EP service does **not** have `ep_proxy_user` credentials.
- The private key must be available to the EP service process but never written to disk in plaintext. Use Vault, a sealed secret, or an in-memory injection.

### Starting the EP service

```bash
# Set environment (via Vault, .env with 0600, or systemd EnvironmentFile)
export EP_MODE=enforced
export EP_DB_URL=postgresql://ep_service_user:svc%40ssword@100.64.0.10:5432/governance_db
export EP_DB_SCHEMA=ep_governance
# ...

python -m ep_governance.mcp_server
```

---

## 8. MCP Server Configuration

The EP service exposes an MCP server that agents connect to. The agent never talks to PostgreSQL directly — it calls MCP tools that internally request token-gated execution through the proxy.

### Transport modes

| Mode | `EP_MCP_TRANSPORT` | Use case |
|------|-------------------|----------|
| stdio | `stdio` | Local agent, same machine as EP service |
| HTTP | `http` | Remote agent over network |

### HTTP/TLS configuration

For remote agents, enable TLS on the MCP server:

```dotenv
EP_MCP_TRANSPORT=http
EP_MCP_PORT=8200
EP_MCP_TLS_CERT=/path/to/cert.pem
EP_MCP_TLS_KEY=/path/to/key.pem
EP_MCP_ALLOWED_HOSTS=100.64.0.30
```

- `EP_MCP_ALLOWED_HOSTS` restricts which hosts can connect (comma-separated).
- Use Tailscale IPs or hostnames.

### Agent-facing configuration

The agent's MCP client config points to the EP service, **not** the proxy and **not** the database:

```json
{
  "mcpServers": {
    "ep-governance": {
      "url": "https://100.64.0.30:8200",
      "transport": "http"
    }
  }
}
```

The agent has zero database credentials. It can only call MCP tools. Every tool call that requires SQL execution results in the EP service minting a token and forwarding the request to the proxy at `100.64.0.20:8201`.

---

## 9. Verification

After deployment, verify that enforced mode is truly enforced — not just configured, but **operationally guaranteed**.

### 9.1 Agent lacks target DB credentials

```bash
# On the agent host, confirm no target DB credentials exist in environment:
env | grep -i 'PROXY_TARGET\|TARGET_URL\|ep_proxy'
# Expected: no output

# Confirm the agent cannot connect to the target DB directly:
psql "postgresql://100.64.0.10:5432/target_db" -U ep_proxy_user
# Expected: password prompt (agent doesn't have it) or connection refused
```

### 9.2 Proxy owns the credentials

```bash
# On the proxy host, confirm the proxy container has the target URL:
docker exec ep-governance-proxy env | grep EP_PROXY_TARGET_URL
# Expected: EP_PROXY_TARGET_URL=postgresql://ep_proxy_user:***@...

# Confirm the proxy can reach the target DB:
docker exec ep-governance-proxy python -c "
import urllib.request, json
r = urllib.request.urlopen('http://127.0.0.1:8201/health')
print(json.loads(r.read()))
"
# Expected: health OK with DB connectivity status
```

### 9.3 Network path is proxy-only

```bash
# From the EP-service host, verify direct DB access is blocked:
nc -zv 100.64.0.10 5432
# Expected: connection refused / timeout (firewall blocks it)

# From the EP-service host, verify proxy is reachable:
nc -zv 100.64.0.20 8201
# Expected: connection succeeded

# From a random host (not on Tailscale), verify proxy is unreachable:
nc -zv 203.0.113.20 8201
# Expected: connection refused / timeout
```

### 9.4 Token enforcement

```bash
# Attempt to call the proxy without a token:
curl -X POST http://100.64.0.20:8201/execute \
  -H 'Content-Type: application/json' \
  -d '{"sql": "SELECT 1"}'
# Expected: 401 Unauthorized / token required

# Attempt with an invalid token:
curl -X POST http://100.64.0.20:8201/execute \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer invalid-token' \
  -d '{"sql": "SELECT 1"}'
# Expected: 401 Unauthorized / token verification failed

# Valid token (obtained through the EP service MCP flow):
# Should succeed, and the execution should appear in ep_events audit log.
```

### 9.5 Audit log immutability

```sql
-- Connect to governance DB as ep_service and confirm:
-- 1. INSERT works:
INSERT INTO ep_governance.ep_events (event_type, ...) VALUES (...);

-- 2. UPDATE and DELETE are denied:
UPDATE ep_governance.ep_events SET event_type = 'tampered' WHERE id = 1;
-- Expected: ERROR: permission denied

DELETE FROM ep_governance.ep_events WHERE id = 1;
-- Expected: ERROR: permission denied
```

### 9.6 Governance schema isolation

```sql
-- Connect to target DB as ep_proxy_user and attempt to access governance schema:
SELECT * FROM ep_governance.ep_events;
-- Expected: ERROR: permission denied for schema ep_governance
```

---

## 10. Environment Variable Reference

### Proxy environment

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `EP_DB_URL` | Yes | — | Governance DB connection string. Used for audit logging and policy lookups. URL-encode passwords. |
| `EP_DB_SCHEMA` | No | `ep_governance` | PostgreSQL schema for governance tables. |
| `EP_MODE` | Yes | `enforced` | Operating mode. Must be `enforced` or `advisory`. Use `enforced` for production. |
| `EP_PROXY_TARGET_URL` | Yes | — | Target DB connection string. The proxy uses this to execute agent SQL. URL-encode passwords. |
| `EP_PROXY_AUDIENCE` | No | `postgres-proxy` | Expected `aud` claim in the Ed25519 token. Must match what the EP service mints. |
| `EP_PROXY_PORT` | No | `8201` | Port the proxy listens on. |
| `EP_EP_SERVICE_ID` | Yes | — | XID of the EP service principal (e.g., `d9ll4o7ug6j0oak02ck0`). Used for token validation. |
| `EP_PUBLIC_KEY` | Yes | — | Hex-encoded Ed25519 public key. The proxy uses this to verify tokens. **Must not** be the private key. |

### EP service environment

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `EP_MODE` | Yes | `enforced` | Operating mode. Must be `enforced` for proxy-gated execution. |
| `EP_DB_URL` | Yes | — | Governance DB connection string. The EP service uses `ep_service` or equivalent credentials — **not** `ep_proxy_user`. |
| `EP_DB_SCHEMA` | No | `ep_governance` | PostgreSQL schema for governance tables. |
| `EP_MCP_TRANSPORT` | No | `stdio` | MCP server transport: `stdio` or `http`. |
| `EP_MCP_PORT` | No | `8200` | MCP server port (when transport is `http`). |
| `EP_MCP_TLS_CERT` | No | — | Path to TLS certificate for MCP HTTP server. |
| `EP_MCP_TLS_KEY` | No | — | Path to TLS private key for MCP HTTP server. |
| `EP_MCP_ALLOWED_HOSTS` | No | — | Comma-separated list of allowed client host IPs/hostnames. |
| `EP_TOKEN_TTL_SECONDS` | No | `300` | Token time-to-live in seconds. Tokens expire after this window. |
| `EP_NOTIFY` | No | `native` | Notification backend: `native` (PostgreSQL LISTEN/NOTIFY), `nats`, or `none`. |
| `EP_NATS_URL` | No | — | NATS server URL (when `EP_NOTIFY=nats`). |
| `EP_EMBEDDING_PROVIDER` | No | `none` | Embedding provider: `ollama`, `openai`, `cohere`, or `none`. |
| `EP_EMBEDDING_MODEL` | No | — | Model name for the embedding provider. |
| `EP_EMBEDDING_HOST` | No | — | Host URL for the embedding provider (e.g., Ollama endpoint). |
| `EP_EMBEDDING_API_KEY` | No | — | API key for the embedding provider (if required). |
| `EP_EP_SERVICE_ID` | Yes | — | XID of the EP service principal. |
| `EP_PUBLIC_KEY` | Yes | — | Hex-encoded Ed25519 public key (same value as proxy). |
| `EP_DEV` | No | `false` | Development mode flag. Set to `true` or `1` to enable dev features. **Never** enable in production. |
| `EP_BOOTSTRAP_TOKEN_HASH` | No | — | Hash of the bootstrap token for initial setup. |

### Security checklist

- [ ] `.env.proxy` has `0600` permissions and is in `.gitignore`
- [ ] `EP_PROXY_TARGET_URL` password is URL-encoded
- [ ] `EP_DB_URL` and `EP_PROXY_TARGET_URL` use different credentials
- [ ] `EP_PUBLIC_KEY` is the public key (not private) on the proxy host
- [ ] Ed25519 private key is only on the EP-service host (not in `.env` files)
- [ ] Firewall blocks target DB port (5432) from all hosts except the proxy
- [ ] Firewall blocks proxy port (8201) from all non-Tailscale interfaces
- [ ] PostgreSQL TLS is enabled on the target DB
- [ ] `pg_hba.conf` requires `hostssl` for `ep_proxy_user`
- [ ] `ep_proxy_user` password changed from the migration placeholder
- [ ] Agent host has no `EP_PROXY_TARGET_URL` or `ep_proxy_user` credentials
- [ ] Docker container runs with `no-new-privileges` and `cap_drop: ALL`
- [ ] Health check reports `healthy`
- [ ] `restart: unless-stopped` is set
- [ ] Audit log (`ep_events`) is INSERT-only (no UPDATE/DELETE) — verified via §9.5
- [ ] `ep_proxy_user` cannot access the `ep_governance` schema — verified via §9.6
