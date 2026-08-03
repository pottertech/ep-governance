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
10. [Agent Runtime Lockdown](#10-agent-runtime-lockdown)
11. [Launcher and Configuration Protection](#11-launcher-and-configuration-protection)
12. [Capability Inventory](#12-capability-inventory)
13. [Bypass Detection and Reconciliation](#13-bypass-detection-and-reconciliation)
14. [Multiple Narrowly-Scoped Proxies](#14-multiple-narrowly-scoped-proxies)
15. [Preventing Alternate Tool Paths](#15-preventing-alternate-tool-paths)
16. [Production Mode Configuration](#16-production-mode-configuration)
17. [Environment Variable Reference](#17-environment-variable-reference)

---

## 1. Architecture Overview

```
 ┌──────────────┐         ┌─────────────────────┐         ┌──────────────────┐
 │  EP Service   │  token  │   Governed Proxy     │  SQL    │   Target DB       │
 │  (MCP server) │────────▶│   (Docker, port 8201)│────────▶│   (PostgreSQL)    │
 │  No target DB │         │   Owns DB creds      │         │   TLS enabled     │
 └──────────────┘         └─────────────────────┘         └──────────────────┘
        │                          │
        │                          ▼
        │                 ┌─────────────────────┐
        │                 │  Governance DB       │
        └────────────────▶│  (ep_governance      │
                          │   schema)             │
                          └─────────────────────┘
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

| Secret | Purpose |
|--------|---------|
| `EP_DB_URL` | Connects to governance DB (audit log, policy tables) |
| `EP_PROXY_TARGET_URL` | Connects to target DB (executes agent SQL) |
| `EP_PUBLIC_KEY` | Ed25519 public key (verifies tokens, cannot mint them) |
| `EP_EP_SERVICE_ID` | XID of the EP service principal |

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

## 10. Agent Runtime Lockdown

The governed proxy is the only path to the target database, but enforcement only holds if the **agent process itself** cannot circumvent the proxy. A proxy that owns the DB credentials provides no protection if the agent can spawn a shell, reach the DB over a raw socket, or read a credentials file off disk. This section defines the runtime constraints every agent process must run under in production.

### 10.1 Hardening rules

The agent process (the MCP client, AI agent, or whatever invokes the EP service) must operate under the following restrictions in enforced mode:

| Rule | Why |
|------|-----|
| No host Docker socket access (`/var/run/docker.sock`) | Access to the Docker socket is root-equivalent on the host — the agent could start privileged containers, read any mounted secret, or escape the sandbox entirely. Never mount the Docker socket into the agent container. |
| No unrestricted shell | The agent must not be able to spawn an arbitrary interactive shell (`bash`, `sh`, `zsh`) that can run any command. Shell access, if present at all, must be a governed tool that routes through EP-Governance. |
| No mounted credential directories | The agent container/namespace must not have any bind-mount of host paths containing credentials: `~/.aws`, `~/.ssh`, `~/.config/gcloud`, `~/.kube`, `/etc/secrets`, Vault token caches, etc. |
| Read-only system filesystem | `/usr`, `/bin`, `/sbin`, `/lib`, `/etc` should be mounted read-only so the agent cannot install backdoors, replace binaries, or tamper with system configuration. |
| Restricted writable directories | The agent should only be able to write to a single scratch directory (e.g., `/tmp/agent-work`) with a size cap. All other paths are read-only or inaccessible. |
| No cloud instance metadata access | Block HTTP access to `169.254.169.254` (AWS/GCP) and `169.254.169.253` (GCP DNS). Instance metadata exposes IAM tokens and other temporary credentials the agent could use to reach protected services directly. |
| No inherited environment secrets | The agent's environment must not contain `EP_PROXY_TARGET_URL`, `EP_DB_URL`, cloud provider keys, or any credential that lets it bypass the proxy. Pass only `EP_EP_SERVICE_ID`, MCP endpoint URLs, and non-secret configuration. |
| Limited process execution | The agent should run under a restricted account that can only execute the agent binary and its declared dependencies — not `psql`, `curl`, `nc`, `python` with network libs, or other general-purpose tools. Use an allowlist. |
| No ability to install arbitrary software | The agent must not have `pip install`, `npm install`, `apt-get`, `apk add`, or package-manager access at runtime. All dependencies are baked into the image at build time. |

### 10.2 Container hardening

When the agent runs in a container (the recommended deployment), apply every one of the following hardening flags:

- **Non-root user** — run the agent process as a dedicated UID (e.g., `1001`) with no root group membership.
- **Dropped Linux capabilities** — `cap_drop: ALL`. The agent needs no capabilities.
- **Seccomp profile** — apply a default-deny seccomp profile (Docker's `--security-opt seccomp=<profile.json>` or Kubernetes `seccompProfile: RuntimeDefault`).
- **AppArmor or SELinux** — enforce a profile that confines the agent to its expected filesystem and network paths.
- **Read-only root filesystem** — `read_only: true` in Compose / `readOnlyRootFilesystem: true` in Kubernetes. Mount a `tmpfs` for the single writable scratch directory.
- **Resource limits** — set CPU and memory limits to prevent the agent from exhausting host resources or using resource exhaustion as a side-channel.
- **Explicit volume mounts** — only mount the specific directories the agent needs (e.g., its workspace). Never mount host paths broadly.

### 10.3 Example: hardened Docker run command

```bash
docker run -d \
  --name agent \
  --user 1001:1001 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --security-opt seccomp=/etc/docker/seccomp-agent.json \
  --security-opt apparmor=agent-profile \
  --tmpfs /tmp/agent-work:size=100m,mode=0700 \
  --memory=2g --cpus=2 \
  --network=ep-internal \
  --env EP_EP_SERVICE_ID=d9ll4o7ug6j0oak02ck0 \
  --env EP_MCP_URL=https://100.64.0.30:8200 \
  -v /srv/agent/workspace:/workspace:ro \
  agent-image:latest
```

Key points: no Docker socket mounted, root filesystem read-only, all capabilities dropped, a single writable tmpfs, and only non-secret environment variables. The `ep-internal` network is a Docker network that can reach the EP service and proxy but **not** the target DB host.

### 10.4 Example: hardened Kubernetes pod security context

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: agent
  labels:
    app: ep-agent
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1001
    runAsGroup: 1001
    fsGroup: 1001
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: agent
      image: agent-image:latest
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 1001
        capabilities:
          drop:
            - ALL
      resources:
        limits:
          cpu: "2"
          memory: 2Gi
        requests:
          cpu: "500m"
          memory: 512Mi
      volumeMounts:
        - name: workspace
          mountPath: /workspace
          readOnly: true
        - name: scratch
          mountPath: /tmp/agent-work
      env:
        - name: EP_EP_SERVICE_ID
          value: "d9ll4o7ug6j0oak02ck0"
        - name: EP_MCP_URL
          value: "https://100.64.0.30:8200"
  volumes:
    - name: workspace
      persistentVolumeClaim:
        claimName: agent-workspace
    - name: scratch
      emptyDir:
        sizeLimit: 100Mi
```

The pod has no host path mounts, no privileged containers, a default-deny seccomp profile, a read-only root filesystem, and only non-secret environment variables.

---

## 11. Launcher and Configuration Protection

The agent's **identity** — its principal ID, which proxy it talks to, which enforcement mode is active, and where policy comes from — is fixed at launch time. If the agent process can change any of these after it starts, it can re-point itself at a weaker proxy, disable enforcement, or assume a different principal. The launcher and configuration that establish identity must therefore be protected from modification by the agent.

### 11.1 What the agent must not be able to change

The following values are set by the launcher and must be immutable from the agent's perspective:

| Value | Why it must be fixed |
|-------|---------------------|
| Principal ID (`EP_EP_SERVICE_ID` or agent principal) | Changing the principal lets the agent impersonate another agent with different permissions. |
| Proxy endpoint (`EP_PROXY_TARGET_URL` / proxy host) | The agent must not be able to re-point at a different, weaker, or fake proxy. |
| Enforcement mode (`EP_MODE`) | The agent must not be able to downgrade from `enforced` to `advisory`. |
| Policy source | The agent must not be able to swap the governance DB or policy tables for ones it controls. |
| Environment variables | The agent must not be able to inject credentials, change the MCP endpoint, or unset enforcement flags. |
| Startup command | The agent must not be able to replace its own launcher with a script that skips governance initialization. |
| Configuration files | Any `.env`, YAML, or JSON config that feeds the above must be read-only to the agent. |

### 11.2 Implementation: ownership and read-only mounts

All launcher scripts, configuration files, and environment files must be:

1. **Owned by an administrator account** — not the account the agent runs as. On Linux, `chown root:root` (or a dedicated `epadmin` user) with `chmod 0640`.
2. **Mounted read-only into the agent's filesystem namespace** — bind-mount the config directory with `:ro` in Docker, or use a `readOnly: true` volume in Kubernetes.
3. **Injected as environment at launch time** — the launcher (systemd, Docker entrypoint, or Kubernetes init) reads the admin-owned config and exports the variables into the agent process. The agent never reads the config file directly.

### 11.3 Example: docker-compose with read-only config mount

```yaml
services:
  agent:
    image: agent-image:latest
    user: "1001:1001"
    read_only: true
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp/agent-work:size=100m
    volumes:
      # Config is owned by root on the host, mounted read-only.
      # The entrypoint reads it and exports env vars to the agent process.
      - type: bind
        source: /srv/ep-governance/agent-config
        target: /etc/ep-governance
        read_only: true
      - type: bind
        source: /srv/agent/workspace
        target: /workspace
        read_only: true
    environment:
      - EP_EP_SERVICE_ID=d9ll4o7ug6j0oak02ck0
      - EP_MCP_URL=https://100.64.0.30:8200
    entrypoint: ["/usr/local/bin/ep-agent-launcher"]
    command: ["--config", "/etc/ep-governance/agent.env"]
    networks:
      - ep-internal

networks:
  ep-internal:
    driver: bridge
```

On the host, `/srv/ep-governance/agent-config` is owned by `root:root` with mode `0640`. The agent UID `1001` cannot read it directly — only the launcher (which starts as root, reads the config, drops privileges, then execs the agent) can.

### 11.4 Example: systemd unit with ProtectSystem=strict

For bare-metal or VM deployments, use systemd's built-in filesystem protection:

```ini
[Unit]
Description=EP-Governance Agent
After=network-online.target

[Service]
Type=simple
User=epagent
Group=epagent

# Read the admin-owned config file and export its variables
EnvironmentFile=/etc/ep-governance/agent.env

# Filesystem protection
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/ep-agent/work

# Namespace isolation
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true

# Capability and privilege restrictions
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=

# Resource limits
LimitNOFILE=1024
LimitNPROC=64

ExecStart=/usr/local/bin/ep-agent --config /etc/ep-governance/agent.env
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

`ProtectSystem=strict` makes the entire filesystem read-only except for paths listed in `ReadWritePaths`. The config file `/etc/ep-governance/agent.env` is owned by `root:root` with mode `0640` — the `epagent` user cannot modify it. `EnvironmentFile=` injects the variables at launch; the agent process inherits them but cannot change the file.

---

## 12. Capability Inventory

Enforced mode is only as strong as the **completeness** of the path enumeration. If the agent has a tool or plugin that can reach a protected target without going through EP-Governance, enforcement is bypassed — regardless of how strong the proxy's token validation is. A capability inventory is a structured enumeration of every possible path from the agent to each protected target, with a determination of whether each path is governed, removed, or a bypass risk.

### 12.1 What to enumerate

For each protected target (target DB, governance DB, cloud APIs, email service, deployment system, etc.), list every mechanism by which the agent process could reach it:

| Path type | Examples |
|-----------|----------|
| **Tools** | MCP tools, CLI tools, built-in functions the agent can call |
| **Plugins** | Database plugins, HTTP plugins, cloud SDK plugins loaded into the agent runtime |
| **Shell access** | `bash`, `sh`, `python -c`, `node -e`, or any REPL the agent can invoke |
| **Network paths** | Raw TCP/UDP sockets, HTTP clients, DNS, any network library available to the agent |
| **Database drivers** | `psycopg2`, `asyncpg`, `sqlalchemy`, `pg8000`, ODBC, JDBC — anything that can open a DB connection |
| **Filesystem credentials** | Any file on disk or in a mounted volume that contains credentials for a protected target |
| **Cloud SDKs** | `boto3`, `google-cloud-*`, `azure-sdk` — if present, the agent can reach cloud APIs directly |
| **Environment variables** | Any env var in the agent's process that contains a credential or connection string |
| **Inherited processes** | Subprocesses spawned by the agent that may have broader access than the agent itself |

### 12.2 Inventory template

For each protected target, fill in a table like the following. This is the artifact that auditors and operators review before declaring the deployment "enforced."

```markdown
### Protected target: PostgreSQL target_db (100.64.0.10:5432)

| # | Path type | Specific mechanism | Governed? | Action |
|---|-----------|-------------------|-----------|--------|
| 1 | MCP tool | `ep_governance.execute_sql` | Yes — routes through proxy | Keep |
| 2 | Shell | `shell.exec` → `psql` | No — direct DB access | Remove tool or block `psql` |
| 3 | Python driver | `python` with `psycopg2` | No — direct DB access | Remove `psycopg2` from image |
| 4 | Network | Raw TCP to 100.64.0.10:5432 | No — direct connection | Firewall: block at network layer (§4) |
| 5 | Env var | `EP_PROXY_TARGET_URL` in agent env | No — credential exposure | Remove from agent env (§10.1) |
| 6 | Filesystem | `/srv/secrets/db-creds.json` mounted | No — credential exposure | Unmount; proxy owns creds |
| 7 | Cloud SDK | N/A (no cloud SDK for Postgres) | — | — |
| 8 | Other DB plugin | `database.query` MCP tool | No — direct DB access | Remove plugin or route through proxy |
```

### 12.3 Governing or removing each path

Every row in the inventory must end with one of two outcomes:

- **Governed** — the path routes through EP-Governance (the proxy validates a token, checks policy, executes, and audits). Keep it.
- **Removed** — the path is eliminated: the tool is uninstalled, the library is not in the image, the network route is firewalled, the credential is not present. There is no third option. A path that is "neither governed nor removed" is a bypass.

### 12.4 Periodic re-inventory

The capability inventory is not a one-time exercise. Re-run it whenever:

1. **A new tool or plugin is added** to the agent runtime — before it goes live, enumerate what it can reach.
2. **A new protected target is added** — enumerate all paths to it.
3. **The agent image is rebuilt** — verify that no new libraries, CLI tools, or network utilities were introduced by a dependency.
4. **Quarterly** as a routine audit — catch drift from config changes, new environment variables, or network policy changes.

Store the inventory in version control alongside the deployment config. Review changes in PR review just like code changes.

---

## 13. Bypass Detection and Reconciliation

Even with a complete capability inventory and runtime lockdown, deployments drift and new paths appear. Bypass detection is the operational layer that catches circumvention — whether accidental or adversarial — by comparing what the protected targets observe against what EP-Governance authorized.

### 13.1 What to monitor for

| Signal | Description | Detection method |
|--------|-------------|------------------|
| Direct agent connections to protected services | The agent process opens a connection to the target DB, cloud API, or email service without going through the proxy. | Network-level: egress flow logs, TCP connection logs on the target host. Compare source IPs to the proxy's IP. |
| Credentials used outside proxy identity | A DB credential or API key that should only exist in the proxy is used from a different source. | DB-level: `pg_stat_activity` source IP audit; cloud API: access logs showing unexpected caller identity. |
| Actions in target without EP audit records | A query, API call, or write occurred on the protected target, but no corresponding `ep_events` row exists in the governance DB. | Reconciliation check (§13.2). |
| Unexpected outbound destinations | The agent process connects to a host that is not the EP service or an approved external API. | Egress monitoring: `iptables LOG`, eBPF-based connection logging (e.g., Falco, Tetragon), or cloud VPC flow logs. |
| Unauthorized subprocesses | The agent spawns a process that is not in its allowlist (e.g., `psql`, `curl`, `nc`, `python`). | Process monitoring: Falco rules for `execve` on unexpected binaries; auditd `EXECVE` events. |
| Changes while EP was unavailable | The proxy or EP service was down, but target DB activity occurred during that window. | Compare proxy downtime windows (health check gaps) against target DB activity logs. Any activity during a gap is suspicious. |

### 13.2 Reconciliation check

The core bypass-detection mechanism is a **reconciliation check** that compares the target's activity log against EP-Governance's authorized-action log. Every action on the protected target should have a matching authorization record. Any target action without a matching EP authorization is a potential bypass.

For PostgreSQL, the target's activity can be captured via `pgaudit` (session audit logging) or `pg_stat_statements`. The EP authorized-action log is the `ep_events` table in the governance DB.

**Reconciliation procedure:**

1. For a given time window (e.g., the last hour), query the target DB's audit log for all SQL executed by `ep_proxy_user`.
2. For the same window, query `ep_governance.ep_events` for all `EXECUTE` events authorized by the proxy.
3. Join the two logs on a correlation key (e.g., a transaction ID or timestamp window).
4. Any target-side action with no matching EP event is a bypass. Generate an alert.

### 13.3 Example reconciliation script

```python
"""
reconcile.py — Compare target DB audit log against EP-Governance
authorized-action log. Any target action without a matching EP
authorization is flagged as a potential bypass.

Run hourly via cron or a scheduled task.
"""
import os
import sys
import psycopg2
from datetime import datetime, timedelta, timezone


def reconcile(window_minutes: int = 60) -> list[dict]:
    now = datetime.now(timezone.utc)
    since = now - timedelta(minutes=window_minutes)

    # Target DB: query pgaudit log for actions by ep_proxy_user
    target = psycopg2.connect(os.environ["EP_PROXY_TARGET_URL"])
    target.autocommit = True
    cur = target.cursor()
    cur.execute(
        """
        SELECT
            statement_timestamp,
            session_line_num,
            record_message
        FROM pgaudit.log
        WHERE user_name = 'ep_proxy_user'
          AND statement_timestamp >= %s
        ORDER BY statement_timestamp
        """,
        (since,),
    )
    target_actions = cur.fetchall()
    cur.close()
    target.close()

    # Governance DB: query ep_events for authorized EXECUTE events
    gov = psycopg2.connect(os.environ["EP_DB_URL"])
    gov.autocommit = True
    cur = gov.cursor()
    cur.execute(
        """
        SELECT
            created_at,
            event_type,
            details
        FROM ep_governance.ep_events
        WHERE event_type = 'EXECUTE'
          AND created_at >= %s
        ORDER BY created_at
        """,
        (since,),
    )
    ep_events = cur.fetchall()
    cur.close()
    gov.close()

    # Build set of authorized timestamps (within a small tolerance)
    authorized_times = [
        row[0].replace(tzinfo=timezone.utc) for row in ep_events
    ]

    bypasses = []
    for ts, line_num, message in target_actions:
        ts = ts.replace(tzinfo=timezone.utc) if ts.tzinfo else ts
        # Match within a 5-second tolerance
        matched = any(
            abs((ts - auth_ts).total_seconds()) < 5
            for auth_ts in authorized_times
        )
        if not matched:
            bypasses.append({
                "timestamp": ts.isoformat(),
                "line": line_num,
                "message": message,
            })

    return bypasses


if __name__ == "__main__":
    results = reconcile()
    if results:
        print(f"ALERT: {len(results)} unauthorized target action(s) detected:")
        for b in results:
            print(f"  {b['timestamp']} (line {b['line']}): {b['message'][:120]}")
        sys.exit(1)
    else:
        print(f"OK: All target actions have matching EP authorizations.")
        sys.exit(0)
```

### 13.4 Integration with monitoring systems

Reconciliation results and bypass signals should flow into the same monitoring infrastructure as the rest of the deployment:

| System | Integration |
|--------|-------------|
| **NATS** | Publish bypass alerts to a `ep.governance.bypass` subject. Subscribe in a notification service that pages on-call. EP-Governance already supports NATS for event notifications (`EP_NOTIFY=nats`). |
| **Syslog** | Forward reconciliation script output and Falco/Tetragon alerts to a central syslog server. Use `logger` from the reconciliation cron job: `logger -t ep-reconcile -p user.alert "Bypass detected: ..."`. |
| **SIEM** | Ship both the EP-Governance `ep_events` audit log and the target DB's audit log to a SIEM (Splunk, Elastic, Datadog). Create a correlation rule: `target_db_action WHERE NOT EXISTS (ep_events.action MATCH) → alert`. |

For Falco/Tetragon eBPF-based runtime monitoring, deploy rules that alert on:

- The agent process opening a TCP connection to any host other than the EP service and the proxy.
- The agent process executing `psql`, `nc`, `curl`, `python`, or any binary not in the allowlist.
- The agent process reading files under `/etc/secrets`, `~/.aws`, `~/.ssh`, or other credential paths.

---

## 14. Multiple Narrowly-Scoped Proxies

A single universal proxy with broad admin credentials is a concentration of risk. If that proxy's credentials are compromised, the attacker has full access to every protected target. More importantly, a single proxy cannot enforce **principle of least privilege** — its credential must be powerful enough for the most privileged operation any agent might need, which means every agent implicitly has that power.

The solution is to deploy **multiple narrowly-scoped proxies**, each with credentials that permit only what that proxy needs. An agent that needs to run reports uses the read-only DB proxy. An agent that needs to file a GitHub issue uses the GitHub proxy. Neither proxy has the other's credentials.

### 14.1 Proxy scoping

| Proxy | Credential scope | Allowed operations | Denied operations |
|-------|-----------------|-------------------|-------------------|
| `ep-proxy-db-readonly` | DB role: `ep_report_user` (SELECT only) | `SELECT` on public tables | `INSERT`, `UPDATE`, `DELETE`, `DROP`, `ALTER`, `CREATE`, access to `secret_tables` schema |
| `ep-proxy-db-write` | DB role: `ep_writer_user` (controlled DML) | `INSERT`, `UPDATE`, `DELETE` on approved tables | `DROP TABLE`, `ALTER ROLE`, `CREATE EXTENSION`, `TRUNCATE`, schema changes, access to `secret_tables` |
| `ep-proxy-github` | GitHub PAT: `repo:issues` scope only | Create/comment on issues in specified repos | Push commits, merge PRs, delete branches, admin settings |
| `ep-proxy-deploy` | Deployment API key: deploy to staging only | Trigger staging deployments | Production deployments, rollback, config changes |
| `ep-proxy-email` | SMTP credentials: sender-only | Send emails from a fixed address | Read mailbox, delete messages, modify mail config |
| `ep-proxy-fs` | Filesystem: restricted directory | Read/write within `/srv/agent-output` | Access to `/etc`, `/root`, credential dirs, system paths |

A **report proxy** (read-only DB) should not have `DROP TABLE`, `ALTER ROLE`, `CREATE EXTENSION`, or access to `secret_tables`. If the agent's task is to generate a report, it only needs `SELECT` on public tables — give it exactly that and nothing more.

### 14.2 Example: docker-compose with multiple proxy services

```yaml
services:
  ep-proxy-db-readonly:
    build:
      context: .
      dockerfile: docker/proxy/Dockerfile
    container_name: ep-proxy-db-readonly
    restart: unless-stopped
    network_mode: host
    environment:
      EP_DB_URL: "postgresql://gov_user:***@100.64.0.10:5432/governance_db"
      EP_DB_SCHEMA: ep_governance
      EP_MODE: enforced
      EP_PROXY_TARGET_URL: "postgresql://ep_report_user:***@100.64.0.10:5432/target_db"
      EP_PROXY_AUDIENCE: postgres-readonly
      EP_PROXY_PORT: "8201"
      EP_EP_SERVICE_ID: "d9ll4o7ug6j0oak02ck0"
      EP_PUBLIC_KEY: "${EP_PUBLIC_KEY}"
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL

  ep-proxy-db-write:
    build:
      context: .
      dockerfile: docker/proxy/Dockerfile
    container_name: ep-proxy-db-write
    restart: unless-stopped
    network_mode: host
    environment:
      EP_DB_URL: "postgresql://gov_user:***@100.64.0.10:5432/governance_db"
      EP_DB_SCHEMA: ep_governance
      EP_MODE: enforced
      EP_PROXY_TARGET_URL: "postgresql://ep_writer_user:***@100.64.0.10:5432/target_db"
      EP_PROXY_AUDIENCE: postgres-write
      EP_PROXY_PORT: "8202"
      EP_EP_SERVICE_ID: "d9ll4o7ug6j0oak02ck0"
      EP_PUBLIC_KEY: "${EP_PUBLIC_KEY}"
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL

  ep-proxy-github:
    build:
      context: .
      dockerfile: docker/proxy/Dockerfile
    container_name: ep-proxy-github
    restart: unless-stopped
    network_mode: host
    environment:
      EP_DB_URL: "postgresql://gov_user:***@100.64.0.10:5432/governance_db"
      EP_DB_SCHEMA: ep_governance
      EP_MODE: enforced
      EP_PROXY_TARGET_URL: "github://issues"
      EP_PROXY_GITHUB_TOKEN: "${GITHUB_ISSUE_PAT}"
      EP_PROXY_AUDIENCE: github-issues
      EP_PROXY_PORT: "8203"
      EP_EP_SERVICE_ID: "d9ll4o7ug6j0oak02ck0"
      EP_PUBLIC_KEY: "${EP_PUBLIC_KEY}"
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL

  ep-proxy-email:
    build:
      context: .
      dockerfile: docker/proxy/Dockerfile
    container_name: ep-proxy-email
    restart: unless-stopped
    network_mode: host
    environment:
      EP_DB_URL: "postgresql://gov_user:***@100.64.0.10:5432/governance_db"
      EP_DB_SCHEMA: ep_governance
      EP_MODE: enforced
      EP_PROXY_TARGET_URL: "smtp://smtp.internal:587"
      EP_PROXY_SMTP_USER: "agent@internal"
      EP_PROXY_SMTP_PASS: "${SMTP_SENDER_PASS}"
      EP_PROXY_AUDIENCE: email-send
      EP_PROXY_PORT: "8204"
      EP_EP_SERVICE_ID: "d9ll4o7ug6j0oak02ck0"
      EP_PUBLIC_KEY: "${EP_PUBLIC_KEY}"
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
```

Each proxy listens on a different port, uses a different `EP_PROXY_AUDIENCE` (so a token minted for the read-only proxy is rejected by the write proxy), and has credentials scoped to exactly its purpose. The EP service mints tokens with the correct `aud` claim for the target proxy — the agent cannot use a read-only token against the write proxy.

### 14.3 Proxy scoping matrix

| Proxy type | Port | Credential scope | Allowed operations | Explicitly denied |
|-----------|------|-----------------|-------------------|-------------------|
| Read-only DB | 8201 | `ep_report_user`: SELECT on public tables | `SELECT` | `INSERT/UPDATE/DELETE`, `DROP`, `ALTER`, `CREATE EXTENSION`, `secret_tables` schema |
| Controlled DB-write | 8202 | `ep_writer_user`: DML on approved tables | `INSERT`, `UPDATE`, `DELETE` | `DROP TABLE`, `ALTER ROLE`, `CREATE EXTENSION`, `TRUNCATE`, schema DDL, `secret_tables` |
| GitHub issues | 8203 | PAT with `repo:issues` | Create/comment issues | Push, merge, delete, admin |
| Deployment (staging) | 8204 | Deploy API key: staging only | Trigger staging deploys | Production deploys, rollback, config |
| Email send | 8205 | SMTP sender credentials | Send from fixed address | Read/delete mailbox, config changes |
| Restricted filesystem | 8206 | FS access: `/srv/agent-output` only | Read/write in that dir | `/etc`, `/root`, credential paths |

---

## 15. Preventing Alternate Tool Paths

Adding a governed PostgreSQL proxy does not help if the agent also has `shell.exec` that can run `psql`, a Python tool that can `import psycopg2`, generic TCP access to the DB host, or another database plugin that connects directly. **Every tool capable of performing a governed action must either route through EP-Governance or be removed.** There is no "monitor only" option for a tool that can bypass enforcement.

### 15.1 The alternate-path problem

Consider an agent with the following tools:

| Tool | What it can do |
|------|---------------|
| `ep_governance.execute_sql` | Executes SQL through the governed proxy (token-gated, audited) |
| `shell.exec` | Runs arbitrary shell commands — including `psql -h 100.64.0.10 ...` |
| `python.run` | Runs Python — including `import psycopg2; psycopg2.connect(...)` |
| `http.request` | Sends HTTP requests — including to cloud APIs with inherited credentials |
| `database.query` (another MCP plugin) | Connects to PostgreSQL directly with its own credentials |

The `ep_governance.execute_sql` tool is governed, but the other four tools can all reach the target DB (or other protected targets) without going through the proxy. Enforcement is effectively bypassed. The agent could call `shell.exec("psql ...")` and execute arbitrary SQL with no token, no policy check, and no audit trail.

### 15.2 Capability inventory for each protected target

For each protected target, enumerate every tool that can reach it. This is the same capability inventory from §12, but focused on **tools** rather than runtime capabilities:

```markdown
### Protected target: PostgreSQL target_db

| Tool | Can reach target? | Governed? | Action |
|------|-------------------|-----------|--------|
| ep_governance.execute_sql | Yes (via proxy) | Yes | Keep |
| shell.exec | Yes (psql, pg_dump) | No | Remove or restrict to allowlist |
| python.run | Yes (psycopg2, asyncpg) | No | Remove psycopg2/asyncpg from image, or remove tool |
| http.request | No (Postgres is TCP, not HTTP) | — | — |
| database.query (plugin) | Yes (direct connection) | No | Remove plugin |
```

### 15.3 Tool removal checklist

For each tool that can reach a protected target but does not route through EP-Governance:

- [ ] **Remove the tool entirely** — if the agent does not need it, uninstall it. This is the safest option.
- [ ] **If the tool must remain, restrict it** — if `shell.exec` is needed for non-DB tasks, restrict it to an allowlist of commands that excludes `psql`, `pg_dump`, `nc`, `curl`, `python`, `node`, and any other binary that can open a network connection or load a DB driver.
- [ ] **Remove the library from the image** — if `python.run` must remain, build the image without `psycopg2`, `asyncpg`, `sqlalchemy`, `pg8000`, `pymysql`, and any other DB driver. Verify with a post-build scan (`pip list | grep -i 'psycopg\|asyncpg\|sqlalchemy\|pg8000'`).
- [ ] **Block the network path** — even if the tool is present, firewall rules (§4) should prevent direct connections to the target DB from the agent host. This is defense-in-depth, not a substitute for tool removal.
- [ ] **Remove credentials** — the agent should not have any credential that a direct-connection tool could use. If `psycopg2` is present but there is no DB connection string in the environment or on disk, it cannot connect. But do not rely on this alone — credentials can be discovered.
- [ ] **Document the decision** — for each tool that is kept (restricted or otherwise), record why it was not removed and what mitigations are in place. This goes in the capability inventory (§12).

The rule is absolute: **a tool that can perform a governed action without routing through EP-Governance is a bypass, regardless of whether the agent has used it.** Remove it or govern it before the deployment is considered "enforced."

---

## 16. Production Mode Configuration

EP-Governance ships with configuration flags that enforce production-grade safety. In production, advisory mode is rejected, all actions require signed authorization, and the proxy fails closed if governance is unavailable. These flags are enforced at config load time in `src/ep_governance/config.py` and at proxy startup in `proxy_service.py` — they cannot be overridden by the agent.

### 16.1 Production environment variables

| Variable | Required in production | Production value | Description |
|----------|----------------------|------------------|-------------|
| `EP_MODE` | Yes | `enforced` | Operating mode. Must be `enforced` in production. Advisory mode is rejected at config load time unless `EP_DEV=true` and `EP_ALLOW_ADVISORY_EXECUTION=true`. |
| `EP_ALLOW_ADVISORY_EXECUTION` | Yes | `false` | When `false`, advisory mode is rejected entirely. Advisory mode can remain in development (`EP_DEV=true` and `EP_ALLOW_ADVISORY_EXECUTION=true`), but production proxies refuse to start if advisory is selected. |
| `EP_REQUIRE_SIGNED_AUTHORIZATION` | Yes | `true` | When `true`, all actions require a signed Ed25519 token. The proxy will not execute any action without a valid signed authorization. This prevents unsigned or advisory bypass of the token check. |
| `EP_FAIL_CLOSED` | Yes | `true` | When `true`, the proxy refuses to execute if the governance service (policy lookup, audit logging) is unavailable. The agent's action fails rather than proceeding without oversight. Set to `false` only in development. |

### 16.2 Advisory mode rejection

The config loader (`load_config()` in `src/ep_governance/config.py`) enforces the following logic at startup:

1. If `EP_MODE=advisory` and `EP_DEV` is not `true`, the config load raises `ConfigError` and the process exits. Advisory mode is not permitted in production.
2. If `EP_MODE=advisory` and `EP_DEV=true` but `EP_ALLOW_ADVISORY_EXECUTION` is not `true`, the config load raises `ConfigError`. Advisory mode requires explicit opt-in even in development.
3. The proxy service (`proxy_service.py`) refuses to start in advisory mode in production — it checks the mode and exits with an error if advisory is selected and `EP_DEV` is not set.

This means: **in production, there is no way to run in advisory mode.** The only way to use advisory mode is to explicitly set `EP_DEV=true` and `EP_ALLOW_ADVISORY_EXECUTION=true`, which disables production safety flags and should never be done outside a development environment.

### 16.3 Example production `.env` for the EP service

```dotenv
# EP service production .env (on the EP-service host)
# Permissions: 0600, owned by epadmin. Never committed to git.

EP_MODE=enforced
EP_ALLOW_ADVISORY_EXECUTION=false
EP_REQUIRE_SIGNED_AUTHORIZATION=true
EP_FAIL_CLOSED=true

EP_DB_URL=postgresql://ep_service_user:***@100.64.0.10:5432/governance_db
EP_DB_SCHEMA=ep_governance

EP_MCP_TRANSPORT=http
EP_MCP_PORT=8200
EP_MCP_TLS_CERT=/etc/ep-governance/tls/server.crt
EP_MCP_TLS_KEY=/etc/ep-governance/tls/server.key
EP_MCP_ALLOWED_HOSTS=100.64.0.40

EP_TOKEN_TTL_SECONDS=300
EP_EP_SERVICE_ID=d9ll4o7ug6j0oak02ck0
EP_PUBLIC_KEY=<hex-encoded Ed25519 public key>
# EP_PRIVATE_KEY is injected via Vault or sealed secret — never in a plaintext env file

EP_NOTIFY=native
```

### 16.4 Example production `.env` for the proxy

```dotenv
# Proxy production .env (on the proxy host)
# Permissions: 0600, owned by epadmin. Never committed to git.

EP_MODE=enforced
EP_ALLOW_ADVISORY_EXECUTION=false
EP_REQUIRE_SIGNED_AUTHORIZATION=true
EP_FAIL_CLOSED=true

EP_DB_URL=postgresql://gov_user:***@100.64.0.10:5432/governance_db
EP_DB_SCHEMA=ep_governance
EP_PROXY_TARGET_URL=postgresql://ep_proxy_user:***@100.64.0.10:5432/target_db
EP_PROXY_AUDIENCE=postgres-proxy
EP_PROXY_PORT=8201
EP_EP_SERVICE_ID=d9ll4o7ug6j0oak02ck0
EP_PUBLIC_KEY=<hex-encoded Ed25519 public key>
```

### 16.5 Verification

After starting the EP service and proxy with these production flags, verify:

```bash
# On the proxy host: confirm it started in enforced mode
docker exec ep-governance-proxy env | grep EP_MODE
# Expected: EP_MODE=enforced

# Attempt to start the proxy with EP_MODE=advisory (should fail):
EP_MODE=advisory docker compose -f docker/proxy/docker-compose.proxy.yml up
# Expected: ConfigError: Advisory mode is not permitted in production.

# Confirm signed authorization is required (unsigned request rejected):
curl -X POST http://100.64.0.20:8201/execute \
  -H 'Content-Type: application/json' \
  -d '{"sql": "SELECT 1"}'
# Expected: 401 Unauthorized — signed token required

# Confirm fail-closed behavior: stop the governance DB, then attempt an action.
# The proxy should refuse to execute and return an error, not proceed without auditing.
```

---

## 17. Environment Variable Reference

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
- [ ] Agent container has no host Docker socket (`/var/run/docker.sock`) mounted (§10)
- [ ] Agent runs as a non-root user with all Linux capabilities dropped (§10)
- [ ] Agent container has a read-only root filesystem with a single writable tmpfs (§10)
- [ ] Agent has no mounted credential directories (`~/.aws`, `~/.ssh`, `~/.kube`, etc.) (§10)
- [ ] Cloud instance metadata endpoint (`169.254.169.254`) is blocked from the agent (§10)
- [ ] Agent environment contains no target DB credentials or cloud provider keys (§10)
- [ ] Agent cannot install arbitrary software (no `pip`, `npm`, `apt-get` at runtime) (§10)
- [ ] Seccomp profile (RuntimeDefault or custom) applied to agent container (§10)
- [ ] AppArmor or SELinux profile enforced on agent container (§10)
- [ ] CPU and memory limits set on agent container/pod (§10)
- [ ] Launcher script and config files owned by admin account, not the agent user (§11)
- [ ] Configuration files mounted read-only into agent filesystem (§11)
- [ ] Agent cannot modify `EP_EP_SERVICE_ID`, `EP_MODE`, proxy endpoint, or policy source (§11)
- [ ] systemd unit uses `ProtectSystem=strict` (or equivalent) for agent service (§11)
- [ ] Capability inventory completed for every protected target (§12)
- [ ] Every path in the inventory is either governed through EP-Governance or removed (§12)
- [ ] Capability inventory stored in version control and reviewed on changes (§12)
- [ ] Reconciliation check (target activity log vs EP authorized-action log) runs on schedule (§13)
- [ ] Bypass detection alerts flow to NATS, syslog, or SIEM (§13)
- [ ] Falco/Tetragon rules deployed for unauthorized subprocesses and egress (§13)
- [ ] Multiple narrowly-scoped proxies deployed instead of one universal proxy (§14)
- [ ] Each proxy's DB role has least-privilege permissions (no `DROP`, `ALTER`, `CREATE EXTENSION` unless needed) (§14)
- [ ] Each proxy uses a distinct `EP_PROXY_AUDIENCE` so tokens are not cross-usable (§14)
- [ ] Proxy scoping matrix documented and reviewed (§14)
- [ ] Every agent tool that can reach a protected target is governed or removed (§15)
- [ ] No DB drivers (`psycopg2`, `asyncpg`, `sqlalchemy`, `pg8000`) in agent image (§15)
- [ ] No ungoverned `shell.exec`, `python.run`, or direct-connect database plugin available to agent (§15)
- [ ] `EP_MODE=enforced` set in production for both EP service and proxy (§16)
- [ ] `EP_ALLOW_ADVISORY_EXECUTION=false` in production (§16)
- [ ] `EP_REQUIRE_SIGNED_AUTHORIZATION=true` in production (§16)
- [ ] `EP_FAIL_CLOSED=true` in production (§16)
- [ ] Proxy refuses to start in advisory mode without `EP_DEV=true` and `EP_ALLOW_ADVISORY_EXECUTION=true` (§16)