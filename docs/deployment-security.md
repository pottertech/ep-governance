# EP-Governance Deployment Security

**Version:** 1.0 (Phase 1)
**Date:** July 29, 2026
**Governing Sources:** v1.1.1 §8. Enforced mode deployment requirements.

---

## 1. Enforced Mode Deployment Requirements

To achieve binding enforcement (not merely advisory), the following six requirements MUST all be satisfied:

### 1.1 Requirement 1: Governed Proxy as Separate Process

- The governed proxy MUST run as a separate process (or container) with access to target credentials.
- The proxy MUST NOT run in the same process as the agent.
- The proxy MUST have its own network identity.

### 1.2 Requirement 2: No Target Credentials in Agent Environment

- SSH keys, database passwords, email credentials, API tokens, and cloud CLI configuration MUST NOT be present in the agent's:
  - Environment variables
  - Files (including mounted volumes)
  - Process memory
- Target credentials belong exclusively to the proxy.

### 1.3 Requirement 3: No Docker Sockets, SSH Agents, or Cloud CLI Configs

- The Docker socket (`docker.sock`) MUST NOT be mounted to the agent process.
- The SSH agent socket MUST NOT be accessible to the agent process.
- Cloud CLI configuration files (e.g., `~/.aws/credentials`, `~/.config/gcloud/`, `~/.kube/`) MUST NOT be present in the agent environment.

### 1.4 Requirement 4: Network Policy Restricting Access to Sensitive Services

- Where feasible, network policy (firewall rules, Tailscale ACLs, service mesh) MUST restrict which identities can reach sensitive targets.
- Only the proxy's network identity SHOULD be able to reach:
  - Database endpoints
  - SSH endpoints
  - Email servers
  - Cloud API endpoints
- The agent's network identity SHOULD NOT have direct access to these services.

### 1.5 Requirement 5: Only Governed Execution and Governance Management Tools Exposed

- The agent's MCP tools and CLI MUST include only:
  - `ep_check` (evaluate a proposed action without executing)
  - `ep_execute` (request authorization and execute through the governed proxy)
  - Governance management tools (policy management, state inspection, approvals, audit, transfer)
- Raw `shell.exec`, `postgres.execute`, `email.send`, `docker.*`, `git.*` tools MUST NOT be exposed.

### 1.6 Requirement 6: No Raw Consequential Tools Exposed

- The agent MUST NOT have access to raw shell, database, email, Docker, or Git tools.
- All consequential actions MUST go through `ep_execute` → governed proxy.
- Read-only tools (e.g., `ep_status`, `ep_log`, `ep_audit`) are permitted.

---

## 2. Advisory Mode Acknowledgment

### 2.1 When Advisory Mode Applies

EP-Governance operates in advisory mode when ANY of the following are true:

| Condition | Advisory Mode Reason |
|-----------|---------------------|
| `EP_MODE=advisory` | Explicitly configured |
| `EP_DEV=true` | Development mode |
| Deployment requirements §1.1–1.6 not satisfied | Capability isolation not achieved |
| Proxy not running as separate process | No enforcement path |
| Target credentials present in agent environment | Agent can bypass proxy |
| Docker socket or SSH agent mounted to agent | Agent can bypass proxy |
| Raw consequential tools exposed to agent | Agent can bypass proxy |
| Network policy not restricting access | Agent can reach targets directly |

### 2.2 Advisory Mode Guarantees

In advisory mode, the system provides:

- ✅ Policy evaluation and recommendations
- ✅ Audit trail
- ✅ Risk assessment
- ✅ Structural state tracking

### 2.3 Advisory Mode Does NOT Provide

- ❌ Binding enforcement (agent can bypass the gate)
- ❌ Credential isolation (agent has direct infrastructure access)
- ❌ Execution path governance (agent can call tools directly)
- ❌ Atomic authorization claiming (no proxy to claim tokens)
- ❌ Stale authorization detection (no execution path to protect)
- ❌ Authenticated proxy results (no proxy)

### 2.4 Explicit Acknowledgment

The system MUST explicitly acknowledge when it is operating in advisory mode due to missing deployment requirements, even if `EP_MODE=enforced` is set. The startup log and `ep_status` output MUST include:

```
WARNING: EP_MODE=enforced but deployment isolation requirements not met.
Operating in advisory mode. Binding enforcement is NOT active.
Missing requirements:
  - [ ] Governed proxy running as separate process
  - [ ] Target credentials absent from agent environment
  - [ ] Docker socket not mounted to agent
  ...
```

---

## 3. Capability Isolation Verification Checklist

The following checklist MUST be verified at deployment time and periodically (e.g., on EP service restart):

### 3.1 Credential Isolation

- [ ] **C1.** No SSH keys in agent environment (`~/.ssh/` does not exist or is empty)
- [ ] **C2.** No database passwords in agent environment variables
- [ ] **C3.** No email credentials in agent environment
- [ ] **C4.** No API tokens in agent environment (except EP API key for authentication to EP)
- [ ] **C5.** No cloud CLI configuration files in agent environment

### 3.2 Socket and Mount Isolation

- [ ] **S1.** Docker socket (`/var/run/docker.sock`) not mounted to agent container
- [ ] **S2.** SSH agent socket not forwarded to agent process
- [ ] **S3.** No host mount of sensitive directories to agent container

### 3.3 Network Isolation

- [ ] **N1.** Agent cannot reach database endpoints directly (test with `nc -zv <db_host> <db_port>`)
- [ ] **N2.** Agent cannot reach SSH endpoints directly
- [ ] **N3.** Agent cannot reach email servers directly
- [ ] **N4.** Proxy CAN reach all sensitive targets
- [ ] **N5.** Network policy (firewall/Tailscale ACLs) configured to enforce the above

### 3.4 Tool Exposure

- [ ] **T1.** Agent MCP tools list does not include `shell.exec`, `postgres.execute`, `email.send`, `docker.*`, `git.*`
- [ ] **T2.** Agent CLI does not include raw infrastructure commands
- [ ] **T3.** Only `ep_check`, `ep_execute`, and governance management tools are available
- [ ] **T4.** `ep_execute` routes through the governed proxy

### 3.5 Proxy Isolation

- [ ] **P1.** Proxy runs as a separate process or container
- [ ] **P2.** Proxy has its own network identity
- [ ] **P3.** Proxy holds target credentials (not the agent)
- [ ] **P4.** Proxy holds only the Ed25519 public verification key (not the private signing key)
- [ ] **P5.** Proxy can authenticate to EP

### 3.6 Verification Command

```
ep-governance verify-deployment
```

This command runs the checklist above and reports:
- Which requirements are satisfied
- Which requirements are missing
- Whether the system is in enforced or advisory mode
- If advisory due to missing requirements: which specific requirements are missing

---

## 4. Network Policy Requirements

### 4.1 Required Network Segmentation

```
┌─────────────────────────────────────────────────────────────┐
│                    Agent Network                             │
│  ┌─────────┐  ┌─────────┐                                    │
│  │ Agent A  │  │ Agent B  │   Can reach: EP service only     │
│  └────┬────┘  └────┬────┘   Cannot reach: DB, SSH, Email    │
│       │            │                                          │
└───────┼────────────┼─────────────────────────────────────────┘
        │            │
        ▼            ▼
┌──────────────────────────────────┐
│        EP Service Network         │
│  ┌────────────┐  ┌─────────────┐  │
│  │ EP Service  │  │  Database  │  │
│  └──────┬─────┘  └─────────────┘  │
│         │                         │
└─────────┼─────────────────────────┘
          │
          ▼
┌──────────────────────────────────┐
│      Proxy Network                │
│  ┌────────────┐                   │
│  │  Governed   │  Can reach:     │
│  │   Proxy     │  DB, SSH, Email, │
│  └────────────┘  Cloud APIs       │
│                                    │
└────────────────────────────────────┘
```

### 4.2 Firewall Rules

| Source | Destination | Port(s) | Action |
|--------|-------------|---------|--------|
| Agent | EP Service | EP MCP port (e.g., 8200) | ALLOW |
| Agent | Database | 5432 (PostgreSQL) | DENY |
| Agent | SSH targets | 22 | DENY |
| Agent | Email servers | 25, 465, 587 | DENY |
| Agent | Cloud APIs | 443 (various) | DENY (where feasible) |
| EP Service | Database | 5432 (PostgreSQL) | ALLOW |
| Proxy | EP Service | EP MCP port | ALLOW |
| Proxy | Database | 5432 (PostgreSQL) | ALLOW |
| Proxy | SSH targets | 22 | ALLOW |
| Proxy | Email servers | 25, 465, 587 | ALLOW |
| Proxy | Cloud APIs | 443 (various) | ALLOW |

### 4.3 Tailscale ACLs

If using Tailscale:

```
{
  "acls": [
    // Agents can reach EP service only
    {"action": "accept", "src": ["agents"], "dst": ["ep-service:*"]},
    // Agents cannot reach database, SSH, email, cloud
    {"action": "deny", "src": ["agents"], "dst": ["db:*", "ssh-targets:*", "email:*", "cloud:*"]},
    // Proxy can reach all targets
    {"action": "accept", "src": ["proxy"], "dst": ["db:*", "ssh-targets:*", "email:*", "cloud:*", "ep-service:*"]},
    // EP service can reach database
    {"action": "accept", "src": ["ep-service"], "dst": ["db:5432"]}
  ]
}
```

---

## 5. Proxy Deployment as Separate Process

### 5.1 Deployment Model

The governed proxy MUST be deployed as:

- A **separate process** (different PID, different process space)
- OR a **separate container** (different container, different filesystem namespace)
- With its own **network identity** (different IP address or Tailscale identity)
- With its own **credential store** (not shared with the agent)

### 5.2 Proxy Configuration

The proxy process holds:
- Target infrastructure credentials (SSH keys, database passwords, email credentials, API tokens)
- Ed25519 public verification key (to validate authorization tokens)
- EP service API key (to report results back to EP)

The proxy process does NOT hold:
- Ed25519 private signing key (held by EP service only)
- EP database credentials (only the EP service connects to the database)
- Agent credentials

### 5.3 Proxy Lifecycle

- The proxy starts independently of the agent.
- The proxy can be restarted without affecting the agent (the agent waits for the proxy to be available).
- The proxy can be updated independently of the agent.
- The proxy's health is monitored by EP (health check endpoint or heartbeat).

---

## 6. Credential Isolation Requirements

### 6.1 What the Agent Holds

| Credential | Agent Has? | Purpose |
|-----------|-----------|---------|
| EP API key | ✅ YES | Authenticate to EP service |
| Ed25519 private signing key | ❌ NO | Held by EP service only |
| Ed25519 public verification key | ❌ NO | Held by proxy only |
| SSH keys | ❌ NO | Held by proxy only |
| Database passwords | ❌ NO | Held by proxy only |
| Email credentials | ❌ NO | Held by proxy only |
| Cloud CLI credentials | ❌ NO | Held by proxy only |
| Docker socket access | ❌ NO | Not mounted to agent |

### 6.2 What the Proxy Holds

| Credential | Proxy Has? | Purpose |
|-----------|-----------|---------|
| EP API key | ✅ YES | Report results to EP service |
| Ed25519 public verification key | ✅ YES | Validate authorization tokens |
| Ed25519 private signing key | ❌ NO | Held by EP service only |
| SSH keys | ✅ YES | Execute SSH commands on behalf of agents |
| Database passwords | ✅ YES | Execute SQL on behalf of agents |
| Email credentials | ✅ YES | Send emails on behalf of agents |
| Cloud CLI credentials | ✅ YES | Execute cloud operations on behalf of agents |

### 6.3 What the EP Service Holds

| Credential | EP Has? | Purpose |
|-----------|---------|---------|
| EP database credentials | ✅ YES | Connect to governance database |
| Ed25519 private signing key | ✅ YES | Sign authorization tokens |
| EP API keys for all principals | ❌ NO | Stores hashes only (EP-IDENTITY-006) |
| Target infrastructure credentials | ❌ NO | Held by proxy only |

---

## 7. When Deployment Isolation Is Not Achieved

### 7.1 Automatic Advisory Mode

If the deployment verification checklist (§3) identifies any missing requirement:

1. The system MUST report an advisory.
2. The system MUST operate in advisory mode, regardless of `EP_MODE=enforced`.
3. The advisory MUST list which specific requirements are missing.
4. The `ep_status` output MUST include the advisory.
5. The startup log MUST include the advisory.

### 7.2 Advisory Message Format

```
ADVISORY: Operating in advisory mode despite EP_MODE=enforced.

The following deployment isolation requirements are not satisfied:
  1. [MISSING] Governed proxy running as separate process
  2. [MISSING] Target credentials absent from agent environment
  3. [SATISFIED] Docker socket not mounted to agent
  4. [MISSING] Network policy restricting access to sensitive services
  5. [SATISFIED] Only governed execution and governance tools exposed
  6. [SATISFIED] No raw consequential tools exposed

Binding enforcement is NOT active. The agent can bypass the governed proxy.
EP-Governance provides policy evaluation, audit, risk assessment, and
structural state tracking only.
```

### 7.3 No Silent Enforcement Failure

- The system MUST NOT silently claim to be in enforced mode when deployment requirements are not met.
- The system MUST NOT attempt to enforce without the proxy (it cannot — there is no execution path).
- The system MUST clearly communicate the mode to all users and agents.

### 7.4 Remediation

To transition from advisory to enforced mode:

1. Deploy the governed proxy as a separate process (§5).
2. Remove all target credentials from the agent environment (§6.1).
3. Unmount Docker sockets and SSH agents from the agent.
4. Configure network policy (§4).
5. Remove raw consequential tools from the agent's MCP and CLI (§1.5, §1.6).
6. Run `ep-governance verify-deployment` to confirm all requirements are satisfied.
7. Restart the EP service. The system should now operate in enforced mode.