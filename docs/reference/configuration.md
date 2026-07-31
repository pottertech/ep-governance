# Configuration Reference

EP-Governance is configured entirely through environment variables (or an equivalent `.env` file supplied by the deployment system). No configuration files are read by the library itself — `load_config()` in `src/ep_governance/config.py` reads directly from `os.environ`.

This page lists every supported environment variable, grouped by the component that consumes it.

---

## Variable index by component

| Component | Variables |
|-----------|-----------|
| **Service** (core governance daemon) | `EP_MODE`, `EP_DB_URL`, `EP_DB_SCHEMA`, `EP_NOTIFY`, `EP_NATS_URL`, `EP_TOKEN_TTL_SECONDS`, `EP_DEV`, `EP_BOOTSTRAP_TOKEN_HASH`, `EP_SIGNING_KEY_FILE` |
| **Embedding** (used by Service & MCP) | `EP_EMBEDDING_PROVIDER`, `EP_EMBEDDING_MODEL`, `EP_EMBEDDING_HOST`, `EP_EMBEDDING_API_KEY` |
| **MCP Server** | `EP_MCP_TRANSPORT`, `EP_MCP_PORT`, `EP_MCP_TLS_CERT`, `EP_MCP_TLS_KEY`, `EP_MCP_ALLOWED_HOSTS`, `EP_BOOTSTRAP_MODE` |
| **Proxy** | `EP_PROXY_TARGET_URL`, `EP_PROXY_AUDIENCE`, `EP_PROXY_PORT`, `EP_PUBLIC_KEY`, `EP_EP_SERVICE_ID` |
| **CLI** | `EP_BOOTSTRAP_TOKEN` (additionally reads all Service vars via `load_config`) |

---

## Service variables

These are loaded by `load_config()` and consumed by the core EP-Governance service.

| Variable | Required | Default | Secret | Description |
|----------|----------|---------|--------|-------------|
| `EP_MODE` | no | `enforced` | no | Operating mode. `enforced` blocks actions that fail policy; `advisory` logs but allows them. |
| `EP_DB_URL` | **yes** | *(none)* | yes | PostgreSQL connection string for the governance database (e.g. `postgresql://user:pass@host:5432/db`). |
| `EP_DB_SCHEMA` | no | *(empty)* | no | PostgreSQL schema name to use. When empty, the database default schema (`public`) is used. |
| `EP_NOTIFY` | no | `native` | no | Notification backend for policy events. One of `native` (PostgreSQL LISTEN/NOTIFY), `nats`, or `none`. |
| `EP_NATS_URL` | no | *(empty)* | no | NATS server URL. Required when `EP_NOTIFY=nats`; ignored otherwise. |
| `EP_TOKEN_TTL_SECONDS` | no | `300` | no | Time-to-live (seconds) for issued governance tokens. Must be an integer. |
| `EP_DEV` | no | `false` | no | Development-mode flag. Set to `true`, `1`, or `yes` to enable. |
| `EP_BOOTSTRAP_TOKEN_HASH` | no | *(none)* | yes | SHA-256 hash of the bootstrap token. When set, the CLI bootstrap flow verifies the supplied plaintext token against this hash. |
| `EP_SIGNING_KEY_FILE` | no | *(none)* | yes | Filesystem path to the Ed25519 private signing key (32 raw bytes, mode 0600). Used by the EP service to sign authorization tokens. In production, prefer Docker secrets, systemd credentials, or Vault over a plaintext file. |

---

## Embedding variables

Used by the Service and MCP server when semantic policy matching is enabled. All four are optional when `EP_EMBEDDING_PROVIDER=none`.

| Variable | Required | Default | Secret | Description |
|----------|----------|---------|--------|-------------|
| `EP_EMBEDDING_PROVIDER` | no | `none` | no | Embedding provider. One of `ollama`, `openai`, `cohere`, or `none`. |
| `EP_EMBEDDING_MODEL` | no | *(empty)* | no | Model identifier for the chosen provider (e.g. `nomic-embed-text` for Ollama, `text-embedding-3-small` for OpenAI). |
| `EP_EMBEDDING_HOST` | no | *(empty)* | no | Base URL / host of the embedding service. For Ollama this is the Ollama server URL; for OpenAI/Cohere it can be a custom endpoint. |
| `EP_EMBEDDING_API_KEY` | no | *(empty)* | yes | API key for the embedding provider. Required by `openai` and `cohere` providers; typically unused for local `ollama`. |

---

## MCP Server variables

Control the MCP (Model Context Protocol) server transport and TLS.

| Variable | Required | Default | Secret | Description |
|----------|----------|---------|--------|-------------|
| `EP_MCP_TRANSPORT` | no | `stdio` | no | Transport mode for the MCP server. `stdio` or `http`. |
| `EP_MCP_PORT` | no | `8200` | no | TCP port to listen on when transport is `http`. Must be an integer. |
| `EP_MCP_TLS_CERT` | no | *(empty)* | no | Filesystem path to the TLS certificate (PEM). Used only with `http` transport. |
| `EP_MCP_TLS_KEY` | no | *(empty)* | yes | Filesystem path to the TLS private key (PEM). Used only with `http` transport. |
| `EP_MCP_ALLOWED_HOSTS` | no | *(empty)* | no | Comma-separated list of allowed Host header values for HTTP transport. When empty, all hosts are accepted. |
| `EP_BOOTSTRAP_MODE` | no | `false` | no | Set to `true` to allow the MCP server to run in bootstrap mode for initial setup, bypassing normal token authentication. |

---

## Proxy variables

The proxy service (`proxy_service.py`) reads **both** the Service variables (via `load_config()`) and the following proxy-specific variables (via `os.environ`).

This is **Architecture A — direct governance access**: the proxy connects directly to the governance database to claim authorizations, advance transition stages, and report execution results. It also connects to the target database to execute SQL. The proxy holds two separate database credentials:

1. **Governance DB credential** (`EP_DB_URL`): used to claim tokens, mark transitions, and write results. The proxy's governance DB user should have INSERT/UPDATE on `ep_authorizations`, `ep_transitions`, `ep_audit_heads`, and `ep_events`, but should NOT have access to target database tables.
2. **Target DB credential** (`EP_PROXY_TARGET_URL`): used to execute SQL on behalf of agents. The proxy's target DB user (`ep_proxy_user`) should have SELECT/INSERT/UPDATE/DELETE on target tables, but should NOT have access to the `ep_governance` schema.

The agent has **neither** credential.

| Variable | Required | Default | Secret | Description |
|----------|----------|---------|--------|-------------|
| `EP_DB_URL` | **yes** | *(none)* | yes | Governance DB connection string. Loaded via `load_config()`. The proxy uses this to claim authorizations and report results. |
| `EP_DB_SCHEMA` | no | *(empty)* | no | Governance DB schema name. Loaded via `load_config()`. |
| `EP_PROXY_TARGET_URL` | **yes** | *(none)* | yes | Target database connection string that the proxy executes queries against. |
| `EP_PROXY_AUDIENCE` | no | `postgres-proxy` | no | Token audience string. Must match the audience that EP-Governance issues in its tokens. |
| `EP_PROXY_PORT` | no | `8201` | no | TCP port the proxy listens on. Must be an integer. |
| `EP_PUBLIC_KEY` | **yes** | *(none)* | no | Ed25519 public key (32 bytes encoded as 64 hexadecimal characters), used to verify governance tokens. |
| `EP_EP_SERVICE_ID` | **yes** | *(none)* | no | XID of the EP-Governance service principal used for token issuance validation. |

---

## CLI variables

The CLI (`ep-governance` command) loads Service variables via `load_config()` and additionally reads:

| Variable | Required | Default | Secret | Description |
|----------|----------|---------|--------|-------------|
| `EP_BOOTSTRAP_TOKEN` | no | *(empty)* | yes | Plaintext bootstrap token supplied during initial setup. Verified against `EP_BOOTSTRAP_TOKEN_HASH`. Can also be passed via `--bootstrap-token`. |

---

## Component matrix

Which variables each component requires or optionally reads:

| Variable | Service | Proxy | MCP | CLI |
|----------|---------|-------|-----|-----|
| `EP_MODE` | ✅ | ✅ | | ✅ |
| `EP_DB_URL` | ✅ (req) | ✅ (req) | | ✅ (req) |
| `EP_DB_SCHEMA` | ✅ | ✅ | | ✅ |
| `EP_EMBEDDING_PROVIDER` | ✅ | | ✅ | |
| `EP_EMBEDDING_MODEL` | ✅ | | ✅ | |
| `EP_EMBEDDING_HOST` | ✅ | | ✅ | |
| `EP_EMBEDDING_API_KEY` | ✅ | | ✅ | |
| `EP_MCP_TRANSPORT` | | | ✅ | |
| `EP_MCP_PORT` | | | ✅ | |
| `EP_MCP_TLS_CERT` | | | ✅ | |
| `EP_MCP_TLS_KEY` | | | ✅ | |
| `EP_MCP_ALLOWED_HOSTS` | | | ✅ | |
| `EP_BOOTSTRAP_MODE` | | | ✅ | |
| `EP_NOTIFY` | ✅ | | | |
| `EP_NATS_URL` | ✅ | | | |
| `EP_TOKEN_TTL_SECONDS` | ✅ | | | |
| `EP_DEV` | ✅ | | | ✅ |
| `EP_BOOTSTRAP_TOKEN_HASH` | ✅ | | | ✅ |
| `EP_PROXY_TARGET_URL` | | ✅ (req) | | |
| `EP_PROXY_AUDIENCE` | | ✅ | | |
| `EP_PROXY_PORT` | | ✅ | | |
| `EP_PUBLIC_KEY` | | ✅ (req) | | |
| `EP_EP_SERVICE_ID` | | ✅ (req) | | |
| `EP_SIGNING_KEY_FILE` | ✅ | | | ✅ |
| `EP_BOOTSTRAP_TOKEN` | | | | ✅ |

✅ = read by the component. **(req)** = required (no usable default).