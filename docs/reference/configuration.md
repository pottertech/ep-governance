# Configuration Reference

EP-Governance is configured entirely through environment variables (or an equivalent `.env` file supplied by the deployment system). No configuration files are read by the library itself — `load_config()` in `src/ep_governance/config.py` reads directly from `os.environ`.

This page lists every supported environment variable, grouped by the component that consumes it.

---

## Variable index by component

| Component | Variables |
|-----------|-----------|
| **Service** (core governance daemon) | `EP_MODE`, `EP_DB_URL`, `EP_DB_SCHEMA`, `EP_NOTIFY`, `EP_NATS_URL`, `EP_TOKEN_TTL_SECONDS`, `EP_DEV`, `EP_BOOTSTRAP_TOKEN_HASH`, `EP_SIGNING_KEY_FILE`, `EP_ALLOW_ADVISORY_EXECUTION`, `EP_REQUIRE_SIGNED_AUTHORIZATION`, `EP_FAIL_CLOSED` |
| **Embedding** (used by Service & MCP) | `EP_EMBEDDING_PROVIDER`, `EP_EMBEDDING_MODEL`, `EP_EMBEDDING_HOST`, `EP_EMBEDDING_API_KEY` |
| **MCP Server** | `EP_MCP_TRANSPORT`, `EP_MCP_PORT`, `EP_MCP_TLS_CERT`, `EP_MCP_TLS_KEY`, `EP_MCP_ALLOWED_HOSTS`, `EP_BOOTSTRAP_MODE` |
| **Proxy** | `EP_PROXY_TARGET_URL`, `EP_PROXY_AUDIENCE`, `EP_PROXY_PRINCIPAL_ID`, `EP_DEPLOYMENT_ID`, `EP_PROXY_TARGET_ID`, `EP_PROXY_PORT`, `EP_PUBLIC_KEY`, `EP_EP_SERVICE_ID`, `EP_PROXY_ATTESTATION_PATH`, `EP_CONTROLLER_PUBLIC_KEY` |
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
| `EP_ALLOW_ADVISORY_EXECUTION` | no | `false` | no | When `true`, allows advisory mode in development. Advisory mode is always rejected in production (when `EP_DEV` is not set). |
| `EP_REQUIRE_SIGNED_AUTHORIZATION` | no | `true` | no | When `true`, all consequential actions require Ed25519-signed authorization tokens. Should always be `true` in production. |
| `EP_FAIL_CLOSED` | no | `true` | no | When `true`, the proxy refuses to execute if governance is unavailable. Should always be `true` in production. |

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

1. **Governance DB** credentials — for claiming tokens and recording results.
2. **Target DB** credentials — for executing agent SQL.

The agent has neither.

| Variable | Required | Default | Secret | Description |
|----------|----------|---------|--------|-------------|
| `EP_DB_URL` | Yes | None | Yes | Governance database connection string. |
| `EP_DB_SCHEMA` | No | Empty | No | Governance database schema. |
| `EP_PROXY_TARGET_URL` | Yes | None | Yes | Target PostgreSQL connection string. |
| `EP_PROXY_AUDIENCE` | Yes | None | No | Token and attestation audience (e.g., `postgres-proxy`). |
| `EP_PROXY_PRINCIPAL_ID` | Yes | None | No | Stable identity of this proxy instance. |
| `EP_DEPLOYMENT_ID` | Yes | None | No | Identity of the deployment receiving the attestation. |
| `EP_PROXY_TARGET_ID` | Yes | None | No | Identity of the governed target system. |
| `EP_PROXY_ATTESTATION_PATH` | Yes | None | No | Path inside the container to the signed attestation JSON. |
| `EP_CONTROLLER_PUBLIC_KEY` | Yes | None | No | Hex-encoded Ed25519 public key of the trusted deployment controller. |
| `EP_PROXY_PORT` | No | `8201` | No | Proxy listening port. |
| `EP_PUBLIC_KEY` | Yes | None | No | Governance-token verification public key (Ed25519). |
| `EP_EP_SERVICE_ID` | Yes | None | No | EP service principal identity (XID). |

### Attestation file mounting (Docker)

When deploying with Docker Compose, mount the attestation file as a
read-only volume rather than baking it into the image:

```yaml
volumes:
  - "${EP_PROXY_ATTESTATION_FILE:?required}:/run/ep-governance/proxy-attestation.json:ro"
environment:
  EP_PROXY_ATTESTATION_PATH: /run/ep-governance/proxy-attestation.json
```

Attestations expire and require rotation. Do not bake them into the
Docker image.

| Variable | Scope | Required | Description |
|----------|-------|----------|-------------|
| `EP_PROXY_ATTESTATION_FILE` | Host/Compose | Yes (Docker) | Host path mounted read-only into the container. |
| `EP_PROXY_ATTESTATION_PATH` | Container/process | Yes | Path from which the proxy reads the attestation inside the container. |

Preflight check before starting the proxy:

```bash
test -f "$EP_PROXY_ATTESTATION_FILE" || {
    echo "Attestation file does not exist: $EP_PROXY_ATTESTATION_FILE"
    exit 1
}
```


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
| `EP_ALLOW_ADVISORY_EXECUTION` | ✅ | ✅ | | ✅ |
| `EP_REQUIRE_SIGNED_AUTHORIZATION` | ✅ | ✅ | | |
| `EP_FAIL_CLOSED` | ✅ | ✅ | | |
| `EP_BOOTSTRAP_TOKEN` | | | | ✅ |

✅ = read by the component. **(req)** = required (no usable default).