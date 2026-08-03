"""EP-Governance configuration.

Loads configuration from environment variables (or a .env file).
No instance state, no in-memory caches.  Each function takes what it needs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from .errors import ConfigError

__all__ = ["Config", "load_config", "OperatingMode", "NotifyBackend", "EmbeddingProvider"]


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class OperatingMode:
    ENFORCED = "enforced"
    ADVISORY = "advisory"


class NotifyBackend:
    NATIVE = "native"  # PostgreSQL LISTEN/NOTIFY
    NATS = "nats"
    NONE = "none"


class EmbeddingProvider:
    OLLAMA = "ollama"
    OPENAI = "openai"
    COHERE = "cohere"
    NONE = "none"


# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Config:
    """Immutable configuration loaded from environment."""

    mode: str = OperatingMode.ENFORCED
    db_url: str = ""
    db_schema: str = ""
    embedding_provider: str = EmbeddingProvider.NONE
    embedding_model: str = ""
    embedding_host: str = ""
    embedding_api_key: str = ""
    mcp_transport: str = "stdio"
    mcp_port: int = 8200
    mcp_tls_cert: str = ""
    mcp_tls_key: str = ""
    mcp_allowed_hosts: str = ""
    notify_backend: str = NotifyBackend.NATIVE
    nats_url: str = ""
    token_ttl_seconds: int = 300
    dev: bool = False
    bootstrap_token_hash: str | None = None
    signing_key_file: str | None = None
    # Production enforcement flags (enforced-mode hardening)
    allow_advisory_execution: bool = False
    require_signed_authorization: bool = True
    fail_closed: bool = True


def load_config(env: dict[str, str] | None = None) -> Config:
    """Load configuration from *env* (defaults to os.environ).

    Does NOT read .env files — the caller or deployment system is responsible
    for setting environment variables.
    """
    e = env if env is not None else os.environ

    mode = e.get("EP_MODE", OperatingMode.ENFORCED)
    if mode not in (OperatingMode.ENFORCED, OperatingMode.ADVISORY):
        raise ConfigError(f"EP_MODE must be 'enforced' or 'advisory', got '{mode}'")

    db_url = e.get("EP_DB_URL", "")
    if not db_url:
        raise ConfigError("EP_DB_URL is required")

    embedding_provider = e.get("EP_EMBEDDING_PROVIDER", EmbeddingProvider.NONE)
    if embedding_provider not in (
        EmbeddingProvider.OLLAMA,
        EmbeddingProvider.OPENAI,
        EmbeddingProvider.COHERE,
        EmbeddingProvider.NONE,
    ):
        raise ConfigError(f"Unknown EP_EMBEDDING_PROVIDER: '{embedding_provider}'")

    notify_backend = e.get("EP_NOTIFY", NotifyBackend.NATIVE)
    if notify_backend not in (NotifyBackend.NATIVE, NotifyBackend.NATS, NotifyBackend.NONE):
        raise ConfigError(f"Unknown EP_NOTIFY: '{notify_backend}'")

    try:
        token_ttl = int(e.get("EP_TOKEN_TTL_SECONDS", "300"))
    except ValueError:
        raise ConfigError("EP_TOKEN_TTL_SECONDS must be an integer") from None

    try:
        mcp_port = int(e.get("EP_MCP_PORT", "8200"))
    except ValueError:
        raise ConfigError("EP_MCP_PORT must be an integer") from None

    dev = e.get("EP_DEV", "").lower() in ("true", "1", "yes")

    # Production enforcement flags
    allow_advisory = e.get("EP_ALLOW_ADVISORY_EXECUTION", "false").lower() in (
        "true", "1", "yes",
    )
    require_signed = e.get("EP_REQUIRE_SIGNED_AUTHORIZATION", "true").lower() in (
        "true", "1", "yes",
    )
    fail_closed = e.get("EP_FAIL_CLOSED", "true").lower() in (
        "true", "1", "yes",
    )

    # In production (dev=false), advisory mode must be rejected entirely.
    # Advisory mode can only be used when EP_DEV=true and
    # EP_ALLOW_ADVISORY_EXECUTION=true.
    if mode == OperatingMode.ADVISORY and not dev:
        raise ConfigError(
            "Advisory mode is not permitted in production. "
            "Set EP_MODE=enforced, or set EP_DEV=true and "
            "EP_ALLOW_ADVISORY_EXECUTION=true for development."
        )
    if mode == OperatingMode.ADVISORY and dev and not allow_advisory:
        raise ConfigError(
            "Advisory mode requires EP_ALLOW_ADVISORY_EXECUTION=true "
            "even in development."
        )

    return Config(
        mode=mode,
        db_url=db_url,
        db_schema=e.get("EP_DB_SCHEMA", ""),
        embedding_provider=embedding_provider,
        embedding_model=e.get("EP_EMBEDDING_MODEL", ""),
        embedding_host=e.get("EP_EMBEDDING_HOST", ""),
        embedding_api_key=e.get("EP_EMBEDDING_API_KEY", ""),
        mcp_transport=e.get("EP_MCP_TRANSPORT", "stdio"),
        mcp_port=mcp_port,
        mcp_tls_cert=e.get("EP_MCP_TLS_CERT", ""),
        mcp_tls_key=e.get("EP_MCP_TLS_KEY", ""),
        mcp_allowed_hosts=e.get("EP_MCP_ALLOWED_HOSTS", ""),
        notify_backend=notify_backend,
        nats_url=e.get("EP_NATS_URL", ""),
        token_ttl_seconds=token_ttl,
        dev=dev,
        bootstrap_token_hash=e.get("EP_BOOTSTRAP_TOKEN_HASH") or None,
        signing_key_file=e.get("EP_SIGNING_KEY_FILE") or None,
        allow_advisory_execution=allow_advisory,
        require_signed_authorization=require_signed,
        fail_closed=fail_closed,
    )
