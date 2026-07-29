"""Unit tests for EP-Governance configuration.

References: v1.1 section 15, ADR-0004-database-boundaries.md
"""

from __future__ import annotations

import pytest

from ep_governance.config import (
    Config,
    OperatingMode,
    NotifyBackend,
    EmbeddingProvider,
    load_config,
)
from ep_governance.errors import ConfigError


class TestLoadConfig:
    def test_valid_enforced_config(self):
        cfg = load_config(
            {
                "EP_MODE": "enforced",
                "EP_DB_URL": "postgresql://user:pw@localhost:5432/ep",
            }
        )
        assert cfg.mode == "envised" or cfg.mode == "enforced"
        assert cfg.db_url == "postgresql://user:pw@localhost:5432/ep"

    def test_valid_advisory_config(self):
        cfg = load_config(
            {
                "EP_MODE": "advisory",
                "EP_DB_URL": "sqlite:///./test.db",
            }
        )
        assert cfg.mode == "advisory"
        assert cfg.db_url == "sqlite:///./test.db"

    def test_missing_db_url_raises(self):
        with pytest.raises(ConfigError):
            load_config({})

    def test_invalid_mode_raises(self):
        with pytest.raises(ConfigError):
            load_config({"EP_MODE": "invalid", "EP_DB_URL": "sqlite:///x"})

    def test_invalid_embedding_provider_raises(self):
        with pytest.raises(ConfigError):
            load_config(
                {
                    "EP_DB_URL": "sqlite:///x",
                    "EP_EMBEDDING_PROVIDER": "unknown",
                }
            )

    def test_invalid_notify_backend_raises(self):
        with pytest.raises(ConfigError):
            load_config(
                {
                    "EP_DB_URL": "sqlite:///x",
                    "EP_NOTIFY": "unknown",
                }
            )

    def test_invalid_token_ttl_raises(self):
        with pytest.raises(ConfigError):
            load_config(
                {
                    "EP_DB_URL": "sqlite:///x",
                    "EP_TOKEN_TTL_SECONDS": "not-a-number",
                }
            )

    def test_dev_flag_true(self):
        cfg = load_config(
            {
                "EP_DB_URL": "sqlite:///x",
                "EP_DEV": "true",
            }
        )
        assert cfg.dev is True

    def test_dev_flag_false(self):
        cfg = load_config(
            {
                "EP_DB_URL": "sqlite:///x",
            }
        )
        assert cfg.dev is False

    def test_defaults(self):
        cfg = load_config({"EP_DB_URL": "sqlite:///x"})
        assert cfg.mode == "enforced"
        assert cfg.embedding_provider == "none"
        assert cfg.mcp_transport == "stdio"
        assert cfg.mcp_port == 8200
        assert cfg.notify_backend == "native"
        assert cfg.token_ttl_seconds == 300

    def test_config_is_immutable(self):
        cfg = load_config({"EP_DB_URL": "sqlite:///x"})
        with pytest.raises(Exception):
            cfg.mode = "advisory"  # type: ignore
