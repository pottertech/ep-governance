"""Structured JSON logging for EP-Governance components.

Provides a configured logger that emits JSON lines to stderr (for Docker)
or to a rotating file. Log levels are configurable via EP_LOG_LEVEL.

Usage:
    from ep_governance.logging import get_logger
    log = get_logger("proxy")
    log.info("proxy_started", port=8201, audience="postgres-proxy")
    log.warn("rate_limited", client_ip="10.0.0.1", requests=30)
    log.error("token_verification_failed", reason="expired")
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
from datetime import datetime, timezone
from typing import Any


class JSONFormatter(logging.Formatter):
    """Format log records as JSON lines."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add any extra attributes passed via the log call
        for key, value in record.__dict__.items():
            if key not in (
                "name", "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "exc_info", "exc_text", "stack_info",
                "lineno", "funcName", "created", "msecs", "relativeCreated",
                "thread", "threadName", "processName", "process", "message",
                "taskName",
            ):
                try:
                    json.dumps(value)  # Test serializability
                    log_entry[key] = value
                except (TypeError, ValueError):
                    log_entry[key] = str(value)

        if record.exc_info and record.exc_text is None:
            log_entry["traceback"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, ensure_ascii=False)


def get_logger(
    name: str = "ep_governance",
    level: str | None = None,
    log_file: str | None = None,
) -> logging.Logger:
    """Get a configured structured logger.

    Args:
        name: Logger name (e.g. "proxy", "mcp_server", "cli").
        level: Log level override. Falls back to EP_LOG_LEVEL env var,
               then defaults to INFO.
        log_file: Optional file path for rotating file logs. Falls back
                  to EP_LOG_FILE env var. If not set, logs go to stderr.

    Returns:
        A configured logging.Logger instance that accepts extra keyword
        arguments directly: log.info("msg", key=value) passes key=value
        as an extra field in the JSON output.
    """
    logger = logging.getLogger(f"ep_governance.{name}")

    # Avoid duplicate handlers if called multiple times
    if logger.handlers:
        return logger

    # Determine level
    if level is None:
        level = os.environ.get("EP_LOG_LEVEL", "INFO")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    formatter = JSONFormatter()

    # stderr handler (for Docker logs)
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setFormatter(formatter)
    logger.addHandler(stderr_handler)

    # Optional rotating file handler
    file_path = log_file or os.environ.get("EP_LOG_FILE", "")
    if file_path:
        file_handler = logging.handlers.RotatingFileHandler(
            file_path,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    # Don't propagate to root logger (avoid duplicate messages)
    logger.propagate = False

    # Wrap log methods to accept extra kwargs directly
    _wrap_logger(logger)

    return logger


def _wrap_logger(logger: logging.Logger) -> None:
    """Wrap log methods so extra fields can be passed as kwargs.

    Transforms: log.info("msg", key=value)
    Into:       log.info("msg", extra={"key": value})
    """
    for level_name in ("debug", "info", "warning", "error", "critical", "exception"):
        original = getattr(logger, level_name, None)
        if original is None:
            continue

        def make_wrapper(orig):
            def wrapper(msg, *args, **kwargs):
                extra = kwargs.pop("extra", {})
                extra.update(kwargs)
                if args:
                    return orig(msg, *args, extra=extra)
                return orig(msg, extra=extra)
            return wrapper

        setattr(logger, level_name, make_wrapper(original))