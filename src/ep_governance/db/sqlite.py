"""EP-Governance SQLite connection management (development only).

SQLite is supported ONLY for:
- local development
- demonstrations
- single-agent testing

Do NOT use SQLite for production.  It lacks:
- LISTEN/NOTIFY
- FOR UPDATE row locking
- partial indexes (before 3.8.0)
- cross-machine multi-agent support
- pgvector
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import sqlalchemy as sa

if TYPE_CHECKING:
    from sqlalchemy.engine import Connection

__all__ = ["create_sqlite_engine", "create_sqlite_connection", "SQLITE_LIMITATIONS"]

SQLITE_LIMITATIONS = [
    "No LISTEN/NOTIFY support — polling required for notifications",
    "No FOR UPDATE row locking — use BEGIN IMMEDIATE for serialization",
    "No pgvector — embeddings not supported",
    "No cross-machine multi-agent support — single-machine only",
    "No partial indexes before SQLite 3.8.0",
    "No database roles — permission enforcement must be in application code",
    "WAL mode allows concurrent reads but only one writer at a time",
]


def create_sqlite_engine(db_path: str, **kwargs: Any) -> sa.Engine:
    """Create a SQLAlchemy engine for a SQLite database file.

    Args:
        db_path: Path to the SQLite database file, or ':memory:' for in-memory.
    """
    url = "sqlite://" if db_path == ":memory:" else f"sqlite:///{db_path}"

    engine = sa.create_engine(
        url,
        future=True,
        connect_args={"check_same_thread": False},
        **kwargs,
    )

    @sa.event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_conn: Any, _record: Any) -> None:
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.execute("PRAGMA journal_mode = WAL")
        cursor.close()

    return engine


def create_sqlite_connection(db_path: str, **kwargs: Any) -> Connection:
    """Create a new SQLite connection.

    Returns a SQLAlchemy Connection.  Caller is responsible for closing it.
    """
    engine = create_sqlite_engine(db_path, **kwargs)
    return engine.connect()
