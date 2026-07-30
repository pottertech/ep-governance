"""EP-Governance PostgreSQL connection management.

Provides connection creation, URL parsing, and dialect detection.
PostgreSQL is the production backend.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import sqlalchemy as sa

from ..errors import DatabaseError

if TYPE_CHECKING:
    from sqlalchemy.engine import Connection

__all__ = ["create_engine", "create_connection", "is_postgres", "is_sqlite"]


def create_engine(db_url: str, **kwargs: Any) -> sa.Engine:
    """Create a SQLAlchemy engine from a database URL.

    For PostgreSQL: uses psycopg (psycopg3) as the driver.
    For SQLite: uses the built-in sqlite3 driver with WAL mode.
    """
    schema = kwargs.pop("schema", None)

    if db_url.startswith("postgresql://") or db_url.startswith("postgresql+psycopg://"):
        # Ensure we use psycopg (psycopg3) if available
        if not db_url.startswith("postgresql+psycopg://"):
            db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)
        engine = sa.create_engine(db_url, future=True, **kwargs)

        if schema:
            @sa.event.listens_for(engine, "connect")
            def _set_search_path(dbapi_conn: Any, _record: Any) -> None:
                cursor = dbapi_conn.cursor()
                cursor.execute(f"SET search_path TO {schema}")
                cursor.close()

            # SQLAlchemy resets connections on return to the pool (rollback).
            # The default rollback clears session-level settings like search_path.
            # Re-apply search_path on every reset so pooled connections always
            # see the correct schema.
            @sa.event.listens_for(engine, "reset")
            def _reset_search_path(dbapi_conn: Any, _record: Any, _reset_state: Any = None) -> None:
                cursor = dbapi_conn.cursor()
                cursor.execute(f"SET search_path TO {schema}")
                cursor.close()
    elif db_url.startswith("sqlite://"):
        # Enable foreign keys and WAL mode for SQLite
        engine = sa.create_engine(
            db_url,
            future=True,
            connect_args={"check_same_thread": False},
            **kwargs,
        )

        # Set pragmas on every connection
        @sa.event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_conn: Any, _record: Any) -> None:
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA foreign_keys = ON")
            cursor.execute("PRAGMA journal_mode = WAL")
            cursor.close()
    else:
        raise DatabaseError(f"Unsupported database URL scheme: {db_url.split('://')[0]}")

    return engine


def create_connection(db_url: str, **kwargs: Any) -> Connection:
    """Create a new database connection from a URL.

    Returns a SQLAlchemy Connection.  Caller is responsible for closing it
    (use as a context manager or call .close()).
    """
    engine = create_engine(db_url, **kwargs)
    return engine.connect()


def is_postgres(conn: Connection) -> bool:
    """Return True if the connection is to a PostgreSQL database."""
    return conn.dialect.name == "postgresql"


def is_sqlite(conn: Connection) -> bool:
    """Return True if the connection is to a SQLite database."""
    return conn.dialect.name == "sqlite"
