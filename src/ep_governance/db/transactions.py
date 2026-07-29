"""EP-Governance transaction helpers.

Provides context managers for database transactions with dialect-aware
behaviour for PostgreSQL and SQLite.

- ``transaction(conn)`` — plain transaction (BEGIN / COMMIT / ROLLBACK).
- ``serializable_transaction(conn)`` — SERIALIZABLE isolation on PostgreSQL,
  BEGIN IMMEDIATE on SQLite (SQLite has no isolation levels beyond the
  begin-mode).
- ``locked_transaction(conn, lock_key)`` — advisory lock on PostgreSQL
  (``pg_advisory_xact_lock``), BEGIN IMMEDIATE on SQLite.

All three are context managers (``with transaction(conn) as conn: ...``).
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

from sqlalchemy import text

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sqlalchemy.engine import Connection

__all__ = [
    "transaction",
    "serializable_transaction",
    "locked_transaction",
]


@contextlib.contextmanager
def transaction(conn: Connection) -> Iterator[Connection]:
    """Begin a transaction, yield the connection, commit on success, rollback on exception.

    Uses SQLAlchemy 2.0's implicit transaction model.  We issue explicit
    BEGIN / COMMIT / ROLLBACK so the behaviour is identical on both
    PostgreSQL and SQLite regardless of the driver's autocommit defaults.
    """
    dialect = conn.dialect.name
    if dialect == "sqlite":
        # SQLite: use BEGIN IMMEDIATE to acquire a write lock immediately,
        # preventing "database is locked" errors during concurrent writes.
        conn.execute(text("BEGIN IMMEDIATE"))
    else:
        # PostgreSQL (and others): plain BEGIN
        conn.execute(text("BEGIN"))
    try:
        yield conn
        conn.execute(text("COMMIT"))
    except Exception:
        conn.execute(text("ROLLBACK"))
        raise


@contextlib.contextmanager
def serializable_transaction(conn: Connection) -> Iterator[Connection]:
    """Begin a SERIALIZABLE transaction.

    PostgreSQL: ``BEGIN ISOLATION LEVEL SERIALIZABLE``
    SQLite: ``BEGIN IMMEDIATE`` (SQLite SERIALIZABLE is the default under
    IMMEDIATE; there is no finer-grained isolation control).
    """
    dialect = conn.dialect.name
    if dialect == "sqlite":
        conn.execute(text("BEGIN IMMEDIATE"))
    else:
        conn.execute(text("BEGIN ISOLATION LEVEL SERIALIZABLE"))
    try:
        yield conn
        conn.execute(text("COMMIT"))
    except Exception:
        conn.execute(text("ROLLBACK"))
        raise


@contextlib.contextmanager
def locked_transaction(conn: Connection, lock_key: int | str) -> Iterator[Connection]:
    """Begin a transaction guarded by an advisory lock (PostgreSQL) or
    write lock (SQLite).

    PostgreSQL: ``SELECT pg_advisory_xact_lock(:lock_key)`` — the lock is
    automatically released at COMMIT/ROLLBACK (xact-level).

    SQLite: ``BEGIN IMMEDIATE`` — the write lock itself serialises access.
    The *lock_key* is accepted but ignored on SQLite.
    """
    dialect = conn.dialect.name
    if dialect == "sqlite":
        conn.execute(text("BEGIN IMMEDIATE"))
    else:
        # PostgreSQL: acquire a transaction-scoped advisory lock.
        # lock_key is cast to bigint for pg_advisory_xact_lock.
        conn.execute(text("SELECT pg_advisory_xact_lock(:lock_key)"), {"lock_key": int(lock_key)})
    try:
        yield conn
        conn.execute(text("COMMIT"))
    except Exception:
        conn.execute(text("ROLLBACK"))
        raise
