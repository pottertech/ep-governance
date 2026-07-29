"""EP-Governance transaction helpers.

Provides context managers for database transactions with dialect-aware
behaviour for PostgreSQL and SQLite.

- ``transaction(conn)`` — plain transaction (commit on success, rollback on exception).
- ``serializable_transaction(conn)`` — SERIALIZABLE isolation on PostgreSQL,
  BEGIN IMMEDIATE on SQLite (SQLite has no isolation levels beyond the
  begin-mode).
- ``locked_transaction(conn, lock_key)`` — advisory lock on PostgreSQL
  (``pg_advisory_xact_lock``), BEGIN IMMEDIATE on SQLite.

All three are context managers (``with transaction(conn) as conn: ...``).

Uses SQLAlchemy 2.0's transaction API to avoid conflicts with autobegin.
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

    Handles SQLAlchemy 2.0's autobegin behavior by committing any pending
    autobegun transaction before starting an explicit one.
    """
    # If SQLAlchemy has already autobegun a transaction (from prior reads),
    # commit it first so we can start a clean explicit transaction.
    if conn.in_transaction():
        conn.commit()
    trans = conn.begin()
    try:
        yield conn
        trans.commit()
    except Exception:
        trans.rollback()
        raise


@contextlib.contextmanager
def serializable_transaction(conn: Connection) -> Iterator[Connection]:
    """Begin a SERIALIZABLE transaction.

    PostgreSQL: SERIALIZABLE isolation level.
    SQLite: BEGIN IMMEDIATE (SQLite SERIALIZABLE is the default under
    IMMEDIATE; there is no finer-grained isolation control).

    Uses SQLAlchemy's conn.begin() and SET TRANSACTION ISOLATION LEVEL
    for PostgreSQL. For SQLite, uses BEGIN IMMEDIATE.
    """
    dialect = conn.dialect.name
    # Commit any pending autobegun transaction first
    if conn.in_transaction():
        conn.commit()
    if dialect == "sqlite":
        # SQLite: use BEGIN IMMEDIATE to acquire a write lock immediately
        # Only if not already in a transaction
        if not conn.in_transaction():
            conn.execute(text("BEGIN IMMEDIATE"))
            try:
                yield conn
                conn.execute(text("COMMIT"))
            except Exception:
                conn.execute(text("ROLLBACK"))
                raise
        else:
            trans = conn.begin()
            try:
                yield conn
                trans.commit()
            except Exception:
                trans.rollback()
                raise
    else:
        # PostgreSQL: use SQLAlchemy begin() with isolation level
        trans = conn.begin()
        try:
            conn.execute(text("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"))
            yield conn
            trans.commit()
        except Exception:
            trans.rollback()
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
    in_transaction = conn.in_transaction()

    if in_transaction:
        nested = conn.begin_nested()
        try:
            if dialect != "sqlite":
                conn.execute(
                    text("SELECT pg_advisory_xact_lock(:lock_key)"),
                    {"lock_key": int(lock_key)},
                )
            yield conn
            nested.commit()
        except Exception:
            nested.rollback()
            raise
    elif dialect == "sqlite":
        conn.execute(text("BEGIN IMMEDIATE"))
        try:
            yield conn
            conn.execute(text("COMMIT"))
        except Exception:
            conn.execute(text("ROLLBACK"))
            raise
    else:
        trans = conn.begin()
        try:
            conn.execute(
                text("SELECT pg_advisory_xact_lock(:lock_key)"),
                {"lock_key": int(lock_key)},
            )
            yield conn
            trans.commit()
        except Exception:
            trans.rollback()
            raise
