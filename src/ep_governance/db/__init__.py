"""EP-Governance database connection and migration runner.

Provides functions to run migration files against PostgreSQL or SQLite.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import sqlalchemy as sa

from ..errors import MigrationError

if TYPE_CHECKING:
    from sqlalchemy.engine import Connection

__all__ = ["run_migrations", "get_migration_files", "MIGRATIONS_DIR"]


MIGRATIONS_DIR = Path(__file__).parent.parent.parent.parent / "migrations"


def get_migration_files(dialect: str) -> list[Path]:
    """Return sorted migration files for the given dialect ('postgres' or 'sqlite')."""
    migration_dir = MIGRATIONS_DIR / dialect
    if not migration_dir.exists():
        return []
    files = sorted(migration_dir.glob("*.sql"))
    return files


def run_migrations(conn: Connection, dialect: str) -> list[str]:
    """Run all migration files for the given dialect in order.

    Returns a list of executed migration file names.
    Raises MigrationError if any migration fails.
    """
    migration_files = get_migration_files(dialect)
    if not migration_files:
        raise MigrationError(f"No migration files found for dialect '{dialect}'")

    executed: list[str] = []
    for migration_file in migration_files:
        sql_text = migration_file.read_text(encoding="utf-8")
        try:
            # Split on semicolons for SQLite, but for PostgreSQL we can
            # execute the whole script as one statement
            if dialect == "sqlite":
                # SQLite needs statement-by-statement execution
                statements = _split_sql_statements(sql_text)
                for stmt in statements:
                    stmt = stmt.strip()
                    if not stmt:
                        continue
                    # Skip pure comment statements, but not statements
                    # that start with a comment and then have SQL
                    lines = stmt.split("\n")
                    # Remove leading comment lines
                    while lines and lines[0].strip().startswith("--"):
                        lines.pop(0)
                    sql_stmt = "\n".join(lines).strip()
                    if sql_stmt:
                        conn.execute(sa.text(sql_stmt))
            else:
                # PostgreSQL can handle multi-statement via raw execution
                conn.execute(sa.text(sql_text))
            executed.append(migration_file.name)
        except Exception as exc:
            raise MigrationError(f"Migration {migration_file.name} failed: {exc}") from exc

    return executed


def _split_sql_statements(sql_text: str) -> list[str]:
    """Split SQL text into individual statements, respecting string literals.

    Simple splitter that handles single-quote strings and line comments.
    """
    statements: list[str] = []
    current: list[str] = []
    in_string = False
    i = 0
    while i < len(sql_text):
        char = sql_text[i]
        if char == "'" and (i == 0 or sql_text[i - 1] != "\\"):
            in_string = not in_string
        if char == ";" and not in_string:
            current.append(char)
            statements.append("".join(current))
            current = []
        else:
            current.append(char)
        i += 1
    if current:
        statements.append("".join(current))
    return statements
