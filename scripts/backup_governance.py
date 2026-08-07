#!/usr/bin/env python3
"""EP-Governance backup/restore for the NAS PostgreSQL schema.

Uses Python to handle the password with special characters correctly.

Backup:  python3 scripts/backup_governance.py
Restore: python3 scripts/backup_governance.py restore <backup_file>
"""
import gzip
import os
import re
import subprocess
import sys
from datetime import datetime
from urllib.parse import unquote

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


def parse_db_url():
    """Parse EP_DB_URL from .env, handling special characters in password."""
    env_file = os.path.join(os.path.dirname(__file__), "..", ".env")
    db_url = None
    schema = "ep_governance"
    with open(env_file) as f:
        for line in f:
            if line.startswith("EP_DB_URL="):
                db_url = line.split("=", 1)[1].strip()
            if line.startswith("EP_DB_SCHEMA="):
                schema = line.split("=", 1)[1].strip()
    if not db_url:
        print("ERROR: EP_DB_URL not found in .env")
        sys.exit(1)

    m = re.match(r'postgresql://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)', db_url)
    if not m:
        print(f"ERROR: Cannot parse DB URL")
        sys.exit(1)

    user, pwd_raw, host, port, db = m.groups()
    pwd = unquote(pwd_raw)
    return user, pwd, host, port, db, schema


def main():
    user, pwd, host, port, db, schema = parse_db_url()
    env = {**os.environ, "PGPASSWORD": pwd}

    backup_dir = os.path.join(os.path.dirname(__file__), "..", "backups")
    os.makedirs(backup_dir, exist_ok=True)

    if len(sys.argv) > 1 and sys.argv[1] == "restore":
        # --- Restore ---
        if len(sys.argv) < 3:
            print("Usage: python3 backup_governance.py restore <backup_file>")
            sys.exit(1)
        restore_file = sys.argv[2]
        if not os.path.isfile(restore_file):
            print(f"ERROR: Backup file not found: {restore_file}")
            sys.exit(1)

        temp_schema = f"{schema}_restore_temp"
        print(f"=== EP-Governance Restore ===")
        print(f"  Source: {restore_file}")
        print(f"  Target: {host}:{port}/{db} schema: {schema}")
        print()

        # 1. Create temp schema
        print(f"1. Creating temporary schema: {temp_schema}")
        subprocess.run(
            ["psql", "-h", host, "-p", port, "-U", user, "-d", db, "-c",
             f"DROP SCHEMA IF EXISTS {temp_schema} CASCADE; CREATE SCHEMA {temp_schema};"],
            env=env, capture_output=True, timeout=30,
        )

        # 2. Load backup into temp schema
        print("2. Loading backup into temporary schema...")
        with gzip.open(restore_file, 'rt') as f:
            dump_content = f.read()
        # Replace schema name
        dump_content = dump_content.replace(schema, temp_schema)
        result = subprocess.run(
            ["psql", "-h", host, "-p", port, "-U", user, "-d", db, "-q"],
            input=dump_content, env=env, capture_output=True, text=True, timeout=120,
        )

        # 3. Verify
        print("3. Verifying restored data...")
        result = subprocess.run(
            ["psql", "-h", host, "-p", port, "-U", user, "-d", db, "-t", "-c",
             f"SELECT count(*) FROM pg_tables WHERE schemaname = '{temp_schema}';"],
            env=env, capture_output=True, text=True, timeout=15,
        )
        table_count = int(result.stdout.strip()) if result.stdout.strip() else 0
        print(f"  Tables: {table_count}")

        if table_count < 20:
            print("ERROR: Restore verification failed -- too few tables")
            subprocess.run(
                ["psql", "-h", host, "-p", port, "-U", user, "-d", db, "-c",
                 f"DROP SCHEMA IF EXISTS {temp_schema} CASCADE;"],
                env=env, capture_output=True, timeout=30,
            )
            sys.exit(1)

        # 4. Swap schemas
        print("4. Swapping schemas...")
        old_schema = f"{schema}_backup_{int(datetime.now().timestamp())}"
        subprocess.run(
            ["psql", "-h", host, "-p", port, "-U", user, "-d", db, "-c",
             f"ALTER SCHEMA {schema} RENAME TO {old_schema}; "
             f"ALTER SCHEMA {temp_schema} RENAME TO {schema}; "
             f"DROP SCHEMA {old_schema} CASCADE;"],
            env=env, capture_output=True, timeout=30,
        )
        print("5. Restore complete.")

    else:
        # --- Backup ---
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(backup_dir, f"governance_{timestamp}.sql.gz")

        print(f"=== EP-Governance Backup ===")
        print(f"  Source: {host}:{port}/{db} schema: {schema}")
        print(f"  Target: {backup_file}")
        print()

        # Dump
        print("1. Dumping schema...")
        result = subprocess.run(
            ["pg_dump", "-h", host, "-p", port, "-U", user, "-d", db,
             f"--schema={schema}", "--no-owner", "--no-privileges"],
            env=env, capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            print(f"ERROR: pg_dump failed: {result.stderr}")
            sys.exit(1)

        # Compress
        with gzip.open(backup_file, 'wt') as f:
            f.write(result.stdout)

        file_size = os.path.getsize(backup_file)
        print(f"2. Backup created: {backup_file} ({file_size} bytes)")

        # Verify
        print("3. Verifying backup...")
        with gzip.open(backup_file, 'rt') as f:
            content = f.read()
        if "PostgreSQL" not in content[:200]:
            print("ERROR: Backup file is not a valid PostgreSQL dump")
            sys.exit(1)
        table_count = content.count("CREATE TABLE")
        print(f"  Tables in backup: {table_count}")
        print(f"4. Backup verified.")
        print(f"\nBackup complete: {backup_file}")


if __name__ == "__main__":
    main()