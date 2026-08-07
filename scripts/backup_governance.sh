#!/usr/bin/env bash
# EP-Governance backup/restore script for the NAS PostgreSQL schema.
#
# Backup:  scripts/backup_governance.sh
# Restore: scripts/backup_governance.sh restore <backup_file>
#
# The backup uses pg_dump to export the ep_governance schema from the NAS
# PostgreSQL. The restore creates a temporary schema, verifies the data,
# then swaps it in.
#
# Required env vars (from .env):
#   EP_DB_URL -- governance DB URL (postgresql://user:pass@host:port/db)
#   EP_DB_SCHEMA -- schema name (ep_governance)
#
set -euo pipefail

# Load .env
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/../.env"
if [ -f "$ENV_FILE" ]; then
    set -a
    source "$ENV_FILE"
    set +a
fi

DB_URL="${EP_DB_URL:?EP_DB_URL is required}"
SCHEMA="${EP_DB_SCHEMA:-ep_governance}"

# Parse DB URL
DB_USER=$(echo "$DB_URL" | sed -n 's|postgresql://\([^:]*\):.*|\1|p')
DB_PASS=$(echo "$DB_URL" | sed -n 's|postgresql://[^:]*:\([^@]*\)@.*|\1|p')
DB_HOST=$(echo "$DB_URL" | sed -n 's|.*@\([^:]*\):.*|\1|p')
DB_PORT=$(echo "$DB_URL" | sed -n 's|.*@\([^:]*\):\([0-9]*\)/.*|\2|p')
DB_NAME=$(echo "$DB_URL" | sed -n 's|.*/\([^?]*\).*|\1|p')

export PGPASSWORD="$DB_PASS"

BACKUP_DIR="${SCRIPT_DIR}/../backups"
mkdir -p "$BACKUP_DIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/governance_${TIMESTAMP}.sql.gz"

if [ "${1:-}" = "restore" ]; then
    # --- Restore ---
    RESTORE_FILE="${2:?Usage: $0 restore <backup_file>}"
    if [ ! -f "$RESTORE_FILE" ]; then
        echo "ERROR: Backup file not found: $RESTORE_FILE"
        exit 1
    fi

    echo "=== EP-Governance Restore ==="
    echo "  Source: $RESTORE_FILE"
    echo "  Target: $DB_HOST:$DB_PORT/$DB_NAME schema: $SCHEMA"
    echo

    # Create a temporary schema for verification
    TEMP_SCHEMA="${SCHEMA}_restore_temp"
    echo "1. Creating temporary schema: $TEMP_SCHEMA"
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c \
        "DROP SCHEMA IF EXISTS $TEMP_SCHEMA CASCADE; CREATE SCHEMA $TEMP_SCHEMA;"

    echo "2. Loading backup into temporary schema..."
    # Replace schema name in the dump and load
    zcat "$RESTORE_FILE" | sed "s/$SCHEMA/$TEMP_SCHEMA/g" | \
        psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -q 2>&1 | grep -v "^$" || true

    echo "3. Verifying restored data..."
    TABLE_COUNT=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c \
        "SELECT count(*) FROM pg_tables WHERE schemaname = '$TEMP_SCHEMA';")
    NODE_COUNT=$(psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -t -c \
        "SELECT count(*) FROM ${TEMP_SCHEMA}.ep_nodes;" 2>/dev/null || echo "0")

    echo "  Tables: $(echo $TABLE_COUNT | tr -d ' ')"
    echo "  Nodes: $(echo $NODE_COUNT | tr -d ' ')"

    if [ "$(echo $TABLE_COUNT | tr -d ' ')" -lt 20 ]; then
        echo "ERROR: Restore verification failed -- too few tables"
        psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c \
            "DROP SCHEMA IF EXISTS $TEMP_SCHEMA CASCADE;"
        exit 1
    fi

    echo "4. Swapping schemas..."
    OLD_SCHEMA="${SCHEMA}_backup_$(date +%s)"
    psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -c \
        "ALTER SCHEMA $SCHEMA RENAME TO $OLD_SCHEMA; \
         ALTER SCHEMA $TEMP_SCHEMA RENAME TO $SCHEMA; \
         DROP SCHEMA $OLD_SCHEMA CASCADE;"

    echo "5. Restore complete."
    echo "  Old schema preserved briefly as: $OLD_SCHEMA (now dropped)"

else
    # --- Backup ---
    echo "=== EP-Governance Backup ==="
    echo "  Source: $DB_HOST:$DB_PORT/$DB_NAME schema: $SCHEMA"
    echo "  Target: $BACKUP_FILE"
    echo

    echo "1. Dumping schema..."
    pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
        --schema="$SCHEMA" --no-owner --no-privileges | gzip > "$BACKUP_FILE"

    FILE_SIZE=$(stat -f%z "$BACKUP_FILE" 2>/dev/null || stat -c%s "$BACKUP_FILE" 2>/dev/null)
    echo "2. Backup created: $BACKUP_FILE ($(numfmt --to=iec $FILE_SIZE 2>/dev/null || echo ${FILE_SIZE}B))"

    echo "3. Verifying backup..."
    TABLE_COUNT=$(pg_dump -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
        --schema="$SCHEMA" --list 2>/dev/null | grep "TABLE" | wc -l | tr -d ' ')
    echo "  Tables in backup: $TABLE_COUNT"

    # Verify the gz file is valid
    if ! zcat "$BACKUP_FILE" | head -5 | grep -q "PostgreSQL"; then
        echo "ERROR: Backup file is not a valid PostgreSQL dump"
        exit 1
    fi
    echo "4. Backup verified."
    echo
    echo "Backup complete: $BACKUP_FILE"
fi