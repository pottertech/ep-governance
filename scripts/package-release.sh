#!/usr/bin/env bash
# EP-Governance release packaging script.
# Creates a clean ZIP archive excluding sensitive files, caches, and build artifacts.
# Fails if sensitive files are detected in the working tree or in the archive.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT="${1:-${REPO_DIR}/../ep-governance.zip}"

echo "=== Pre-packaging safety scan ==="

# Check for sensitive files that must NOT be in the archive
cd "$REPO_DIR"
FOUND_SECRETS=0
while IFS= read -r -d '' file; do
    case "$file" in
        ./.env.example|./.env.example.*) continue ;;
        ./.env|./.env.*) echo "  DANGER: Sensitive file found: $file"; FOUND_SECRETS=$((FOUND_SECRETS + 1)) ;;
    esac
done < <(find . -maxdepth 1 -name '.env*' -not -path './.git/*' -print0 2>/dev/null || true)

while IFS= read -r -d '' file; do
    echo "  DANGER: Sensitive file found: $file"
    FOUND_SECRETS=$((FOUND_SECRETS + 1))
done < <(find . \
    \( -name '*.key' -o -name '*.pem' -o -name '*.p12' -o -name '*.pfx' \) \
    -not -path './.git/*' \
    -not -path './.venv/*' \
    -print0 2>/dev/null || true)

if [ "$FOUND_SECRETS" -gt 0 ]; then
    echo ""
    echo "FATAL: $FOUND_SECRETS sensitive file(s) found. Refusing to package."
    echo "Remove or .gitignore these files before creating a release archive."
    exit 1
fi

echo "  No sensitive files found."

# Scan Python source for secret-like patterns (fail closed)
echo "=== Scanning source for secret patterns ==="
SECRET_HITS=0
while IFS= read -r -d '' file; do
    if grep -qE '(password|passwd|secret|api_key|private_key)\s*[:=]\s*["'"'"'][^"'"'"']{8,}' "$file" 2>/dev/null; then
        echo "  DANGER: Potential secret pattern in: $file"
        SECRET_HITS=$((SECRET_HITS + 1))
    fi
done < <(find src tests -name '*.py' -print0 2>/dev/null)

if [ "$SECRET_HITS" -gt 0 ]; then
    echo ""
    echo "FATAL: $SECRET_HITS potential secret pattern(s) found in source files."
    echo "Use an explicit allowlist or scanner configuration for intentional test fixtures."
    exit 1
fi

echo "  No secret patterns found."

echo ""
echo "=== Creating archive ==="

# Build the zip with a Bash array (no eval)
ZIP_ARGS=(-r "$OUTPUT" ep-governance/)

EXCLUDES=(
    "ep-governance/.git/*"
    "ep-governance/__pycache__/*"
    "ep-governance/**/__pycache__/*"
    "ep-governance/.pytest_cache/*"
    "ep-governance/.mypy_cache/*"
    "ep-governance/.ruff_cache/*"
    "ep-governance/.hypothesis/*"
    "ep-governance/**/*.pyc"
    "ep-governance/**/*.pyo"
    "ep-governance/**/*.pyd"
    "ep-governance/.env"
    "ep-governance/.env.*"
    "ep-governance/ep_signing_test.key"
    "ep-governance/.venv/*"
    "ep-governance/venv/*"
    "ep-governance/.DS_Store"
    "ep-governance/**/.DS_Store"
    "ep-governance/.coverage"
    "ep-governance/htmlcov/*"
    "ep-governance/dist/*"
    "ep-governance/build/*"
    "ep-governance/*.egg-info/*"
    "ep-governance/bandit-report.json"
)

for pat in "${EXCLUDES[@]}"; do
    ZIP_ARGS+=(-x "$pat")
done

cd "$REPO_DIR/.."
rm -f "$OUTPUT"
zip "${ZIP_ARGS[@]}"

echo ""
echo "=== Verifying archive ==="

# Post-package verification: check archive entries for sensitive files.
# Use unzip -Z1 to get a plain file list, then match with shell patterns.
ARCHIVE_SECRETS=0
while IFS= read -r entry; do
    case "$entry" in
        */.env.example)
            # These are templates, not secrets
            ;;
        */.env|*/.env.*|*.key|*.pem|*.p12|*.pfx)
            echo "  DANGER: Sensitive archive entry: $entry"
            ARCHIVE_SECRETS=$((ARCHIVE_SECRETS + 1))
            ;;
    esac
done < <(unzip -Z1 "$OUTPUT" 2>/dev/null)

if [ "$ARCHIVE_SECRETS" -gt 0 ]; then
    rm -f "$OUTPUT"
    echo "FATAL: Sensitive files leaked into archive. Archive deleted."
    exit 1
fi

echo "  No sensitive files in archive."

# Post-package verification: check for cache directories (fail, not warn)
CACHE_HITS=0
while IFS= read -r entry; do
    case "$entry" in
        */__pycache__/*|*/.pytest_cache/*|*/.mypy_cache/*|*/.ruff_cache/*|*/.hypothesis/*)
            echo "  DANGER: Cache directory in archive: $entry"
            CACHE_HITS=$((CACHE_HITS + 1))
            ;;
    esac
done < <(unzip -Z1 "$OUTPUT" 2>/dev/null)

if [ "$CACHE_HITS" -gt 0 ]; then
    rm -f "$OUTPUT"
    echo "FATAL: Cache directories found in archive. Archive deleted."
    exit 1
fi

echo "  No cache directories in archive."

echo ""
echo "Archive created: $OUTPUT"
echo "Size: $(ls -lh "$OUTPUT" | awk '{print $5}')"
echo "Entries: $(unzip -l "$OUTPUT" | tail -1 | awk '{print $2}')"
echo ""
echo "Packaging complete."