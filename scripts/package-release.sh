#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_DIR="$(basename "$ROOT_DIR")"
VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$ROOT_DIR/backend/pyproject.toml" | head -n 1)"
[[ -n "$VERSION" ]] || { printf 'Unable to determine project version.\n' >&2; exit 1; }

OUTPUT_DIR="$ROOT_DIR/release"
OUTPUT_FILE="$OUTPUT_DIR/ExtortSignal-v${VERSION}.tar.gz"
mkdir -p "$OUTPUT_DIR"

tar -czf "$OUTPUT_FILE" \
  --exclude="$PROJECT_DIR/.git" \
  --exclude="$PROJECT_DIR/.env" \
  --exclude="$PROJECT_DIR/.env.local" \
  --exclude="$PROJECT_DIR/.venv" \
  --exclude="$PROJECT_DIR/data" \
  --exclude="$PROJECT_DIR/release" \
  --exclude="$PROJECT_DIR/frontend/node_modules" \
  --exclude="$PROJECT_DIR/frontend/dist" \
  --exclude='*.sqlite3' \
  --exclude='*.sqlite3-shm' \
  --exclude='*.sqlite3-wal' \
  --exclude='secrets.json' \
  --exclude='__pycache__' \
  --exclude='.pytest_cache' \
  --exclude='.ruff_cache' \
  --exclude='*.egg-info' \
  --exclude='*.tsbuildinfo' \
  --exclude='.DS_Store' \
  -C "$(dirname "$ROOT_DIR")" "$PROJECT_DIR"

ARCHIVE_LIST="$(tar -tzf "$OUTPUT_FILE")"
for required_file in .env.example LICENSE NOTICE SECURITY.md; do
  grep -Fqx "$PROJECT_DIR/$required_file" <<<"$ARCHIVE_LIST" || {
    printf 'Release validation failed: %s is missing.\n' "$required_file" >&2
    exit 1
  }
done

printf 'Created clean release archive: %s\n' "$OUTPUT_FILE"
