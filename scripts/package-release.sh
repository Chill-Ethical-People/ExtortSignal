#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_DIR="$(basename "$ROOT_DIR")"
VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$ROOT_DIR/backend/pyproject.toml" | head -n 1)"
[[ -n "$VERSION" ]] || { printf 'Unable to determine project version.\n' >&2; exit 1; }

OUTPUT_DIR="$ROOT_DIR/release"
OUTPUT_FILE="$OUTPUT_DIR/ExtortSignal-v${VERSION}.tar.gz"
mkdir -p "$OUTPUT_DIR"

# Prevent macOS metadata and extended-attribute headers from leaking into the
# portable Linux release archive. GNU tar safely ignores this variable.
export COPYFILE_DISABLE=1
TAR_METADATA_OPTIONS=()
if tar --version 2>/dev/null | grep -qi 'bsdtar'; then
  TAR_METADATA_OPTIONS=(--no-xattrs --no-acls --no-fflags)
fi

# Package only version-controlled source. This makes accidental inclusion of
# local databases, credentials, caches, or generated artifacts impossible.
FILE_LIST="$(mktemp)"
trap 'rm -f "$FILE_LIST"' EXIT
git -C "$ROOT_DIR" ls-files | sed "s|^|$PROJECT_DIR/|" > "$FILE_LIST"

tar "${TAR_METADATA_OPTIONS[@]}" -czf "$OUTPUT_FILE" \
  -C "$(dirname "$ROOT_DIR")" \
  -T "$FILE_LIST"

ARCHIVE_LIST="$(tar -tzf "$OUTPUT_FILE")"
for required_file in .env.example LICENSE NOTICE SECURITY.md; do
  grep -Fqx "$PROJECT_DIR/$required_file" <<<"$ARCHIVE_LIST" || {
    printf 'Release validation failed: %s is missing.\n' "$required_file" >&2
    exit 1
  }
done

printf 'Created clean release archive: %s\n' "$OUTPUT_FILE"
