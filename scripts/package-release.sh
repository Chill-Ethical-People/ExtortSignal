#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_DIR="$(basename "$ROOT_DIR")"
VERSION="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$ROOT_DIR/backend/pyproject.toml" | head -n 1)"
[[ -n "$VERSION" ]] || { printf 'Unable to determine project version.\n' >&2; exit 1; }

OUTPUT_DIR="$ROOT_DIR/release"
OUTPUT_FILE="$OUTPUT_DIR/ExtortSignal-v${VERSION}.tar.gz"
CHECKSUM_FILE="${OUTPUT_FILE}.sha256"
mkdir -p "$OUTPUT_DIR"

python3 "$ROOT_DIR/scripts/public-release-audit.py" --repository-only

if [[ -n "$(git -C "$ROOT_DIR" status --porcelain --untracked-files=all)" ]]; then
  printf '%s\n' \
    'Release packaging requires a clean worktree.' \
    'Commit or intentionally remove every modified and untracked file, then retry.' >&2
  exit 1
fi

# Archive the committed tree rather than mutable working-tree content. This
# prevents a release from importing an untracked module that the archive omitted.
git -C "$ROOT_DIR" archive \
  --format=tar.gz \
  --prefix="$PROJECT_DIR/" \
  --output="$OUTPUT_FILE" \
  HEAD

ARCHIVE_LIST="$(tar -tzf "$OUTPUT_FILE")"
for required_file in .env.example DATA_SOURCES.md LICENSE NOTICE SECURITY.md run-capture-worker.sh; do
  grep -Fqx "$PROJECT_DIR/$required_file" <<<"$ARCHIVE_LIST" || {
    printf 'Release validation failed: %s is missing.\n' "$required_file" >&2
    exit 1
  }
done

if grep -E '(^|/)(data|\.venv|node_modules|dist|release|\.git)(/|$)|(^|/)\.env$|\.sqlite3($|-)|secrets\.json|__pycache__|\.pytest_cache|\.ruff_cache|\.egg-info|\.tsbuildinfo|\.(pem|p12|pfx)$' <<<"$ARCHIVE_LIST"; then
  printf 'Release validation failed: private or generated content is present.\n' >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  (
    cd "$OUTPUT_DIR"
    sha256sum "$(basename "$OUTPUT_FILE")" > "$(basename "$CHECKSUM_FILE")"
  )
else
  (
    cd "$OUTPUT_DIR"
    shasum -a 256 "$(basename "$OUTPUT_FILE")" > "$(basename "$CHECKSUM_FILE")"
  )
fi

printf 'Created clean release archive: %s\n' "$OUTPUT_FILE"
printf 'Created release checksum: %s\n' "$CHECKSUM_FILE"
