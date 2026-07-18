#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

if [[ ! -x .venv/bin/python ]]; then
  echo "Backend dependencies are missing. Follow the setup steps in README.md."
  exit 1
fi

if [[ ! -f frontend/dist/index.html ]]; then
  echo "Frontend build is missing. Follow the setup steps in README.md."
  exit 1
fi

HOST="${EXTORTSIGNAL_HOST:-127.0.0.1}"
PORT="${EXTORTSIGNAL_PORT:-8765}"

exec .venv/bin/python -m uvicorn ransom_monitor.main:app --app-dir backend --host "$HOST" --port "$PORT"
