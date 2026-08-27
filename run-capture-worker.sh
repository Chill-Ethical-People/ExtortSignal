#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

if [[ ! -x .venv/bin/python ]]; then
  echo "Capture worker dependencies are missing. Rerun setup-kali.sh --prepare-capture."
  exit 1
fi

exec .venv/bin/python -m ransom_monitor.capture_worker_process
