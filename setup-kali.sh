#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="ExtortSignal"
SERVICE_NAME="extortsignal"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LISTEN_HOST="127.0.0.1"
LISTEN_PORT="8765"
INSTALL_SERVICE=1
INSTALL_PACKAGES=1
PREPARE_CAPTURE=0

log() { printf '\n[%s] %s\n' "$APP_NAME" "$*"; }
die() { printf '\n[%s] ERROR: %s\n' "$APP_NAME" "$*" >&2; exit 1; }

cleanup() {
  if [[ -n "${UNIT_TEMP:-}" && -f "${UNIT_TEMP:-}" ]]; then
    rm -f "$UNIT_TEMP"
  fi
}
trap cleanup EXIT
trap 'die "Setup stopped near line $LINENO. Review the message above, fix the issue, and rerun this script."' ERR

usage() {
  cat <<'EOF'
Usage: ./setup-kali.sh [options]

Installs and starts ExtortSignal on Kali Linux.

Options:
  --prepare-capture    Install and start Tor plus Chromium prerequisites.
                       This does not visit threat-actor sites.
  --host ADDRESS      Web listen address (default: 127.0.0.1).
  --port PORT         Web listen port (default: 8765).
  --no-service        Build the platform but do not install a systemd service.
  --skip-apt          Skip apt update/install when packages already exist.
  -h, --help          Show this help.

Examples:
  ./setup-kali.sh
  ./setup-kali.sh --prepare-capture

Security note: keep the default localhost address. ExtortSignal does not yet
provide user authentication and should not be exposed to a LAN or the internet.
EOF
}

while (($#)); do
  case "$1" in
    --prepare-capture) PREPARE_CAPTURE=1; shift ;;
    --host) [[ $# -ge 2 ]] || die "--host requires an address"; LISTEN_HOST="$2"; shift 2 ;;
    --port) [[ $# -ge 2 ]] || die "--port requires a number"; LISTEN_PORT="$2"; shift 2 ;;
    --no-service) INSTALL_SERVICE=0; shift ;;
    --skip-apt) INSTALL_PACKAGES=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

[[ "$LISTEN_PORT" =~ ^[0-9]+$ ]] || die "Port must be numeric"
((LISTEN_PORT >= 1024 && LISTEN_PORT <= 65535)) || die "Choose a port from 1024 to 65535"
if [[ "$LISTEN_HOST" != "127.0.0.1" && "$LISTEN_HOST" != "localhost" ]]; then
  die "Network exposure is disabled by this installer. Use 127.0.0.1 and open the GUI inside Kali."
fi

[[ -f "$ROOT_DIR/backend/pyproject.toml" ]] || die "Run this script from the extracted ExtortSignal project"
[[ -f "$ROOT_DIR/frontend/package.json" ]] || die "Frontend source is missing"

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  source /etc/os-release
  case "${ID:-}:${ID_LIKE:-}" in
    kali:*|*:debian*) ;;
    *) log "Warning: this installer is tested for Kali/Debian; detected ${PRETTY_NAME:-unknown Linux}." ;;
  esac
fi

if [[ $EUID -eq 0 ]]; then
  APP_USER="${SUDO_USER:-root}"
else
  APP_USER="$USER"
fi
APP_GROUP="$(id -gn "$APP_USER")"

run_root() {
  if [[ $EUID -eq 0 ]]; then "$@"; else sudo "$@"; fi
}

if ((INSTALL_PACKAGES)); then
  command -v apt-get >/dev/null || die "apt-get is required; use --skip-apt only after installing dependencies yourself"
  log "Installing Kali system dependencies"
  run_root apt-get update
  packages=(ca-certificates curl openssl python3 python3-pip python3-venv nodejs npm)
  if ((PREPARE_CAPTURE)); then
    packages+=(tor chromium)
  fi
  run_root apt-get install -y "${packages[@]}"
fi

for command in python3 node npm curl openssl; do
  command -v "$command" >/dev/null || die "$command is missing. Rerun without --skip-apt."
done

python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' \
  || die "Python 3.11 or newer is required"
node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 20 ? 0 : 1)' \
  || die "Node.js 20 or newer is required; update Node and rerun"

log "Creating the Python environment"
cd "$ROOT_DIR"
if [[ ! -x .venv/bin/python ]]; then
  python3 -m venv .venv
fi
.venv/bin/python -m pip install --upgrade pip setuptools wheel
.venv/bin/python -m pip install -e 'backend[dev]'

log "Installing and building the web interface"
cd "$ROOT_DIR/frontend"
if command -v corepack >/dev/null 2>&1; then
  corepack enable >/dev/null 2>&1 || true
fi
if command -v pnpm >/dev/null 2>&1; then
  pnpm install --frozen-lockfile
  pnpm run build
else
  npm install --no-audit --no-fund
  npm run build
fi

log "Creating local configuration without overwriting existing values"
cd "$ROOT_DIR"
if [[ ! -f .env ]]; then
  install -m 600 .env.example .env
fi
chmod 600 .env
if ! grep -Eq '^EXTORTSIGNAL_CAPTURE_WORKER_TOKEN=.{24,}$' .env; then
  worker_token="$(openssl rand -hex 32)"
  if grep -q '^EXTORTSIGNAL_CAPTURE_WORKER_TOKEN=' .env; then
    sed -i "s/^EXTORTSIGNAL_CAPTURE_WORKER_TOKEN=.*/EXTORTSIGNAL_CAPTURE_WORKER_TOKEN=${worker_token}/" .env
  else
    printf '\nEXTORTSIGNAL_CAPTURE_WORKER_TOKEN=%s\n' "$worker_token" >> .env
  fi
fi

mkdir -p data
chmod 700 data
run_root chown -R "$APP_USER:$APP_GROUP" .venv frontend/dist data .env
chmod +x run.sh setup-kali.sh

if ((PREPARE_CAPTURE)); then
  log "Preparing the isolated capture prerequisites"
  run_root systemctl enable --now tor
  run_root systemctl is-active --quiet tor || die "Tor did not start"
  log "Tor is running locally. No onion address was contacted. Site capture remains opt-in per catalog entry."
fi

if ((INSTALL_SERVICE)); then
  log "Installing the locked-down systemd service"
  UNIT_TEMP="$(mktemp)"
  {
    printf '%s\n' '[Unit]'
    printf '%s\n' 'Description=ExtortSignal defensive ransomware intelligence'
    printf '%s\n' 'After=network-online.target'
    printf '%s\n' 'Wants=network-online.target'
    printf '\n%s\n' '[Service]'
    printf 'Type=%s\n' 'simple'
    printf 'User=%s\n' "$APP_USER"
    printf 'Group=%s\n' "$APP_GROUP"
    printf 'WorkingDirectory=%s\n' "$ROOT_DIR"
    printf 'EnvironmentFile=-%s/.env\n' "$ROOT_DIR"
    printf 'Environment=EXTORTSIGNAL_HOST=%s\n' "$LISTEN_HOST"
    printf 'Environment=EXTORTSIGNAL_PORT=%s\n' "$LISTEN_PORT"
    printf 'ExecStart=%s/run.sh\n' "$ROOT_DIR"
    printf '%s\n' 'Restart=on-failure' 'RestartSec=5' 'UMask=0077'
    printf '%s\n' 'NoNewPrivileges=true' 'PrivateTmp=true' 'PrivateDevices=true'
    printf '%s\n' 'CapabilityBoundingSet=' 'LockPersonality=true' 'MemoryDenyWriteExecute=true'
    printf '%s\n' 'ProtectSystem=strict' 'ProtectHome=read-only' 'ProtectClock=true'
    printf '%s\n' 'ProtectControlGroups=true' 'ProtectHostname=true' 'ProtectKernelLogs=true'
    printf '%s\n' 'ProtectKernelModules=true' 'ProtectKernelTunables=true' 'ProtectProc=invisible'
    printf '%s\n' 'ProcSubset=pid' 'RemoveIPC=true' 'RestrictNamespaces=true'
    printf '%s\n' 'RestrictRealtime=true' 'RestrictSUIDSGID=true' 'SystemCallArchitectures=native'
    printf 'ReadWritePaths=%s/data\n' "$ROOT_DIR"
    printf '%s\n' 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6'
    printf '\n%s\n' '[Install]'
    printf '%s\n' 'WantedBy=multi-user.target'
  } > "$UNIT_TEMP"
  run_root install -m 644 "$UNIT_TEMP" "/etc/systemd/system/${SERVICE_NAME}.service"
  run_root systemctl daemon-reload
  run_root systemctl enable --now "$SERVICE_NAME"

  log "Waiting for the local service"
  ready=0
  for _ in $(seq 1 30); do
    if curl --silent --fail "http://${LISTEN_HOST}:${LISTEN_PORT}/health/ready" >/dev/null; then
      ready=1
      break
    fi
    sleep 1
  done
  if ((ready == 0)); then
    run_root systemctl status "$SERVICE_NAME" --no-pager || true
    die "The service did not become ready"
  fi
else
  log "Systemd installation skipped"
  printf 'Start manually with: %q/run.sh\n' "$ROOT_DIR"
fi

printf '\n%s\n' '============================================================'
printf '%s installed successfully.\n' "$APP_NAME"
printf 'Open inside Kali: http://%s:%s/\n' "$LISTEN_HOST" "$LISTEN_PORT"
if ((INSTALL_SERVICE)); then
  printf 'Service status: sudo systemctl status %s\n' "$SERVICE_NAME"
  printf 'Live logs:       sudo journalctl -u %s -f\n' "$SERVICE_NAME"
fi
printf '%s\n' 'The platform uses public feeds immediately. Direct-site capture'
printf '%s\n' 'still requires explicit per-site approval in the GUI.'
printf '%s\n' '============================================================'
