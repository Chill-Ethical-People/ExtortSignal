#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="ExtortSignal"
SERVICE_NAME="extortsignal"
CAPTURE_SERVICE_NAME="extortsignal-capture"
CAPTURE_USER="extortsignal-capture"
CAPTURE_GROUP="extortsignal-capture"
CAPTURE_ENV_FILE="/etc/extortsignal/capture-worker.env"
PNPM_VERSION="10.13.1"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LISTEN_HOST="127.0.0.1"
LISTEN_PORT="8765"
INSTALL_SERVICE=1
INSTALL_PACKAGES=1
PREPARE_CAPTURE=0

log() { printf '\n[%s] %s\n' "$APP_NAME" "$*"; }
die() { printf '\n[%s] ERROR: %s\n' "$APP_NAME" "$*" >&2; exit 1; }

cleanup() {
  for temporary in "${UNIT_TEMP:-}" "${WORKER_UNIT_TEMP:-}" "${WORKER_ENV_TEMP:-}"; do
    if [[ -n "$temporary" && -f "$temporary" ]]; then rm -f "$temporary"; fi
  done
}
trap cleanup EXIT
trap 'die "Setup stopped near line $LINENO. Review the message above, fix the issue, and rerun this script."' ERR

usage() {
  cat <<'EOF'
Usage: ./setup-kali.sh [options]

Installs and starts ExtortSignal on Kali Linux.

Options:
  --prepare-capture    Install and start Tor, Chromium, and local OCR prerequisites.
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
    packages+=(acl tor chromium tesseract-ocr)
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
if ((PREPARE_CAPTURE)); then
  .venv/bin/python -m pip install -e 'backend[dev,capture]'
else
  .venv/bin/python -m pip install -e 'backend[dev]'
fi

log "Installing and building the web interface"
cd "$ROOT_DIR/frontend"
pnpm_current="$(pnpm --version 2>/dev/null || true)"
if [[ "$pnpm_current" != "$PNPM_VERSION" ]]; then
  log "Installing the pinned pnpm ${PNPM_VERSION} package manager"
  run_root npm install --global "pnpm@${PNPM_VERSION}"
  hash -r
fi
[[ "$(pnpm --version 2>/dev/null || true)" == "$PNPM_VERSION" ]] \
  || die "pnpm ${PNPM_VERSION} could not be installed"
pnpm install --frozen-lockfile
pnpm run build

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

mkdir -p data data/captures
chmod 700 data
run_root chown -R "$APP_USER:$APP_GROUP" .venv frontend/dist data .env
chmod +x run.sh run-capture-worker.sh setup-kali.sh

if ((PREPARE_CAPTURE)); then
  if grep -q '^EXTORTSIGNAL_CAPTURE_WORKER_ENABLED=' .env; then
    sed -i 's/^EXTORTSIGNAL_CAPTURE_WORKER_ENABLED=.*/EXTORTSIGNAL_CAPTURE_WORKER_ENABLED=1/' .env
  else
    printf '%s\n' 'EXTORTSIGNAL_CAPTURE_WORKER_ENABLED=1' >> .env
  fi
  if grep -q '^EXTORTSIGNAL_TOR_PROXY=' .env; then
    sed -i 's#^EXTORTSIGNAL_TOR_PROXY=.*#EXTORTSIGNAL_TOR_PROXY=socks5://127.0.0.1:9050#' .env
  else
    printf '%s\n' 'EXTORTSIGNAL_TOR_PROXY=socks5://127.0.0.1:9050' >> .env
  fi
  if grep -q '^EXTORTSIGNAL_CAPTURE_WORKER_API_URL=' .env; then
    sed -i "s#^EXTORTSIGNAL_CAPTURE_WORKER_API_URL=.*#EXTORTSIGNAL_CAPTURE_WORKER_API_URL=http://127.0.0.1:${LISTEN_PORT}#" .env
  else
    printf 'EXTORTSIGNAL_CAPTURE_WORKER_API_URL=http://127.0.0.1:%s\n' "$LISTEN_PORT" >> .env
  fi
  log "Preparing the isolated capture prerequisites"
  run_root tor --verify-config >/dev/null || die "Tor configuration validation failed"
  # Debian/Kali use the instantiated Tor unit. The generic tor.service is a
  # static helper and cannot be enabled directly.
  run_root systemctl start tor@default.service
  run_root systemctl is-active --quiet tor@default.service || die "Tor did not start"
  timeout 5 .venv/bin/python -c 'import socket; s=socket.create_connection(("127.0.0.1",9050),3); s.sendall(b"\x05\x01\x00"); reply=s.recv(2); s.close(); raise SystemExit(0 if reply == b"\x05\x00" else 1)' \
    || die "Tor SOCKS5 listener did not pass the local handshake"
  log "Tor is running locally. The screenshot worker is ready; no onion address was contacted during setup."
fi

if ((INSTALL_SERVICE)); then
  log "Installing the locked-down web service"
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
    if ((PREPARE_CAPTURE)); then
      printf 'SupplementaryGroups=%s\n' "$CAPTURE_GROUP"
    fi
    printf 'WorkingDirectory=%s\n' "$ROOT_DIR"
    printf 'EnvironmentFile=-%s/.env\n' "$ROOT_DIR"
    printf 'Environment=EXTORTSIGNAL_HOST=%s\n' "$LISTEN_HOST"
    printf 'Environment=EXTORTSIGNAL_PORT=%s\n' "$LISTEN_PORT"
    printf 'ExecStart=%s/run.sh\n' "$ROOT_DIR"
    printf '%s\n' 'Restart=on-failure' 'RestartSec=5' 'UMask=0077'
    printf '%s\n' 'NoNewPrivileges=true' 'PrivateTmp=true' 'PrivateDevices=true'
    printf '%s\n' 'CapabilityBoundingSet=' 'LockPersonality=true'
    printf '%s\n' 'ProtectSystem=strict' 'ProtectHome=read-only' 'ProtectClock=true'
    printf '%s\n' 'ProtectControlGroups=true' 'ProtectHostname=true' 'ProtectKernelLogs=true'
    printf '%s\n' 'ProtectKernelModules=true' 'ProtectKernelTunables=true' 'ProtectProc=invisible'
    printf '%s\n' 'ProcSubset=pid' 'RemoveIPC=true'
    printf '%s\n' 'RestrictRealtime=true' 'RestrictSUIDSGID=true' 'SystemCallArchitectures=native'
    printf 'ReadWritePaths=%s/data\n' "$ROOT_DIR"
    printf '%s\n' 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6'
    printf '\n%s\n' '[Install]'
    printf '%s\n' 'WantedBy=multi-user.target'
  } > "$UNIT_TEMP"
  run_root install -m 644 "$UNIT_TEMP" "/etc/systemd/system/${SERVICE_NAME}.service"

  if ((PREPARE_CAPTURE)); then
    log "Creating the separate capture-worker identity and evidence boundary"
    command -v setfacl >/dev/null || die "setfacl is required; rerun without --skip-apt or install acl"
    getent group "$CAPTURE_GROUP" >/dev/null || run_root groupadd --system "$CAPTURE_GROUP"
    if ! id "$CAPTURE_USER" >/dev/null 2>&1; then
      run_root useradd --system --gid "$CAPTURE_GROUP" --home-dir /nonexistent \
        --shell /usr/sbin/nologin "$CAPTURE_USER"
    fi
    run_root usermod -a -G "$CAPTURE_GROUP" "$APP_USER"

    # Permit the worker to traverse the project path and read only its code/runtime.
    ancestor="$ROOT_DIR"
    while [[ "$ancestor" != "/" ]]; do
      run_root setfacl -m "u:${CAPTURE_USER}:--x" "$ancestor"
      ancestor="$(dirname "$ancestor")"
    done
    run_root setfacl -m "u:${CAPTURE_USER}:r-x" "$ROOT_DIR"
    run_root setfacl -R -m "u:${CAPTURE_USER}:r-X" \
      "$ROOT_DIR/backend" "$ROOT_DIR/.venv" "$ROOT_DIR/run-capture-worker.sh"

    run_root chown "$APP_USER:$CAPTURE_GROUP" "$ROOT_DIR/data"
    run_root chmod 0710 "$ROOT_DIR/data"
    run_root chown -R "$CAPTURE_USER:$CAPTURE_GROUP" "$ROOT_DIR/data/captures"
    run_root find "$ROOT_DIR/data/captures" -type d -exec chmod 0750 {} +
    run_root find "$ROOT_DIR/data/captures" -type f -exec chmod 0640 {} +

    worker_token="$(sed -n 's/^EXTORTSIGNAL_CAPTURE_WORKER_TOKEN=//p' .env | tail -n 1)"
    [[ ${#worker_token} -ge 24 ]] || die "Capture worker token was not generated correctly"
    chromium_path="$(command -v chromium || command -v chromium-browser || true)"
    tesseract_path="$(command -v tesseract || true)"
    [[ -n "$chromium_path" ]] || die "Chromium was not found after capture setup"

    WORKER_ENV_TEMP="$(mktemp)"
    {
      printf 'EXTORTSIGNAL_CAPTURE_WORKER_ENABLED=1\n'
      printf 'EXTORTSIGNAL_CAPTURE_WORKER_TOKEN=%s\n' "$worker_token"
      printf 'EXTORTSIGNAL_CAPTURE_WORKER_API_URL=http://127.0.0.1:%s\n' "$LISTEN_PORT"
      printf 'RANSOM_MONITOR_DATA_DIR=%s/data\n' "$ROOT_DIR"
      printf 'EXTORTSIGNAL_CHROMIUM_PATH=%s\n' "$chromium_path"
      printf 'EXTORTSIGNAL_TESSERACT_PATH=%s\n' "$tesseract_path"
      printf 'EXTORTSIGNAL_TOR_PROXY=socks5://127.0.0.1:9050\n'
      for key in EXTORTSIGNAL_CAPTURE_TIMEOUT EXTORTSIGNAL_CAPTURE_MAX_SCROLLS \
        EXTORTSIGNAL_CAPTURE_SCROLL_DELAY_MS EXTORTSIGNAL_CAPTURE_MAX_PAGE_HEIGHT \
        EXTORTSIGNAL_CAPTURE_SEGMENT_HEIGHT EXTORTSIGNAL_CAPTURE_OCR_MODE \
        EXTORTSIGNAL_CAPTURE_OCR_TIMEOUT; do
        value="$(sed -n "s/^${key}=//p" .env | tail -n 1)"
        if [[ -n "$value" ]]; then printf '%s=%s\n' "$key" "$value"; fi
      done
    } > "$WORKER_ENV_TEMP"
    run_root install -d -m 0750 -o root -g "$CAPTURE_GROUP" /etc/extortsignal
    run_root install -m 0640 -o root -g "$CAPTURE_GROUP" \
      "$WORKER_ENV_TEMP" "$CAPTURE_ENV_FILE"

    WORKER_UNIT_TEMP="$(mktemp)"
    {
      printf '%s\n' '[Unit]'
      printf '%s\n' 'Description=ExtortSignal isolated DLS capture worker'
      printf 'After=%s.service tor@default.service network-online.target\n' "$SERVICE_NAME"
      printf 'Requires=%s.service\n' "$SERVICE_NAME"
      printf 'PartOf=%s.service\n' "$SERVICE_NAME"
      printf '%s\n' 'Wants=tor@default.service network-online.target'
      printf '\n%s\n' '[Service]'
      printf '%s\n' 'Type=simple'
      printf 'User=%s\n' "$CAPTURE_USER"
      printf 'Group=%s\n' "$CAPTURE_GROUP"
      printf 'WorkingDirectory=%s\n' "$ROOT_DIR"
      printf 'EnvironmentFile=%s\n' "$CAPTURE_ENV_FILE"
      printf 'ExecStart=%s/run-capture-worker.sh\n' "$ROOT_DIR"
      printf '%s\n' 'Restart=on-failure' 'RestartSec=5' 'UMask=0027'
      printf '%s\n' 'NoNewPrivileges=true' 'PrivateTmp=true' 'PrivateDevices=true'
      printf '%s\n' 'CapabilityBoundingSet=' 'LockPersonality=true'
      printf '%s\n' 'ProtectSystem=strict' 'ProtectHome=read-only' 'ProtectClock=true'
      printf '%s\n' 'ProtectControlGroups=true' 'ProtectHostname=true' 'ProtectKernelLogs=true'
      printf '%s\n' 'ProtectKernelModules=true' 'ProtectKernelTunables=true' 'ProtectProc=invisible'
      printf '%s\n' 'ProcSubset=pid' 'RemoveIPC=true' 'RestrictRealtime=true'
      printf '%s\n' 'RestrictSUIDSGID=true' 'SystemCallArchitectures=native'
      printf 'ReadWritePaths=%s/data/captures\n' "$ROOT_DIR"
      printf 'InaccessiblePaths=-%s/.env -%s/data/raw -%s/data/secrets.json -%s/data/ransom-monitor.sqlite3 -%s/data/ransom-monitor.sqlite3-wal -%s/data/ransom-monitor.sqlite3-shm\n' \
        "$ROOT_DIR" "$ROOT_DIR" "$ROOT_DIR" "$ROOT_DIR" "$ROOT_DIR" "$ROOT_DIR"
      printf '%s\n' 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6'
      printf '%s\n' 'IPAddressDeny=any' 'IPAddressAllow=localhost'
      printf '\n%s\n' '[Install]'
      printf '%s\n' 'WantedBy=multi-user.target'
    } > "$WORKER_UNIT_TEMP"
    run_root install -m 0644 "$WORKER_UNIT_TEMP" \
      "/etc/systemd/system/${CAPTURE_SERVICE_NAME}.service"
  fi

  run_root systemctl daemon-reload
  run_root systemctl enable "$SERVICE_NAME"
  if ((PREPARE_CAPTURE)); then
    run_root systemctl enable "$CAPTURE_SERVICE_NAME"
  fi
  run_root systemctl restart "$SERVICE_NAME"

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
  if ((PREPARE_CAPTURE)); then
    run_root systemctl restart "$CAPTURE_SERVICE_NAME"
    worker_ready=0
    for _ in $(seq 1 20); do
      if curl --silent --fail "http://${LISTEN_HOST}:${LISTEN_PORT}/api/v1/settings/runtime" \
        | grep -q '"worker_online":true'; then
        worker_ready=1
        break
      fi
      sleep 1
    done
    if ((worker_ready == 0)); then
      run_root systemctl status "$CAPTURE_SERVICE_NAME" --no-pager || true
      die "The separate capture worker did not register its authenticated heartbeat"
    fi
  fi
else
  log "Systemd installation skipped"
  printf 'Start manually with: %q/run.sh\n' "$ROOT_DIR"
  if ((PREPARE_CAPTURE)); then
    printf 'Then start the separate worker with: %q/run-capture-worker.sh\n' "$ROOT_DIR"
  fi
fi

printf '\n%s\n' '============================================================'
printf '%s installed successfully.\n' "$APP_NAME"
printf 'Open inside Kali: http://%s:%s/\n' "$LISTEN_HOST" "$LISTEN_PORT"
if ((INSTALL_SERVICE)); then
  printf 'Service status: sudo systemctl status %s\n' "$SERVICE_NAME"
  printf 'Live logs:       sudo journalctl -u %s -f\n' "$SERVICE_NAME"
  if ((PREPARE_CAPTURE)); then
    printf 'Capture worker:  sudo systemctl status %s\n' "$CAPTURE_SERVICE_NAME"
    printf 'Capture logs:    sudo journalctl -u %s -f\n' "$CAPTURE_SERVICE_NAME"
  fi
fi
printf '%s\n' 'The platform uses public feeds immediately. Direct-site capture'
printf '%s\n' 'requires explicit per-site approval in the GUI.'
if ((PREPARE_CAPTURE)); then
  printf 'Evidence: %s/data/captures/THREAT-ACTOR/YYYY-MM-DD_HH-MM-SS_TZ_pNNN.png (+ .txt)\n' "$ROOT_DIR"
fi
printf '%s\n' '============================================================'
