#!/usr/bin/env bash
set -euo pipefail

TAILSCALE_BIN="${POHW_TAILSCALE_BIN:-tailscale}"
SYSTEMCTL_BIN="${POHW_TAILSCALE_SYSTEMCTL_BIN:-systemctl}"
CURL_BIN="${POHW_TAILSCALE_CURL_BIN:-curl}"
INSTALLER_URL="${POHW_TAILSCALE_INSTALLER_URL:-https://tailscale.com/install.sh}"
INSTALLER_PATH="${POHW_TAILSCALE_INSTALLER_PATH:-/tmp/pohw-tailscale-install.sh}"
INSTALL_IF_MISSING="${POHW_TAILSCALE_INSTALL_IF_MISSING:-true}"
HOSTNAME="${POHW_TAILSCALE_HOSTNAME:-pibtc}"
ENABLE_SSH="${POHW_TAILSCALE_ENABLE_SSH:-true}"
ACCEPT_DNS="${POHW_TAILSCALE_ACCEPT_DNS:-true}"
ACCEPT_ROUTES="${POHW_TAILSCALE_ACCEPT_ROUTES:-false}"
SSH_USER="${POHW_TAILSCALE_SSH_USER:-ubuntu}"
AUTHKEY_FILE="${POHW_TAILSCALE_AUTHKEY_FILE:-}"
DRY_RUN="${POHW_TAILSCALE_DRY_RUN:-false}"

is_truthy() {
  case "${1:-}" in
    1|true|TRUE|yes|YES|on|ON)
      return 0
      ;;
  esac
  return 1
}

need_root() {
  if [[ "${POHW_TAILSCALE_SKIP_ROOT_CHECK:-false}" == "true" ]]; then
    return 0
  fi
  if is_truthy "$DRY_RUN"; then
    return 0
  fi
  if [[ "$(id -u)" != "0" ]]; then
    echo "Run as root, for example: sudo $0" >&2
    exit 1
  fi
}

stat_mode() {
  local path="$1"
  if stat -c %a "$path" 2>/dev/null; then
    return 0
  fi
  stat -f %Lp "$path"
}

validate_hostname() {
  local value="$1"
  if [[ ! "$value" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]{0,62}$ ]]; then
    echo "Invalid Tailscale hostname: $value" >&2
    exit 1
  fi
}

validate_ssh_user() {
  local value="$1"
  if [[ ! "$value" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
    echo "Invalid SSH user: $value" >&2
    exit 1
  fi
}

validate_authkey_file() {
  local path="$1" mode
  if [[ -L "$path" ]]; then
    echo "Tailscale auth key file must not be a symlink: $path" >&2
    exit 1
  fi
  if [[ ! -f "$path" || ! -r "$path" ]]; then
    echo "Tailscale auth key file must be readable: $path" >&2
    exit 1
  fi
  mode="$(stat_mode "$path")"
  if (( (8#$mode & 077) != 0 )); then
    echo "Tailscale auth key file is too permissive ($mode); run chmod 600 $path" >&2
    exit 1
  fi
  if ! python3 - "$path" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
raw = path.read_bytes()
if len(raw) > 4096:
    raise SystemExit("Tailscale auth key file is unexpectedly large")
text = raw.decode("utf-8", errors="strict").strip()
if not text:
    raise SystemExit("Tailscale auth key file is empty")
if any(ord(ch) < 33 for ch in text):
    raise SystemExit("Tailscale auth key must be a single printable token")
if not text.startswith("tskey-"):
    raise SystemExit("Tailscale auth key should start with tskey-")
PY
  then
    exit 1
  fi
}

run_cmd() {
  printf '+'
  printf ' %q' "$@"
  printf '\n'
  if ! is_truthy "$DRY_RUN"; then
    "$@"
  fi
}

ensure_tailscale_installed() {
  if command -v "$TAILSCALE_BIN" >/dev/null 2>&1; then
    return 0
  fi
  if ! is_truthy "$INSTALL_IF_MISSING"; then
    echo "tailscale binary not found and POHW_TAILSCALE_INSTALL_IF_MISSING=false" >&2
    exit 1
  fi
  if ! command -v "$CURL_BIN" >/dev/null 2>&1; then
    echo "curl is required to install Tailscale automatically" >&2
    exit 1
  fi
  run_cmd "$CURL_BIN" -fsSL "$INSTALLER_URL" -o "$INSTALLER_PATH"
  run_cmd chmod 700 "$INSTALLER_PATH"
  run_cmd sh "$INSTALLER_PATH"
}

tailscale_logged_in() {
  "$TAILSCALE_BIN" status --json >/dev/null 2>&1
}

tailscale_ip4() {
  "$TAILSCALE_BIN" ip -4 2>/dev/null | head -n 1
}

need_root
validate_hostname "$HOSTNAME"
validate_ssh_user "$SSH_USER"

if [[ -n "$AUTHKEY_FILE" ]]; then
  validate_authkey_file "$AUTHKEY_FILE"
fi

ensure_tailscale_installed
run_cmd "$SYSTEMCTL_BIN" enable --now tailscaled

up_args=(up "--hostname=$HOSTNAME" "--accept-dns=$ACCEPT_DNS" "--accept-routes=$ACCEPT_ROUTES")
if [[ -n "$AUTHKEY_FILE" ]]; then
  up_args+=("--auth-key=file:$AUTHKEY_FILE")
fi

if tailscale_logged_in; then
  run_cmd "$TAILSCALE_BIN" "${up_args[@]}"
else
  echo "Tailscale is not authenticated yet."
  if [[ -z "$AUTHKEY_FILE" ]]; then
    echo "Run again with POHW_TAILSCALE_AUTHKEY_FILE=/path/to/chmod600-authkey for unattended setup." >&2
    echo "Or run interactively on the Pi: sudo tailscale up --hostname=$HOSTNAME" >&2
    exit 1
  fi
  run_cmd "$TAILSCALE_BIN" "${up_args[@]}"
fi

if is_truthy "$ENABLE_SSH"; then
  run_cmd "$TAILSCALE_BIN" set --ssh
fi

ip4="$(tailscale_ip4 || true)"
cat <<EOF
PoHW Tailscale remote access is configured.

Tailnet hostname: ${HOSTNAME}
Tailnet IPv4: ${ip4:-unknown}
Normal SSH over tailnet:
  ssh ${SSH_USER}@${HOSTNAME}

Dashboard tunnel over tailnet:
  /mnt/ssd/p2pool/scripts/pohw-dashboard-tunnel.sh ${SSH_USER}@${HOSTNAME}
EOF
