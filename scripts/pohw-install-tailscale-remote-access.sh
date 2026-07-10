#!/usr/bin/env bash
set -euo pipefail

TAILSCALE_BIN="${POHW_TAILSCALE_BIN:-tailscale}"
SYSTEMCTL_BIN="${POHW_TAILSCALE_SYSTEMCTL_BIN:-systemctl}"
CURL_BIN="${POHW_TAILSCALE_CURL_BIN:-curl}"
UFW_BIN="${POHW_TAILSCALE_UFW_BIN:-ufw}"
INSTALLER_URL="${POHW_TAILSCALE_INSTALLER_URL:-https://tailscale.com/install.sh}"
INSTALLER_PATH="${POHW_TAILSCALE_INSTALLER_PATH:-/tmp/pohw-tailscale-install.sh}"
INSTALL_IF_MISSING="${POHW_TAILSCALE_INSTALL_IF_MISSING:-true}"
HOSTNAME="${POHW_TAILSCALE_HOSTNAME:-pibtc}"
ENABLE_SSH="${POHW_TAILSCALE_ENABLE_SSH:-true}"
ENABLE_KEY_SSH_SERVE="${POHW_TAILSCALE_ENABLE_KEY_SSH_SERVE:-false}"
KEY_SSH_SERVE_PORT="${POHW_TAILSCALE_KEY_SSH_SERVE_PORT:-2222}"
SSHD_BIN="${POHW_TAILSCALE_SSHD_BIN:-sshd}"
ID_BIN="${POHW_TAILSCALE_ID_BIN:-id}"
CONFIGURE_UFW="${POHW_TAILSCALE_CONFIGURE_UFW:-true}"
UFW_INTERFACE="${POHW_TAILSCALE_UFW_INTERFACE:-tailscale0}"
ACCEPT_DNS="${POHW_TAILSCALE_ACCEPT_DNS:-false}"
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

validate_interface() {
  local value="$1"
  if [[ ! "$value" =~ ^[a-zA-Z0-9_.:-]{1,32}$ ]]; then
    echo "Invalid Tailscale firewall interface: $value" >&2
    exit 1
  fi
}

validate_port() {
  local value="$1" numeric
  if [[ ! "$value" =~ ^[0-9]{1,5}$ ]]; then
    echo "Invalid unprivileged Tailscale SSH Serve port: $value" >&2
    exit 1
  fi
  numeric=$((10#$value))
  if (( numeric < 1024 || numeric > 65535 )); then
    echo "Invalid unprivileged Tailscale SSH Serve port: $value" >&2
    exit 1
  fi
}

validate_key_ssh_policy() {
  local policy
  if ! command -v "$SSHD_BIN" >/dev/null 2>&1; then
    echo "sshd is required for key-only Tailscale SSH Serve: $SSHD_BIN" >&2
    exit 1
  fi
  if ! policy="$($SSHD_BIN -T -C "user=$SSH_USER,host=localhost,addr=127.0.0.1")"; then
    echo "Unable to inspect the effective sshd policy for $SSH_USER" >&2
    exit 1
  fi
  if ! printf '%s\n' "$policy" | python3 -c '
import sys

user = sys.argv[1]
settings = {}
allow_users = []
for raw in sys.stdin:
    parts = raw.strip().split()
    if not parts:
        continue
    key = parts[0].lower()
    if key == "allowusers":
        allow_users.extend(parts[1:])
    elif len(parts) > 1:
        settings[key] = parts[1].lower()

required = {
    "pubkeyauthentication": "yes",
    "passwordauthentication": "no",
    "kbdinteractiveauthentication": "no",
    "permitrootlogin": "no",
}
for key, expected in required.items():
    actual = settings.get(key)
    if actual != expected:
        display = actual or "missing"
        raise SystemExit(f"unsafe sshd policy: {key}={display}; expected {expected}")
if allow_users and user not in allow_users:
    raise SystemExit(f"unsafe sshd policy: {user} is not present in AllowUsers")
' "$SSH_USER"; then
    exit 1
  fi
  if ! "$ID_BIN" -u "$SSH_USER" >/dev/null 2>&1; then
    echo "Configured Tailscale SSH user does not exist: $SSH_USER" >&2
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

tailscale_authenticated() {
  local status_json
  if ! status_json="$("$TAILSCALE_BIN" status --json 2>/dev/null)"; then
    return 1
  fi
  python3 -c '
import json
import sys

try:
    data = json.load(sys.stdin)
except json.JSONDecodeError:
    sys.exit(1)

state = data.get("BackendState")
tailnet_ips = (data.get("Self") or {}).get("TailscaleIPs") or []
sys.exit(0 if state == "Running" or tailnet_ips else 1)
' <<<"$status_json"
}

tailscale_ip4() {
  "$TAILSCALE_BIN" ip -4 2>/dev/null | head -n 1
}

ensure_tailscale_ssh_ufw_rule() {
  if ! is_truthy "$CONFIGURE_UFW"; then
    return 0
  fi
  if ! command -v "$UFW_BIN" >/dev/null 2>&1; then
    echo "ufw binary not found; skipping Tailscale SSH firewall rule." >&2
    return 0
  fi
  run_cmd "$UFW_BIN" allow in on "$UFW_INTERFACE" to any port 22 proto tcp comment "SSH over Tailscale"
}

ensure_key_ssh_serve() {
  if ! is_truthy "$ENABLE_KEY_SSH_SERVE"; then
    return 0
  fi
  validate_port "$KEY_SSH_SERVE_PORT"
  validate_key_ssh_policy
  run_cmd "$TAILSCALE_BIN" serve --bg --yes "--tcp=$KEY_SSH_SERVE_PORT" tcp://127.0.0.1:22
}

need_root
validate_hostname "$HOSTNAME"
validate_ssh_user "$SSH_USER"
validate_interface "$UFW_INTERFACE"

if [[ -n "$AUTHKEY_FILE" ]]; then
  validate_authkey_file "$AUTHKEY_FILE"
fi

ensure_tailscale_installed
run_cmd "$SYSTEMCTL_BIN" enable --now tailscaled
if is_truthy "$ENABLE_SSH"; then
  ensure_tailscale_ssh_ufw_rule
fi

up_args=(up "--hostname=$HOSTNAME" "--accept-dns=$ACCEPT_DNS" "--accept-routes=$ACCEPT_ROUTES")
if [[ -n "$AUTHKEY_FILE" ]]; then
  up_args+=("--auth-key=file:$AUTHKEY_FILE")
fi

if tailscale_authenticated; then
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

if ! is_truthy "$DRY_RUN" && ! tailscale_authenticated; then
  echo "Tailscale did not reach an authenticated Running state after setup." >&2
  exit 1
fi

if is_truthy "$ENABLE_SSH"; then
  run_cmd "$TAILSCALE_BIN" set --ssh
fi
ensure_key_ssh_serve

ip4="$(tailscale_ip4 || true)"
key_ssh_help="Key-only SSH Serve fallback: disabled"
key_tunnel_help=""
if is_truthy "$ENABLE_KEY_SSH_SERVE"; then
  printf -v key_ssh_help 'Key-only SSH Serve fallback:\n  ssh -p %s %s@%s' \
    "$KEY_SSH_SERVE_PORT" "$SSH_USER" "$HOSTNAME"
  printf -v key_tunnel_help '\nDashboard tunnel through key-only fallback:\n  POHW_PI_SSH_PORT=%s /mnt/ssd/p2pool/scripts/pohw-dashboard-tunnel.sh %s@%s' \
    "$KEY_SSH_SERVE_PORT" "$SSH_USER" "$HOSTNAME"
fi
cat <<EOF
PoHW Tailscale remote access is configured.

Tailnet hostname: ${HOSTNAME}
Tailnet IPv4: ${ip4:-unknown}
Normal SSH over tailnet:
  ssh ${SSH_USER}@${HOSTNAME}
${key_ssh_help}

Dashboard tunnel over tailnet:
  /mnt/ssd/p2pool/scripts/pohw-dashboard-tunnel.sh ${SSH_USER}@${HOSTNAME}
${key_tunnel_help}
EOF
