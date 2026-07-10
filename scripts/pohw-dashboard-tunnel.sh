#!/usr/bin/env bash
set -euo pipefail

SSH_TARGET="${1:-${POHW_PI_SSH_TARGET:-pohw-pi}}"
SSH_BIN="${POHW_SSH_BIN:-ssh}"
SSH_PORT="${POHW_PI_SSH_PORT:-}"
LOCAL_UI_PORT="${POHW_LOCAL_DASHBOARD_UI_PORT:-5176}"
REMOTE_UI_PORT="${POHW_REMOTE_DASHBOARD_UI_PORT:-5176}"
LOCAL_API_PORT="${POHW_LOCAL_DASHBOARD_API_PORT:-40407}"
REMOTE_API_PORT="${POHW_REMOTE_DASHBOARD_API_PORT:-40407}"

for port in "$LOCAL_UI_PORT" "$REMOTE_UI_PORT" "$LOCAL_API_PORT" "$REMOTE_API_PORT"; do
  if [[ ! "$port" =~ ^[0-9]{1,5}$ ]]; then
    echo "Invalid TCP port: $port" >&2
    exit 1
  fi
  parsed_port=$((10#$port))
  if (( parsed_port < 1 || parsed_port > 65535 )); then
    echo "Invalid TCP port: $port" >&2
    exit 1
  fi
done
if [[ -n "$SSH_PORT" ]]; then
  if [[ ! "$SSH_PORT" =~ ^[0-9]{1,5}$ ]]; then
    echo "Invalid SSH TCP port: $SSH_PORT" >&2
    exit 1
  fi
  parsed_ssh_port=$((10#$SSH_PORT))
  if (( parsed_ssh_port < 1 || parsed_ssh_port > 65535 )); then
    echo "Invalid SSH TCP port: $SSH_PORT" >&2
    exit 1
  fi
fi

echo "Opening PoHW dashboard tunnel to $SSH_TARGET"
echo "UI:  http://127.0.0.1:$LOCAL_UI_PORT/ -> Pi 127.0.0.1:$REMOTE_UI_PORT"
echo "API: http://127.0.0.1:$LOCAL_API_PORT/dashboard.json -> Pi 127.0.0.1:$REMOTE_API_PORT"
echo "Keep this process running while using the dashboard."

ssh_args=(
  -N \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=20 \
  -o ServerAliveCountMax=3 \
  -L "127.0.0.1:$LOCAL_UI_PORT:127.0.0.1:$REMOTE_UI_PORT" \
  -L "127.0.0.1:$LOCAL_API_PORT:127.0.0.1:$REMOTE_API_PORT"
)
if [[ -n "$SSH_PORT" ]]; then
  ssh_args+=(-p "$SSH_PORT")
fi
exec "$SSH_BIN" "${ssh_args[@]}" "$SSH_TARGET"
