#!/usr/bin/env bash
set -euo pipefail

WORKDIR="${POHW_WORKDIR:-/mnt/ssd/p2pool}"
DATADIR="${POHW_DATADIR:-/mnt/ssd/pohw-p2pool}"
HEALTH_STATUS_FILE="${POHW_HEALTH_STATUS_FILE:-$DATADIR/health/status.json}"
HEALTH_SCRIPT="${POHW_HEALTH_SCRIPT:-$WORKDIR/scripts/pohw-health-status.py}"
HEALTH_MAX_AGE_SECONDS="${POHW_HEALTH_MAX_AGE_SECONDS:-180}"
BOOTSTRAP_SCRIPT="${POHW_BOOTSTRAP_SCRIPT:-$WORKDIR/scripts/pohw-bootstrap-readiness.sh}"
AUTO_DIR="${POHW_AUTO_BOOTSTRAP_DIR:-$DATADIR/auto-bootstrap}"
LOCK_DIR="${POHW_AUTO_BOOTSTRAP_LOCK_DIR:-$AUTO_DIR/bootstrap.lock}"
MARKER_FILE="${POHW_AUTO_BOOTSTRAP_MARKER_FILE:-$AUTO_DIR/bootstrap.done.json}"
OUTPUT_ROOT="${POHW_AUTO_BOOTSTRAP_OUTPUT_ROOT:-${POHW_EXPERIMENT_OUTPUT_ROOT:-$DATADIR/output}}"
MODE="${POHW_AUTO_BOOTSTRAP_MODE:-real}"
APPEND="${POHW_AUTO_BOOTSTRAP_APPEND:-true}"

reject_symlink_ancestor() {
  local path="$1"
  local current="$path" owner parent parent_mode parent_unsafe_bits
  current="$(cd "$(dirname "$path")" 2>/dev/null && pwd -P)/$(basename "$path")" || current="$path"
  while [[ -n "$current" && "$current" != "/" && "$current" != "." ]]; do
    if [[ -L "$current" ]]; then
      if owner="$(stat -c %u "$current" 2>/dev/null)"; then
        :
      else
        owner="$(stat -f %u "$current")"
      fi
      parent="$(dirname "$current")"
      if parent_mode="$(stat -c %a "$parent" 2>/dev/null)"; then
        :
      else
        parent_mode="$(stat -f %Lp "$parent")"
      fi
      parent_unsafe_bits=$((8#$parent_mode & 022))
      if [[ "$owner" != "0" || "$parent_unsafe_bits" != "0" ]]; then
        echo "Refusing symlinked path component: $current" >&2
        exit 1
      fi
    fi
    current="$(dirname "$current")"
  done
}

ensure_private_dir() {
  local dir="$1"
  if [[ -L "$dir" ]]; then
    echo "Refusing symlinked auto-bootstrap directory: $dir" >&2
    exit 1
  fi
  reject_symlink_ancestor "$(dirname "$dir")"
  mkdir -p "$dir"
  chmod 700 "$dir"
}

if [[ "$MODE" != "real" && "$MODE" != "dev" ]]; then
  echo "POHW_AUTO_BOOTSTRAP_MODE must be real or dev." >&2
  exit 1
fi

ensure_private_dir "$AUTO_DIR"

if [[ -e "$MARKER_FILE" && "${POHW_AUTO_BOOTSTRAP_FORCE:-false}" != "true" ]]; then
  echo "PoHW auto-bootstrap already completed: $MARKER_FILE"
  exit 0
fi

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  echo "PoHW auto-bootstrap is already running: $LOCK_DIR"
  exit 0
fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT

if [[ ! -f "$HEALTH_STATUS_FILE" ]]; then
  echo "PoHW health status file is not available yet: $HEALTH_STATUS_FILE"
  exit 0
fi
if [[ ! -r "$HEALTH_SCRIPT" ]]; then
  echo "PoHW health script is not readable: $HEALTH_SCRIPT" >&2
  exit 1
fi
if [[ ! -x "$BOOTSTRAP_SCRIPT" && ! -r "$BOOTSTRAP_SCRIPT" ]]; then
  echo "PoHW bootstrap script is not readable: $BOOTSTRAP_SCRIPT" >&2
  exit 1
fi

set +e
python3 "$HEALTH_SCRIPT" \
  --check-mining-ready \
  --status-file "$HEALTH_STATUS_FILE" \
  --max-age-seconds "$HEALTH_MAX_AGE_SECONDS" \
  > "$AUTO_DIR/health-readiness.txt" 2>&1
health_status=$?
set -e
if (( health_status != 0 )); then
  cat "$AUTO_DIR/health-readiness.txt" >&2
  echo "PoHW health is not mining-ready; skipping auto-bootstrap."
  exit 0
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
output_dir="$OUTPUT_ROOT/work-bootstrap-auto-$timestamp"
bootstrap_args=(--mode "$MODE" --output-dir "$output_dir")
if [[ "$APPEND" == "true" ]]; then
  bootstrap_args+=(--append)
else
  bootstrap_args+=(--no-append)
fi
if [[ "$MODE" == "dev" && -n "${POHW_AUTO_BOOTSTRAP_DEV_ACK:-}" ]]; then
  bootstrap_args+=(--dev-ack "$POHW_AUTO_BOOTSTRAP_DEV_ACK")
fi

"$BOOTSTRAP_SCRIPT" "${bootstrap_args[@]}"

python3 - "$MARKER_FILE" "$output_dir/status.json" "$output_dir" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

marker_path = pathlib.Path(sys.argv[1])
status_path = pathlib.Path(sys.argv[2])
output_dir = pathlib.Path(sys.argv[3])
try:
    status = json.loads(status_path.read_text(encoding="utf-8"))
except Exception as exc:
    raise SystemExit(f"bootstrap did not produce a readable status.json: {exc}")
if status.get("status") != "completed":
    print(f"bootstrap finished without completion marker: {status.get('status')}", file=sys.stderr)
    raise SystemExit(0)
marker = {
    "completedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "outputDir": str(output_dir),
    "status": status.get("status"),
    "mode": status.get("mode"),
    "appended": status.get("appended"),
}
marker_path.parent.mkdir(parents=True, exist_ok=True)
tmp = marker_path.with_name(f".{marker_path.name}.tmp")
tmp.write_text(json.dumps(marker, indent=2, sort_keys=True) + "\n", encoding="utf-8")
tmp.chmod(0o600)
tmp.replace(marker_path)
print(json.dumps(marker, indent=2, sort_keys=True))
PY
