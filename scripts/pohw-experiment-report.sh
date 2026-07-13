#!/usr/bin/env bash
set -euo pipefail
set -f
umask 077

ENV_FILE="${1:-${POHW_EXPERIMENT_ENV:-}}"
validate_env_file() {
  local file="$1"
  local owner mode unsafe_bits parent parent_mode parent_unsafe_bits current
  if [[ ! -f "$file" ]]; then
    echo "Experiment env file not found: $file" >&2
    exit 1
  fi
  if [[ -L "$file" ]]; then
    echo "Refusing to source symlinked env file: $file" >&2
    exit 1
  fi
  parent="$(dirname "$file")"
  if [[ -L "$parent" ]]; then
    echo "Refusing to source env file from symlinked directory: $parent" >&2
    exit 1
  fi
  if [[ ! -d "$parent" ]]; then
    echo "Env file parent is not a directory: $parent" >&2
    exit 1
  fi
  current="$parent"
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
        echo "Refusing to source env file through symlinked path component: $current" >&2
        exit 1
      fi
    fi
    current="$(dirname "$current")"
  done
  parent="$(dirname "$file")"
  if parent_mode="$(stat -c %a "$parent" 2>/dev/null)"; then
    :
  else
    parent_mode="$(stat -f %Lp "$parent")"
  fi
  parent_unsafe_bits=$((8#$parent_mode & 022))
  if (( parent_unsafe_bits != 0 )); then
    echo "Refusing to source env file from group/world-writable directory: $parent" >&2
    echo "Fix with: chmod go-w $parent" >&2
    exit 1
  fi
  if owner="$(stat -c %u "$file" 2>/dev/null)"; then
    :
  else
    owner="$(stat -f %u "$file")"
  fi
  if [[ "$owner" != "$(id -u)" ]]; then
    echo "Refusing to source env file not owned by the current user: $file" >&2
    exit 1
  fi
  if mode="$(stat -c %a "$file" 2>/dev/null)"; then
    :
  else
    mode="$(stat -f %Lp "$file")"
  fi
  unsafe_bits=$((8#$mode & 022))
  if (( unsafe_bits != 0 )); then
    echo "Refusing to source group/world-writable env file: $file" >&2
    echo "Fix with: chmod 600 $file" >&2
    exit 1
  fi
}

if [[ -n "$ENV_FILE" ]]; then
  validate_env_file "$ENV_FILE"
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
elif [[ -f ".pohw-experiment.env" ]]; then
  validate_env_file ".pohw-experiment.env"
  set -a
  # shellcheck disable=SC1091
  . ".pohw-experiment.env"
  set +a
fi

WORKDIR="${POHW_WORKDIR:-$(pwd)}"
DATADIR="${POHW_DATADIR:-$WORKDIR/.pohw-p2pool}"
SNAPSHOT_DIR="${POHW_SNAPSHOT_DIR:-$WORKDIR/snapshots}"
OUTPUT_ROOT="${POHW_EXPERIMENT_OUTPUT_ROOT:-$WORKDIR/output}"
OUTPUT_DIR="$OUTPUT_ROOT/experiment-report-$(date -u +%Y%m%dT%H%M%SZ)"
MINER_ID="${POHW_MINER_ID:-}"
PEER_ADDRS="${POHW_PEER_ADDRS:-}"
FORK_ACTIVATION_MANIFEST="${POHW_FORK_ACTIVATION_MANIFEST:-$DATADIR/fork-activation.json}"
MAX_GOSSIP_LOG_EXPORT_BYTES="${POHW_MAX_GOSSIP_LOG_EXPORT_BYTES:-67108864}"
MAX_GOSSIP_LOG_EXPORT_LINES="${POHW_MAX_GOSSIP_LOG_EXPORT_LINES:-200000}"

if [[ -n "${POHW_P2POOL_NODE_BIN:-}" ]]; then
  P2POOL_CMD=("$POHW_P2POOL_NODE_BIN")
elif [[ -x "$WORKDIR/target/release/p2pool-node" ]]; then
  P2POOL_CMD=("$WORKDIR/target/release/p2pool-node")
elif [[ -x "$WORKDIR/target/debug/p2pool-node" ]]; then
  P2POOL_CMD=("$WORKDIR/target/debug/p2pool-node")
else
  P2POOL_CMD=(cargo run --manifest-path "$WORKDIR/Cargo.toml" -q -p p2pool-node --)
fi

split_words() {
  printf '%s\n' "$1" | tr ',' ' ' | tr '\n' ' '
}

reject_symlink_ancestor() {
  local path="$1"
  local current="$path" owner parent parent_mode parent_unsafe_bits
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
        echo "Refusing to write through symlinked path component: $current" >&2
        exit 1
      fi
    fi
    current="$(dirname "$current")"
  done
}

run_capture() {
  local label="$1"
  local stdout_path="$OUTPUT_DIR/$label"
  local stdout_tmp="$OUTPUT_DIR/$label.tmp"
  local stderr_path="$OUTPUT_DIR/$label.stderr"
  shift
  for path in "$stdout_path" "$stdout_tmp" "$stderr_path"; do
    if [[ -e "$path" ]]; then
      echo "Refusing to overwrite existing report artifact: $path" >&2
      exit 1
    fi
  done
  if "$@" > "$stdout_tmp" 2> "$stderr_path"; then
    mv "$stdout_tmp" "$stdout_path"
    echo "$label ok" >> "$OUTPUT_DIR/manifest.txt"
  else
    rm -f "$stdout_tmp" "$stdout_path"
    echo "$label failed" >> "$OUTPUT_DIR/manifest.txt"
  fi
  rm -f "$stderr_path"
}

redact_json_file() {
  local path="$1"
  [[ -s "$path" ]] || return 0
  python3 - "$path" <<'PY'
import json
import pathlib
import sys

MAX_JSON_BYTES = 16 * 1024 * 1024
path = pathlib.Path(sys.argv[1])

def read_limited_json_file(path):
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError(f"JSON artifact exceeds {MAX_JSON_BYTES} bytes")
    return json.loads(path.read_text(encoding="utf-8"))

try:
    data = read_limited_json_file(path)
except Exception as exc:
    raise SystemExit(f"refusing to publish malformed JSON artifact {path}: {exc}") from exc

PATH_KEYS = {
    "datadir",
    "gossip_envelope_log",
    "path",
    "sharechain_log",
    "snapshot_dir",
    "workdir",
}
NETWORK_KEYS = {
    "addr",
    "advertise_addr",
    "bind_addr",
    "listening_on",
    "peer_addr",
    "peer_addrs",
    "remote_addr",
    "rpc_addr",
}
ERROR_KEYS = {"error"}

def scrub(value):
    if isinstance(value, dict):
        return {
            key: (
                "<redacted>"
                if key in PATH_KEYS | NETWORK_KEYS | ERROR_KEYS
                else scrub(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [scrub(item) for item in value]
    return value

path.write_text(json.dumps(scrub(data), indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

export_miner_registration_proof() {
  local log_path="$DATADIR/gossip-envelopes.ndjson"
  local envelope_out="$OUTPUT_DIR/miner-registration-envelope.json"
  local summary_out="$OUTPUT_DIR/miner-registration-proof-summary.json"
  local log_size
  for path in "$envelope_out" "$summary_out"; do
    if [[ -e "$path" ]]; then
      echo "Refusing to overwrite existing report artifact: $path" >&2
      exit 1
    fi
  done

  if [[ -z "$MINER_ID" ]]; then
    printf '{\n  "found": false,\n  "reason": "POHW_MINER_ID not configured"\n}\n' > "$summary_out"
    return 0
  fi
  if [[ -L "$log_path" ]]; then
    echo "Refusing symlinked gossip envelope log: $log_path" >&2
    exit 1
  fi
  if [[ -e "$log_path" && ! -f "$log_path" ]]; then
    echo "Gossip envelope log must be a regular file: $log_path" >&2
    exit 1
  fi
  if [[ ! -s "$log_path" ]]; then
    printf '{\n  "found": false,\n  "reason": "gossip envelope log not found or empty"\n}\n' > "$summary_out"
    return 0
  fi
  reject_symlink_ancestor "$log_path"
  if log_size="$(stat -c %s "$log_path" 2>/dev/null)"; then
    :
  else
    log_size="$(stat -f %z "$log_path")"
  fi
  if (( log_size > MAX_GOSSIP_LOG_EXPORT_BYTES )); then
    echo "Gossip envelope log is too large for report export: $log_path ($log_size bytes; maximum $MAX_GOSSIP_LOG_EXPORT_BYTES)" >&2
    exit 1
  fi

  python3 - "$log_path" "$MINER_ID" "$envelope_out" "$summary_out" "$MAX_GOSSIP_LOG_EXPORT_BYTES" "$MAX_GOSSIP_LOG_EXPORT_LINES" <<'PY'
import json
import os
import pathlib
import stat
import sys

log_path = pathlib.Path(sys.argv[1])
miner_id = sys.argv[2].strip().lower()
envelope_out = pathlib.Path(sys.argv[3])
summary_out = pathlib.Path(sys.argv[4])
max_bytes = int(sys.argv[5])
max_lines = int(sys.argv[6])

open_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
try:
    fd = os.open(log_path, open_flags)
except OSError as exc:
    raise SystemExit(f"failed to open gossip envelope log safely: {exc}") from exc

file_stat = os.fstat(fd)
if not stat.S_ISREG(file_stat.st_mode):
    os.close(fd)
    raise SystemExit(f"gossip envelope log must be a non-symlink regular file: {log_path}")
if file_stat.st_size > max_bytes:
    os.close(fd)
    raise SystemExit(f"gossip envelope log exceeds {max_bytes} bytes")

selected = None
selected_summary = None
parse_errors = 0

def miner_registration_payload(envelope):
    if not isinstance(envelope, dict):
        return None
    message = envelope.get("message")
    if not isinstance(message, dict):
        return None
    if message.get("type") == "MinerRegistration" and isinstance(message.get("payload"), dict):
        return message["payload"]
    return None

with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as handle:
    for line_number, line in enumerate(handle, start=1):
        if line_number > max_lines:
            raise SystemExit(f"gossip envelope log exceeds {max_lines} lines")
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except Exception:
            parse_errors += 1
            continue
        envelope = record.get("envelope") if isinstance(record, dict) else None
        if not isinstance(envelope, dict):
            envelope = record
        payload = miner_registration_payload(envelope)
        if not payload or str(payload.get("miner_id", "")).lower() != miner_id:
            continue
        selected = envelope
        selected_summary = {
            "found": True,
            "miner_id": payload.get("miner_id"),
            "idena_address": payload.get("idena_address"),
            "btc_payout_script_hex": payload.get("btc_payout_script_hex"),
            "claim_owner_pubkey_hex": payload.get("claim_owner_pubkey_hex"),
            "mining_pubkey_hex": payload.get("mining_pubkey_hex"),
            "envelope_hash": record.get("envelope_hash") if isinstance(record, dict) else None,
            "message_hash": record.get("message_hash") if isinstance(record, dict) else None,
            "peer_pubkey_xonly_hex": envelope.get("peer_pubkey_xonly_hex"),
            "parse_errors": parse_errors,
        }

if selected is None:
    summary = {
        "found": False,
        "reason": "signed MinerRegistration envelope not found for POHW_MINER_ID",
        "miner_id": miner_id,
        "parse_errors": parse_errors,
    }
else:
    envelope_out.write_text(
        json.dumps(selected, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    summary = selected_summary

summary_out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

create_output_dir() {
  local dir="$1"
  local parent
  if [[ -L "$dir" ]]; then
    echo "Refusing to write into symlinked output directory: $dir" >&2
    exit 1
  fi
  if [[ -e "$dir" ]]; then
    echo "Refusing to reuse existing output directory: $dir" >&2
    exit 1
  fi
  parent="$(dirname "$dir")"
  if [[ -L "$parent" ]]; then
    echo "Refusing to write into symlinked output parent: $parent" >&2
    exit 1
  fi
  reject_symlink_ancestor "$parent"
  mkdir -p "$parent"
  mkdir "$dir"
}

create_output_dir "$OUTPUT_DIR"

gossip_peer_count=0
for peer in $(split_words "$PEER_ADDRS"); do
  [[ -z "$peer" ]] && continue
  gossip_peer_count=$((gossip_peer_count + 1))
done

{
  echo "generated_at_utc=$(date -u +%FT%TZ)"
  echo "miner_id=$MINER_ID"
  echo "fork_chain_name=${POHW_FORK_CHAIN_NAME:-pohw-experiment-0}"
  echo "fork_launch_timestamp_utc=${POHW_FORK_LAUNCH_TIMESTAMP_UTC:-}"
  echo "gossip_bind_configured=$([[ -n "${POHW_GOSSIP_BIND_ADDR:-}" ]] && echo true || echo false)"
  echo "advertise_addr_configured=$([[ -n "${POHW_ADVERTISE_ADDR:-}" ]] && echo true || echo false)"
  echo "gossip_peer_count=$gossip_peer_count"
  git -C "$WORKDIR" rev-parse --abbrev-ref HEAD 2>/dev/null | sed 's/^/git_branch=/' || true
  git -C "$WORKDIR" rev-parse HEAD 2>/dev/null | sed 's/^/git_commit=/' || true
  if [[ -z "$(git -C "$WORKDIR" status --porcelain --untracked-files=normal 2>/dev/null)" ]]; then
    echo "git_dirty=false"
  else
    echo "git_dirty=true"
  fi
} > "$OUTPUT_DIR/metadata.txt"

if [[ -L "$FORK_ACTIVATION_MANIFEST" ]]; then
  echo "Refusing symlinked fork activation manifest: $FORK_ACTIVATION_MANIFEST" >&2
  exit 1
elif [[ -e "$FORK_ACTIVATION_MANIFEST" && ! -f "$FORK_ACTIVATION_MANIFEST" ]]; then
  echo "Fork activation manifest must be a regular file: $FORK_ACTIVATION_MANIFEST" >&2
  exit 1
elif [[ -s "$FORK_ACTIVATION_MANIFEST" ]]; then
  reject_symlink_ancestor "$FORK_ACTIVATION_MANIFEST"
  cp "$FORK_ACTIVATION_MANIFEST" "$OUTPUT_DIR/fork-activation.json"
fi

cat > "$OUTPUT_DIR/README.txt" <<'EOF'
PoHW Experiment 0 report bundle.

This bundle is intended to be shareable with other experiment participants.
It should contain public replay status only. It must not contain private keys,
Idena API keys, Bitcoin RPC cookies, dashboard API tokens, passwords, seed
phrases, peer network addresses, or raw service journals. The signed miner
registration proof intentionally contains the public Idena address, payout
script, and public keys needed to verify participant quorum.
EOF

run_capture status.json "${P2POOL_CMD[@]}" status --datadir "$DATADIR"
redact_json_file "$OUTPUT_DIR/status.json"
run_capture gossip-peers.json "${P2POOL_CMD[@]}" list-gossip-peers --datadir "$DATADIR"
redact_json_file "$OUTPUT_DIR/gossip-peers.json"

preflight_args=(multinode-preflight --datadir "$DATADIR" --snapshot-dir "$SNAPSHOT_DIR")
if [[ -n "$MINER_ID" ]]; then
  preflight_args+=(--miner-id "$MINER_ID")
fi
for peer in $(split_words "$PEER_ADDRS"); do
  [[ -z "$peer" ]] && continue
  preflight_args+=(--peer-addr "$peer")
done
run_capture multinode-preflight.json "${P2POOL_CMD[@]}" "${preflight_args[@]}"
redact_json_file "$OUTPUT_DIR/multinode-preflight.json"
export_miner_registration_proof

python3 - "$SNAPSHOT_DIR" > "$OUTPUT_DIR/latest-snapshot-summary.json" <<'PY'
import json
import pathlib
import sys

MAX_JSON_BYTES = 16 * 1024 * 1024
snapshot_dir = pathlib.Path(sys.argv[1])
files = sorted(snapshot_dir.glob("*.json"))
latest = None
for path in files:
    if path.is_symlink() or not path.is_file():
        continue
    if path.stat().st_size > MAX_JSON_BYTES:
        continue
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        continue
    required = ["snapshot_day", "idena_height", "idena_block_hash", "identity_root", "score_root"]
    if all(key in data for key in required):
        latest = (path, data)

if latest is None:
    print(json.dumps({"configured": snapshot_dir.exists(), "latest": None}, indent=2, sort_keys=True))
else:
    path, data = latest
    print(json.dumps({
        "configured": True,
        "snapshot_day": data.get("snapshot_day"),
        "idena_height": data.get("idena_height"),
        "idena_block_hash": data.get("idena_block_hash"),
        "identity_root": data.get("identity_root"),
        "score_root": data.get("score_root"),
        "formula_version": data.get("formula_version"),
        "leaf_count": len(data.get("leaves") or []),
    }, indent=2, sort_keys=True))
PY
redact_json_file "$OUTPUT_DIR/latest-snapshot-summary.json"

if command -v systemctl >/dev/null 2>&1; then
  for service in \
    bitcoind-mainnet.service \
    idena.service \
    idena-reward-indexer.service \
    idena-session-recorder.service \
    pohw-gossip-mesh.service \
    pohw-dashboard-api.service
  do
    printf '%s=' "$service"
    systemctl is-active "$service" 2>/dev/null || true
  done > "$OUTPUT_DIR/systemd-active.txt"
fi

archive="$OUTPUT_DIR.tar.gz"
if [[ -e "$archive" ]]; then
  echo "Refusing to overwrite existing report archive: $archive" >&2
  exit 1
fi
tar -czf "$archive" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")"

echo "Report directory: $OUTPUT_DIR"
echo "Shareable archive: $archive"
