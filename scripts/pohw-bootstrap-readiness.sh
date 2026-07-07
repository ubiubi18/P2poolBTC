#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/pohw-bootstrap-readiness.sh [ENV_FILE] [options]

Bootstraps the remaining local sharechain readiness items after miner
registration and a verified Idena snapshot exist.

Default mode is production-safe: it tries to build a Bitcoin job from local
Bitcoin RPC, publish a signed BitcoinWorkTemplate, and accept it locally only
after Bitcoin RPC validation succeeds. While Bitcoin Core is in IBD, this exits
cleanly without appending a fake template.

Options:
  --mode real|dev               real uses Bitcoin RPC; dev uses synthetic local-only work
  --snapshot-file PATH          Snapshot JSON to bind shares to
  --output-dir PATH             Output directory for generated public artifacts
  --share-target HEX            Share target for the bootstrap share
  --max-nonce-tries N           Nonces to try while looking for a share
  --append                      Append generated messages locally
  --no-append                   Do not append generated messages locally
  --peer-addr HOST:PORT         Gossip generated messages to a peer
  --dev-ack I_UNDERSTAND_DEV_ONLY
                                Required with --mode dev and --append
  -h, --help                    Show this help

Dev mode is not Bitcoin mining. It is only for proving the local sharechain
plumbing on a single node without waiting for Bitcoin IBD or peers.
EOF
}

ENV_FILE="${POHW_EXPERIMENT_ENV:-}"
if [[ $# -gt 0 && "$1" != --* ]]; then
  ENV_FILE="$1"
  shift
fi

MODE="${POHW_BOOTSTRAP_MODE:-real}"
SNAPSHOT_FILE="${POHW_BOOTSTRAP_SNAPSHOT_FILE:-}"
OUTPUT_DIR="${POHW_BOOTSTRAP_OUTPUT_DIR:-}"
APPEND="${POHW_BOOTSTRAP_APPEND:-true}"
DEV_ACK="${POHW_BOOTSTRAP_DEV_ACK:-}"
DEFAULT_SHARE_TARGET="7fffff0000000000000000000000000000000000000000000000000000000000"
SHARE_TARGET="${POHW_BOOTSTRAP_SHARE_TARGET:-$DEFAULT_SHARE_TARGET}"
MAX_NONCE_TRIES="${POHW_BOOTSTRAP_MAX_NONCE_TRIES:-10000}"
PEER_ADDRS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="${2:?missing value for --mode}"
      shift 2
      ;;
    --snapshot-file)
      SNAPSHOT_FILE="${2:?missing value for --snapshot-file}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:?missing value for --output-dir}"
      shift 2
      ;;
    --share-target)
      SHARE_TARGET="${2:?missing value for --share-target}"
      shift 2
      ;;
    --max-nonce-tries)
      MAX_NONCE_TRIES="${2:?missing value for --max-nonce-tries}"
      shift 2
      ;;
    --append)
      APPEND="true"
      shift
      ;;
    --no-append)
      APPEND="false"
      shift
      ;;
    --peer-addr)
      PEER_ADDRS+=("${2:?missing value for --peer-addr}")
      shift 2
      ;;
    --dev-ack)
      DEV_ACK="${2:?missing value for --dev-ack}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

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
    exit 1
  fi
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
        echo "Refusing symlinked path component: $current" >&2
        exit 1
      fi
    fi
    current="$(dirname "$current")"
  done
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

if [[ "$MODE" != "real" && "$MODE" != "dev" ]]; then
  echo "--mode must be real or dev" >&2
  exit 1
fi
python3 - "$SHARE_TARGET" "$MAX_NONCE_TRIES" "$DEFAULT_SHARE_TARGET" <<'PY'
import sys

target, max_nonce_tries, max_target = sys.argv[1:4]
if len(target) != 64 or any(char not in "0123456789abcdefABCDEF" for char in target):
    raise SystemExit("--share-target must be exactly 32 bytes encoded as hex")
target_int = int(target, 16)
if target_int == 0:
    raise SystemExit("--share-target must not be zero")
if target_int > int(max_target, 16):
    raise SystemExit("--share-target is easier than the maximum accepted share target")
try:
    tries = int(max_nonce_tries)
except ValueError as exc:
    raise SystemExit("--max-nonce-tries must be a positive integer") from exc
if tries <= 0 or tries > 4_294_967_296:
    raise SystemExit("--max-nonce-tries must be between 1 and 4294967296")
PY
if [[ "$MODE" == "dev" && "$APPEND" == "true" && "$DEV_ACK" != "I_UNDERSTAND_DEV_ONLY" ]]; then
  echo "Dev append requires --dev-ack I_UNDERSTAND_DEV_ONLY." >&2
  echo "Use --no-append for a non-mutating dry run." >&2
  exit 1
fi

WORKDIR="${POHW_WORKDIR:-$(pwd)}"
DATADIR="${POHW_DATADIR:-$WORKDIR/.pohw-p2pool}"
SNAPSHOT_DIR="${POHW_SNAPSHOT_DIR:-$DATADIR/snapshots}"
OUTPUT_ROOT="${POHW_EXPERIMENT_OUTPUT_ROOT:-$WORKDIR/output}"
OUTPUT_DIR="${OUTPUT_DIR:-$OUTPUT_ROOT/work-bootstrap-$(date -u +%Y%m%dT%H%M%SZ)}"
MINER_ID="${POHW_MINER_ID:-}"
if [[ -z "$MINER_ID" ]]; then
  echo "POHW_MINER_ID is required." >&2
  exit 1
fi

if [[ -n "${POHW_P2POOL_NODE_BIN:-}" ]]; then
  P2POOL_CMD=("$POHW_P2POOL_NODE_BIN")
elif [[ -x "$WORKDIR/target/release/p2pool-node" ]]; then
  P2POOL_CMD=("$WORKDIR/target/release/p2pool-node")
elif [[ -x "$WORKDIR/target/debug/p2pool-node" ]]; then
  P2POOL_CMD=("$WORKDIR/target/debug/p2pool-node")
else
  P2POOL_CMD=(cargo run --manifest-path "$WORKDIR/Cargo.toml" -q -p p2pool-node --)
fi

KEY_DIR="$DATADIR/keys/$MINER_ID"
MINING_SECRET_KEY_FILE="${POHW_MINING_SECRET_KEY_FILE:-$KEY_DIR/mining.key}"
NODE_SECRET_KEY_FILE="${POHW_NODE_SECRET_KEY_FILE:-$KEY_DIR/gossip-node.key}"
for key_file in "$MINING_SECRET_KEY_FILE" "$NODE_SECRET_KEY_FILE"; do
  if [[ -L "$key_file" ]]; then
    echo "Refusing symlinked key file: $key_file" >&2
    exit 1
  fi
  if [[ ! -f "$key_file" || ! -r "$key_file" ]]; then
    echo "Required key file is missing or unreadable: $key_file" >&2
    exit 1
  fi
  reject_symlink_ancestor "$key_file"
done

if [[ -L "$OUTPUT_DIR" || -e "$OUTPUT_DIR" ]]; then
  echo "Refusing to reuse existing output directory: $OUTPUT_DIR" >&2
  exit 1
fi
reject_symlink_ancestor "$(dirname "$OUTPUT_DIR")"
mkdir -p "$(dirname "$OUTPUT_DIR")"
mkdir "$OUTPUT_DIR"
chmod 700 "$OUTPUT_DIR"

split_words() {
  printf '%s\n' "$1" | tr ',' ' ' | tr '\n' ' '
}

if [[ "${#PEER_ADDRS[@]}" -eq 0 && -n "${POHW_PEER_ADDRS:-}" ]]; then
  for peer in $(split_words "$POHW_PEER_ADDRS"); do
    [[ -n "$peer" ]] && PEER_ADDRS+=("$peer")
  done
fi

latest_snapshot_file() {
  python3 - "$SNAPSHOT_DIR" <<'PY'
import json
import pathlib
import sys

snapshot_dir = pathlib.Path(sys.argv[1])
candidates = []
for path in sorted(snapshot_dir.glob("*.json")):
    if path.is_symlink() or not path.is_file():
        continue
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        continue
    required = ("snapshot_day", "idena_height", "score_root")
    if not all(data.get(key) for key in required):
        continue
    candidates.append((str(data["snapshot_day"]), int(data["idena_height"]), path.as_posix()))
if not candidates:
    raise SystemExit(1)
print(max(candidates)[2])
PY
}

if [[ -z "$SNAPSHOT_FILE" ]]; then
  if ! SNAPSHOT_FILE="$(latest_snapshot_file)"; then
    echo "No verified snapshot JSON found in $SNAPSHOT_DIR; pass --snapshot-file." >&2
    exit 1
  fi
fi
if [[ -L "$SNAPSHOT_FILE" || ! -f "$SNAPSHOT_FILE" || ! -r "$SNAPSHOT_FILE" ]]; then
  echo "Snapshot file must be a readable regular file: $SNAPSHOT_FILE" >&2
  exit 1
fi
reject_symlink_ancestor "$SNAPSHOT_FILE"

snapshot_fields="$OUTPUT_DIR/snapshot-fields.json"
python3 - "$SNAPSHOT_FILE" > "$snapshot_fields" <<'PY'
import json
import pathlib
import sys

data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
print(json.dumps({
    "snapshot_day": data["snapshot_day"],
    "score_root": data["score_root"],
    "idena_height": data["idena_height"],
}, sort_keys=True))
PY
SNAPSHOT_ID="$(python3 - "$snapshot_fields" <<'PY'
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())["snapshot_day"])
PY
)"
SNAPSHOT_PROOF_ROOT="$(python3 - "$snapshot_fields" <<'PY'
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())["score_root"])
PY
)"

common_publish_args=(
  --datadir "$DATADIR"
  --miner-id "$MINER_ID"
  --mining-secret-key-file "$MINING_SECRET_KEY_FILE"
  --node-secret-key-file "$NODE_SECRET_KEY_FILE"
)
if [[ "$APPEND" == "true" ]]; then
  common_publish_args+=(--append)
fi
if ((${#PEER_ADDRS[@]} > 0)); then
  for peer in "${PEER_ADDRS[@]}"; do
    common_publish_args+=(--peer-addr "$peer")
  done
fi

build_real_candidate() {
  local job_file="$OUTPUT_DIR/mining-job.json"
  local candidate_file="$OUTPUT_DIR/block-candidate.json"
  local job_error_file="$OUTPUT_DIR/build-stratum-job-error.txt"
  local extranonce1="${POHW_BOOTSTRAP_EXTRANONCE1:-00000000}"
  local extranonce2="${POHW_BOOTSTRAP_EXTRANONCE2:-00000000}"
  local -a build_args
  local ntime attempt nonce result_file
  build_args=(build-stratum-job-rpc --job-out "$job_file" --replace)
  if [[ -n "${POHW_BITCOIN_RPC_URL:-${BITCOIN_RPC_URL:-}}" ]]; then
    build_args+=(--rpc-url "${POHW_BITCOIN_RPC_URL:-${BITCOIN_RPC_URL:-}}")
  fi
  if [[ -n "${POHW_BITCOIN_RPC_COOKIE_FILE:-${BITCOIN_RPC_COOKIE_FILE:-}}" ]]; then
    build_args+=(--rpc-cookie-file "${POHW_BITCOIN_RPC_COOKIE_FILE:-${BITCOIN_RPC_COOKIE_FILE:-}}")
  fi
  if [[ "${POHW_BITCOIN_RPC_ALLOW_REMOTE:-false}" == "true" ]]; then
    build_args+=(--allow-remote-rpc)
  fi
  if ! "${P2POOL_CMD[@]}" "${build_args[@]}" > "$OUTPUT_DIR/build-stratum-job-result.json" 2> "$job_error_file"; then
    if grep -Eiq 'initial sync|waiting for blocks|in IBD|in initial block download|getblocktemplate' "$job_error_file"; then
      return 20
    fi
    cat "$job_error_file" >&2
    return 22
  fi
  ntime="$(python3 - "$job_file" <<'PY'
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["ntime"])
PY
)"
  for ((attempt = 0; attempt < MAX_NONCE_TRIES; attempt++)); do
    nonce="$(python3 - "$attempt" <<'PY'
import struct
import sys

print(struct.pack("<I", int(sys.argv[1])).hex())
PY
)"
    result_file="$OUTPUT_DIR/build-block-candidate-result-$attempt.json"
    "${P2POOL_CMD[@]}" build-stratum-block-candidate \
      --job-file "$job_file" \
      --candidate-out "$candidate_file" \
      --replace \
      --extranonce1 "$extranonce1" \
      --extranonce2 "$extranonce2" \
      --ntime "$ntime" \
      --nonce "$nonce" \
      > "$result_file"
    cp "$result_file" "$OUTPUT_DIR/build-block-candidate-result.json"
    if candidate_meets_share_target "$candidate_file"; then
      return 0
    fi
  done
  echo "Could not find a bootstrap share meeting target $SHARE_TARGET in $MAX_NONCE_TRIES tries." >&2
  return 21
}

build_dev_candidate() {
  local candidate_file="$OUTPUT_DIR/block-candidate.json"
  python3 - "$candidate_file" "$SHARE_TARGET" "$MAX_NONCE_TRIES" <<'PY'
import hashlib
import json
import pathlib
import struct
import sys
import time

candidate_file = pathlib.Path(sys.argv[1])
target = sys.argv[2]
max_nonce_tries = int(sys.argv[3])
version = struct.pack("<i", 1).hex()
prev = "00" * 32
merkle = "11" * 32
ntime = struct.pack("<I", max(1, int(time.time()))).hex()
bits = "ffff7f20"
target_int = int(target, 16)
for nonce in range(max_nonce_tries):
    nonce_hex = struct.pack("<I", nonce).hex()
    header = version + prev + merkle + ntime + bits + nonce_hex
    digest = hashlib.sha256(hashlib.sha256(bytes.fromhex(header)).digest()).digest()[::-1].hex()
    if int(digest, 16) <= target_int:
        candidate_file.write_text(json.dumps({
            "bitcoin_header_hex": header,
            "block_hash": digest,
            "target": target,
            "nonce": nonce_hex,
            "mode": "dev-only"
        }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({"candidate_out": str(candidate_file), "block_hash": digest, "nonce": nonce_hex}, indent=2))
        break
else:
    raise SystemExit("could not find dev candidate meeting share target")
PY
}

candidate_meets_share_target() {
  local candidate_file="$1"
  python3 - "$candidate_file" "$SHARE_TARGET" <<'PY'
import json
import pathlib
import sys

candidate = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if int(candidate["block_hash"], 16) <= int(sys.argv[2], 16):
    raise SystemExit(0)
raise SystemExit(1)
PY
}

publish_template_and_share() {
  local candidate_file="$OUTPUT_DIR/block-candidate.json"
  local header_hex header_merkle_root_hex
  local -a template_args
  header_hex="$(python3 - "$candidate_file" <<'PY'
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))["bitcoin_header_hex"])
PY
)"
  header_merkle_root_hex="$(python3 - "$candidate_file" <<'PY'
import json, pathlib, sys
data = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
print(data.get("header_merkle_root_hex") or data["bitcoin_header_hex"][72:136])
PY
)"
  template_args=(publish-bitcoin-work-template)
  template_args+=("${common_publish_args[@]}")
  template_args+=(
    --bitcoin-header-hex "$header_hex" \
    --message-out "$OUTPUT_DIR/bitcoin-work-template-message.json" \
    --envelope-out "$OUTPUT_DIR/bitcoin-work-template-envelope.json" \
    --accept-locally
  )
  if [[ "$MODE" == "real" ]]; then
    template_args+=(--validate-with-bitcoin-rpc --expected-header-merkle-root-hex "$header_merkle_root_hex" --allow-mutable-time)
    if [[ -n "${POHW_BITCOIN_RPC_URL:-${BITCOIN_RPC_URL:-}}" ]]; then
      template_args+=(--rpc-url "${POHW_BITCOIN_RPC_URL:-${BITCOIN_RPC_URL:-}}")
    fi
    if [[ -n "${POHW_BITCOIN_RPC_COOKIE_FILE:-${BITCOIN_RPC_COOKIE_FILE:-}}" ]]; then
      template_args+=(--rpc-cookie-file "${POHW_BITCOIN_RPC_COOKIE_FILE:-${BITCOIN_RPC_COOKIE_FILE:-}}")
    fi
    if [[ "${POHW_BITCOIN_RPC_ALLOW_REMOTE:-false}" == "true" ]]; then
      template_args+=(--allow-remote-rpc)
    fi
  else
    template_args+=(--allow-unverified-local-accept)
  fi
  "${P2POOL_CMD[@]}" "${template_args[@]}" > "$OUTPUT_DIR/bitcoin-work-template-result.json"

  "${P2POOL_CMD[@]}" publish-share \
    "${common_publish_args[@]}" \
    --bitcoin-header-hex "$header_hex" \
    --target "$SHARE_TARGET" \
    --idena-snapshot-id "$SNAPSHOT_ID" \
    --idena-snapshot-proof-root "$SNAPSHOT_PROOF_ROOT" \
    --message-out "$OUTPUT_DIR/share-message.json" \
    --envelope-out "$OUTPUT_DIR/share-envelope.json" \
    > "$OUTPUT_DIR/share-result.json"
}

if [[ "$MODE" == "real" ]]; then
  build_status=0
  build_real_candidate || build_status=$?
  if (( build_status != 0 )); then
    if (( build_status == 20 )); then
      cat > "$OUTPUT_DIR/status.json" <<'JSON'
{
  "status": "bitcoin_not_ready",
  "detail": "Bitcoin RPC could not provide getblocktemplate; no work template or share was appended."
}
JSON
      echo "Bitcoin RPC is not template-ready; wrote $OUTPUT_DIR/status.json" >&2
      exit 0
    fi
    if (( build_status == 22 )); then
      cat > "$OUTPUT_DIR/status.json" <<'JSON'
{
  "status": "bitcoin_rpc_error",
  "detail": "Bitcoin RPC job construction failed for a reason other than initial block download; inspect build-stratum-job-error.txt."
}
JSON
      echo "Bitcoin RPC job construction failed; wrote $OUTPUT_DIR/status.json" >&2
      exit 1
    fi
    cat > "$OUTPUT_DIR/status.json" <<'JSON'
{
  "status": "share_not_found",
  "detail": "Bitcoin RPC produced a job, but no header met the configured share target within the nonce search limit."
}
JSON
    echo "No bootstrap share found; wrote $OUTPUT_DIR/status.json" >&2
    exit 1
  fi
else
  build_dev_candidate > "$OUTPUT_DIR/build-dev-candidate-result.json"
fi

publish_template_and_share
"${P2POOL_CMD[@]}" multinode-preflight \
  --datadir "$DATADIR" \
  --snapshot-dir "$SNAPSHOT_DIR" \
  --miner-id "$MINER_ID" \
  > "$OUTPUT_DIR/multinode-preflight.json"

python3 - "$OUTPUT_DIR" "$MODE" "$APPEND" "$SHARE_TARGET" <<'PY'
import json
import pathlib
import sys

out = pathlib.Path(sys.argv[1])
summary = {
    "status": "completed",
    "mode": sys.argv[2],
    "appended": sys.argv[3] == "true",
    "output_dir": str(out),
    "share_target": sys.argv[4],
  }
preflight = out / "multinode-preflight.json"
if preflight.exists():
    summary["readiness"] = json.loads(preflight.read_text(encoding="utf-8")).get("readiness")
(out / "status.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=2, sort_keys=True))
PY
