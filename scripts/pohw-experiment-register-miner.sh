#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/pohw-experiment-register-miner.sh [ENV_FILE] [options]

Creates the local miner registration challenge, then publishes the signed
registration after the Idena signature is supplied.

Options:
  --idena-address ADDRESS       Idena address to bind to this miner
  --idena-signature-hex HEX     Signature over the printed ownership challenge
  --output-dir PATH             Output directory for local registration artifacts
  --no-append                   Do not append the signed registration locally
  --no-gossip                   Do not send the signed registration to configured peers
  -h, --help                    Show this help

First run without --idena-signature-hex. Sign the printed
idena_ownership_challenge in Idena, then rerun with --idena-signature-hex.
EOF
}

ENV_FILE="${POHW_EXPERIMENT_ENV:-}"
if [[ $# -gt 0 && "$1" != --* ]]; then
  ENV_FILE="$1"
  shift
fi

IDENA_ADDRESS=""
IDENA_SIGNATURE_HEX=""
OUTPUT_DIR=""
APPEND="true"
GOSSIP="true"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --idena-address)
      IDENA_ADDRESS="${2:?missing value for --idena-address}"
      shift 2
      ;;
    --idena-signature-hex)
      IDENA_SIGNATURE_HEX="${2:?missing value for --idena-signature-hex}"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="${2:?missing value for --output-dir}"
      shift 2
      ;;
    --no-append)
      APPEND="false"
      shift
      ;;
    --no-gossip)
      GOSSIP="false"
      shift
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

if [[ "${POHW_EXPERIMENT_NO_VALUE_ACK:-}" != "I_UNDERSTAND_NO_VALUE" ]]; then
  echo "Set POHW_EXPERIMENT_NO_VALUE_ACK=I_UNDERSTAND_NO_VALUE before joining Experiment 0." >&2
  exit 1
fi

WORKDIR="${POHW_WORKDIR:-$(pwd)}"
DATADIR="${POHW_DATADIR:-$WORKDIR/.pohw-p2pool}"
OUTPUT_ROOT="${POHW_EXPERIMENT_OUTPUT_ROOT:-$WORKDIR/output}"
MINER_ID="${POHW_MINER_ID:-}"
PEER_ADDRS="${POHW_PEER_ADDRS:-}"
IDENA_ADDRESS="${IDENA_ADDRESS:-${POHW_IDENA_ADDRESS:-${POHW_DASHBOARD_IDENA_ADDRESS:-}}}"
OUTPUT_DIR="${OUTPUT_DIR:-$OUTPUT_ROOT/experiment-registration-$(date -u +%Y%m%dT%H%M%SZ)}"

if [[ -z "$MINER_ID" ]]; then
  echo "POHW_MINER_ID is required. Run scripts/pohw-experiment-init.sh first." >&2
  exit 1
fi
if [[ -z "$IDENA_ADDRESS" ]]; then
  echo "Idena address is required. Pass --idena-address or set POHW_IDENA_ADDRESS." >&2
  exit 1
fi
if [[ "$IDENA_ADDRESS" =~ [[:space:]] ]]; then
  echo "Idena address must not contain whitespace." >&2
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

write_public_view() {
  local input="$1"
  local output="$2"
  if [[ -e "$output" ]]; then
    echo "Refusing to overwrite existing output file: $output" >&2
    exit 1
  fi
  python3 - "$input" "$output" <<'PY'
import json
import pathlib
import sys

MAX_JSON_BYTES = 16 * 1024 * 1024
source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
if source.stat().st_size > MAX_JSON_BYTES:
    raise SystemExit(f"private registration output exceeds {MAX_JSON_BYTES} bytes")
data = json.loads(source.read_text(encoding="utf-8"))

PATH_KEYS = {"message_out", "envelope_out", "path"}

def scrub(value):
    if isinstance(value, dict):
        scrubbed = {}
        for key, item in value.items():
            if key in PATH_KEYS and isinstance(item, str):
                scrubbed[key] = "<redacted>"
            else:
                scrubbed[key] = scrub(item)
        return scrubbed
    if isinstance(value, list):
        return [scrub(item) for item in value]
    return value

target.write_text(json.dumps(scrub(data), indent=2, sort_keys=True) + "\n", encoding="utf-8")
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

ensure_local_dir() {
  local dir="$1"
  local label="$2"
  if [[ -L "$dir" ]]; then
    echo "Refusing to use symlinked $label directory: $dir" >&2
    exit 1
  fi
  if [[ -e "$dir" && ! -d "$dir" ]]; then
    echo "$label path is not a directory: $dir" >&2
    exit 1
  fi
  reject_symlink_ancestor "$dir"
  mkdir -p "$dir"
}

ensure_local_dir "$DATADIR" "datadir"
create_output_dir "$OUTPUT_DIR"
raw_out="$OUTPUT_DIR/registration-local-private.json"
public_out="$OUTPUT_DIR/registration-public.json"
message_out="$OUTPUT_DIR/miner-registration-message.json"
envelope_out="$OUTPUT_DIR/miner-registration-envelope.json"
for path in "$raw_out" "$public_out"; do
  if [[ -e "$path" ]]; then
    echo "Refusing to overwrite existing output file: $path" >&2
    exit 1
  fi
done

args=(
  prepare-miner-registration
  --datadir "$DATADIR"
  --miner-id "$MINER_ID"
  --idena-address "$IDENA_ADDRESS"
)

if [[ -n "$IDENA_SIGNATURE_HEX" ]]; then
  args+=(--idena-signature-hex "$IDENA_SIGNATURE_HEX")
  args+=(--message-out "$message_out")
  args+=(--envelope-out "$envelope_out")
  for path in "$message_out" "$envelope_out"; do
    if [[ -e "$path" ]]; then
      echo "Refusing to overwrite existing output file: $path" >&2
      exit 1
    fi
  done
  if [[ "$APPEND" == "true" ]]; then
    args+=(--append)
  fi
  if [[ "$GOSSIP" == "true" && -n "$PEER_ADDRS" ]]; then
    for peer in $(split_words "$PEER_ADDRS"); do
      [[ -z "$peer" ]] && continue
      args+=(--peer-addr "$peer")
    done
  fi
fi

raw_tmp="$(mktemp "$OUTPUT_DIR/.registration-local-private.XXXXXX")"
trap 'rm -f "$raw_tmp"' EXIT
"${P2POOL_CMD[@]}" "${args[@]}" > "$raw_tmp"
mv "$raw_tmp" "$raw_out"
trap - EXIT
write_public_view "$raw_out" "$public_out"

cat "$public_out"
echo "Local private registration output written: registration-local-private.json" >&2
echo "Public registration output written: registration-public.json" >&2
if [[ -z "$IDENA_SIGNATURE_HEX" ]]; then
  echo "Next: sign idena_ownership_challenge in Idena, then rerun this script with --idena-signature-hex." >&2
else
  echo "Next: run scripts/pohw-experiment-preflight.sh ${ENV_FILE:-.pohw-experiment.env}" >&2
fi
