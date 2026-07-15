#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Build P2poolBTC locally from a clean source tree and open the join wizard.

Usage:
  scripts/pohw-community-join.sh \
    --gossip-peer HOST:PORT \
    --fork-rpc-peer HOST:PORT \
    --fork-p2p-peer HOST:PORT [options]

Required (repeat each option for additional independent peers):
  --gossip-peer HOST:PORT
  --fork-rpc-peer HOST:PORT
  --fork-p2p-peer HOST:PORT

Options:
  --datadir PATH                 Local state outside the source tree
  --launch-phase PHASE          registration, fork-sync, or mining
  --explorer-url HTTPS_URL      Optional public experiment explorer
  --snapshot-dir PATH           Verified snapshot JSON directory for mining
  --snapshot-min-voters N       Required signed snapshot-vote quorum for mining
  --allow-private-peers         Permit LAN/loopback peers for a local test
  --verify-tests                Run focused Rust tests before onboarding
  --no-open                     Print the local wizard URL without opening it
  -h, --help                    Show this help

This command trusts no prebuilt executable and no lead-developer signature.
It builds from the current clean source tree and records a deterministic source
CID, Git commit metadata, Cargo.lock digest, compiler versions, local binary
digest, and the tracked Experiment 0 activation digest.
EOF
}

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
DATADIR="${HOME}/.pohw-agent/pohw-experiment-0"
LAUNCH_PHASE="registration"
EXPLORER_URL=""
SNAPSHOT_DIR=""
SNAPSHOT_MIN_VOTERS=""
ALLOW_PRIVATE_PEERS=false
VERIFY_TESTS=false
NO_OPEN=false
GOSSIP_PEERS=()
FORK_RPC_PEERS=()
FORK_P2P_PEERS=()

while (($#)); do
  case "$1" in
    --gossip-peer)
      [[ $# -ge 2 ]] || { echo "missing value for $1" >&2; exit 2; }
      GOSSIP_PEERS+=("$2")
      shift 2
      ;;
    --fork-rpc-peer)
      [[ $# -ge 2 ]] || { echo "missing value for $1" >&2; exit 2; }
      FORK_RPC_PEERS+=("$2")
      shift 2
      ;;
    --fork-p2p-peer)
      [[ $# -ge 2 ]] || { echo "missing value for $1" >&2; exit 2; }
      FORK_P2P_PEERS+=("$2")
      shift 2
      ;;
    --datadir)
      [[ $# -ge 2 ]] || { echo "missing value for $1" >&2; exit 2; }
      DATADIR="$2"
      shift 2
      ;;
    --launch-phase)
      [[ $# -ge 2 ]] || { echo "missing value for $1" >&2; exit 2; }
      LAUNCH_PHASE="$2"
      shift 2
      ;;
    --explorer-url)
      [[ $# -ge 2 ]] || { echo "missing value for $1" >&2; exit 2; }
      EXPLORER_URL="$2"
      shift 2
      ;;
    --snapshot-dir)
      [[ $# -ge 2 ]] || { echo "missing value for $1" >&2; exit 2; }
      SNAPSHOT_DIR="$2"
      shift 2
      ;;
    --snapshot-min-voters)
      [[ $# -ge 2 ]] || { echo "missing value for $1" >&2; exit 2; }
      SNAPSHOT_MIN_VOTERS="$2"
      shift 2
      ;;
    --allow-private-peers)
      ALLOW_PRIVATE_PEERS=true
      shift
      ;;
    --verify-tests)
      VERIFY_TESTS=true
      shift
      ;;
    --no-open)
      NO_OPEN=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ ${#GOSSIP_PEERS[@]} -gt 0 ]] || { echo "at least one --gossip-peer is required" >&2; exit 2; }
[[ ${#FORK_RPC_PEERS[@]} -gt 0 ]] || { echo "at least one --fork-rpc-peer is required" >&2; exit 2; }
[[ ${#FORK_P2P_PEERS[@]} -gt 0 ]] || { echo "at least one --fork-p2p-peer is required" >&2; exit 2; }
case "$LAUNCH_PHASE" in
  registration|fork-sync|mining) ;;
  *) echo "--launch-phase must be registration, fork-sync, or mining" >&2; exit 2 ;;
esac

if [[ "$LAUNCH_PHASE" == mining ]]; then
  [[ -n "$SNAPSHOT_DIR" && -n "$SNAPSHOT_MIN_VOTERS" ]] || {
    echo "mining requires --snapshot-dir and --snapshot-min-voters" >&2
    exit 2
  }
  [[ "$SNAPSHOT_MIN_VOTERS" =~ ^[1-9][0-9]*$ ]] || {
    echo "--snapshot-min-voters must be a positive integer" >&2
    exit 2
  }
elif [[ -n "$SNAPSHOT_DIR" || -n "$SNAPSHOT_MIN_VOTERS" ]]; then
  echo "snapshot options are accepted only with --launch-phase mining" >&2
  exit 2
fi

command -v git >/dev/null || { echo "git is required" >&2; exit 1; }
command -v cargo >/dev/null || { echo "Cargo is required" >&2; exit 1; }
if [[ -n "$(git -C "$ROOT_DIR" status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "source worktree is dirty; use a clean committed checkout" >&2
  exit 1
fi
if [[ -n "$(git -C "$ROOT_DIR" ls-files --others --ignored --exclude-standard --directory)" ]]; then
  echo "source tree contains ignored files or directories; use a fresh checkout" >&2
  exit 1
fi

BUILD_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/pohw-source-build.XXXXXXXX")"
chmod 700 "$BUILD_ROOT"
cleanup_build_root() {
  [[ -z "${BUILD_ROOT:-}" || ! -d "$BUILD_ROOT" ]] || rm -rf -- "$BUILD_ROOT"
}
trap cleanup_build_root EXIT

unset RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
unset CARGO_BUILD_RUSTC CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_TARGET
export CARGO_TARGET_DIR="$BUILD_ROOT"
cd -- "$ROOT_DIR"
echo "Building pohw-agent and p2pool-node from the local locked source tree..."
cargo build --manifest-path "$ROOT_DIR/Cargo.toml" --locked --release \
  -p p2pool-node -p pohw-agent
if [[ "$VERIFY_TESTS" == true ]]; then
  cargo test --manifest-path "$ROOT_DIR/Cargo.toml" --locked \
    -p p2pool-node -p pohw-agent
fi

AGENT="$BUILD_ROOT/release/pohw-agent"
NODE="$BUILD_ROOT/release/p2pool-node"
[[ -x "$AGENT" && -x "$NODE" ]] || { echo "local source build did not produce the expected executables" >&2; exit 1; }

args=(
  join-source
  --source-root "$ROOT_DIR"
  --build-root "$BUILD_ROOT"
  --p2pool-node "$NODE"
  --activation-manifest "$ROOT_DIR/compatibility/experiment-0-activation.json"
  --datadir "$DATADIR"
  --launch-phase "$LAUNCH_PHASE"
)
for peer in "${GOSSIP_PEERS[@]}"; do args+=(--gossip-peer "$peer"); done
for peer in "${FORK_RPC_PEERS[@]}"; do args+=(--fork-rpc-peer "$peer"); done
for peer in "${FORK_P2P_PEERS[@]}"; do args+=(--fork-p2p-peer "$peer"); done
[[ -z "$EXPLORER_URL" ]] || args+=(--explorer-url "$EXPLORER_URL")
if [[ "$LAUNCH_PHASE" == mining ]]; then
  args+=(
    --snapshot-dir "$SNAPSHOT_DIR"
    --snapshot-min-voters "$SNAPSHOT_MIN_VOTERS"
  )
fi
[[ "$ALLOW_PRIVATE_PEERS" == false ]] || args+=(--allow-private-peers)
[[ "$NO_OPEN" == false ]] || args+=(--no-open)

"$AGENT" "${args[@]}"
