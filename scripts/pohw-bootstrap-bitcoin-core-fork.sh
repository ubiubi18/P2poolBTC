#!/usr/bin/env bash
set -euo pipefail

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
MANIFEST="$REPO_ROOT/compatibility/experiment-1-full-consensus.json"
SOURCE_DATADIR=/srv/bitcoin/mainnet
TARGET_BASE=/srv/bitcoin/pohw
SOURCE_SERVICE=bitcoind-mainnet.service
SOURCE_USER=bitcoin
FORK_USER=bitcoin-pohw
SHARED_GROUP=bitcoin-chain-read
RPC_GROUP=bitcoin-pohw-rpc
BITCOIND=/usr/local/bin/bitcoind
BITCOIN_CLI=/usr/local/bin/bitcoin-cli
RESTART_MAIN=false

usage() {
  cat <<'EOF'
Usage: sudo scripts/pohw-bootstrap-bitcoin-core-fork.sh [options]

Create a consistent Experiment 1 datadir from a mainnet node stopped at the
pinned fork point. Historical blk/rev files are cloned with copy-on-write when
supported and otherwise copied; the active tail is always copied without
reflinks. Block index and chainstate are copied. Wallets, cookies, peer state,
logs, settings, and mempool files are never copied.

Options:
  --manifest FILE
  --source-datadir DIR
  --target-base DIR
  --source-service UNIT
  --source-user USER
  --fork-user USER
  --shared-group GROUP  Deprecated compatibility option; no files are shared
  --rpc-group GROUP
  --bitcoind FILE
  --bitcoin-cli FILE
  --restart-main       Restart mainnet even if it was stopped on entry
EOF
}

while (($#)); do
  case "$1" in
    --manifest) MANIFEST=${2:?}; shift 2 ;;
    --source-datadir) SOURCE_DATADIR=${2:?}; shift 2 ;;
    --target-base) TARGET_BASE=${2:?}; shift 2 ;;
    --source-service) SOURCE_SERVICE=${2:?}; shift 2 ;;
    --source-user) SOURCE_USER=${2:?}; shift 2 ;;
    --fork-user) FORK_USER=${2:?}; shift 2 ;;
    --shared-group) SHARED_GROUP=${2:?}; shift 2 ;;
    --rpc-group) RPC_GROUP=${2:?}; shift 2 ;;
    --bitcoind) BITCOIND=${2:?}; shift 2 ;;
    --bitcoin-cli) BITCOIN_CLI=${2:?}; shift 2 ;;
    --restart-main) RESTART_MAIN=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "run as root" >&2; exit 1; }
for account in "$SOURCE_USER" "$FORK_USER" "$SHARED_GROUP" "$RPC_GROUP"; do
  [[ "$account" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]] || {
    echo "invalid local account or group name: $account" >&2
    exit 1
  }
done
[[ "$SOURCE_SERVICE" =~ ^[A-Za-z0-9_.@-]+\.service$ ]] || {
  echo "invalid source service unit: $SOURCE_SERVICE" >&2
  exit 1
}
BITCOIND=$(readlink -f -- "$BITCOIND")
BITCOIN_CLI=$(readlink -f -- "$BITCOIN_CLI")
for binary in "$BITCOIND" "$BITCOIN_CLI"; do
  [[ "$binary" = /* && -f "$binary" && -x "$binary" ]] || {
    echo "binary must resolve to an executable regular file: $binary" >&2
    exit 1
  }
done
for path in "$SOURCE_DATADIR" "$TARGET_BASE"; do
  [[ "$path" = /* && "$path" != / && "$path" != /srv && "$path" != /srv/bitcoin ]] || {
    echo "unsafe datadir path: $path" >&2
    exit 1
  }
done
[[ -d "$SOURCE_DATADIR/blocks/index" && -d "$SOURCE_DATADIR/chainstate" ]] || {
  echo "source datadir is missing blocks/index or chainstate" >&2
  exit 1
}
python3 -I - "$SOURCE_DATADIR" "$TARGET_BASE" <<'PY'
import pathlib, sys

resolved = []
for raw in sys.argv[1:]:
    path = pathlib.Path(raw)
    for candidate in (path, *path.parents):
        if candidate.is_symlink():
            raise SystemExit(f"datadir path contains a symlink: {candidate}")
        if candidate == candidate.parent:
            break
    resolved.append(path.resolve(strict=path.exists()))

source, target = resolved
if source == target or source in target.parents or target in source.parents:
    raise SystemExit("source and target datadirs must not overlap")
PY

python3 "$SCRIPT_DIR/pohw-experiment-1-manifest.py" verify "$MANIFEST" --repo-root "$REPO_ROOT"
readarray -t FIELDS < <(python3 - "$MANIFEST" <<'PY'
import json, sys
def pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value
with open(sys.argv[1], encoding="utf-8") as handle:
    m = json.load(handle, object_pairs_hook=pairs)
print(m["fork_point"]["inherited_tip_height"])
print(m["fork_point"]["inherited_tip_hash"])
print(m["network"]["data_subdirectory"])
print(m["network"]["p2p_port"])
print(m["network"]["rpc_port"])
PY
)
FORK_HEIGHT=${FIELDS[0]}
FORK_HASH=${FIELDS[1]}
DATA_SUBDIR=${FIELDS[2]}
P2P_PORT=${FIELDS[3]}
RPC_PORT=${FIELDS[4]}
TARGET_NETWORK="$TARGET_BASE/$DATA_SUBDIR"
STAGING=
CONFIG_STAGING=
PUBLISHED=false

[[ ! -e "$TARGET_NETWORK" ]] || { echo "target already exists: $TARGET_NETWORK" >&2; exit 1; }
getent group "$RPC_GROUP" >/dev/null || groupadd --system "$RPC_GROUP"
getent group "$FORK_USER" >/dev/null || groupadd --system "$FORK_USER"
id "$FORK_USER" >/dev/null 2>&1 || useradd --system --gid "$FORK_USER" --home-dir /nonexistent --shell /usr/sbin/nologin "$FORK_USER"
usermod -a -G "$FORK_USER,$RPC_GROUP" "$FORK_USER"
install -d -m 0710 -o root -g "$FORK_USER" "$TARGET_BASE"
[[ -d "$TARGET_BASE" && ! -L "$TARGET_BASE" ]] || {
  echo "target base is not a real directory: $TARGET_BASE" >&2
  exit 1
}
chown root:"$FORK_USER" "$TARGET_BASE"
chmod 0710 "$TARGET_BASE"

SOURCE_WAS_ACTIVE=false
OFFLINE_STARTED=false
SOURCE_MASKED_BY_SCRIPT=false
LOCK_GUARD_PID=
LOCK_READY="$TARGET_BASE/.pohw-source-lock-ready.$$"

cleanup() {
  status=$?
  if [[ "$OFFLINE_STARTED" == true ]]; then
    runuser -u "$SOURCE_USER" -- "$BITCOIN_CLI" -datadir="$SOURCE_DATADIR" stop >/dev/null 2>&1 || true
    sleep 2
    OFFLINE_STARTED=false
  fi
  if [[ -n "$LOCK_GUARD_PID" ]]; then
    kill "$LOCK_GUARD_PID" >/dev/null 2>&1 || true
    wait "$LOCK_GUARD_PID" 2>/dev/null || true
    LOCK_GUARD_PID=
  fi
  rm -f -- "$LOCK_READY"
  if [[ -n "$STAGING" && -e "$STAGING" ]]; then
    case "$STAGING" in
      "$TARGET_BASE"/.*.staging.*) rm -rf -- "$STAGING" ;;
      *) echo "refusing unsafe staging cleanup: $STAGING" >&2 ;;
    esac
  fi
  if [[ -n "$CONFIG_STAGING" && -e "$CONFIG_STAGING" ]]; then
    case "$CONFIG_STAGING" in
      "$TARGET_BASE"/.bitcoin.conf.staging.*) rm -f -- "$CONFIG_STAGING" ;;
      *) echo "refusing unsafe config staging cleanup: $CONFIG_STAGING" >&2 ;;
    esac
  fi
  if [[ $status -ne 0 && "$PUBLISHED" == true && -e "$TARGET_NETWORK" ]]; then
    case "$TARGET_NETWORK" in
      "$TARGET_BASE"/"$DATA_SUBDIR") rm -rf -- "$TARGET_NETWORK" ;;
      *) echo "refusing unsafe published-target cleanup: $TARGET_NETWORK" >&2 ;;
    esac
  fi
  if [[ "$SOURCE_MASKED_BY_SCRIPT" == true ]]; then
    systemctl unmask --runtime -- "$SOURCE_SERVICE" >/dev/null 2>&1 || true
    SOURCE_MASKED_BY_SCRIPT=false
  fi
  if [[ "$SOURCE_WAS_ACTIVE" == true || "$RESTART_MAIN" == true ]]; then
    systemctl start -- "$SOURCE_SERVICE" || true
  fi
  if [[ $status -ne 0 ]]; then
    echo "fork bootstrap failed; mainnet restart was attempted" >&2
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

if systemctl is-active --quiet -- "$SOURCE_SERVICE"; then
  SOURCE_WAS_ACTIVE=true
  systemctl stop -- "$SOURCE_SERVICE"
fi
case "$(systemctl is-enabled -- "$SOURCE_SERVICE" 2>/dev/null || true)" in
  masked|masked-runtime) ;;
  *)
    systemctl mask --runtime -- "$SOURCE_SERVICE" >/dev/null
    SOURCE_MASKED_BY_SCRIPT=true
    ;;
esac
systemctl is-active --quiet -- "$SOURCE_SERVICE" && {
  echo "source service remained active after stop" >&2
  exit 1
}

runuser -u "$SOURCE_USER" -- "$BITCOIND" \
  -datadir="$SOURCE_DATADIR" -daemonwait -networkactive=0 -listen=0 \
  -dnsseed=0 -fixedseeds=0
OFFLINE_STARTED=true

ACTUAL_HEIGHT=$(runuser -u "$SOURCE_USER" -- "$BITCOIN_CLI" -datadir="$SOURCE_DATADIR" getblockcount)
ACTUAL_HASH=$(runuser -u "$SOURCE_USER" -- "$BITCOIN_CLI" -datadir="$SOURCE_DATADIR" getblockhash "$FORK_HEIGHT")
[[ "$ACTUAL_HEIGHT" == "$FORK_HEIGHT" ]] || {
  echo "source tip moved: expected height $FORK_HEIGHT, got $ACTUAL_HEIGHT" >&2
  exit 1
}
[[ "$ACTUAL_HASH" == "$FORK_HASH" ]] || { echo "source fork hash mismatch" >&2; exit 1; }

runuser -u "$SOURCE_USER" -- "$BITCOIN_CLI" -datadir="$SOURCE_DATADIR" stop >/dev/null

# Hold the same POSIX whole-file lock used by Bitcoin Core until every source
# file has been copied. Acquiring it also waits for the offline node to finish
# flushing LevelDB after the RPC stop response.
python3 - "$SOURCE_DATADIR/.lock" "$LOCK_READY" <<'PY' &
import fcntl
import os
import pathlib
import signal
import sys

fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)
fcntl.lockf(fd, fcntl.LOCK_EX)
pathlib.Path(sys.argv[2]).touch(mode=0o600, exist_ok=False)
for name in (signal.SIGTERM, signal.SIGINT):
    signal.signal(name, lambda *_: raise_exit())

def wait_forever():
    while True:
        signal.pause()

def raise_exit():
    raise SystemExit(0)

wait_forever()
PY
LOCK_GUARD_PID=$!
for _ in $(seq 1 60); do
  [[ -e "$LOCK_READY" ]] && break
  kill -0 "$LOCK_GUARD_PID" 2>/dev/null || {
    echo "failed to acquire exclusive source datadir lock" >&2
    exit 1
  }
  sleep 1
done
[[ -e "$LOCK_READY" ]] || { echo "timed out acquiring source datadir lock" >&2; exit 1; }
OFFLINE_STARTED=false
systemctl is-active --quiet -- "$SOURCE_SERVICE" && {
  echo "source service restarted while bootstrap lock was being acquired" >&2
  exit 1
}
if find "$SOURCE_DATADIR/blocks" "$SOURCE_DATADIR/chainstate" -type l -print -quit | grep -q .; then
  echo "source blocks or chainstate contains a symlink" >&2
  exit 1
fi
sync

[[ ! -e "$TARGET_NETWORK" && ! -L "$TARGET_NETWORK" ]] || {
  echo "target appeared while source state was being locked: $TARGET_NETWORK" >&2
  exit 1
}

# Nothing under the unpublished tree is writable by the eventual service
# account. Root performs and validates every copy before the atomic rename;
# ownership is transferred only after no privileged transformation remains.
STAGING=$(mktemp -d "$TARGET_BASE/.${DATA_SUBDIR}.staging.XXXXXX")
chown root:root "$STAGING"
chmod 0700 "$STAGING"
install -d -m 0700 -o root -g root "$STAGING/blocks"
mapfile -t BLOCK_FILES < <(find "$SOURCE_DATADIR/blocks" -maxdepth 1 -type f -name 'blk*.dat' -printf '%f\n' | sort)
mapfile -t UNDO_FILES < <(find "$SOURCE_DATADIR/blocks" -maxdepth 1 -type f -name 'rev*.dat' -printf '%f\n' | sort)
(( ${#BLOCK_FILES[@]} > 0 && ${#UNDO_FILES[@]} > 0 )) || { echo "source block files are missing" >&2; exit 1; }
LAST_BLOCK=${BLOCK_FILES[-1]}
LAST_UNDO=${UNDO_FILES[-1]}

copy_block_file() {
  local name=$1
  local last=$2
  local source="$SOURCE_DATADIR/blocks/$name"
  local target="$STAGING/blocks/$name"
  if [[ "$name" == "$last" ]]; then
    # The active tail may later be truncated or extended by mainnet. Force a
    # byte copy even on CoW filesystems so the two datadirs are fully detached.
    cp -a --reflink=never -- "$source" "$target"
  else
    cp -a --reflink=auto -- "$source" "$target"
  fi
  chmod 0600 "$target"
  [[ "$(stat -c '%d:%i' "$source")" != "$(stat -c '%d:%i' "$target")" ]] || {
    echo "copied block file aliases its source inode: $name" >&2
    exit 1
  }
}

for name in "${BLOCK_FILES[@]}"; do copy_block_file "$name" "$LAST_BLOCK"; done
for name in "${UNDO_FILES[@]}"; do copy_block_file "$name" "$LAST_UNDO"; done

while IFS= read -r -d '' extra; do
  target="$STAGING/blocks/$(basename -- "$extra")"
  cp -a --reflink=auto -- "$extra" "$target"
  chmod 0600 "$target"
done < <(find "$SOURCE_DATADIR/blocks" -maxdepth 1 -type f ! -name 'blk*.dat' ! -name 'rev*.dat' -print0)

cp -a --reflink=auto -- "$SOURCE_DATADIR/blocks/index" "$STAGING/blocks/index"
cp -a --reflink=auto -- "$SOURCE_DATADIR/chainstate" "$STAGING/chainstate"
chmod 0700 "$STAGING/blocks/index" "$STAGING/chainstate"
install -m 0600 -o root -g root "$MANIFEST" "$STAGING/experiment-manifest.json"

[[ -r "$STAGING/blocks/${BLOCK_FILES[0]}" && -r "$STAGING/blocks/$LAST_BLOCK" ]] || {
  echo "staged block files are not readable by root" >&2
  exit 1
}
# Normalize and transfer every child while the root-owned 0700 staging parent
# still prevents the service account from reaching them. Publishing the tree
# and transferring its top directory are then the only remaining operations.
find "$STAGING/blocks" "$STAGING/chainstate" -type d -exec chmod 0700 {} +
find "$STAGING/blocks" "$STAGING/chainstate" -type f -exec chmod 0600 {} +
chown -R "$FORK_USER:$FORK_USER" \
  "$STAGING/blocks" "$STAGING/chainstate" "$STAGING/experiment-manifest.json"
sync -f "$STAGING"
mv -- "$STAGING" "$TARGET_NETWORK"
STAGING=
PUBLISHED=true
chown "$FORK_USER:$FORK_USER" "$TARGET_NETWORK"
runuser -u "$FORK_USER" -- test -r "$TARGET_NETWORK/blocks/${BLOCK_FILES[0]}"
runuser -u "$FORK_USER" -- test -r "$TARGET_NETWORK/blocks/$LAST_BLOCK"

[[ ! -L "$TARGET_BASE/bitcoin.conf" ]] || {
  echo "refusing symlinked Bitcoin configuration: $TARGET_BASE/bitcoin.conf" >&2
  exit 1
}
if [[ ! -e "$TARGET_BASE/bitcoin.conf" ]]; then
  CONFIG_STAGING=$(mktemp "$TARGET_BASE/.bitcoin.conf.staging.XXXXXX")
  chown root:root "$CONFIG_STAGING"
  chmod 0600 "$CONFIG_STAGING"
  cat >"$CONFIG_STAGING" <<EOF
chain=pohw
server=1
txindex=1

[pohw]
listen=1
port=$P2P_PORT
rpcport=$RPC_PORT
rpccookiefile=/run/bitcoin-pohw-rpc/.cookie
rpccookieperms=group
dnsseed=0
fixedseeds=0
discover=0
EOF
  chown "$FORK_USER:$FORK_USER" "$CONFIG_STAGING"
  mv -- "$CONFIG_STAGING" "$TARGET_BASE/bitcoin.conf"
  CONFIG_STAGING=
fi

echo "Experiment 1 chainstate clone complete at $TARGET_NETWORK"
