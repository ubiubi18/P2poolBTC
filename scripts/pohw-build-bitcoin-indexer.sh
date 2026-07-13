#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK_FILE="$ROOT_DIR/compatibility/explorer-stack-lock.json"
SOURCE_DIR="${1:-$ROOT_DIR/.build/electrs}"

if [[ "$(id -u)" == "0" ]]; then
  echo "Build electrs as an unprivileged user, not root." >&2
  exit 1
fi
[[ -f "$LOCK_FILE" && ! -L "$LOCK_FILE" ]] || {
  echo "Missing explorer stack lock: $LOCK_FILE" >&2
  exit 1
}

IFS=$'\t' read -r repository commit expected_lock_hash < <(python3 - "$LOCK_FILE" <<'PY'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
entry = data["bitcoinHistoryIndexer"]
print(entry["repository"], entry["commit"], entry["cargoLockSha256"], sep="\t")
PY
)

if [[ -e "$SOURCE_DIR" ]]; then
  if [[ -d "$SOURCE_DIR/.git" && ! -L "$SOURCE_DIR" ]]; then
    actual_remote="$(git -C "$SOURCE_DIR" remote get-url origin)"
    [[ "$actual_remote" == "$repository" ]] || {
      echo "Existing electrs checkout uses an unexpected origin." >&2
      exit 1
    }
  elif [[ -d "$SOURCE_DIR" && ! -L "$SOURCE_DIR" && -z "$(find "$SOURCE_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    git clone --no-checkout --filter=blob:none "$repository" "$SOURCE_DIR"
  else
    echo "Existing source path is not an empty directory or Git checkout: $SOURCE_DIR" >&2
    exit 1
  fi
else
  install -d -m 0700 "$(dirname "$SOURCE_DIR")"
  git clone --no-checkout --filter=blob:none "$repository" "$SOURCE_DIR"
fi

git -C "$SOURCE_DIR" fetch --depth=1 origin "$commit"
git -C "$SOURCE_DIR" checkout --detach --force "$commit"
[[ "$(git -C "$SOURCE_DIR" rev-parse HEAD)" == "$commit" ]] || {
  echo "Electrs checkout did not resolve to the locked commit." >&2
  exit 1
}
actual_lock_hash="$(sha256sum "$SOURCE_DIR/Cargo.lock" | awk '{print $1}')"
[[ "$actual_lock_hash" == "$expected_lock_hash" ]] || {
  echo "Electrs Cargo.lock does not match the reviewed lock." >&2
  exit 1
}

cargo build --locked --release --manifest-path "$SOURCE_DIR/Cargo.toml" --bin electrs
"$SOURCE_DIR/target/release/electrs" --version
printf 'electrs_binary=%s\n' "$SOURCE_DIR/target/release/electrs"
