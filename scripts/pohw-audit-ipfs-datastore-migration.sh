#!/usr/bin/env bash
set -euo pipefail

IPFS_REPO="${IPFS_PATH:-}"
IPFS_BIN="${IPFS_BIN:-ipfs}"

usage() {
  cat <<EOF
Usage: IPFS_PATH=/offline/repo [IPFS_BIN=/path/to/ipfs] $0

Audit an offline Kubo repository before a Badger-to-FlatFS pinned-data
migration. The report contains counts only; it never prints CIDs or identities.
EOF
}

fail() {
  echo "$*" >&2
  return 1
}

if [[ -z "$IPFS_REPO" || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  [[ -n "$IPFS_REPO" ]] || exit 2
  exit 0
fi
if [[ $# -ne 0 ]]; then
  usage >&2
  exit 2
fi
[[ -x "$IPFS_BIN" ]] || fail "IPFS binary is missing or not executable"
[[ -d "$IPFS_REPO" && ! -L "$IPFS_REPO" ]] || fail "IPFS_PATH must be a real directory"
[[ -f "$IPFS_REPO/config" && ! -L "$IPFS_REPO/config" ]] || fail "IPFS config is missing or symlinked"
[[ -f "$IPFS_REPO/version" && ! -L "$IPFS_REPO/version" ]] || fail "IPFS repo version is missing or symlinked"

datastore_type="$(python3 - "$IPFS_REPO/config" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    config = json.load(handle)

spec = config.get("Datastore", {}).get("Spec", {})
types = []

def collect(value):
    if isinstance(value, dict):
        if isinstance(value.get("type"), str):
            types.append(value["type"])
        for child in value.values():
            collect(child)
    elif isinstance(value, list):
        for child in value:
            collect(child)

collect(spec)
if "badgerds" in types:
    print("badgerds")
elif "flatfs" in types:
    print("flatfs")
else:
    print("other")
PY
)"
repo_version="$(tr -d '[:space:]' <"$IPFS_REPO/version")"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/pohw-ipfs-audit.XXXXXX")"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT INT TERM

run_ipfs() {
  "$IPFS_BIN" "$@" 2>"$tmp_dir/ipfs.stderr"
}

run_ipfs repo verify >/dev/null \
  || fail "Repository verification failed or the repository is still locked"
recursive_pins="$(run_ipfs pin ls --type=recursive --quiet | wc -l | tr -d '[:space:]')"
direct_pins="$(run_ipfs pin ls --type=direct --quiet | wc -l | tr -d '[:space:]')"
indirect_pins="$(run_ipfs pin ls --type=indirect --quiet | wc -l | tr -d '[:space:]')"
local_blocks="$(run_ipfs refs local | wc -l | tr -d '[:space:]')"
pinned_entries=$((recursive_pins + direct_pins + indirect_pins))
if ((local_blocks > pinned_entries)); then
  unpinned_local_blocks=$((local_blocks - pinned_entries))
else
  unpinned_local_blocks=0
fi

printf '%s\n' \
  "datastore=$datastore_type" \
  "repo_version=$repo_version" \
  "repo_verify=ok" \
  "local_blocks=$local_blocks" \
  "recursive_pins=$recursive_pins" \
  "direct_pins=$direct_pins" \
  "indirect_pins=$indirect_pins" \
  "unpinned_local_blocks=$unpinned_local_blocks"

if [[ "$datastore_type" == "badgerds" && "$unpinned_local_blocks" -gt 0 ]]; then
  echo "Pinned-data migration would omit local blocks; refusing migration approval." >&2
  exit 2
fi
