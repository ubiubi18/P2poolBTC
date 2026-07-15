#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)
MANIFEST="$REPO_ROOT/compatibility/experiment-1-full-consensus.json"
SOURCE_DIR=
SNAPSHOT_DIR=
SNAPSHOT_METADATA=

usage() {
  cat <<'EOF'
Usage: scripts/pohw-verify-bitcoin-core-source.sh --source-dir DIR [options]

Verify the pinned Bitcoin Core commit and create a deterministic, read-only
Experiment 1 source snapshot from a fresh Git object database and index. The
caller's Git index is inspected for hiding flags but is never trusted to create
or verify the snapshot.

Options:
  --source-dir DIR
  --snapshot-dir DIR       New destination for the immutable patched snapshot
  --snapshot-metadata FILE Required with --snapshot-dir
  --manifest FILE
EOF
}

while (($#)); do
  case "$1" in
    --source-dir) SOURCE_DIR=${2:?}; shift 2 ;;
    --snapshot-dir) SNAPSHOT_DIR=${2:?}; shift 2 ;;
    --snapshot-metadata) SNAPSHOT_METADATA=${2:?}; shift 2 ;;
    --manifest) MANIFEST=${2:?}; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n "$SOURCE_DIR" ]] || { usage >&2; exit 2; }
[[ -z "$SNAPSHOT_DIR" && -z "$SNAPSHOT_METADATA" ]] || \
  [[ -n "$SNAPSHOT_DIR" && -n "$SNAPSHOT_METADATA" ]] || {
    echo "--snapshot-dir and --snapshot-metadata must be provided together" >&2
    exit 2
  }
SOURCE_DIR=$(cd -- "$SOURCE_DIR" && pwd)
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY
unset GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_NAMESPACE
unset GIT_REPLACE_REF_BASE GIT_ATTR_SOURCE GIT_CONFIG GIT_CONFIG_COUNT
unset GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM GIT_CONFIG_NOSYSTEM
while IFS= read -r variable; do
  unset "$variable"
done < <(compgen -A variable 'GIT_CONFIG_KEY_'; compgen -A variable 'GIT_CONFIG_VALUE_')
git -C "$SOURCE_DIR" rev-parse --is-inside-work-tree >/dev/null

# These bits can make ordinary status/diff checks conceal modified files. They
# are rejected explicitly even though snapshot creation uses a fresh index.
python3 - "$SOURCE_DIR" <<'PY'
import subprocess
import sys

source = sys.argv[1]

def records(flag: str) -> list[bytes]:
    result = subprocess.run(
        ["git", "-C", source, "-c", "core.fsmonitor=false", "ls-files", flag, "-z"],
        check=True,
        stdout=subprocess.PIPE,
    )
    return [item for item in result.stdout.split(b"\0") if item]

assume_unchanged = [item for item in records("-v") if item[:1].islower()]
skip_worktree = [item for item in records("-t") if item.startswith(b"S ")]
if assume_unchanged:
    raise SystemExit("source checkout contains assume-unchanged index entries")
if skip_worktree:
    raise SystemExit("source checkout contains skip-worktree index entries")
PY

TMP_ROOT=$(mktemp -d)
TEMP_GIT="$TMP_ROOT/object-db.git"
TEMP_INDEX=$(mktemp "$TMP_ROOT/index.XXXXXXXX")
rm -f -- "$TEMP_INDEX"
SNAPSHOT_STAGING=
METADATA_CREATED=0
cleanup() {
  local status=$?
  if [[ -n "$SNAPSHOT_STAGING" && -e "$SNAPSHOT_STAGING" ]]; then
    chmod -R u+w -- "$SNAPSHOT_STAGING" 2>/dev/null || true
    rm -rf -- "$SNAPSHOT_STAGING"
  fi
  if [[ "$status" -ne 0 && "$METADATA_CREATED" -eq 1 ]]; then
    rm -f -- "$SNAPSHOT_METADATA" 2>/dev/null || true
  fi
  rm -rf -- "$TMP_ROOT"
  exit "$status"
}
trap cleanup EXIT

secure_copy() {
  python3 - "$1" "$2" "${3:-}" <<'PY'
import hashlib
import os
import pathlib
import stat
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
expected = sys.argv[3]
if not hasattr(os, "O_NOFOLLOW"):
    raise SystemExit("platform lacks O_NOFOLLOW required for source verification")
fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
try:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        raise SystemExit(f"provenance input is not a regular file: {source}")
    chunks = []
    digest = hashlib.sha256()
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        chunks.append(chunk)
        digest.update(chunk)
    after = os.fstat(fd)
    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise SystemExit(f"provenance input changed while reading: {source}")
finally:
    os.close(fd)
actual = digest.hexdigest()
if expected and actual != expected:
    raise SystemExit(f"provenance input SHA-256 mismatch: {source}")
out = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400)
try:
    for chunk in chunks:
        view = memoryview(chunk)
        while view:
            view = view[os.write(out, view):]
    os.fsync(out)
finally:
    os.close(out)
print(actual)
PY
}

MANIFEST_COPY="$TMP_ROOT/experiment-manifest.json"
MANIFEST_SHA256=$(secure_copy "$MANIFEST" "$MANIFEST_COPY")
python3 "$SCRIPT_DIR/pohw-experiment-1-manifest.py" verify \
  "$MANIFEST_COPY" --repo-root "$REPO_ROOT"

PINNED=$(python3 - "$MANIFEST_COPY" <<'PY'
import json
import sys

def pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value

with open(sys.argv[1], encoding="utf-8") as handle:
    manifest = json.load(handle, object_pairs_hook=pairs)
print(
    manifest["upstream"]["commit"],
    manifest["build"]["patch_path"],
    manifest["build"]["patch_sha256"],
    sep="\t",
)
PY
)
IFS=$'\t' read -r UPSTREAM_COMMIT PATCH_REL PATCH_SHA256 <<<"$PINNED"
PATCH_SOURCE="$REPO_ROOT/$PATCH_REL"
PATCH="$TMP_ROOT/pinned.patch"
secure_copy "$PATCH_SOURCE" "$PATCH" "$PATCH_SHA256" >/dev/null

ACTUAL_COMMIT=$(git -C "$SOURCE_DIR" rev-parse HEAD)
[[ "$ACTUAL_COMMIT" == "$UPSTREAM_COMMIT" ]] || {
  echo "source commit does not match the manifest" >&2
  exit 1
}
git -C "$SOURCE_DIR" -c core.fsmonitor=false diff --cached --quiet HEAD -- || {
  echo "source checkout contains staged changes" >&2
  exit 1
}

export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
mkdir -m 0700 -- "$TMP_ROOT/empty-template"
git init -q --bare --template="$TMP_ROOT/empty-template" "$TEMP_GIT"
SOURCE_OBJECTS=$(git -C "$SOURCE_DIR" rev-parse --git-path objects)
SOURCE_OBJECTS=$(python3 - "$SOURCE_DIR" "$SOURCE_OBJECTS" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[2])
if not path.is_absolute():
    path = pathlib.Path(sys.argv[1]) / path
print(path.resolve(strict=True))
PY
)
[[ "$SOURCE_OBJECTS" != *$'\n'* ]] || {
  echo "source object path contains an unsupported newline" >&2
  exit 1
}
printf '%s\n' "$SOURCE_OBJECTS" >"$TEMP_GIT/objects/info/alternates"

export GIT_INDEX_FILE="$TEMP_INDEX"
GIT=(git --git-dir="$TEMP_GIT" -c core.fsmonitor=false -c core.excludesFile=/dev/null)
"${GIT[@]}" cat-file -e "$UPSTREAM_COMMIT^{commit}"
"${GIT[@]}" read-tree "$UPSTREAM_COMMIT"

worktree_matches_index() {
  "${GIT[@]}" --work-tree="$SOURCE_DIR" diff \
    --quiet --no-ext-diff --ignore-submodules=none -- &&
    [[ -z "$("${GIT[@]}" --work-tree="$SOURCE_DIR" ls-files \
      --others --exclude-standard)" ]]
}

SOURCE_STATE=
if worktree_matches_index; then
  SOURCE_STATE=clean-upstream
fi

"${GIT[@]}" apply --cached --whitespace=nowarn "$PATCH"
PATCHED_TREE=$("${GIT[@]}" write-tree)
if [[ -z "$SOURCE_STATE" ]] && worktree_matches_index; then
  SOURCE_STATE=exact-patched
fi
[[ -n "$SOURCE_STATE" ]] || {
  echo "source worktree is neither clean upstream nor the exact pinned patch" >&2
  exit 1
}
[[ -z "$("${GIT[@]}" ls-files --stage | awk '$1 == "160000" { print; exit }')" ]] || {
  echo "source snapshot contains an unsupported Git submodule entry" >&2
  exit 1
}

if [[ -n "$SNAPSHOT_DIR" ]]; then
  SNAPSHOT_DIR=$(python3 - "$SNAPSHOT_DIR" <<'PY'
import pathlib
import sys
print(pathlib.Path(sys.argv[1]).expanduser().resolve(strict=False))
PY
  )
  SNAPSHOT_METADATA=$(python3 - "$SNAPSHOT_METADATA" <<'PY'
import pathlib
import sys
print(pathlib.Path(sys.argv[1]).expanduser().resolve(strict=False))
PY
  )
  [[ ! -e "$SNAPSHOT_DIR" && ! -L "$SNAPSHOT_DIR" ]] || {
    echo "snapshot destination must not already exist: $SNAPSHOT_DIR" >&2
    exit 1
  }
  [[ ! -e "$SNAPSHOT_METADATA" && ! -L "$SNAPSHOT_METADATA" ]] || {
    echo "snapshot metadata destination must not already exist: $SNAPSHOT_METADATA" >&2
    exit 1
  }
  SNAPSHOT_PARENT=$(dirname -- "$SNAPSHOT_DIR")
  [[ -d "$SNAPSHOT_PARENT" && ! -L "$SNAPSHOT_PARENT" ]] || {
    echo "snapshot parent must be a real directory: $SNAPSHOT_PARENT" >&2
    exit 1
  }
  SNAPSHOT_STAGING=$(mktemp -d "$SNAPSHOT_PARENT/.pohw-source-snapshot.XXXXXXXX")
else
  SNAPSHOT_STAGING="$TMP_ROOT/source-snapshot"
  mkdir -m 0700 -- "$SNAPSHOT_STAGING"
  SNAPSHOT_METADATA="$TMP_ROOT/source-snapshot.json"
fi

"${GIT[@]}" --work-tree="$SNAPSHOT_STAGING" checkout-index --all --force
"${GIT[@]}" --work-tree="$SNAPSHOT_STAGING" diff \
  --quiet --no-ext-diff --ignore-submodules=none -- || {
    echo "materialized snapshot differs from the independent patched index" >&2
    exit 1
  }

python3 - "$SNAPSHOT_STAGING" <<'PY'
import os
import pathlib
import posixpath
import stat
import sys

root = pathlib.Path(sys.argv[1])

def seal(directory, prefix=""):
    entries = sorted(os.scandir(directory), key=lambda item: os.fsencode(item.name))
    for entry in entries:
        path = pathlib.Path(entry.path)
        relative = f"{prefix}/{entry.name}" if prefix else entry.name
        mode = entry.stat(follow_symlinks=False).st_mode
        if stat.S_ISLNK(mode):
            target = os.readlink(path)
            if posixpath.isabs(target):
                raise SystemExit(f"snapshot symlink is absolute: {relative}")
            resolved = posixpath.normpath(
                posixpath.join(posixpath.dirname(relative), target)
            )
            if resolved == ".." or resolved.startswith("../"):
                raise SystemExit(f"snapshot symlink escapes the tree: {relative}")
        elif stat.S_ISDIR(mode):
            seal(path, relative)
            path.chmod(0o555)
        elif stat.S_ISREG(mode):
            if path.stat().st_nlink != 1:
                raise SystemExit(f"snapshot file has external hard links: {relative}")
            path.chmod(0o555 if mode & 0o111 else 0o444)
        else:
            raise SystemExit(f"snapshot contains a special file: {relative}")

seal(root)
root.chmod(0o555)
PY

python3 "$SCRIPT_DIR/pohw-bitcoin-core-build-evidence.py" snapshot-metadata \
  --snapshot-dir "$SNAPSHOT_STAGING" \
  --metadata "$SNAPSHOT_METADATA" \
  --tree-oid "$PATCHED_TREE" \
  --upstream-commit "$UPSTREAM_COMMIT" \
  --patch-sha256 "$PATCH_SHA256" \
  --manifest-sha256 "$MANIFEST_SHA256" >/dev/null
METADATA_CREATED=1

if [[ -n "$SNAPSHOT_DIR" ]]; then
  # macOS sandboxing rejects renaming a read-only directory even when both
  # parents are writable. Make only the already-sealed root movable, publish
  # it atomically, reseal it immediately, and then recompute the locked
  # metadata before any build command is allowed to run.
  chmod 0700 "$SNAPSHOT_STAGING"
  mv -- "$SNAPSHOT_STAGING" "$SNAPSHOT_DIR"
  SNAPSHOT_STAGING="$SNAPSHOT_DIR"
  chmod 0555 "$SNAPSHOT_DIR"
  VERIFY_METADATA="$TMP_ROOT/published-source-snapshot.json"
  python3 "$SCRIPT_DIR/pohw-bitcoin-core-build-evidence.py" snapshot-metadata \
    --snapshot-dir "$SNAPSHOT_DIR" \
    --metadata "$VERIFY_METADATA" \
    --tree-oid "$PATCHED_TREE" \
    --upstream-commit "$UPSTREAM_COMMIT" \
    --patch-sha256 "$PATCH_SHA256" \
    --manifest-sha256 "$MANIFEST_SHA256" >/dev/null
  cmp -s -- "$SNAPSHOT_METADATA" "$VERIFY_METADATA" || {
    echo "published source snapshot differs from its pre-publication metadata" >&2
    exit 1
  }
  SNAPSHOT_STAGING=
  echo "Experiment 1 source snapshot created: $SNAPSHOT_DIR"
else
  echo "Experiment 1 source verified from independent snapshot ($SOURCE_STATE)"
fi
