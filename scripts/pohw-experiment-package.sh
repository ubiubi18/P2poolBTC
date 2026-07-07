#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/pohw-experiment-package.sh [options]

Build a source-only Community Experiment 0 participant bundle.

Options:
  --output-root PATH     Directory for the archive (default: output)
  --package-name NAME    Archive root/name without .tar.gz
  --require-clean        Refuse to package a dirty git worktree
  -h, --help             Show this help

The bundle includes source, runbooks, env templates, wrappers, and tests.
It intentionally excludes .git, target, output, node_modules, dist/build
artifacts, local datadirs, env files, keys, cookies, logs, and reports.
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
OUTPUT_ROOT="$REPO_ROOT/output"
PACKAGE_NAME=""
REQUIRE_CLEAN="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-root)
      OUTPUT_ROOT="${2:?missing value for --output-root}"
      shift 2
      ;;
    --package-name)
      PACKAGE_NAME="${2:?missing value for --package-name}"
      shift 2
      ;;
    --require-clean)
      REQUIRE_CLEAN="true"
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

if [[ ! -f "$REPO_ROOT/Cargo.toml" || ! -d "$REPO_ROOT/crates" ]]; then
  echo "Could not locate repository root from $SCRIPT_DIR" >&2
  exit 1
fi

stat_mode() {
  local path="$1"
  if stat -c %a "$path" >/dev/null 2>&1; then
    stat -c %a "$path"
  else
    stat -f %Lp "$path"
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
        echo "Refusing to write through symlinked path component: $current" >&2
        exit 1
      fi
    fi
    current="$(dirname "$current")"
  done
}

validate_package_name() {
  local name="$1"
  if [[ -z "$name" || ${#name} -gt 128 || ! "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]; then
    echo "Package name must be 1-128 chars, start with A-Z/a-z/0-9, and contain only dot, underscore, dash, or alphanumerics." >&2
    exit 1
  fi
}

validate_output_root() {
  local dir="$1"
  local parent mode unsafe_bits
  if [[ -L "$dir" ]]; then
    echo "Refusing to write package output through symlinked directory: $dir" >&2
    exit 1
  fi
  if [[ -e "$dir" && ! -d "$dir" ]]; then
    echo "Package output root is not a directory: $dir" >&2
    exit 1
  fi
  parent="$(dirname "$dir")"
  if [[ -L "$parent" ]]; then
    echo "Refusing to write package output in symlinked parent: $parent" >&2
    exit 1
  fi
  reject_symlink_ancestor "$dir"
  if [[ ! -e "$dir" ]]; then
    mkdir -p "$dir"
  fi
  mode="$(stat_mode "$dir")"
  unsafe_bits=$((8#$mode & 022))
  if (( unsafe_bits != 0 )); then
    echo "Refusing to write package output in group/world-writable directory: $dir" >&2
    echo "Fix with: chmod go-w $dir" >&2
    exit 1
  fi
}

git_value() {
  git -C "$REPO_ROOT" "$@" 2>/dev/null || true
}

GIT_COMMIT="$(git_value rev-parse HEAD)"
GIT_BRANCH="$(git_value rev-parse --abbrev-ref HEAD)"
GIT_STATUS="$(git -C "$REPO_ROOT" status --porcelain --untracked-files=normal 2>/dev/null || true)"
GIT_DIRTY="false"
if [[ -n "$GIT_STATUS" ]]; then
  GIT_DIRTY="true"
fi
if [[ "$REQUIRE_CLEAN" == "true" && "$GIT_DIRTY" == "true" ]]; then
  echo "Refusing to package dirty worktree because --require-clean was set." >&2
  git -C "$REPO_ROOT" status --short >&2 || true
  exit 1
fi

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SHORT_COMMIT="${GIT_COMMIT:0:12}"
if [[ -z "$SHORT_COMMIT" ]]; then
  SHORT_COMMIT="nogit"
fi
if [[ -z "$PACKAGE_NAME" ]]; then
  PACKAGE_NAME="pohw-experiment-0-${SHORT_COMMIT}-${STAMP}"
  if [[ "$GIT_DIRTY" == "true" ]]; then
    PACKAGE_NAME="${PACKAGE_NAME}-dirty"
  fi
fi
validate_package_name "$PACKAGE_NAME"

OUTPUT_ROOT="$(cd "$OUTPUT_ROOT" 2>/dev/null && pwd -P || printf '%s' "$OUTPUT_ROOT")"
validate_output_root "$OUTPUT_ROOT"

ARCHIVE="$OUTPUT_ROOT/$PACKAGE_NAME.tar.gz"
ARCHIVE_SHA="$ARCHIVE.sha256"
if [[ -e "$ARCHIVE" || -e "$ARCHIVE_SHA" ]]; then
  echo "Refusing to overwrite existing package artifact: $ARCHIVE" >&2
  exit 1
fi

WORK_ROOT="$(mktemp -d)"
trap 'rm -rf "$WORK_ROOT"' EXIT
FILE_LIST="$WORK_ROOT/file-list.txt"
PACKAGE_ROOT="$WORK_ROOT/$PACKAGE_NAME"
: > "$FILE_LIST"
mkdir -p "$PACKAGE_ROOT"

add_file() {
  local rel="$1"
  rel="${rel#./}"
  [[ -z "$rel" ]] && return 0
  if [[ "$rel" == /* || "$rel" == *"/../"* || "$rel" == "../"* ]]; then
    echo "Refusing unsafe package path: $rel" >&2
    exit 1
  fi
  if [[ -L "$REPO_ROOT/$rel" ]]; then
    echo "Refusing symlinked package source file: $rel" >&2
    exit 1
  fi
  if [[ -f "$REPO_ROOT/$rel" ]]; then
    printf '%s\n' "$rel" >> "$FILE_LIST"
  fi
}

add_find() {
  local dir="$1"
  shift
  [[ -d "$REPO_ROOT/$dir" ]] || return 0
  (cd "$REPO_ROOT" && find "$dir" "$@" -type f -print) >> "$FILE_LIST"
}

reject_forbidden_path() {
  local rel="$1"
  local base
  base="$(basename "$rel")"
  case "$rel" in
    .git|.git/*|target|target/*|output|output/*|tmp|tmp/*|.pohw-p2pool|.pohw-p2pool/*)
      echo "Package file list contains forbidden generated/local path: $rel" >&2
      exit 1
      ;;
    *node_modules*|*"/dist/"*|*"/build/"*|*idena-data*|*bitcoin-data*)
      echo "Package file list contains forbidden dependency/build/data path: $rel" >&2
      exit 1
      ;;
  esac
  case "$base" in
    .env|.env.*|*.key|*.cookie|*.pid|*.log|*.sqlite|*.sqlite3|*.db|*.tar|*.tar.gz|*.tgz)
      echo "Package file list contains forbidden secret/generated file: $rel" >&2
      exit 1
      ;;
  esac
}

for file in \
  .gitignore \
  Cargo.lock \
  Cargo.toml \
  README.md \
  EXPERIMENT-0.md \
  deploy/pohw-experiment.env.example
do
  add_file "$file"
done

add_find crates \
  \( -name Cargo.toml -o -path '*/src/*.rs' \)
add_find scripts \
  \( -name '*.sh' -o -name '*.py' -o -name '*.sql' \)
add_find deploy \
  \( -name '*.conf' -o -name '*.service' -o -name '*.path' -o -name '*.timer' -o -name '*.json' \)
add_find pohw_idena_rpc \
  \( -name '*.py' \)
add_find tests \
  \( -name '*.py' \)
add_find contracts/idena-snapshot-registry \
  \( -path '*/node_modules' -o -path '*/build' \) -prune -o \
  \( -name '*.ts' -o -name '*.json' -o -name '*.md' -o -name '*.mjs' -o -name 'pnpm-lock.yaml' \)
add_find ui/pohw-dashboard \
  \( -path '*/node_modules' -o -path '*/dist' \) -prune -o \
  \( -name '*.tsx' -o -name '*.ts' -o -name '*.css' -o -name '*.html' -o -name '*.json' -o -name 'pnpm-lock.yaml' -o -name 'pnpm-workspace.yaml' \)

sort -u "$FILE_LIST" -o "$FILE_LIST"

while IFS= read -r rel; do
  [[ -n "$rel" ]] || continue
  reject_forbidden_path "$rel"
  if [[ -L "$REPO_ROOT/$rel" ]]; then
    echo "Refusing symlinked package source file: $rel" >&2
    exit 1
  fi
  if [[ ! -f "$REPO_ROOT/$rel" ]]; then
    echo "Package source path is not a regular file: $rel" >&2
    exit 1
  fi
  mkdir -p "$PACKAGE_ROOT/$(dirname "$rel")"
  cp -p "$REPO_ROOT/$rel" "$PACKAGE_ROOT/$rel"
done < "$FILE_LIST"

cat > "$PACKAGE_ROOT/QUICKSTART.md" <<'EOF'
# PoHW P2Pool Experiment 0 Quickstart

This bundle is for a no-value community dry run. It is not Bitcoin mainnet
mining, not a token launch, not a bridge, and not a deposit system.

## 1. Inspect And Build

```sh
tar -xzf pohw-experiment-0-*.tar.gz
cd pohw-experiment-0-*
cargo build --release -p p2pool-node
```

## 2. Create Local Config

```sh
scripts/pohw-experiment-init.sh \
  --miner-id alice \
  --bind-addr 127.0.0.1:40406
```

For LAN testing, use your own reachable WLAN IP for `--bind-addr` and
`--advertise-addr`, then exchange peer addresses out of band. Keep Bitcoin RPC
and Idena RPC on loopback.

## 3. Prepare Fork Activation

Agree on one launch timestamp with the group, set
`POHW_FORK_LAUNCH_TIMESTAMP_UTC` in `.pohw-experiment.env`, then derive the
manifest from your own Bitcoin Core RPC:

```sh
scripts/pohw-experiment-prepare-fork-activation.sh .pohw-experiment.env
```

Compare the resulting `activation_id` with the group before mining tests.

## 4. Preflight And Start Gossip

```sh
scripts/pohw-experiment-preflight.sh .pohw-experiment.env
scripts/pohw-experiment-start-gossip.sh .pohw-experiment.env
```

## 5. Register, Vote, Report

```sh
scripts/pohw-experiment-register-miner.sh .pohw-experiment.env --idena-address 0x...
# sign the printed challenge in Idena, then rerun with --idena-signature-hex
scripts/pohw-experiment-publish-snapshot-vote.sh .pohw-experiment.env
scripts/pohw-bootstrap-readiness.sh .pohw-experiment.env --mode real
scripts/pohw-experiment-report.sh .pohw-experiment.env
```

If Bitcoin Core is still in initial block download, the bootstrap command exits
cleanly with `bitcoin_not_ready` and does not append synthetic Bitcoin work.

Share only the generated report `.tar.gz`. Never share `.pohw-experiment.env`,
private keys, API keys, Bitcoin cookies, dashboard tokens, seed phrases, raw
service logs, or chain data.

## 6. Compare Reports

```sh
scripts/pohw-experiment-compare-reports.py \
  --min-nodes 3 \
  output/alice-report.tar.gz \
  output/bob-report.tar.gz \
  output/carol-report.tar.gz
```

Read `EXPERIMENT-0.md` for the complete runbook, success criteria, and stop
conditions.
EOF

python3 - "$PACKAGE_ROOT" "$PACKAGE_NAME" "$STAMP" "$GIT_BRANCH" "$GIT_COMMIT" "$GIT_DIRTY" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
package_name, generated_at, git_branch, git_commit, git_dirty = sys.argv[2:7]
files = sorted(
    str(path.relative_to(root))
    for path in root.rglob("*")
    if path.is_file() and path.name not in {"MANIFEST.json", "SHA256SUMS"}
)
manifest = {
    "package": package_name,
    "purpose": "PoHW P2Pool Community Experiment 0 participant source bundle",
    "generated_at_utc": generated_at,
    "git_branch": git_branch or None,
    "git_commit": git_commit or None,
    "git_dirty": git_dirty == "true",
    "no_value_ack_required": "I_UNDERSTAND_NO_VALUE",
    "file_count": len(files),
    "files": files,
    "excluded_by_policy": [
        ".git",
        "target",
        "output",
        ".pohw-p2pool",
        "node_modules",
        "dist",
        "build",
        "local datadirs",
        "env files",
        "keys",
        "cookies",
        "logs",
        "reports",
    ],
}
(root / "MANIFEST.json").write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
PY

python3 - "$PACKAGE_ROOT" > "$PACKAGE_ROOT/SHA256SUMS" <<'PY'
import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
for path in sorted(p for p in root.rglob("*") if p.is_file()):
    rel = path.relative_to(root)
    if rel.name == "SHA256SUMS":
        continue
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    print(f"{digest}  {rel}")
PY

(cd "$WORK_ROOT" && tar -czf "$ARCHIVE" "$PACKAGE_NAME")
python3 - "$ARCHIVE" > "$ARCHIVE_SHA" <<'PY'
import hashlib
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
print(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
PY

echo "Package archive: $ARCHIVE"
echo "Archive checksum: $ARCHIVE_SHA"
echo "Verify checksum: (cd \"$OUTPUT_ROOT\" && shasum -a 256 -c \"$(basename "$ARCHIVE_SHA")\")"
echo "Package root: $PACKAGE_NAME"
echo "Git commit: ${GIT_COMMIT:-unknown}"
echo "Git dirty: $GIT_DIRTY"
