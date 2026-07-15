#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly REPOSITORY_ROOT
readonly KUBO_IMAGE="${POHW_KUBO_TEST_IMAGE:-ipfs/kubo:v0.42.0}"
readonly RUN_ID="${PPID}-$$"
readonly NODE_ONE="pohw-governance-kubo-a-${RUN_ID}"
readonly NODE_TWO="pohw-governance-kubo-b-${RUN_ID}"

for command in cargo curl docker; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'missing required command: %s\n' "$command" >&2
    exit 1
  }
done

docker info >/dev/null 2>&1 || {
  printf 'Docker daemon is unavailable\n' >&2
  exit 1
}

workdir="$(mktemp -d "${TMPDIR:-/tmp}/pohw-kubo-e2e.XXXXXX")"
cleanup() {
  docker rm -f "$NODE_ONE" "$NODE_TWO" >/dev/null 2>&1 || true
  rm -rf "$workdir"
}
trap cleanup EXIT INT TERM

fixture="$workdir/source"
package_dir="$workdir/package"
checkout_dir="$workdir/checkout"
mkdir -p "$fixture/config" "$package_dir"
printf 'governance Kubo integration fixture\n' >"$fixture/README.txt"
printf '{"schemaVersion":1,"enabled":false}\n' >"$fixture/config/profile.json"
chmod 0644 "$fixture/README.txt" "$fixture/config/profile.json"

cargo build --quiet --manifest-path "$REPOSITORY_ROOT/Cargo.toml" -p governance-cli
readonly GOVERNANCE_CLI="$REPOSITORY_ROOT/target/debug/pohw-governance"

"$GOVERNANCE_CLI" package \
  --root "$fixture" \
  --repository kubo-fixture \
  --output-dir "$package_dir" >/dev/null

readonly SOURCE_CAR="$package_dir/kubo-fixture.source.car"
SOURCE_CID="$(tr -d '\r\n' <"$package_dir/kubo-fixture.source.cid")"
readonly SOURCE_CID
[[ "$SOURCE_CID" == bafy* ]] || {
  printf 'packager emitted an unexpected source CID\n' >&2
  exit 1
}

start_kubo() {
  local name="$1"
  docker run --detach --rm \
    --name "$name" \
    --security-opt no-new-privileges \
    --memory 768m \
    --cpus 1 \
    --publish 127.0.0.1::5001 \
    --publish 127.0.0.1::8080 \
    "$KUBO_IMAGE" >/dev/null
}

mapped_port() {
  local name="$1"
  local container_port="$2"
  docker port "$name" "$container_port/tcp" | awk -F: 'NR == 1 {print $NF}'
}

wait_for_api() {
  local port="$1"
  local attempt
  for ((attempt = 1; attempt <= 90; attempt++)); do
    if curl --fail --silent --show-error --max-time 2 \
      --request POST "http://127.0.0.1:${port}/api/v0/version" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  printf 'Kubo API did not become ready on its loopback port\n' >&2
  return 1
}

start_kubo "$NODE_ONE"
start_kubo "$NODE_TWO"

api_one="$(mapped_port "$NODE_ONE" 5001)"
api_two="$(mapped_port "$NODE_TWO" 5001)"
gateway_one="$(mapped_port "$NODE_ONE" 8080)"
gateway_two="$(mapped_port "$NODE_TWO" 8080)"
for port in "$api_one" "$api_two" "$gateway_one" "$gateway_two"; do
  [[ "$port" =~ ^[0-9]{1,5}$ ]] || {
    printf 'Docker returned an invalid loopback port mapping\n' >&2
    exit 1
  }
done

wait_for_api "$api_one"
wait_for_api "$api_two"

"$GOVERNANCE_CLI" pin \
  --car "$SOURCE_CAR" \
  --store "$workdir/pins-a" \
  --kubo-api "http://127.0.0.1:${api_one}" >/dev/null
"$GOVERNANCE_CLI" pin \
  --car "$SOURCE_CAR" \
  --store "$workdir/pins-b" \
  --kubo-api "http://127.0.0.1:${api_two}" >/dev/null

"$GOVERNANCE_CLI" fetch \
  --cid "$SOURCE_CID" \
  --gateway "http://127.0.0.1:${gateway_one}" \
  --gateway "http://127.0.0.1:${gateway_two}" \
  --output-dir "$workdir/fetched" >/dev/null

readonly FETCHED_CAR="$workdir/fetched/${SOURCE_CID}.car"
"$GOVERNANCE_CLI" verify --car "$FETCHED_CAR" >/dev/null
"$GOVERNANCE_CLI" checkout --car "$FETCHED_CAR" --output "$checkout_dir" >/dev/null
diff -ru "$fixture" "$checkout_dir" >/dev/null

image_id="$(docker image inspect "$KUBO_IMAGE" --format '{{.Id}}')"
printf 'Kubo sidecar E2E passed: cid=%s image=%s\n' "$SOURCE_CID" "$image_id"
