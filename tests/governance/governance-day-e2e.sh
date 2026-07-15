#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly ROOT
IDENA_AI_ROOT="${IDENA_AI_ROOT:-${1:-}}"
readonly IDENA_AI_ROOT
OUTPUT_ROOT="${POHW_GOVERNANCE_E2E_OUTPUT:-$ROOT/target/governance-day-e2e}"
readonly OUTPUT_ROOT
INTEGRATION_RECORD="$ROOT/compatibility/governance-day-idena-ai-integration.json"
readonly INTEGRATION_RECORD

if [[ "$POHW_CONFIRM_LOCAL_TEST_PATCH" != "YES" ]]; then
  printf 'Set POHW_CONFIRM_LOCAL_TEST_PATCH=YES to apply the harmless disposable fixture patch.\n' >&2
  exit 2
fi
if [[ -z "$IDENA_AI_ROOT" || ! -f "$IDENA_AI_ROOT/package.json" ]]; then
  printf 'Provide the pinned IdenaAI checkout through IDENA_AI_ROOT or the first argument.\n' >&2
  exit 2
fi
for command in cargo corepack git node npm tar; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'missing required command: %s\n' "$command" >&2
    exit 2
  }
done
[[ "$(node --version)" == v24.18.0 ]] || {
  printf 'Governance Day E2E requires Node.js v24.18.0 exactly.\n' >&2
  exit 2
}

workdir="$(mktemp -d "${TMPDIR:-/tmp}/pohw-governance-day.XXXXXX")"
cleanup() {
  rm -rf "$workdir"
}
trap cleanup EXIT INT TERM

read_integration_field() {
  node -e 'const fs=require("node:fs"); const value=process.argv[2].split(".").reduce((item, key) => item[key], JSON.parse(fs.readFileSync(process.argv[1], "utf8"))); process.stdout.write(String(value));' \
    "$INTEGRATION_RECORD" "$1"
}

idena_ai_base_commit="$(read_integration_field repository.baseCommit)"
integration_patch="$ROOT/$(read_integration_field integrationPatch.path)"
expected_patch_sha256="$(read_integration_field integrationPatch.sha256)"
expected_lock_sha256="$(read_integration_field dependencyLocks.0.sha256)"
expected_idena_ai_source_cid="$(read_integration_field sourcePackage.canonicalSourceCid)"
removed_forbidden_path="$(read_integration_field sourcePackage.removedForbiddenPath)"
redaction_mechanism="$(read_integration_field sourcePackage.redactionMechanism)"
actual_patch_sha256="$(node -e 'const fs=require("node:fs"); const crypto=require("node:crypto"); process.stdout.write(crypto.createHash("sha256").update(fs.readFileSync(process.argv[1])).digest("hex"));' "$integration_patch")"
[[ "$actual_patch_sha256" == "$expected_patch_sha256" ]] || {
  printf 'IdenaAI integration patch digest does not match its local integration record.\n' >&2
  exit 2
}
[[ "$removed_forbidden_path" == ".env.e2e" && "$redaction_mechanism" == "harness-policy-removal-before-packaging" ]] || {
  printf 'IdenaAI forbidden-path policy is not the reviewed fail-closed profile.\n' >&2
  exit 2
}
if grep -Fq -- "$removed_forbidden_path" "$integration_patch"; then
  printf 'IdenaAI integration patch must not transport environment-file paths or contents.\n' >&2
  exit 2
fi
git -C "$IDENA_AI_ROOT" cat-file -e "$idena_ai_base_commit^{commit}" || {
  printf 'The supplied IdenaAI checkout does not contain the exact integration base commit.\n' >&2
  exit 2
}

idena_ai_test_root="$workdir/idena-ai"
mkdir -p "$idena_ai_test_root"
git -C "$IDENA_AI_ROOT" archive "$idena_ai_base_commit" | tar -x -C "$idena_ai_test_root"
git -C "$idena_ai_test_root" init -q
git -C "$idena_ai_test_root" apply --check "$integration_patch"
git -C "$idena_ai_test_root" apply "$integration_patch"
forbidden_target="$idena_ai_test_root/$removed_forbidden_path"
[[ -f "$forbidden_target" && ! -L "$forbidden_target" ]] || {
  printf 'Expected tracked IdenaAI environment file is missing or not a regular file.\n' >&2
  exit 2
}
rm -- "$forbidden_target"
actual_lock_sha256="$(node -e 'const fs=require("node:fs"); const crypto=require("node:crypto"); process.stdout.write(crypto.createHash("sha256").update(fs.readFileSync(process.argv[1])).digest("hex"));' "$idena_ai_test_root/package-lock.json")"
[[ "$actual_lock_sha256" == "$expected_lock_sha256" ]] || {
  printf 'IdenaAI dependency lock digest does not match its integration record.\n' >&2
  exit 2
}
cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -p governance-cli -- package \
  --root "$idena_ai_test_root" \
  --repository IdenaAI \
  --output-dir "$workdir/idena-ai-package" >/dev/null
actual_idena_ai_source_cid="$(cat "$workdir/idena-ai-package/IdenaAI.source.cid")"
[[ "$actual_idena_ai_source_cid" == "$expected_idena_ai_source_cid" ]] || {
  printf 'IdenaAI source CID does not match its local integration record.\n' >&2
  exit 2
}
if [[ -d "$IDENA_AI_ROOT/node_modules" ]]; then
  ln -s "$IDENA_AI_ROOT/node_modules" "$idena_ai_test_root/node_modules"
else
  printf 'Install the exact IdenaAI dependencies in the supplied checkout before running the offline harness.\n' >&2
  exit 2
fi

rm -rf "$OUTPUT_ROOT"
mkdir -p "$OUTPUT_ROOT"

export npm_config_cache="${npm_config_cache:-/private/tmp/idena-ai-npm-cache}"
(
  cd "$idena_ai_test_root"
  npm exec -- jest \
    main/ai-providers/governance-operations.test.js \
    main/ai-providers/governance-operations-bridge.test.js \
    renderer/shared/components/ai-first-navigation.test.js \
    renderer/shared/components/governance-day-card.test.js \
    renderer/shared/utils/epoch-governance.test.js \
    renderer/shared/utils/governance-day-local-e2e.test.js \
    --runInBand
)
npm --prefix "$idena_ai_test_root" run build:renderer

cargo test --manifest-path "$ROOT/Cargo.toml" -p governance-core --test governance_vertical_slice
corepack pnpm --dir "$ROOT/contracts/idena-code-governance" test
corepack pnpm --dir "$ROOT/ui/pohw-dashboard" build

fixture_base="$workdir/fixture-base"
fixture_candidate="$workdir/fixture-candidate"
cp -R "$ROOT/tests/governance/fixtures/source-tree" "$fixture_base"
cp -R "$ROOT/tests/governance/fixtures/source-tree" "$fixture_candidate"
printf 'normalized source bytes\nconfirmed local governance fixture patch\n' >"$fixture_candidate/src/example.txt"

cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -p governance-cli -- package \
  --root "$fixture_base" \
  --repository GovernanceFixture \
  --output-dir "$workdir/base-package" >/dev/null
cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -p governance-cli -- package \
  --root "$fixture_candidate" \
  --repository GovernanceFixture \
  --output-dir "$workdir/candidate-package" >/dev/null
cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -p governance-cli -- diff \
  --base-car "$workdir/base-package/GovernanceFixture.source.car" \
  --candidate-car "$workdir/candidate-package/GovernanceFixture.source.car" \
  --output-dir "$workdir/patch-package" >/dev/null
cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -p governance-cli -- proposal-verify \
  --base-car "$workdir/base-package/GovernanceFixture.source.car" \
  --candidate-car "$workdir/candidate-package/GovernanceFixture.source.car" \
  --patch-car "$workdir/patch-package/GovernanceFixture.patch.car" >/dev/null

cargo run --quiet --manifest-path "$ROOT/Cargo.toml" -p governance-cli -- demo-epoch-governance \
  --output-dir "$OUTPUT_ROOT/protocol" >"$OUTPUT_ROOT/protocol.stdout.json"
cmp "$OUTPUT_ROOT/protocol/governance-day-protocol-demo.json" "$OUTPUT_ROOT/protocol.stdout.json"

kubo_status="not-run-docker-daemon-unavailable"
if [[ "${POHW_RUN_KUBO_E2E:-0}" == "1" ]]; then
  "$ROOT/tests/governance/kubo-sidecar-e2e.sh"
  kubo_status="passed-two-independent-loopback-sidecars"
fi

node "$ROOT/tests/governance/assemble-governance-day-e2e-report.mjs" \
  "$OUTPUT_ROOT/protocol/governance-day-protocol-demo.json" \
  "$OUTPUT_ROOT/governance-day-e2e-report.json" \
  "$kubo_status"
