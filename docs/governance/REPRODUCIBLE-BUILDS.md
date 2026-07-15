# Reproducible Builds

Build attestations bind exact source CIDs, dependency lock digests, compiler
versions, commands, test-result CIDs, SBOM CIDs, artifact CIDs, SHA-256 values,
sizes, platform families, and builder identities. Builders use clean source
checkout from verified CARs, not an unverified Git working tree.

## Required workflow

1. Verify and check out every repository CAR.
2. Restore dependencies only from the declared lockfiles.
3. Record the fetch result, then disable network access.
4. Build in a fresh container or equivalent clean environment.
5. Run tests, static analysis, dependency analysis, and SBOM generation.
6. Compute raw artifact CIDs, SHA-256 values, and sizes.
7. Package and sign `BuildAttestationV1`.

The pinned local-only plan is
`compatibility/governance-build-plan-v1.json`. It covers the Rust workspace,
governance contract, dashboard, idena-go, desktop renderer and installer,
idena-sdk-js-lite, and every locked native WASM archive. Validate it without
executing repository code:

```sh
python3 scripts/pohw-governance-build-evidence.py validate-plan \
  --plan compatibility/governance-build-plan-v1.json
```

Each target identifies a nonempty dependency-fetch command prefix. The build
worker may enable network access only for that prefix. Package-manager scripts
are disabled while dependencies are fetched. The remaining Cargo and Go
commands use offline mode, and the worker must enforce network isolation at the
operating-system or container boundary. A Boolean claim in a result record is
not a substitute for that isolation.

The Experiment 1 Bitcoin Core builder follows the same separation. Build
evidence v4 first hashes a byte-identical working copy of the immutable
snapshot's `depends` subtree, then records the exact `download-one` and
`install` commands. It seals the resulting prefix, hashes every normalized path
and byte, binds the generated `toolchain.cmake`, and rejects CMake
configurations that did not use it. The evidence also records the CMake
compiler configuration and executable digests. The shell script does not
provide a portable network sandbox; clean-room operators must disable network
access after `depends_fetch`. Tests execute the unstripped build outputs first;
the deterministic artifact set comes from a separately recorded CMake install
with stripping. The recorded C and C++ flags map source and build roots to
stable `/pohw/source` and `/pohw/build` paths so dependency headers and
generated sources cannot embed a builder's scratch directory. On Darwin the
recorded configure environment also disables the path-sensitive Mach-O UUID,
which makes the linker-generated ad-hoc code signature deterministic for
identical bytes. Apple notarization is not part of that deterministic core.

The evidence generator never executes source-controlled commands. It verifies
the plan, source CID bindings through a digest-pinned verifier and source CAR,
exact dependency locks, declared toolchains, successful command records,
complete redacted stdout/stderr logs, and artifact paths. It then emits
deterministic `BuildEvidenceV1`, CycloneDX 1.5 SBOM,
environment, test-result, raw-CID, and SHA-256 evidence. Directory outputs are
archived with sorted UTF-8 paths, normalized modes and owners, and zero mtimes.
Symlinks, special files, credential-like paths, lock drift, and unexpected
commands fail closed.

An attestation may retain failed command records only when `testsPassed` is
false. Rust, the AssemblyScript contract, and the desktop release verifier all
reject `testsPassed: true` when any committed command has a nonzero exit code.
This catches an objectively contradictory claim; it does not prove that the
recorded command set was complete or that a self-asserted runtime label is
truthful.

`coreArtifactDigest` is not the SHA-256 of one arbitrarily selected file. It
commits to every artifact marked `deterministic` in the build plan. When a
`BuildAttestationV1` is assembled, those entries receive `core: true`; all
other artifacts receive `core: false`. Implementations hash the UTF-8-sorted
core entries as:

```text
SHA256(
  "IDENA_GOV_CORE_ARTIFACT_SET_V1\\0" ||
  u32be(core_count) ||
  for each core artifact:
    u32be(name_utf8_length) || name_utf8 ||
    u32be(cid_utf8_length)  || cid_utf8  ||
    sha256_raw_32_bytes     || u64be(size)
)
```

The contract and updater recompute this commitment. A build target with no
deterministic core is invalid. The platform-constrained desktop-installer
target therefore includes the renderer archive and bundled node as core
artifacts while treating the signed installer itself as non-core.

SBOMs, test results, and artifact bytes use raw CIDv1/SHA2-256. The generator
also writes `toolchain-locks.dag-cbor`, a canonical DAG-CBOR map of the full
plan toolchain lock. Its CID is the attestation `toolchainCid`; the raw
`build-environment.json` CID remains supporting evidence and must not be used
as a toolchain manifest.

Core local commands are:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo build --workspace

corepack pnpm --dir contracts/idena-code-governance install --frozen-lockfile
corepack pnpm --dir contracts/idena-code-governance build
corepack pnpm --dir contracts/idena-code-governance test

python3 scripts/pohw-governance-runtime-gate.py \
  --idena-go /absolute/path/to/idena-go

cargo run -p governance-cli -- artifact-inspect \
  --file contracts/idena-code-governance/build/idena-code-governance.wasm
```

Those commands are development checks. A governance build attestation is valid
only when its exact plan target is run in an independent clean room with the
locked toolchain and its generated evidence is publicly retrievable by CID.
The governance-contract target also runs the same exact artifact through
idena-go's production `WasmVM`. The integration test is a deterministic
P2poolBTC source artifact bound in `governance-fork-lock.json`; the gate checks
its raw CID and digest, then overlays it into the otherwise clean pinned Go
package without writing to that checkout. Its release command adds
`--require-locked-sources` and every component path, and fails unless all source
worktrees are clean at the fork-lock revisions. The compiler disables
`bulk-memory` because that instruction set is unsupported by the pinned
runtime. Measured deterministic gas ceilings are regression guards, not a
maximum-state proof.

For Go and desktop commands, use the exact versions in `ecosystem-lock.json`:

```sh
go test ./...
go vet ./...

npm ci
npm run lint
npm test -- --runInBand
npm run audit:privacy
npm run audit:metadata
npm run audit:artifacts
npm run audit:deps
npm run audit:electron
npm run release:check
```

Normal proposals need two independent builders in one matching deterministic
artifact-set group. Critical proposals need three builders in one group and
at least two architecture or operating-system families. Conflicting groups do
not contribute to the selected group; they remain committed and auditable.

Rust binaries, Go binaries, renderer output, and contract WASM should be made
deterministic first. Desktop installers may still contain platform timestamps,
signing envelopes, notarization tickets, or tool-specific ordering. Those
differences must be documented. Apple notarization and Windows signing remain
external centralized constraints and are not solved by IPFS or DAO approval.

The fork lock records an exact contract artifact, but labels it
`committed-experimental-prototype` and `canonicalAuthorization: none`. It is
not a release. No installer or release is authorized until independent
clean-room attestations and all governance gates exist.
