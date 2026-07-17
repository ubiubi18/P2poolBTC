# IPFS Format

## Canonical profile

Governance objects use CIDv1, lowercase base32 display, and SHA2-256
multihashes. Structured roots use canonical DAG-CBOR (`0x71`). Artifact and
file blocks use raw (`0x55`). CAR exports are deterministic CARv1 with the root
first and referenced blocks in sorted path order. CAR length prefixes must use
minimal unsigned varints; duplicate, missing, trailing, oversized, or
out-of-order blocks are rejected. CID bytes must be the exact CIDv1,
DAG-CBOR-or-raw, SHA2-256 profile, not merely a string that a permissive parser
can decode.

The human JSON view is deterministic but is not the trust root. A Git commit is
optional metadata. It never replaces a source CID. GitHub and other Git mirrors
are transport fallbacks only, and bytes from a mirror are accepted only if they
recreate the expected canonical source CID.

## Source trees

The source packager normalizes paths, mode bits, and metadata. It excludes
`.git`, timestamps, known cache directories, local databases, environment
files, credentials, cookies, wallet material, and device files. Generic output
names such as `build`, `dist`, `tmp`, and `logs` are excluded only at the
repository root. A nested path such as `src/build/dist/module.rs` remains
canonical source; a directory name alone cannot silently hide nested code.
Absolute links, escaping links, directory links, and links to excluded binary
artifacts are rejected. A relative in-tree symlink to a regular source file is
normalized to the target bytes so checkout behavior is platform independent.
Packaging and verification share the same resource profile: at most 100,000
files, 100,001 CAR blocks, 256 MiB per file, and 2 GiB of source bytes. Paths
are limited to 4,096 UTF-8 bytes, 64 components, and 255 bytes per component.
Case-insensitive path collisions are rejected even on a case-sensitive host.
Files are opened without following links, bounded while reading, and checked
against the metadata identity observed during traversal, so a concurrent path
swap or growing file cannot bypass these limits.
Git, Mercurial, and Subversion control entries are omitted by component name
regardless of whether the checkout represents them as a directory or a control
file. Imported CAR manifests containing those control-path components are
rejected.

Release packaging uses `package-commit` with a full lowercase Git object ID.
The command reads immutable commit/tree/blob objects without checking out a
worktree, verifies each blob against the repository object format, packages
the source twice, and emits `SourceCommitReceiptV1`. The receipt is canonical
DAG-CBOR and binds the full commit and tree IDs, source-tree CID and digest,
source-CAR SHA-256, and file counts. It is audit evidence only: a source CID,
not the Git ID or receipt, remains the canonical source identity. Ordinary
`package --root` output remains valid for draft review but cannot satisfy the
deployment source-receipt gate.

The generated root file `ecosystem-lock.json` is deliberately absent from a
repository source tree. That lock records the repository source CID and would
otherwise make its own CID self-referential. This is a single exact-path rule:
`fixtures/ecosystem-lock.json` and every other nested file with the same name
remain ordinary source. A source CAR that includes the root control file is
rejected, and the compat-stack derivation metadata records the omission. The
lock itself is distributed and verified as governance control-plane evidence,
not as a member of the source tree whose identity it records.

Root component checkouts named `idena-go`, `idena-wasm-binding`,
`idena-wasm`, `idena-sdk-js-lite`, or `wasmer` are likewise omitted because
their source trees are independently CID-pinned and materialized by the
desktop source bootstrapper. The rule applies only to root directories; a
nested path such as `fixtures/idena-go` remains source. Imported CAR manifests
using one of those root prefixes are rejected. The ecosystem lock records the
generated dependency directories that were actually present during packaging.

The desktop static renderer export at the exact path `renderer/out` is omitted
as generated build output. Next.js embeds a per-build identifier there, so
including the directory would make a source CID depend on whether and when a
local renderer build ran. Nested paths such as `fixtures/renderer/out` remain
ordinary source. Imported CAR manifests using the generated output prefix are
rejected, and the ecosystem lock records the omitted output directory.

Identity-metrics snapshots are bounded to 262,144 eligible leaves and 65,537
canonical replay anchors in both Rust and Go. Contract-consumed DAG-CBOR
proposal and attestation payloads are additionally capped at 65,536 bytes.

Compiled archives and WASM binaries may be omitted only through an exact
reviewed exclusion policy containing each path and SHA-256. The policy cannot
hide source, an environment file, a database, or a secret-bearing path. The
omitted artifact must be distributed and verified separately by raw CID,
SHA-256, and size.

```sh
cargo run -p governance-cli -- package \
  --root /absolute/path/to/repository \
  --repository repository-name \
  --artifact-exclusions compatibility/governance-fork-artifact-exclusions/idena-go.json \
  --output-dir /tmp/repository-package

cargo run -p governance-cli -- verify \
  --car /tmp/repository-package/repository-name.source.car \
  --root /absolute/path/to/repository \
  --repository repository-name \
  --artifact-exclusions compatibility/governance-fork-artifact-exclusions/idena-go.json
```

The candidate ecosystem is also the source of the canonical toolchain
manifest. The opening availability pinset is derived only after an exact
parent-to-candidate transition has been verified. Repeat `--additional-cid`
for the rationale, migration notes, test plan, and any optional release or
critical-finding-waiver object referenced by the proposal.

```sh
cargo run -p governance-cli -- ecosystem-patch-package \
  --manifest /tmp/candidate/ecosystem-patch-input.json \
  --output-dir /tmp/candidate

cargo run -p governance-cli -- ecosystem-verify \
  --parent-car /tmp/parent/ecosystem.car \
  --candidate-car /tmp/candidate/ecosystem.car \
  --patch-car /tmp/candidate/ecosystem-patch.car

cargo run -p governance-cli -- toolchain-package \
  --ecosystem-car /tmp/candidate/ecosystem.car \
  --output-dir /tmp/toolchain

cargo run -p governance-cli -- pinset-package \
  --parent-car /tmp/parent/ecosystem.car \
  --candidate-car /tmp/candidate/ecosystem.car \
  --patch-car /tmp/candidate/ecosystem-patch.car \
  --additional-cid <rationale-cid> \
  --additional-cid <migration-notes-cid> \
  --additional-cid <test-plan-cid> \
  --output-dir /tmp/pinset
```

## Public IPFS boundary

Idena's embedded Kubo instance belongs to a private swarm and writes its own
swarm key. Governance must use a separate public Kubo repository and process.
Never point `POHW_PUBLIC_IPFS_API` at the Idena data directory or API.

```sh
export IPFS_PATH="$HOME/.ipfs-pohw-governance-public"
ipfs init
ipfs daemon

export POHW_PUBLIC_IPFS_API=http://127.0.0.1:5001
cargo run -p governance-cli -- pin \
  --car /tmp/repository-package/repository-name.source.car \
  --store "$HOME/.local/share/pohw-governance/pins" \
  --kubo-api "$POHW_PUBLIC_IPFS_API"
```

The CLI rejects a non-loopback Kubo control API unless the operator explicitly
opts into that risk. Gateway fallback must use HTTPS (loopback HTTP is allowed
for tests), and every downloaded CAR is parsed and rehashed locally. `pin` and
`fetch` support all governance CAR roots, including proposals, attestations,
parameter sets, releases, and source trees. Source-specific semantic checks
still require the corresponding `verify`, `proposal-verify`, or inspection
command.

```sh
cargo run -p governance-cli -- fetch \
  --cid <expected-cid> \
  --gateway https://ipfs.io,https://dweb.link \
  --output-dir /tmp/fetched-content
```

The fetched file is named `<expected-cid>.car`. Re-run the type-specific
validator before using its contents; generic CAR verification proves block and
root integrity, not that an arbitrary object satisfies a governance schema.

## Availability

The opening pinset manifest contains the candidate ecosystem, aggregate patch,
every repository patch, governance parameters, candidate source trees,
candidate artifacts, and proposal metadata. It may contain additional policy
or release objects. It is a required minimum rather than a way to conceal
evidence added later in the review window.

Each accepted agent review dynamically adds its own attestation, policy,
prompt-policy, test-result, static-analysis, dependency-finding, and finding-
evidence CIDs to the final availability set. Each accepted build adds its
attestation, exact toolchain, test-result, SBOM, and artifact CIDs. Deployment
readiness also adds every affected repository's source-commit receipt. For a
migration or consensus scope, it adds each deployed rehearsal attestation and
the referenced contract artifact, state snapshot, event log, redacted command
log, legacy-compatibility report, and governance-disabled report. At review
freeze, only availability attestations whose sorted verified-CID set covers
that complete final set count toward the gate. Each provider must additionally
include its own independently retrievable probe-result CID. Providers should
therefore attest after the agent, build, source-receipt, and rehearsal evidence
has settled, or submit a new attestation covering the expanded set.

Multiple independently operated providers must retrieve and verify every
required CID before submitting a signed availability attestation. An
attestation binds its operator, opening pinset, probe, expiry, and candidate
ecosystem. Its own attestation CID cannot recursively include itself and is
therefore verified directly from the submitted canonical DAG-CBOR payload;
all content it references is part of the availability set.

A CID proves content identity, not persistence. Signed pinning attestations and
provider bonds reduce risk but cannot cryptographically guarantee permanent
availability. The current WASM host cannot fetch public IPFS. A transient
gateway or provider outage also has no trustless negative proof; only committed
probe contradictions and other objective evidence are slashable.
