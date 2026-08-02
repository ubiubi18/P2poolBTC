# P2poolBTC Experiment 1: Five-Minute Start

This is the shortest safe path for a community member who wants to review or,
later, join P2poolBTC Experiment 1. The command is source-first and read-only:
it does not download a binary, install a service, access a wallet, register an
Idena identity, connect to a peer, or start mining.

Experiment 1 is an experimental no-value Bitcoin Core fork. Its coins have no
promised value. Idena is a live chain with real identities and IDNA, so never
share an Idena key, backup, password, or node API key. Never reuse a Bitcoin
mainnet key in the experiment.

## Community Review Day

Experiment 1's public interlock does not open: its Idena eligibility gate is a
P2Pool runtime policy, not a Bitcoin block-consensus rule. Community onboarding
therefore has three independent preparation tracks while a separately activated,
consensus-enforced successor is designed and reviewed. None imports an identity,
contacts a peer, starts a service, or mines. Record the exact commit from
`git rev-parse HEAD` as mirror metadata.
When canonical artifacts exist, also record the source CID and source-CAR
SHA-256; those content identities are authoritative, while the commit is not.

Reviewers can also inspect the inactive share-work successor described in
[`docs/share-work-binding.md`](docs/share-work-binding.md). Its content-bound
activation and policy must verify, while `--require-launchable` must fail. It
prevents a P2Pool miner from assigning already-ground header work to a different
parent or Idena anchor, but it is not the still-required Bitcoin-consensus
identity gate.

### Observer or source reviewer

```sh
./scripts/pohw-community-onboard.sh --role observer
```

The expected result is `review-ready`. Report reproducible defects with the
generated `issue-report.md`; use private vulnerability reporting for a security
finding.

### Independent miner-registry builder

Treat the source tree as hostile. Use a disposable clean-room VM that is not
operated by the first builder, mount no wallets or credentials, keep the source
read-only where practical, and disable network access after a separately logged
dependency-fetch phase. Use the exact locked Node.js and pnpm versions, then
build from source:

```sh
test "$(node --version)" = "v24.18.0"
test "$(corepack pnpm@11.11.0 --version)" = "11.11.0"
corepack pnpm@11.11.0 --dir contracts/idena-pohw-miner-registry install --frozen-lockfile
corepack pnpm@11.11.0 --dir contracts/idena-pohw-miner-registry test
corepack pnpm@11.11.0 --dir contracts/idena-pohw-miner-registry build
cargo run --locked -p governance-cli -- artifact-inspect \
  --file contracts/idena-pohw-miner-registry/build/idena-pohw-miner-registry.wasm
```

For the current reviewed candidate, the final command must independently
produce size `55875`, SHA-256
`7f5cbf0daeded9bc3ca04ade914e37688edccaa0a8ad025bb74842ec788ad601`,
and raw CID
`bafkreid7ls7q3lw63g6dzick32iu4n3ir3omvifivubfxn2iilwhrcwwae`.
A matching result is useful reproducibility evidence, but it is not an
attestation until its exact source, toolchain, commands, and owner are
authenticated through the governance evidence flow.

### Second-node host operator

On a Linux host with SSD storage, run only the read-only host and policy check:

```sh
./scripts/pohw-community-onboard.sh \
  --role pruned-miner \
  --storage-path /srv/sharechain
```

The expected Experiment 1 result is always `blocked-public-join`. A suitable host may pass its
system checks, but the command must not register an identity or start Core,
gossip, Stratum, or mining. The end-to-end second-node rehearsal happens only
on a new successor activation after its consensus implementation, independently
verified registry deployment, migration rehearsal, and release evidence are
available. No evidence bundle can turn the existing Experiment 1 activation into
that successor.

Use the dedicated
[independent verification form](https://github.com/ubiubi18/P2poolBTC/issues/new?template=experiment-1-independent-verification.yml)
for non-sensitive aggregate results. A public issue is coordination evidence,
not by itself a builder, audit, availability, or deployment attestation.

## 1. Choose A Role

| Role | Minimum checked by the tool | What it does now |
| --- | --- | --- |
| `observer` | 2 CPU cores, 4 GiB RAM, 5 GiB free | Performs static source/policy checks; never executes repository tests or joins the network |
| `pruned-miner` | Linux, systemd, SSD, 4 cores, 16 GiB RAM, 90 GiB free on a nominal 100 GiB volume | Checks readiness for the future pruned live-node path |
| `archive-operator` | Linux, systemd, SSD, 4 cores, 16 GiB RAM, 900 GiB free | Checks readiness for the future archival-node path |

The Raspberry Pi without an SSD should use `observer`. Do not run Experiment 1
Core, Stratum, gossip, or mining on its SD card.

The pruned-miner threshold accounts for filesystem metadata and reserved blocks:
a freshly formatted nominal 100 GiB volume commonly exposes less than 100 GiB
as free space. The check still requires 90 GiB to remain available before setup.

## 2. Obtain The Exact Source Candidate

GitHub is currently a development mirror, not a canonical release authority.
Until a source CID and exact release commit are published, this checkout is for
review only:

```sh
git clone https://github.com/ubiubi18/P2poolBTC.git
cd P2poolBTC
git fetch origin
git switch --detach origin/vibe/experiment-1-release-readiness
test -z "$(git status --short)"
```

Do not substitute `main`, `master`, or another moving branch for a future exact
release revision.

A live release uses a stronger trust path. Read the canonical ecosystem CID
from the Idena governance reference through an independent synchronized node,
fetch its `EcosystemManifestV1` CAR and the P2poolBTC source CAR from public
IPFS, and obtain the four runtime artifacts named by that manifest. The
onboarding tool parses and hashes the ecosystem CAR itself, verifies the
`pohw-governance` executable against the manifest before executing it, and
requires the local source tree to reproduce the declared source CID. Only then
can repository-provided manifest or policy code run. Git and GitHub remain
transport and review tools; neither selects the canonical release.

## 3. Run One Guarded Command

For a review on a laptop or Pi:

```sh
./scripts/pohw-community-onboard.sh --role observer
```

On Windows PowerShell, run the same state machine with:

```powershell
.\scripts\pohw-community-onboard.ps1 --role observer
```

This default check does not contact a package registry or execute repository
build/test commands. `--run-tests` deliberately refuses: onboarding receipts
must not turn hostile source into an unsandboxed command runner. For a deeper
review, use a disposable VM with no wallets, SSH agent, provider tokens, API
keys, or host mounts. Log a distinct dependency-fetch phase, disconnect the
network, then run the locked checks directly inside that disposable environment:

```sh
cargo fetch --locked
cargo test --locked --workspace
```

For a future pruned-node host readiness check:

```sh
./scripts/pohw-community-onboard.sh \
  --role pruned-miner \
  --storage-path /srv/sharechain
```

Today, a clean observer checkout should end at `review-ready`; this means the
guarded static review completed, not that project tests or release verification
passed. A miner should end at `blocked-public-join`, because Experiment 1 lacks
Bitcoin-consensus identity enforcement in addition to its incomplete independent
release, registry, and second-node gates. That block is a safety result, not an
installation failure. Do not bypass it.

The command writes three private local files under
`~/.pohw-onboarding/pohw-experiment-1/`:

- `onboarding-report.html`: a local five-stage status page;
- `onboarding-receipt.json`: machine-readable aggregate diagnostics; and
- `issue-report.md`: a pre-redacted issue template.

None of these files contains an identity address, miner ID, peer endpoint,
wallet data, RPC secret, or local path. Still inspect the issue template before
posting anything.

## 4. Understand The Result

| Result | Meaning | What to do |
| --- | --- | --- |
| `review-ready` | Guarded static source, manifest, policy, and host checks completed; project code was not executed | Review code and docs; use a disposable clean-room builder for tests |
| `host-not-ready` | The selected role exceeds this host or required tools are missing | Read the plain-language next actions; choose `observer` if appropriate |
| `verification-failed` | Source is dirty or a pinned verifier/test failed | Stop and use a clean exact checkout; do not override the failure |
| `blocked-public-join` | Local checks passed, but this activation lacks Bitcoin-consensus identity enforcement or another release gate | Review only; do not register an identity or start services; wait for a separately activated successor |
| `ready-for-identity-registration` | A future successor release passed every public and consensus gate | Continue with that successor's reviewed guide |
| `live-join-incomplete` | A read-only live proof found a missing local result | Follow only the listed local corrective action |
| `live-join-verified` | The exact local Core service and consensus profile, fresh tip and peer, registration, eligible three-voter snapshot, template, gossip peer, and a fresh share from this miner all passed | Keep the receipt and monitor progress |

The five displayed stages are always the same: system check, release
verification, identity registration, network join, and success proof. A later
stage never passes when an earlier required stage is blocked.

## 5. Report A Useful Issue

Open a GitHub issue only after removing any private context. Start from the
generated `issue-report.md` and the repository's
[Experiment 1 issue form](https://github.com/ubiubi18/P2poolBTC/issues/new?template=experiment-1-bug.yml),
then include:

- the receipt schema, selected role, journey status, and stage statuses;
- the canonical source CID and source-CAR SHA-256 when published;
- the exact Git commit reviewed as optional mirror metadata;
- the next-action codes;
- what you expected and what happened; and
- the smallest reproducible command that does not contain private data.

Never post identity addresses merely for debugging, miner IDs, peer endpoints,
wallet descriptors, RPC cookies, API keys, signatures, local filesystem paths,
or full service logs. Security-sensitive findings should use a private security
report rather than a public issue.

## After The Public Interlock Opens

Do not use the live probe today. Once an exact source CID, CAR, build evidence,
finalized Idena registry anchor, external review, and independent second-node
rehearsal are published, the same command can verify those artifacts and then
perform a read-only local success proof. Obtain every placeholder below from
the accepted ecosystem manifest, the Idena governance reference, or locally
verified service state. Do not derive `EXPECTED_ECOSYSTEM_CID` from the CAR,
GitHub, or the launch-policy file it is meant to check.

```sh
EXPECTED_ECOSYSTEM_CID='<CID read independently from Idena governance>'
CANDIDATE_ECOSYSTEM_CAR='/path/to/EcosystemManifestV1.car'
P2POOL_SOURCE_CAR='/path/to/P2poolBTC-source.car'
READINESS_CAR='/path/to/deployment-readiness.car'
READINESS_EVIDENCE_CAR='/path/to/deployment-readiness-evidence.car'
ANCHOR_POLICY='/path/to/finalized-idena-anchor-policy-v2.json'
GOVERNANCE_CLI='/path/to/manifest-attested/pohw-governance'
P2POOL_NODE='/usr/local/libexec/p2pool-experiment-1/p2pool-node'
IDENA_RPC_URL='http://127.0.0.1:9009'
IDENA_API_KEY_FILE='/path/to/private/idena-api.key'
BITCOIN_CLI='/usr/local/libexec/pohw-bitcoin-core-v31.1/bin/bitcoin-cli'
STORAGE_ROOT='/srv'
POHW_DATADIR='/srv/sharechain/<activation-specific-directory>'
SNAPSHOT_DIR="$POHW_DATADIR/snapshots"
BITCOIN_DATADIR='/srv/bitcoin/pohw'
BITCOIN_COOKIE='/run/bitcoin-pohw-rpc/.cookie'
MINER_ID='<your locally registered miner ID>'

./scripts/pohw-community-onboard.sh \
  --role pruned-miner \
  --storage-path "$STORAGE_ROOT" \
  --expected-ecosystem-cid "$EXPECTED_ECOSYSTEM_CID" \
  --candidate-ecosystem-car "$CANDIDATE_ECOSYSTEM_CAR" \
  --source-car "$P2POOL_SOURCE_CAR" \
  --governance-cli "$GOVERNANCE_CLI" \
  --readiness-car "$READINESS_CAR" \
  --readiness-evidence-car "$READINESS_EVIDENCE_CAR" \
  --idena-anchor-policy "$ANCHOR_POLICY" \
  --idena-rpc-url "$IDENA_RPC_URL" \
  --idena-api-key-file "$IDENA_API_KEY_FILE" \
  --probe-live \
  --p2pool-node "$P2POOL_NODE" \
  --p2pool-datadir "$POHW_DATADIR" \
  --snapshot-dir "$SNAPSHOT_DIR" \
  --miner-id "$MINER_ID" \
  --bitcoin-cli "$BITCOIN_CLI" \
  --bitcoin-datadir "$BITCOIN_DATADIR" \
  --bitcoin-cookie-file "$BITCOIN_COOKIE"
```

This evidence-bound live verifier requires Linux because it executes reviewed
binaries only from sealed immutable `memfd` snapshots. Other platforms fail
closed instead of staging a mutable temporary executable. The result cannot be
`ready-for-identity-registration` unless the attested `p2pool-node` verifies the
exact registry deployment and finality through that synchronized loopback Idena
RPC. Never paste the API key or its file contents into a report.

`STORAGE_ROOT` must be an existing non-symlink root on the filesystem that
contains both data directories. It may be service-owned; the checker requires
the root to be readable/traversable and the filesystem to be writable, then
the live commands prove access to the actual data. All subprocess output is
bounded and the generated receipt contains only aggregate, redacted results.
Another miner's historical share does not count: the live result fails when
this miner has no fresh active share, when fewer than three distinct snapshot
voters attest the eligible identity, or if Core is remote, stale, unsynced, peerless, launched
from another executable/profile, or not running under the reviewed systemd
unit.

The full argument list is available through:

```sh
./scripts/pohw-community-onboard.sh --help
```

Windows users can replace the shell wrapper with
`.\scripts\pohw-community-onboard.ps1 --help`.

The detailed source build, Core setup, identity challenge, gossip, Stratum,
stop, and recovery procedure remains in
[COMMUNITY-EXPERIMENT-1.md](COMMUNITY-EXPERIMENT-1.md). Do not execute its live
sections until this command reports `ready-for-identity-registration` from a
clean exact release.
