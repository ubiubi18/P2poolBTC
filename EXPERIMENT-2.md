# Experiment 2: Consensus-Enforced Idena Authorization

Experiment 2 is a source-only, inactive successor candidate. It adds a distinct
Bitcoin Core `pohw2` network where block consensus, rather than only the
supported P2Pool services, rejects a miner that lacks an authorization derived
from a finalized Idena snapshot. It does not alter Bitcoin mainnet, Idena
consensus, Experiment 1, or any existing fork history.

> [!CAUTION]
> This repository contains public fixture keys, dummy Idena data, no release
> artifacts, and `launch_enabled=false`. Do not expose its P2P port or advertise
> it as a live network. `bitcoind -chain=pohw2` refuses to start unless the
> binary was configured with the exact activation ID and the local-test-only
> `-allowexperimentalpohw2` override is supplied.

The exact candidate inputs are:

- [`compatibility/experiment-2-consensus-identity-candidate.json`](compatibility/experiment-2-consensus-identity-candidate.json)
- [`compatibility/experiment-2-consensus-identity-policy.fixture.json`](compatibility/experiment-2-consensus-identity-policy.fixture.json)
- [`compatibility/experiment-2-consensus-identity-authorization.fixture.json`](compatibility/experiment-2-consensus-identity-authorization.fixture.json)
- [`compatibility/experiment-2-bitcoin-core-patch-lock.json`](compatibility/experiment-2-bitcoin-core-patch-lock.json)
- [`schemas/pohw/ConsensusIdentitySnapshotInputV1.schema.json`](schemas/pohw/ConsensusIdentitySnapshotInputV1.schema.json)
- [`schemas/pohw/ConsensusIdentitySnapshotBundleV1.schema.json`](schemas/pohw/ConsensusIdentitySnapshotBundleV1.schema.json)

Verify their hashes, fixed vectors, Merkle proof, activation ID, schemas, and
both ordered Core patches offline:

```sh
python3 scripts/pohw-experiment-2-consensus-identity.py
```

## Consensus Rule

At heights `958176` through `959184`, inclusive, and while chain median time is
at least `1784404800` but lower than `1786219200`, every `pohw2` block must have
exactly one zero-value canonical `P2IA1` coinbase output and one zero-value
canonical `P2SW1` output. Core verifies that `P2IA1` contains:

- the exact compiled policy hash;
- a leaf for an Idena identity in only `Newbie`, `Verified`, or `Human` state;
- the registered x-only mining public key and registry commitment;
- a bounded Merkle proof to the compiled authorization root; and
- a valid BIP340 signature from that mining key.

The authorization set is strictly ordered by normalized Idena address with no
duplicate identity leaves. Proof depth must equal `ceil(log2(identity_count))`;
shorter, longer, malformed, or merely prefix-matching commitments are rejected.

The signature commits to the source-bound activation ID, policy and leaf
hashes, previous block, height, version, bits, ordered non-coinbase transaction
set, and all coinbase outputs except `P2IA1` itself. This prevents cross-profile
signature replay and changing payouts, `P2SW1`, or transactions after
authorization. Time, nonce, and coinbase extranonces remain mutable so ordinary
mining does not require a new identity signature per hash attempt.

The activation parent at height `958175` is pinned. Experiment 2 branches from
that immutable Experiment 1 checkpoint under new message magic, ports, chain
name, activation ID, and datadir. The activation ID commits to the exact Core
upstream commit, ordered patch-series digest, parent checkpoint, rule-set name,
and policy hash. Core exposes the configured activation ID through both
`getblockchaininfo` and `getblocktemplate`; the Rust adapter rejects any
mismatch. Experiment 2 never reinterprets Experiment 1 blocks at or after
activation.

## Snapshot Security Boundary

Bitcoin Core does not call an Idena RPC or trust a gateway during block
validation. The policy hash commits to an Idena finalized height and block
hash, registry contract address, authorization root, and expiry. Every node
therefore reaches the same result from block bytes and compiled parameters.

This is a bounded finalized-snapshot design, not a live Idena light client.
Consensus cannot revoke an identity in the middle of the committed window.
Eligibility changes after the snapshot take effect only in a later successor
profile; live Idena checks by supported services are additional honest-miner
policy, not a substitute for this consensus limitation. The earlier of the
height or median-time expiry makes the chain halt instead of silently accepting
a stale authorization set forever. Median time is miner-influenced within
Bitcoin's normal timestamp rules, so the height bound remains independently
necessary. A public candidate needs the complete authorization set,
deterministic replay evidence, independent attestations, and a newly computed
activation ID. Editing the checked-in fixture is not an upgrade path.

### Prepare finalized snapshot inputs

Build the capture tool from this exact repository source. Each capture operator
needs a separately administered, fully synchronized Idena node and the complete
set of public `registration-public.json` records returned by the deployed
ownerless registry. Do not use a wallet key, node key, backup, API key, or
password as a registration input.

```sh
umask 077
cargo build --locked --release -p idena-lite-indexer
mkdir -p /secure/pohw2-snapshot

# Add one public file per contract-indexed miner. The capture normalizes file
# order and rejects incomplete, extra, duplicate, or noncanonical contract data.
jq -s '.' \
  /absolute/path/miner-a/registration-public.json \
  /absolute/path/miner-b/registration-public.json \
  > /secure/pohw2-snapshot/registrations.json

target/release/idena-lite-indexer consensus-identity-capture \
  --rpc-url http://127.0.0.1:9009 \
  --api-key-file /protected/idena/api.key \
  --experiment-id p2poolbtc-experiment-2 \
  --registry-contract-address 0xREPLACE_WITH_DEPLOYED_CONTRACT \
  --registrations-file /secure/pohw2-snapshot/registrations.json \
  --finality-confirmations 6 \
  > /secure/pohw2-snapshot/snapshot-input.json

target/release/idena-lite-indexer consensus-identity-build \
  --input-file /secure/pohw2-snapshot/snapshot-input.json \
  > /secure/pohw2-snapshot/snapshot-bundle.json

target/release/idena-lite-indexer consensus-identity-verify \
  --input-file /secure/pohw2-snapshot/snapshot-input.json \
  --bundle-file /secure/pohw2-snapshot/snapshot-bundle.json \
  > /secure/pohw2-snapshot/snapshot-verification.json
```

The API key is read from its protected file and is never written to snapshot
output. Snapshot input is nevertheless public identity, registration, payout,
signature, and block evidence; inspect it before publishing its CID.

At least three operators must capture the same stable Idena head concurrently.
If any finalized boundary, identity root, complete source-input hash, or
authorization root differs, discard the set and repeat. Compare the pairs with:

```sh
python3 scripts/pohw-compare-idena-snapshots.py \
  --indexer-bin "$PWD/target/release/idena-lite-indexer" \
  --input /captures/operator-a/snapshot-input.json \
  --bundle /captures/operator-a/snapshot-bundle.json \
  --input /captures/operator-b/snapshot-input.json \
  --bundle /captures/operator-b/snapshot-bundle.json \
  --input /captures/operator-c/snapshot-input.json \
  --bundle /captures/operator-c/snapshot-bundle.json \
  --output /captures/snapshot-comparison.json
```

Matching files do not prove independent operation. The comparison deliberately
reports `operator_independence_verified=false` and `release_authorized=false`.
It rejects repeated paths, symlinks, and repeated filesystem objects, but copied
bytes can still come from one operator and therefore do not prove independence.
Each capture, input CID, bundle CID, and comparison CID still needs an
address-bound attestation from a distinct eligible Idena owner.

The current compatible Idena RPC returns the complete identity list and an
identity root but no Merkle proof connecting each returned row to that root.
Every v1 capture therefore declares
`identity_rows_assurance=compatible-rpc-unproven`. The lock also requires
`identity_rows_cryptographically_bound_to_root=false` and
`active_release_allowed=false`; the verifier rejects any attempt to flip those
claims. The capture binds a stable block and confirmation chain but cannot
cryptographically prove the RPC's identity rows. A deterministic finalized-state
replay or authenticated row proofs require a new reviewed snapshot schema before
an active manifest is possible. This limitation must not be replaced with
identity age, `LastValidationFlags`, or a developer-signed list.

## Build The Candidate From Source

Use a disposable checkout at the exact upstream commit with no wallet,
credentials, or live peer configuration. The builder verifies the lock, creates
a read-only patched source snapshot from a separate Git index, builds with the
pinned `depends` toolchain, runs both Experiment 1 and Experiment 2 consensus
tests, installs the deterministic core artifacts, and emits evidence v4.

```sh
git clone https://github.com/bitcoin/bitcoin.git bitcoin-core-pohw2
git -C bitcoin-core-pohw2 checkout --detach \
  9be056a8a72b624dae9623b2f7bded92c2a21c91

python3 scripts/pohw-experiment-2-consensus-identity.py

scripts/pohw-build-bitcoin-core-fork.sh \
  --source-dir "$PWD/bitcoin-core-pohw2" \
  --manifest "$PWD/compatibility/experiment-2-bitcoin-core-patch-lock.json" \
  --build-dir /secure/builds/pohw2-core \
  --snapshot-dir /secure/builds/pohw2-core-source \
  --jobs 4

python3 scripts/pohw-bitcoin-core-build-evidence.py verify \
  --manifest compatibility/experiment-2-bitcoin-core-patch-lock.json \
  --snapshot-dir /secure/builds/pohw2-core-source \
  --snapshot-metadata /secure/builds/pohw2-core/pohw-source-snapshot.json \
  --build-dir /secure/builds/pohw2-core \
  --run-record /secure/builds/pohw2-core/pohw-build-run.json \
  --evidence /secure/builds/pohw2-core/pohw-build-evidence.json
```

Run that flow in at least three clean rooms controlled by three distinct
eligible Idena owners and spanning at least two independently verifiable
platform families. Compare all evidence files:

```sh
python3 scripts/pohw-compare-bitcoin-core-builds.py \
  --evidence /builds/operator-a/pohw-build-evidence.json \
  --evidence /builds/operator-b/pohw-build-evidence.json \
  --evidence /builds/operator-c/pohw-build-evidence.json \
  --output /builds/pohw2-build-comparison.json
```

This comparison proves only matching declared source snapshots, required test
records, and artifact sets. It cannot infer who operated a builder, so its
output is always non-authorizing. Package every evidence file as a
`BuildAttestationV1`, authenticate its exact CID with a distinct eligible Idena
owner, publish the artifacts/SBOM/log CIDs, and pass the DAO build gate.

The normal startup refusal is another required test:

```sh
DATADIR=$(mktemp -d)
/secure/builds/pohw2-core/bin/bitcoind \
  -datadir="$DATADIR" -chain=pohw2 -daemon=0
```

It must exit nonzero and request `-allowexperimentalpohw2`. A build configured
without `POHW2_ACTIVATION_ID` must still refuse `pohw2` after that override is
supplied. Do not add the override to a service unit. It exists only to permit
isolated developer tests of the inactive fixture.

## P2Pool Integration

The Rust adapter accepts `--expected-rpc-chain pohw2` only when Core reports
the exact compiled Experiment 1 base rules plus the candidate activation ID,
parent, authorization height, height and MTP expiry, policy hash, root,
identity count, and proof-depth cap. Core's `getblocktemplate` must also require
the same fresh authorization metadata and report the exact parent-chain MTP
used by consensus; the adapter does not substitute template wall time.
The adapter then validates the local policy and Merkle proof, checks that the
leaf matches its protected mining key, constructs `P2SW1`, signs `P2IA1`, and
locally verifies the result before exposing a Stratum job.

The relevant future active-profile arguments are:

```text
--expected-rpc-chain pohw2
--refresh-job-from-rpc
--consensus-identity-activation-manifest /verified/active-manifest.json
--consensus-identity-policy /verified/active-policy.json
--consensus-identity-authorization /verified/miner-proof.json
--share-work-binding-policy /verified/active-share-work-policy.json
--share-work-binding-activation-manifest /verified/active-share-work-manifest.json
```

These flags do not authorize the checked-in fixture. A public runbook must bind
them to a new active manifest, independently verified source and build
artifacts, a deployed ownerless registry, and public peers.

## Public-Launch Blockers

Before a public test network can exist:

1. Deploy and independently verify the ownerless Idena registry contract.
2. Replay a finalized Idena boundary and publish the complete eligible set,
   Merkle root, proofs, source block evidence, and availability attestations.
   The replay or proofs must cryptographically bind every identity row to the
   finalized block's identity root; compatible-RPC v1 captures are insufficient.
3. Replace every fixture value and public test key.
4. Choose and document snapshot refresh or successor-activation rules before
   the current root expires.
5. Rehearse the inherited chain boundary with at least two independent nodes.
6. Obtain the lock-required matching snapshot captures and clean-room builds,
   authenticate each with distinct eligible Idena owners, and obtain an
   external audit.
7. Publish a new immutable active manifest and canonical source artifacts
   through the DAO process. No developer signature may substitute for this.

Until those gates pass, Experiment 2 is suitable only for local consensus and
interoperability testing.
