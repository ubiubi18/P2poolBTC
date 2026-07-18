# Migration And Rollback

## Phase 0: package and verify, without deployment

The repository can package files directly from an exact full Git commit object,
without reading its worktree, and emit a canonical source CAR plus
`SourceCommitReceiptV1`. The command verifies every Git blob object, rejects
moving refs, symlinks, submodules, secrets, and unsafe paths, and packages the
same object set twice before accepting byte equality. Git remains optional
audit metadata; the source CID remains canonical.

The legacy compatibility lock stays byte-for-byte unchanged. No contract
address, initial canonical CID, genesis CID, activation height, or release is
authorized merely because a receipt or CAR exists.

Run package, proposal, contract-emulator, dashboard, desktop, identity-replay,
and cross-lock tests using disposable data and a separate public IPFS sidecar.
Retain the existing desktop updater as the rollback path.

```sh
COMMIT="$(git rev-parse HEAD)"
cargo run --locked -p governance-cli -- package-commit \
  --git-repository "$PWD" \
  --commit "$COMMIT" \
  --repository P2poolBTC \
  --output-dir /absolute/path/to/exact-commit-package
```

Each affected repository needs its own receipt. Deployment readiness rejects a
candidate when a repository has no receipt or its receipt names a different
source CID. Every receipt CID is also added to the content set that all public
availability operators must retrieve and verify.

## Phase 1: compatible application layer

Deploy only after review to an explicitly named testnet that already supports
the pinned contract ABI. Publish the initial `EcosystemManifestV1`, parameter
CAR, source CARs, artifacts, and pinset to several public-IPFS providers. The
deployment transaction sets the initial ecosystem CID and the exact parameter
CID compiled into the contract. It grants no continuing privilege.

Build identity metrics from exact finalized validation outcomes at the earliest
verifiable boundary. The current node database cannot automatically recover
the complete pre-integration author-to-final-qualification mapping, and the
reindex command therefore rejects unauthenticated operator JSONL. Start at the
first ceremony captured by the integrated indexer unless a future authenticated
chain data source is implemented. Record the source boundary, source block
hashes, counters, domain-separated ordered-record replay commitment, Merkle
root, and snapshot CID. At least three distinct eligible indexer operators must
replay and attest to the same complete descriptor before a migration proposal
can use it; conflicting quorums fail closed. If earlier history is unavailable,
mark it unknown and apply the deterministic prior. Never use Age or
`LastValidationFlags` as a substitute.

## Phase 2: separate governance fork

Any new WASM host import, consensus-maintained identity counter, genesis rule,
network ID, or validation-processing change must use
`compatibility/governance-fork-lock.json`. That profile is currently inactive,
uses network ID 10001 only as an experimental reservation, and states
`consensusDeltaImplemented=false`.

Before activation, require legacy state replay, pre-activation behavior,
cross-architecture WASM and gas determinism, state migration, explicit testnet
genesis, peer isolation, and rollback rehearsal. A high-threshold consensus or
migration proposal and timelock are required. No administrator can migrate the
contract or canonical reference.

## Deployed rehearsal gate

A local emulator run is development evidence, not a deployed migration
rehearsal. Before a `migration` or `consensus` candidate can receive a ready
deployment report, two distinct Idena-authenticated operators on two platform
families must independently observe the same public-testnet sequence:

1. Deploy the exact governance WASM artifact on the named isolated testnet.
2. Confirm the initial canonical CID equals the parent ecosystem CID.
3. Execute an accepted proposal and observe the candidate CID from contract
   state and versioned events.
4. Submit and execute a normal governed rollback proposal, without an admin or
   emergency key.
5. Observe the parent CID restored, preserve the state snapshot and event log,
   and verify a legacy-compatible node still works with governance disabled.
6. Publish redacted command output, compatibility results, and disabled-mode
   results by CID. Never publish RPC credentials, private endpoints, or keys.

Each operator packages `MigrationRehearsalAttestationV1`, derives its shared
transition digest, signs the generated authentication challenge with the
declared Idena identity, and publishes the CAR and proof. Pass the exact UTF-8
challenge to Idena's `dna_sign` method with the `doubleHash` format (or omit the
format, which defaults to `doubleHash`); do not pre-hash it or use `prefix`.
Operator-specific command and compatibility report CIDs may differ. The
network, contract, transactions, blocks, observed CIDs, state snapshot, and
event log must produce the same rehearsal digest.

```sh
cargo run --locked -p governance-cli -- migration-rehearsal-attestation \
  --input /protected/rehearsal/operator-a.json \
  --derive-rehearsal-digest \
  --output-dir /absolute/path/to/rehearsal-a

# Sign only the exact public challenge as dna_sign doubleHash input.
cargo run --locked -p governance-cli -- attestation-authenticate \
  --kind migration-rehearsal \
  --car /absolute/path/to/rehearsal-a/migration-rehearsal-attestation.car \
  --signature-file /protected/rehearsal/operator-a.signature \
  --output-dir /absolute/path/to/rehearsal-a-auth
```

The readiness verifier rejects missing signatures, duplicate operators,
conflicting rehearsal digests, failed tests, candidate/scope substitution, and
insufficient platform diversity. This is corroborated operator evidence, not a
cryptographic proof of permanent availability or independent infrastructure.

## Rollback

Canonical execution is append-only: the old CID remains retrievable and
auditable. A rollback is a new proposal whose candidate manifest references a
previously accepted source set with a new parent CID. It passes the same gates;
no emergency key bypass exists.

Before any public testnet activation, snapshot the testnet state, export CARs
and pinsets, record binary digests, test stopping the governance services, and
prove that legacy-compatible nodes still operate with governance disabled. A
failed migration means the inactive profile remains inactive.

As of this repository revision, the mechanisms above are implemented, but no
real independent builder set, public pin-operator set, external audit set, or
deployed rehearsal set is bundled. Readiness therefore remains fail-closed.
