# Migration And Rollback

## Phase 0: local only

The current state is an uncommitted local experimental prototype based on the
exact revision recorded in the governance-fork lock. The prototype files and
artifact are not yet represented by a canonical source commit or source CID.
The legacy compatibility lock stays byte-for-byte unchanged. No contract address, initial canonical CID,
genesis CID, activation height, or release is authorized.

Run package, proposal, contract-emulator, dashboard, desktop, identity-replay,
and cross-lock tests using disposable data and a separate public IPFS sidecar.
Retain the existing desktop updater as the rollback path.

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

## Rollback

Canonical execution is append-only: the old CID remains retrievable and
auditable. A rollback is a new proposal whose candidate manifest references a
previously accepted source set with a new parent CID. It passes the same gates;
no emergency key bypass exists.

Before any public testnet activation, snapshot the testnet state, export CARs
and pinsets, record binary digests, test stopping the governance services, and
prove that legacy-compatible nodes still operate with governance disabled. A
failed migration means the inactive profile remains inactive.
