# IPFS-Native Governance Architecture

## Trust Root

The canonical trust root is a CIDv1/base32 `EcosystemManifestV1` stored by an
Idena WASM governance contract. Git commits and mirrors are metadata and
transport only. Contract execution changes one canonical CID atomically; it
never edits repository files. A proposal whose parent is no longer canonical
is stale and cannot overwrite the newer manifest.

There is no lead developer, maintainer merge key, contract owner, emergency
installer, or AI merge authority. Deployment may set the immutable initial CID
and testnet parameters once. Afterwards, any caller may execute an accepted
proposal after all gates, challenge period, and timelock pass.

## Components

1. `governance-core` implements canonical schemas, deterministic integer
   voting math, CID verification, proposal gates, and a local contract model.
2. `governance-cli` packages sorted source trees into deterministic DAG-CBOR
   manifests and CARv1 files, creates multi-repository proposals, verifies
   patches, interacts with a separate public Kubo sidecar, and runs simulations.
3. `contracts/idena-code-governance` is a non-upgradeable AssemblyScript WASM
   contract with stake, bond, permissionless review-round, vote, attestation,
   challenge, and execution state. It derives evidence roots only when a fixed
   review window is frozen; a proposer cannot curate the committed set.
4. idena-go builds exact authored-flip metrics by replaying finalized validation
   outcomes, commits the exact ordered replay payload, and exposes only
   read-only governance RPC methods. The application-layer contract requires a
   threshold of distinct eligible indexer operators for a migration root and
   rejects conflicting quorums.
5. P2poolBTC exposes a local read-only governance API and experimental UI.
6. idena-desktop adds an opt-in experimental resolver and release verifier while
   retaining the existing updater as a rollback path.
7. idena-compat-stack validates atomic cross-repository locks and separates the
   unchanged legacy compatibility candidate from governance-fork experiments.
8. The non-executing build-evidence tool validates a pinned command plan,
   source CIDs, dependency locks, redacted logs, SBOM inputs, and artifacts.
   Source-controlled commands run only in separately isolated workers.
9. The production-runtime gate verifies the exact contract CID and SHA-256,
   confirms idena-go resolves the locked native binding, deploys twice through
   the real `WasmVM`, compares deterministic outputs/gas, and rejects unlocked
   source evidence in release mode. The cross-repository Go test is itself
   path-, size-, SHA-256-, and CID-bound by the governance-fork lock and is
   injected with Go's read-only build overlay; it does not modify or silently
   reinterpret the pinned idena-go source tree.
10. The Governance Day profile adds one proposal slot per eligible identity and
    epoch, one deterministic frozen proposal set, one complete commit/reveal
    epoch ballot, grace-delayed execution, append-only canonical history,
    decentralized revert proposals, and explicit local recovery staging.
    Deployment initializes this profile permanently; no contract method can
    re-enable the legacy independent per-proposal voting path. Canonical
    history is append-only and exposed through bounded 64-entry pages.
11. IdenaAI is the primary experimental governance interface. Its provider-
    neutral agents prepare reviews and briefs, but the user controls every
    ballot choice, signature, submission, and local rollback confirmation.
12. `DevelopmentPolicyBundleV1` adapts the MIT AI-Driven Dev phase vocabulary
    into a CID-bound lifecycle. Human/AI specification and isolated
    implementation feed independent review, build, availability, Idena voting,
    and permissionless execution. The policy validator rejects maintainer,
    GitHub, deployer, or autonomous-agent authority.

## Four Independent Gates

- PoS: sublinear, time-locked IDNA stake with yes/no/abstain and snapshotted
  turnout. One identity is not one equal political vote.
- PoHW: distinct eligible Idena identities, bounded state multiplier, and exact
  finalized authored-flip trust. Identity age is ignored.
- PoAW: content-addressed AI review attestations with authenticated owner-group
  diversity and one bounded model-family claim per owner. Runtime and provider
  labels remain audit metadata. AI agents cannot execute proposals.
- Proof of verification work: independent reproducible builds, tests, SBOMs,
  static/dependency analysis, and matching core artifact digests.

Every required gate must pass. No component is collapsed into an opaque score.
Because the current Idena WASM ABI cannot establish that claimed model and
builder platforms are operationally independent, the deployed contract state
is initialized with `blocked-unverified-v1` and critical proposals fail the
attestation gate. No current entry point enables that capability; a successor
requires a separate DAO migration and objective receipt verifier.

## Public IPFS Boundary

Idena's embedded Kubo node writes a fixed private-swarm key and is never reused.
Governance uses a separate repository, process, API endpoint, and pinset. CAR
downloads and gateway responses are accepted only after CID and declared digest
verification. Multiple signed availability attestations reduce, but cannot
eliminate, long-term availability risk.

## Compatibility Boundary

`compatibility/stack-lock.json` remains the legacy, no-consensus-change profile.
Application-layer contracts, indexers, Merkle proofs, and public IPFS work
without changing mainnet consensus. Any new host function, identity-state
counter, genesis change, network ID, or validation rule belongs exclusively in
a separate governance-fork profile with a distinct network identifier,
activation mechanism, replay/migration gates, source CIDs, and artifact digests.
`governance-fork-lock.json` preserves the historical inactive prototype;
`governance-day-fork-candidate-lock.json` is the current, still inactive
candidate and does not inherit authority from that historical file.

The legacy-compatible host ABI cannot authenticate a Governance Day epoch
anchor. The disabled `governance-day-fork-candidate-lock.json` therefore binds
exact patches for a read-only `env.epoch_block` import backed by
`State.EpochBlock()`. The component source CIDs and deterministic CAR digests
are locked and reconstructed in CI, but candidate commits remain unset, so the
profile cannot activate. The contract derives normal/critical risk and every
scope counter from bounded canonical base, candidate, and patch DAG-CBOR proofs; a
proposer-declared downgrade or fabricated path is rejected. Runtime, replay,
migration, independent-build, availability, and audit gates remain mandatory
before any fork activation.
