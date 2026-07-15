# Chain-Liveness Recovery Boundary

This document describes the experimental recovery boundary for the IPFS-native
governance prototype. It is not a production recovery protocol. Nothing in this
repository grants an owner, maintainer, emergency committee, AI agent, or
release signer authority to replace the canonical ecosystem CID.

## A. The chain is live and executed software is wrong

Create a `RevertProposalV1` that references a real canonical-history entry, the
currently canonical CID, the proposed previous or replacement CID, the evidence
and rollback-instruction CIDs, affected repositories, compatibility checks, and
risk class. The proposal consumes the caller's epoch proposal slot and remains
subject to its bond, eligibility checks, AI and build evidence, sublinear stake
vote, breadth/quorum gates, Governance Day, grace period, and permissionless
execution. There is no direct administrator revert.

Execution appends another history entry. It never deletes the original
proposal, vote, execution, or manifest. Each entry preserves the old and new
CIDs, proposal ID, governance epoch, decision-record CID, execution block,
rollback-manifest CID, release rollback-instructions CID, and observation end.

## B. The chain is live and the proposal is still in grace

Submit an objectively verifiable challenge before the challenge deadline. A
valid unresolved challenge prevents execution and does not alter the canonical
CID. After deterministic resolution, the proposal either resumes its timelock
or is rejected. A corrected change is a new immutable proposal; mutating the
accepted proposal is not allowed.

## C. A local desktop or node update is broken

Local recovery must not wait for an on-chain transaction. Before any future
installation, retain the previous release manifest, source CID, artifact
digest, binary location or reinstall source, compatibility metadata, health
criteria, and rollback instructions. The user can then choose **Return to
last-known-good version** and must confirm it explicitly.

The current MVP only verifies, stages, inspects, and simulates this action. It
does not replace files, stop processes, install software, or change the
canonical CID. The IdenaAI simulation verifies the expected last-known-good
digest, requires explicit confirmation, and remains available when chain RPC
is deliberately unavailable. Unattended install and unattended rollback are
disabled.

## D. The chain is not producing blocks

An on-chain WASM contract cannot vote, challenge, execute, or revert when the
chain cannot include transactions. The UI must enter safe mode, preserve the
last finalized governance checkpoint, and clearly state that on-chain recovery
is unavailable. Users must retain and be able to run last-known-good software.

A future protocol may study precommitted recovery manifests, last-finalized
checkpoints, broad rotating threshold attestations, offline recovery bundles,
explicit client opt-in, and later on-chain ratification. None of those ideas is
implemented as a hidden production path here. A complete chain-liveness
recovery mechanism requires a separate threat model, governance decision,
implementation, and activation profile.

## Future Interfaces

`RecoveryManifestV1` and `RevertProposalV1` are content-addressed interchange
formats, not authority. Future clients may expose read-only checkpoint queries,
verified offline-bundle inspection, and explicit opt-in activation, but they
must not infer approval from a publisher identity or repository location.

## Current Test Boundary

The local 33-step demonstration proves that canonical history retains both
CIDs, a revert references an actual execution, grace blocks early execution,
an objective challenge blocks execution, local rollback simulation works with
chain RPC unavailable, and no code is automatically installed. It does not
prove public-chain liveness, independent availability, or safe production
recovery.
