# Idena Code Governance Contract (Experimental)

This non-upgradeable AssemblyScript contract is a local/testnet vertical slice.
It has no owner, administrator, emergency executor, or privileged canonical-CID
setter after deployment. A proposal can update the canonical ecosystem CID only
after its independent PoS, PoHW, AI-review, reproducible-build, availability,
challenge, and timelock gates pass. Execution is permissionless.

The adapter uses the exact host imports exposed by the pinned `idena-wasm`
runtime. External method arguments are Idena `Region` pointers containing raw
RPC argument bytes. Do not pass native AssemblyScript string pointers.
The release target explicitly disables WebAssembly bulk-memory instructions,
which the pinned production runtime rejects.

Build and test with the locked Node and pnpm versions:

```sh
corepack pnpm --dir contracts/idena-code-governance install --frozen-lockfile
corepack pnpm --dir contracts/idena-code-governance build
corepack pnpm --dir contracts/idena-code-governance test
python3 scripts/pohw-governance-runtime-gate.py \
  --idena-go /absolute/path/to/idena-go
```

The last command deploys the exact lock-bound artifact twice through idena-go's
production `WasmVM`, compares outputs and gas, and exercises storage, attached
payment rejection, identity-proof registration, stake scheduling, and epoch
activation. Its cross-repository Go test is independently hash/CID-bound in the
governance-fork lock and applied as a read-only build overlay, leaving the
pinned idena-go checkout clean. For release evidence add
`--require-locked-sources` plus a `--component-repo NAME=/absolute/path` for
every non-idena-go component. That mode deliberately fails while any worktree
is dirty, any revision differs, or the fork lock is not marked
`canonical-locked-source`. The published prototype remains
`committed-experimental-prototype` and therefore fails this release gate.

The emulator exercises initialization, exact identity Merkle proofs,
independently certified metrics roots, delayed stake activation, vote
replacement, permissionless review rounds, all acceptance gates,
attestation-set completeness, all three bounded raw-result challenge types,
challenge and timelock boundaries, permissionless execution, separate bond
withdrawals, and unbonding. The production runtime gate is a compatibility and
bounded-gas smoke test, not a formal audit or exhaustive maximum-state gas
proof.

The contract intentionally cannot fetch IPFS. Clients and deterministic workers
must verify proposal CIDs, source trees, artifacts, and availability before
submitting commitment proofs. A CID does not guarantee permanent availability.

Proposal and attestation submission methods require the canonical DAG-CBOR
bytes in addition to the CID and Merkle proof. The contract recomputes the CID
and derives gate-relevant values from that payload, so parallel caller claims
cannot substitute a different candidate, owner, bond, result, or digest. Only
the explicitly separate `migration` risk class may advance the committed
identity-metrics root and epoch.

Review evidence is not selected by the proposal creator. An eligible identity
opens a bonded round with the canonical DAG-CBOR bytes for one exact
parent/candidate/patch tuple and its complete pinset. The contract recomputes
the four CIDs and commits to every candidate repository source, candidate
artifact, and toolchain lock. Build evidence must repeat that complete source
and artifact set and use the exact candidate toolchains. Omitting an authorized
candidate artifact is rejected; the per-artifact `core` flag affects only the
reproducible digest group, not coverage. The opening pinset must cover the candidate, aggregate and
repository patches, parameter set, candidate sources and artifacts, and all
proposal metadata. Agent and build submissions then add their attestation,
policy, result, finding, toolchain, SBOM, and artifact CIDs to the final
availability requirement. At freeze, only providers covering that complete
final set and their own probe-result CID count; an early partial attestation
remains auditable but contributes no availability weight. Duplicate provider
IDs and duplicate eligible owners do not create independent availability
weight. The availability phase cannot be frozen until the risk-specific number
of complete independent providers is present, so an arbitrary caller cannot
close the phase early with a single partial or short-lived attestation. Any
eligible reviewer, builder, or availability operator may submit bonded evidence during
the fixed review window. Anyone may freeze the round; the contract derives
sorted roots from the complete registered sets, and proposal creation must use
that exact frozen round. Every leaf is canonical-payload verified when it is
registered, each evidence class is bounded to 256 leaves, and favorable subsets
are rejected. The WASM challenge ABI recomputes the raw CID of an
attestation's own `testResultsCid` or `probeResultCid` and accepts only the exact
canonical false-result bytes `{"passed":false}` or `{"available":false}`. It
cannot prove global IPFS unavailability or adjudicate subjective findings.

Identity-metrics migration roots require three distinct eligible operator
identities to attest to the exact snapshot CID, digest, replay commitment,
boundary, source block, and indexer implementation. One dissenting operator
cannot reserve a root. The first descriptor to reach quorum becomes immutable;
later attestations for a conflicting descriptor are rejected.

Stake snapshots use immutable deposit lots and finalized-withdrawal
checkpoints. Aggregate weight for next-epoch deposits is scheduled at deposit
time and settled automatically at proposal creation, so a holder cannot be
excluded from the denominator by declining to call the per-address activation
method. Withdrawals do not mutate an already-open proposal's historical
weight. The current local-test contract caps each history at 256 entries and
has no reviewed compaction mechanism. One checkpoint slot is reserved for each
outstanding slashable proposal or attestation bond, preventing voluntary
withdrawals from exhausting the history needed for deterministic stake
slashing.
