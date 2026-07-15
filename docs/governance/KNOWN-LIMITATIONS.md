# Known Limitations

This implementation is safe only for local, no-value testing.

- The legacy-compatible WASM host still cannot authenticate the Governance Day
  schedule. A separate disabled fork candidate now supplies a read-only
  `epoch_block` import backed by `State.EpochBlock()`. Its component patches now
  have deterministic source CIDs and CAR digests that CI reconstructs from the
  exact base revisions, but they still have no committed candidate revisions.
  It cannot be activated until those commits plus replay, migration, gas, and
  cross-repository compatibility gates pass.
- The Governance Day contract now derives normal/critical risk and scope
  counters from exact bounded base, candidate, and patch DAG-CBOR payloads.
  This removes proposer-declared paths and counters, but each aggregate source
  proof is capped at 600,000 canonical bytes. Larger ecosystem transitions must
  be split without evading the critical-path classifier or use a separately
  reviewed proof format.
- The classifier is objective, not omniscient. It treats consensus, contracts,
  compatibility, security, deployment, workflow, dependency, and migration
  paths as critical and otherwise permits bounded normal changes. A dangerous
  semantic change hidden in an apparently normal path can still be missed by
  path classification, so independent review and build gates remain required.
- The local candidate requires the 10 IDNA normal or 25 IDNA critical bond
  derived from the verified source transition. An underfunded critical round
  cannot create a proposal and must expire before its refundable balance is
  claimed.
- The IdenaAI integration is represented as a local, exact-base patch because
  this task forbids publishing branches. Its tracked `.env.e2e` is excluded
  from the patch so deleted environment bytes cannot leak through diff
  transport, then removed by one exact fail-closed harness policy before source
  packaging. The environment-file policy is not relaxed. The patch and source
  CID are local candidate evidence, not a release or DAO authorization.
- The MIT human/AI development policy is implemented and content-addressed, but
  it is not a proof that reviewers, model families, builders, or pin providers
  are organizationally independent. It also does not make AI output correct.
  Prompt injection, correlated models, provider compromise, and dishonest
  attestations remain residual risks handled only partially by isolation,
  diversity, objective challenges, bonds, and the other acceptance gates.
- Local rollback support verifies, stages, inspects, and simulates a return to
  last-known-good software. It does not install binaries, replace files, stop
  processes, or claim that an on-chain revert works while the chain is stuck.
- Nothing is deployed. There is no authorized contract address, initial
  ecosystem CID, genesis CID, activation block, release, or public testnet.
- The exact lock-bound contract now deploys and executes through idena-go's
  production `WasmVM` with the pinned native binding. Two independent
  in-memory runs match byte-for-byte and enforce measured ceilings for deploy,
  query, storage, attached-payment, stake-scheduling, and activation paths. The
  test discovered and removed unsupported bulk-memory instructions. This is
  still not an exhaustive maximum-state gas proof, cross-architecture run, or
  external runtime audit.
- The production integration test lives in P2poolBTC rather than the pinned
  idena-go commit. Its exact path, target, size, SHA-256, and raw CID are locked,
  and Go injects it as a read-only build overlay. This adds test code only; it
  does not patch production runtime code or make the prototype a release.
- The contract parameter CID is compiled in and exact, but changing parameters
  requires a separately reviewed contract migration proposal. There is no
  upgradeable admin proxy.
- Evidence is registered permissionlessly in a fixed bonded review round for
  one parent/candidate/patch/scope tuple. The V2 round ID and every builder
  attestation bind the exact verified scope CID. Anyone may freeze the round
  after its deadline, and roots are derived from all registered CIDs; proposal
  creation cannot curate a favorable subset. Both the Rust lifecycle and WASM
  contract recompute bounded raw evidence CIDs for false agent test, builder
  test, and availability claims. The WASM parser deliberately accepts only
  `{"passed":false}` and `{"available":false}`. General malformed-content and
  transient IPFS outage proofs are not fully expressible on-chain. The host
  cannot fetch IPFS, and global unavailability has no simple trustless proof.
- A permissionless review window does not prove universal notice, network
  access, or freedom from censorship. Operators still need public discovery,
  mirrors, and enough review time. The prototype caps each evidence class at
  256 entries and allows at most two agent and two build attestations from one
  eligible identity per round; availability already permits one per owner.
  Saturating an agent or build class therefore requires at least 128 eligible,
  bonded identities. That materially raises the cost but does not eliminate a
  coordinated identity-farming or censorship attack, so public-testnet
  parameters still require adversarial capacity testing.
- Model family, runtime family, architecture, provider, and pin-operator labels
  are authenticated to the submitting Idena identity but remain self-asserted.
  Diversity counts therefore resist duplicate identities, not coordinated
  operators lying about infrastructure. External attestation or measured
  execution is still required before these labels can be treated as strong
  independence evidence.
- Signed pinning attestations reduce availability risk but cannot guarantee
  permanent retrieval. The opening pinset covers candidate and proposal
  content, and the final gate additionally requires every accepted agent/build
  attestation and referenced policy, result, finding, toolchain, SBOM, and
  artifact CID. An availability attestation's own CID is necessarily excluded
  from its recursively described set; its canonical bytes are instead checked
  directly at submission. The Governance Day path stores the minimum
  attestation expiry and rechecks that it spans finalization, grace, and the
  execution window. No finite attestation proves future persistence.
- Bitcoin Core build evidence records a distinct checksummed dependency-fetch
  phase and a sealed `depends` prefix, but it cannot portably enforce network
  isolation for the later dependency build. Independent builders must apply
  that boundary externally. Host compilers, SDKs, platform signing, and
  notarization can still make native packages differ, so no release is
  reproducible until the required builders report matching deterministic-core
  digests. The deterministic core uses stable source/build prefix maps and
  stripped install artifacts rather than raw debug-bearing build outputs.
- The current idena-go database does not retain enough direct author-to-final-
  qualification history for an authenticated pre-integration replay. The
  offline `governance-reindex` command therefore fails closed instead of
  trusting operator-supplied JSONL. The live index begins at the earliest
  verifiable post-integration validation ceremony. Missing pre-boundary
  reputation stays unknown and is never approximated with age or validation
  flags.
- Canonical source block hashes prove that a locally persisted record refers to
  the canonical chain at those heights; on the legacy chain they do not commit
  the record's author-to-final-qualification mapping. The index now adds a
  domain-separated commitment over every ordered author/outcome record, so any
  payload difference is visible, but a modified local index can still retain
  valid block hashes. The contract therefore requires three distinct eligible
  operator attestations over the exact snapshot, replay commitment, source
  boundary, and implementation. One bad first writer cannot reserve a root,
  and two conflicting quorums fail closed. Correlated or colluding operators
  remain a trust assumption until a separately activated governance fork
  commits the counters in consensus.
- The read-only governance RPC namespace is disabled from the default HTTP
  module list and must be enabled explicitly. Its proof cache avoids rebuilding
  the full Merkle tree per request, but large snapshots still consume memory.
  Snapshots now fail closed above 262,144 eligible leaves or 65,537 replay
  anchors; these are format safety ceilings, not claims about future network
  scale.
- The experimental contract stores at most 256 stake lots and 256 finalized
  withdrawal/slash checkpoints per account. Every outstanding slashable bond
  reserves checkpoint capacity, so voluntary withdrawals cannot make a later
  slash fail. There is no reviewed compaction protocol; reaching the bound
  halts new bonds or voluntary history growth rather than discarding snapshot
  history.
- Consensus-maintained governance counters and new host functions are not
  implemented. Any such work belongs only to the disabled governance-fork
  profile.
- Source CIDs for the five legacy-pinned components are exact, but public CAR
  replication and independent availability attestations have not been run.
- The contract artifact in the fork lock is bound to a committed experimental
  prototype. It is explicitly unauthorized and not a release.
- Exact locked Rust 1.97.0 and Go 1.26.5 builds must be performed by attested
  clean-room builders. A local development build with different versions is
  non-attested and its tool versions must be reported.
- `pohw-governance-runtime-gate.py --require-locked-sources` intentionally
  fails while the fork lock is not marked `canonical-locked-source` or any
  component is dirty/revision-mismatched. The local production-runtime pass is
  not a clean-room or independent-builder attestation. Normal CI verifies that
  such a prototype remains inactive and unauthorized, then skips the release-
  grade invocation; this skip is not release evidence.
- A deterministic build-evidence generator and SBOM workflow exist and have
  local fixture coverage. No independent clean-room builder attestations,
  reviewer attestations, public evidence replication, or external security
  audit exist yet.
- Desktop renderer output can be deterministic, but signed/notarized installers
  may retain platform-specific nondeterminism and centralized signing
  constraints.
- `BuildAttestationV1` currently fails closed by requiring every builder to
  cover the candidate manifest's complete artifact inventory. This prevents
  favorable-subset attestations but cannot yet express separately verified
  per-platform artifact groups. Candidates whose full inventory cannot be
  reproduced by every required builder remain ineligible until that schema and
  gate model is implemented and audited.
- The existing desktop updater remains present for rollback. The experimental
  DAO path verifies contract-executed proposal state, canonical artifact pins,
  build roots, CIDs, SHA-256 digests, and a local anti-replay high-water mark,
  then fetches an artifact after explicit confirmation. It does not yet hand
  the artifact to a privileged installer.
- Experimental desktop release retrieval currently buffers each artifact in
  the renderer verification path and therefore rejects artifacts larger than
  512 MiB. A future privileged installer should stream to a private temporary
  file while incrementally verifying CID and SHA-256 before raising this cap.
- The desktop anti-replay sequence is local persistent state. Resetting or
  tampering with the application data directory can erase that high-water
  mark; semantic-version downgrade checks and exact contract authorization
  still apply, but durable rollback resistance ultimately needs a contract-
  committed release sequence or equivalent authenticated monotonic state.
- Dashboard proposal counters are cross-checked against read-only contract
  state before rendering, and the node now recomputes every displayed gate
  from bounded vote and attestation evidence. Diff summaries and affected-
  repository labels remain local index metadata until the desktop also decodes
  the full proposal CID.
- Canonical history is append-only and paginated at 64 entries per contract
  query. The dashboard snapshot itself remains capped at 1,024 history entries;
  archival consumers must page and persist older entries independently.
- The Rust lifecycle engine emulates WASM transaction rollback by snapshotting
  state around fallible balance, vote, settlement, and execution transitions.
  This is appropriate for tests and simulation but can be expensive at maximum
  review-round size; it is not the production contract storage engine.
- Concave square-root stake weight does not eliminate stake splitting, identity
  farming, whale coordination, bribery, collusion, or low participation.
- AI diversity labels cannot prove independent ownership. AI agents are not
  correctness oracles and cannot execute proposals. Prompt injection,
  provider compromise, and collusion remain residual risks even when the
  content-addressed review record is structurally valid.
- The lifecycle E2E uses a deterministic local content-addressed store, and the
  opt-in Docker smoke test imports the same verified CAR into two disposable
  Kubo 0.42.0 sidecars, fetches through their gateway path, re-verifies the CAR,
  and checks it out. This proves local sidecar interoperability only; it is not
  a public-swarm persistence test or an independent availability attestation.
- Visual browser automation of the Electron governance page remains limited by
  preload and live-provider dependencies. Renderer build and unit checks do not
  replace a packaged Electron smoke test.

GitHub is optional infrastructure, not canonical authority. IPFS supplies
content addressing, not governance. No lead developer, maintainer key, AI
agent, builder, staker, or identity class can bypass all four gates.
