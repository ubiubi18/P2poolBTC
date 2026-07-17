# Local Operations

These commands create a disposable local flow. They do not deploy a contract,
publish a release, push Git, or change a live canonical reference.

## Toolchains

Use Go 1.26.5, Rust 1.97.0, Node 24.18.0, npm 11.16.0, and pnpm 11.11.0 for
attested builds. Local versions that differ are suitable only for development
and must be reported as non-attested.

## Community launch interlock

The candidate contract starts dormant. Before public use, clients must query
`communityGovernanceStatus` and display all returned fields. A participant is
counted only after its current eligible identity-metrics proof is registered
and its next-epoch governance stake reaches the minimum active amount.

Expected pre-launch status:

```json
{
  "schemaVersion": 1,
  "active": false,
  "participantCount": 0,
  "participantThreshold": 100,
  "participantDefinition": "eligible-current-metrics-and-minimum-active-stake",
  "permissionlessActivation": true,
  "automaticDeployment": false,
  "activationBlock": null
}
```

Do not open reviews, create proposals, collect ballots, or claim canonical DAO
authority while `active` is false. The contract rejects those actions. After
the count reaches 100, any account may submit `activateCommunityGovernance`
with no payment. Independently verify the resulting activation event and block
before enabling proposal UI. This transaction does not deploy the contract,
publish a release, install artifacts, or bypass deployment-readiness gates.

## Package the human/AI development policy

Package the MIT policy and verify its canonical CAR before accepting review
evidence:

```sh
cargo run -p governance-cli -- development-policy-package \
  --input integrations/decentralized-aidd/policy.json \
  --output-dir /tmp/pohw-development-policy

cargo run -p governance-cli -- development-policy-inspect \
  --car /tmp/pohw-development-policy/development-policy.car
```

The expected policy CID is
`bafyreid56pzxhbjuhonxsl5b2a2jjrgrzydgyyvvyfboucqh53y7hzyare`. Bind an AI
review to the verified policy rather than trusting a provider or branch:

```sh
cargo run -p governance-cli -- review-attestation \
  --input /absolute/path/agent-review.json \
  --development-policy /tmp/pohw-development-policy/development-policy.car \
  --output-dir /tmp/agent-review
```

The policy and review CARs must be included in the public proposal pinset. None
of these commands signs, votes, publishes a release, or changes the canonical
ecosystem CID.

## Governance Day local demonstration

Build the deterministic protocol fixture first:

```sh
cargo run -p governance-cli -- demo-epoch-governance \
  --output-dir "$PWD/target/governance-day-demo"
```

Run the complete 33-step cross-repository scenario against an exact local
IdenaAI checkout. The confirmation variable allows only local patch application
for the disposable test; it does not authorize a deployment, publication,
installation, rollback, or canonical-reference update.

```sh
env POHW_CONFIRM_LOCAL_TEST_PATCH=YES \
  IDENA_AI_ROOT=/absolute/path/to/idena-ai \
  tests/governance/governance-day-e2e.sh
```

The report labels all identities, balances, votes, CIDs, and transactions as
local test data. It records a public-IPFS sidecar result separately. If Docker
is unavailable, the sidecar step is reported as not run; it is never presented
as an availability attestation. See `GOVERNANCE-DAY.md` and
`chain-liveness-recovery.md` for protocol and recovery boundaries.

## Package and inspect parameters

Governance Day uses a separate immutable parameter object:

```sh
cargo run -p governance-cli -- epoch-parameters-package \
  --input compatibility/governance-day-parameters.json \
  --output-dir /tmp/governance-day-parameters

cargo run -p governance-cli -- epoch-parameters-inspect \
  --car /tmp/governance-day-parameters/governance-day-parameters.car
```

The expected CID is
`bafyreidvih25dx6cmuwi3mpjtij3c4qfmmym2s7r2r6fvxwmgm4thzbgei`.
Treat any other CID as a different governance experiment. The local candidate
artifact inventory is
`compatibility/governance-day-local-candidate-lock.json`; it is explicitly
non-authorizing and must not be used as a deployment instruction.

The earlier per-proposal parameter package remains inspectable for migration
and regression testing:

```sh
cargo run -p governance-cli -- parameters-package \
  --input compatibility/governance-testnet-parameters-v1.json \
  --output-dir /tmp/governance-parameters

cargo run -p governance-cli -- parameters-inspect \
  --car /tmp/governance-parameters/governance-parameters.car
```

## Package source and publish to a public sidecar

Release evidence must start from an exact full Git commit object. The command
below reads Git objects directly, verifies every blob identifier, rejects
moving refs, symlinks, submodules, unsafe paths, and secret-like files, then
packages the same object set twice and requires byte-identical CAR output. It
does not read the working tree, run hooks, or apply checkout filters. Git is
only audit metadata; the resulting source CID remains the content identity.

```sh
COMMIT="$(git rev-parse HEAD)"
cargo run --locked -p governance-cli -- package-commit \
  --git-repository "$PWD" \
  --commit "$COMMIT" \
  --repository P2poolBTC \
  --output-dir /tmp/p2pool-source

export IPFS_PATH="$HOME/.ipfs-pohw-governance-public"
ipfs init
ipfs daemon

cargo run -p governance-cli -- pin \
  --car /tmp/p2pool-source/P2poolBTC.source.car \
  --store "$HOME/.local/share/pohw-governance/pins" \
  --kubo-api http://127.0.0.1:5001

cargo run -p governance-cli -- pin \
  --car /tmp/p2pool-source/P2poolBTC.source-commit-receipt.car \
  --store "$HOME/.local/share/pohw-governance/pins" \
  --kubo-api http://127.0.0.1:5001
```

Repeat `package-commit` independently for every affected repository. The
receipt binds the repository label, full commit and tree identifiers, source
CID, source digest, source-CAR digest, and file counts. Deployment readiness
requires one matching receipt per affected repository and requires all public
availability operators to retrieve each receipt. A receipt does not authorize
deployment and cannot replace independent builders reproducing the same source
CID from the exact commit.

For a draft that has not been committed, the ordinary `package --root ...`
command remains useful for review. Draft packages are not acceptable as
deployment-readiness source receipts.

Do not add generated binaries to the source tree or bypass a packaging
rejection. The IdenaAI local integration follows the same rule: its tracked
`.env.e2e` is never copied into the integration patch. The disposable harness
removes that one exact regular file by fail-closed policy before packaging and
verifies that the deterministic source CID matches the inactive integration
record.

Do not reuse the idena-go IPFS repository. Keep Kubo's control API on loopback.
External pin providers are optional and require operator-specific credentials
outside the repository.

Before opening a review round, verify that the aggregate patch exactly covers
every changed repository source and that the candidate names the verified
parent CID:

```sh
cargo run -p governance-cli -- ecosystem-verify \
  --parent-car /verified/ecosystem/parent.car \
  --candidate-car /verified/ecosystem/candidate.car \
  --patch-car /verified/ecosystem/aggregate-patch.car
```

This command rejects added, removed, omitted, unchanged, or substituted source
transitions. Per-repository patch CARs must still be checked with
`proposal-verify --base-car ... --candidate-car ... --patch-car ...`.

Run the disposable two-sidecar interoperability test when Docker is available:

```sh
POHW_RUN_KUBO_E2E=1 \
  python3 -m unittest \
  tests.test_governance_kubo_sidecar.GovernanceKuboSidecarTests.test_disposable_kubo_sidecars -v
```

It uses only generated fixtures, binds both Kubo control APIs and gateways to
host loopback, verifies structured recursive-pin responses, retrieves and
rehashes the CAR, compares checkout bytes, and removes both containers on exit.
The default image is version-pinned as `ipfs/kubo:v0.42.0`; an attested run must
also record and approve the resolved image digest.

## Generate deterministic build evidence

Validate the pinned plan first:

```sh
python3 scripts/pohw-governance-build-evidence.py validate-plan \
  --plan compatibility/governance-build-plan-v1.json
```

Run the selected target in a separate keyless clean-room worker. Enable
network access only for the first `dependencyFetchCommandCount` commands, then
enforce network denial for every remaining command. Mount verified source CAR
checkouts read-only, use the exact locked toolchains, apply process/CPU/memory
limits, redact secrets from logs, and save each complete stream as
`000.stdout.log`, `000.stderr.log`, and so on.

For the governance-contract target, the worker result record is:

```json
{
  "schemaVersion": 1,
  "target": "governance-contract",
  "sourceCids": {
    "P2poolBTC": "<candidate-p2pool-source-cid>",
    "idena-go": "<candidate-idena-go-source-cid>",
    "idena-wasm-binding": "<locked-binding-source-cid>",
    "idena-wasm": "<locked-runtime-source-cid>",
    "wasmer": "<locked-wasmer-source-cid>",
    "idena-sdk-js-lite": "<locked-sdk-source-cid>"
  },
  "cleanRoom": true,
  "readOnlySources": true,
  "networkDisabledAfterFetch": true,
  "dependencyFetchSeparated": true,
  "isolationKind": "container",
  "containerImageDigest": "sha256:<64-lowercase-hex-digest>",
  "resourceLimits": {"cpuCount": 4, "memoryBytes": 8589934592, "processes": 256},
  "redactionPolicy": "pohw-build-log-redaction-v1",
  "toolchains": {"node": "24.18.0", "pnpm": "11.11.0", "assemblyscript": "0.27.37", "go": "1.26.5"},
  "platform": "linux",
  "architecture": "amd64",
  "osFamily": "linux",
  "commands": [
    {"command": "corepack pnpm --dir contracts/idena-code-governance install --frozen-lockfile --ignore-scripts", "exitCode": 0},
    {"command": "go -C ../idena-go mod download", "exitCode": 0},
    {"command": "corepack pnpm --dir contracts/idena-code-governance build", "exitCode": 0},
    {"command": "corepack pnpm --dir contracts/idena-code-governance test", "exitCode": 0},
    {"command": "python3 scripts/pohw-governance-runtime-gate.py --idena-go ../idena-go --fork-candidate-lock compatibility/governance-day-fork-candidate-lock.json --component-repo idena-wasm-binding=../idena-wasm-binding --component-repo idena-wasm=../idena-wasm", "exitCode": 0}
  ]
}
```

With that record and the five pairs of redacted logs, generate evidence. Supply
all six exact source roots and CIDs shown by the build plan; the abbreviated
command below shows the P2poolBTC pair, and omitting the other five pairs is a
hard failure:

```sh
python3 scripts/pohw-governance-build-evidence.py generate \
  --plan compatibility/governance-build-plan-v1.json \
  --target governance-contract \
  --repository-root P2poolBTC="$PWD" \
  --repository-root idena-go=/verified/idena-go \
  --repository-root idena-wasm-binding=/verified/idena-wasm-binding \
  --repository-root idena-wasm=/verified/idena-wasm \
  --repository-root wasmer=/verified/wasmer \
  --repository-root idena-sdk-js-lite=/verified/idena-sdk-js-lite \
  --source-cid P2poolBTC=<candidate-p2pool-source-cid> \
  --source-cid idena-go=<candidate-idena-go-source-cid> \
  --source-cid idena-wasm-binding=<locked-binding-source-cid> \
  --source-cid idena-wasm=<locked-runtime-source-cid> \
  --source-cid wasmer=<locked-wasmer-source-cid> \
  --source-cid idena-sdk-js-lite=<locked-sdk-source-cid> \
  --source-car P2poolBTC=/verified/cars/P2poolBTC.car \
  --source-car idena-go=/verified/cars/idena-go.car \
  --source-car idena-wasm-binding=/verified/cars/idena-wasm-binding.car \
  --source-car idena-wasm=/verified/cars/idena-wasm.car \
  --source-car wasmer=/verified/cars/wasmer.car \
  --source-car idena-sdk-js-lite=/verified/cars/idena-sdk-js-lite.car \
  --source-verifier /verified/bin/pohw-governance \
  --source-verifier-sha256 <sha256-of-pohw-governance> \
  --artifact-exclusions idena-go="$PWD/compatibility/governance-fork-artifact-exclusions/idena-go.json" \
  --artifact-exclusions idena-wasm-binding="$PWD/compatibility/governance-fork-artifact-exclusions/idena-wasm-binding.json" \
  --artifact-exclusions idena-wasm="$PWD/compatibility/governance-fork-artifact-exclusions/idena-wasm.json" \
  --artifact-exclusions wasmer="$PWD/compatibility/governance-fork-artifact-exclusions/wasmer.json" \
  --artifact idena-code-governance.wasm="$PWD/contracts/idena-code-governance/build/idena-code-governance.wasm" \
  --result-record /protected/governance-contract-result.json \
  --logs-dir /protected/governance-contract-logs \
  --output-dir /tmp/governance-contract-evidence
```

Use the emitted raw SBOM CID as `sbomCid`, raw test-results CID as
`testResultsCid`, DAG-CBOR toolchain-locks CID as `toolchainCid`, and
`coreArtifactDigest` in the
`BuildAttestationV1` input. Map each evidence artifact's `deterministic` flag
to the attestation artifact's `core` flag without changing any other field.
The contract recomputes the complete core-set digest and also requires the
attestation inventory to exactly cover every artifact in the candidate
ecosystem manifest. `core: false` excludes an artifact from the matching-core
digest but never from the coverage check. A local evidence package is not an
independent builder attestation and does not authorize a release.

## Create and verify a proposal

First create `/absolute/path/scope-input.json`. Every path may be absolute; a
relative path is resolved from the input file's directory. The repository list
must exactly match the aggregate ecosystem patch:

```json
{
  "schemaVersion": 1,
  "parentEcosystemCar": "/verified/cars/parent-ecosystem.car",
  "candidateEcosystemCar": "/verified/cars/candidate-ecosystem.car",
  "ecosystemPatchCar": "/verified/cars/ecosystem-patch.car",
  "rationaleFile": "/verified/metadata/rationale.md",
  "migrationNotesFile": "/verified/metadata/migration-notes.md",
  "testPlanFile": "/verified/metadata/test-plan.md",
  "repositories": [
    {
      "repository": "P2poolBTC",
      "baseCar": "/verified/cars/P2poolBTC-base.car",
      "candidateCar": "/verified/cars/P2poolBTC-candidate.car",
      "patchCar": "/verified/cars/P2poolBTC-patch.car"
    }
  ]
}
```

Package and independently re-inspect the objective path, size, migration, and
risk classification evidence:

```sh
cargo run -p governance-cli -- scope-package \
  --input /absolute/path/scope-input.json \
  --output-dir /tmp/governance-scope

cargo run -p governance-cli -- scope-inspect \
  --car /tmp/governance-scope/proposal-scope.car
```

Create a strict proposal JSON matching
`schemas/governance/ChangeProposalV1.schema.json`. Its `scopeEvidenceCid`,
source CIDs, counters, and risk class must exactly match the inspected scope
CAR. Then run:

```sh
cargo run -p governance-cli -- proposal-create \
  --input /absolute/path/proposal-input.json \
  --parameters compatibility/governance-testnet-parameters-v1.json \
  --scope-car /tmp/governance-scope/proposal-scope.car \
  --output-dir /tmp/governance-proposal

cargo run -p governance-cli -- proposal-verify \
  --proposal-car /tmp/governance-proposal/proposal.car \
  --parameters compatibility/governance-testnet-parameters-v1.json \
  --scope-car /tmp/governance-scope/proposal-scope.car
```

`--scope-car` is mandatory for proposal verification. Supplying a different
scope CAR fails even when its contents are otherwise valid. The separate
per-repository patch-verification mode does not take a scope CAR because it
verifies one source transition rather than an executable proposal.

`proposal-create` also writes `proposal.dag-cbor.hex`. Submit that exact file
with the emitted proposal CID. The contract recomputes the CID from the
canonical DAG-CBOR bytes and derives every executable proposal field from the
verified payload. Do not reconstruct the payload manually or submit parallel
candidate, risk, bond, root, epoch, or deadline arguments.

Only a `migration` risk-class proposal may replace the identity-metrics root.
Such a proposal must commit both `candidateIdentityMetricsRoot` and a strictly
newer `candidateIdentityMetricsEpoch`. Normal and critical code proposals must
set both fields to `null`.

## Package attestations

```sh
cargo run -p governance-cli -- identity-metrics-snapshot-package \
  --input /protected/idena-go-identity-metrics-snapshot.json \
  --output-dir /tmp/identity-metrics-snapshot

cargo run -p governance-cli -- identity-metrics-snapshot-verify \
  --car /tmp/identity-metrics-snapshot/identity-metrics-snapshot.car

cargo run -p governance-cli -- review-attestation \
  --input /absolute/path/agent-review.json \
  --output-dir /tmp/agent-review

cargo run -p governance-cli -- build-attestation \
  --input /absolute/path/build-attestation.json \
  --output-dir /tmp/build-attestation

cargo run -p governance-cli -- identity-metrics-attestation \
  --input /absolute/path/identity-metrics-attestation.json \
  --output-dir /tmp/identity-metrics-attestation
```

The attestation inputs contain public Idena addresses and authentication, so
generate them in a protected working directory. Never put private keys or RPC
credentials in the JSON.

The payload `authentication` field is an intent marker, not proof by itself.
Use `detached-idena-signature-v1` for evidence consumed by the offline
deployment-readiness verifier. `on-chain-submitter` remains valid only inside
contract execution, where the runtime supplies the caller; receipt-shaped JSON
is not accepted as a substitute for an authenticated chain proof. Review,
build, availability, and external-audit packaging commands write a deterministic
`*.authentication-request.json`. Sign its exact
`challenge` with the declared Idena address, place the public recoverable
signature in a file, and assemble the detached envelope:

```sh
cargo run -p governance-cli -- attestation-authenticate \
  --kind build \
  --car /tmp/build-attestation/build-attestation.car \
  --signature-file /protected/build-attestation.signature \
  --output-dir /tmp/build-attestation-auth

cargo run -p governance-cli -- attestation-verify \
  --kind build \
  --car /tmp/build-attestation/build-attestation.car \
  --authentication /tmp/build-attestation-auth/build-attestation.authentication.json
```

The signature uses the existing Idena sign-in convention and covers a
domain-separated digest of the attestation kind, exact DAG-CBOR CID and
content digest, candidate ecosystem CID, and role identity. Reusing a
signature for another CAR, candidate, builder, auditor, or pin operator fails.
The signature is public; private keys must remain in the wallet.

`FinalizedOnChainAttestationReceiptV1` is reserved for a later authenticated
Idena inclusion/finality verifier. The current offline verifier rejects it even
when all JSON fields look plausible, because those fields can otherwise be
fabricated. Contract submissions remain authenticated by the actual runtime
caller.

Each packaging command writes a `*.dag-cbor.hex` file next to its CAR. Submit
the exact CID and canonical bytes together with the Merkle proof. The contract
recomputes the CID, checks the caller and attached bond against the payload,
and derives content, caller, bond, result, and artifact-digest claims from
those verified bytes. Model-family, runtime-family, architecture, provider,
and pin-operator labels are still assertions by that authenticated caller; a
canonical CID does not make those labels independently true. For this reason,
`attestationDiversityCapability()` reports `blocked-unverified-v1` in this
contract version and critical/consensus proposals fail closed. No contract
method can enable the reserved capability. A migration proposal may replace the
canonical ecosystem reference with an audited successor only through
`owner-authenticated-bootstrap-v1`: five distinct eligible review owners, three
builder owners, three availability owners, complete committed leaves, matching
artifacts, no critical finding or waiver, no build conflict, and all critical
vote/challenge/timelock gates. Query clients must check
`migrationExecutionEnabled` and `migrationMode`; neither field grants a caller
special authority.

Deployment readiness additionally requires a detached authentication envelope
for every build, availability, and external-audit CAR. Relative paths resolve
from the readiness input file:

```json
{
  "schemaVersion": 1,
  "scopeCar": "proposal-scope.car",
  "sourceCommitReceipts": [
    {
      "car": "sources/P2poolBTC.source-commit-receipt.car"
    }
  ],
  "buildAttestations": [
    {
      "car": "builder-a/build-attestation.car",
      "authentication": "builder-a/build-attestation.authentication.json"
    },
    {
      "car": "builder-b/build-attestation.car",
      "authentication": "builder-b/build-attestation.authentication.json"
    }
  ],
  "dataAvailabilityAttestations": [
    {
      "car": "pin-a/data-availability-attestation.car",
      "authentication": "pin-a/data-availability-attestation.authentication.json"
    },
    {
      "car": "pin-b/data-availability-attestation.car",
      "authentication": "pin-b/data-availability-attestation.authentication.json"
    }
  ],
  "externalAuditAttestations": [
    {
      "car": "audit-a/external-audit-attestation.car",
      "authentication": "audit-a/external-audit-attestation.authentication.json"
    }
  ],
  "migrationRehearsalAttestations": [
    {
      "car": "rehearsal-a/migration-rehearsal-attestation.car",
      "authentication": "rehearsal-a/migration-rehearsal-attestation.authentication.json"
    },
    {
      "car": "rehearsal-b/migration-rehearsal-attestation.car",
      "authentication": "rehearsal-b/migration-rehearsal-attestation.authentication.json"
    }
  ],
  "requiredAvailabilityThroughBlock": 123456
}
```

```sh
cargo run -p governance-cli -- deployment-readiness-verify \
  --input /verified/readiness/deployment-readiness.json \
  --output-dir /verified/readiness/report

cargo run -p governance-cli -- deployment-readiness-evidence-verify \
  --car /verified/readiness/report/deployment-readiness-evidence.car
```

The verifier reconstructs every canonical content CID and authentication
binding offline. A self-declared identity, the legacy intent marker alone, or
an envelope copied from another attestation contributes zero to independence
thresholds; the builder, availability, and audit thresholds are unchanged.
Every affected repository needs one exact source-commit receipt. Migration and
consensus scopes additionally need two matching, Idena-authenticated deployed
rehearsal attestations from distinct operators on two platform families. A
normal or critical application proposal may omit `migrationRehearsalAttestations`.
The output directory contains `deployment-readiness-report.car` and
`deployment-readiness-evidence.car`, with CID and SHA-256 sidecars for each.
The report commits to the evidence-bundle CID. The second command replays the
actual canonical scope and authenticated attestation packages from that bundle
and recomputes the complete report; a report containing only favorable copied
counts is therefore insufficient. A production launch policy must bind both
CARs, and its service interlock must compare the recomputed report byte for byte
with the policy-bound report.

Create deployed rehearsal evidence only after actually exercising the exact
candidate on the named isolated public testnet. Each operator must observe an
accepted parent-to-candidate execution followed by a governed candidate-to-
parent rollback, publish redacted state/event/command/compatibility evidence,
and sign the generated public challenge independently:

```sh
cargo run --locked -p governance-cli -- migration-rehearsal-attestation \
  --input /protected/rehearsal/operator-a.json \
  --derive-rehearsal-digest \
  --output-dir /verified/rehearsal-a

cargo run --locked -p governance-cli -- attestation-authenticate \
  --kind migration-rehearsal \
  --car /verified/rehearsal-a/migration-rehearsal-attestation.car \
  --signature-file /protected/rehearsal/operator-a.signature \
  --output-dir /verified/rehearsal-a
```

The two attestations must agree on the deterministic transition digest while
retaining their own operator identity, runtime, architecture, command-log CID,
and compatibility-report CIDs. Signatures corroborate who made each claim;
they do not by themselves prove independent infrastructure or chain truth.

Three distinct eligible operator identities must submit matching canonical
`IdentityMetricsAttestationV1` objects before a metrics root/epoch can be used.
The object binds the snapshot CID and SHA-256, source boundary and block,
domain-separated replay commitment, indexer implementation CID, and operator.
One early bad descriptor cannot reserve the root. Two conflicting descriptors
that each reach quorum mark the certification conflicted and unusable.
The snapshot packaging command rejects unknown fields, reordered or duplicate
leaves, ineligible states, wrong trust math, boundary drift, noncanonical
hashes, and a Merkle root that does not recompute from the exact idena-go JSON.

Review evidence is collected before proposal creation. An eligible opener locks
the review bond for one exact parent/candidate/patch tuple. Any eligible agent,
builder, or availability operator may submit bonded evidence before the review
deadline. Anyone may freeze the round; freezing derives sorted, count-bound
roots from every registered CID. Proposal creation must claim that exact frozen
round. Every committed leaf is then resubmitted with its proof before
`openVoting`, so a proposal cannot hide a registered negative review, failed
build, or unavailable pin behind a favorable subset. Each evidence class is
bounded to 256 leaves.

`testResultsCid` and `probeResultCid` refer to exact raw evidence bytes in the
Rust lifecycle and WASM contract. Their raw CIDs are recomputed before an
objective false-claim challenge is accepted. The WASM vertical slice accepts
only the exact canonical byte strings `{"passed":false}` and
`{"available":false}`; arbitrary JSON, gateway timeouts, and subjective review
disagreements are not slashable evidence.

## Contract actions

The exact RPC transaction envelope depends on the pinned Idena client. The
desktop experimental UI estimates first and submits only after a second user
confirmation. In order, call the contract methods:

```text
registerGovernanceStake()                 attached IDNA; activates next epoch
activateGovernanceStake()
registerIdentityMetricsProof(...)
submitIdentityMetricsAttestation(attestationCid,
  attestationDagCborHex)                  no attached payment
identityMetricsCertification(root, epoch)
openReviewRound(parentCid, parentDagCborHex,
  candidateCid, candidateDagCborHex,
  patchCid, patchDagCborHex,
  pinsetCid, pinsetDagCborHex)
                                          exact attached proposal bond
submitAgentAttestation(reviewRoundId, attestationCid,
  attestationDagCborHex)                  exact attached reviewer bond
submitBuildAttestation(reviewRoundId, attestationCid,
  attestationDagCborHex, toolchainDagCborHex)
                                          exact attached builder bond
submitDataAvailabilityAttestation(reviewRoundId, attestationCid,
  attestationDagCborHex)                  exact attached availability bond
freezeReviewRound(reviewRoundId)          callable by anyone after review end
createProposal(proposalCid, proposalDagCborHex)
                                          no attached payment; claims frozen round
submitProposalMetadataRoot(...)
openVoting(proposalId)
castVote(proposalId, yes|no|abstain)
finalizeVoting(proposalId)
submitObjectiveChallenge(proposalId, kind, attestationCid,
  attestationDagCborHex, evidenceCid, evidenceHex,
  index, leafCount, siblings)
                                          kind is agent_test_result,
                                          builder_test_result, or
                                          availability_probe
resolveObjectiveChallenge(proposalId)
advanceChallengePeriod(proposalId)
executeProposal(proposalId)               callable by anyone after timelock
```

`openReviewRound` recomputes all four DAG-CBOR CIDs and binds the candidate's
complete repository source set, artifact set, and toolchain maps to the round.
The pinset must contain the candidate, patch, parameter set, every candidate
source tree, every candidate artifact, every repository patch, and every
proposal metadata CID. Each build attestation must repeat the complete source
and candidate artifact sets and provide the exact candidate-derived toolchain
manifest. Agent and build
submissions dynamically extend the required availability set with their own
attestation and referenced policy, result, finding, SBOM, toolchain, and
artifact CIDs. At freeze, an availability attestation counts only if it covers
that complete final set plus its own probe-result CID. Providers should submit
after agent and build evidence has settled, or resubmit against the expanded
set. Distinct provider IDs and distinct eligible owners are required.

The stake snapshot is proposal-specific. Governance weight scheduled for an
epoch is settled globally when proposal creation reaches that epoch, so a
holder cannot be omitted merely by declining to call
`activateGovernanceStake()`. That method only materializes the holder's pending
balance for withdrawals and queries. Finalized withdrawals append an
immutable checkpoint and do not rewrite historical lots, so withdrawing for a
later epoch cannot change an already-open proposal's vote weight. This
experimental contract currently caps each account's stake history at 256 lots
and 256 finalized-withdrawal/slash checkpoints. Each outstanding slashable bond
reserves one checkpoint slot; operators must treat either limit as a hard
preflight constraint.

Stake and registered identity-weight changes in the proposal's creation block
are excluded. Proposal creation requires a block whose global registered weight
has not already changed, and voter metrics proofs must have been registered in
an earlier block. This makes the creation-block snapshot deterministic rather
than transaction-order dependent.

Execution changes only the canonical ecosystem CID. It does not write files or
install software.

For release verification, the desktop requires the release proposal to be in
`Executed` state, with the contract's candidate CID and build-attestation root
matching the release. Every downloadable artifact must also be pinned exactly
by the accepted ecosystem manifest. A locally indexed proposal summary is not
release authorization.

## Resolve and check out canonical source

Query `canonicalEcosystemCid()`, retrieve its verified ecosystem CAR through
the public sidecar or multiple gateways, then retrieve each repository CAR.

```sh
cargo run -p governance-cli -- fetch \
  --cid <repository-source-cid> \
  --gateway https://ipfs.io,https://dweb.link \
  --output-dir /tmp/canonical-source

cargo run -p governance-cli -- checkout \
  --car /tmp/canonical-source/<repository-source-cid>.car \
  --output /tmp/canonical-checkout
```

`pin` and `fetch` accept any governance CAR, not only repository source CARs.
They rehash every block and verify the declared root before writing or
importing it. `checkout` remains source-tree specific and must not be used for
proposal, attestation, parameter, or release objects.

## Governance metrics RPC opt-in

The read-only `governance` RPC namespace is disabled from the default HTTP
module list. Explicitly add `governance` to the node's configured HTTP modules
only on an authenticated or otherwise access-controlled endpoint. The live
node records exact finalized authored-flip outcomes beginning at its earliest
verifiable integration boundary and includes eligible zero-history identities
using the deterministic prior.

Even a new empty metrics runtime rejects records and proofs until node startup
explicitly supplies the canonical block-hash view. A persisted snapshot is a
derived cache: it is never exposed on startup, and a valid index plus stale
snapshot (for example after a crash between atomic file renames) is rebuilt
after canonical-history verification and authoritative current-state refresh.
Malformed or unsafe files remain fatal.

The `governance-reindex` command deliberately rejects external JSONL input.
Current legacy chain data does not independently commit enough author-to-final-
qualification history to authenticate such an export. On startup, persisted
record heights and block hashes are checked against the canonical local chain,
and the current identity-state snapshot is anchored to the current canonical
head. Those checks detect reorgs and stale snapshots, but legacy block hashes do
not authenticate the locally observed author/outcome payload. Require matching
snapshots and attestations from independent indexers before a DAO migration
uses a root. Do not approximate the missing interval with identity age,
`LastValidationFlags`, or an operator-supplied file.

## Cross-repository lock gate

From `idena-compat-stack`, run `scripts/verify-ecosystem-lock.py` with
`--require-external-files` as documented in that repository. A successful lock
check does not replace source replay, public availability, independent builds,
or security review.
