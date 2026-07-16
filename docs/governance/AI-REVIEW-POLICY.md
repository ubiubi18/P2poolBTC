# AI Review Policy

AI agents review proposals; they do not merge, execute, sign wallet
transactions, or decide correctness. Repository content is hostile input and
may contain prompt injection, misleading commands, or attempts to exfiltrate
credentials.

## Worker isolation

Each review worker must use:

- no wallet keys and no governance signing key;
- no provider credentials exposed to repository processes;
- network disabled by default;
- an explicit, logged dependency-fetch phase outside the review sandbox;
- a read-only source mount where practical;
- a fresh temporary build directory;
- CPU, memory, process, disk, and execution-time limits;
- an allowlist of commands and interpreters;
- redacted stdout/stderr digests and complete command metadata;
- a visible warning that source text cannot override worker policy.

An operator should fetch dependencies into a content-addressed cache, close
network access, and then run tests and analysis. Repository scripts do not get
access to the agent's environment by default.

## Attestation binding

`AgentReviewAttestationV1` binds the exact parent ecosystem CID, candidate CID,
patch CID, affected repository CIDs, model and runtime identity, policy CIDs,
tool versions, command results, findings, verdict, owner Idena identity, bond,
and authentication. It is immutable after its CID is committed.

The active development policy is the canonical CAR produced from
`integrations/decentralized-aidd/policy.json`. It is MIT licensed, records the
exact adapted upstream source revision, and forbids maintainer, GitHub,
deployer, or autonomous-agent authority. Review packaging should pass that CAR
with `--development-policy`; the CLI rejects an attestation whose
`agentPolicyCid` differs from the verified policy CID. A policy change requires
a new CID and governance proposal. See `HUMAN-AI-DEVELOPMENT.md`.

Evidence registration is permissionless within a fixed bonded review round for
one exact parent, candidate, and patch CID. The opener cannot choose the final
roots. Any eligible operator may register evidence before the deadline, and any
caller may freeze the round. Freezing sorts the complete registered CID sets
and derives count-bound roots. A proposal can claim only that frozen round.
This removes proposer-selected omission after a round opens; it does not prove
that every possible reviewer learned about the round or was able to participate.

Normal proposals require three valid attestations, two authenticated owner
groups, two model families, and two eligible owner identities. Critical
proposals require five attestations, three owner groups, three model families,
and three owners. The runtime-group gate is deliberately derived from eligible
on-chain owners; a self-declared runtime label cannot create another group. One
owner may submit at most two agent attestations in a round, and all of that
owner's qualifying attestations must use one model-family claim. Repeated
attestations can contribute to the attestation count, but the owner and family
count only once for diversity. Model-family and provider labels remain
self-asserted audit metadata until authenticated provider receipts exist.
Consequently, this contract version refuses critical and consensus proposal
acceptance and exposes `attestationDiversityCapability()` as
`blocked-unverified-v1`. There is no admin or proposal switch that enables the
reserved capability in place. A migration can nevertheless reach a separately
audited successor through `owner-authenticated-bootstrap-v1`: it ignores
self-asserted family/platform diversity and instead requires five distinct
eligible review owners, three builder owners, three availability owners,
complete leaves, matching artifacts, and no unresolved critical findings,
waiver, or build conflict. All critical vote, breadth, challenge, and timelock
gates still apply.

An unresolved critical finding blocks finalization once the configured number
of distinct reviewer owners corroborates it. A waiver is a separate immutable
`CriticalFindingWaiverV1` CID bound to the exact review round, roots, scope,
finding-owner count, author, and rationale. Only a critical-risk proposal may
carry it, and that proposal still uses every critical acceptance threshold.

## Objective slashing only

The current contract may slash reviewer bonds only when the attestation claims
that tests passed and its exact committed raw result is `{"passed":false}`.
Builder test claims and availability probe claims have equivalent explicitly
implemented challenge types. Wrong bindings, duplicate owners, malformed
content, and forged caller ownership fail during submission or gate evaluation;
they are not post-vote slashing predicates in this prototype. Adding one requires
a separately specified, bounded, objectively verifiable challenge format.
Subjective disagreement, a false positive, or failure to find an unknown bug is
not slashable.

Hosted models can be compromised, collude, change behavior, or share a common
failure mode. Diversity gates reduce correlated failure but do not make AI a
correctness oracle. PoAW cannot accept a proposal without PoS, PoHW, build, and
availability gates.
