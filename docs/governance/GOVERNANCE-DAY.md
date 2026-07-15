# Governance Day

Governance Day is one shared, deterministic governance event per Idena epoch.
IdenaAI is the primary user interface, while manual inspection remains
available. AI agents summarize and review; only the user prepares, confirms,
commits, and reveals a ballot.

This implementation is experimental local-test software. It does not deploy a
contract, publish a release, install code, or change a live canonical CID.
The exact local parameter set is
`bafyreidyq6bfhdf4xejx2s46t7vwwxwtnctqc4dh3wqvrrbyhzunu45afq`; proposals,
the contract, the node API, and decision records reject any other parameter
CID.

## Schedule

Each epoch has one immutable schedule:

1. proposal submission window;
2. proposal cutoff;
3. frozen proposal set;
4. review and discussion window;
5. ballot commit window;
6. ballot reveal window;
7. deterministic result finalization;
8. grace and challenge period;
9. execution eligibility; and
10. optional observation and revert window.

The proposal set is sorted deterministically and frozen once. Proposals cannot
be inserted or reordered during voting. A proposal submitted after cutoff fails
clearly and does not consume the current epoch slot. The current WASM prototype
exposes this state machine, but its epoch anchor is not yet authenticated to the
finalized Idena validation boundary. The first caller can currently choose the
anchor. That is a deployment blocker, not a configurable operator privilege.

## Proposal Slot

An authenticated eligible caller can create at most one on-chain proposal in
an epoch. Local drafts are unlimited. Successful creation consumes the slot
atomically; cancellation, withdrawal, rejection, no quorum, expiration, or a
later revert does not restore it. A malformed transaction that rolls back
before proposal creation does not consume it. A new slot becomes available in
the next governance epoch, and identities have independent slots.

The immutable proposal envelope also carries declared changed-file, patch,
source-package, description, migration-operation, and affected-repository
counts. Critical limits are 16 repositories, 1,024 files, 16 MiB patch data,
1 GiB source packages, 64 KiB description data, and 64 migration operations.
The WASM contract rejects an envelope above those bounds before consuming the
slot. These counters are CID-bound and independently reviewable, but the pinned
host cannot fetch every referenced IPFS block to recompute them on-chain. They
remain attested claims until a bounded proof format is implemented.

## Epoch Ballot

One ballot covers every proposal in the exact frozen order. Choices are `yes`,
`no`, or `abstain`. Missing, duplicate, reordered, unknown, or extra proposal
choices are rejected. The commitment binds the governance epoch, proposal-set
root, voter, complete ordered choices, and a user-held reveal secret. A missed
reveal contributes no vote.

The client stores only a `LocalEpochBallotDraftV1` until the user explicitly
confirms a commit preparation. An AI recommendation is always labeled and
never becomes a vote. Reveal also requires explicit confirmation.

## Voting Power

Voting uses active stake snapshotted before Governance Day. Deposits activate
in the next governance epoch and cannot be flash-deposited for an existing
ballot. There is no flat one-identity vote and no linear stake term:

```text
stake_quanta = floor(active_stake_atoms / 10^12)
stake_score = integer_sqrt(stake_quanta)
effective_vote_weight = floor(
  stake_score * identity_status_bps * flip_trust_bps / 100000000
)
```

The eligible status multipliers are Human `10000`, Verified `8500`, and Newbie
`7000` basis points. Identity age, birthday, generation, account age, and past
voting activity are ignored. Authored-flip trust is:

```text
reported_rate_bps = floor((r + 1) * 10000 / (n + 20))
flip_trust_bps = clamp(4000, 10000,
  10000 - floor(15000 * reported_rate_bps / 10000))
```

Only finalized consensus `GradeReported` outcomes for the identity's authored
flips count as `r`; individual report clicks do not. Concave per-identity stake
weighting reduces whale dominance but increases stake-splitting incentives. It
does not eliminate identity farming.

## Result, Bonds, and Grace

Weighted turnout and yes thresholds are independent from distinct-identity
breadth, AI-review, build-verification, and data-availability gates. Every
required gate must pass. No quorum keeps the proposal slot consumed and follows
the configured no-quorum refund. A valid rejection applies the configured
refund, burn, and treasury split. Accepted bonds become claimable only under
the deterministic settlement rules.

The current contract permits only critical-class proposals and therefore
requires a 25 IDNA proposal bond. A review round may be opened with the lower
normal minimum, but critical proposal creation fails unless the frozen round
holds the full critical bond. Data-availability attestations must remain valid
through finalization, the risk-specific grace period, and the complete
execution window; delayed finalization rechecks that horizon and expires stale
evidence.

Passing proposals enter grace. They cannot execute early. Objective challenges
block execution until deterministically resolved. After grace and all gates,
any caller may execute. Execution appends old and new CIDs to canonical history;
it does not automatically install or activate software.
Canonical history is queried in deterministic pages of at most 64 entries;
older entries remain immutable and addressable.

The contract currently rejects `normal` risk proposals because no objective,
contract-verifiable risk classifier is finalized. This fail-closed restriction
is the second deployment blocker. It must not be replaced by a maintainer flag.

## AI-First User Flow

The IdenaAI Governance Day card loads the frozen set, generates a clearly
labeled `EpochGovernanceBriefV1`, guides the user through every proposal, and
offers **Review with idena.AI**, **Inspect manually**, **Join discussion**,
**Run another agent**, and **Add optional manual review**. Source facts, test
evidence, AI findings, discussion claims, and user notes remain distinct.

Local and hosted providers use one modular agent interface. Hosted context
disclosure requires confirmation. Repository content is hostile input and
workers must remain keyless, isolated, resource-limited, logged, and offline by
default. Duplicate identities do not satisfy independent-agent diversity.

## Local Demonstration

```sh
cargo run -p governance-cli -- demo-epoch-governance \
  --output-dir "$PWD/target/governance-day-demo"

env POHW_CONFIRM_LOCAL_TEST_PATCH=YES \
  IDENA_AI_ROOT=/absolute/path/to/idena-ai \
  tests/governance/governance-day-e2e.sh
```

The second command applies the checked integration patch only to a disposable
archive of the exact IdenaAI base, verifies its deterministic source CID, runs
the 33-step no-value scenario, and records whether the optional public-IPFS
sidecar was available. It performs no deployment, release publication, Git
push, automatic installation, or automatic rollback.
