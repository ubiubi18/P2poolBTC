# Voting Math

All arithmetic is unsigned integer arithmetic. Floating point is forbidden.
The shared vectors are in `tests/governance/voting-vectors-v1.json` and must
match Rust, AssemblyScript, Go, and JavaScript byte for byte.

## Eligibility

Only `Human`, `Verified`, and `Newbie` are eligible. Their bounded status
multipliers are 10000, 8500, and 7000 basis points respectively, preserving
`Human > Verified > Newbie`. Candidate, Invite, Suspended, Zombie, Killed, an
unknown state, or a missing proof has zero eligible weight.

Identity age, birthday, generation, completed epochs, creation date, inviter
age, first-validation time, previous votes, developer seniority, repository
ownership, and GitHub status are not inputs. Tests hold every input constant
and change only age-related metadata; the result must remain identical.

## Authored-flip trust

`n` is the number of flips authored by the identity that entered a finalized
validation ceremony. `r` is the subset whose final consensus qualification was
`GradeReported`. An individual clicking Report is not counted. Unfinalized or
rejected reports, reports made about another author's flip, and
`AtLeastOneFlipReported` are not exact counters and are not used.

```text
0 <= r <= n
PRIOR_REPORTED = 1
PRIOR_TOTAL = 20

reported_rate_bps = floor((r + 1) * 10000 / (n + 20))
flip_trust_bps = clamp(
  4000,
  10000,
  10000 - floor(15000 * reported_rate_bps / 10000)
)
```

More final consensus-reported authored flips cannot increase trust. Adding a
non-reported finalized authored flip cannot decrease trust. Zero history is
deterministic. Larger samples change the smoothing confidence, but there is no
reward for being old or merely having many flips.

## Sublinear stake

Idena uses `10^18` atomic units per IDNA. The Go implementation returns
`common.DnaBase`, and its tests require the decimal value to equal the shared
constant. Stake means IDNA deposited in the governance contract, not wallet
balance or ordinary identity stake.

```text
STAKE_QUANTUM_ATOMS = 10^12
stake_quanta = floor(active_stake_atoms / STAKE_QUANTUM_ATOMS)
stake_score = integer_sqrt(stake_quanta)

effective_vote_weight = floor(
  stake_score * identity_status_bps * flip_trust_bps / 100000000
)
```

There is no linear stake term and no flat one-vote-per-identity political
weight. Deposits activate in the next governance epoch. Proposal snapshots fix
the stake epoch and metrics epoch. Later deposits cannot vote. Scheduled
withdrawals remain locked and slashable until the unbonding delay completes.

## Acceptance gates

PoS turnout is `(yes + no + abstain) / registered_snapshot_weight`. Approval is
`yes / (yes + no)`; a zero decisive denominator fails. Normal proposals need
20 percent turnout and 66.67 percent approval. Critical, consensus, and
migration proposals need 30 percent turnout and 75 percent approval.

PoHW is a separate breadth gate. Normal proposals need seven distinct yes
identities, at least three Verified or Human. Critical proposals need twelve,
at least five Verified or Human. Breadth does not replace weighted voting.

PoAW and proof-of-verification-work are independent gates. Normal proposals
need 3 reviews, 2 owner-bound runtime groups, 2 model-family claims, and 2
eligible owners, plus 2 builders. Critical proposals need 5 reviews, 3 owner
groups, 3 model-family claims, and 3 owners, plus 3 builders on at least 2
platform families. One owner can submit at most two reviews and can contribute
only one qualifying model-family claim per round. Normal availability requires
2 independent providers; critical availability requires 3.

PoS alone, PoHW alone, AI alone, or build workers alone cannot accept a
proposal. Every required gate must pass.

## Residual splitting risk

Square-root weighting is concave per identity. Dividing capital among several
eligible identities can increase aggregate weight. Eligibility, minimum active
stake, delayed activation, unbonding, authored-flip trust, breadth, and
objective slashing raise the cost, but do not eliminate stake splitting or
identity farming. The simulator reports this tradeoff instead of claiming a
Sybil-proof result.
