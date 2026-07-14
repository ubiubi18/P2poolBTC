# Bonds And Slashing

Balances for governance stake, proposal bonds, AI reviewer bonds, builder
bonds, and data-availability bonds are separate. Losing a vote is never
slashable. A committee cannot declare a subjective slash.

## Proposal settlement

The provisional testnet policy is deterministic:

| Outcome | Settlement |
| --- | --- |
| Executed | Return 100 percent of proposal bond |
| Normally rejected | Return 90 percent; burn 10 percent anti-spam fee |
| Stale parent | Return bond minus fixed `0.1 IDNA` processing fee |
| Expired without required artifacts | Return 75 percent; slash 25 percent |
| Proven fraudulent proposal | Slash 50 percent under the current parameter set |

The minimum proposal bond is 10 IDNA. Reviewer, builder, and availability bonds
are each at least 1 IDNA. These are provisional local/testnet values, not an
economic-security claim.

## Objective violations

The deterministic policy permits slashing only when contract state and a
content-addressed challenge payload prove an implemented condition. The WASM
vertical slice currently implements these objective conditions:

- an AI attestation claims tests passed while its own raw `testResultsCid`
  resolves to exactly `{"passed":false}`;
- a builder attestation makes the same false test claim;
- an availability attestation claims availability while its own raw
  `probeResultCid` resolves to exactly `{"available":false}`.

Wrong source bindings, forged caller ownership, duplicate identity claims,
digest conflicts, malformed payloads, and incomplete committed sets fail before
voting opens. They are rejected, but are not post-vote slashing predicates in
this vertical slice. A future violation type must define exact bounded bytes,
CID binding, deadlines, and settlement before it can slash anyone.

Successful raw-result challenges burn 100 percent of a targeted reviewer or
builder bond, or 50 percent of a targeted availability bond, plus 50 percent
of the proposer bond. They also burn 5 percent of active governance stake for
each distinct proposer/offender identity. If both roles use the same identity,
the stake slash is applied once. Checked integer arithmetic and exact
basis-point division are required.

Each outstanding slashable bond reserves an immutable stake-history checkpoint
slot. Objective settlement consumes the reservation; ordinary bond withdrawal
releases it. A scheduled withdrawal is capped to the post-slash active balance,
so stake remains slashable throughout unbonding without trapping the remainder.

An ordinary live outage is not, by itself, a trustless proof. The WASM contract
cannot query IPFS, and absence from a gateway is not proof of global absence.
The prototype therefore does not slash a provider merely because one caller
reports a timeout. This limitation prevents subjective slashing abuse.

Refund and withdrawal records are effects-first and single-use. Replayed
withdrawals, re-execution, and claims against a slashed bond fail closed.
