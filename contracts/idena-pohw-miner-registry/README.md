# Idena PoHW Miner Registry

Experimental, ownerless Idena WASM contract for timestamping PoHW miner
registrations, later key/configuration rotations, and quorum-finalized
sharechain checkpoints.

The deployer sets three immutable values during deployment: the experiment ID,
the canonical ecosystem CID, and the minimum registration burn. The contract
stores no owner or administrator and exposes no method that can replace those
values. Any valid Idena caller may register one globally unique miner ID.

Each registration stores an append-only canonical record:

```text
1|miner_id|registration_commitment|sequence|Idena_block|Idena_epoch|Idena_timestamp
```

Storage keys are `miner:<caller-without-0x>:<sequence>`. P2Pool nodes recompute
the commitment from the miner ID, Idena address, Bitcoin payout script, claim
key, mining key, and experiment ID, then read the record through a fully synced
local Idena node using `contract_readData`. The contract never receives payout
scripts or mining keys.

Registered miners may vote on the next checkpoint round. A candidate finalizes
at `ceil(2 * registered_miners / 3)` support, no administrator can finalize or
replace it, votes may converge before finalization, and rounds must be at least
six Idena blocks apart. The finalized append-only record is:

```text
1|round|share_tip|share_height|cumulative_score|parent_tip|Idena_block|Idena_epoch|Idena_timestamp|support_count|registered_count|registered_miners_csv|supporters_csv
```

The experimental contract caps registrations at 48, above Experiment 1's
planned 30 participants, so complete voter sets fit in bounded contract state
and can be rechecked by every P2Pool node.

This is a public timestamp and identity-ownership anchor, not a complete
anti-withholding mechanism. The activated sharechain policy must also require
fresh finalized Idena block anchors, one cheap-bootstrap share per miner/anchor,
strictly increasing anchors on cheap-bootstrap branches, and the exact policy
commitment in every version-3 work template. `max_anchor_age_blocks` bounds live
admission. Historical replay deliberately accepts older finalized anchors.
Finalized checkpoint rounds now constrain fork choice: a branch that does not
descend from the newest accepted checkpoint remains auditable but cannot become
active or receive payouts. A miner can still withhold work between checkpoints,
so the interval is a bounded exposure window rather than proof of instant
publication.

The contract records the Idena caller but does not synchronously query identity
state. The pinned host exposes identity lookup through an asynchronous promise
ABI. P2Pool nodes therefore query `dna_identity` through their own local Idena
RPC and allow new live work only for Newbie, Verified, or Human identities.
Historical replay skips the current-state check so a later status change cannot
invalidate old accepted history.

Because the legacy-compatible WASM identity lookup is asynchronous, the
contract cannot synchronously exclude an ineligible account during
`registerMiner`. The checkpoint record therefore publishes both the complete
registered set and supporter set; P2Pool nodes require matching anchored
registrations and current eligibility for live supporters. An attacker willing
to burn registrations can still cause checkpoint denial of service. This
residual must be resolved before raising the participant cap or treating the
protocol as production-ready.

No contract has been deployed by this source change. Deployment creates
permanent public state, burns real IDNA, and requires a separate explicit
operator confirmation.

```sh
corepack pnpm --dir contracts/idena-pohw-miner-registry install --frozen-lockfile
corepack pnpm --dir contracts/idena-pohw-miner-registry build
corepack pnpm --dir contracts/idena-pohw-miner-registry test
```

See [the activation and onboarding runbook](../../docs/idena-miner-registry.md).
