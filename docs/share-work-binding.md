# Share-Work Binding Successor

Status: implemented candidate, intentionally inactive. It is not permission to
start or join a public mining network.

## Problem

An Experiment 1 share proves the double-SHA256 work of its Bitcoin header. In
the original share format, that header did not commit to the selected
sharechain parent, Idena anchor, identity snapshot, or assigned pool target. A
registered miner could therefore grind cheap headers offline and later attach
them to a more favorable parent or anchor before signing and publishing the
share.

An Idena miner registration gives a public lower-bound registration time. It
does not, by itself, prove when a Bitcoin header was created or which
sharechain state that work originally extended.

## Candidate Protocol

`ShareWorkBindingV1` commits to all of the following before hashing begins:

- the immutable binding-policy hash;
- miner ID and assigned share target;
- parent share hash;
- Idena snapshot ID and proof root;
- finalized Idena block height and hash; and
- the complete Idena anchor-policy hash.

The tagged commitment is placed in exactly one coinbase `OP_RETURN` output as
`P2SW1 || SHA256(tag || 0x00 || canonical_payload)`. The share carries the exact
canonical coinbase transaction and its Merkle branch. Every accepting node:

1. recomputes the policy and share-work commitment;
2. verifies that the coinbase has exactly one `P2SW1` output and that it matches;
3. recomputes the coinbase transaction ID and Merkle root;
4. verifies that root against the submitted Bitcoin header;
5. verifies the share fields, assigned template target, and mining signature;
6. verifies the current parent and finalized Idena anchor; and
7. applies the same checks during local replay, peer admission, and recovery.

Changing the parent, target, snapshot, anchor, policy, coinbase, or Merkle proof
after work was found invalidates the proof. Ordinary pool shares still need to
meet only the assigned pool target; only block publication requires the harder
Bitcoin block target.

## Activation Boundary

The candidate is pinned by:

- `compatibility/experiment-1-share-work-successor-candidate.json`
- `compatibility/experiment-1-share-work-binding-policy-v1.json`

It uses a distinct sharechain network ID, requires a fresh datadir, requires
bindings from the first share, and explicitly sets `history_reinterpreted` to
`false`. Existing Experiment 1 shares remain historical data and are not made
valid under the successor rules.

Verify the candidate from source:

```sh
cargo run --locked -p p2pool-node -- inspect-share-work-activation \
  --activation-manifest compatibility/experiment-1-share-work-successor-candidate.json \
  --binding-policy compatibility/experiment-1-share-work-binding-policy-v1.json
```

The output must say `experimental-candidate` and `launch_enabled: false`. The
following command must fail closed:

```sh
cargo run --locked -p p2pool-node -- inspect-share-work-activation \
  --activation-manifest compatibility/experiment-1-share-work-successor-candidate.json \
  --binding-policy compatibility/experiment-1-share-work-binding-policy-v1.json \
  --require-launchable
```

Activation requires a separately reviewed `experimental-active` manifest. Its
status and launch flag are part of the canonical activation hash, so editing
the candidate in place cannot open it. The active profile must have a matching
policy, a new activation ID, independent build and audit evidence, and a fresh
sharechain datadir.

## Remaining Boundary

This protocol is enforced by P2Pool mining, replay, and gossip code. The
Bitcoin Core fork validates the resulting Bitcoin block, but it does not yet
require an eligible Idena identity or the `P2SW1` output as a Bitcoin consensus
rule. A bypass node can still construct a Bitcoin-valid fork block outside the
P2Pool services. Consequently this candidate fixes retrospective share-work
assignment but does not clear the public-join interlock described in the main
README.

The coinbase proof is bounded to keep a complete signed gossip envelope below
the persistence limit. All policy files are strict JSON, network-bound,
immutable once written to a datadir, and revalidated during replay.
