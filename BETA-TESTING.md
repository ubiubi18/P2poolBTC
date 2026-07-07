# Beta Testing P2poolBTC

P2poolBTC is looking for careful early testers who want to help check whether a Bitcoin pool can use Idena human-work accounting without a central operator.

You are not mining real BTC in this test. You are helping prove that independent nodes can see the same registrations, snapshots, sharechain messages, and payout accounting.

## Who Can Help

You can join at different levels. Stop at the role that fits your machine and time.

| Role | Good For | You Run |
| --- | --- | --- |
| Observer | People who want to understand the flow first | Dashboard demo and docs |
| Gossip tester | People who can run a Rust binary and connect to peers | P2Pool node, gossip mesh, report bundle |
| Idena tester | People with an Idena node or identity | Gossip tester plus local Idena snapshot vote |
| Bitcoin tester | People with Bitcoin Core synced far enough for the agreed fork point | Work-template and fork-activation validation |

You do not need to be an Idena expert to start. The dashboard and report tools should make it clear what is local, what is synced, and what is still missing.

## What You Are Testing

- Can several independent nodes exchange signed messages?
- Do those nodes replay the same sharechain state?
- Can testers prove an Idena identity owns a pool pledge without sharing private keys?
- Can local Idena snapshots become a verifiable human-work score?
- Can payout estimates be checked locally instead of trusted from a central website?
- Can report bundles be shared without leaking keys, tokens, cookies, hostnames, or local paths?

## Safety Promise

Experiment 0 is deliberately no-value:

- no real BTC payouts,
- no user BTC deposits,
- no tradable token,
- no bridge,
- no claim market,
- no promise that test data survives.

Never share private keys, seed phrases, Idena API keys, Bitcoin RPC cookies, dashboard tokens, raw logs, or `.pohw-experiment.env`.

## Fastest First Look

Run the dashboard in demo mode:

```sh
pnpm --dir ui/pohw-dashboard install
VITE_POHW_DASHBOARD_DEMO=true pnpm --dir ui/pohw-dashboard dev
```

Open `http://127.0.0.1:5176/`.

This shows the user journey and reward math with sample data only. It is for orientation, not verification.

## First Real Test Run

Ask the experiment coordinator for:

- the agreed git commit,
- `POHW_FORK_LAUNCH_TIMESTAMP_UTC`,
- two or more peer addresses if available,
- whether this round expects Idena snapshots, Bitcoin fork activation, or only gossip/report testing.

Then run:

```sh
cargo build --release -p p2pool-node

scripts/pohw-experiment-init.sh \
  --miner-id <your-name> \
  --bind-addr <node-lan-ip>:40406 \
  --advertise-addr <node-lan-ip>:40406 \
  --peer-addrs <peer-a-lan-ip>:40406,<peer-b-lan-ip>:40406 \
  --register-peers
```

Open `.pohw-experiment.env`, set:

```sh
POHW_EXPERIMENT_NO_VALUE_ACK=I_UNDERSTAND_NO_VALUE
POHW_FORK_LAUNCH_TIMESTAMP_UTC=<agreed-timestamp>
```

Preflight your node:

```sh
scripts/pohw-experiment-preflight.sh .pohw-experiment.env
```

Start gossip:

```sh
scripts/pohw-experiment-start-gossip.sh .pohw-experiment.env
```

Create a report bundle:

```sh
scripts/pohw-experiment-report.sh .pohw-experiment.env
```

Share only the generated `.tar.gz` report bundle with the group.

## Optional: Pledge An Idena Identity

If you have an Idena identity, prepare a local pledge:

```sh
scripts/pohw-experiment-register-miner.sh \
  .pohw-experiment.env \
  --idena-address 0x...
```

The script prints a challenge. Sign that challenge in Idena, then publish the signed registration:

```sh
scripts/pohw-experiment-register-miner.sh \
  .pohw-experiment.env \
  --idena-address 0x... \
  --idena-signature-hex <signature>
```

This proves ownership for the test without sharing your Idena private key.

## Optional: Idena Snapshot Vote

Once your local Idena snapshot exists:

```sh
scripts/pohw-experiment-publish-snapshot-vote.sh .pohw-experiment.env
```

Your node still verifies snapshot roots locally. The vote is not a central accountant.

## Optional: Bitcoin Fork Activation Check

If your Bitcoin Core node is synced far enough for the agreed timestamp:

```sh
scripts/pohw-experiment-prepare-fork-activation.sh .pohw-experiment.env
```

Compare `activation_id`, `first_fork_height`, and `inherited_tip_hash` with the group.

## What Success Looks Like

At least three independent testers should be able to:

- run the same commit,
- reach at least one peer,
- exchange signed registrations or test messages,
- produce report bundles,
- compare those bundles locally,
- agree on replay summaries,
- agree on snapshot roots once Idena data is ready.

## Where To Go Next

- Use [Experiment 0](EXPERIMENT-0.md) for the detailed operator runbook.
- Use the dashboard for a human-readable view of your local status.
- Use report bundles for group comparison.

If something feels confusing, that is useful beta feedback. Open an issue or tell the coordinator exactly where you got stuck and what command/output you saw.
