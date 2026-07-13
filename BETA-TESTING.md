# Beta Testing P2poolBTC

For the current reproducible five-step join process and issue-reporting rules,
use the [Community Experiment 0 Guide](COMMUNITY-README.md). This page explains
the roles and goals behind that process.

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
- at least one current existing-network gossip peer,
- at least one current existing-network fork peer if this round includes fork mining,
- whether this round expects Idena snapshots, Bitcoin fork activation, or only gossip/report testing.

Then run:

```sh
cargo build --release -p p2pool-node

scripts/pohw-experiment-init.sh \
  --miner-id <your-name> \
  --bind-addr <node-lan-ip>:40406 \
  --advertise-addr <node-lan-ip>:40406 \
  --peer-addrs <current-experiment-0-gossip-seed>:40406 \
  --register-peers
```

Open `.pohw-experiment.env`, set:

```sh
POHW_EXPERIMENT_NO_VALUE_ACK=I_UNDERSTAND_NO_VALUE
POHW_EXPERIMENT_NETWORK_MODE=join-existing
POHW_FORK_LAUNCH_TIMESTAMP_UTC=2026-07-13T00:52:48Z
POHW_FORK_ACTIVATION_MANIFEST=/path/to/pohw-p2pool/fork-activation.json
POHW_FORK_PEER_ADDRS=<current-experiment-0-fork-seed>:40409
```

The init script copies `compatibility/experiment-0-activation.json` to the
configured manifest path in its default `join-existing` mode. If a different
file already exists there, initialization stops; follow the network selection
instructions in [Experiment 0](EXPERIMENT-0.md) rather than overwriting it.

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

## Optional: Existing Fork Activation Check

Beta testers join the existing Experiment 0 fork by using its canonical
manifest. Do not derive a new manifest for the normal participant path:

```sh
python3 - compatibility/experiment-0-activation.json <<'PY'
import json
import sys

expected = "0db86bcc630703bb2004116509f8bdd3e54f6dbadb0693b9e9644d2f6c52fd4e"
with open(sys.argv[1], encoding="utf-8") as handle:
    actual = json.load(handle).get("activation_id")
if actual != expected:
    raise SystemExit(f"wrong Experiment 0 activation_id: {actual!r}")
print("Experiment 0 activation manifest verified")
PY
```

Copy that file to the `POHW_FORK_ACTIVATION_MANIFEST` path in your local config,
configure current existing-network peers, and stop if none are reachable. The
separate-network workflow in [Experiment 0](EXPERIMENT-0.md) is the only place
that uses `pohw-experiment-prepare-fork-activation.sh`.

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
