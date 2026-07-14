# Beta Testing P2poolBTC

For the current reproducible five-step join process and issue-reporting rules,
use the [Community Experiment 0 Guide](COMMUNITY-README.md). This page explains
the roles and goals behind that process.

P2poolBTC is looking for careful early testers who want to help check whether a Bitcoin pool can use Idena human-work accounting without a central operator.

During the fork phase you are not mining real BTC. You are helping prove that
independent nodes can see the same registrations, snapshots, sharechain
messages, and payout accounting. The canonical deployment can switch to
Bitcoin mainnet at 20 distinct active Idena identities; disconnect your miner
before that threshold unless you explicitly accept real-Bitcoin submission
risk. On an armed host this is automatic and deletes that host's dedicated fork
datadir after mainnet preflight. See
[the handoff policy](README.md#the-20-participant-mainnet-handoff).

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

The Experiment 0 fork phase is deliberately no-value:

- no real BTC payouts,
- no user BTC deposits,
- no tradable token,
- no bridge,
- no claim market,
- no promise that test data survives.

Those statements stop describing the mining target after an armed node's
mainnet handoff completes. The software remains experimental and does not make
the payout/vault path production-safe.

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

Obtain the community-agreed source commit and current gossip, fork RPC, and
fork P2P hints from independent participants. Build and launch locally:

```sh
git clone https://github.com/ubiubi18/P2poolBTC.git
cd P2poolBTC
git checkout --detach '<community-agreed-commit>'

scripts/pohw-community-join.sh \
  --gossip-peer '<gossip-host:port>' \
  --fork-rpc-peer '<fork-rpc-host:port>' \
  --fork-p2p-peer '<fork-p2p-host:port>'
```

The launcher accepts no prebuilt executable or maintainer signature. Compare
the source CID it prints with independent participants, then use the local
wizard to register your identity and start signed gossip. See the
[Community Experiment 0 Guide](COMMUNITY-README.md) for fork-sync and mining
progression. The older env/systemd flow below remains the advanced operator
path.

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

If something feels confusing, that is useful beta feedback. Open an issue and
state exactly where you got stuck and what sanitized command/output you saw.
