# Join P2poolBTC Experiment 0

This is the short community guide for reproducing the software, joining the
existing Experiment 0 network, connecting an Idena identity, and reporting a
problem safely.

The Experiment 0 fork phase has no monetary value, accepts no deposits, and
creates no transferable claims. Bitcoin and Idena consensus remain unchanged.
The optional PoHW fork is a separate test chain. An explicitly armed operator
switches to Bitcoin mainnet at 20 distinct active Idena identities; disconnect
your miner before that threshold unless you accept real-Bitcoin submission
risk. An armed host transitions automatically and deletes its dedicated local
fork datadir after preflight. Read
[the handoff policy](README.md#the-20-participant-mainnet-handoff).

> [!IMPORTANT]
> Join the existing network by default. Do not generate another activation
> manifest and do not start fork mining until the coordinator posts an explicit
> launch message. A different activation ID is a different experiment.

## What You Need

- Git, Python 3, and a current stable Rust toolchain.
- The exact commit, gossip seed, and fork seed from the coordinator's pinned
  Experiment 0 announcement.
- About 2 GB of free space for source and builds. Participants do not need a
  Bitcoin address index, `txindex=1`, or a full local explorer.
- A synced local Idena node only if you want to register an identity or
  independently produce an Idena snapshot.
- A Stratum v1 miner only if you want to submit test hashrate after launch.

Choose the smallest useful role:

| Role | Runs locally | Idena identity required |
| --- | --- | --- |
| Observer | Dashboard or report viewer | No |
| Replay peer | P2Pool binary and gossip | No |
| Idena participant | Replay peer, registration, snapshot vote | Yes |
| Miner | Replay peer or trusted hosted endpoint, Stratum miner | Yes |

The coordinator announcement supplies public connection values. Never accept a
replacement activation manifest or executable sent through a direct message.
The designated coordinator is the only first-node exception: that operator may
start the canonical fork seed before another fork peer exists, but must keep
Stratum and block production stopped until an independent second peer connects.

## Five-Step Fast Path

### 1. Reproduce The Agreed Build

Set the exact public commit from the pinned announcement, then build with the
tracked lockfile:

```sh
git clone https://github.com/ubiubi18/P2poolBTC.git
cd P2poolBTC

export POHW_COMMIT='<40-character-commit-from-the-pinned-announcement>'
git fetch --tags origin
git checkout --detach "$POHW_COMMIT"
test -z "$(git status --porcelain)"

cargo build --locked --release -p p2pool-node -p idena-lite-indexer
cargo test --locked --workspace
```

If the coordinator supplied a source archive instead, verify its adjacent
`.sha256` file before extraction, compare `MANIFEST.json` field `git_commit` to
the announced commit, and run the two Cargo commands from the extracted
directory. A source archive intentionally contains no `.git` directory, so the
checkout and clean-worktree commands apply only to a Git clone.

Verify that the repository contains the existing Experiment 0 activation:

```sh
python3 - compatibility/experiment-0-activation.json <<'PY'
import json
import sys

expected = "0db86bcc630703bb2004116509f8bdd3e54f6dbadb0693b9e9644d2f6c52fd4e"
with open(sys.argv[1], encoding="utf-8") as handle:
    actual = json.load(handle).get("activation_id")
if actual != expected:
    raise SystemExit(f"wrong Experiment 0 activation ID: {actual!r}")
print("Experiment 0 activation verified")
PY
```

Stop if the commit is not the announced commit, the worktree is dirty, tests
fail, or the activation ID differs. Do not run
`pohw-experiment-prepare-fork-activation.sh`; that command creates a separate
network.

### 2. Create A Local Join Configuration

Choose a lowercase public participant name and use the current public seeds
from the pinned announcement:

```sh
export POHW_MINER_ID='<your-public-participant-name>'
export POHW_GOSSIP_SEED='<current-gossip-seed-host:40406>'
export POHW_FORK_SEED='<current-fork-seed-host:40409>'

scripts/pohw-experiment-init.sh \
  --miner-id "$POHW_MINER_ID" \
  --peer-addrs "$POHW_GOSSIP_SEED" \
  --fork-peer-addrs "$POHW_FORK_SEED" \
  --register-peers
```

To contribute an Idena identity, add
`--idena-address '<your-public-idena-address>'`. The address is public network
data, but linking it to your GitHub identity may affect your privacy.

Initialization creates `.pohw-experiment.env` with mode `600` and copies the
canonical activation manifest into a new local datadir. Never post that env
file. Run a separate experiment only with the documented
`--separate-experiment` option and a different datadir.

The designated coordinator initializes the first canonical fork seed with the
explicit one-time exception below and no `--fork-peer-addrs` value:

```sh
scripts/pohw-experiment-init.sh \
  --miner-id "$POHW_MINER_ID" \
  --bootstrap-first-seed
```

This writes `POHW_FORK_BOOTSTRAP_FIRST_SEED=true`. It permits only the canonical
fork node to wait for its first peer; it does not approve Stratum or block
production. Everyone else must use the ordinary command with an existing fork
seed.

### 3. Preflight, Register, And Join Gossip

Run preflight before starting any network component:

```sh
scripts/pohw-experiment-preflight.sh .pohw-experiment.env
```

For ordinary participants, preflight must show the canonical activation,
non-placeholder gossip and fork peers, and no local replay error. Stop if an
existing network peer is not reachable. The designated coordinator may omit
fork peers only while `POHW_FORK_BOOTSTRAP_FIRST_SEED=true` and must announce
that role.

An Idena participant now creates an ownership challenge:

```sh
scripts/pohw-experiment-register-miner.sh .pohw-experiment.env
```

Sign only the printed `idena_ownership_challenge` in Idena. Then publish the
registration without ever exporting the Idena private key or API key:

```sh
scripts/pohw-experiment-register-miner.sh \
  .pohw-experiment.env \
  --idena-signature-hex '<signature-returned-by-idena>'
```

Start gossip in a dedicated terminal and leave it running:

```sh
scripts/pohw-experiment-start-gossip.sh .pohw-experiment.env
```

This joins only the signed sharechain gossip layer. It does not start the PoHW
fork or Stratum mining.

### 4. Add Idena Reward And Delegated-Stake Accounting

Skip this step if you are an observer or replay-only peer. Update
`IDENA_API_KEY_FILE` in `.pohw-experiment.env` so it points to your protected
local Idena API key file. Keep Idena RPC on loopback.

In a second terminal, load the local configuration and build a consensus-safe
snapshot from exact completed-epoch reward data:

```sh
set -a
. ./.pohw-experiment.env
set +a

export IDENA_REWARD_LEDGER_DB="$POHW_DATADIR/rewards/reward-ledger.sqlite3"
export IDENA_REWARD_INDEXER_SCRIPT="$POHW_WORKDIR/pohw_idena_rpc/idena_reward_indexer.py"
export IDENA_OFFICIAL_API_SYNC=true
export IDENA_OFFICIAL_API_COMPLETED_EPOCHS=10

scripts/pohw-snapshot-if-synced.sh
scripts/pohw-experiment-publish-snapshot-vote.sh .pohw-experiment.env
```

The ten-epoch import covers the invitation-liability window and exact completed
validation, staking, session, and mining reward records exposed by the official
API. A block-eligible delegated identity is attributed to its pool address in
the snapshot. Invitation rewards remain excluded from the PoHW payout score
because they can still be reversed or burned.

Raw staked iDNA is not a direct multiplier in the current formula. The Idena
half of the test payout weight uses eligible reward history. The other half uses
submitted Bitcoin hashrate work. This distinction must remain visible in issue
reports and dashboard screenshots.

### 5. Produce A Readiness Report And Wait For Launch

Create the bounded experiment report:

```sh
scripts/pohw-experiment-report.sh .pohw-experiment.env
```

Send the coordinator the report checksum first. Inspect the archive before
sharing it publicly:

```sh
report="$(ls -1t output/experiment-report-*.tar.gz | head -1)"
tar -tzf "$report"
review_dir="$(mktemp -d)"
tar -xzf "$report" -C "$review_dir"
find "$review_dir" -type f -print
```

The report deliberately contains public replay evidence and the signed
registration proof, including your Idena address, miner ID, payout script, and
public keys. Do not upload it publicly unless you accept that linkage. Peer
network endpoints are aggregated or redacted. The bundle must never contain
private keys, seed phrases, API keys, RPC cookies, passwords, dashboard tokens,
raw service journals, wallet files, or identity keystores.

At this point an ordinary participant is joined and ready, but **must not start
the fork or mining**. The coordinator first compares reports from independent
peers. After a written launch announcement, systemd operators may create the
fork approval marker and start only the fork peer:

```sh
sudo scripts/pohw-install-manual-launch-gate.sh
sudo touch /etc/pohw/enable-experiment-0-fork
sudo systemctl start pohw-fork-chain-node.service
```

The designated coordinator uses the same command to bootstrap the first seed.
Zero upstream peers are expected only while the explicit first-seed exception
is active. The coordinator then publishes its fork endpoint. As soon as an
independent second endpoint exists, update `/etc/pohw/p2pool.env` (or the local
env file), set `POHW_FORK_BOOTSTRAP_FIRST_SEED=false`, set
`POHW_FORK_PEER_ADDRS=<second-peer-ip:40409>`, and restart the fork service. The
runner refuses to retain the exception together with configured peers.

Configured peer IPs are the remote block-submission allowlist during this
easy-difficulty experiment. Unconfigured peers may query fork status and
synchronize the active block stream, but they cannot run explorer scans or
submit blocks. Keep the P2P port firewalled to announced participants until
authenticated peer identities are implemented.

Stratum has a separate approval marker. Create it and start mining only after
the fork peer has the canonical activation, at least one reachable existing
fork peer, and the registration and snapshot checks pass:

```sh
sudo touch /etc/pohw/enable-experiment-0-mining
sudo systemctl start pohw-mining-adapter.service
```

If you are not using the supplied systemd deployment, follow
[`EXPERIMENT-0.md`](EXPERIMENT-0.md) after the launch announcement. Never mine
an isolated fork tip.

## Reproducibility Checklist

Two peers reproduce the same experiment only when all of these match:

- exact 40-character Git commit and clean worktree;
- `Cargo.lock` build with `--locked`;
- activation ID
  `0db86bcc630703bb2004116509f8bdd3e54f6dbadb0693b9e9644d2f6c52fd4e`;
- canonical activation manifest bytes;
- formula version, snapshot height, identity root, and score root;
- sharechain replay summary after gossip convergence;
- fork cumulative-work tip after the fork is explicitly launched.

For a formal source handoff, the coordinator builds a clean participant bundle:

```sh
scripts/pohw-experiment-package.sh --require-clean --output-root output
```

Recipients verify the adjacent SHA-256 file before extracting it. Independent
participants compare report bundles with:

```sh
scripts/pohw-experiment-compare-reports.py \
  --strict \
  --min-nodes 3 \
  output/node-a-report.tar.gz \
  output/node-b-report.tar.gz \
  output/node-c-report.tar.gz
```

## Report A Problem

Search [existing issues](https://github.com/ubiubi18/P2poolBTC/issues) first.
For a normal bug, use the
[Experiment 0 issue form](https://github.com/ubiubi18/P2poolBTC/issues/new?template=experiment-0-bug.yml).

Before opening the issue:

1. Stop fork mining if the problem involves activation, consensus, replay,
   payout accounting, unexpected network exposure, or signature validation.
   Preserve the datadir; do not edit or delete evidence.
2. Reproduce once on the announced commit if doing so cannot create value loss
   or expose data.
3. Record the UTC time, role, operating system, architecture, exact commit,
   command, expected result, actual result, and whether it happens every time.
4. Run `pohw-experiment-report.sh`. Inspect its archive. Attach it only after
   confirming that every contained identifier is safe to publish.
5. Reduce terminal output to the smallest relevant excerpt and redact secrets,
   addresses, peer endpoints, usernames, hostnames, and local paths.

A useful public issue contains:

```text
Title: [Experiment 0] <component>: <short failure>

Role:
Exact commit:
Operating system and architecture:
UTC occurrence time:
Command or action:
Expected result:
Actual result:
Minimal reproduction:
Frequency:
Sanitized report attached: yes/no
Fork and mining stopped if consensus-related: yes/no/not applicable
```

Do not paste `.env` files, API requests, RPC cookies, private or public IP
addresses, Idena API keys, wallet data, identity addresses, seed phrases,
private keys, signatures that were not intentionally published, core dumps, or
raw logs. Screenshots need the same review as text.

### Security Or Privacy Problems

Do not open a public issue for a suspected secret leak, authentication bypass,
remote-code execution, consensus bypass, signature failure, or deanonymization
problem. Open the repository's
[Security page](https://github.com/ubiubi18/P2poolBTC/security), select
**Report a vulnerability** when available, and include only the minimum private
evidence needed to reproduce it. See [`SECURITY.md`](SECURITY.md) for the
fallback when private reporting is unavailable.

## Stop Conditions

Stop the affected service and report immediately if:

- a peer reports a different activation ID;
- honest peers replay the same messages to different roots;
- an unsigned or invalidly signed message is accepted;
- before the documented handoff completes, Stratum submits to Bitcoin mainnet
  instead of the fork RPC;
- after handoff, the adapter lacks `--allow-mainnet-submit` or still has a fork
  RPC argument;
- a participant is asked for a key, seed phrase, cookie, API key, or deposit;
- a report archive contains data that its owner did not intend to publish.

The full protocol and recovery details are in
[`EXPERIMENT-0.md`](EXPERIMENT-0.md). Tester roles and expectations are in
[`BETA-TESTING.md`](BETA-TESTING.md).
