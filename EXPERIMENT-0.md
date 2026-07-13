# Experiment 0: Multi-Node PoHW P2Pool Dry Run

This is the detailed operator runbook for the first community experiment.

If you are joining as a beta tester for the first time, start with [Beta Testing P2poolBTC](BETA-TESTING.md). It explains the roles, the shortest path to a first report bundle, and what feedback is useful.

Experiment 0 is a no-value, replay-only test of the decentralized P2Pool layer. It is not Bitcoin mainnet mining, not a token launch, not a bridge, and not a deposit system.

The optional fork phase runs the repository's coinbase-only Experiment 0 chain.
It is still no-value and does not alter or submit blocks to Bitcoin mainnet.

## Why This Test Matters

P2poolBTC tests whether independent participants can verify the same Bitcoin-hashrate work, Idena human-work accounting, payout schedule, and vault-claim state without trusting one central pool server.

The goal is not to pay anyone in this round. The goal is to learn whether the protocol and user journey are clear enough for community testers to run independently.

## Goal

Run several independent nodes that can:

- exchange signed gossip envelopes,
- replay the same sharechain messages locally,
- compare replay roots and snapshot roots,
- derive and compare one shared fork activation manifest,
- publish miner registrations and snapshot votes,
- dry-run FROST DKG/signing with test inputs,
- produce shareable report bundles without leaking secrets.

## Non-Value Rule

Every participant must understand:

- no real BTC is paid,
- no user BTC deposits are accepted,
- no transferable claim or token exists,
- test claims can be deleted,
- the test can be shut down at any time.

Set this in your local env file before running the helper scripts:

```sh
POHW_EXPERIMENT_NO_VALUE_ACK=I_UNDERSTAND_NO_VALUE
```

## Required Local Setup

Each participant needs:

- this repository at the agreed git commit,
- Rust toolchain,
- local `p2pool-node` build,
- a local datadir,
- one reachable gossip address if they want inbound peers,
- optional local Idena and Bitcoin RPC while those nodes sync.

The experiment can begin before Bitcoin and Idena are fully synced, but snapshot votes and Bitcoin work-template validation remain gated by local data availability.
Fork activation requires a local Bitcoin RPC that has synced at least past the agreed launch timestamp.

## Participant Package

Create a shareable source bundle for the agreed experiment commit:

```sh
scripts/pohw-experiment-package.sh --output-root output
```

The package builder writes:

- `pohw-experiment-0-<commit>-<timestamp>.tar.gz`,
- a sibling `.sha256` checksum file,
- `QUICKSTART.md`, `MANIFEST.json`, and `SHA256SUMS` inside the archive.

It includes source, wrappers, tests, the env template, and this runbook. It excludes `.git`, `target`, `output`, local datadirs, generated UI/WASM artifacts, `node_modules`, env files, keys, cookies, logs, report bundles, and chain data. For a formal dry run, package from a clean worktree:

```sh
scripts/pohw-experiment-package.sh --require-clean --output-root output
```

Participants should verify the checksum before unpacking:

```sh
cd output
shasum -a 256 -c pohw-experiment-0-*.tar.gz.sha256
```

## Per-Node Config

Create a local config:

```sh
scripts/pohw-experiment-init.sh \
  --miner-id alice \
  --bind-addr <node-lan-ip>:40406 \
  --advertise-addr <node-lan-ip>:40406 \
  --peer-addrs <peer-a-lan-ip>:40406,<peer-b-lan-ip>:40406 \
  --register-peers
```

The init script creates `.pohw-experiment.env`, the datadir, snapshot directory, and output directory with local-only defaults. The env file is written with mode `600`.

If you prefer manual setup, copy the template:

```sh
cp deploy/pohw-experiment.env.example .pohw-experiment.env
chmod 600 .pohw-experiment.env
```

Then edit at least:

```sh
POHW_WORKDIR=/path/to/p2pool
POHW_DATADIR=/path/to/pohw-p2pool
POHW_SNAPSHOT_DIR=/path/to/pohw-p2pool/snapshots
POHW_FORK_LAUNCH_TIMESTAMP_UTC=2026-07-05T00:00:00Z
POHW_MINER_ID=alice
POHW_GOSSIP_BIND_ADDR=<node-lan-ip>:40406
POHW_ADVERTISE_ADDR=<node-lan-ip>:40406
POHW_PEER_ADDRS=<peer-a-lan-ip>:40406,<peer-b-lan-ip>:40406
```

Never share `.pohw-experiment.env` if it contains local paths to secret files. Never share API keys, dashboard tokens, Bitcoin cookies, or private keys.

## Build

```sh
cargo build --workspace
cargo build --release -p p2pool-node
```

## Prepare Fork Activation

The group must agree on one `POHW_FORK_LAUNCH_TIMESTAMP_UTC` before any fork mining test. Each node derives the activation manifest from its own Bitcoin Core RPC:

```sh
scripts/pohw-experiment-prepare-fork-activation.sh .pohw-experiment.env
```

The manifest records the first Bitcoin mainnet block at or after the launch timestamp, the inherited parent tip, post-fork test difficulty parameters, and an `activation_id`. Share the manifest or at least the `activation_id`, `first_fork_height`, and `inherited_tip_hash` out of band. Do not set `POHW_FORK_INHERITED_UTXO_SPENDING_ENABLED=true` for Experiment 0.

## Preflight

Run:

```sh
scripts/pohw-experiment-preflight.sh .pohw-experiment.env
```

The script writes a timestamped folder under `output/` with:

- local node status,
- gossip peer list,
- multi-node readiness report,
- non-secret env summary.

If `POHW_EXPERIMENT_REGISTER_PEERS=true`, the script also adds configured `POHW_PEER_ADDRS` to the local peer book.

## Start Gossip

Local development:

```sh
scripts/pohw-experiment-start-gossip.sh .pohw-experiment.env
```

The wrapper loads the env file, enforces the no-value acknowledgement, creates the datadir, and uses `target/release/p2pool-node`, `target/debug/p2pool-node`, or `cargo run` in that order.

For systemd or Pi deployment, use the lower-level runner after the env file is already loaded:

```sh
set -a
. ./.pohw-experiment.env
set +a
scripts/pohw-run-gossip-mesh.sh
```

For LAN experiments, expose only gossip TCP `40406` to known peers. Keep Bitcoin RPC and Idena RPC on loopback.

## Start The Optional Fork Chain

After every node has the same activation manifest, start the fork consensus node:

```sh
scripts/pohw-run-fork-chain-node.sh
```

Configure a separate fork P2P port and at least one peer. Keep control RPC
`127.0.0.1:40408` on loopback. Verify that all nodes report the same activation
ID and, after mining begins, the same cumulative-work tip. Full consensus rules,
Stratum configuration, smoke tests, and rollback are documented in
[`docs/fork-chain-node.md`](docs/fork-chain-node.md).

## Prepare A Miner Registration

Each participant prepares their own keys and unsigned Idena ownership challenge:

```sh
scripts/pohw-experiment-register-miner.sh \
  .pohw-experiment.env \
  --idena-address 0x...
```

The script prints a redacted public view and stores the raw local output under `output/`. Sign `idena_ownership_challenge` in Idena.

After signing the challenge in Idena, append and gossip the signed registration:

```sh
scripts/pohw-experiment-register-miner.sh \
  .pohw-experiment.env \
  --idena-address 0x... \
  --idena-signature-hex <signature>
```

By default, the signed registration is appended locally and sent to `POHW_PEER_ADDRS`. Use `--no-gossip` or `--no-append` only for controlled local tests.

## Publish A Snapshot Vote

Once your local Idena snapshot exists, publish a signed vote for the latest verified snapshot:

```sh
scripts/pohw-experiment-publish-snapshot-vote.sh .pohw-experiment.env
```

The script uses the mining and gossip keys created by the registration step. By default it picks the newest snapshot JSON in `POHW_SNAPSHOT_DIR`, appends the signed `SnapshotVote` locally, and sends it to `POHW_PEER_ADDRS`. If you are testing a specific file, pass `--snapshot-file path/to/snapshot.json`.

## Compare State

After participants exchange registrations, snapshot votes, and any test messages, each participant runs:

```sh
scripts/pohw-experiment-report.sh .pohw-experiment.env
```

Share only the generated `.tar.gz` report bundle. The bundle is designed to include public replay metadata plus the public signed `MinerRegistration` envelope for your `POHW_MINER_ID`, and to exclude private keys, cookies, dashboard tokens, API keys, raw service journals, hostnames, and local filesystem paths.

Compare the exchanged bundles locally:

```sh
scripts/pohw-experiment-compare-reports.py \
  --min-nodes 3 \
  output/alice-report.tar.gz \
  output/bob-report.tar.gz \
  output/carol-report.tar.gz
```

Use `--strict` once the group expects gossip convergence. Strict mode turns unreachable peers and replay mismatches into hard failures. The comparer also rejects duplicate report bundles and duplicate node ids. `--min-nodes 3` counts only signed `MinerRegistration` proofs verified through `p2pool-node verify-miner-registration-envelope`, so hand-written preflight summaries and unregistered dry-run reports can be compared with `--min-nodes 0` but do not satisfy the participant quorum.

The group should compare:

- git commit,
- sharechain message count,
- gossip envelope count,
- replay summary,
- latest snapshot `score_root`,
- latest snapshot `identity_root`,
- peer reachability.

## Success Criteria

Experiment 0 is successful when at least three independent nodes:

- run the same git commit,
- reach at least one peer,
- accept and replay the same signed registrations,
- report matching replay summaries after sync,
- can produce matching snapshot roots once local Idena data is ready,
- can complete a test-only FROST DKG/signing dry run without real funds.

## Stop Conditions

Stop and fix before expanding if:

- two honest nodes compute different replay roots from the same envelopes,
- a node accepts an unsigned or malformed envelope,
- report comparison shows different git commits or conflicting snapshot roots for the same day,
- peer sync requires trusting one fixed server,
- work templates are accepted without each node's own Bitcoin RPC/template-policy admission pass,
- any script asks participants to share private keys, API keys, cookies, dashboard tokens, or raw logs,
- anyone proposes real BTC deposits or tradable claims.

## What Is Still Not Public-Ready

- no general post-fork transaction/script or UTXO consensus yet,
- no inherited UTXO spending or adaptive post-fork DAA yet,
- no long-running networked FROST signer daemon yet,
- no real BTC payout flow,
- no complete official-indexer-backed Idena reward replay for every category,
- no production anti-eclipse review.
