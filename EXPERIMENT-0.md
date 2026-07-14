# Experiment 0: Multi-Node PoHW P2Pool Dry Run

This is the detailed operator runbook for the first community experiment.

If you are joining as a beta tester for the first time, use the
[source-first community guide](COMMUNITY-README.md). It builds locally and does
not trust a prebuilt binary or lead-developer signature. This document is the
advanced operator runbook.

> [!IMPORTANT]
> **The default workflow joins the canonical Experiment 0 network.** Do
> not derive a new fork activation manifest, change its launch parameters, or
> begin mining while isolated. Use the repository's canonical
> [`compatibility/experiment-0-activation.json`](compatibility/experiment-0-activation.json)
> and verify the activation ID below. Creating another experiment is supported,
> but only through the explicit [separate experiment](#start-a-separate-experiment-explicit-opt-in)
> workflow near the end of this document.

> [!WARNING]
> **The canonical fork phase ends at 20 active Idena identities on hosts that
> arm the mainnet handoff controller.** At that threshold the controller can
> automatically stop and delete the local no-value fork datadir, derive payouts
> for each live Bitcoin template, and start submitting target-meeting work to
> Bitcoin mainnet. There is no second prompt after the controller is armed.
> Mainnet blocks have real value. Operators who do not
> accept that risk must stop their miner and leave the controller disabled.
> See [The 20-participant mainnet handoff](README.md#the-20-participant-mainnet-handoff).

The designated first-seed operator may bootstrap the canonical fork seed without
an upstream fork peer by initializing with `--bootstrap-first-seed`. That
first-node exception permits only the consensus/P2P service to start. Stratum
and block production remain stopped until at least one independently operated
peer connects and verifies the same activation ID.

Experiment 0 begins as a no-value test of the decentralized P2Pool layer. The
fork phase is not Bitcoin mainnet mining, a token launch, a bridge, or a deposit
system. An explicitly armed host transitions to Bitcoin mainnet after the
canonical 20-participant condition; it still accepts no user deposits.

The optional fork phase runs the repository's coinbase-only Experiment 0 chain.
Before the handoff completes, it is no-value and does not alter or submit
blocks to Bitcoin mainnet.

## Why This Test Matters

P2poolBTC tests whether independent participants can verify the same Bitcoin-hashrate work, Idena human-work accounting, payout schedule, and vault-claim state without trusting one central pool server.

The goal is not to pay anyone in this round. The goal is to learn whether the protocol and user journey are clear enough for community testers to run independently.

## Goal

Run several independent nodes that can:

- exchange signed gossip envelopes,
- replay the same sharechain messages locally,
- compare replay roots and snapshot roots,
- load and verify the existing network's canonical fork activation manifest,
- publish miner registrations and snapshot votes,
- dry-run FROST DKG/signing with test inputs,
- produce shareable report bundles without leaking secrets.

## Fork-Phase Non-Value Rule

Before the 20-participant handoff, every participant must understand:

- no real BTC is paid,
- no user BTC deposits are accepted,
- no transferable claim or token exists,
- test claims can be deleted,
- the test can be shut down at any time.

After the handoff, a miner connected to an armed node works on Bitcoin mainnet.
That does not turn test claims into guaranteed payouts, and the unfinished
vault path is not production-ready. Stop the miner before `20 / 20` if you do
not explicitly accept real-Bitcoin submission risk.

Set this in your local env file before running the helper scripts:

```sh
POHW_EXPERIMENT_NO_VALUE_ACK=I_UNDERSTAND_NO_VALUE
```

## Network Identity: Join Existing Experiment 0 By Default

The activation manifest, not the human-readable chain name, identifies the fork
network. The existing Experiment 0 network is pinned to:

| Field | Canonical value |
| --- | --- |
| Chain name | `pohw-experiment-0` |
| Activation ID | `0db86bcc630703bb2004116509f8bdd3e54f6dbadb0693b9e9644d2f6c52fd4e` |
| Manifest SHA-256 | `5a7bc5b1df0be3c562710148b0cdb621eaeec228b48906cfd00d3c1357071851` |
| Launch timestamp | `2026-07-13T00:52:48Z` |
| First fork height | `957782` |
| Bootstrap handoff | `1 PH/s` |
| Inherited UTXO spending | disabled |

For the normal participant path:

1. Use the canonical manifest tracked in this repository.
2. Obtain current gossip and fork seed addresses from several existing
   participants. Peer addresses are transport hints and can change; the
   activation ID above cannot. The designated first-seed operator omits the
   fork seed only while starting the first canonical seed.
3. Ordinary participants stop if no existing peer is reachable or if any peer
   reports a different activation ID. The first seed may wait with zero peers,
   but nobody mines until a second independent peer verifies the activation.
4. Never run `pohw-experiment-prepare-fork-activation.sh` while joining this
   network. That command is reserved for creating a deliberately separate
   experiment.

A peer address is only a transport hint. Connecting to a peer cannot override
the activation manifest: the fork node validates every received block against
the pinned network identity and fails closed on mismatches.

## Required Local Setup

Each participant needs:

- this repository at the agreed git commit,
- Rust toolchain,
- local `p2pool-node` build,
- a local datadir,
- one reachable gossip address if they want inbound peers,
- at least one current existing-network peer before fork mining,
- optional local Idena and Bitcoin RPC while those nodes sync.

The experiment can begin before Bitcoin and Idena are fully synced, but snapshot votes and Bitcoin work-template validation remain gated by local data availability.
Joining the existing fork does not require deriving activation from Bitcoin RPC;
the canonical manifest already fixes the fork point. A synced Bitcoin RPC is
required only when deliberately creating a separate experiment or when a local
workflow explicitly validates Bitcoin mainnet templates.

## Participant Package

Create a shareable source bundle for the agreed experiment commit:

```sh
scripts/pohw-experiment-package.sh --output-root output
```

The package builder writes:

- `pohw-experiment-0-<commit>-<timestamp>.tar.gz`,
- a sibling `.sha256` checksum file,
- `QUICKSTART.md`, `MANIFEST.json`, and `SHA256SUMS` inside the archive.

It includes source, wrappers, tests, the env template, this runbook, and the
canonical existing-network activation manifest. It excludes `.git`, `target`,
`output`, local datadirs, generated UI/WASM artifacts, `node_modules`, env
files, keys, cookies, logs, report bundles, and chain data. For a formal dry
run, package from a clean worktree:

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
  --peer-addrs <current-experiment-0-gossip-seed>:40406 \
  --fork-peer-addrs <current-experiment-0-fork-seed>:40409 \
  --register-peers
```

Only the designated first-seed operator starting the canonical seed omits
`--fork-peer-addrs` and adds `--bootstrap-first-seed`. The generated temporary
exception must be removed as soon as the second fork endpoint is known.

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
POHW_EXPERIMENT_NETWORK_MODE=join-existing
POHW_FORK_LAUNCH_TIMESTAMP_UTC=2026-07-13T00:52:48Z
POHW_FORK_ACTIVATION_MANIFEST=/path/to/pohw-p2pool/fork-activation.json
POHW_FORK_PEER_ADDRS=<current-experiment-0-fork-seed>:40409
POHW_FORK_BOOTSTRAP_FIRST_SEED=false
POHW_MINER_ID=alice
POHW_GOSSIP_BIND_ADDR=<node-lan-ip>:40406
POHW_ADVERTISE_ADDR=<node-lan-ip>:40406
POHW_PEER_ADDRS=<current-experiment-0-gossip-seed>:40406
```

The init script installs the canonical activation manifest automatically in
`join-existing` mode. For a manual setup, or to verify that existing state is
still pinned correctly, use the following. It refuses to replace a different
manifest:

```sh
set -a
. ./.pohw-experiment.env
set +a

if test -e "$POHW_FORK_ACTIVATION_MANIFEST"; then
  cmp compatibility/experiment-0-activation.json "$POHW_FORK_ACTIVATION_MANIFEST"
else
  install -m 600 compatibility/experiment-0-activation.json \
    "$POHW_FORK_ACTIVATION_MANIFEST"
fi
```

If `cmp` fails, stop. Preserve the other manifest only if you intentionally use
the separate-experiment workflow with a different datadir and peer set.

Never share `.pohw-experiment.env` if it contains local paths to secret files. Never share API keys, dashboard tokens, Bitcoin cookies, or private keys.

## Build

```sh
cargo build --workspace
cargo build --release -p p2pool-node
```

## Verify Existing Fork Activation

Joining nodes use the tracked canonical manifest; they do not derive a new one.
Verify its activation ID before starting fork P2P or Stratum:

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

The manifest fixes the inherited parent, first fork height, bootstrap PoW limit,
per-block bootstrap DAA, handoff threshold, Bitcoin-2016 retarget phase, and
replay-protection policy. Do not set
`POHW_FORK_INHERITED_UTXO_SPENDING_ENABLED=true` for this network.

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

For a node joining the existing experiment, preflight is not complete unless:

- the reported fork activation ID equals the canonical ID above,
- `POHW_PEER_ADDRS` contains at least one current Experiment 0 gossip peer,
- `POHW_FORK_PEER_ADDRS` contains at least one current Experiment 0 fork peer,
- the values contain no documentation placeholders, and
- at least one existing peer is reachable before mining is enabled.

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

If the intended mode is `join existing` and the fork peer count remains zero,
stop the fork node and fix connectivity unless this is the designated first
seed with `POHW_FORK_BOOTSTRAP_FIRST_SEED=true`. The runner rejects a peerless
ordinary joiner. The first seed may remain online to accept its initial peer,
but starting Stratum against that isolated tip would create a private branch
even though the activation ID is correct.

After the second endpoint is available, the first-seed operator sets
`POHW_FORK_BOOTSTRAP_FIRST_SEED=false`, configures that endpoint in
`POHW_FORK_PEER_ADDRS`, and restarts the fork node. The runner rejects a stale
first-seed exception when peers are configured. Configured peer IPs are also the
remote block-submission allowlist; unconfigured peers may read fork status and
synchronize the active block stream, but they cannot run explorer scans or
submit easy-difficulty blocks.

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

Share only the generated `.tar.gz` report bundle. The bundle is designed to include public replay metadata plus the public signed `MinerRegistration` envelope for your `POHW_MINER_ID`. That proof exposes the registered Idena address, payout script, and public keys. Peer endpoints are aggregated or redacted, and the bundle excludes private keys, cookies, dashboard tokens, API keys, raw service journals, hostnames, and local filesystem paths.

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

## Start A Separate Experiment: Explicit Opt-In

Running another experiment is allowed, but it must be unmistakably separate.
Do this only when you intend to create a new network rather than join the
existing Experiment 0 network.

1. Use a separate env file, datadir, snapshot directory, output directory, and
   gossip/fork ports. Never reuse an existing Experiment 0 chain directory.
   Initialize that configuration with the explicit opt-in flag:

   ```sh
   scripts/pohw-experiment-init.sh \
     --separate-experiment \
     --env-file separate-experiment.env \
     --miner-id alice \
     --datadir /path/to/separate-experiment
   ```

   This writes `POHW_EXPERIMENT_NETWORK_MODE=create-separate`; manifest
   generation refuses to run without that mode.
2. Choose a distinct `POHW_FORK_CHAIN_NAME` and a future
   `POHW_FORK_LAUNCH_TIMESTAMP_UTC` agreed by that new group.
3. Leave both existing Experiment 0 peer lists out of the new configuration.
4. Remove no canonical files. Point `POHW_FORK_ACTIVATION_MANIFEST` at a new,
   nonexistent destination in the separate datadir.
5. Only then derive the new manifest from a sufficiently synced Bitcoin Core:

   ```sh
   scripts/pohw-experiment-prepare-fork-activation.sh separate-experiment.env
   ```

6. Publish the complete new manifest and label it with its different
   `activation_id`. Every participant in that new experiment must compare it
   before connecting or mining.

The preparation script refuses to overwrite an existing manifest. Do not work
around that protection. A different activation ID is a different network even
if someone reuses the same chain name.

## Success Criteria

Experiment 0 is successful when at least three independent nodes:

- run the same git commit,
- reach at least one peer,
- accept and replay the same signed registrations,
- report matching replay summaries after sync,
- can produce matching snapshot roots once local Idena data is ready,
- can complete a test-only FROST DKG/signing dry run without real funds.
- independently report the same distinct active-Idena participant count and
  the same 20-participant handoff policy.

## Stop Conditions

Stop and fix before expanding if:

- two honest nodes compute different replay roots from the same envelopes,
- a node accepts an unsigned or malformed envelope,
- report comparison shows different git commits or conflicting snapshot roots for the same day,
- a joining node has a missing or noncanonical Experiment 0 activation manifest,
- a joining node starts mining without reaching an existing fork peer,
- peer sync requires trusting one fixed server,
- work templates are accepted without each node's own Bitcoin RPC/template-policy admission pass,
- any script asks participants to share private keys, API keys, cookies, dashboard tokens, or raw logs,
- anyone proposes real BTC deposits or tradable claims.

## What Is Still Not Public-Ready

- no general post-fork transaction/script or UTXO consensus yet,
- no inherited UTXO spending or adaptive post-fork DAA yet,
- no long-running networked FROST signer daemon yet,
- no production-ready real BTC payout or vault flow,
- no complete official-indexer-backed Idena reward replay for every category,
- no production anti-eclipse review.
