# P2poolBTC

P2poolBTC is a no-value Bitcoin P2Pool-style experiment with Idena proof-of-human-work accounting.
It explores a voluntary mining layer where every node can replay the same sharechain, Idena snapshots, reward scores, payout schedules, and vault claims locally.

Bitcoin and Idena stay unchanged. This repo builds the experimental coordination layer between them.

`compatibility/stack-lock.json` pins the reviewed Idena candidate consumed by
PoHW. Run `python3 scripts/pohw-idena-compatibility-lock.py` before deployment;
the production installers additionally require root-owned source provenance
files for both modern and legacy binaries.

The idea is simple:

- Bitcoin hashrate still mines the block.
- Idena human-work history adds a second reward signal.
- Pool rewards are split 50/50 between hashrate score and Idena reward-accounting score.
- Large unpaid balances can be paid directly in the coinbase.
- Smaller balances become non-transferable withdrawal claims against a weekly FROST vault epoch.

This repo is not a production Bitcoin node, not a token bridge, and not ready for real funds.

## Preview

These screenshots use demo data only; they show the user flow, not live payout claims.

### Combined explorer

![P2poolBTC combined Bitcoin fork, sharechain, and Idena explorer](docs/assets/explorer-overview.png)

### Participant dashboard

![P2poolBTC dashboard overview](docs/assets/dashboard-overview.png)

<p align="center">
  <img src="docs/assets/dashboard-mobile.png" alt="P2poolBTC mobile dashboard overview" width="360">
</p>

![PoHW pool flow: solve flips, join p2pool, mine Bitcoin, decentralize Bitcoin mining](docs/assets/pohw-flow.png)

## Start Here

If you want to help test, start with the
[Community Experiment 0 Guide](COMMUNITY-README.md). It gives the explicit
five-step path to reproduce the build, join the existing experiment, connect an
Idena identity, produce a readiness report, and report problems safely.

[Beta Testing P2poolBTC](BETA-TESTING.md) explains the tester roles and safety
boundaries in more detail.

Use [Experiment 0](EXPERIMENT-0.md) as the detailed operator runbook once you are ready to run a multi-node test.

## Status

Working prototype pieces:

- deterministic `POHW1` commitment model,
- reproducible Bitcoin-mainnet-history fork activation manifest generation,
- complete Experiment 0 coinbase-only fork consensus with durable replay,
  cumulative-work fork choice, bootstrap difficulty, irreversible Bitcoin-2016
  difficulty handoff, peer synchronization, and a loopback control RPC,
- live fork templates and fork-only block submission wired into the Stratum adapter,
- local append-only sharechain replay,
- signed miner registrations, shares, snapshot votes, payout schedules, withdrawal requests, and withdrawal batches,
- signed TCP gossip mesh with inventory sync, peer exchange, rebroadcast, rate limits, and private-network defaults,
- operator commands to preflight a multi-node setup and publish signed registrations, snapshot votes, work templates, and shares,
- local Stratum v1 mining adapter for real Bitcoin miners or rented hashrate to submit sharechain work to their own node,
- local Idena snapshot builder using `idena-go` RPC,
- deterministic 50/50 payout schedule logic,
- confirmed payout replay log for vault claim balances,
- automatic payout confirmer that watches local candidate files and calls the RPC-confirmed payout flow,
- Taproot FROST vault primitives, real local DKG/signing CLI commands, demos, and RPC-validated vault input checks,
- AssemblyScript snapshot registry with Idena host-storage imports, record validation, and deterministic encoding,
- read-only local dashboard API,
- versioned public explorer API for decoded fork transactions, scripts, addresses,
  UTXOs, inherited Bitcoin history, sharechain shares, and aggregate Idena snapshots,
- optional host-only Esplora index integration; pool participants do not run a
  Bitcoin address index or enable Bitcoin Core `txindex`,
- Vite/React combined explorer and participant dashboard,
- Raspberry Pi systemd helpers for snapshots, gossip mesh, dashboard API, and dashboard UI.

Not done yet:

- general post-fork transaction/script and UTXO consensus,
- inherited UTXO replay protection and spending,
- production P2Pool fork-choice and anti-eclipse logic,
- long-running networked ChillDKG/FROST signer daemon,
- complete idena-go reward extraction for every reward source,
- Idena SDK/bindgen packaging decision, WASM deployment, and data availability publishing.

## Repository Layout

```text
crates/pohw-core          consensus/accounting/vault primitives
crates/p2pool-node        local node, gossip, dashboard API, Bitcoin RPC checks
crates/idena-lite-indexer local idena-go snapshot builder
ui/pohw-dashboard         React dashboard
contracts/                Idena WASM snapshot registry
deploy/systemd            Raspberry Pi service templates
scripts/                  Pi helper scripts
docs/                     design artifacts
```

## Defaults

| Component | Default | Purpose |
| --- | --- | --- |
| Gossip mesh | `127.0.0.1:40406` | Signed sharechain envelope exchange |
| Fork control RPC | `127.0.0.1:40408` | Activation-bound templates and block submission |
| Fork P2P | disabled | Validated fork-block synchronization |
| Mining adapter | `127.0.0.1:3333` | Local Stratum v1 frontend |
| Dashboard UI | `127.0.0.1:5176` | Browser UI, tunnel from a workstation |
| Dashboard API | `127.0.0.1:40407` | Read-only local status |
| Bitcoin history index | `127.0.0.1:3002` | Optional host-only Esplora HTTP source |
| Dashboard dev server | Vite | Local frontend development |
| Idena RPC | `http://127.0.0.1:9009` | Local `idena-go` source |
| Bitcoin RPC | `http://127.0.0.1:8332` | Local Bitcoin Core source |
| Sharechain data | `.pohw-p2pool/` or `/mnt/ssd/pohw-p2pool` | Local replay logs |
| Snapshots | `./snapshots/` or `/mnt/ssd/pohw-p2pool/snapshots` | Verified Idena snapshot JSON |

Keep Bitcoin and Idena RPC on loopback. Expose gossip, dashboard, or Stratum only to trusted peers, with firewall rules. Non-loopback dashboard needs a token; non-loopback Stratum needs a protected password file.

The combined explorer can be deployed locally or on a dedicated host. See
[PoHW Network Explorer](docs/explorer.md) for the public API, privacy boundary,
systemd/Caddy host profile, smoke tests, and rollback procedure.

Only the dedicated explorer operator needs the Bitcoin history index. A miner,
Pi, or observer can use the hosted versioned API and never downloads the full
Bitcoin chain or address index. Fork consensus validation remains independent
from the history index.

## Community Experiment

Start with the [Community Experiment 0 Guide](COMMUNITY-README.md) when
multiple people help. It gives the reproducible five-step join path and the
safe issue-reporting workflow. [Beta Testing P2poolBTC](BETA-TESTING.md)
describes the available tester roles.

Use [Experiment 0](EXPERIMENT-0.md) for the complete no-value scope, env template, preflight, miner registration, snapshot voting, report bundles, deterministic report comparison, success criteria, and stop conditions for a decentralized dry run.

Build a participant source package:

```sh
scripts/pohw-experiment-package.sh --output-root output
```

The archive includes the runbook, source, scripts, tests, env template, `QUICKSTART.md`, `MANIFEST.json`, and `SHA256SUMS`; it excludes local datadirs, build output, generated frontend/WASM artifacts, env files, keys, cookies, logs, and reports.

## Quick Start

```sh
cargo test --workspace
cargo build --workspace
```

Run a local replay-only node:

```sh
cargo run -p p2pool-node -- run --datadir .pohw-p2pool
cargo run -p p2pool-node -- status --datadir .pohw-p2pool
```

Run the dashboard API:

```sh
cargo run -p p2pool-node -- serve-dashboard-api \
  --datadir .pohw-p2pool \
  --snapshot-dir ./snapshots \
  --dashboard-idena-address 0x... \
  --bind-addr 127.0.0.1:40407
```

Set one local account selector (`--dashboard-idena-address`, `--dashboard-miner-id`, or `--dashboard-claim-owner-id`) once more than one miner exists in the sharechain.

Run the UI:

```sh
corepack pnpm@10.13.1 --dir ui/pohw-dashboard install
corepack pnpm@10.13.1 --dir ui/pohw-dashboard dev
```

When both dashboard services run on the Pi, keep them bound to Pi loopback and open an SSH tunnel from your workstation:

```sh
scripts/pohw-dashboard-tunnel.sh <pi-ssh-host>
```

Then open `http://127.0.0.1:5176/` locally. The tunnel forwards workstation `127.0.0.1:5176` to the Pi UI and workstation `127.0.0.1:40407` to the Pi dashboard API, without exposing either service to the WLAN or Internet.

If you deliberately run only the UI on your workstation while the dashboard API runs on the Pi over your WLAN, point the local UI at the Pi API and pass the dashboard token:

```sh
PI_POHW_API=http://<pi-wlan-ip>:40407/dashboard.json

VITE_POHW_DASHBOARD_API_URL="$PI_POHW_API" \
VITE_POHW_DASHBOARD_API_TOKEN='<dashboard-token-from-your-local-secret-file>' \
corepack pnpm@10.13.1 --dir ui/pohw-dashboard dev
```

Keep the Vite UI bound to loopback. `VITE_POHW_DASHBOARD_API_TOKEN` is visible to that browser session.

The dashboard intentionally shows an offline state if the local API is unavailable. Demo data is opt-in:

```sh
VITE_POHW_DASHBOARD_DEMO=true corepack pnpm@10.13.1 --dir ui/pohw-dashboard dev
```

## Core Commands

To create a deliberately separate no-value fork/testnet, derive a new
activation manifest from local Bitcoin Core:

```sh
cargo run -p p2pool-node -- prepare-fork-activation \
  --chain-name my-separate-experiment \
  --launch-timestamp-utc <future-rfc3339-time> \
  --rpc-cookie-file ~/.bitcoin/.cookie \
  --manifest-out ./fork-activation.json
```

The command derives the first Bitcoin mainnet block at or after the launch
timestamp, records the inherited parent tip, starts at the no-value bootstrap
PoW limit `0x207fffff`, and emits an `activation_id`. Bootstrap difficulty
adjusts every block. At a difficulty-implied hashrate of `1 PH/s` by default,
the chain irreversibly hands descendants to Bitcoin's normal 2016-block
retarget mechanism. Set `--bootstrap-handoff-hashrate-hps` before activation to
choose another threshold. The algorithm, threshold, and spacing are committed
by the manifest, so every participant must use the identical
`fork-activation.json`. Inherited-mainnet UTXO spending remains disabled unless
`--inherited-utxo-spending-enabled` is explicitly set, and it should stay
disabled until replay protection exists.

Run the activation-bound Experiment 0 chain and inspect its live status:

```sh
scripts/pohw-run-fork-chain-node.sh
target/release/p2pool-node fork-chain-status \
  --activation-manifest .pohw-p2pool/fork-activation.json
```

The fork node validates scheduled-target PoW, ancestry, merkle and witness
roots, block weight, BIP34 height, subsidy, time, and coinbase-only transaction
rules; persists every accepted branch; selects cumulative work; and
synchronizes fork blocks with configured peers. See
[Experiment 0 Fork-Chain Node](docs/fork-chain-node.md).

The normal Experiment 0 participant path does not run that command. Initialize
in the default `join-existing` mode and use the canonical tracked manifest:

```sh
scripts/pohw-experiment-init.sh --miner-id alice
cmp compatibility/experiment-0-activation.json \
  .pohw-p2pool/fork-activation.json
```

Its activation ID is
`0db86bcc630703bb2004116509f8bdd3e54f6dbadb0693b9e9644d2f6c52fd4e`.
The wrapper `pohw-experiment-prepare-fork-activation.sh` refuses to generate a
manifest unless initialization used `--separate-experiment`. See
[Experiment 0](EXPERIMENT-0.md) for peer checks and both network workflows.

Prepare a miner pledge locally:

```sh
cargo run -p p2pool-node -- prepare-miner-registration \
  --datadir .pohw-p2pool \
  --miner-id alice \
  --idena-address 0x...
```

The first run creates protected local keys, derives a default Taproot payout script, and prints the Idena ownership challenge. After signing that challenge in Idena, rerun with `--idena-signature-hex`, plus `--append` or `--peer-addr` when ready to publish the registration.

For Experiment 0, prefer the env-file wrapper:

```sh
scripts/pohw-experiment-register-miner.sh .pohw-experiment.env --idena-address 0x...
scripts/pohw-experiment-register-miner.sh .pohw-experiment.env \
  --idena-address 0x... \
  --idena-signature-hex <signature>
```

Create and verify gossip:

```sh
cargo run -p p2pool-node -- create-gossip-envelope \
  --message-file ./message.json \
  --node-secret-key-file ./node.key \
  > envelope.json

cargo run -p p2pool-node -- verify-gossip-envelope \
  --envelope-file ./envelope.json
```

Run the local gossip mesh:

```sh
cargo run -p p2pool-node -- run-gossip-mesh \
  --datadir .pohw-p2pool
```

Expose gossip to trusted WLAN peers only when your firewall rules are ready:

```sh
cargo run -p p2pool-node -- run-gossip-mesh \
  --datadir .pohw-p2pool \
  --bind-addr <node-lan-ip>:40406 \
  --advertise-addr <node-lan-ip>:40406 \
  --peer-addr <peer-lan-ip>:40406
```

Preflight a multi-node experiment:

```sh
scripts/pohw-experiment-init.sh \
  --miner-id alice \
  --bind-addr 127.0.0.1:40406

scripts/pohw-experiment-preflight.sh .pohw-experiment.env
scripts/pohw-experiment-start-gossip.sh .pohw-experiment.env
```

Or call the node command directly:

```sh
cargo run -p p2pool-node -- multinode-preflight \
  --datadir .pohw-p2pool \
  --snapshot-dir ./snapshots \
  --miner-id alice \
  --peer-addr <peer-lan-ip>:40406
```

Publish locally verified data into the signed gossip layer:

```sh
cargo run -p p2pool-node -- publish-snapshot-vote \
  --datadir .pohw-p2pool \
  --miner-id alice \
  --snapshot-file ./snapshots/latest.json \
  --mining-secret-key-file .pohw-p2pool/keys/alice/mining.key \
  --node-secret-key-file .pohw-p2pool/keys/alice/gossip-node.key \
  --append \
  --peer-addr <peer-lan-ip>:40406

cargo run -p p2pool-node -- publish-bitcoin-work-template \
  --datadir .pohw-p2pool \
  --miner-id alice \
  --bitcoin-header-hex <80-byte-header-hex> \
  --mining-secret-key-file .pohw-p2pool/keys/alice/mining.key \
  --node-secret-key-file .pohw-p2pool/keys/alice/gossip-node.key \
  --validate-with-bitcoin-rpc \
  --rpc-cookie-file ~/.bitcoin/.cookie \
  --accept-locally \
  --append \
  --peer-addr <peer-lan-ip>:40406

cargo run -p p2pool-node -- publish-share \
  --datadir .pohw-p2pool \
  --miner-id alice \
  --bitcoin-header-hex <80-byte-header-hex> \
  --target <32-byte-target-hex> \
  --idena-snapshot-id <snapshot-day-or-id> \
  --idena-snapshot-proof-root <32-byte-root-hex> \
  --mining-secret-key-file .pohw-p2pool/keys/alice/mining.key \
  --node-secret-key-file .pohw-p2pool/keys/alice/gossip-node.key \
  --block-candidate-dir .pohw-p2pool/block-candidates \
  --append \
  --peer-addr <peer-lan-ip>:40406
```

Each node still verifies the append locally. Use `--accept-locally` only after Bitcoin RPC validation, unless you deliberately pass `--allow-unverified-local-accept` for a controlled test fixture.
`publish-share` defaults `--parent-share-hash` to the local best share tip; on an empty sharechain it uses the zero parent.

Bootstrap the remaining readiness checks from one command once miner registration
and a verified Idena snapshot exist:

```sh
scripts/pohw-bootstrap-readiness.sh .pohw-experiment.env --mode real
```

Real mode builds the Bitcoin work candidate from local Bitcoin Core RPC, publishes
and locally accepts a signed `BitcoinWorkTemplate` only after RPC validation, then
publishes the first share bound to the selected Idena snapshot. The default
bootstrap share target is the maximum accepted rehearsal target; set
`POHW_BOOTSTRAP_SHARE_TARGET` or pass `--share-target` for stricter accounting.
If Bitcoin Core is still in initial block download, it writes `status.json` with
`bitcoin_not_ready` and exits without appending synthetic work.

For isolated single-node plumbing tests only, use:

```sh
scripts/pohw-bootstrap-readiness.sh .pohw-experiment.env \
  --mode dev \
  --dev-ack I_UNDERSTAND_DEV_ONLY
```

Dev mode uses synthetic local work and must not be used for Bitcoin mining or
shared experiment consensus.

Mesh sync can admit peer work templates automatically when it has local Bitcoin RPC access:

```sh
cargo run -p p2pool-node -- run-gossip-mesh \
  --datadir .pohw-p2pool \
  --bind-addr 127.0.0.1:40406 \
  --peer-addr <peer-lan-ip>:40406 \
  --admit-peer-work-templates \
  --rpc-cookie-file ~/.bitcoin/.cookie \
  --allow-mutable-time \
  --expected-header-merkle-root-hex <32-byte-coinbase-merkle-root-hex>
```

This does not trust the peer. During sync the node can fetch missing miner registrations by `miner_id` and missing work templates by `bitcoin_template_hash` before replaying a share, verifies the registration signature, template mining signature, and Bitcoin Core template policy locally, then records only admitted templates.
Use `--allow-unverified-merkle-root` only for controlled development fixtures where no local block builder/fork validator can provide the expected header merkle root.

For one-off diagnostics, run the same admission pass manually:

```sh
cargo run -p p2pool-node -- admit-peer-work-templates \
  --datadir .pohw-p2pool \
  --peer-addr <peer-lan-ip>:40406 \
  --rpc-cookie-file ~/.bitcoin/.cookie \
  --allow-mutable-time \
  --expected-header-merkle-root-hex <32-byte-coinbase-merkle-root-hex>
```

Run the local Stratum mining adapter:

```sh
cargo run -p p2pool-node -- run-mining-adapter \
  --datadir .pohw-p2pool \
  --bind-addr 127.0.0.1:3333 \
  --miner-id alice \
  --job-file ./mining-job.json \
  --idena-snapshot-id <snapshot-day-or-id> \
  --idena-snapshot-proof-root <32-byte-root-hex> \
  --mining-secret-key-file .pohw-p2pool/keys/alice/mining.key \
  --node-secret-key-file .pohw-p2pool/keys/alice/gossip-node.key \
  --append \
  --peer-addr <peer-lan-ip>:40406
```

Point a miner at `stratum+tcp://127.0.0.1:3333`. The worker name is informational; accepted shares are credited to `--miner-id`, after local replay confirms that miner registration owns the mining key. The adapter verifies share difficulty locally, signs `BitcoinWorkTemplate` and `Share` messages, appends them to the local sharechain, and gossips them to configured peers.

By default, `--stratum-difficulty 1` uses the Bitcoin Stratum diff-1 target for sharechain accounting. If you raise `--stratum-difficulty`, set the matching `--share-target` too; the adapter refuses to infer a custom target because wrong target accounting would miscredit miners. Job file fields are Stratum notify wire values, not human display block hashes. The packaged example job is refused by the binary unless `--allow-example-mining-job` is passed for an explicit local dry-run.

Build a fresh Experiment 0 mining job from your local Bitcoin RPC before starting Stratum:

```sh
cargo run -p p2pool-node -- build-stratum-job-rpc \
  --job-out .pohw-p2pool/mining-job.json \
  --replace \
  --rpc-cookie-file ~/.bitcoin/.cookie
```

The generated job uses local `getblocktemplate` for version, previous block, time, bits, and transaction merkle branches. It is enough for sharechain work accounting and multi-node rehearsal, but it is not yet the final PoHW block-submission coinbase with payout outputs.

For the live Experiment 0 fork feed, do not use Bitcoin RPC job refresh. Start the
fork node, then run the adapter with:

```sh
cargo run -p p2pool-node -- run-mining-adapter \
  --datadir .pohw-p2pool \
  --bind-addr 127.0.0.1:3333 \
  --miner-id alice \
  --fork-chain-rpc-addr 127.0.0.1:40408 \
  --fork-chain-activation-manifest .pohw-p2pool/fork-activation.json \
  --idena-snapshot-id <snapshot-id> \
  --idena-snapshot-proof-root <root> \
  --mining-secret-key-file .pohw-p2pool/keys/alice/mining.key \
  --node-secret-key-file .pohw-p2pool/keys/alice/gossip-node.key \
  --auto-submit-blocks
```

The adapter derives the easy fork target and Stratum difficulty from each live
template. Target-meeting blocks go only to the activation-bound fork RPC.
When using `--replace`, keep the job file in a private node directory that is not group/world writable.

For a long-running adapter, add `--refresh-job-from-rpc --rpc-cookie-file ~/.bitcoin/.cookie`. It polls `getblocktemplate`, atomically swaps changed jobs, and sends a clean `mining.notify` to subscribed miners without restarting their connection. The default refresh interval is five seconds and can be changed with `--job-refresh-interval-seconds`.

When a locally verified payout schedule and POHW commitment are available, build the payout-aware Stratum job instead:

```sh
cargo run -p p2pool-node -- build-pohw-stratum-job-rpc \
  --job-out .pohw-p2pool/mining-job.json \
  --replace \
  --payout-schedule-file .pohw-p2pool/payout-schedule.json \
  --pohw-commitment-file .pohw-p2pool/pohw-commitment.json \
  --rpc-cookie-file ~/.bitcoin/.cookie
```

That job places the deterministic direct outputs, the current vault output, and the `POHW1` OP_RETURN commitment into the coinbase split miners receive over Stratum. The command refuses schedules whose positive coinbase outputs do not exactly match the local `getblocktemplate` `coinbasevalue`.

Build a reproducible candidate artifact from a Stratum submit tuple:

```sh
cargo run -p p2pool-node -- build-stratum-block-candidate \
  --job-file .pohw-p2pool/mining-job.json \
  --candidate-out .pohw-p2pool/block-candidate.json \
  --replace \
  --extranonce1 <from-adapter-log> \
  --extranonce2 <from-miner-submit> \
  --ntime <from-miner-submit> \
  --nonce <from-miner-submit> \
  --require-block-target
```

The artifact contains the exact coinbase tx, header, block hash, target check, and complete `block_hex` when the job carries the raw non-coinbase transactions. Jobs built by this repository from Bitcoin RPC include that transaction data. Manually supplied legacy jobs with merkle branches but no transaction data remain audit-only and produce an incomplete artifact.

When `run-mining-adapter` has `--block-candidate-dir`, every accepted submit that meets the advertised block target is also written as `block-<hash>.json` in that directory. Existing matching files are kept; different content at the same path is refused. The Pi wrapper enables this by default under `$POHW_DATADIR/block-candidates`, configurable with `POHW_STRATUM_BLOCK_CANDIDATE_DIR`.

Add `--auto-submit-blocks` only when the job coinbase and RPC target are ready for real block submission. A complete target-meeting candidate is sent to `submitblock` immediately; the result is logged, while an RPC rejection or transient error does not erase the accepted share or its candidate artifact. The Pi setting is the explicit opt-in `POHW_STRATUM_AUTO_SUBMIT_BLOCKS=true`.

Submit a complete target-meeting candidate to a local fork/testnet Bitcoin RPC:

```sh
cargo run -p p2pool-node -- submit-stratum-block-candidate \
  --candidate-file .pohw-p2pool/block-candidate.json \
  --rpc-cookie-file ~/.bitcoin/.cookie
```

The submit command refuses incomplete artifacts, candidates that do not meet the advertised block target, and Bitcoin mainnet RPC unless `--allow-mainnet-submit` is explicitly set.

For a LAN miner or rented hashrate endpoint, bind to the node IP and require a password file:

```sh
openssl rand -hex 24 > .pohw-p2pool/stratum.password
chmod 600 .pohw-p2pool/stratum.password

cargo run -p p2pool-node -- run-mining-adapter \
  --datadir .pohw-p2pool \
  --bind-addr <node-lan-ip>:3333 \
  --allow-non-loopback-stratum \
  --stratum-password-file .pohw-p2pool/stratum.password \
  --miner-id alice \
  --job-file ./mining-job.json \
  --idena-snapshot-id <snapshot-day-or-id> \
  --idena-snapshot-proof-root <32-byte-root-hex> \
  --mining-secret-key-file .pohw-p2pool/keys/alice/mining.key \
  --node-secret-key-file .pohw-p2pool/keys/alice/gossip-node.key
```

Use the password as the miner's Stratum password and firewall `3333/tcp` to the miner or rental provider IP when possible. Version rolling is intentionally rejected in this first adapter. The example job file is dry-run material; for live rehearsal set `POHW_STRATUM_BUILD_JOB_FROM_RPC=true` for a generic RPC job, or `POHW_STRATUM_BUILD_POHW_JOB_FROM_RPC=true` plus `POHW_STRATUM_PAYOUT_SCHEDULE_FILE` and `POHW_STRATUM_POHW_COMMITMENT_FILE` for a payout-aware job. Both wrapper modes now keep refreshing the job after startup.

Exercise the signed/encrypted DKG transport envelope demo:

```sh
cargo run -p p2pool-node -- demo-dkg-transport \
  --epoch-id 1
```

Build an Idena snapshot from local `idena-go`:

```sh
cargo run -p idena-lite-indexer -- snapshot-now \
  --api-key-file /mnt/ssd/idena/idena-data/api.key \
  --rpc-url http://127.0.0.1:9009 \
  --reward-events-file ./reward-events.json
```

Exact reward pipeline from official `idena-indexer`:

```sh
install -d -m 700 /mnt/ssd/pohw-p2pool/rewards
install -m 600 /dev/null /mnt/ssd/pohw-p2pool/rewards/idena-indexer-db.url
printf '%s\n' 'postgres://user:password@127.0.0.1:5432/idena_indexer' \
  > /mnt/ssd/pohw-p2pool/rewards/idena-indexer-db.url

python3 pohw_idena_rpc/idena_reward_indexer.py \
  --db /mnt/ssd/pohw-p2pool/rewards/reward_ledger.sqlite3 \
  sync-official-indexer \
  --database-url-file /mnt/ssd/pohw-p2pool/rewards/idena-indexer-db.url

python3 pohw_idena_rpc/idena_reward_indexer.py \
  --db /mnt/ssd/pohw-p2pool/rewards/reward_ledger.sqlite3 \
  export-replay \
  --latest-epoch \
  --require-exact \
  > /mnt/ssd/pohw-p2pool/rewards/reward-events.json
```

`sync-official-indexer` runs `scripts/pohw-export-idena-indexer-rewards.sql` against the official `idena-indexer` Postgres schema and imports exact StatsCollector-derived rewards from completed epochs. `export-replay --latest-epoch` selects one canonical epoch instead of accumulating all imported history. Set `IDENA_REWARD_EPOCH` to pin a specific epoch for reproducible backfills; otherwise the snapshot timer selects the latest canonical epoch. The snapshot timer can run the sync automatically when `IDENA_INDEXER_DATABASE_URL_FILE` or `IDENA_INDEXER_DATABASE_URL` is configured.

If local Postgres `idena-indexer` data is not available yet, import completed-epoch rewards from the official public Idena API:

```sh
python3 pohw_idena_rpc/idena_reward_indexer.py \
  --db /mnt/ssd/pohw-p2pool/rewards/reward_ledger.sqlite3 \
  sync-official-api \
  --completed-epochs 10
```

`sync-official-api` defaults to ten completed epochs so invitation liabilities can be reconstructed across their full clawback window. It imports exact validation/staking/session reward categories from `/Epoch/{epoch}/IdentityRewards`, aggregate epoch mining summaries from `/Address/{address}/MiningRewardSummaries`, and invitation/invitee credits plus later kill reversals into the liability ledger. Consensus scoring remains one epoch because the snapshot path exports only `--latest-epoch` (or the explicitly pinned `IDENA_REWARD_EPOCH`). Set `IDENA_OFFICIAL_API_SYNC=true` in the snapshot environment to let `pohw-idena-snapshot.service` run this fallback automatically when no Postgres URL is configured.

The first writable open of an existing large reward ledger after this upgrade builds a partial index over exact events and performs one canonical-source reconciliation. Keep the live indexer stopped for that migration and retain a database/WAL backup. Later starts and exact imports reconcile only the epochs they touch.

Build the snapshot registry ABI:

```sh
corepack pnpm@10.13.1 --dir contracts/idena-snapshot-registry install --frozen-lockfile
corepack pnpm@10.13.1 --dir contracts/idena-snapshot-registry build
corepack pnpm@10.13.1 --dir contracts/idena-snapshot-registry test
```

Propose a payout schedule:

```sh
cargo run -p p2pool-node -- propose-payout-schedule \
  --datadir .pohw-p2pool \
  --snapshot-file ./snapshot.json \
  --reward-sats 312500000 \
  --direct-limit 50
```

Confirm a mined fork block payout with Bitcoin Core:

```sh
cargo run -p p2pool-node -- confirm-payout-from-block \
  --datadir .pohw-p2pool \
  --snapshot-file ./snapshot.json \
  --payout-schedule-file ./payout-schedule.json \
  --pohw-commitment-file ./pohw-commitment.json \
  --rpc-cookie-file ~/.bitcoin/.cookie \
  --block-hash <fork-block-hash>
```

This verifies the coinbase outputs and `POHW1` commitment, then credits the replay log from the confirmed output total. Supplying `--reward-sats` is optional and must match the verified total.

Run the automatic confirmer:

```sh
mkdir -p .pohw-p2pool/payout-candidates
cat > .pohw-p2pool/payout-candidates/block-000001.json <<'JSON'
{
  "block_hash": "<fork-block-hash>",
  "snapshot_file": "../../snapshot.json",
  "payout_schedule_file": "../../payout-schedule.json",
  "pohw_commitment_file": "../../pohw-commitment.json",
  "min_confirmations": 100
}
JSON

cargo run -p p2pool-node -- run-payout-confirmer \
  --datadir .pohw-p2pool \
  --candidate-dir .pohw-p2pool/payout-candidates \
  --rpc-cookie-file ~/.bitcoin/.cookie
```

Use `--once` for a single scan. The confirmer does not trust the candidate file: it verifies Bitcoin Core block confirmations, coinbase outputs, the `POHW1` commitment, and local replay before appending `confirmed-payouts.ndjson`. Relative paths in a candidate are resolved from the candidate file directory.

Validate a vault input with Bitcoin Core:

```sh
cargo run -p p2pool-node -- validate-vault-input \
  --rpc-url http://127.0.0.1:8332 \
  --rpc-cookie-file ~/.bitcoin/.cookie \
  --txid <txid> \
  --vout 0 \
  --vault-key-xonly <xonly-taproot-internal-key>
```

Build a vault rotation plan after revalidating current-vault UTXOs:

```sh
cargo run -p p2pool-node -- build-validated-vault-rotation \
  --rpc-url http://127.0.0.1:8332 \
  --rpc-cookie-file ~/.bitcoin/.cookie \
  --current-vault-key-xonly <current-xonly-taproot-internal-key> \
  --next-vault-key-xonly <next-xonly-taproot-internal-key> \
  --outpoint <txid:vout> \
  --fee-sats 1000
```

Create a non-transferable withdrawal claim request:

```sh
cargo run -p p2pool-node -- create-withdrawal-request \
  --datadir .pohw-p2pool \
  --request-id alice-001 \
  --claim-owner-secret-key-file .pohw-p2pool/keys/alice/claim-owner.key \
  --destination-script-hex <p2tr-or-p2wpkh-scriptpubkey-hex> \
  --amount-sats 20000 \
  --max-fee-rate-sat-vb 5 \
  --nonce 1 \
  --expiry-height <fork-height> \
  --node-secret-key-file .pohw-p2pool/keys/alice/gossip-node.key \
  --append \
  --peer-addr <peer-lan-ip>:40406
```

Replay accepts a withdrawal request only after the claim owner key already has enough confirmed local vault-claim balance. This keeps unfunded or overdrawn requests out of the sharechain instead of letting them wait for future rewards.

Build the withdrawal spend plan and publish the pending batch before FROST signing:

```sh
cargo run -p p2pool-node -- build-withdrawal-spend-plan \
  --datadir .pohw-p2pool \
  --dkg-transcript-file ./current-vault-transcript.json \
  --request-id alice-001 \
  --outpoint <vault-funding-txid:vout> \
  --fee-rate-sat-vb 1 \
  --current-height <fork-height> \
  --rpc-cookie-file ~/.bitcoin/.cookie \
  --spend-plan-out ./withdrawal-plan.json \
  --node-secret-key-file .pohw-p2pool/keys/alice/gossip-node.key \
  --append \
  --peer-addr <peer-lan-ip>:40406
```

Every FROST signer must sync that `WithdrawalBatch` first. `frost-create-commitments` and `frost-sign-shares` refuse withdrawal plans unless local replay already reserved the exact batch and Bitcoin Core still sees the vault inputs.

Useful vault demos:

```sh
cargo run -p p2pool-node -- vault-threshold --signers 21
cargo run -p p2pool-node -- demo-vault-peer-dkg-sign \
  --signers 4 \
  --input-sats 100000 \
  --fee-sats 1000 \
  --allow-unsafe-demo-vault-signing
cargo run -p p2pool-node -- demo-dkg-transport --epoch-id 1
```

## Raspberry Pi

Expected layout:

```text
/mnt/ssd/p2pool              repository
/mnt/ssd/pohw-p2pool         P2Pool replay data and Idena snapshots
/mnt/ssd/idena/idena-data    idena-go data and API key
```

Install snapshot timer:

```sh
cargo build --release -p idena-lite-indexer
sudo install -d -m 700 -o ubuntu -g ubuntu /mnt/ssd/pohw-p2pool/snapshots
sudo cp deploy/systemd/pohw-idena-snapshot.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-idena-snapshot.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pohw-idena-snapshot.timer
```

Install gossip mesh, dashboard API, and optional mining adapter:

```sh
cargo build --release -p p2pool-node
corepack pnpm@10.13.1 --dir ui/pohw-dashboard install
corepack pnpm@10.13.1 --dir ui/pohw-dashboard build
sudo install -d -m 755 -o root -g root /etc/pohw
sudo install -m 600 -o root -g root deploy/pohw-experiment.env.example /etc/pohw/p2pool.env
sudoedit /etc/pohw/p2pool.env
sudo install -d -m 700 -o ubuntu -g ubuntu /mnt/ssd/pohw-p2pool
sudo install -d -m 700 -o ubuntu -g ubuntu /mnt/ssd/pohw-p2pool/dashboard-ui-cache
sudo install -d -m 700 -o ubuntu -g ubuntu /mnt/ssd/pohw-p2pool/health
sudo install -d -m 700 -o ubuntu -g ubuntu /mnt/ssd/pohw-p2pool/auto-bootstrap
openssl rand -hex 32 | sudo tee /etc/pohw/dashboard-api.token >/dev/null
openssl rand -hex 24 | sudo tee /etc/pohw/stratum.password >/dev/null
sudo chmod 640 /etc/pohw/dashboard-api.token /etc/pohw/stratum.password
sudo chown root:ubuntu /etc/pohw/dashboard-api.token /etc/pohw/stratum.password
sudo install -m 600 -o ubuntu -g ubuntu deploy/mining-adapter-job.example.json /mnt/ssd/pohw-p2pool/mining-job.example.json
sudo cp deploy/systemd/pohw-health-status.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-health-status.timer /etc/systemd/system/
sudo cp deploy/systemd/pohw-auto-bootstrap.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-auto-bootstrap.timer /etc/systemd/system/
sudo cp deploy/systemd/pohw-gossip-mesh.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-gossip-mesh-local-peer.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-dashboard-api.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-dashboard-ui.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-mining-adapter.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-fork-chain-node.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-dashboard-api-cookie-watch.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-dashboard-api-cookie-watch.path /etc/systemd/system/
sudo cp deploy/systemd/pohw-dashboard-api-cookie-watch@.path /etc/systemd/system/
sudo /opt/p2pool/scripts/pohw-install-pi-self-recovery.sh
sudo systemctl daemon-reload
sudo systemctl enable --now pohw-health-status.timer pohw-auto-bootstrap.timer pohw-gossip-mesh.service pohw-dashboard-api.service pohw-dashboard-ui.service pohw-dashboard-api-cookie-watch.path
```

Or reinstall only the self-recovery layer idempotently. It always enables the network watchdog, but installs the two resource guards without changing their enablement:

```sh
sudo /opt/p2pool/scripts/pohw-install-pi-self-recovery.sh
```

Opt into either resource guard or the post-sync worker watcher explicitly when its policy matches the current workload:

```sh
sudo POHW_INSTALL_ENABLE_IDENA_PRIORITY_GUARD=true \
  /opt/p2pool/scripts/pohw-install-pi-self-recovery.sh
sudo POHW_INSTALL_ENABLE_BITCOIN_PRESSURE_GUARD=true \
  /opt/p2pool/scripts/pohw-install-pi-self-recovery.sh
sudo POHW_INSTALL_ENABLE_IDENA_WORKERS_WATCHER=true \
  /opt/p2pool/scripts/pohw-install-pi-self-recovery.sh
```

The installer copies all root-run helpers to root-owned `/usr/local/libexec/pohw`, keeps their state under root-owned `/var/lib/pohw`, and enforces root ownership with mode `0600` on `/etc/pohw/p2pool.env`. Root services never execute scripts from the writable Git checkout.

Enable `pohw-mining-adapter.service` only after miner registration and snapshot fields are set in `/etc/pohw/p2pool.env`. For live rehearsal, set `POHW_STRATUM_BUILD_JOB_FROM_RPC=true` plus the local Bitcoin RPC cookie path for a generic RPC job, or set `POHW_STRATUM_BUILD_POHW_JOB_FROM_RPC=true` plus payout schedule and POHW commitment file paths for the payout-aware job. These modes refresh changed RPC jobs continuously; real `submitblock` calls remain disabled unless `POHW_STRATUM_AUTO_SUBMIT_BLOCKS=true`. The packaged `mining-job.example.json` is dry-run material; the Rust adapter refuses it unless `--allow-example-mining-job` is passed, and `scripts/pohw-run-mining-adapter.sh` only passes that flag when `POHW_ALLOW_EXAMPLE_MINING_JOB=true` is set explicitly for a local dry-run.

For Experiment 0 fork mining, start `pohw-fork-chain-node.service` first and set
`POHW_STRATUM_FORK_CHAIN_RPC_ADDR=127.0.0.1:40408`. Set
`POHW_ADMIT_PEER_WORK_TEMPLATES=true` when exchanging signed work templates with
other participants. This mode consumes live fork templates, validates peer work
through fork RPC, and submits target blocks only to fork RPC; it cannot be
combined with the Bitcoin RPC job-builder flags.

Use `/etc/pohw/p2pool.env` for Pi-specific paths, peer hints, allowed dashboard origins, Stratum settings, and local RPC cookie paths. The systemd helpers bind gossip, dashboard, and Stratum to loopback unless you explicitly expose them. For trusted WLAN access, bind to the Pi WLAN IP instead of all interfaces:

```sh
POHW_SNAPSHOT_DIR=/mnt/ssd/pohw-p2pool/snapshots
POHW_GOSSIP_BIND_ADDR=<pi-wlan-ip>:40406
POHW_PEER_ADDRS=<peer-host-or-ip>:40406
POHW_LOCAL_GOSSIP_BIND_ADDR=<pi-wlan-ip>:40416
POHW_LOCAL_GOSSIP_ADVERTISE_ADDR=<pi-wlan-ip>:40416
POHW_LOCAL_GOSSIP_PEER_ADDRS=<pi-wlan-ip>:40406
POHW_DASHBOARD_ALLOW_NON_LOOPBACK=true
POHW_DASHBOARD_BIND_ADDR=<pi-wlan-ip>:40407
POHW_DASHBOARD_API_TOKEN_FILE=/etc/pohw/dashboard-api.token
POHW_DASHBOARD_ALLOWED_ORIGINS=http://127.0.0.1:5176,http://localhost:5176
POHW_DASHBOARD_UI_BIND_HOST=127.0.0.1
POHW_DASHBOARD_UI_PORT=5176
POHW_DASHBOARD_UI_API_URL=http://127.0.0.1:40407/dashboard.json
POHW_DASHBOARD_UI_CACHE_DIR=/mnt/ssd/pohw-p2pool/dashboard-ui-cache
POHW_DASHBOARD_IDENA_ADDRESS=0x...
POHW_IDENA_DATADIR=/mnt/ssd/idena/idena-data
POHW_HEALTH_IDENA_MIN_PEERS=3
POHW_HEALTH_STATUS_FILE=/mnt/ssd/pohw-p2pool/health/status.json
POHW_AUTO_BOOTSTRAP_DIR=/mnt/ssd/pohw-p2pool/auto-bootstrap
POHW_AUTO_BOOTSTRAP_OUTPUT_ROOT=/mnt/ssd/pohw-p2pool/output
POHW_AUTO_BOOTSTRAP_APPEND=true
POHW_AUTO_BOOTSTRAP_LOCK_STALE_SECONDS=3600
POHW_NETWORK_WATCHDOG_STATE_DIR=/var/lib/pohw/network-watchdog
POHW_NETWORK_WATCHDOG_TARGETS=
POHW_NETWORK_WATCHDOG_RESTART_THRESHOLD=3
POHW_NETWORK_WATCHDOG_REBOOT_THRESHOLD=8
POHW_NETWORK_WATCHDOG_LOCK_STALE_SECONDS=300
POHW_NETWORK_WATCHDOG_DRY_RUN=false
POHW_IDENA_PRIORITY_STATE_DIR=/var/lib/pohw/idena-priority
POHW_IDENA_PRIORITY_LEAD_SECONDS=3600
POHW_IDENA_PRIORITY_COOLDOWN_SECONDS=1800
POHW_IDENA_PRIORITY_RESTORE_BITCOIN=true
POHW_IDENA_PRIORITY_FORCE=false
POHW_IDENA_PRIORITY_DRY_RUN=false
POHW_BITCOIN_PRESSURE_STATE_DIR=/var/lib/pohw/bitcoin-pressure
POHW_BITCOIN_PRESSURE_HIGH_IOWAIT_PERCENT=40
POHW_BITCOIN_PRESSURE_HIGH_UTIL_PERCENT=85
POHW_BITCOIN_PRESSURE_LOW_IOWAIT_PERCENT=20
POHW_BITCOIN_PRESSURE_LOW_UTIL_PERCENT=60
POHW_BITCOIN_PRESSURE_HIGH_STREAK=2
POHW_BITCOIN_PRESSURE_LOW_STREAK=3
POHW_BITCOIN_PRESSURE_COOLDOWN_SECONDS=1800
POHW_BITCOIN_PRESSURE_RESTORE_BITCOIN=true
POHW_BITCOIN_PRESSURE_STOP_WHEN_MINING_READY=false
POHW_BITCOIN_PRESSURE_FORCE=false
POHW_BITCOIN_PRESSURE_DRY_RUN=false
POHW_TAILSCALE_CONFIGURE_UFW=true
POHW_TAILSCALE_UFW_INTERFACE=tailscale0
POHW_STRATUM_BIND_ADDR=<pi-wlan-ip>:3333
POHW_STRATUM_ALLOW_NON_LOOPBACK=true
POHW_STRATUM_PASSWORD_FILE=/etc/pohw/stratum.password
POHW_STRATUM_JOB_FILE=/mnt/ssd/pohw-p2pool/mining-job.json
POHW_STRATUM_BLOCK_CANDIDATE_DIR=/mnt/ssd/pohw-p2pool/block-candidates
POHW_IDENA_SNAPSHOT_ID=<snapshot-day-or-id>
POHW_IDENA_SNAPSHOT_PROOF_ROOT=<32-byte-root-hex>
```

Keep `POHW_DASHBOARD_UI_BIND_HOST` on loopback when the participant dashboard
is enabled. Its generated browser configuration contains the dashboard API
token, so the runner refuses to expose participant mode on a non-loopback UI.
Use SSH forwarding for remote participant access. A public explorer must set
`POHW_DASHBOARD_UI_PARTICIPANT_ENABLED=false` and never embeds that token.

Set `POHW_DASHBOARD_ALLOWED_ORIGINS` to the browser UI origin you actually use, for example `http://<pi-wlan-ip>:5176` if the UI is served from the Pi.

`pohw-gossip-mesh-local-peer.service` is optional. It runs a second local gossip
node with its own datadir so a single Pi can exercise peer inventory, sync, and
rebroadcast plumbing. Bind it to the specific Pi LAN IP instead of `0.0.0.0`,
and keep it off public interfaces. For real multi-node testing, replace
`POHW_PEER_ADDRS` with actual trusted participant peers and disable the local
test peer.

For remote workstation access, prefer SSH forwarding instead of non-loopback dashboard binds:

```sh
scripts/pohw-dashboard-tunnel.sh <pi-ssh-host>
open http://127.0.0.1:5176/
```

This requires SSH reachability to the Pi. Away from home, use a private VPN such as WireGuard/Tailscale, or expose only SSH with key auth and firewalling; do not expose `5176` or `40407` directly.

For holiday-safe access from changing networks, use Tailscale instead of router port forwarding:

```sh
# On the Mac: install Tailscale from https://tailscale.com/download and sign in.
# On the Pi, create a reusable or ephemeral auth key in the Tailscale admin UI,
# paste it into a protected local file, then install/connect:
sudo install -d -m 700 /etc/pohw
sudo install -m 600 -o root -g root /dev/null /etc/pohw/tailscale.authkey
sudo python3 - <<'PY'
import getpass
import os
from pathlib import Path

path = Path("/etc/pohw/tailscale.authkey")
key = getpass.getpass("Paste Tailscale auth key: ").strip()
if not key.startswith("tskey-"):
    raise SystemExit("Tailscale auth key should start with tskey-")
path.write_text(key + "\n", encoding="utf-8")
os.chmod(path, 0o600)
PY
sudo POHW_TAILSCALE_AUTHKEY_FILE=/etc/pohw/tailscale.authkey \
  /mnt/ssd/p2pool/scripts/pohw-install-tailscale-remote-access.sh
```

The installer also adds an SSH allow rule on `tailscale0` when UFW is present. Set `POHW_TAILSCALE_CONFIGURE_UFW=false` only if another firewall policy already permits Tailscale SSH.

Tailscale SSH policy can require a periodic browser identity check. For unattended key-based access, optionally publish the Pi's existing OpenSSH daemon on a separate tailnet-only TCP port:

```sh
sudo POHW_TAILSCALE_ENABLE_KEY_SSH_SERVE=true \
  POHW_TAILSCALE_KEY_SSH_SERVE_PORT=2222 \
  /mnt/ssd/p2pool/scripts/pohw-install-tailscale-remote-access.sh

ssh -p 2222 ubuntu@pibtc
POHW_PI_SSH_PORT=2222 scripts/pohw-dashboard-tunnel.sh ubuntu@pibtc
```

This fallback still requires an authorized Tailscale device and the OpenSSH private key. Before enabling it, the installer verifies that public-key authentication is enabled, password and keyboard-interactive authentication are disabled, root login is disabled, and the configured user is allowed. Tailscale Serve keeps port `2222` inside the tailnet; do not add a router-forward or public UFW rule for it.

After both the Mac and Pi are in the same tailnet, SSH and the dashboard tunnel work from any IP range:

```sh
ssh ubuntu@pibtc
scripts/pohw-dashboard-tunnel.sh ubuntu@pibtc
open http://127.0.0.1:5176/
```

If MagicDNS is disabled in Tailscale, replace `pibtc` with the Pi's `100.x.y.z` Tailscale IPv4 from `tailscale ip -4`. Keep the Tailscale auth key out of Git and delete it from `/etc/pohw/tailscale.authkey` after the Pi is connected if it is not reusable.

For a vacation-safe command-line status that avoids keys, cookies, addresses, and blockchain data, use the health monitor summary:

```sh
ssh <pi-ssh-host> '/usr/bin/python3 /opt/p2pool/scripts/pohw-health-status.py --format summary'
```

The legacy SSD timer writes the same sanitized state to `/mnt/ssd/pohw-p2pool/health/status.json`. Bootstrap and Stratum RPC-job refresh use `POHW_HEALTH_STATUS_FILE` when it exists, so they stop before calling Bitcoin RPC while the health state says Bitcoin is still in IBD, `NODE_NETWORK_LIMITED`, RPC timeout, or `getblocktemplate` failure. The health monitor also reports warning-only Idena P2P state from local config/log files, including active IPFS port drift and consensus-loop peer counts below `POHW_HEALTH_IDENA_MIN_PEERS`. If the summary reports `idena_ipfs_port_drift`, allow and router-forward the reported active port, or restart Idena during a non-validation window to return to the configured port.

On the SD-card runtime, the sanitized health state is stored at `/var/lib/pohw-p2pool/health/status.json`. `pohw-idena-workers-if-synced.timer` is an explicit opt-in that checks `bcn_syncing` every two minutes and starts only `idena-reward-indexer.service` and `idena-session-recorder.service` after the local node reaches the reported head with a valid clock. It never starts `idena.service`, so an operator pause remains in effect. Its secret-free status is `/var/lib/pohw/idena-workers/status.json`.

For an SD-only Pi that consumes Bitcoin from the Hetzner host, install the
persistent load guard:

```sh
sudo scripts/pohw-install-pi-load-guard.sh
```

It caps Idena at 2.5 CPU cores, starts 1 GB of compressed RAM swap without SD
writes, keeps 1 GB of RAM available to the operating system through cgroup
memory limits, disables Bitcoin restart timers, and blocks local Bitcoin Core
unless `/etc/pohw/enable-local-bitcoin` is deliberately created. Re-enable a
local Core only as an explicit maintenance action:

```sh
sudo touch /etc/pohw/enable-local-bitcoin
sudo systemctl daemon-reload
sudo systemctl enable --now bitcoind-mainnet.service
```

`pohw-auto-bootstrap.timer` checks the health file once per minute and runs `scripts/pohw-bootstrap-readiness.sh --mode real` once after the health monitor reports `miningReady=true`. Successful bootstrap writes `/mnt/ssd/pohw-p2pool/auto-bootstrap/bootstrap.done.json`; remove that marker only if you intentionally want another automatic bootstrap run.

`pohw-network-watchdog.timer` is the host self-recovery layer for cases where the Pi stays powered but disappears from the LAN. By default it pings the current default gateway once per minute, restarts the active network manager after 3 failed checks, and requests a reboot after 8 failed checks. A missing default route now follows those same thresholds instead of stalling in a diagnostic-only state. Set `POHW_NETWORK_WATCHDOG_TARGETS` to comma-separated stable targets if the default gateway is not enough for your network. The timer writes secret-free state to `/var/lib/pohw/network-watchdog/status.json`.

`pohw-idena-priority-guard.timer` protects validation/flip sessions from Bitcoin background validation load. It checks local `dna_epoch` once per minute, stops `bitcoind-mainnet.service` when the current Idena period looks like a flip, short, long, or validation period, or when `nextValidation` is inside `POHW_IDENA_PRIORITY_LEAD_SECONDS`, and restarts Bitcoin after `POHW_IDENA_PRIORITY_COOLDOWN_SECONDS` only if the guard stopped it itself. It does not depend on or start `idena.service`, so an operator pause remains a pause. The default lead is 1 hour and the default cooldown is 30 minutes. For an emergency manual pause, set `POHW_IDENA_PRIORITY_FORCE=true` in `/etc/pohw/p2pool.env` and restart the timer service; set it back to `false` after validation.

```sh
sudo systemctl start pohw-idena-priority-guard.service
sudo cat /var/lib/pohw/idena-priority/status.json
```

`pohw-bitcoin-pressure-guard.timer` is an optional last-resort protection against harmful Bitcoin background-validation I/O pressure. High disk utilization alone no longer trips it: pressure requires both high iowait and utilization, or critical utilization combined with high read/write latency, for `POHW_BITCOIN_PRESSURE_HIGH_STREAK` checks. It restarts Bitcoin after `POHW_BITCOIN_PRESSURE_COOLDOWN_SECONDS` once iowait, utilization, and latency remain below their low thresholds for `POHW_BITCOIN_PRESSURE_LOW_STREAK` checks. By default it will not stop Bitcoin after the health monitor reports `miningReady=true`, and the installer does not enable this timer without explicit opt-in.

```sh
sudo systemctl start pohw-bitcoin-pressure-guard.service
sudo cat /var/lib/pohw/bitcoin-pressure/status.json
```

The hardware watchdog config in `deploy/systemd/system.conf.d/10-pohw-watchdog.conf` lets systemd feed the Raspberry Pi watchdog device. After the next reboot, the host should reboot itself if PID 1 or the kernel stops scheduling long enough that the watchdog is no longer fed. Check support with:

```sh
ls -l /dev/watchdog*
systemctl show -p RuntimeWatchdogUSec -p RebootWatchdogUSec
```

The default cookie watcher assumes `BITCOIN_RPC_COOKIE_FILE=/mnt/ssd/bitcoin/bitcoin-core-mainnet/.cookie`. If you use a different Bitcoin cookie path, enable the templated watcher for that path instead:

```sh
COOKIE_UNIT="$(systemd-escape --path "$BITCOIN_RPC_COOKIE_FILE")"
sudo systemctl disable --now pohw-dashboard-api-cookie-watch.path
sudo systemctl enable --now "pohw-dashboard-api-cookie-watch@${COOKIE_UNIT}.path"
```

Install host hardening drop-ins after Bitcoin Core and idena-go are already configured:

```sh
sudo install -d -m 755 /etc/ssh/sshd_config.d /etc/systemd/system/bitcoind-mainnet.service.d /etc/systemd/system/idena.service.d
sudo install -m 644 deploy/ssh/sshd-pohw-hardening.conf /etc/ssh/sshd_config.d/99-pohw-hardening.conf
sudo install -m 644 deploy/systemd/bitcoind-mainnet-hardening.conf /etc/systemd/system/bitcoind-mainnet.service.d/30-hardening.conf
sudo install -m 644 deploy/systemd/bitcoind-mainnet-runtime.conf /etc/systemd/system/bitcoind-mainnet.service.d/50-runtime.conf
sudo install -m 644 deploy/systemd/bitcoind-mainnet-resource.conf /etc/systemd/system/bitcoind-mainnet.service.d/60-resource.conf
sudo install -m 644 deploy/systemd/idena-hardening.conf /etc/systemd/system/idena.service.d/30-hardening.conf
sudo sshd -t
sudo systemctl daemon-reload
```

For a Pi with Bitcoin Core on `/mnt/ssd`, start from `deploy/bitcoin/bitcoin-mainnet.conf.example` and copy only non-secret settings into the live `bitcoin.conf`. The template keeps RPC local-only, keeps a full unpruned chain for fork/testing work, and uses `dbcache=1536` for a 4 GiB Pi to reduce SSD pressure during AssumeUTXO background validation. The `60-resource.conf` drop-in lowers Bitcoin CPU/I/O priority so Idena and PoHW control services stay responsive while background validation runs. Reduce `dbcache` if the host shows real memory pressure.

### Dedicated Bitcoin Disk

For a split-disk Pi, keep the repository, Idena, and PoHW state under `/mnt/ssd`, and mount the Bitcoin disk separately at `/mnt/bitcoin-wd`. Use a filesystem UUID in the Pi's local `/etc/fstab`; do not commit the UUID or a `/dev/sdX` name. A suitable local entry is:

```text
UUID=REPLACE_WITH_LOCAL_UUID /mnt/bitcoin-wd ext4 defaults,noatime,nofail,x-systemd.automount,x-systemd.device-timeout=30s 0 2
```

Before allowing a newer Bitcoin Core version to write an older datadir, stop Core and preserve at least `chainstate`, `blocks/index`, the live configuration, and the mutable tail of `blk*.dat`/`rev*.dat`. Keep the previous Bitcoin disk unchanged until the replacement node has survived a clean restart. The dedicated datadir used by the supplied drop-ins is `/mnt/bitcoin-wd/bitcoin/bitcoin-core-mainnet`.

Install the dedicated-disk overrides after the standard hardening/runtime drop-ins:

```sh
sudo install -d -m 755 \
  /etc/systemd/system/bitcoind-mainnet.service.d \
  /etc/systemd/system/pohw-auto-bootstrap.service.d \
  /etc/systemd/system/pohw-dashboard-api.service.d \
  /etc/systemd/system/pohw-health-status.service.d
sudo install -m 644 deploy/systemd/bitcoind-mainnet-wd.conf \
  /etc/systemd/system/bitcoind-mainnet.service.d/70-wd-datadir.conf
sudo install -m 644 deploy/systemd/bitcoind-mainnet-sync-priority.conf \
  /etc/systemd/system/bitcoind-mainnet.service.d/80-sync-priority.conf
for service in pohw-auto-bootstrap pohw-dashboard-api pohw-health-status; do
  sudo install -m 644 deploy/systemd/pohw-bitcoin-wd-readonly.conf \
    "/etc/systemd/system/${service}.service.d/50-bitcoin-wd.conf"
done
```

Archive any older drop-in that still adds `RequiresMountsFor=/mnt/ssd` to `bitcoind-mainnet.service`; systemd dependencies from that file cannot be removed by a later drop-in. Set these three path-only values in `/etc/pohw/p2pool.env`, preserving all other protected values:

```text
POHW_BITCOIN_DATADIR=/mnt/bitcoin-wd/bitcoin/bitcoin-core-mainnet
POHW_BITCOIN_RPC_COOKIE_FILE=/mnt/bitcoin-wd/bitcoin/bitcoin-core-mainnet/.cookie
BITCOIN_RPC_COOKIE_FILE=/mnt/bitcoin-wd/bitcoin/bitcoin-core-mainnet/.cookie
```

Use the templated cookie watcher for the new location. The watcher intentionally has no `Wants=` or `After=` dependency on runtime services; adding those dependencies can pull Bitcoin and the dashboard into `paths.target` and create a boot ordering cycle.

```sh
sudo install -m 644 deploy/systemd/pohw-dashboard-api-cookie-watch@.path /etc/systemd/system/
sudo systemctl disable --now pohw-dashboard-api-cookie-watch.path
COOKIE_UNIT="$(systemd-escape --path /mnt/bitcoin-wd/bitcoin/bitcoin-core-mainnet/.cookie)"
sudo systemctl daemon-reload
sudo systemctl enable --now "pohw-dashboard-api-cookie-watch@${COOKIE_UNIT}.path"
sudo systemd-analyze verify bitcoind-mainnet.service "pohw-dashboard-api-cookie-watch@${COOKIE_UNIT}.path"
sudo systemctl enable --now bitcoind-mainnet.service
```

During an intentional Bitcoin-only sync window, the `80-sync-priority.conf` override cancels the normal Idena-friendly CPU/I/O de-prioritization. Keep Idena and both priority/pressure guard timers disabled during that window. Remove the override and reload systemd before resuming Idena:

```sh
sudo rm /etc/systemd/system/bitcoind-mainnet.service.d/80-sync-priority.conf
sudo systemctl daemon-reload
```

Validate the migration with a clean reboot. The acceptance checks are: both mounts are read-write, `bitcoind-mainnet.service` starts without restarts from the dedicated datadir, Idena remains in the intended state, the cookie watcher and dashboard are active, and the tailnet SSH path returns after boot.

If UFW is enabled, expose only the intended ports:

```sh
sudo ufw allow in on wlan0 from <trusted-lan-cidr> to any port 22 proto tcp comment "SSH WLAN only"
sudo ufw allow in on wlan0 from <trusted-lan-cidr> to any port 40406 proto tcp comment "PoHW P2Pool gossip LAN"
sudo ufw allow in on wlan0 from <trusted-mac-ip> to any port 40407 proto tcp comment "PoHW dashboard API trusted client only"
sudo ufw allow in on wlan0 from <miner-or-rental-ip> to any port 3333 proto tcp comment "PoHW Stratum trusted miner only"
sudo ufw allow in on wlan0 to any port 8333 proto tcp comment "Bitcoin mainnet P2P"
sudo ufw allow in on wlan0 to any port 40405 proto tcp comment "Idena P2P active port"
sudo ufw allow in on tailscale0 to any port 22 proto tcp comment "SSH over Tailscale"
```

## Reward And Payout Rules

- Reward weight = 50% Bitcoin hashrate score + 50% Idena score.
- Idena score includes validation, mining, proposer, and final committee rewards.
- Idena score excludes invitation, generic contract, and oracle rewards unless explicitly added later.
- Accounting credits the identity that earned the reward.
- Direct payouts require at least `10_000 sats`.
- The direct payout count is configurable; the current default is 100.
- Everything else goes to the current FROST vault as a non-transferable withdrawal claim.

## FROST Vault Model

- Signer membership is dynamic per weekly epoch.
- Each epoch runs its own DKG and creates one Taproot vault key.
- Threshold is `ceil(0.67 * n)` for that epoch.
- New signers join the next epoch, not an existing vault key.
- Signers must replay the ledger and revalidate vault inputs before releasing signature shares.

## Security Boundaries

Do not use real funds.

Important boundaries:

- The dashboard is not an authority.
- Sharechain logs and indexes are local replay artifacts.
- Gossip peers forward signed messages, but every node still verifies locally.
- Non-loopback dashboard API mode requires a strong token and explicit allowed origins.
- RPC URLs are loopback-only by default.
- Do not use size-only verified Bitcoin chainstate snapshots. If using AssumeUTXO, import through Bitcoin Core so the built-in snapshot metadata/hash is validated.
- The project intentionally has no transferable iBTC token, no user BTC deposits, and no secondary-market claim object.
- Replay protection is required before inherited Bitcoin UTXO spending can be meaningful on a fork.

## Checks

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 -m unittest discover -s pohw_idena_rpc/tests -p 'test_*.py' -v
corepack pnpm@10.13.1 --dir ui/pohw-dashboard build
corepack pnpm@10.13.1 --dir contracts/idena-snapshot-registry test
bash -n scripts/*.sh
gitleaks git . --redact
```

## License

MIT. See [`LICENSE`](LICENSE).
