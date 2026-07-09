# P2poolBTC

P2poolBTC is a no-value Bitcoin P2Pool-style experiment with Idena proof-of-human-work accounting.
It explores a voluntary mining layer where every node can replay the same sharechain, Idena snapshots, reward scores, payout schedules, and vault claims locally.

Bitcoin and Idena stay unchanged. This repo builds the experimental coordination layer between them.

The idea is simple:

- Bitcoin hashrate still mines the block.
- Idena human-work history adds a second reward signal.
- Pool rewards are split 50/50 between hashrate score and Idena reward-accounting score.
- Large unpaid balances can be paid directly in the coinbase.
- Smaller balances become non-transferable withdrawal claims against a weekly FROST vault epoch.

This repo is not a production Bitcoin node, not a token bridge, and not ready for real funds.

## Preview

These screenshots use demo data only; they show the user flow, not live payout claims.

![P2poolBTC dashboard overview](docs/assets/dashboard-overview.png)

<p align="center">
  <img src="docs/assets/dashboard-mobile.png" alt="P2poolBTC mobile dashboard overview" width="360">
</p>

![PoHW pool flow: solve flips, join p2pool, mine Bitcoin, decentralize Bitcoin mining](docs/assets/pohw-flow.png)

## Start Here

If you want to help test, start with [Beta Testing P2poolBTC](BETA-TESTING.md). It explains the tester roles, the safety boundaries, and the shortest path to a first report bundle.

Use [Experiment 0](EXPERIMENT-0.md) as the detailed operator runbook once you are ready to run a multi-node test.

## Status

Working prototype pieces:

- deterministic `POHW1` commitment model,
- reproducible Bitcoin-mainnet-history fork activation manifest generation,
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
- Vite/React dashboard focused on pledge status, hashrate share, Idena share, and block-found payout estimate,
- Raspberry Pi systemd helpers for snapshots, gossip mesh, dashboard API, and dashboard UI.

Not done yet:

- full fork-chain consensus node,
- post-fork block-template builder and custom DAA implementation,
- live Bitcoin block-template builder wired into the mining adapter,
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
| Mining adapter | `127.0.0.1:3333` | Local Stratum v1 frontend |
| Dashboard UI | `127.0.0.1:5176` | Browser UI, tunnel from a workstation |
| Dashboard API | `127.0.0.1:40407` | Read-only local status |
| Dashboard dev server | Vite | Local frontend development |
| Idena RPC | `http://127.0.0.1:9009` | Local `idena-go` source |
| Bitcoin RPC | `http://127.0.0.1:8332` | Local Bitcoin Core source |
| Sharechain data | `.pohw-p2pool/` or `/mnt/ssd/pohw-p2pool` | Local replay logs |
| Snapshots | `./snapshots/` or `/mnt/ssd/pohw-p2pool/snapshots` | Verified Idena snapshot JSON |

Keep Bitcoin and Idena RPC on loopback. Expose gossip, dashboard, or Stratum only to trusted peers, with firewall rules. Non-loopback dashboard needs a token; non-loopback Stratum needs a protected password file.

## Community Experiment

Start with [Beta Testing P2poolBTC](BETA-TESTING.md) when multiple people help. It gives a shorter, more welcoming path for observers, gossip testers, Idena testers, and Bitcoin testers.

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
pnpm --dir ui/pohw-dashboard install
pnpm --dir ui/pohw-dashboard dev
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
pnpm --dir ui/pohw-dashboard dev
```

Keep the Vite UI bound to loopback. `VITE_POHW_DASHBOARD_API_TOKEN` is visible to that browser session.

The dashboard intentionally shows an offline state if the local API is unavailable. Demo data is opt-in:

```sh
VITE_POHW_DASHBOARD_DEMO=true pnpm --dir ui/pohw-dashboard dev
```

## Core Commands

Prepare a no-value fork/testnet activation manifest from local Bitcoin Core:

```sh
cargo run -p p2pool-node -- prepare-fork-activation \
  --chain-name pohw-experiment-0 \
  --launch-timestamp-utc 2026-07-05T00:00:00Z \
  --rpc-cookie-file ~/.bitcoin/.cookie \
  --manifest-out ./fork-activation.json
```

The command derives the first Bitcoin mainnet block at or after the launch timestamp, records the inherited parent tip, resets post-fork difficulty to testnet-safe `0x207fffff` by default, and emits an `activation_id`. Every participant should compare the same `fork-activation.json` before mining. Inherited-mainnet UTXO spending remains disabled unless `--inherited-utxo-spending-enabled` is explicitly set, and it should stay disabled until replay protection exists.

For Experiment 0, set `POHW_FORK_LAUNCH_TIMESTAMP_UTC` in `.pohw-experiment.env` and use the wrapper:

```sh
scripts/pohw-experiment-prepare-fork-activation.sh .pohw-experiment.env
```

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
When using `--replace`, keep the job file in a private node directory that is not group/world writable.

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

The artifact contains the exact coinbase tx, header, block hash, target check, and `block_hex` when the job has no non-coinbase transaction branches. If the job has merkle branches, the artifact stays useful for audit but marks `block_hex` incomplete because Stratum jobs do not carry raw non-coinbase transaction data.

When `run-mining-adapter` has `--block-candidate-dir`, every accepted submit that meets the advertised block target is also written as `block-<hash>.json` in that directory. Existing matching files are kept; different content at the same path is refused. The Pi wrapper enables this by default under `$POHW_DATADIR/block-candidates`, configurable with `POHW_STRATUM_BLOCK_CANDIDATE_DIR`.

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

Use the password as the miner's Stratum password and firewall `3333/tcp` to the miner or rental provider IP when possible. Version rolling is intentionally rejected in this first adapter. The example job file is dry-run material; for live rehearsal set `POHW_STRATUM_BUILD_JOB_FROM_RPC=true` for a generic RPC job, or `POHW_STRATUM_BUILD_POHW_JOB_FROM_RPC=true` plus `POHW_STRATUM_PAYOUT_SCHEDULE_FILE` and `POHW_STRATUM_POHW_COMMITMENT_FILE` for a payout-aware job.

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
  --require-exact \
  > /mnt/ssd/pohw-p2pool/rewards/reward-events.json
```

`sync-official-indexer` runs `scripts/pohw-export-idena-indexer-rewards.sql` against the official `idena-indexer` Postgres schema, imports only exact StatsCollector-derived validation/mining reward events, and keeps invitation/contract/oracle rewards excluded from eligible replay. The snapshot timer can run the sync automatically when `IDENA_INDEXER_DATABASE_URL_FILE` or `IDENA_INDEXER_DATABASE_URL` is configured.

If local Postgres `idena-indexer` data is not available yet, import completed-epoch rewards from the official public Idena API:

```sh
python3 pohw_idena_rpc/idena_reward_indexer.py \
  --db /mnt/ssd/pohw-p2pool/rewards/reward_ledger.sqlite3 \
  sync-official-api \
  --completed-epochs 1
```

`sync-official-api` defaults to the previous completed epoch. It imports exact validation/staking/session reward categories from `/Epoch/{epoch}/IdentityRewards`, imports aggregate epoch mining summaries from `/Address/{address}/MiningRewardSummaries`, and records invitation/invitee rewards as ignored replay events. Set `IDENA_OFFICIAL_API_SYNC=true` in the snapshot environment to let `pohw-idena-snapshot.service` run this fallback automatically when no Postgres URL is configured.

Build the snapshot registry ABI:

```sh
pnpm --dir contracts/idena-snapshot-registry install --frozen-lockfile
pnpm --dir contracts/idena-snapshot-registry build
pnpm --dir contracts/idena-snapshot-registry test
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
pnpm --dir ui/pohw-dashboard install
pnpm --dir ui/pohw-dashboard build
sudo install -d -m 700 -o ubuntu -g ubuntu /etc/pohw /mnt/ssd/pohw-p2pool
sudo install -d -m 700 -o ubuntu -g ubuntu /mnt/ssd/pohw-p2pool/dashboard-ui-cache
sudo install -d -m 700 -o ubuntu -g ubuntu /mnt/ssd/pohw-p2pool/health
sudo install -d -m 700 -o ubuntu -g ubuntu /mnt/ssd/pohw-p2pool/auto-bootstrap
sudo install -d -m 700 -o root -g root /mnt/ssd/pohw-p2pool/network-watchdog
sudo install -d -m 700 -o root -g root /mnt/ssd/pohw-p2pool/idena-priority
openssl rand -hex 32 | sudo tee /etc/pohw/dashboard-api.token >/dev/null
openssl rand -hex 24 | sudo tee /etc/pohw/stratum.password >/dev/null
sudo chmod 600 /etc/pohw/dashboard-api.token
sudo chmod 600 /etc/pohw/stratum.password
sudo chown ubuntu:ubuntu /etc/pohw/dashboard-api.token /etc/pohw/stratum.password
sudo install -m 600 -o ubuntu -g ubuntu deploy/mining-adapter-job.example.json /mnt/ssd/pohw-p2pool/mining-job.example.json
sudo cp deploy/systemd/pohw-health-status.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-health-status.timer /etc/systemd/system/
sudo cp deploy/systemd/pohw-auto-bootstrap.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-auto-bootstrap.timer /etc/systemd/system/
sudo cp deploy/systemd/pohw-network-watchdog.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-network-watchdog.timer /etc/systemd/system/
sudo cp deploy/systemd/pohw-idena-priority-guard.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-idena-priority-guard.timer /etc/systemd/system/
sudo cp deploy/systemd/pohw-gossip-mesh.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-gossip-mesh-local-peer.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-dashboard-api.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-dashboard-ui.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-mining-adapter.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-dashboard-api-cookie-watch.service /etc/systemd/system/
sudo cp deploy/systemd/pohw-dashboard-api-cookie-watch.path /etc/systemd/system/
sudo cp deploy/systemd/pohw-dashboard-api-cookie-watch@.path /etc/systemd/system/
sudo install -d -m 755 /etc/systemd/system.conf.d
sudo cp deploy/systemd/system.conf.d/10-pohw-watchdog.conf /etc/systemd/system.conf.d/
sudo systemctl daemon-reload
sudo systemctl enable --now pohw-health-status.timer pohw-auto-bootstrap.timer pohw-network-watchdog.timer pohw-idena-priority-guard.timer pohw-gossip-mesh.service pohw-dashboard-api.service pohw-dashboard-ui.service pohw-dashboard-api-cookie-watch.path
```

Or install only the self-recovery layer idempotently:

```sh
sudo /mnt/ssd/p2pool/scripts/pohw-install-pi-self-recovery.sh
```

Enable `pohw-mining-adapter.service` only after miner registration and snapshot fields are set in `/etc/pohw/p2pool.env`. For live rehearsal, set `POHW_STRATUM_BUILD_JOB_FROM_RPC=true` plus the local Bitcoin RPC cookie path for a generic RPC job, or set `POHW_STRATUM_BUILD_POHW_JOB_FROM_RPC=true` plus payout schedule and POHW commitment file paths for the payout-aware job. The packaged `mining-job.example.json` is dry-run material; the Rust adapter refuses it unless `--allow-example-mining-job` is passed, and `scripts/pohw-run-mining-adapter.sh` only passes that flag when `POHW_ALLOW_EXAMPLE_MINING_JOB=true` is set explicitly for a local dry-run.

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
POHW_HEALTH_STATUS_FILE=/mnt/ssd/pohw-p2pool/health/status.json
POHW_AUTO_BOOTSTRAP_DIR=/mnt/ssd/pohw-p2pool/auto-bootstrap
POHW_AUTO_BOOTSTRAP_OUTPUT_ROOT=/mnt/ssd/pohw-p2pool/output
POHW_AUTO_BOOTSTRAP_APPEND=true
POHW_AUTO_BOOTSTRAP_LOCK_STALE_SECONDS=3600
POHW_NETWORK_WATCHDOG_STATE_DIR=/mnt/ssd/pohw-p2pool/network-watchdog
POHW_NETWORK_WATCHDOG_TARGETS=
POHW_NETWORK_WATCHDOG_RESTART_THRESHOLD=3
POHW_NETWORK_WATCHDOG_REBOOT_THRESHOLD=8
POHW_NETWORK_WATCHDOG_LOCK_STALE_SECONDS=300
POHW_NETWORK_WATCHDOG_DRY_RUN=false
POHW_IDENA_PRIORITY_STATE_DIR=/mnt/ssd/pohw-p2pool/idena-priority
POHW_IDENA_PRIORITY_LEAD_SECONDS=3600
POHW_IDENA_PRIORITY_COOLDOWN_SECONDS=1800
POHW_IDENA_PRIORITY_RESTORE_BITCOIN=true
POHW_IDENA_PRIORITY_FORCE=false
POHW_IDENA_PRIORITY_DRY_RUN=false
POHW_STRATUM_BIND_ADDR=<pi-wlan-ip>:3333
POHW_STRATUM_ALLOW_NON_LOOPBACK=true
POHW_STRATUM_PASSWORD_FILE=/etc/pohw/stratum.password
POHW_STRATUM_JOB_FILE=/mnt/ssd/pohw-p2pool/mining-job.json
POHW_STRATUM_BLOCK_CANDIDATE_DIR=/mnt/ssd/pohw-p2pool/block-candidates
POHW_IDENA_SNAPSHOT_ID=<snapshot-day-or-id>
POHW_IDENA_SNAPSHOT_PROOF_ROOT=<32-byte-root-hex>
```

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
sudo install -m 600 /dev/null /etc/pohw/tailscale.authkey
sudo sh -c 'printf "%s\n" "tskey-auth-..." > /etc/pohw/tailscale.authkey'
sudo POHW_TAILSCALE_AUTHKEY_FILE=/etc/pohw/tailscale.authkey \
  /mnt/ssd/p2pool/scripts/pohw-install-tailscale-remote-access.sh
```

After both the Mac and Pi are in the same tailnet, SSH and the dashboard tunnel work from any IP range:

```sh
ssh ubuntu@pibtc
scripts/pohw-dashboard-tunnel.sh ubuntu@pibtc
open http://127.0.0.1:5176/
```

If MagicDNS is disabled in Tailscale, replace `pibtc` with the Pi's `100.x.y.z` Tailscale IPv4 from `tailscale ip -4`. Keep the Tailscale auth key out of Git and delete it from `/etc/pohw/tailscale.authkey` after the Pi is connected if it is not reusable.

For a vacation-safe command-line status that avoids keys, cookies, addresses, and blockchain data, use the health monitor summary:

```sh
ssh <pi-ssh-host> '/usr/bin/python3 /mnt/ssd/p2pool/scripts/pohw-health-status.py --format summary'
```

The timer writes the same sanitized state to `/mnt/ssd/pohw-p2pool/health/status.json`. Bootstrap and Stratum RPC-job refresh use `POHW_HEALTH_STATUS_FILE` when it exists, so they stop before calling Bitcoin RPC while the health state says Bitcoin is still in IBD, `NODE_NETWORK_LIMITED`, RPC timeout, or `getblocktemplate` failure.

`pohw-auto-bootstrap.timer` checks the health file once per minute and runs `scripts/pohw-bootstrap-readiness.sh --mode real` once after the health monitor reports `miningReady=true`. Successful bootstrap writes `/mnt/ssd/pohw-p2pool/auto-bootstrap/bootstrap.done.json`; remove that marker only if you intentionally want another automatic bootstrap run.

`pohw-network-watchdog.timer` is the host self-recovery layer for cases where the Pi stays powered but disappears from the LAN. By default it pings the current default gateway once per minute, restarts the active network manager after 3 failed checks, and requests a reboot after 8 failed checks. Set `POHW_NETWORK_WATCHDOG_TARGETS` to comma-separated stable targets if the default gateway is not enough for your network. The timer writes secret-free state to `/mnt/ssd/pohw-p2pool/network-watchdog/status.json`.

`pohw-idena-priority-guard.timer` protects validation/flip sessions from Bitcoin background validation load. It checks local `dna_epoch` once per minute, stops `bitcoind-mainnet.service` when the current Idena period looks like a flip, short, long, or validation period, or when `nextValidation` is inside `POHW_IDENA_PRIORITY_LEAD_SECONDS`, and restarts Bitcoin after `POHW_IDENA_PRIORITY_COOLDOWN_SECONDS` only if the guard stopped it itself. The default lead is 1 hour and the default cooldown is 30 minutes. For an emergency manual pause, set `POHW_IDENA_PRIORITY_FORCE=true` in `/etc/pohw/p2pool.env` and restart the timer service; set it back to `false` after validation.

```sh
sudo systemctl start pohw-idena-priority-guard.service
sudo cat /mnt/ssd/pohw-p2pool/idena-priority/status.json
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
sudo install -m 644 deploy/systemd/idena-hardening.conf /etc/systemd/system/idena.service.d/30-hardening.conf
sudo sshd -t
sudo systemctl daemon-reload
```

For a Pi with Bitcoin Core on `/mnt/ssd`, start from `deploy/bitcoin/bitcoin-mainnet.conf.example` and copy only non-secret settings into the live `bitcoin.conf`. The template keeps RPC local-only, keeps a full unpruned chain for fork/testing work, and uses `dbcache=1536` for a 4 GiB Pi to reduce SSD pressure during AssumeUTXO background validation. Reduce `dbcache` if the host shows real memory pressure.

If UFW is enabled, expose only the intended ports:

```sh
sudo ufw allow in on wlan0 from <trusted-lan-cidr> to any port 22 proto tcp comment "SSH WLAN only"
sudo ufw allow in on wlan0 from <trusted-lan-cidr> to any port 40406 proto tcp comment "PoHW P2Pool gossip LAN"
sudo ufw allow in on wlan0 from <trusted-mac-ip> to any port 40407 proto tcp comment "PoHW dashboard API trusted client only"
sudo ufw allow in on wlan0 from <miner-or-rental-ip> to any port 3333 proto tcp comment "PoHW Stratum trusted miner only"
sudo ufw allow in on wlan0 to any port 8333 proto tcp comment "Bitcoin mainnet P2P"
sudo ufw allow in on wlan0 to any port 40405 proto tcp comment "Idena P2P active port"
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
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
pnpm --dir ui/pohw-dashboard build
bash -n scripts/pohw-snapshot-if-synced.sh
```

## License

MIT. See `Cargo.toml` workspace metadata.
