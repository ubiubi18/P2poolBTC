# PoHW Network Explorer

The combined UI has two modes built from the same Vite artifact:

- **Explorer:** sanitized fork-chain, sharechain, and aggregate Idena state.
- **Dashboard:** private participant pledge, contribution, payout, and vault data.

The explorer reads deterministic local replay state plus an optional loopback
Esplora index for inherited Bitcoin history. It does not expose Bitcoin, Idena,
fork-control, wallet, Electrum, indexer, or Stratum RPC endpoints to the browser.
The PoHW API validates and bounds every index request before proxying it.

The heavy index is a network-host role, not a participant requirement. Miners,
Pis, and observers use the public PoHW API and need neither `txindex=1` nor a
local Electrs/Esplora database.

## Public API

The versioned read-only API is served by `p2pool-node serve-dashboard-api`:

| Endpoint | Data |
| --- | --- |
| `GET /api/v1/overview` | Cross-layer fork/sharechain/Idena summary |
| `GET /api/v1/fork/blocks?limit=25&cursor=<hash>` | Fork blocks, including inactive branches |
| `GET /api/v1/fork/blocks/<hash>` | Sanitized fork-block detail |
| `GET /api/v1/fork/heights/<height>` | Active fork block at a height |
| `GET /api/v1/fork/blocks/<hash>/transactions?cursor=0&limit=25` | Decoded transactions in a fork block |
| `GET /api/v1/fork/transactions/<txid>` | Inputs, outputs, scripts, addresses, fees, and spend state |
| `GET /api/v1/fork/addresses/<address>` | Active-fork address totals |
| `GET /api/v1/fork/addresses/<address>/transactions?cursor=0&limit=25` | Active-fork address history |
| `GET /api/v1/fork/addresses/<address>/utxos?cursor=0&limit=25` | Active-fork UTXOs |
| `GET /api/v1/bitcoin/blocks` | Latest host-indexed Bitcoin history blocks |
| `GET /api/v1/bitcoin/blocks/<hash>` | Bitcoin history block detail |
| `GET /api/v1/bitcoin/blocks/<hash>/transactions?cursor=0` | Paginated decoded transactions in a Bitcoin history block |
| `GET /api/v1/bitcoin/heights/<height>` | Bitcoin history block at a height |
| `GET /api/v1/bitcoin/transactions/<txid>` | Bitcoin history transaction detail |
| `GET /api/v1/bitcoin/transactions/<txid>/outspends` | Spend state for each Bitcoin history transaction output |
| `GET /api/v1/bitcoin/addresses/<address>` | Current-mainnet address aggregate, explicitly not a fork balance |
| `GET /api/v1/bitcoin/addresses/<address>/transactions?cursor=<txid>` | Paginated Bitcoin history |
| `GET /api/v1/bitcoin/addresses/<address>/utxos` | Current-mainnet UTXOs with fork relation labels |
| `GET /api/v1/sharechain/shares?limit=25&cursor=<hash>` | Active and inactive shares |
| `GET /api/v1/sharechain/shares/<hash>` | Sanitized share detail |
| `GET /api/v1/idena/snapshot` | Aggregate latest verified Idena snapshot |

Fork block/share cursors are object hashes. Fork transaction/address cursors are
bounded numeric offsets. Bitcoin address-history cursors are transaction IDs.
Explicit limits must be between 1 and 100.
Public responses intentionally omit Idena identity addresses, payout scripts, peer
addresses, raw blocks, signatures, RPC credentials, private paths, and wallet
data. Miner IDs, consensus hashes, heights, scores, and aggregate snapshot roots
remain visible because they are needed to audit the experiment.

Every indexed Bitcoin object is labeled `inherited_history`,
`bitcoin_mainnet_after_fork`, or `bitcoin_mainnet_unconfirmed`. Current-mainnet
address aggregates are never presented as fork-spendable balances. Experiment 0
keeps inherited outputs locked, so mainnet-to-fork transaction replay is not
enabled by adding the explorer.

`/dashboard.json` remains the private participant endpoint. Enabling the public
explorer does not remove its token requirement.

## Local Deployment

Build and run both services on loopback:

```sh
cargo build --release
corepack pnpm@10.13.1 --dir ui/pohw-dashboard build

POHW_WORKDIR="$PWD" \
POHW_DATADIR="$PWD/.pohw-p2pool" \
POHW_SNAPSHOT_DIR="$PWD/snapshots" \
POHW_EXPLORER_FORK_CHAIN_RPC_ADDR=127.0.0.1:40408 \
POHW_FORK_ACTIVATION_MANIFEST="$PWD/.pohw-p2pool/fork-activation.json" \
POHW_EXPLORER_BITCOIN_INDEX_URL=http://127.0.0.1:3002 \
scripts/pohw-run-dashboard-api.sh
```

In another terminal:

```sh
POHW_WORKDIR="$PWD" \
POHW_DATADIR="$PWD/.pohw-p2pool" \
POHW_DASHBOARD_UI_DEFAULT_VIEW=explorer \
scripts/pohw-run-dashboard-ui.sh
```

Open `http://127.0.0.1:5176/#explorer`. For a remote local-only deployment,
forward ports 5176 and 40407 over SSH or Tailscale instead of changing either
bind address.

## Dedicated Host

The host profile assumes a protected root-owned checkout at `/opt/p2pool`,
runtime data below `/var/lib/pohw-p2pool` or `/srv/sharechain`, and existing
`pohw` service user. The API runs as `pohw` to read the live consensus state;
the installer creates a no-login `pohw-explorer-ui` account for the static UI.

The Bitcoin history index uses the existing unpruned Bitcoin Core datadir and
writes only its index below `/srv/bitcoin/esplora-index`. Its source repository,
commit, and dependency lock hash are pinned in
`compatibility/explorer-stack-lock.json`. The service reads the rotating Core
cookie through the `bitcoin` group; credentials never appear in arguments,
environment files, logs, or the browser API.
Bitcoin Core must set `rpccookieperms=group`; only the dedicated index account
and explicitly trusted local operators should belong to the `bitcoin` group.
The pinned indexer must run with `--jsonrpc-import`. This asks Bitcoin Core for
blocks in chain order and avoids the upstream direct-file ordering regression
that can abort a fresh mainnet index. The index account does not need read
access to `blk*.dat`, `rev*.dat`, or `xor.dat`, and Core `txindex` remains off.
It also runs in upstream light mode, which preserves the explorer API but asks
Core for raw transaction and block metadata on demand. The installer requires
at least 2 TiB free for the initial index and compaction; this is a host role,
not a participant requirement.

1. Install the native build prerequisites and build the release binary, UI,
   and pinned host indexer.
2. Install the two non-secret environment profiles.
3. Install and start the indexer. Initial indexing continues in the background.
4. Install and start the explorer API/UI.
5. Install the Caddy example after setting the real hostname.

```sh
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config libclang-dev

cd /opt/p2pool
cargo build --release
corepack pnpm@10.13.1 --dir ui/pohw-dashboard build

# Run this build command as an unprivileged operator.
scripts/pohw-build-bitcoin-indexer.sh /srv/bitcoin/electrs-build

sudo install -m 0644 -o root -g root \
  deploy/pohw-bitcoin-indexer.env.example /etc/pohw/bitcoin-indexer.env
sudo scripts/pohw-install-bitcoin-indexer.sh --activate \
  --binary /srv/bitcoin/electrs-build/target/release/electrs
```

Install `deploy/pohw-explorer-host.env.example` as
   `/etc/pohw/explorer.env`, mode `0600`, and replace the example origin.

```sh
sudo install -m 0600 -o root -g root \
  deploy/pohw-explorer-host.env.example /etc/pohw/explorer.env
sudoedit /etc/pohw/explorer.env
sudo scripts/pohw-install-explorer-host.sh --activate

sudo install -m 0644 -o root -g root \
  deploy/caddy/pohw-explorer.Caddyfile.example \
  /etc/caddy/conf.d/pohw-explorer.caddy
sudoedit /etc/caddy/conf.d/pohw-explorer.caddy
# Add this once to /etc/caddy/Caddyfile if the directory is not imported yet:
# import conf.d/*.caddy
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

The reverse proxy publishes only `/api/v1/*` and the static UI. Ports 40407,
40408, 5176, 3002, 50001, Bitcoin RPC, and Idena RPC must remain blocked from the Internet.
Fork P2P is a separate listener with its own firewall policy.

If the explorer host does not have the multi-terabyte capacity for a local
Esplora index, it can use one shared HTTPS Esplora provider:

```sh
POHW_EXPLORER_BITCOIN_INDEX_URL=https://blockstream.info/api
POHW_EXPLORER_ALLOW_REMOTE_BITCOIN_INDEX=true
```

Remote history is an explicit fallback: the provider can observe requested
transaction IDs and addresses, and its availability and rate limits apply.
The API rejects credentials, URL query strings, fragments, redirects, plain
remote HTTP, localhost, and literal non-public remote addresses. A sufficiently
provisioned local index remains the privacy-preserving production profile.

Do not reuse the node's private environment file for these services. The
dedicated explorer environment must contain paths and bind settings only, never
RPC cookies, API keys, wallet values, identity addresses, or private keys.
The private dashboard token is loaded through systemd credentials and is never
embedded in the public UI artifact or its runtime configuration.

## Smoke Test

```sh
curl --fail http://127.0.0.1:40407/api/v1/overview
curl --fail 'http://127.0.0.1:40407/api/v1/fork/blocks?limit=1'
curl --fail 'http://127.0.0.1:40407/api/v1/bitcoin/blocks'
curl --fail 'http://127.0.0.1:40407/api/v1/sharechain/shares?limit=1'
curl --fail http://127.0.0.1:5176/
```

No response should contain private identity selectors, `payoutScript`, `signature`,
`bitcoinHeader`, API keys, cookies, or filesystem paths.

## Rollback

The installer preserves the first replaced units under
`/var/lib/pohw-p2pool/explorer-unit-backup/` and automatically restores the
immediately previous units if activation or smoke tests fail. Manual rollback:

```sh
sudo systemctl disable --now pohw-dashboard-api.service pohw-dashboard-ui.service
sudo systemctl disable --now pohw-bitcoin-indexer.service
sudo cp /var/lib/pohw-p2pool/explorer-unit-backup/pohw-dashboard-api.service \
  /etc/systemd/system/pohw-dashboard-api.service
sudo cp /var/lib/pohw-p2pool/explorer-unit-backup/pohw-dashboard-ui.service \
  /etc/systemd/system/pohw-dashboard-ui.service
sudo systemctl daemon-reload
```

## Consensus And Coverage Boundaries

- The explorer fully decodes every transaction accepted by the fork node and
  exposes its scripts, standard addresses, outputs, and active-chain spend state.
  Experiment 0 consensus deliberately remains coinbase-only and inherited
  outputs remain locked; the explorer does not silently turn a no-value testnet
  into a replayable asset fork.
- The host Esplora index covers Bitcoin history without requiring Core
  `txindex`. It is a read model only and has no influence on fork consensus,
  mining admission, share validation, or payout decisions.
- Idena pages show verified aggregate snapshot data. `rewardSourceCoverage`
  remains explicit and partial until every source is reconstructed exactly.
