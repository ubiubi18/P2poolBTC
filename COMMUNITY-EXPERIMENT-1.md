# Join P2poolBTC Experiment 1

Experiment 1 is the current no-value P2poolBTC network. It runs a separately
identified Bitcoin Core fork with ordinary Bitcoin transactions, wallets,
PSBTs, and scripts. It is not Bitcoin mainnet and its coins have no promised
value.

This is a source-first procedure. There is no coordinator-signed installer and
no lead-developer key to trust. Every participant builds the exact source,
verifies the activation manifest, and validates the fork locally.

This guide joins the existing Experiment 1 network by default. Use the exact
community-agreed commit, the tracked manifest, and verified existing peers. Do
not generate a new activation manifest, change the activation ID, or initialize
a different network unless you deliberately intend to create a separate
experiment.

> [!WARNING]
> Fork address encodings match Bitcoin mainnet. Never import or reuse a Bitcoin
> key that can control real BTC. Idena is also a live chain: provide only your
> public identity address and a message signature, never an identity key,
> backup, password, or node API key.

> [!WARNING]
> Experiment 1 coins and inherited fork balances have no promised value. The
> fork permits inherited-mainnet spends subject to its mixed-input replay rule,
> but that rule cannot protect a reused or exposed mainnet private key. Use
> fresh fork-only wallet keys for ordinary testing, never broadcast a fork
> transaction to Bitcoin mainnet, and independently inspect any inherited
> output before attempting to spend it.

## What You Need

- A Linux host with at least four CPU cores, 16 GB RAM, and SSD storage.
- About 100 GB for a pruned participant node or substantially more for a full
  archival node. A transaction/address explorer index is not required to mine.
- Git, Rust, CMake, Ninja, a C++ compiler, Python 3, and Bitcoin Core build
  dependencies.
- The current Core P2P and P2Pool gossip endpoints from at least one existing
  participant, verified through an independent channel. Two independent seeds
  are recommended as soon as the network has them; the second participant can
  start from the first node and add another seed later. Do not copy an endpoint
  from an unverified social-media post.
- A `Newbie`, `Verified`, or `Human` Idena identity for reward accounting.

Do not run the Core fork, gossip, Stratum adapter, or miner on an SD-card-only
Raspberry Pi. The current Pi is observer-only and deliberately kept at low
load. Core, gossip, Stratum, and the bounded smoke miner run on the dedicated
Hetzner host.

## 1. Build And Verify The Source

GitHub is a mirror, not the canonical authority. Obtain the exact community-
agreed commit and source CID through independent channels, then use a fresh
checkout:

```sh
git clone https://github.com/ubiubi18/P2poolBTC.git
cd P2poolBTC
git checkout --detach '<community-agreed-commit>'
git status --short

python3 scripts/pohw-experiment-1-manifest.py verify \
  compatibility/experiment-1-full-consensus.json
cargo build --locked --release -p p2pool-node
cargo test --locked -p p2pool-node -p pohw-core
```

`git status --short` must print nothing. Compare the full activation ID and
manifest SHA-256 with independent participants:

```sh
python3 - <<'PY'
import hashlib, json, pathlib
p = pathlib.Path("compatibility/experiment-1-full-consensus.json")
m = json.loads(p.read_text(encoding="utf-8"))
print("activation_id=" + m["activation_id"])
print("manifest_sha256=" + hashlib.sha256(p.read_bytes()).hexdigest())
PY
```

A mismatch means a different network. Stop rather than overriding it.

To join the existing experiment, keep the tracked manifest byte-for-byte
unchanged and obtain both Core and gossip peer endpoints from independently
verified participants. Manifest-generation commands belong only to operators
creating a deliberately separate experiment.

## 2. Build A Pruned Experiment 1 Core Node

Build from the exact pinned Bitcoin Core revision. The privileged installer
applies the manifest-bound patch, performs a fresh build in an empty directory,
runs the complete Core test suite, verifies the build evidence, and installs
the result. Do not run a redundant check build first:

```sh
git clone https://github.com/bitcoin/bitcoin.git ../bitcoin-pohw-v31.1
git -C ../bitcoin-pohw-v31.1 checkout --detach \
  9be056a8a72b624dae9623b2f7bded92c2a21c91

sudo scripts/pohw-install-bitcoin-core-fork.sh \
  --source-dir "$PWD/../bitcoin-pohw-v31.1" \
  --build-dir "$PWD/../bitcoin-pohw-v31.1/build-pohw-install"
```

Create the dedicated account and an empty pruned datadir. Replace only the
peer placeholder; RPC remains loopback-only:

```sh
sudo groupadd --force --system bitcoin-pohw
sudo groupadd --force --system bitcoin-pohw-rpc
sudo groupadd --force --system bitcoin-chain-read
id bitcoin-pohw >/dev/null 2>&1 || \
  sudo useradd --system --gid bitcoin-pohw --home-dir /nonexistent \
    --shell /usr/sbin/nologin bitcoin-pohw
sudo usermod -a -G bitcoin-pohw-rpc,bitcoin-chain-read bitcoin-pohw
sudo install -d -o bitcoin-pohw -g bitcoin-pohw -m 0710 /srv/bitcoin/pohw

sudo tee /srv/bitcoin/pohw/bitcoin.conf >/dev/null <<'EOF'
chain=pohw
server=1
prune=100000
txindex=0
blockfilterindex=0
maxconnections=32
dbcache=4096

[pohw]
listen=1
port=40412
rpcport=40414
rpccookiefile=/run/bitcoin-pohw-rpc/.cookie
rpccookieperms=group
dnsseed=0
fixedseeds=0
discover=0
upnp=0
natpmp=0
listenonion=0
addnode=<verified-core-peer-host:40412>
EOF
sudo chown bitcoin-pohw:bitcoin-pohw /srv/bitcoin/pohw/bitcoin.conf
sudo chmod 0600 /srv/bitcoin/pohw/bitcoin.conf
sudo install -m 0644 deploy/systemd/bitcoind-pohw-experiment-1.service \
  /etc/systemd/system/bitcoind-pohw-experiment-1.service
sudo systemctl daemon-reload
sudo systemctl enable --now bitcoind-pohw-experiment-1.service
```

An empty node validates inherited history from genesis before reaching the
fork. Pruning reduces retained disk usage, not validation work. Never use
somebody else's RPC as a substitute for independent validation.

## 3. Verify Core Before Registering

This command prints no block hash, wallet information, peer address, or RPC
credential:

```sh
sudo -u bitcoin-pohw -g bitcoin-pohw-rpc \
  /usr/local/libexec/pohw-bitcoin-core-v31.1/bin/bitcoin-cli \
  -datadir=/srv/bitcoin/pohw -chain=pohw \
  -rpccookiefile=/run/bitcoin-pohw-rpc/.cookie getblockchaininfo |
python3 -c 'import json,sys; d=json.load(sys.stdin); print("chain="+d["chain"]); print("height="+str(d["blocks"])); print("headers="+str(d["headers"])); print("ibd="+str(d["initialblockdownload"])); print("replay="+str(d.get("pohw_experiment",{}).get("replay_protection")))'
```

Continue only when `chain=pohw`, `ibd=False`, the height is at or above the
first fork height in the manifest, and replay protection is present.

## 4. Register Your Idena Identity

Create an Experiment 1 sharechain directory and bind it to the manifest. Choose
a public lowercase miner name; do not use an email address or real name:

```sh
P2POOL="$PWD/target/release/p2pool-node"
MANIFEST="$PWD/compatibility/experiment-1-full-consensus.json"
ACTIVATION_ID=$(python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["activation_id"])' \
  "$MANIFEST")
POHW_DATADIR="$HOME/.local/share/p2poolbtc/experiment-1"
install -d -m 0700 "$POHW_DATADIR"

"$P2POOL" initialize-gossip-network \
  --datadir "$POHW_DATADIR" --network-id "$ACTIVATION_ID"

"$P2POOL" prepare-miner-registration \
  --datadir "$POHW_DATADIR" \
  --miner-id '<public-miner-name>' \
  --idena-address '<public-0x-address>'
```

The second command creates three local P2Pool keys and prints the exact Idena
ownership challenge. Sign that message in Idena Web or Desktop. Then submit
the resulting public signature through stdin so it does not enter shell
history:

```sh
read -r -s -p 'Idena signature: ' IDENA_SIGNATURE; printf '\n'
printf '%s\n' "$IDENA_SIGNATURE" | \
  "$P2POOL" prepare-miner-registration \
    --datadir "$POHW_DATADIR" \
    --miner-id '<same-public-miner-name>' \
    --idena-address '<same-public-0x-address>' \
    --idena-signature-stdin --append \
    --peer-addr '<verified-gossip-peer-host:40406>'
unset IDENA_SIGNATURE
```

Send the signed registration envelope only through the protocol. The envelope
necessarily contains the public ownership proof; do not separately paste the
raw signature or callback URL into chats, screenshots, or issue reports. Never
send the generated key files or Idena backup to another participant.
Registration is eligible only while the live Idena state is `Newbie`,
`Verified`, or `Human`; registration does not transfer custody of the identity
or its stake to P2poolBTC.

## 5. Start P2Pool And Mine

Obtain the current Idena snapshot and signed snapshot votes through independent
participants. Verify them locally; a filename or coordinator statement is not
proof. Configure the Experiment 1 P2Pool services exactly as described in the
[P2Pool Adapter section](EXPERIMENT-1.md#p2pool-adapter), using:

- the `POHW_DATADIR` created above;
- the activation ID derived from your local manifest;
- local Core RPC `http://127.0.0.1:40414` and its cookie file;
- `POHW_BITCOIN_EXPECTED_CHAIN=pohw`;
- `POHW_STRATUM_AUTO_SUBMIT_BLOCKS=true`;
- `POHW_STRATUM_ALLOW_MAINNET_SUBMIT=false`.

Start gossip first, then the adapter:

```sh
sudo systemctl start pohw-gossip-mesh.service
sudo systemctl start pohw-mining-adapter.service
sudo systemctl is-active --quiet \
  bitcoind-pohw-experiment-1.service \
  pohw-gossip-mesh.service \
  pohw-mining-adapter.service
```

Point your miner at your own adapter. Keep Stratum on loopback unless you have
configured its protected password file and firewall. The local endpoint is
`stratum+tcp://127.0.0.1:3333`; use the credentials configured for your own
adapter rather than sharing another operator's Stratum secret.

The adapter serves jobs and waits idle when no miner is connected. It is not a
continuous CPU miner. The repository smoke miner is a bounded acceptance tool
reserved for the dedicated Hetzner host in this experiment; never run it on the
Pi. It exits at the configured hash or time limit, and an attempt may finish
without finding a share or block:

```sh
nice -n 19 python3 scripts/pohw-stratum-smoke-mine.py \
  --host 127.0.0.1 --port 3333 \
  --max-hashes 100000 --timeout-seconds 10 --allow-no-solution
```

The first host may schedule one such bounded attempt every ten minutes. This is
not a general-purpose miner: it is capped at 5% of one CPU, has a ten-second
attempt budget, refuses Raspberry Pi hardware and non-loopback Stratum, and
stops attempting as soon as Core reports the bootstrap-to-normal-difficulty
handoff. Its unit also refuses to run unless Core and Stratum are already
active; it never starts those heavier services itself:

```sh
sudo install -o root -g root -m 0644 deploy/pohw-bootstrap-miner.env.example \
  /etc/pohw/bootstrap-miner.env
sudo install -o root -g root -m 0644 \
  deploy/systemd/pohw-bootstrap-miner.service \
  deploy/systemd/pohw-bootstrap-miner.timer /etc/systemd/system/
sudo install -o root -g root -m 0644 /dev/null \
  /etc/pohw/enable-experiment-1-bootstrap-miner
sudo systemctl daemon-reload
sudo systemctl enable --now pohw-bootstrap-miner.timer
```

Do not install that timer on participant machines with real mining hardware.
Connect the hardware to the local adapter instead. Removing the opt-in marker
and stopping the timer disables bounded bootstrap mining without stopping Core,
gossip, or Stratum:

```sh
sudo rm -f /etc/pohw/enable-experiment-1-bootstrap-miner
sudo systemctl disable --now pohw-bootstrap-miner.timer
```

For ordinary participation, connect your mining hardware to your own adapter
instead of repeatedly running the smoke tool.

## How To Know You Joined Successfully

All rows must pass; a dashboard screenshot alone is not proof.

| Check | Required result |
| --- | --- |
| Source | Clean checkout, manifest verification passes, source/activation values match independent participants |
| Core | `chain=pohw`, `ibd=False`, fork height advances, RPC remains loopback-only |
| Identity | Local replay reports one registration for your miner and the gossip peer accepts its envelope |
| Snapshot | Your eligible identity is present in the independently verified snapshot with the required vote quorum |
| Sharechain | `stored_share_count` and your active share score increase after a submitted share |
| Block | The bounded miner receives an accepted Stratum response and `bitcoin-cli -chain=pohw getblockcount` increases |
| UI | The dashboard shows the same aggregate height/share counts as your local commands |

Record the Core height and local share count before connecting a miner, then
run the same commands again after an accepted submission:

```sh
sudo -u bitcoin-pohw -g bitcoin-pohw-rpc \
  /usr/local/libexec/pohw-bitcoin-core-v31.1/bin/bitcoin-cli \
  -datadir=/srv/bitcoin/pohw -chain=pohw \
  -rpccookiefile=/run/bitcoin-pohw-rpc/.cookie getblockcount

"$P2POOL" status --datadir "$POHW_DATADIR"
```

An accepted fork block must increase the Core fork height. An accepted share
must increase the applicable sharechain count or score, and the dashboard's
Fork blocks and Sharechain views must converge on the same aggregate growth.
No increase means the join is not yet proven; inspect the adapter and gossip
status rather than relying on a screenshot.

Forked BTC appears in Bitcoin Core only when a loaded fork-only wallet controls
the corresponding output. Inspect that wallet without exposing addresses:

```sh
sudo -u bitcoin-pohw -g bitcoin-pohw-rpc \
  /usr/local/libexec/pohw-bitcoin-core-v31.1/bin/bitcoin-cli \
  -datadir=/srv/bitcoin/pohw -chain=pohw \
  -rpccookiefile=/run/bitcoin-pohw-rpc/.cookie \
  -rpcwallet='<fork-only-wallet>' getbalances
```

The wallet's trusted or immature balance changes only if the fork coinbase or
payout actually pays a descriptor owned by that wallet. A pool, explorer, or
dashboard balance does not automatically become wallet balance. Coinbase
outputs require 100 confirmations before spending, exactly as in upstream
Bitcoin Core. None of these balances has promised monetary value.

## Report Problems Without Leaking Secrets

Open a GitHub issue using the repository issue templates. Include operating
system, exact source commit, manifest SHA-256, activation ID, command name,
sanitized error, and whether Core/share heights changed. Remove:

- Idena and Bitcoin private keys, backups, passwords, and API keys;
- RPC cookies and Stratum passwords;
- identity and wallet addresses unless they are essential and intentionally
  public for the report;
- peer IP addresses, block hashes, raw transactions, signatures, and local
  filesystem paths.

Run the repository secret scan before attaching logs. Stop the adapter first if
the issue could affect consensus, payout accounting, or replay protection.
