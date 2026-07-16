# Join P2poolBTC Experiment 1

Experiment 1 revision 3 is a no-value P2poolBTC technical preview. It runs a
separately identified Bitcoin Core fork with ordinary Bitcoin transactions,
wallets, PSBTs, and scripts. It checkpoints the immutable revision-2 prefix and
adds marker plus signature-domain replay protection. It is not Bitcoin mainnet
and its coins have no promised value. Mining is paused and public joining is
blocked until the revision-3 build and all interlock evidence pass.

Start with the
[five-minute guarded quick start](COMMUNITY-QUICKSTART.md). Its one read-only
command chooses a role, verifies the pinned candidate, shows the same five
stages used by this runbook, and creates a private redacted issue template. Use
the longer procedure below only when that command says the relevant next stage
is available.

## Choose Your Journey

There are two different journeys. Do not mix them.

### Lane A: Review And Rehearse Now

Anyone can review the current candidate without joining the live network. This
lane uses no Idena identity signature, API key, wallet, live peer, root
installation, systemd unit, Stratum endpoint, or mining hardware:

```sh
git clone https://github.com/ubiubi18/P2poolBTC.git
cd P2poolBTC
git switch --detach origin/vibe/experiment-1-release-readiness
test -z "$(git status --short)"
./scripts/pohw-community-onboard.sh --role observer

STATUS=$(python3 scripts/pohw-experiment-1-launch-policy.py \
  compatibility/experiment-1-launch-policy.json | \
  sed -n 's/^launch policy verified: //p')
test "$STATUS" = blocked-release-readiness
```

For this lane, `review-ready`, a clean checkout, a verified
`blocked-release-readiness` policy, and a verified manifest are the expected
initial success result. A deeper reviewer should explicitly run
`cargo fetch --locked` and then rerun the onboarding command with `--run-tests`;
the test run itself is offline. Do not continue to the privileged installation or
registration commands below. The candidate branch can move, so include the
exact `git rev-parse HEAD` value in every review report. The generated receipt
contains only aggregate diagnostics; inspect the generated `issue-report.md`
before posting it.

### Lane B: Join Live Only After The Interlock Opens

The live journey has five stages:

| Stage | Outcome required before continuing |
| --- | --- |
| 1. Verify release | The ecosystem CID read independently from Idena governance, its DAG-CBOR CAR, exact P2poolBTC source CAR, runtime artifacts, release commit, build evidence, launch policy, and manifest all agree |
| 2. Build Core | The pinned Bitcoin Core v31.1 fork is built from source in an isolated `chain=pohw` profile |
| 3. Verify Core | Activation and manifest match, RPC is loopback-only, initial block download is complete, and the pinned height-958175 checkpoint hash matches |
| 4. Register identity | An eligible public Idena address signs only the exact registration challenge and gossip accepts the envelope |
| 5. Start P2Pool | Gossip starts before the adapter, local Stratum accepts work, and Core plus sharechain progress is observed locally |

The numbered sections below implement those five stages. Stop immediately on a
mismatch. A screenshot, GitHub branch, social-media message, or coordinator
signature cannot replace any required verification result.

## Public-Join Interlock

You may publish the idea, source, threat model, test results, and sanitized
screenshots for review. Do not invite people to connect miners to the live
experiment yet. Public joining is blocked until all of these are published and
independently checked:

- an exact source commit, DAO-selected ecosystem CID, canonical DAG-CBOR
  ecosystem CAR, P2poolBTC source CAR, each CAR digest, runtime artifact
  digests, and build evidence, all retrievable from public IPFS;
- at least two independent matching builds of the ownerless miner-registry WASM;
- an external security review with no unresolved release-blocking finding;
- a finalized Idena deployment receipt and immutable V2 anchor policy; and
- a successful independent second-node Core, gossip, registration, share, and
  block acceptance rehearsal.

The repository records the current interlock in
`compatibility/experiment-1-launch-policy.json`. The verifier first binds the
exact fork manifest and registry candidate, then rejects a ready status unless
every recorded release gate passes. The checked-in candidate is
`blocked-release-readiness`. A future ready policy is not sufficient by itself:
sections 5.2 and 5.4 run the strict verifier with the report CAR, transitive
evidence CAR, evidence-bound governance binary, and finalized Idena anchor.
Continue to a live start only when that complete invocation prints
`ready-for-public-join`.

The remaining sections are the procedure to use after that check passes. They
are also suitable for isolated source review and local rehearsal, but a local
rehearsal is not evidence that the public network is open.

This is a source-first procedure. There is no coordinator-signed installer and
no lead-developer key to trust. Every participant independently reads the
canonical ecosystem CID from Idena governance, reproduces the exact source,
verifies the activation manifest and CAR contents, and validates the fork
locally. A Git branch, gateway response, launch-policy file, or executable is
not allowed to authenticate itself.

This guide joins the existing Experiment 1 network only after the interlock
passes. Use the exact release commit and source CID, the tracked manifest, and
verified existing peers. Do not generate a new activation manifest, change the
activation ID, or initialize a different network unless you deliberately
intend to create a separate experiment.

> [!WARNING]
> Fork address encodings match Bitcoin mainnet. Never import or reuse a Bitcoin
> key that can control real BTC. Idena is also a live chain: provide only your
> public identity address and a message signature, never an identity key,
> backup, password, or node API key.

> [!WARNING]
> Experiment 1 coins and inherited fork balances have no promised value. The
> fork permits inherited-mainnet spends subject to its marker and
> fork-domain-signature replay rules,
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
- A systemd-based Ubuntu host with the `ubuntu` operator account and an
  SSD-backed `/srv` containing `/srv/sharechain` and `/srv/bitcoin`. The
  procedure creates the fixed non-login
  `pohw` service account and uses the evidence-installed `/opt/p2pool` server
  profile. A different service account or layout needs separately reviewed
  units rather than an untracked local rewrite.
- A synchronized local Idena node on loopback and its existing API-key file.
  The procedure copies that credential into a service-readable protected file;
  it never places the credential itself in an argument or environment file.
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

GitHub is a mirror, not the canonical authority. Obtain the exact release
commit, ecosystem CID, ecosystem CAR, P2poolBTC source CAR, and build-evidence
digest through independent channels. Read the ecosystem CID from Idena
governance through your own synchronized node; do not derive it from GitHub,
the CAR, or the launch-policy file it is meant to verify. A literal placeholder
means there is no release and you must stop. Then use a fresh checkout:

```sh
git clone https://github.com/ubiubi18/P2poolBTC.git
cd P2poolBTC
RELEASE_COMMIT='<published-exact-release-commit>'
test "$RELEASE_COMMIT" != '<published-exact-release-commit>'
git checkout --detach "$RELEASE_COMMIT"
git status --short

python3 scripts/pohw-experiment-1-manifest.py verify \
  compatibility/experiment-1-full-consensus.json
cargo build --locked --release -p p2pool-node -p governance-cli
cargo test --locked -p p2pool-node -p pohw-core -p governance-core -p governance-cli
```

`git status --short` must print nothing. These commands are a build rehearsal,
not yet canonical source proof. Section 5 supplies the independent ecosystem
CID and CARs to the onboarding verifier, which hashes the governance binary
before executing it and proves that this tree reproduces the source CID.
Compare the full activation ID and manifest SHA-256 with independent
participants:

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
sudo groupadd --force --system pohw
id bitcoin-pohw >/dev/null 2>&1 || \
  sudo useradd --system --gid bitcoin-pohw --home-dir /nonexistent \
    --shell /usr/sbin/nologin bitcoin-pohw
id pohw >/dev/null 2>&1 || \
  sudo useradd --system --gid pohw --home-dir /nonexistent \
    --shell /usr/sbin/nologin pohw
test "$(id -gn pohw)" = pohw
test "$(getent passwd pohw | cut -d: -f6)" = /nonexistent
test "$(getent passwd pohw | cut -d: -f7)" = /usr/sbin/nologin
sudo usermod -a -G bitcoin-pohw-rpc,bitcoin-chain-read bitcoin-pohw
sudo usermod -a -G bitcoin-pohw-rpc pohw
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
```

An empty node validates inherited history from genesis before reaching the
fork. Pruning reduces retained disk usage, not validation work. Never use
somebody else's RPC as a substitute for independent validation. Do not install
or start the Core unit yet. Section 5 installs that unit from the same
evidence-bound runtime set and starts it only after the ready policy, both
readiness CARs, and the finalized Idena anchor are present.

## 3. Verify The Core Build Before Registering

The deterministic builder has already run the complete Core test suite. Confirm
the installed binaries and immutable manifest now; the live-chain check occurs
after the launch interlock is staged in section 5.3:

```sh
test -x /usr/local/libexec/pohw-bitcoin-core-v31.1/bin/bitcoind
test -x /usr/local/libexec/pohw-bitcoin-core-v31.1/bin/bitcoin-cli
python3 scripts/pohw-experiment-1-manifest.py verify \
  compatibility/experiment-1-full-consensus.json
/usr/local/libexec/pohw-bitcoin-core-v31.1/bin/bitcoind -version | head -n 1
```

The version line is informational; the manifest and independently selected
build evidence are the authority.

## 4. Register Your Idena Identity

The ownerless Idena registry is mandatory. A legacy one-step registration is
not valid for Experiment 1. Do not sign anything until the finalized contract
receipt has been read back from your own Idena node. Choose a public lowercase
miner name; do not use an email address or real name:

```sh
P2POOL="$PWD/target/release/p2pool-node"
MANIFEST="$PWD/compatibility/experiment-1-full-consensus.json"
ACTIVATION_ID=$(python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["activation_id"])' \
  "$MANIFEST")
DATA_SUBDIRECTORY=$(python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["network"]["data_subdirectory"])' \
  "$MANIFEST")
test "$(id -un)" = ubuntu
POHW_DATADIR="/srv/sharechain/${DATA_SUBDIRECTORY}-${ACTIVATION_ID:0:8}"
for directory in /opt/p2pool /srv/sharechain "$POHW_DATADIR"; do
  if sudo test -L "$directory" ||
    { sudo test -e "$directory" && ! sudo test -d "$directory"; }; then
    echo "Unsafe service-profile directory: $directory" >&2
    exit 1
  fi
done
if sudo test -d "$POHW_DATADIR"; then
  test -z "$(sudo find "$POHW_DATADIR" \
    -mindepth 1 -maxdepth 1 -print -quit)" || {
    echo 'The manifest-bound datadir must be empty before registration.' >&2
    exit 1
  }
fi
sudo install -d -o root -g root -m 0755 /opt/p2pool /srv/sharechain
test -z "$(sudo find /opt/p2pool -mindepth 1 -maxdepth 1 -print -quit)" || {
  echo '/opt/p2pool must be an empty fixed working directory, not a checkout.' >&2
  exit 1
}
sudo install -d -o ubuntu -g ubuntu -m 0700 "$POHW_DATADIR"
test ! -L "$POHW_DATADIR"

"$P2POOL" initialize-gossip-network \
  --datadir "$POHW_DATADIR" --network-id "$ACTIVATION_ID"

export POHW_EXPERIMENT_NO_VALUE_ACK=I_UNDERSTAND_NO_VALUE
export POHW_WORKDIR="$PWD"
export POHW_P2POOL_NODE_BIN="$P2POOL"
export POHW_DATADIR
export POHW_EXPERIMENT_OUTPUT_ROOT="$POHW_DATADIR/onboarding"
export POHW_MINER_ID='<public-miner-name>'
export POHW_IDENA_ADDRESS='<public-0x-address>'
export POHW_MINER_REGISTRY_EXPERIMENT_ID=p2poolbtc-experiment-1
export POHW_PEER_ADDRS='<verified-gossip-peer-ip:40406>'
case "$POHW_MINER_ID$POHW_IDENA_ADDRESS$POHW_PEER_ADDRS" in
  *'<'*|*'>'*) echo 'Replace every registration placeholder first.' >&2; exit 1 ;;
esac

scripts/pohw-experiment-register-miner.sh \
  --registry-experiment-id p2poolbtc-experiment-1 \
  --output-dir "$POHW_EXPERIMENT_OUTPUT_ROOT/01-commitment"
```

The status must be `needs_registry_transaction`. It creates protected local
P2Pool keys and a public commitment, but no ownership challenge may be signed
yet. Call `registerMiner(<miner_id>, <registration_commitment>)` on the exact
contract from the verified public policy, attach at least its immutable minimum
burn, and wait for the policy's finality depth. This is a real public Idena
transaction that burns real IDNA; review the exact fee and arguments in your
wallet before approving it.

Read the finalized receipt from your own synchronized Idena node:

```sh
POLICY='/path/to/independently-verified-idena-anchor-policy.json'
CONTRACT_ADDRESS=$(python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["registry_contract_address"])' \
  "$POLICY")

"$P2POOL" read-miner-registry-anchor \
  --contract-address "$CONTRACT_ADDRESS" \
  --experiment-id p2poolbtc-experiment-1 \
  --idena-address "$POHW_IDENA_ADDRESS" \
  --miner-id "$POHW_MINER_ID" \
  --registration-sequence 1 \
  --idena-rpc-url http://127.0.0.1:9009 \
  --idena-api-key-file '/path/to/private/idena-api.key' \
  > "$POHW_EXPERIMENT_OUTPUT_ROOT/miner-registry-anchor.json"

export POHW_MINER_REGISTRY_ANCHOR_FILE="$POHW_EXPERIMENT_OUTPUT_ROOT/miner-registry-anchor.json"
scripts/pohw-experiment-register-miner.sh \
  --registry-experiment-id p2poolbtc-experiment-1 \
  --registry-anchor-file "$POHW_MINER_REGISTRY_ANCHOR_FILE" \
  --output-dir "$POHW_EXPERIMENT_OUTPUT_ROOT/02-anchored-challenge"
```

The status must now be `needs_idena_signature`. Sign its exact
`idena_ownership_challenge` in Idena, then pass only the resulting public
signature through stdin so it does not enter shell history:

```sh
read -r -s -p 'Idena signature: ' IDENA_SIGNATURE; printf '\n'
printf '%s\n' "$IDENA_SIGNATURE" | \
  scripts/pohw-experiment-register-miner.sh \
    --registry-experiment-id p2poolbtc-experiment-1 \
    --registry-anchor-file "$POHW_MINER_REGISTRY_ANCHOR_FILE" \
    --idena-signature-stdin \
    --output-dir "$POHW_EXPERIMENT_OUTPUT_ROOT/03-registration"
unset IDENA_SIGNATURE
```

The final status must be `registration_ready`, registration version must be
`2`, and the anchor must match the local contract receipt. Send the signed
registration envelope only through the protocol. The envelope necessarily
contains the public ownership proof; do not separately paste the raw signature
or callback URL into chats, screenshots, or issue reports. Never send the
generated key files or Idena backup to another participant.
Registration is eligible only while the live Idena state is `Newbie`,
`Verified`, or `Human`; registration does not transfer custody of the identity
or its stake to P2poolBTC.

## 5. Start P2Pool And Mine

Do not start services while the public-join interlock at the beginning of this
guide is blocked. A source build alone is insufficient: install only the exact
evidence-bound runtime files from the published release, configure the verified
V2 anchor policy, and rerun preflight before enabling any unit.

Run every code block in this section in order, in one Bash session, from the
same clean detached release checkout, as the `ubuntu` account. Later blocks
reuse the evidence-bound variables established by earlier blocks. A different
account or filesystem layout is not supported by these fixed units.

### 5.1 Install The Evidence-Bound Runtime

Obtain the complete `rust-workspace` evidence directory, its SHA-256, the
canonical ecosystem CID, its deterministic CAR, and the P2poolBTC source CAR
through independent channels. The ecosystem CID must come from the Idena
governance reference, not from either downloaded CAR. The directory must contain
`build-evidence.json`, `source-verification.json`, `test-results.json`, and
`build-environment.json`. Do not derive either expected value from that same
directory.

```bash
set -euo pipefail
umask 077
test "$(id -un)" = ubuntu
REPO=$(pwd -P)
MANIFEST="$REPO/compatibility/experiment-1-full-consensus.json"
BUILD_PLAN="$REPO/compatibility/governance-build-plan-v1.json"
EVIDENCE_DIR='/path/to/independently-obtained-rust-workspace-evidence'
EXPECTED_EVIDENCE_SHA256='<published-build-evidence-sha256>'
EXPECTED_SOURCE_CID='<published-canonical-source-cid>'
EXPECTED_ECOSYSTEM_CID='<CID-read-independently-from-Idena-governance>'
CANDIDATE_ECOSYSTEM_CAR='/path/to/EcosystemManifestV1.car'
P2POOL_SOURCE_CAR='/path/to/P2poolBTC-source.car'

[[ "$EXPECTED_EVIDENCE_SHA256" =~ ^[0-9a-f]{64}$ ]] || {
  echo 'Missing independently obtained build-evidence SHA-256.' >&2; exit 1;
}
[[ "$EXPECTED_SOURCE_CID" =~ ^b[a-z2-7]{20,120}$ ]] || {
  echo 'Missing independently obtained canonical source CID.' >&2; exit 1;
}
[[ "$EXPECTED_ECOSYSTEM_CID" =~ ^b[a-z2-7]{20,120}$ ]] || {
  echo 'Missing independently obtained canonical ecosystem CID.' >&2; exit 1;
}
for car in "$CANDIDATE_ECOSYSTEM_CAR" "$P2POOL_SOURCE_CAR"; do
  test -s "$car"
  test -f "$car"
  test ! -L "$car"
done
for name in build-evidence.json source-verification.json \
  test-results.json build-environment.json; do
  test -f "$EVIDENCE_DIR/$name"
  test ! -L "$EVIDENCE_DIR/$name"
done
python3 scripts/pohw-experiment-1-manifest.py verify "$MANIFEST"
python3 scripts/pohw-governance-build-evidence.py validate-plan \
  --plan "$BUILD_PLAN"
test "$(sha256sum "$EVIDENCE_DIR/build-evidence.json" | awk '{print $1}')" = \
  "$EXPECTED_EVIDENCE_SHA256"

UNKNOWN_UNITS=()
for unit in bitcoind-pohw-experiment-1.service \
  pohw-gossip-mesh.service pohw-mining-adapter.service; do
  if sudo systemctl is-enabled --quiet "$unit"; then
    echo "Refusing installation while $unit is enabled." >&2
    exit 1
  fi
  set +e
  sudo systemctl is-active --quiet "$unit"
  unit_status=$?
  set -e
  case "$unit_status" in
    0) echo "Refusing installation while $unit is active." >&2; exit 1 ;;
    3) ;;
    4) UNKNOWN_UNITS+=("$unit") ;;
    *) echo "Cannot prove $unit is inactive (status $unit_status)." >&2; exit 1 ;;
  esac
done

if ((${#UNKNOWN_UNITS[@]})); then
  PLACEHOLDER_UNIT=$(mktemp)
  trap 'rm -f "$PLACEHOLDER_UNIT"' EXIT
  cat > "$PLACEHOLDER_UNIT" <<'EOF'
[Unit]
Description=Inactive placeholder replaced by the evidence-bound installer
RefuseManualStart=yes

[Service]
Type=oneshot
ExecStart=/usr/bin/false
EOF
  for unit in "${UNKNOWN_UNITS[@]}"; do
    if sudo systemctl cat "$unit" >/dev/null 2>&1; then
      echo "Unknown $unit already has a unit definition; refusing overwrite." >&2
      exit 1
    fi
    sudo test ! -e "/etc/systemd/system/$unit"
    sudo install -o root -g root -m 0644 "$PLACEHOLDER_UNIT" \
      "/etc/systemd/system/$unit"
  done
  sudo systemctl daemon-reload
  for unit in "${UNKNOWN_UNITS[@]}"; do
    set +e
    sudo systemctl is-active --quiet "$unit"
    unit_status=$?
    set -e
    test "$unit_status" -eq 3
  done
  rm -f "$PLACEHOLDER_UNIT"
  trap - EXIT
fi

INSTALL_RESULT=$(sudo scripts/pohw-install-experiment-1-adapter.sh \
  --source-root "$REPO" \
  --build-plan "$BUILD_PLAN" \
  --build-evidence "$EVIDENCE_DIR/build-evidence.json" \
  --expected-evidence-sha256 "$EXPECTED_EVIDENCE_SHA256" \
  --expected-source-cid "$EXPECTED_SOURCE_CID" \
  --binary "$REPO/target/release/p2pool-node" \
  --governance-binary "$REPO/target/release/pohw-governance")
printf '%s\n' "$INSTALL_RESULT"
grep -Fq 'services remain stopped' <<<"$INSTALL_RESULT"

RUNTIME_DIR=/usr/local/libexec/p2pool-experiment-1
INSTALLED_NODE="$RUNTIME_DIR/p2pool-node"
for artifact in \
  "$INSTALLED_NODE" \
  "$RUNTIME_DIR/pohw-governance" \
  "$RUNTIME_DIR/pohw-governance.sha256" \
  "$RUNTIME_DIR/pohw-experiment-1-launch-policy.py" \
  "$RUNTIME_DIR/compatibility/experiment-1-full-consensus.json" \
  "$RUNTIME_DIR/compatibility/experiment-1-launch-policy.json" \
  "$RUNTIME_DIR/compatibility/experiment-1-miner-registry-candidate.json" \
  "$RUNTIME_DIR/pohw-run-gossip-mesh.sh" \
  "$RUNTIME_DIR/pohw-run-mining-adapter.sh" \
  "$RUNTIME_DIR/pohw-health-status.py" \
  /etc/systemd/system/bitcoind-pohw-experiment-1.service \
  /etc/systemd/system/pohw-gossip-mesh.service \
  /etc/systemd/system/pohw-mining-adapter.service \
  /etc/systemd/system/pohw-gossip-mesh.service.d/server.conf \
  /etc/systemd/system/pohw-mining-adapter.service.d/server.conf \
  /etc/systemd/system/pohw-gossip-mesh.service.d/experiment-1.conf \
  /etc/systemd/system/pohw-mining-adapter.service.d/experiment-1.conf; do
  sudo test -f "$artifact"
  sudo test ! -L "$artifact"
done
GOVERNANCE_SHA256=$(cat "$RUNTIME_DIR/pohw-governance.sha256")
[[ "$GOVERNANCE_SHA256" =~ ^[0-9a-f]{64}$ ]]
test "$(sha256sum "$RUNTIME_DIR/pohw-governance" | awk '{print $1}')" = \
  "$GOVERNANCE_SHA256"
test "$(sudo systemctl show -p FragmentPath --value \
  bitcoind-pohw-experiment-1.service)" = \
  /etc/systemd/system/bitcoind-pohw-experiment-1.service
test "$(sudo systemctl show -p FragmentPath --value \
  pohw-gossip-mesh.service)" = \
  /etc/systemd/system/pohw-gossip-mesh.service
test "$(sudo systemctl show -p FragmentPath --value \
  pohw-mining-adapter.service)" = \
  /etc/systemd/system/pohw-mining-adapter.service
sudo systemctl show -p ExecStart --value pohw-gossip-mesh.service | \
  grep -Fq "$RUNTIME_DIR/pohw-run-gossip-mesh.sh"
sudo systemctl show -p ExecStart --value pohw-mining-adapter.service | \
  grep -Fq "$RUNTIME_DIR/pohw-run-mining-adapter.sh"
sudo systemctl show -p Environment --value pohw-mining-adapter.service | \
  grep -Fq \
  /usr/local/libexec/p2pool-experiment-1/pohw-health-status.py
for unit in pohw-gossip-mesh.service pohw-mining-adapter.service; do
  test "$(sudo systemctl show -p User --value "$unit")" = pohw
  test "$(sudo systemctl show -p Group --value "$unit")" = pohw
  test "$(sudo systemctl show -p RefuseManualStart --value "$unit")" = no
  test "$(sudo systemctl show -p WorkingDirectory --value "$unit")" = \
    /opt/p2pool
  sudo systemctl show -p DropInPaths --value "$unit" | \
    grep -Fq "/etc/systemd/system/$unit.d/server.conf"
  sudo systemctl show -p DropInPaths --value "$unit" | \
    grep -Fq "/etc/systemd/system/$unit.d/experiment-1.conf"
  sudo systemctl show -p ReadWritePaths --value "$unit" | \
    grep -Fqw /srv/sharechain
  if sudo systemctl is-enabled --quiet "$unit"; then
    echo "$unit became enabled before preflight." >&2
    exit 1
  fi
done
```

The installer deliberately rejects an unknown service state. On a fresh host,
the inert placeholders make the three names provably inactive; they cannot be
enabled or manually started and are never executed. The installer must replace
them before the artifact and effective-unit checks run. Its final line and every
check above must pass. It copies both binaries, the evidence-derived governance
binary digest companion, the launch verifier and its three bound compatibility
inputs, both wrappers, the health checker, all three base units, and all
server/Experiment-1 drop-ins from the exact verified source/evidence set. It
does not execute either candidate binary as root and it does not start any
service.

### 5.2 Stage Policy, Snapshot, Peers, And Secrets

Obtain the immutable V2 policy, its exact file digest and normalized policy
commitment, one current independently checked Idena snapshot, the personalized
PoHW commitment template for this registered miner, and at least one numeric
gossip endpoint through independent channels. Snapshot votes are signed gossip
messages and will be imported from those peers. A filename or a coordinator
statement is not evidence.

```bash
POLICY_SOURCE='/path/to/independently-verified-idena-anchor-policy-v2.json'
EXPECTED_POLICY_SHA256='<published-v2-policy-sha256>'
EXPECTED_POLICY_COMMITMENT='<published-v2-policy-commitment>'
SNAPSHOT_SOURCE='/path/to/independently-verified-current-snapshot.json'
EXPECTED_SNAPSHOT_SHA256='<independently-verified-snapshot-sha256>'
COMMITMENT_SOURCE='/path/to/reviewed-personalized-pohw-commitment.json'
EXPECTED_COMMITMENT_SHA256='<reviewed-personalized-commitment-sha256>'
IDENA_API_KEY_SOURCE='/path/to/local/idena-api.key'
READINESS_REPORT_SOURCE='/path/to/deployment-readiness-report.car'
READINESS_EVIDENCE_SOURCE='/path/to/deployment-readiness-evidence.car'
VERIFIED_GOSSIP_PEERS='<verified-gossip-peer-ip:40406>'
MIN_SNAPSHOT_VOTERS=3

for value in "$EXPECTED_POLICY_SHA256" "$EXPECTED_POLICY_COMMITMENT" \
  "$EXPECTED_SNAPSHOT_SHA256" "$EXPECTED_COMMITMENT_SHA256"; do
  [[ "$value" =~ ^[0-9a-f]{64}$ ]] || {
    echo 'Replace every expected digest or commitment placeholder.' >&2; exit 1;
  }
done
case "$VERIFIED_GOSSIP_PEERS" in
  ''|*'<'*|*'>'*|*[[:space:]]*)
    echo 'Replace the gossip endpoint placeholder with verified numeric peers.' >&2
    exit 1
    ;;
esac
python3 - "$VERIFIED_GOSSIP_PEERS" <<'PY'
import ipaddress, sys
for endpoint in sys.argv[1].split(','):
    if endpoint.startswith('['):
        host, separator, port = endpoint[1:].partition(']:')
    else:
        host, separator, port = endpoint.rpartition(':')
    if not separator or not host or port != '40406':
        raise SystemExit('each gossip peer must be a numeric IP on port 40406')
    ipaddress.ip_address(host)
PY

for artifact in "$POLICY_SOURCE" "$SNAPSHOT_SOURCE" \
  "$COMMITMENT_SOURCE" "$IDENA_API_KEY_SOURCE" \
  "$READINESS_REPORT_SOURCE" "$READINESS_EVIDENCE_SOURCE"; do
  test -s "$artifact"
  test -f "$artifact"
  test ! -L "$artifact"
done
python3 scripts/pohw-experiment-1-launch-policy.py \
  compatibility/experiment-1-launch-policy.json \
  --repo-root "$REPO" \
  --readiness-car "$READINESS_REPORT_SOURCE" \
  --readiness-evidence-car "$READINESS_EVIDENCE_SOURCE" \
  --governance-cli "$RUNTIME_DIR/pohw-governance" \
  --governance-cli-sha256 "$GOVERNANCE_SHA256" \
  --idena-anchor-policy "$POLICY_SOURCE" \
  --require-ready
case "$(stat -c %a "$IDENA_API_KEY_SOURCE")" in
  400|440|600|640) ;;
  *) echo 'The source Idena API-key file has unsafe permissions.' >&2; exit 1 ;;
esac
test "$(sha256sum "$POLICY_SOURCE" | awk '{print $1}')" = \
  "$EXPECTED_POLICY_SHA256"
test "$(sha256sum "$SNAPSHOT_SOURCE" | awk '{print $1}')" = \
  "$EXPECTED_SNAPSHOT_SHA256"
test "$(sha256sum "$COMMITMENT_SOURCE" | awk '{print $1}')" = \
  "$EXPECTED_COMMITMENT_SHA256"

ACTIVATION_ID=$(python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["activation_id"])' \
  "$MANIFEST")
DATA_SUBDIRECTORY=$(python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["network"]["data_subdirectory"])' \
  "$MANIFEST")
[[ "$ACTIVATION_ID" =~ ^[0-9a-f]{64}$ ]]
POHW_DATADIR="/srv/sharechain/${DATA_SUBDIRECTORY}-${ACTIVATION_ID:0:8}"
POHW_SNAPSHOT_DIR="$POHW_DATADIR/snapshots"
PREFLIGHT_DIR="$POHW_DATADIR/preflight"
test -d "$POHW_DATADIR" && test ! -L "$POHW_DATADIR"
install -d -m 0700 "$POHW_DATADIR" "$POHW_SNAPSHOT_DIR" "$PREFLIGHT_DIR"

REGISTRATION_PUBLIC="$POHW_DATADIR/onboarding/03-registration/registration-public.json"
REGISTRY_ANCHOR="$POHW_DATADIR/onboarding/miner-registry-anchor.json"
test -f "$REGISTRATION_PUBLIC" && test ! -L "$REGISTRATION_PUBLIC"
test -f "$REGISTRY_ANCHOR" && test ! -L "$REGISTRY_ANCHOR"
mapfile -t REGISTRATION < <(python3 - "$REGISTRATION_PUBLIC" <<'PY'
import json, pathlib, sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
if value.get('status') != 'registration_ready':
    raise SystemExit('registration status is not registration_ready')
if value.get('registration_version') != 2 or value.get('appended') is not True:
    raise SystemExit('registration is not an appended V2 registration')
delivery = value.get('peer_delivery_summary', {})
if delivery.get('accepted', 0) < 1:
    raise SystemExit('no verified gossip peer accepted the registration')
print(value['miner_id'])
print(value['idena_address'])
PY
)
test "${#REGISTRATION[@]}" -eq 2
POHW_MINER_ID=${REGISTRATION[0]}
POHW_IDENA_ADDRESS=${REGISTRATION[1]}
KEY_DIR="$POHW_DATADIR/keys/$POHW_MINER_ID"
for secret in mining.key claim-owner.key gossip-node.key; do
  test -f "$KEY_DIR/$secret"
  test ! -L "$KEY_DIR/$secret"
  test "$(stat -c %U "$KEY_DIR/$secret")" = ubuntu
  test "$(stat -c %a "$KEY_DIR/$secret")" = 600
done

"$INSTALLED_NODE" inspect-idena-anchor-policy \
  --policy-file "$POLICY_SOURCE" > "$PREFLIGHT_DIR/idena-policy.json"
python3 - "$PREFLIGHT_DIR/idena-policy.json" \
  "$EXPECTED_POLICY_COMMITMENT" \
  "$REPO/compatibility/experiment-1-launch-policy.json" <<'PY'
import json, pathlib, sys
report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
launch = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding='utf-8'))
policy = report.get('policy', {})
if policy.get('schema_version') != 2:
    raise SystemExit('Idena policy is not V2')
if policy.get('experiment_id') != 'p2poolbtc-experiment-1':
    raise SystemExit('Idena policy selects another experiment')
if policy.get('handoff_version_bit') != launch.get('required_handoff_version_bit'):
    raise SystemExit('Idena policy handoff bit does not match launch policy')
if report.get('policy_commitment') != sys.argv[2]:
    raise SystemExit('Idena policy commitment does not match independent evidence')
print('V2 Idena policy evidence verified')
PY

if sudo find "$POHW_DATADIR" -xdev -type l -print -quit | grep -q .; then
  echo 'Refusing to transfer a datadir that contains a symlink.' >&2
  exit 1
fi
sudo chown -hR pohw:pohw "$POHW_DATADIR"
sudo find "$POHW_DATADIR" -xdev -type d -exec chmod 0700 {} +
for secret in mining.key claim-owner.key gossip-node.key; do
  test "$(sudo stat -c %U "$KEY_DIR/$secret")" = pohw
  test "$(sudo stat -c %G "$KEY_DIR/$secret")" = pohw
  test "$(sudo stat -c %a "$KEY_DIR/$secret")" = 600
done

require_safe_directory_destination() {
  local destination=$1
  if sudo test -L "$destination" ||
    { sudo test -e "$destination" && ! sudo test -d "$destination"; }; then
    echo "Unsafe destination directory: $destination" >&2
    exit 1
  fi
}

require_safe_regular_destination() {
  local destination=$1
  if sudo test -L "$destination" ||
    { sudo test -e "$destination" && ! sudo test -f "$destination"; }; then
    echo "Unsafe destination file: $destination" >&2
    exit 1
  fi
}

require_safe_directory_destination /etc/pohw
require_safe_directory_destination /etc/pohw/secrets
for destination in \
  /etc/pohw/experiment-1-full-consensus.json \
  /etc/pohw/experiment-1-deployment-readiness.car \
  /etc/pohw/experiment-1-deployment-readiness-evidence.car \
  /etc/pohw/idena-anchor-policy-v2.json \
  /etc/pohw/secrets/idena-api.key; do
  require_safe_regular_destination "$destination"
done
sudo install -d -o root -g root -m 0755 /etc/pohw
sudo install -d -o root -g pohw -m 0750 /etc/pohw/secrets
sudo install -o root -g root -m 0644 "$MANIFEST" \
  /etc/pohw/experiment-1-full-consensus.json
sudo install -o root -g root -m 0644 "$POLICY_SOURCE" \
  /etc/pohw/idena-anchor-policy-v2.json
sudo install -o root -g root -m 0644 "$READINESS_REPORT_SOURCE" \
  /etc/pohw/experiment-1-deployment-readiness.car
sudo install -o root -g root -m 0644 "$READINESS_EVIDENCE_SOURCE" \
  /etc/pohw/experiment-1-deployment-readiness-evidence.car
sudo install -o root -g pohw -m 0640 "$IDENA_API_KEY_SOURCE" \
  /etc/pohw/secrets/idena-api.key
sudo cmp -s "$MANIFEST" /etc/pohw/experiment-1-full-consensus.json
test "$(sudo sha256sum /etc/pohw/idena-anchor-policy-v2.json | awk '{print $1}')" = \
  "$EXPECTED_POLICY_SHA256"
sudo cmp -s "$IDENA_API_KEY_SOURCE" /etc/pohw/secrets/idena-api.key
sudo cmp -s "$READINESS_REPORT_SOURCE" \
  /etc/pohw/experiment-1-deployment-readiness.car
sudo cmp -s "$READINESS_EVIDENCE_SOURCE" \
  /etc/pohw/experiment-1-deployment-readiness-evidence.car
test "$(sudo stat -c %U:%G /etc/pohw/secrets/idena-api.key)" = root:pohw
test "$(sudo stat -c %a /etc/pohw/secrets/idena-api.key)" = 640
unset IDENA_API_KEY_SOURCE
sudo -u pohw -g pohw test -r /etc/pohw/secrets/idena-api.key
sudo install -o pohw -g pohw -m 0600 "$SNAPSHOT_SOURCE" \
  "$POHW_SNAPSHOT_DIR/current.json"
sudo install -o pohw -g pohw -m 0600 "$COMMITMENT_SOURCE" \
  "$POHW_DATADIR/pohw-commitment-template.json"
test "$(sudo -u pohw -g pohw sha256sum \
  "$POHW_SNAPSHOT_DIR/current.json" | awk '{print $1}')" = \
  "$EXPECTED_SNAPSHOT_SHA256"
test "$(sudo -u pohw -g pohw sha256sum \
  "$POHW_DATADIR/pohw-commitment-template.json" | awk '{print $1}')" = \
  "$EXPECTED_COMMITMENT_SHA256"
test "$(sudo stat -c %a "$POHW_SNAPSHOT_DIR/current.json")" = 600
test "$(sudo stat -c %a \
  "$POHW_DATADIR/pohw-commitment-template.json")" = 600
python3 scripts/pohw-experiment-1-manifest.py verify \
  /etc/pohw/experiment-1-full-consensus.json
```

The V2 policy and manifest are public evidence. The Idena API key and all three
P2Pool keys are secrets. The environment below contains only paths to those
files, never their contents. Do not use `cat`, command substitution, or a shell
variable to move a credential.

### 5.3 Start And Verify Core While Both P2Pool Units Are Stopped

Start the evidence-bound Core unit only after the launch evidence above is in
place. It may need substantial time to validate inherited history. Continue
only when `chain=pohw`, `ibd=False`, blocks equal headers at or above the pinned
revision-3 checkpoint height `958175`, that checkpoint hash is exact, and the
revision-3 replay rule is reported:

```bash
sudo systemctl start bitcoind-pohw-experiment-1.service
sudo systemctl is-active --quiet bitcoind-pohw-experiment-1.service
sudo -u bitcoin-pohw -g bitcoin-pohw-rpc \
  /usr/local/libexec/pohw-bitcoin-core-v31.1/bin/bitcoin-cli \
  -datadir=/srv/bitcoin/pohw -chain=pohw \
  -rpccookiefile=/run/bitcoin-pohw-rpc/.cookie getblockchaininfo |
python3 -c 'import json,sys; d=json.load(sys.stdin); p=d.get("pohw_experiment",{}); print("chain="+d["chain"]); print("height="+str(d["blocks"])); print("headers="+str(d["headers"])); print("ibd="+str(d["initialblockdownload"])); print("replay="+str(p.get("replay_protection")))'

CORE_CLI=/usr/local/libexec/pohw-bitcoin-core-v31.1/bin/bitcoin-cli
CORE_RPC=(sudo -u bitcoin-pohw -g bitcoin-pohw-rpc \
  "$CORE_CLI" -datadir=/srv/bitcoin/pohw -chain=pohw \
  -rpccookiefile=/run/bitcoin-pohw-rpc/.cookie)
CHAIN_INFO="$("${CORE_RPC[@]}" getblockchaininfo)"
python3 -c 'import json,sys; d=json.loads(sys.argv[1]); assert type(d.get("blocks")) is int and type(d.get("headers")) is int; assert d["blocks"] == d["headers"] and d["blocks"] >= 958175; assert d.get("initialblockdownload") is False' "$CHAIN_INFO"
test "$("${CORE_RPC[@]}" getblockhash 958175)" = \
  09b71e8e2ff0fbac330838ad82f71f21c73bc6e420f1bbd17aba05bb03bc4bd6
unset CHAIN_INFO
```

Do not start gossip, the adapter, Stratum, or any bootstrap miner if either
checkpoint command fails. Mining below this checkpoint creates a divergent
prefix that revision 3 will reject.

Then re-read the finalized miner record from the local loopback Idena node and
require it to match the anchor used for registration. Then import signed gossip
history, prove a peer is reachable, derive snapshot values from verified local
evidence, and make one non-mining dynamic job build through the local Core
cookie. These commands neither bind a service port nor submit a share or block.

```bash
run_pohw_to() {
  local output=$1
  shift
  sudo -u pohw -g pohw -- "$@" |
    sudo -u pohw -g pohw tee "$output" >/dev/null
}

run_pohw_rpc_to() {
  local output=$1
  shift
  sudo -u pohw -g bitcoin-pohw-rpc -- "$@" |
    sudo -u pohw -g pohw tee "$output" >/dev/null
}

CONTRACT_ADDRESS=$(python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["registry_contract_address"])' \
  /etc/pohw/idena-anchor-policy-v2.json)
run_pohw_to "$PREFLIGHT_DIR/local-miner-registry-anchor.json" \
  "$INSTALLED_NODE" read-miner-registry-anchor \
  --contract-address "$CONTRACT_ADDRESS" \
  --experiment-id p2poolbtc-experiment-1 \
  --idena-address "$POHW_IDENA_ADDRESS" \
  --miner-id "$POHW_MINER_ID" \
  --registration-sequence 1 \
  --idena-rpc-url http://127.0.0.1:9009 \
  --idena-api-key-file /etc/pohw/secrets/idena-api.key
sudo -u pohw -g pohw cmp -s \
  "$REGISTRY_ANCHOR" "$PREFLIGHT_DIR/local-miner-registry-anchor.json" || {
  echo 'Local finalized Idena registry anchor mismatch.' >&2; exit 1;
}
require_safe_regular_destination /etc/pohw/miner-registry-anchor.json
sudo install -o root -g root -m 0644 \
  "$PREFLIGHT_DIR/local-miner-registry-anchor.json" \
  /etc/pohw/miner-registry-anchor.json
unset CONTRACT_ADDRESS POHW_IDENA_ADDRESS

IFS=',' read -r -a GOSSIP_PEERS <<< "$VERIFIED_GOSSIP_PEERS"
test "${#GOSSIP_PEERS[@]}" -ge 1
peer_index=0
for peer in "${GOSSIP_PEERS[@]}"; do
  peer_index=$((peer_index + 1))
  run_pohw_to "$PREFLIGHT_DIR/peer-$peer_index-add.json" \
    "$INSTALLED_NODE" add-gossip-peer \
    --datadir "$POHW_DATADIR" --peer-addr "$peer"
  run_pohw_to "$PREFLIGHT_DIR/peer-$peer_index-sync.json" \
    "$INSTALLED_NODE" sync-gossip \
    --datadir "$POHW_DATADIR" --peer-addr "$peer" --limit 4096
done

PREFLIGHT_ARGS=(multinode-preflight \
  --datadir "$POHW_DATADIR" \
  --snapshot-dir "$POHW_SNAPSHOT_DIR" \
  --miner-id "$POHW_MINER_ID")
for peer in "${GOSSIP_PEERS[@]}"; do
  PREFLIGHT_ARGS+=(--peer-addr "$peer")
done
run_pohw_to "$PREFLIGHT_DIR/multinode-preflight.json" \
  "$INSTALLED_NODE" "${PREFLIGHT_ARGS[@]}"
sudo -u pohw -g pohw python3 - \
  "$PREFLIGHT_DIR/multinode-preflight.json" <<'PY'
import json, pathlib, sys
report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
readiness = report.get('readiness', {})
required = ('has_registered_miner', 'has_snapshot', 'has_gossip_peers')
failed = [name for name in required if readiness.get(name) is not True]
reachable = sum(
    item.get('reachable') is True
    for item in report.get('peer_inventory_probe', [])
    if isinstance(item, dict)
)
if failed or reachable < 1:
    raise SystemExit(f'P2Pool preflight failed: pending={failed}, reachable={reachable}')
print('P2Pool registration, snapshot, and peer preflight passed')
PY

run_pohw_to "$PREFLIGHT_DIR/mining-snapshot-evidence.json" \
  "$INSTALLED_NODE" mining-snapshot-evidence \
  --datadir "$POHW_DATADIR" \
  --snapshot-dir "$POHW_SNAPSHOT_DIR" \
  --miner-id "$POHW_MINER_ID" \
  --min-snapshot-voters "$MIN_SNAPSHOT_VOTERS"
mapfile -t SNAPSHOT_BINDING < <(sudo -u pohw -g pohw python3 - \
  "$PREFLIGHT_DIR/mining-snapshot-evidence.json" \
  "$MIN_SNAPSHOT_VOTERS" <<'PY'
import json, pathlib, sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
if value.get('miner_eligible') is not True:
    raise SystemExit('registered identity is not eligible in the verified snapshot')
if value.get('distinct_voter_count', 0) < int(sys.argv[2]):
    raise SystemExit('signed snapshot-voter quorum is too small')
print(value['snapshot_id'])
print(value['proof_root'])
PY
)
test "${#SNAPSHOT_BINDING[@]}" -eq 2
POHW_IDENA_SNAPSHOT_ID=${SNAPSHOT_BINDING[0]}
POHW_IDENA_SNAPSHOT_PROOF_ROOT=${SNAPSHOT_BINDING[1]}

RPC_COOKIE=/run/bitcoin-pohw-rpc/.cookie
sudo test -f "$RPC_COOKIE" && sudo test ! -L "$RPC_COOKIE"
test "$(sudo stat -c %G "$RPC_COOKIE")" = bitcoin-pohw-rpc
test "$(sudo stat -c %a "$RPC_COOKIE")" = 640
sudo -u pohw -g bitcoin-pohw-rpc test -r "$RPC_COOKIE"
run_pohw_rpc_to "$PREFLIGHT_DIR/core-mining-readiness.json" \
  "$INSTALLED_NODE" \
  bitcoin-mining-readiness \
  --rpc-url http://127.0.0.1:40414 \
  --rpc-cookie-file "$RPC_COOKIE"
sudo -u pohw -g pohw python3 - \
  "$PREFLIGHT_DIR/core-mining-readiness.json" <<'PY'
import json, pathlib, sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
if value.get('ready') is not True or value.get('chain') != 'pohw':
    raise SystemExit('local Core RPC is not mining-ready on chain=pohw')
if value.get('initialBlockDownload') is not False:
    raise SystemExit('local Core RPC is still in initial block download')
print('Local Experiment 1 Core RPC preflight passed')
PY

run_pohw_rpc_to "$PREFLIGHT_DIR/dynamic-job-preflight.json" \
  "$INSTALLED_NODE" \
  build-dynamic-pohw-stratum-job-rpc \
  --datadir "$POHW_DATADIR" \
  --snapshot-dir "$POHW_SNAPSHOT_DIR" \
  --miner-id "$POHW_MINER_ID" \
  --pohw-commitment-file "$POHW_DATADIR/pohw-commitment-template.json" \
  --job-out "$PREFLIGHT_DIR/mining-job.json" --replace \
  --rpc-url http://127.0.0.1:40414 \
  --rpc-cookie-file "$RPC_COOKIE"
sudo -u pohw -g pohw test -s "$PREFLIGHT_DIR/mining-job.json"
```

The false work-template/share fields in `multinode-preflight.json` are expected
before first start. The three explicitly checked readiness fields, at least one
reachable verified peer, the signed-voter/identity evidence, local V2 registry
read-back, `chain=pohw`, and the dynamic job build must all pass.

Now write the root-owned service environment and verify the already installed
Experiment 1 gate drop-ins. The base units, verifier binaries, and executable
wrappers remain the fixed evidence-installed files. The server drop-ins use the
empty root-owned `/opt/p2pool` only as `WorkingDirectory` and confine writes to
`/srv/sharechain`. `POHW_WORKDIR`, the health checker, and both `ExecStart`
values point at the fixed installed runtime, so systemd does not execute a
wrapper or helper from the checkout.

```bash
require_safe_regular_destination /etc/pohw/p2pool.env
ENV_TMP=$(mktemp)
trap 'rm -f "$ENV_TMP"' EXIT
cat > "$ENV_TMP" <<EOF
POHW_EXPERIMENT_NO_VALUE_ACK=I_UNDERSTAND_NO_VALUE
POHW_WORKDIR=/usr/local/libexec/p2pool-experiment-1
POHW_P2POOL_NODE_BIN=/usr/local/libexec/p2pool-experiment-1/p2pool-node
POHW_DATADIR=$POHW_DATADIR
POHW_GOSSIP_NETWORK_ID=$ACTIVATION_ID
POHW_SNAPSHOT_DIR=$POHW_SNAPSHOT_DIR
POHW_MINER_ID=$POHW_MINER_ID
POHW_MINING_SECRET_KEY_FILE=$KEY_DIR/mining.key
POHW_NODE_SECRET_KEY_FILE=$KEY_DIR/gossip-node.key
POHW_IDENA_SNAPSHOT_ID=$POHW_IDENA_SNAPSHOT_ID
POHW_IDENA_SNAPSHOT_PROOF_ROOT=$POHW_IDENA_SNAPSHOT_PROOF_ROOT
POHW_REQUIRE_IDENA_ANCHOR_POLICY=true
POHW_ADMIT_PEER_WORK_TEMPLATES=true
POHW_IDENA_ANCHOR_POLICY=/etc/pohw/idena-anchor-policy-v2.json
POHW_IDENA_RPC_ALLOW_REMOTE=false
POHW_MINER_REGISTRY_EXPERIMENT_ID=p2poolbtc-experiment-1
POHW_MINER_REGISTRY_ANCHOR_FILE=/etc/pohw/miner-registry-anchor.json
IDENA_RPC_URL=http://127.0.0.1:9009
IDENA_API_KEY_FILE=/etc/pohw/secrets/idena-api.key
POHW_PEER_ADDRS=$VERIFIED_GOSSIP_PEERS
POHW_ALLOW_PUBLIC_PEERS=true
POHW_BITCOIN_RPC_URL=http://127.0.0.1:40414
POHW_BITCOIN_EXPECTED_CHAIN=pohw
POHW_BITCOIN_RPC_COOKIE_FILE=/run/bitcoin-pohw-rpc/.cookie
POHW_BITCOIN_RPC_ALLOW_REMOTE=false
POHW_STRATUM_BUILD_JOB_FROM_RPC=false
POHW_STRATUM_BUILD_POHW_JOB_FROM_RPC=false
POHW_STRATUM_DERIVE_POHW_PAYOUTS_FROM_STATE=true
POHW_STRATUM_DYNAMIC_MIN_SNAPSHOT_VOTERS=$MIN_SNAPSHOT_VOTERS
POHW_STRATUM_POHW_COMMITMENT_FILE=$POHW_DATADIR/pohw-commitment-template.json
POHW_STRATUM_BLOCK_CANDIDATE_DIR=$POHW_DATADIR/block-candidates
POHW_PAYOUT_CANDIDATE_DIR=$POHW_DATADIR/payout-candidates
POHW_STRATUM_AUTO_SUBMIT_BLOCKS=true
POHW_STRATUM_ALLOW_MAINNET_SUBMIT=false
POHW_STRATUM_BIND_ADDR=127.0.0.1:3333
POHW_STRATUM_ALLOW_NON_LOOPBACK=false
POHW_STRATUM_APPEND=true
POHW_MAINNET_HANDOFF_ACTIVE=false
POHW_MAINNET_HANDOFF_ENABLED=false
EOF
sudo install -o root -g root -m 0600 "$ENV_TMP" /etc/pohw/p2pool.env
rm -f "$ENV_TMP"
trap - EXIT

for destination in \
  /etc/systemd/system/pohw-gossip-mesh.service.d/experiment-1.conf \
  /etc/systemd/system/pohw-mining-adapter.service.d/experiment-1.conf; do
  sudo test -f "$destination"
  sudo test ! -L "$destination"
done
sudo systemd-analyze verify \
  /etc/systemd/system/pohw-gossip-mesh.service \
  /etc/systemd/system/pohw-mining-adapter.service
for unit in pohw-gossip-mesh.service pohw-mining-adapter.service; do
  test "$(sudo systemctl show -p User --value "$unit")" = pohw
  test "$(sudo systemctl show -p Group --value "$unit")" = pohw
  test "$(sudo systemctl show -p WorkingDirectory --value "$unit")" = \
    /opt/p2pool
  sudo systemctl show -p DropInPaths --value "$unit" | \
    grep -Fq "/etc/systemd/system/$unit.d/server.conf"
  sudo systemctl show -p DropInPaths --value "$unit" | \
    grep -Fq "/etc/systemd/system/$unit.d/experiment-1.conf"
done
if sudo test -e /etc/pohw/enable-experiment-1-mining; then
  echo 'Stale Experiment 1 start marker exists; remove it and rerun preflight.' >&2
  exit 1
fi
for unit in pohw-gossip-mesh.service pohw-mining-adapter.service; do
  if sudo systemctl is-enabled --quiet "$unit"; then
    echo "$unit became enabled before preflight completed." >&2
    exit 1
  fi
  set +e
  sudo systemctl is-active --quiet "$unit"
  unit_status=$?
  set -e
  if [[ "$unit_status" -ne 3 ]]; then
    echo "$unit is not provably inactive (status $unit_status)." >&2
    exit 1
  fi
done
```

### 5.4 Unlock And Start In Order

Rerun the same strict launch-policy verifier immediately before creating the
one start marker. Enabling a unit does not start it. Start gossip first and
require it to remain active before starting the adapter.

```bash
STATUS=$(sudo -u pohw -g pohw /usr/bin/python3 -I \
  /usr/local/libexec/p2pool-experiment-1/pohw-experiment-1-launch-policy.py \
  /usr/local/libexec/p2pool-experiment-1/compatibility/experiment-1-launch-policy.json \
  --repo-root /usr/local/libexec/p2pool-experiment-1 \
  --readiness-car /etc/pohw/experiment-1-deployment-readiness.car \
  --readiness-evidence-car \
    /etc/pohw/experiment-1-deployment-readiness-evidence.car \
  --governance-cli /usr/local/libexec/p2pool-experiment-1/pohw-governance \
  --governance-cli-sha256 "$GOVERNANCE_SHA256" \
  --idena-anchor-policy /etc/pohw/idena-anchor-policy-v2.json \
  --require-ready | sed -n 's/^launch policy verified: //p')
test "$STATUS" = ready-for-public-join

start_failed() {
  sudo rm -f /etc/pohw/enable-experiment-1-mining || {
    echo 'Failed to remove the Experiment 1 start marker.' >&2
    exit 1
  }
  sudo systemctl disable --now \
    pohw-mining-adapter.service pohw-gossip-mesh.service \
    bitcoind-pohw-experiment-1.service || {
    echo 'Failed to disable and stop the Experiment 1 units.' >&2
    exit 1
  }
  for unit in pohw-mining-adapter.service pohw-gossip-mesh.service \
    bitcoind-pohw-experiment-1.service; do
    set +e
    sudo systemctl is-active --quiet "$unit"
    unit_status=$?
    set -e
    if [[ "$unit_status" -ne 3 ]]; then
      echo "$unit cleanup is incomplete (status $unit_status)." >&2
      exit 1
    fi
  done
  echo 'Experiment 1 start failed; units stopped and start marker removed.' >&2
  exit 1
}

sudo install -o root -g root -m 0600 /dev/null \
  /etc/pohw/enable-experiment-1-mining || start_failed
sudo systemctl enable \
  bitcoind-pohw-experiment-1.service \
  pohw-gossip-mesh.service pohw-mining-adapter.service || start_failed

sudo systemctl start pohw-gossip-mesh.service || start_failed
sleep 3
sudo systemctl is-active --quiet pohw-gossip-mesh.service || start_failed
sudo systemctl start pohw-mining-adapter.service || start_failed
sleep 5
sudo systemctl is-active --quiet bitcoind-pohw-experiment-1.service || start_failed
sudo systemctl is-active --quiet pohw-gossip-mesh.service || start_failed
sudo systemctl is-active --quiet pohw-mining-adapter.service || start_failed
sudo systemctl show -p ExecStart --value pohw-gossip-mesh.service | \
  grep -Fq /usr/local/libexec/p2pool-experiment-1/pohw-run-gossip-mesh.sh || \
  start_failed
sudo systemctl show -p ExecStart --value pohw-mining-adapter.service | \
  grep -Fq /usr/local/libexec/p2pool-experiment-1/pohw-run-mining-adapter.sh || \
  start_failed
run_pohw_to "$PREFLIGHT_DIR/post-start-status.json" \
  "$INSTALLED_NODE" status --datadir "$POHW_DATADIR" || start_failed
printf 'Experiment 1 P2Pool services are active from the fixed installed runtime.\n'
```

Any nonzero command is a failed join. Keep the units stopped and the marker
absent until the cause is fixed and the complete preflight is rerun. Inspect
`journalctl` locally; do not publish an unsanitized journal.

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

The public-join procedure does not install the bootstrap-miner timer: that unit
is outside the evidence-bound adapter installer and executes a checkout helper.
Do not add it to a participant host. The bounded command above is a deliberate
one-shot acceptance check from the exact clean release checkout, never a Pi or
systemd workload.

For ordinary participation, connect your mining hardware to your own adapter
instead of repeatedly running the smoke tool.

## How To Know You Joined Successfully

All rows must pass; a dashboard screenshot alone is not proof.

### Review Or Rehearsal Success

A Lane A rehearsal succeeds when the checkout is clean, the launch-policy
verifier reports `blocked-release-readiness`, the Experiment 1 manifest
verifies, and the focused Rust tests pass. It must not create a registration,
start a service, contact a live peer, or request any secret. This proves only
that the candidate can be reviewed and built locally.

### Live Join Success

After this miner has submitted a share, run the guarded proof from the same
clean canonical checkout. It re-parses the DAO-selected ecosystem CAR, hashes
the governance verifier before executing it, reproduces the local source CID,
rechecks all four runtime artifact digests, and probes only the reviewed local
Core systemd service and loopback RPC:

```sh
./scripts/pohw-community-onboard.sh \
  --role pruned-miner \
  --storage-path /srv \
  --expected-ecosystem-cid "$EXPECTED_ECOSYSTEM_CID" \
  --candidate-ecosystem-car "$CANDIDATE_ECOSYSTEM_CAR" \
  --source-car "$P2POOL_SOURCE_CAR" \
  --governance-cli "$RUNTIME_DIR/pohw-governance" \
  --readiness-car "$READINESS_REPORT_SOURCE" \
  --readiness-evidence-car "$READINESS_EVIDENCE_SOURCE" \
  --idena-anchor-policy /etc/pohw/idena-anchor-policy-v2.json \
  --probe-live \
  --p2pool-node "$INSTALLED_NODE" \
  --p2pool-datadir "$POHW_DATADIR" \
  --snapshot-dir "$POHW_SNAPSHOT_DIR" \
  --miner-id "$POHW_MINER_ID" \
  --bitcoin-cli /usr/local/libexec/pohw-bitcoin-core-v31.1/bin/bitcoin-cli \
  --bitcoin-datadir /srv/bitcoin/pohw \
  --bitcoin-cookie-file /run/bitcoin-pohw-rpc/.cookie
```

The only complete onboarding result is `live-join-verified`. Historical global
shares cannot satisfy this proof: the registered miner must have at least one
active share timestamped within the last hour. Core must have a fully verified
tip no more than two hours old, at least one fork peer, the exact manifest-bound
consensus fingerprint and checkpoint, and the attested running executable and
arguments behind `bitcoind-pohw-experiment-1.service`. The Idena snapshot must
mark this miner eligible and have at least three distinct verified voters.

| Check | Required result |
| --- | --- |
| Source | The independently read DAO ecosystem CID, ecosystem CAR, source CAR, clean checkout, optional Git metadata, and attested executable digests all agree |
| Core | Exact local systemd executable/profile, `chain=pohw`, `ibd=False`, fresh fully verified tip, at least one peer, and loopback-only RPC |
| Identity | Local replay reports one registration for your miner and the gossip peer accepts its envelope |
| Snapshot | Your eligible identity is present in the independently verified snapshot with at least three distinct voters |
| Sharechain | The global share tip exists and this miner has a fresh active share; another miner's historical share does not count |
| Block | Optional stronger mining proof: when this miner finds an accepted fork block, the local Core height increases |
| UI | The dashboard shows the same aggregate height/share counts as your local commands |

Record the Core height and local share count before connecting a miner, then
run the same commands again after an accepted submission:

```sh
sudo -u bitcoin-pohw -g bitcoin-pohw-rpc \
  /usr/local/libexec/pohw-bitcoin-core-v31.1/bin/bitcoin-cli \
  -datadir=/srv/bitcoin/pohw -chain=pohw \
  -rpccookiefile=/run/bitcoin-pohw-rpc/.cookie getblockcount

sudo -u pohw -g pohw \
  /usr/local/libexec/p2pool-experiment-1/p2pool-node \
  status --datadir "$POHW_DATADIR"
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
