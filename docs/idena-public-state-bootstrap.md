# Idena Public-State Bootstrap

This workflow lets a fast temporary Idena node synchronize public state and hand
that state to the Raspberry Pi without moving either node's identity. The source
exports only:

- `idenachain.db`
- `ipfs/badgerds`, named `ipfs-badgerds` in transit
- `snapshots`

It never exports `keystore/nodekey`, `api.key`, `ipfs/config`, `ipfs/swarm.key`,
wallet files, addresses, or service configuration. The Pi hashes its four
key-bearing files before and after the swap. The source identity must remain a
temporary, non-mining identity; it is not copied to the Pi.

## Protocol

Each handoff gets a random 128-bit transfer ID. Manifest schema 2 binds that ID,
the source height, exact file and byte counts, and a SHA-256 tree digest for every
component. `READY` is transferred last and must contain the same transfer ID and
height.

The Pi writer and importer use `/run/lock/idena-return-transfer.lock`. The writer
holds it for every rsync session; the importer holds it continuously from digest
validation through commit or rollback. This prevents inbox changes after
validation. The writer also stops a transfer before free space falls below 10
GiB and imposes a six-hour transfer limit.

The source fsyncs `pushed.json` with phase `ready-intent` before sending `READY`.
It changes the phase to `ready-sent` only after rsync succeeds. Either phase
blocks automatic retransmission. The Pi fsyncs `in-progress.json` before every
destructive boundary and recovers it automatically after process failure or
reboot.

## Source Credentials

On the Hetzner host, create a dedicated key. Never add this key or the resulting
environment files to Git.

```sh
sudo install -d -o root -g root -m 0700 /etc/idena-return
sudo ssh-keygen -q -t ed25519 -N '' -C idena-public-state-return \
  -f /etc/idena-return/id_ed25519
sudo chmod 0600 /etc/idena-return/id_ed25519
sudo cat /etc/idena-return/id_ed25519.pub
```

Transfer only the displayed public key to the Pi over an already authenticated
administrative connection.

## Pi Setup

Install the destination files from this repository:

```sh
sudo apt-get update
sudo apt-get install -y python3 rsync
sudo install -d -o root -g root -m 0755 /usr/local/libexec
sudo install -m 0755 scripts/idena-public-state-import.sh \
  /usr/local/sbin/idena-public-state-import
sudo install -m 0755 scripts/idena-public-state-manifest.py \
  /usr/local/libexec/idena-public-state-manifest.py
sudo install -m 0755 scripts/idena-private-lock-exec.py \
  /usr/local/libexec/idena-private-lock-exec.py
sudo install -m 0755 scripts/idena-return-rrsync-guard.py \
  /usr/local/libexec/idena-return-rrsync-guard.py
sudo install -m 0755 scripts/idena-return-restricted-shell.sh \
  /usr/local/sbin/idena-return-restricted-shell
```

Create the dedicated account idempotently, then create the managed paths and
shared lock from the tmpfiles declaration:

```sh
getent group idena-return >/dev/null || sudo groupadd --system idena-return
id idena-return >/dev/null 2>&1 || sudo useradd --system \
  --gid idena-return \
  --home-dir /var/lib/idena-return-home \
  --create-home \
  --shell /usr/local/sbin/idena-return-restricted-shell \
  idena-return
sudo usermod --home /var/lib/idena-return-home \
  --shell /usr/local/sbin/idena-return-restricted-shell idena-return
sudo install -d -o idena-return -g idena-return -m 0700 \
  /var/lib/idena-return-home /var/lib/idena-return-home/.ssh
sudo install -d -o root -g root -m 0755 /etc/tmpfiles.d
sudo install -m 0644 deploy/tmpfiles/idena-return.conf \
  /etc/tmpfiles.d/idena-return.conf
sudo install -m 0644 deploy/tmpfiles/idena-public-state-locks.conf \
  /etc/tmpfiles.d/idena-public-state-locks.conf
sudo systemd-tmpfiles --create \
  /etc/tmpfiles.d/idena-return.conf \
  /etc/tmpfiles.d/idena-public-state-locks.conf
```

Create `/var/lib/idena-return-home/.ssh/authorized_keys` with one line. Replace
`PUBLIC_KEY` with the dedicated source public key, not an administrative key:

```text
from="127.0.0.1",restrict,command="/usr/bin/rrsync -wo /var/lib/idena-return-inbox" ssh-ed25519 PUBLIC_KEY idena-public-state-return
```

The `127.0.0.1` source constraint is correct when Tailscale Serve proxies port
2222 to local OpenSSH port 22. For direct OpenSSH without that proxy, use the
source host's fixed tailnet address instead. Apply strict ownership:

```sh
sudo chown idena-return:idena-return \
  /var/lib/idena-return-home/.ssh/authorized_keys
sudo chmod 0600 /var/lib/idena-return-home/.ssh/authorized_keys
```

Add a user-specific OpenSSH policy in
`/etc/ssh/sshd_config.d/60-idena-return.conf`:

```text
Match User idena-return
    AuthenticationMethods publickey
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    PermitTTY no
    AllowAgentForwarding no
    AllowTcpForwarding no
    X11Forwarding no
    PermitTunnel no
```

If the existing SSH policy uses `AllowUsers`, merge `idena-return` into that
existing directive. Do not create a second conflicting `AllowUsers` line. Then:

```sh
sudo sshd -t
sudo systemctl reload ssh.service
sudo tailscale serve --bg --tcp 2222 tcp://127.0.0.1:22
sudo tailscale serve status
```

Install and enable the importer:

```sh
sudo install -d -o root -g root -m 0700 /etc/idena-return
sudo install -m 0600 deploy/idena-return/import.env.example \
  /etc/idena-return/import.env
sudo install -m 0644 deploy/systemd/idena-public-state-import.service \
  /etc/systemd/system/idena-public-state-import.service
sudo install -m 0644 deploy/systemd/idena-public-state-import.path \
  /etc/systemd/system/idena-public-state-import.path
sudo systemctl daemon-reload
sudo systemd-analyze verify \
  /etc/systemd/system/idena-public-state-import.service \
  /etc/systemd/system/idena-public-state-import.path
sudo systemctl enable --now idena-public-state-import.path
```

## Source Setup

Install the source files and create their root-owned state directories:

```sh
sudo apt-get update
sudo apt-get install -y python3 rsync openssh-client
sudo install -d -o root -g root -m 0755 /usr/local/libexec
sudo install -m 0755 scripts/idena-public-state-export-push.sh \
  /usr/local/sbin/idena-public-state-export-push
sudo install -m 0755 scripts/idena-public-state-manifest.py \
  /usr/local/libexec/idena-public-state-manifest.py
sudo install -m 0755 scripts/idena-private-lock-exec.py \
  /usr/local/libexec/idena-private-lock-exec.py
sudo install -d -o root -g root -m 0700 \
  /srv/idena-return-export /var/lib/idena-return
sudo install -m 0644 deploy/systemd/idena-public-state-export.service \
  /etc/systemd/system/idena-public-state-export.service
sudo install -m 0644 deploy/systemd/idena-public-state-export.timer \
  /etc/systemd/system/idena-public-state-export.timer
sudo install -m 0644 deploy/tmpfiles/idena-public-state-locks.conf \
  /etc/tmpfiles.d/idena-public-state-locks.conf
sudo systemd-tmpfiles --create \
  /etc/tmpfiles.d/idena-public-state-locks.conf
sudo install -m 0600 deploy/idena-return/export.env.example \
  /etc/idena-return/export.env
```

Edit `/etc/idena-return/export.env`. Set `IDENA_RETURN_TARGET` to the Pi's stable
Tailscale DNS name or address and set `IDENA_EXPORT_MIN_HEIGHT` to a recently
observed mainnet height. Keep port 2222 for the Tailscale-to-OpenSSH proxy.

Pin the Pi's OpenSSH host key. Capture it only over the tailnet, compare its
fingerprint with the Pi's `/etc/ssh/ssh_host_ed25519_key.pub` through a separate
trusted administrative session, and install it only after they match:

```sh
sudo ssh-keyscan -p 2222 PI_TAILSCALE_DNS \
  | sudo tee /etc/idena-return/known_hosts.candidate >/dev/null
sudo ssh-keygen -lf /etc/idena-return/known_hosts.candidate
sudo install -o root -g root -m 0600 \
  /etc/idena-return/known_hosts.candidate /etc/idena-return/known_hosts
sudo rm -f /etc/idena-return/known_hosts.candidate
```

Load and verify the units, but do not enable the timer until the destination
capacity probe succeeds:

```sh
sudo systemctl daemon-reload
sudo systemd-analyze verify \
  /etc/systemd/system/idena-public-state-export.service \
  /etc/systemd/system/idena-public-state-export.timer
sudo ssh -i /etc/idena-return/id_ed25519 -p 2222 \
  -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/etc/idena-return/known_hosts \
  IDENA_RETURN_TARGET idena-return-capacity
sudo systemctl enable --now idena-public-state-export.timer
```

The capacity command must print exactly one integer. Arbitrary commands and
downloads must fail. The timer exits without modifying data until RPC reports
`syncing=false`, `wrongTime=false`, `currentBlock >= highestBlock`, the minimum
peer and height gates pass, and those conditions remain stable for two minutes.

## Verification

Use these checks without printing keys, RPC credentials, or identity data:

```sh
# Source
sudo systemctl status idena-public-state-export.timer --no-pager
sudo journalctl -u idena-public-state-export.service --no-pager -n 100
sudo systemd-analyze security idena-public-state-export.service

# Pi
sudo systemctl status idena-public-state-import.path --no-pager
sudo journalctl -u idena-public-state-import.service --no-pager -n 100
sudo systemd-analyze security idena-public-state-import.service
```

After success, `/var/lib/idena-return-state/completed.json` contains only schema,
transfer ID, source height, validated height, and completion time. The inbox and
rollback directory are empty. The Pi's original key files remain in place.

## Recovery

The Pi handles normal interruption automatically:

- `prepared`: restart the original service if needed, clear the journal, retry.
- `swapping` or `running`: restore the old state and quarantine the transfer.
- `committed`: finish cleanup without rolling back the validated state.

The path unit watches both `READY` and `in-progress.json`, so recovery also runs
after reboot. Failed or rejected material is stored below
`/var/lib/idena-return-failed/` for inspection.

On the source, `pushed.json` is intentionally fail-closed:

- `ready-intent`: `READY` may or may not have arrived.
- `ready-sent`: delivery returned success, but the Pi may still be importing.

Never delete `pushed.json` merely to make the timer retry. First compare its
transfer ID with the Pi's inbox, transaction journal, completion record, and
service log. Stop the source timer and importer path before manually clearing a
failed transfer. Only after proving that the transfer was neither committed nor
still in progress should an operator remove the source decision file and retry.

The manifest is integrity metadata, not a signature. The dedicated SSH private
key, pinned Pi host key, forced command, restricted shell, tailnet ACL, shared
lock, and free-space guard together form the transport trust boundary.
