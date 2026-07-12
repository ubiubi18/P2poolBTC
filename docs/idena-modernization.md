# Idena Modernization Runbook

This runbook upgrades an existing Idena 1.1.2 node to the compatibility build
without changing Idena network, genesis, gossip protocol, node key, or chain
data. Treat the node key, API key, IPFS identity, and swarm key as private.

## Compatibility Gate

Before deployment, require all of the following from the exact source commit:

- full `go test ./...` and `go vet ./...` pass;
- legacy key-derivation, bitmap, IPFS CID, resource, and Wasm result vectors pass;
- a modern canary exchanges blocks with an unmodified 1.1.2 node;
- sampled block hash, parent hash, state root, and identity root match 1.1.2;
- the built binary checksum is recorded outside the repository;
- a secret scan reports no findings.

The compatibility build must continue to use mainnet network ID `1` and
`/idena/gossip/1.1.0`. Do not deploy a build that changes consensus constants,
genesis resources, transaction encoding, reward rules, or protocol ID.

## Backup

Stop writers and make a same-filesystem or offline backup before migrating the
IPFS repository. Never copy a live LevelDB/Badger repository.

```sh
sudo systemctl stop idena.service
sudo install -d -m 0700 -o ubuntu -g ubuntu /var/lib/idena-rollback-v1.1.2
sudo rsync -aHAX --numeric-ids /var/lib/idena/ /var/lib/idena-rollback-v1.1.2/
```

Confirm that source and backup sizes are plausible and that enough free space
remains for rollback. Do not print or archive private files in CI artifacts.

## IPFS Repository

The modern embedded Kubo expects repository version 18. Use checksum-verified
official ARM64/AMD64 binaries for Kubo 0.42.0 and `fs-repo-migrations` 2.0.2.
The external migrator handles versions below 16; Kubo handles 16 through 18.

```sh
sudo -u ubuntu env IPFS_PATH=/var/lib/idena/ipfs \
  /usr/local/libexec/fs-repo-migrations-2.0.2 -to 16 -y

MIGRATION_HOME="$(sudo -u ubuntu mktemp -d /tmp/idena-kubo-home.XXXXXX)"
sudo -u ubuntu env \
  HOME="$MIGRATION_HOME" \
  XDG_CONFIG_HOME="$MIGRATION_HOME/xdg-config" \
  XDG_DATA_HOME="$MIGRATION_HOME/xdg-data" \
  IPFS_PATH=/var/lib/idena/ipfs \
  /usr/local/libexec/ipfs-kubo-0.42.0 repo migrate --to=18
sudo rm -rf "$MIGRATION_HOME"
```

If the stopped legacy node left an empty `repo.lock`, remove it only after both
`pgrep -x idena-node` and `lslocks` prove that no process holds the repository.
After migration, require version 18, run `ipfs repo verify`, and compare the
IPFS identity and swarm key byte-for-byte with the backup.

New repositories created by the modern Idena fork use FlatFS. Existing Badger
v1 repositories remain readable and are deliberately preserved in place so an
upgrade cannot silently discard data. Kubo plans to remove Badger v1 later in
2026 and states that no complete automated conversion is feasible. Its supported
path creates a new FlatFS repository and transfers pinned DAGs only.

Before considering that transfer, stop the node, make an offline copy, migrate
the copy to repository version 18, and audit its pin coverage without printing
CIDs or identities:

```sh
sudo -u IDENA_USER env \
  IPFS_PATH=/offline/idena-ipfs-copy \
  IPFS_BIN=/usr/local/libexec/ipfs-kubo-0.42.0 \
  /opt/p2pool/scripts/pohw-audit-ipfs-datastore-migration.sh
```

An exit status of `2` means pinned-data export would omit local blocks. Do not
convert or replace the live repository in that case. Keep the modern runtime on
the existing Badger repository until Idena-specific retention semantics prove
that those unpinned blocks are disposable or an upstream full-block migration
path exists. Never use the archived `ipfs-ds-convert`; its maintainers warn that
it targets repository version 11 and may damage data. See the
[Kubo Badger removal plan](https://github.com/ipfs/kubo/issues/11186) and
[archived converter warning](https://github.com/ipfs-inactive/ipfs-ds-convert).

## Binary And Services

Install the checksum-verified binary beside the legacy binary. Keep the stable
symlink and the rollback binary separate.

```sh
sudo install -m 0755 -o root -g root IDENA_BINARY \
  /usr/local/libexec/idena-node-modern-COMMIT
sudo ln -sfn idena-node-modern-COMMIT /usr/local/libexec/idena-node-modern
printf '%s\n' 4947ddfd41391cca0e51dc2635aaa8a06827a890 \
  | sudo tee /usr/local/libexec/idena-node-modern.source-commit >/dev/null
sudo chown root:root /usr/local/libexec/idena-node-modern.source-commit
sudo chmod 0644 /usr/local/libexec/idena-node-modern.source-commit
```

The installer verifies this public source-commit marker against
`compatibility/stack-lock.json`. The marker is provenance, not proof of the
binary digest; retain the independently recorded checksum required by the
compatibility gate.

For the SD-card layout, deploy this repository as a root-owned checkout at
`/opt/p2pool`, then run:

```sh
sudo /opt/p2pool/scripts/pohw-install-pi-modern-runtime.sh
sudo systemctl restart idena.service
sudo systemctl start pohw-health-status.service
```

The installer updates paths for Idena, reward indexing, session recording,
snapshots, and health reporting. It does not enable a previously disabled
service or timer. These units are replaced as complete units because
`RequiresMountsFor` dependencies generated by the legacy SSD units cannot be
reliably removed by later drop-ins. Previous units are retained under
`/var/lib/pohw-p2pool/runtime-backup/`.

### Hetzner Runtime Isolation

The modern node and legacy compatibility relay must never share a Unix user,
configuration directory, or writable data directory. Before installing the
units, stop both services and stage the existing private configuration without
printing it:

```sh
sudo systemctl stop idena-bootstrap.service idena-original-relay.service
getent passwd idena-modern >/dev/null || sudo useradd --system --home-dir /srv/idena --shell /usr/sbin/nologin idena-modern
getent passwd idena-relay >/dev/null || sudo useradd --system --home-dir /srv/idena-original-relay --shell /usr/sbin/nologin idena-relay
sudo install -d -m 0750 -o root -g idena-modern /etc/idena-modern
sudo install -d -m 0750 -o root -g idena-relay /etc/idena-relay
sudo install -m 0640 -o root -g idena-modern MODERN_CONFIG.json /etc/idena-modern/config.json
sudo install -m 0640 -o root -g idena-relay RELAY_CONFIG.json /etc/idena-relay/config.json
sudo chown -R idena-modern:idena-modern /srv/idena
sudo chown -R idena-relay:idena-relay /srv/idena-original-relay
sudo chmod 0700 /srv/idena /srv/idena-original-relay
printf '%s\n' 4947ddfd41391cca0e51dc2635aaa8a06827a890 \
  | sudo tee /usr/local/libexec/idena-node-compat-v5.source-commit >/dev/null
printf '%s\n' 938be81dbdeff85f888f4337060a8ebabb12e5b5 \
  | sudo tee /usr/local/libexec/idena-node-1.1.2.source-commit >/dev/null
sudo chown root:root /usr/local/libexec/idena-node-*.source-commit
sudo chmod 0644 /usr/local/libexec/idena-node-*.source-commit
```

The two config files must bind JSON-RPC to loopback and point at their own data
directories. `/srv/idena` must be a dedicated mount point with IPFS repository
version 18. Install the checksum-verified binaries at the paths named in the
unit files, deploy this repository as a root-owned checkout at `/opt/p2pool`,
then run:

```sh
sudo /opt/p2pool/scripts/pohw-install-hetzner-idena-runtime.sh --restart
```

The installer validates ownership, modes, RPC binding, data-directory
separation, binaries, IPFS version, and systemd units before mutation. It saves
the prior unit files under `/var/lib/pohw-p2pool/hetzner-runtime-backup/` and
restores both units if an active service does not restart. It never enables an
inactive service. Enable a new deployment only after the acceptance checks:

```sh
sudo systemctl enable idena-bootstrap.service idena-original-relay.service
```

Treat the legacy relay as outbound-only. Do not publish its P2P port. Permit
only the intended modern P2P port and SSH in the host firewall; keep both RPC
ports private. Re-run the installer without `--restart` to validate and stage a
new unit revision without interrupting either node.

Keep RAID and NVMe monitoring active on the dedicated host:

```sh
sudo apt-get install -y mdadm nvme-cli smartmontools
sudo systemctl enable --now smartmontools.service
systemctl is-active mdmonitor.service smartmontools.service
cat /proc/mdstat
sudo nvme smart-log /dev/nvme0
sudo nvme smart-log /dev/nvme1
```

Require zero NVMe critical warnings and media errors, and all mirrored arrays to
show every member online. The large Bitcoin array may be RAID0 because its data
is independently reproducible; identity, configuration, and sharechain state
must remain on mirrored storage and in encrypted off-host backups.

Expose only the configured Idena TCP P2P port when the node must accept public
peers. Keep JSON-RPC on loopback and never publish port `9009`. A compatibility
relay and a modern canary on the same host must use distinct P2P ports.

The Idena unit points `HOME` and `XDG_CONFIG_HOME` at `/var/lib/idena`. This
lets Kubo load optional NoPFS denylist configuration while `ProtectHome=true`
continues to deny access to user home directories.

## Acceptance And Rollback

Acceptance requires: service active with zero restarts, RPC version equal to the
intended build, IPFS repo version 18, original baseline blocks unchanged, at
least one original-chain peer, increasing height, and no panic/fatal log entry.

If any Pi check fails, stop Idena, restore the complete unit backup and data
backup, reload systemd, and start the unchanged legacy binary. On Hetzner,
restore the two service files and any saved drop-in directories from
`/var/lib/pohw-p2pool/hetzner-runtime-backup/`, then reload systemd and restart
the previously active services. Preserve failed modern data separately for
diagnosis; never merge its database files into the rollback copy.
