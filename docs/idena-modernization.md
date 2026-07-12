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

Existing Badger v1 blockstores remain readable but are deprecated by Kubo.
Plan a separate tested export/import to flatfs before Badger support is removed;
do not combine that datastore conversion with this node upgrade.

## Binary And Services

Install the checksum-verified binary beside the legacy binary. Keep the stable
symlink and the rollback binary separate.

```sh
sudo install -m 0755 -o root -g root IDENA_BINARY \
  /usr/local/libexec/idena-node-modern-COMMIT
sudo ln -sfn idena-node-modern-COMMIT /usr/local/libexec/idena-node-modern
```

For the SD-card layout, deploy this repository as a root-owned checkout at
`/opt/p2pool`, then run:

```sh
sudo /opt/p2pool/scripts/pohw-install-pi-modern-runtime.sh
sudo systemctl restart idena.service
sudo systemctl start pohw-health-status.service
```

The installer updates paths for Idena, reward indexing, session recording,
snapshots, and health reporting. It does not enable a previously disabled
indexer or timer.

## Acceptance And Rollback

Acceptance requires: service active with zero restarts, RPC version equal to the
intended build, IPFS repo version 18, original baseline blocks unchanged, at
least one original-chain peer, increasing height, and no panic/fatal log entry.

If any check fails, stop Idena, remove the modern systemd drop-in, restore the
complete backup into `/var/lib/idena`, reload systemd, and start the unchanged
legacy binary. Preserve the failed modern data separately for diagnosis; never
merge its database files into the rollback copy.
