# Backup and restore

## What a backup holds

`python -m sakshya backup` writes one `.tar.gz` with:

- every case: original evidence, ledger, decisions and all analysis versions with their artifacts;
- the user, session and job databases, copied through SQLite's backup interface so the copy is consistent while the service runs;
- the system ledger and the schema version;
- the signing key and checkpoints, unless `--exclude-keys` is given;
- `BACKUP.json` with the creation time and file count.

The command prints the SHA-256 of the archive. Record it with the archive.

## Making a backup

```bash
python -m sakshya backup --out /secure/backups/sakshya-$(date +%Y%m%d).tar.gz
```

On Render, open a shell on the service and run the same command with an output path on the disk, then copy the file off the host. With Docker:

```bash
docker exec sakshya python -m sakshya backup --out /data/backup.tar.gz
docker cp sakshya:/data/backup.tar.gz .
docker exec sakshya rm /data/backup.tar.gz
```

The archive contains evidence and, by default, the signing key. Encrypt it at rest and limit who can read it. If keys are excluded, back up `SAKSHYA_KEY_DIR` and `SAKSHYA_ANCHOR_DIR` separately, ideally to a different place.

## Restoring

Stop the service, then:

```bash
python -m sakshya restore /secure/backups/sakshya-20261119.tar.gz --data-dir /path/to/empty/folder
```

Restore refuses a folder that is not empty unless `--force` is given. Archive members are extracted with Python's `data` filter, which refuses absolute paths, links outside the target and device files. After extraction the command runs a full verification and prints the result.

## Verifying at any time

```bash
python -m sakshya verify
```

For every case this checks:

1. the ledger chain and every signed checkpoint;
2. every evidence file against its intake hash in the ledger;
3. every decision in `actions.json` against an `investigator_action` ledger entry;
4. every analysis version's stored bundle against its recorded digest.

It also checks the system ledger. The exit report lists each problem by case. Run it after every restore and on a schedule.

## Testing restores

A backup is only useful if it restores. At least once a month restore the latest backup into a scratch folder, run `verify`, and start a service on it with `SAKSHYA_DATA_DIR` pointing there to confirm that cases open. `tests/test_storage.py::test_backup_restore_round_trip_verifies` does the same in the test suite.
