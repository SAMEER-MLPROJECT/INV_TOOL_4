# Incident response notes

These notes cover incidents specific to Sakshya. Follow your organisation's incident process for notification and legal steps.

## Suspected account compromise

1. Under Administration, choose "Disable" and "Sign out everywhere" for the account. Both take effect on the next request.
2. Read the `login`, `login_failed` and `password_changed` entries in `system_ledger.jsonl` in the data folder, and the case ledgers the account could reach (Evidence and custody view, or `/api/cases/<id>/audit` for auditors and administrators).
3. Check each case the account could reach for `investigator_action`, `decision_import`, `export` and `report_export` entries by that user. Revoke any decision that was not made by the real person; revoking keeps the original entry and adds a new one.
4. Reset the password before re-enabling the account.

## Evidence changed on disk

The workbench marks the file `changed_since_intake`, the ledger has an `analysis_invalidated` entry, and `python -m sakshya verify` lists the file.

1. Do not delete or overwrite anything.
2. Take a backup of the current state.
3. Compare the file with the copy held by whoever supplied it, using the intake hash recorded in the ledger.
4. Restore the original file from a verified backup if needed. The next analysis will show the file as unchanged again, and both events remain in the ledger.

## Ledger verification fails

1. Stop the service and take a backup of the current state, including keys and checkpoints.
2. Run `python -m sakshya verify` and note the first failing entry and the reason.
3. Compare with the latest verified backup. Entries up to the last good checkpoint can be trusted; everything after must be reviewed by hand.
4. If anchoring was "local", treat the whole ledger as untrusted until checkpoints copied off the host agree with it.

## Signing key exposed

1. Stop the service.
2. Move the old key out of `SAKSHYA_KEY_DIR`, keeping a copy for verifying old checkpoints.
3. Start the service; a new key is generated and its identifier appears in new checkpoints.
4. Record the change and the old key identifier in your case records. Checkpoints signed before the exposure should be compared with copies held elsewhere.

## Service unavailable

1. Check `/api/health/ready`; the failing check is named in the response.
2. Storage failures: check free space and permissions on `SAKSHYA_DATA_DIR`.
3. Database failures: the SQLite files are `sakshya.db` and `jobs.db` in the data folder. Restore them from backup if they are corrupt.
4. After a crash, interrupted uploads are removed on the next start and jobs that were running are marked failed with "Interrupted by a service restart". Re-run them from the workbench.

## Suspected malicious upload

Uploads are staged and checked before they become cases. If a case looks wrong after upload, remove its access grants, back it up, and examine the archive offline. The ledger records who uploaded it and when.
