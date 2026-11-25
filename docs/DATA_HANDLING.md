# Data handling and retention

## What Sakshya stores

| Data | Location | Contains personal data |
| --- | --- | --- |
| Original evidence | `cases/<id>/source` | Yes |
| Case ledger | `cases/<id>/state/ledger.jsonl` | Yes: user names, decisions, file names, hashes |
| Decisions | `cases/<id>/state/actions.json` | Yes: user names and reasons |
| Analysis versions | `cases/<id>/state/runs/<run>` | Yes: everything derived from the evidence |
| Users and sessions | `sakshya.db` | Yes: user names, display names, password hashes |
| Jobs | `jobs.db` | Case identifiers and error summaries |
| System ledger | `system_ledger.jsonl` | User names and sign-in events with client addresses |
| Access log | Standard output of the process | No evidence content; paths with case identifiers removed and a salted hash of the client address |

## Principles

1. **Only lawfully acquired evidence.** Sakshya analyses what is supplied to it. It has no capability to collect data from devices, networks or services.
2. **Originals are never changed.** Evidence is made read-only at intake. Everything the engine produces is written under `state`.
3. **Least access.** Users see only the cases they are granted. Reviewers cannot record decisions; auditors read the custody trail.
4. **Nothing leaves the server by default.** No base map, no external fonts or scripts, no telemetry.
5. **Every access is recorded.** Opening a case, exporting, printing a report and reading the audit trail are written to the case ledger.

## Locations and identity

A phone, SIM or account being in a place shows where that device or account was used. It does not show who held it. The workbench and report say this wherever a location appears, and the location basis (exact, approximate, coverage area, cell site, fixed site) is shown with every point.

## Recovered fragments

Text recovered from unallocated space in a phone database is shown as "Recovered fragment (unverified)". Its time, sender and completeness are unknown, it is never given a time, and it cannot support a link or a phase on its own.

## Retention

Sakshya does not delete cases automatically, because deletion of evidence needs a decision by the case owner under your organisation's rules. When a case is closed and its retention period has passed:

1. Export the final report and the audit trail and file them with the case records.
2. Take a backup of the case for the archive if your rules require one.
3. Remove access grants.
4. Delete the folder `cases/<id>` on the server and record the deletion, with who approved it, in the system records your organisation keeps.

Backups contain every case they were taken from. Apply the same retention period to backups, and destroy old backup archives securely.

Sessions expire after `SAKSHYA_SESSION_HOURS` and are removed at sign-out. Process logs should be kept no longer than your operational need, typically 30 to 90 days.

## Synthetic data

The demonstration cases and the evaluation corpus are generated. All names, numbers, banks, domains and addresses in them are invented; domains use reserved suffixes and IP addresses come from documentation ranges.
