# Forensic reliability

This document says what each part of Sakshya's output can be relied on for, and where it stops. It is written for investigators, reviewers and anyone who has to explain a Sakshya finding to someone else.

## 1. Original evidence

1. Evidence files are kept under `cases/<id>/source` and made read-only (mode 0444) when the case is created. Nothing Sakshya produces is written there.
2. Each file is hashed with SHA-256 at intake. The hash, size and parse state are written to the case ledger as an `intake` entry before the file is parsed.
3. Every later analysis hashes every file again. A file that differs from its intake hash is marked `changed_since_intake`, an `intake_changed` entry is logged, any cached analysis is discarded with an `analysis_invalidated` entry, and the next analysis runs on the file as it now is. Both states stay in the ledger.

### Hash check states

A hash can only be "verified" against a reference that someone supplied: a hash in the manifest written when the evidence was acquired, or a frame hash in a CCTV recorder's export log.

| State | Meaning |
| --- | --- |
| VERIFIED | The file matches the supplied reference |
| MISMATCH | The file differs from the supplied reference; it was changed after the reference was taken, or the reference is wrong |
| MISSING_REFERENCE_HASH | A reference source exists (for example the manifest) but gives no hash for this file |
| INVALID_REFERENCE_HASH | The reference is not a valid SHA-256 value |
| UNREADABLE | The file could not be read |
| NOT_VERIFIABLE | No reference exists for this kind of file (for example a typed complaint) |
| NOT_CHECKED | The check was not run, for example a frame listed in a recorder log but not supplied |

The intake hash itself proves only that the file has not changed since Sakshya received it. It says nothing about the file's history before that.

## 2. Custody ledger

Each case has a ledger, and the service has a system ledger. Each entry holds a sequence number, a time, a type, a payload and the hash of the previous entry; the first entry is a genesis entry naming the case. After every append the head is signed with an Ed25519 key and stored as a checkpoint.

Recorded events include case creation, intake, analysis versions (with the digest of the result and what changed), investigator decisions and their revocations, imported decisions (with the SHA-256 of the import), exports, reports (with the SHA-256 of the HTML), case access, access grants and evidence changes.

Verification reports three things:

| Field | Meaning |
| --- | --- |
| `chain_ok` | Every entry links to the one before it and none was altered |
| `anchoring` | `independent` if the key and checkpoints are on storage outside the data folder, `local` if they share it, `none` if no checkpoints are configured |
| `issues` | Checkpoints with bad signatures, entries beyond the last checkpoint, heads that differ from a checkpoint, missing genesis |

With `local` anchoring, someone who controls the whole disk could rewrite the ledger, the checkpoints and the key together. The workbench and report say "locally verified but not independently anchored" in that case.

## 3. Observations

Every record the parsers produce carries:

| Field | Meaning |
| --- | --- |
| `evidence_id`, `file`, `row` | Where the record is; for databases the row identifier, for captures the first packet number, for video the frame index |
| `sha256` | The hash of the source file at the time of analysis |
| `parser`, `parser_version` | The code that read it |
| `family` | financial, telecom, mobile, social, network, cctv, email, cloud or records |
| `dependence_group` | Records that share an origin, for example every record from one bank's core system or one handset; see section 5 |
| `t_raw`, `tz` | Time as recorded and the time zone it was recorded in |
| `t`, `sigma_t` | Time after clock correction and its uncertainty in seconds |
| `lat`, `lon`, `radius_m`, `coord_basis` | Location, its radius and what kind of location it is (section 4) |
| `raw` | The record as it appears in the file |

Rows that cannot be read are quarantined with their line number and reason, never silently dropped. Each evidence file gets a parse state: parsed, partial (read with warnings), empty, or failed.

## 4. Time and place

### Clock correction

Bank statements, ATM journals, CDRs and tower dumps are treated as reference clocks. Other files are aligned to them using events that appear in both. Safeguards:

1. An anchor event that matches reference events more than 30 seconds apart is ambiguous and is not used.
2. A time zone correction is made only when the file has no declared time zone, at least the minimum number of anchors agree, their spread is at most 120 seconds and the offset is at least 20 minutes.
3. Each estimate has a status: `reference`, `estimated`, `weak` (two anchors or spread of 300 seconds or more) or `unestimated` (too few anchors; the declared time is used with a wide uncertainty).
4. The original time, the correction and the reason are shown with every record.

### Location basis

| Basis | Meaning |
| --- | --- |
| exact | A fix with a radius of 50 m or less |
| approximate | A fix with a radius up to 500 m, or a fix with stated accuracy |
| coverage | The device was somewhere in a large area |
| cell_site | The position of a cell tower; the handset was somewhere in its coverage |
| fixed_site | The location of a fixed installation such as an ATM |
| unresolved | No location could be determined |

A device or account location shows where the device or account was used. It never shows who was holding it, and Sakshya never uses it to state where a person was. Co-presence and impossibility links are worded in terms of the device.

## 5. Links and their weights

A link weight W is the base ten logarithm of a likelihood ratio: how much more probable the observed records are if the claim is true than if they arose by coincidence. Terms are grouped by dependence group and each group is capped at plus or minus 4, so records that share an origin (an SMS bank alert and the bank's own statement, say) count once. A link is accepted at W of 2 only when at least two independent groups contribute. Coincidence rates are estimated from the case's own records with add-one smoothing so that no rate is zero.

The weights are statistical models, not facts. Section 2 of [MODEL_VALIDATION.md](MODEL_VALIDATION.md) shows how often links in each weight band were true on synthetic data.

## 6. Explanations

A hypothesis score adds the indicators bound to its roles and the links between roles, each counted once: an indicator derived from a link is replaced by the link, and a link resting on records already counted by an indicator is excluded. Missing phases are penalised only to the extent that the sources in the case would have shown them. The five outcomes are:

| Outcome | When |
| --- | --- |
| OFFENCE_SUPPORTED | One offence pattern scores at least 2 and leads every alternative, including no offence, by at least 1 |
| NO_OFFENCE_INDICATED | No suspicious indicators, and the sources present could have shown an offence |
| UNKNOWN_PATTERN | Suspicious indicators exist but no pattern fits clearly |
| INSUFFICIENT_EVIDENCE | No readable records beyond the complaint, or too few sources to see the patterns |
| ANALYSIS_FAILED | No evidence file could be parsed |

"Offence pattern supported" means the records fit a known pattern better than the alternatives. It is not a finding that any person committed an offence; that is for the investigator and the court.

## 7. What is modelled and what is a heuristic

| Component | Status |
| --- | --- |
| Time, place and attribute terms in links | Statistical model with stated assumptions |
| Calibration scales | Fitted on synthetic training data |
| Indicator weights and template priors | Elicited from case experience and fixed in configuration; not fitted |
| Phase observability values | Elicited; not fitted |
| Phase durations | Fitted on synthetic training cases where at least five exist, otherwise elicited and labelled as such |
| Freeze ranking | A model estimate when the phase model gives a probability for the account, otherwise a heuristic by amount and hop; each row says which |
| Evidence request ranking | Expected information gain under elicited chances of each request returning a result |
| Fragility | Measured by re-running the analysis with links removed |
| Money attribution | Pro-rata and first-in first-out are tracing conventions; neither proves which rupees moved |

## 8. Format-specific limits

| Source | Limit |
| --- | --- |
| Packet captures | Flows, DNS and the TLS server name are read. Payloads are never decrypted. The server name is what the client asked for and may not match the server that answered. |
| Phone databases | Opened read-only on a copy. Text recovered from unallocated space is labelled "Recovered fragment (unverified)", has no time, and its sender and completeness are unknown. |
| Email | Authentication results (DKIM, SPF, DMARC) are reported as stamped by the receiving server; they are not re-verified. |
| Video | Key frames and scene changes are listed with the SHA-256 of their decoded pixels. That hash identifies the picture, not the file; the file hash is in the intake entry. Wall-clock times need a recording start in the manifest or the container's creation time, and are marked with their basis. |
| Social media exports | Parsed as the platform exported them. Display names may be edited by users and are not identity. |

## 9. Reproducibility

Each analysis stores its inputs: evidence digests, parser versions, a configuration digest, the engine version, the decisions and the cut-off time. The SHA-256 of these is the cache key. Each result is kept as a numbered analysis version with its bundle, its tables (Parquet, or JSON Lines if Parquet is unavailable) with per-table hashes, the reason it was run, who ran it and what changed from the previous version. The same inputs give the same result digest on any machine, which the test suite checks with two different Python hash seeds.
