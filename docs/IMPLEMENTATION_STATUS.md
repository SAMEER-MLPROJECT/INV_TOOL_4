# Implementation status

State of the build delivered on 2026-11-24, engine version 1.0.0, against the engineering directive for SUTRAM 2026 PS03.

## Summary

| Priority | Scope | Status |
| --- | --- | --- |
| P0 | 22 security findings, custody integrity, storage, deployment safety | Done, each finding with a regression test |
| P1 | Link model, entity resolution, hypotheses, money, prediction, decision support, evaluation | Done, except identity resolution recall (partial) |
| P2 | Packet captures, mobile databases and deleted artefacts, social exports, video, email and cloud, parser validation | Done, with the format limits listed below |
| P3 | Dashboard, typed and job-based API, reproducibility, supply chain, documentation | Done, except pagination of links and timeline (partial) |

The full requirement-by-requirement table is in [ARCHITECTURE_TRACEABILITY.md](ARCHITECTURE_TRACEABILITY.md).

## Test results

Run on the build machine with Python 3.13 on Linux:

```
python -m pytest -q
174 passed in 144 s
```

| File | Tests | What it covers |
| --- | --- | --- |
| `tests/test_security.py` | 30 | One test for each of the 22 findings, plus traversal, executables, ledger edits, role isolation, non-root container, read-only evidence |
| `tests/test_adapters.py` | 29 | Field-level precision and recall for 17 formats, PCAP details, recovered fragments, read-only database handling, write-ahead logs, email authentication and attachments, video frames and the frame endpoint, cloud accuracy, text repair, daylight saving, observability mapping |
| `tests/test_pipeline.py` | 29 | Five outcomes against answer keys, clock recovery, money and roles, traceability, tamper detection, decoys, determinism across hash seeds, provenance columns, look-ahead protection, acquisition cut-off, versioned artifacts |
| `tests/test_custody.py` | 21 | Genesis, anchoring states, edit location, forged signatures, key permissions, seven hash states, manifest validation |
| `tests/test_api.py` | 17 | Health, identity, listing, pagination, reach, strict forecast, versioning with revoke and idempotency, notes, report and export audit, uploads, user administration, lockout, audit access by role |
| `tests/test_identifiers.py` | 16 | Canonical identifiers and transliteration |
| `tests/test_models.py` | 15 | Dependence groups, smoothing, clustering conflicts, reconciliation, reversals and fees, freeze reasoning, semi-Markov behaviour, information gain, fragility, calibration |
| `tests/test_storage.py` | 7 | Layout, backup and restore, verification, independent anchoring, migration, staging cleanup, case isolation |
| `tests/test_link_terms.py` | 6 | Closed-form link terms, caps, calibration scaling, verbal scale |
| `tests/test_money.py` | 4 | Layered tracing, pro-rata against first-in first-out, replay in time, long-standing payees |

No test is skipped or marked as an expected failure.

Other checks on the same build:

| Check | Result |
| --- | --- |
| `ruff check sakshya tests` | No findings |
| `pip-audit -r requirements.lock` | No known vulnerabilities (2026-11-24) |
| `python -m sakshya.evaluation.parsers` | Minimum precision 1.000, minimum recall 1.000, 81 of 81 value checks |
| Workbench pages loaded in Chromium with the production content security policy | No policy violations |

## Measured performance

From the evaluation run of 2026-11-24 ([MODEL_VALIDATION.md](MODEL_VALIDATION.md)):

| Measure | Result |
| --- | --- |
| Analysis time per held-out case, median / worst | 0.43 s / 2.20 s |
| Demonstration case 0147 (3,063 records), including fragility re-runs | about 2.1 s |
| 100 times scale: 66,265 records, 96,310 identifiers | 135.5 s with memory tracing on, peak 456 MB traced |
| Full evaluation run (48 cases, 36 strict forecasts, five scales) | 4 min 51 s |
| Full test suite | 144 s |

## Partial and not done

| Item | State | Detail |
| --- | --- | --- |
| Identity resolution recall | Partial | 0.772 on held-out cases, precision 1.0, no decoy merges. The contradiction checks favour precision. Unmerged pairs remain visible as candidate links. |
| API pagination | Partial | Observations are paginated. Links, timeline and graph are delivered inside the case bundle, which is fine for the tested sizes but not for very large cases. |
| Deleted mobile artefacts | Partial | SQLite free pages and unallocated page space are carved for text. Superseded write-ahead log frames, file-system level recovery and other database engines are not handled. |
| Mobile extraction formats | Partial | Android SMS and call logs, iOS Messages, Chromium history, property lists, vCard and device reports. Vendor report formats (for example UFED or XRY reports), iOS backup manifests and WhatsApp `msgstore.db` are not parsed directly; the configurable JSON, CSV and HTML parsers can read exports converted to those forms. |
| Packet captures | Partial | Flows, DNS and TLS server names. No TCP stream reassembly, no QUIC server names, no payload decryption (by design). |
| Video | Partial | Metadata, key frames, scene changes, frame hashes and frame images. Times printed on the picture are not read; wall-clock time comes from the manifest or the container. |
| Independent anchoring on a single-disk host | Not done | On a host with one disk the signing key and checkpoints share storage with the ledgers and are reported as "local". Separate storage must be provided by the deployment. |
| Multi-factor sign-in | Not done | Use an identity-aware proxy if required. |
| Real-case validation | Not done | All measured accuracy is on synthetic cases. A blind evaluation on labelled real cases is needed before the figures can be quoted as field accuracy. |
| Original findings report | Not available | The 22 findings were addressed as listed in the directive; the separate findings report was not supplied, so any detail in it beyond its titles was not checked. |

## Known limitations

1. The crime templates cover UPI investment fraud, sextortion and SIM swap takeover. Other offences are reported as an unknown pattern with the suspicious indicators found.
2. Indicator weights, template priors, phase observability values and the outcome probabilities used for evidence requests are elicited, not fitted.
3. Calibration scales and phase durations were fitted on synthetic training cases. Two calibration scales sit at their upper bound and the fitted duration spreads sit at their floor, both reflecting the generator rather than real offences.
4. Rate limits are per process.
5. The verbal strength scale uses the example bands of the ENFSI guideline for evaluative reporting and should be confirmed before formal use.

## Exact commands used for this build

```bash
pip install --require-hashes -r requirements.lock
pip install -r requirements-dev.txt
ruff check sakshya tests
ruff format --check sakshya tests
python -m pytest -q
python -m sakshya.evaluation.run --fit --per-kind 6 --training 18 --scales 1,5,10,20,100
python -m sakshya.evaluation.parsers --dir /tmp/sakshya-fixtures
pip-audit -r requirements.lock
cyclonedx-py requirements --of JSON --output-reproducible -o sbom.cdx.json requirements.lock
python -m sakshya demo
```
