# Sakshya

Evidence correlation and crime reconstruction for cyber fraud investigations. Built by Team EigenThinkers for SUTRAM 2026, problem statement 03.
## [Source_Code_zip_file_submission](https://drive.google.com/drive/folders/1LmnvXsabPAO5LrWpqa48xd6sJM0K3PN6?usp=sharing)
## [Demo_Video](https://drive.google.com/file/d/1-eg0BlAgoMk0bCZib45plK3NpiwPoIlC/view?usp=sharing)

Sakshya takes the records an investigator already holds in a cyber fraud case (bank statements and ATM journals, call detail records and tower dumps, subscriber and account KYC, phone exports and databases, chat and social media exports, email, cloud sign-in and location history, packet captures and router logs, CCTV logs and video, seizure memos and the complaint) and answers three questions:

1. **Explain.** What happened, who played which role, and how strongly the evidence supports that account over the alternatives, including "no offence".
2. **Reach.** Where the complainant's money went, where it is still held, and which accounts to freeze first.
3. **Predict.** Which phase the offence has reached, how soon the next one usually follows, and which evidence request is worth the most now.

Every finding points to a row, packet or frame in a hashed evidence file. Every analysis, decision, import, export, report and case access is written to a hash-chained custody ledger with signed checkpoints.

## Scope

Sakshya works only on evidence that was lawfully acquired and handed to it. It does not intercept communications, monitor radio, bypass device locks, recognise faces, detect deepfakes or identify suspects automatically. A device or account location shows where the device or account was used, never who held it.

## Quick start on a workstation

Python 3.12 or 3.13.

```bash
python -m venv .venv
source .venv/bin/activate
pip install --require-hashes -r requirements.lock
export SAKSHYA_DATA_DIR="$HOME/sakshya-data"
export SAKSHYA_COOKIE_SECURE=false
python -m sakshya create-admin --username analyst
python -m sakshya serve
```

Open http://127.0.0.1:8000 and sign in. Five demonstration cases are loaded on first start:

| Case | Outcome | What it shows |
| --- | --- | --- |
| CASE-2611-0147 | UPI investment fraud supported | Time zone and drift correction, ATM co-presence, a person cleared by travel time, a tampered CCTV frame, freeze ranking |
| CASE-2611-0152 | Sextortion supported | Threat language, payment, layering and cash-out within hours |
| CASE-2611-0158 | SIM swap takeover supported | New SIM on a new handset, OTP interception, unauthorised debits |
| CASE-2611-0163 | No offence indicated | An ordinary delivery dispute that must not be labelled as fraud |
| CASE-2611-0171 | Unknown pattern | Data theft with a ransom demand that fits no template |

All names, numbers, banks, domains and addresses in the demonstration data are invented.

## Hosted deployment

`render.yaml` deploys the Docker image on Render with a persistent disk and a generated bootstrap token. A `Dockerfile` is included for any container host. Read [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md) before deploying, and [SECURITY.md](SECURITY.md) before loading real case data.

## Adding a case

Choose **Add case** and upload a `.zip` holding a `case.yaml` and the evidence files it lists:

```yaml
id: CASE-2611-0201
title: Short description of the case
seed:
  kind: complaint
  identifiers:
    - {type: phone, value: "+919800000000"}
    - {type: account, value: "IVBK0123456:50100012345678"}
evidence:
  - {file: evidence/complaint.txt, source: complaint}
  - {file: evidence/statement.csv, source: bank_statement, account: "IVBK0123456:50100012345678", sha256: "<hash taken at acquisition>"}
  - {file: evidence/cdr.csv, source: cdr, colmap: {columns: {time: "Call Start"}, time_format: "%d/%m/%Y %H:%M"}}
  - {file: evidence/capture.pcapng, source: pcap}
  - {file: evidence/mmssms.db, source: android_sms_db, owner: "+919800000000"}
  - {file: evidence/atm_cam.mp4, source: video, camera: ATM-1, recording_start: "2026-03-14 15:30:00"}
```

36 source types are supported. [docs/data-format.md](docs/data-format.md) lists them with their fields and the column map options.

## Command line

```bash
python -m sakshya serve [--host 127.0.0.1] [--port 8000]
python -m sakshya create-admin --username NAME
python -m sakshya create-user --username NAME --role investigator
python -m sakshya grant --username NAME --case CASE-ID
python -m sakshya analyse path/to/case [--state out/] [--as-of UNIX_TIME]
python -m sakshya backup --out backup.tar.gz [--exclude-keys]
python -m sakshya restore backup.tar.gz --data-dir path/to/empty/folder
python -m sakshya verify
python -m sakshya generate upi_investment_fraud --seed 7 --out cases
python -m sakshya demo
python -m sakshya.evaluation.run --fit --per-kind 6 --training 18 --scales 1,5,10,20,100
python -m sakshya.evaluation.parsers
```

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest -q
ruff check sakshya tests
pip-audit -r requirements.lock
```

The suite has a regression test for each of the 22 security findings, field-level parser validation for 17 formats, model tests (dependence groups, smoothing, clustering conflicts, reconciliation, reversals, freeze reasoning, phase models, information gain, fragility, calibration), a look-ahead test for forecasts, storage tests (backup, restore, migration, isolation) and API tests.

## Evaluation

On 30 held-out generated cases (six of each outcome). All cases are synthetic; see [docs/MODEL_VALIDATION.md](docs/MODEL_VALIDATION.md) for what this does and does not show.

| Measure | Result |
| --- | --- |
| Records parsed, every generated source type | 100% |
| Field-level parser precision / recall, 17 labelled fixture formats | 1.000 / 1.000 |
| Same-event links, precision / recall | 0.999 / 0.990 |
| Presence links, precision | 1.000 |
| Identity resolution, precision / recall | 1.000 / 0.772 |
| Decoys with matching names wrongly merged | 0 of 20 |
| Clock offset error, worst case | 9.9 s |
| Findings with a resolvable evidence pointer | 2,233 of 2,233 |
| Tampered CCTV frames caught | 4 of 4, no false alarms |
| Money trail, precision / recall | 1.000 / 1.000 |
| Offence type, including unknown and no offence | 30 of 30 |
| Cash-out within 60 minutes, Brier score: phase model / median baseline / base rate | 0.133 / 0.167 / 0.229 |
| 100 times scale (66,265 records, 96,310 identifiers) | 135.5 s with memory tracing, 456 MB |

## Documentation

| Document | Content |
| --- | --- |
| [docs/ARCHITECTURE_TRACEABILITY.md](docs/ARCHITECTURE_TRACEABILITY.md) | Pipeline, modules and requirement-by-requirement status |
| [docs/MODEL.md](docs/MODEL.md) | The arithmetic behind every score |
| [docs/FORENSIC_RELIABILITY.md](docs/FORENSIC_RELIABILITY.md) | What each output can be relied on for |
| [docs/MODEL_VALIDATION.md](docs/MODEL_VALIDATION.md) | Evaluation method and results |
| [docs/IMPLEMENTATION_STATUS.md](docs/IMPLEMENTATION_STATUS.md) | What is done, partial and not done, with test results |
| [docs/data-format.md](docs/data-format.md) | Case manifest, source types and column maps |
| [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md) | Workstation and hosted deployment |
| [docs/ENVIRONMENT.md](docs/ENVIRONMENT.md) | Every setting |
| [docs/BACKUP_RESTORE.md](docs/BACKUP_RESTORE.md) | Backup, restore and verification |
| [SECURITY.md](SECURITY.md), [docs/SECURITY_REMEDIATION.md](docs/SECURITY_REMEDIATION.md), [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Security controls, the 22 findings, threats and residual risks |
| [docs/INCIDENT_RESPONSE.md](docs/INCIDENT_RESPONSE.md) | What to do when something goes wrong |
| [docs/DATA_HANDLING.md](docs/DATA_HANDLING.md) | Data handling and retention |

## Third-party components

Python dependencies are pinned with hashes in `requirements.lock`; `sbom.cdx.json` is a CycloneDX bill of materials for them. The workbench bundles Cytoscape.js, cytoscape-fcose with layout-base and cose-base, vis-timeline and Leaflet, with their licences next to each library under `sakshya/web/vendor/`. No base map is loaded unless one is configured.
