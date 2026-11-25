# Architecture and traceability

## Pipeline

```
case.yaml + evidence files (read only)
  -> intake: validate manifest, hash, ledger, hash check states
  -> adapters: one table of observations with provenance (36 source types)
  -> identifiers: canonical entities
  -> as-of snapshot: drop evidence acquired or records time-stamped after the cut-off
  -> clock correction: offsets, time zones, drift, with ambiguity safeguards
  -> link tests: same event, co-presence, impossibility, same actor, sequence
       likelihood ratio terms, capped per dependence group, blocking
  -> people: constrained clustering with contradiction checks
  -> indicators
  -> explain: templates, beam search, relationships, observability, five outcomes
  -> fragility: re-run with supporting links removed
  -> reach: reconciliation, money trace, freeze ranking
  -> predict: semi-Markov or hidden Markov phase model
  -> decide: evidence requests by expected information gain
  -> bundle, versioned artifacts, report
```

The web service wraps this pipeline with accounts, per-case access, a job queue, custody ledgers with signed checkpoints and analysis versioning.

## Modules

| Module | Responsibility |
| --- | --- |
| `sakshya/custody` | Manifest validation, intake, hash check states, hash-chained ledger, Ed25519 checkpoints |
| `sakshya/adapters` | One parser per source type; `extended.py` holds packet capture, database, property list, vCard, Telegram, Instagram, CSV and HTML social exports, mbox, JSON records and video |
| `sakshya/normalise` | Observation table, place resolution, clock correction, facts and roles |
| `sakshya/links` | Likelihood ratio terms, link engine with blocking statistics, sequence model |
| `sakshya/people` | Clustering with hub, name and travel contradiction checks |
| `sakshya/indicators` | Behavioural indicators |
| `sakshya/explain` | Templates, hypothesis scoring, observability, decision |
| `sakshya/money`, `sakshya/reach` | Statement reconciliation, transfers, tracing, freeze list |
| `sakshya/predict` | Phase models and duration parameters |
| `sakshya/decide` | Evidence request ranking and fragility candidates |
| `sakshya/storage` | Data folder layout, migration, artifacts, backup, restore, verify |
| `sakshya/api` | Web service: authentication, authorisation, jobs, uploads, security headers, workspace |
| `sakshya/evaluation` | Generated-case evaluation, calibration, forecasting, parser fixtures and validation |
| `sakshya/web` | Workbench (plain JavaScript modules, vendored libraries, no build step) |

## Traceability to the directive

Status: **Done** means implemented and covered by a test. **Partial** means implemented with a stated gap. **Not done** means not implemented.

| Requirement | Status | Where | Evidence |
| --- | --- | --- | --- |
| 22 security findings | Done | `sakshya/api`, `sakshya/custody`, `sakshya/adapters/base.py` | `tests/test_security.py`, [SECURITY_REMEDIATION.md](SECURITY_REMEDIATION.md) |
| Excluded capabilities (deepfake detection, live SDR, SIGINT, RF, interception, unlocking, face recognition, automated identification) | Done: none present | n/a | Code review; [SECURITY.md](../SECURITY.md) scope section |
| Offline PCAP and PCAPNG with flows, DNS, TLS SNI and packet references | Done | `adapters/extended.py::parse_pcap` | `test_pcap_flows_dns_and_sni_with_packet_references` |
| Android and iOS exports, SQLite, plist | Done for SMS, calls, iOS Messages, Chromium history, property lists, vCard, device reports | `parse_sqlite`, `parse_plist`, `parse_vcard`, `parse_device_info` | Parser fixtures |
| Recoverable deleted artefacts | Partial: text in free pages and unallocated space of SQLite pages is recovered and labelled unverified; a write-ahead log listed as its own evidence item is applied to a working copy, but its superseded frames are not carved | `carve_free_pages` | `test_recovered_database_fragments_are_labelled_unverified` |
| WhatsApp, Telegram, Instagram, configurable JSON, CSV and HTML | Done | `parse_chat`, `parse_telegram`, `parse_instagram`, `parse_json_records`, `parse_social_csv`, `parse_html_table` | Parser fixtures |
| Reversals, failed transactions, refunds, fees, duplicates | Done | `adapters/bank.py`, `money/flows.py` | `test_reversals_failures_and_fees_are_handled`, bank fixture |
| UniAethel retained | Done | `adapters/network.py` | Demo cases 0147 and 0171 |
| CCTV metadata, frames, frame SHA-256, key frames, annotations, scene changes | Done | `parse_video`, frame endpoint, `annotate` action | `test_video_frames_*`, `test_annotations_are_kept_with_the_record` |
| Email CC, Message-ID, reply chain, attachments, DKIM, SPF, DMARC | Done (authentication as stamped, not re-verified) | `adapters/messages.py`, `parse_mbox` | `test_email_headers_attachments_and_authentication` |
| Cloud sign-ins and locations with accuracy | Done | `parse_json_records` with `cloud_activity` map | `test_cloud_locations_keep_their_accuracy` |
| Field-level precision and recall from labelled fixtures | Done | `evaluation/fixtures.py`, `evaluation/parsers.py` | `test_field_level_precision_and_recall` (17 formats) |
| Observation schema with family, dependence group, original time zone, uncertainty, parser and version, SHA-256 | Done | `normalise/ingest.py` | `test_observations_carry_full_provenance` |
| Versioned intermediate artifacts in Parquet or JSON Lines | Done | `storage/artifacts.py` | `test_versioned_artifacts_are_written` |
| Multiline CSV, clock safeguards, spatial markers | Done | `adapters/base.py`, `normalise/clock.py`, `normalise/ingest.py` | `test_f22_*`, clock tests in `test_pipeline.py` |
| Likelihood ratio framework with dependence groups | Done | `links/terms.py` | `test_sources_sharing_an_origin_count_once` |
| Candidate blocking with statistics | Done | `links/engine.py` | Blocking figures in the scaling results |
| Coincidence models with smoothing | Done | `links/terms.py::smoothed` | `test_smoothed_rates_are_never_zero_or_one` |
| Per-type calibration with Brier score, reliability and intervals | Done | `evaluation/calibration.py` | `test_calibration_reports_brier_and_intervals`, [MODEL_VALIDATION.md](MODEL_VALIDATION.md) |
| Performance at 1, 5, 10, 20 and 100 times | Done | `evaluation/run.py::scaling` | Scaling table in MODEL_VALIDATION |
| Cluster contradiction checks, zero decoy merges | Done | `people/cluster.py` | `test_merges_*`, `test_decoys_with_common_names_are_never_merged` |
| Better identity resolution recall | Partial: recall 0.772 on held-out cases with precision 1.0 | `people/cluster.py` | MODEL_VALIDATION |
| Link weights in hypothesis scores without double counting | Done | `explain/engine.py` | Superseded and excluded items in every hypothesis |
| Detectability-aware missing evidence | Done | `explain/engine.py::_observability`, `detectability` | Outcome tests |
| Five outcomes | Done | `explain/engine.py::decide` | `test_outcome_and_offence_type_match_the_answer_key`, `test_f21_*` |
| Template schema validation | Done | `core/config.py::validate_template` | Readiness check, `test_every_source_type_has_a_parser_and_a_column_map` |
| Full hypothesis output | Done | Bundle `hypotheses` | `test_bundle_is_complete` |
| Reconciliation, conservation, FIFO and pro-rata | Done | `money/flows.py` | `test_reconciliation_*`, `tests/test_money.py` |
| No fixed 20% freeze default, transparent reasoning | Done | `reach/freeze.py` | `test_freeze_list_has_no_arbitrary_default_and_explains_itself` |
| Strict as-of with a leakage test | Done | `pipeline.py::_snapshot` | `test_adding_future_evidence_does_not_change_a_past_forecast`, `test_evidence_acquired_after_the_cutoff_is_excluded` |
| Semi-Markov against hidden Markov against baselines, with proper metrics | Done | `predict/hmm.py`, `evaluation/forecast.py` | Forecast table in MODEL_VALIDATION |
| Expected information gain | Done | `decide/leads.py::_eig` | `test_expected_information_gain_behaves` |
| Fragility by recomputation | Done | `pipeline.py::recompute_fragility` | `test_fragility_is_recomputed_not_estimated` |
| Hash states, freshness, cache keys | Done | `custody/intake.py`, `api/workspace.py` | `test_hash_states`, `test_f09_*` |
| Signed checkpoints outside the case folder | Done; independent of the data folder only when configured | `custody/anchor.py` | `test_checkpoints_on_separate_storage_are_reported_as_independent` |
| Every decision audited | Done | `api/workspace.py::act` | `test_f03_*`, `test_f07_*` |
| Typed, paginated, job-based API | Partial: request models are strict and analysis, upload and decisions are jobs; observations are paginated, but links and timeline arrive inside the case bundle | `api/app.py` | `tests/test_api.py` |
| Dashboard improvements | Done: outcome banner with coverage and verification, provenance and notes in the record drawer, frame viewer, location basis on the map, strict forecast, administration, evaluation | `sakshya/web` | Screenshots checked during release |
| Versioning, lineage, case isolation | Done | `api/workspace.py`, `storage` | `test_decision_versioning_revoke_and_idempotency`, `test_cases_are_isolated_from_each_other` |
| Backup and restore | Done | `storage/maintenance.py` | `tests/test_storage.py` |
| Privacy-aware logs | Done | `api/app.py` access log | Code review |
| Lockfile, SBOM, vulnerability scan | Done | `requirements.lock`, `sbom.cdx.json` | `pip-audit` reported no known vulnerabilities on 2026-11-24 |
| Local and hosted modes | Done | `__main__.py`, `Dockerfile`, `render.yaml` | [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) |
