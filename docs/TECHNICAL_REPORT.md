# Sakshya: Technical Report

**Unified Digital Evidence Correlation and Crime Reconstruction Engine**

SUTRAM 2026, Problem Statement 03 (Digital Evidence Correlation and Crime Reconstruction). Team EigenThinkers.

Source code: https://github.com/SAMEER-MLPROJECT/INV_TOOL_4

## 1. Summary

A cyber fraud investigation draws on bank statements, ATM journals, call records, tower dumps, KYC, phone exports, chats, email, cloud sign-ins, packet captures, CCTV and the complaint. Each comes from a different institution, in a different format and on a different clock. Sakshya reads all of them into one table of observations that keeps every uncertainty, tests the relationships between them as likelihood ratios, and builds one shared investigation graph. Three capabilities read that graph:

* **Explain:** what happened, who played which role, and how strongly the evidence supports that account over competing ones, including "no offence".
* **Reach:** where the complainant's money went, what is still held, and what to freeze first.
* **Predict:** which phase the offence has reached, how soon the next one usually follows, and which evidence request is worth the most now.

Every finding opens the row, packet or frame it came from, with the SHA-256 of the file. Every analysis, decision, import, export, report and case access is written to a hash-chained ledger with Ed25519-signed checkpoints. A correlation is evidence for the investigator to weigh; Sakshya never states identity or guilt.

## 2. Novelty

The methods are established (likelihood ratios, record linkage, semi-Markov models, information gain). What is new is how they are combined for forensic use:

1. **Uncertainty-aware heterogeneous correlation.** Every observation carries time uncertainty, a location radius and basis, and a dependence group. Link weights are log likelihood ratios whose terms are capped per dependence group, so two records from one origin (a bank SMS alert and the bank's own statement) count once, and a link is accepted only when two independent origins agree.
2. **Contradiction-aware hypothesis evaluation.** Offence templates compete with "no offence". Each hypothesis carries supporting and contradicting evidence, missing phases weighted by whether the evidence present could have shown them, and a fragility check that re-runs the analysis without each key link.
3. **One shared, provenance-preserving graph.** Explain, Reach and Predict reuse the same tested links and the same versioned analysis, so the timeline, the money trail and the forecast cannot disagree about the facts, and each is reproducible from its recorded inputs.

## 3. Engineering progression

The repository was built in stages, each kept as a reviewed step:

| Stage | Work |
| --- | --- |
| Baseline 1.0 | Explain, Reach and Predict over 19 source types, five demonstration cases, ledger, graph, timeline, map and money views |
| P0 security and custody | Accounts and roles, CSRF, strict content security policy, streaming uploads with staging, job queue, rate limits, readiness checks, seven hash check states, signed checkpoints, cache keys tied to evidence hashes, five decision outcomes, multiline CSV parsing. All 22 audited findings fixed, each with a regression test |
| P1 models | Dependence groups and smoothing in link weights, cluster contradiction checks, link weights in hypothesis scores without double counting, detectability-aware gaps, statement reconciliation, reversals and refunds, freeze list without a fixed default, semi-Markov forecasting on strict as-of snapshots, three-outcome information gain, fragility by recomputation, per-type calibration |
| P2 evidence | Offline PCAP and PCAPNG, Android and iOS databases with unverified recovery of deleted text, write-ahead logs, property lists, vCard, Telegram, Instagram, CSV and HTML exports, mbox with attachments and authentication results, cloud sign-ins with accuracy, video key frames and scene changes with frame hashes. 36 source types in all, validated field by field on 17 labelled fixtures |
| P3 delivery | Versioned Parquet artifacts per analysis, backup, restore and verification, privacy-aware logs, lockfile with hashes, SBOM, vulnerability scan, Docker image, Render blueprint, documentation |

The sections that follow are the project's design documents, reproduced in full.


## Part: Architecture and traceability

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


## Part: Model

Sakshya runs one pipeline per case. Each stage reads the output of the previous one and nothing is hidden from the investigator: every score is a sum of named terms, and every term names the record it came from.

The pipeline and module map are in [ARCHITECTURE_TRACEABILITY.md](ARCHITECTURE_TRACEABILITY.md). This document gives the arithmetic.

### 1. Intake and custody

Each file listed in `case.yaml` is hashed with SHA-256 before it is parsed and an `intake` entry is written to the case ledger. If the same path later has a different hash an `intake_changed` entry is written and any cached analysis is discarded.

The ledger is a hash chain that starts with a genesis entry. Each entry holds a sequence number, a time, a type, a payload and the hash of the previous entry, and its own hash is

```
hash_i = SHA-256(canonical_json(seq_i, time_i, type_i, payload_i, hash_{i-1}))
```

After every append the new head is signed with Ed25519 and stored as a checkpoint `(scope, seq, head, time, key_id, signature)`. Verification walks the chain and then checks every checkpoint against it. Hash check states and anchoring are described in [FORENSIC_RELIABILITY.md](FORENSIC_RELIABILITY.md).

### 2. Observations and identifiers

Every adapter emits rows with the same columns: time as recorded, time zone, place (latitude, longitude, radius), amount and direction, the identifiers involved and their roles (holder, counterparty, caller, called, device, ATM and so on), the raw text and a pointer to the file and line.

Identifiers are reduced to canonical entities:

| Kind | Canonical form |
| --- | --- |
| phone | E.164, `+91` added to ten digit Indian mobiles, leading zero removed |
| imei | 15 digits; a 14 digit IMEI gets its Luhn check digit |
| imsi | 14 or 15 digits |
| account | `IFSC:number`; numbers without IFSC become `UNKNOWN:number`; masked numbers keep the last four digits |
| upi, email | lower case |
| mac | lower case, colon separated |
| ip, domain | standard form; `www.` removed from domains |

Names are compared after transliterating Devanagari to Latin with schwa deletion, so `रोहित कुमार` and `Rohit Kumar` compare equal. Name agreement is only ever one term in a link; it never merges people on its own.

### 3. Clock correction

Reference sources (bank statements, ATM journals, CDRs, tower dumps) are trusted for time. Every other file is aligned to them.

For a file *f*, events that also appear in reference records (the same transaction reference, the same call, the same SMS alert) give candidate offsets *d_k = t_ref,k - t_f,k*. The offset is chosen by voting: the candidate with the most other candidates within 90 s wins. It is refined with the median of the supporting votes, and its uncertainty is

```
sigma = max(1.4826 * MAD, floor)
```

An anchor whose candidate reference events are more than 30 s apart is ambiguous and is not used. An offset within 150 s of a multiple of 30 minutes is reported as a time zone error only if the file declares no time zone, at least three anchors agree, their spread is at most 120 s and the offset is at least 20 minutes. Each estimate is labelled reference, estimated, weak or unestimated. With anchors spread over at least three days a drift rate is fitted with the Theil and Sen estimator. Files from the same phone export (call log and SMS) share one clock domain and are estimated together. The residual uncertainty is carried into every later time term.

### 4. Link tests

A link states a claim, for example that a phone was near an ATM when cash was withdrawn. Its weight is the base ten logarithm of a likelihood ratio,

```
W = log10 LR = log10 P(evidence | claim) / P(evidence | coincidence)
```

built as a sum of named terms.

**Time term.** For a gap *dt* with expected value *mu* and combined variance *sigma^2* (both clocks plus the event spread), compared with a uniform time in a window *T*:

```
w_time = log10( T * N(dt; mu, sigma^2) )
```

**Place term.** For a distance *d* between two located observations with radii *r_a* and *r_b*, a Rayleigh distance under the claim against a uniform point in a disc of radius *R* under coincidence:

```
sigma^2 = (r_a^2 + r_b^2) / 4
w_place = log10( pi R^2 / (2 pi sigma^2) ) - d^2 / (2 sigma^2 ln 10)
```

*R* is the area the competing phones were actually spread over, not a fixed city radius, so a cell that covers a whole block does not give a strong place term.

**Attribute terms** follow Fellegi and Sunter. For an attribute that agrees with probability *m* under the claim and *u* by chance:

```
w = log10(m / u)              if the attribute agrees
w = log10((1 - m) / (1 - u))  if it disagrees
```

*u* is taken from frequencies inside the case where possible, so a common surname or a popular bank branch counts for little.

**Rarity term** for co-presence. If *N* phones were on the same cells in the same window and *k* of the others are already linked to the case, an entity linked to the case agrees with *m = 0.5* and *u = (k + 1) / (N + 1)*. Busy locations therefore weaken presence links automatically.

**Combining.** Each term belongs to a dependence group: records with a common origin (all records from one bank's core system, one handset, one operator) are one group, whatever file they came from. Terms are summed per group and each group is capped at plus or minus 4, so no single origin can carry a link:

```
W = sum over dependence groups g of clip( sum of terms from g, -4, +4 )
```

A link is accepted (status `inferred`) when *W* is at least 2 and at least two independent groups contribute (for same-event links, two different evidence files). Strong links that rest on one origin stay as candidates with a note. Investigators can confirm or reject any link; rejected links are kept and shown.

**Coincidence rates.** Rates estimated from counts in the case use add-one smoothing, *(k + 1) / (n + 2)*, so a rate is never exactly zero or one.

**Blocking.** Candidate pairs are generated only inside blocks: shared reference or amount for same-event links, a sorted time window and then a distance limit for co-presence, shared KYC attributes for same-actor links. The number of pairs at each stage is recorded with every analysis.

**Prior and posterior.** Co-presence links carry prior odds of *1 / (N - 1)*, one person out of the crowd, so

```
posterior = (prior_odds * LR_c) / (1 + prior_odds * LR_c)
```

where *LR_c* is the calibrated likelihood ratio (section 10).

Link types:

| Type | Claim | Main terms |
| --- | --- | --- |
| same_event | Two records describe one event (debit and credit, UPI reference and SMS alert, ATM journal and statement) | time, amount, reference agreement |
| co_presence | A phone, handset or cloud account was near a cash withdrawal | time, place, rarity |
| impossibility | A phone could not have been at the withdrawal | travel speed above 120 km/h between a fix and the event |
| same_actor | Two identifiers belong to one person | KYC name and address, registered phone, SIM in handset, shared handset, cloud account device, seizure memo, shared network infrastructure, travelling together |
| sequence | One transfer triggered the next | Hawkes trigger probability |

**Sequence links.** Credits and debits on an account are modelled as a self-exciting process with background rate *mu* and kernel *alpha beta e^(-beta t)*, with *alpha = 0.8*. *beta* is fitted by maximum likelihood over a grid of decay times on the case's own statements. The weight of a link from a credit to a later debit is

```
w_trigger = log10( lambda(t) / mu )
```

and only the latest credit in a burst is credited. A new contact (first seen within 14 days) followed by a payment gives a contact to payment link.

### 5. People

Entities are grouped with union and find over accepted same-actor links at *W >= 2*, strongest first. A merge is refused, and the refusal recorded, when:

* an investigator marked the two identifiers as different people;
* the link rests on an identifier that is linked to three or more identifiers of one kind (a shared handset or router), which cannot join people on its own;
* the registered names of the two groups have a similarity below 0.6;
* the two groups have location fixes within 10 minutes of each other that are further apart than travel at 900 km/h, both radii and a 5 km margin allow;
* a shared handset would attach new identifiers to the complainant.

Persons are numbered by their distance from the complainant in the link graph.

### 6. Indicators

Behavioural indicators are computed per entity and weighted from `config/indicators.yaml`:

* money: received from the complainant, passed on within 60 minutes, split across payees, cash withdrawn, a new account, commission kept, funds retained, long history with the payee;
* communication: contact before payment, lure language, threat language;
* telecom: SIM change shortly before debits, OTP on the new SIM, many SIMs on one handset;
* location: present at a withdrawal, cleared by travel time;
* network: beaconing, large outbound volume, shared infrastructure.

### 7. Explain

A crime template (`config/templates/*.yaml`) lists roles, phases, the indicators that support or contradict each role, variants (for example a knowing or unwitting first-layer mule), the observability of each phase in each source and the typical time between phases.

Beam search binds candidate persons or accounts to roles. The score of a hypothesis *H* is

```
S(H) = prior(H)
     + sum over roles of indicator weights of the bound units
     + sum over template relationships of the capped link weights between bound roles
     + sum over missing phases of log10(1 - o)
     + order penalties
```

Relationships (contact before payment, co-presence or impossibility at withdrawals, transfer sequences, shared actor) take the weights of the links between the bound roles, capped per dependence group. To avoid counting the same evidence twice, an indicator that was derived from a link is replaced by that link, and a link whose records were already counted by another indicator is excluded; both lists are shown with each hypothesis.

*o* is the chance that the phase would have been seen given the sources in the case, the parties they cover, and the period they span. A missing phase that the evidence would almost certainly have shown costs a lot; one that the case simply has no source for costs nothing.

"No offence" is the reference with score 0. The decision has five outcomes, set out in [FORENSIC_RELIABILITY.md](FORENSIC_RELIABILITY.md): an offence pattern is reported as supported when *S >= 2* and it leads every other template and the reference by at least 1.

The difference in score between two explanations is a log ten likelihood ratio, so a margin of 5.5 reads as the leading explanation fitting the evidence about 316,000 times better.

### 8. Reach

Transfers are built from statements, with debit and credit legs joined by same-event links. Payments from the complainant to payees first seen within 30 days of the complaint are the origin of the trace.

Each account holds a tainted balance. On every debit the tainted share leaves with the money:

* pro-rata: tainted share of the debit = tainted balance / balance before the debit;
* first in, first out: the oldest money leaves first.

Both rules can be shown at any time *as of*, so the trail can be replayed as it stood at any moment. Cash withdrawals end a path. Reversed transfers are dropped, refunds to the complainant are counted as returned, and fees are kept apart from transfers.

Each statement is reconciled: the opening balance is inferred from the first row, each reported balance is compared with the running balance, gaps of more than 21 days with a balance jump are flagged, and totals of credits, debits and the unexplained remainder are reported. The trace conserves money: what left the complainant equals what is held, withdrawn as cash, or gone outside the evidence.

The freeze list gives, for each account still holding traced money, the verified statement balance, an upper bound on what can be recovered (the smaller of traced money held and the balance), and its basis:

```
expected recoverable = recoverable upper bound * (1 - P(money moves before a freeze lands))
```

The probability is used only for accounts bound to a mule role while the phase model says cash-out is next; the row is then marked "model estimate" and shows a range for the probability 20 points higher or lower. Every other account is marked "heuristic", has no probability, and is ranked by amount and hop.

### 9. Predict

The default model is semi-Markov over the phases of the leading template. The current phase is the latest phase with an observed event up to the cut-off. The time spent in it follows a log-normal duration with median and spread fitted on training cases where at least five exist, otherwise taken from the template and labelled as elicited. The probability that the next phase has already started unseen is

```
P(moved) = F(elapsed) * (1 - o_next) / ( (1 - F(elapsed)) + F(elapsed) * (1 - o_next) )
```

where *F* is the duration distribution and *o_next* the observability of the next phase. The engine reports the chance of the next phase within 15, 30, 60 and 120 minutes, an 80% interval for the time remaining and the chance it happens before a freeze can land (45 minutes by default). A hidden Markov model with fixed stay, advance and skip probabilities is kept for comparison. Every forecast is computed on a strict snapshot: records time-stamped after the cut-off and evidence acquired after it are removed before clock correction, and clock correction is repeated on the snapshot.

### 10. Calibration

For each link type with at least 50 labelled training links of both classes, a logistic model

```
P(true | W) = sigmoid( k * W * ln 10 + b )
```

is fitted by log loss, with *b* replaced by the link's own prior odds where every link has one. *k* is bounded between 0.2 and 2. The calibrated weight *k W* is used for the reported likelihood ratio, posterior and verbal strength. Acceptance uses the uncalibrated weight, so calibration never changes which links are accepted. The verbal scale follows the example bands of the ENFSI guideline for evaluative reporting (2015). Reliability tables with Wilson intervals are in [MODEL_VALIDATION.md](MODEL_VALIDATION.md).

### 11. Decide

Each possible evidence request (a statement for an account the money reached, CDRs for a number with no call records, a tower dump or CCTV for a withdrawal, hosting records for a domain, a statement from an account holder) is scored by

```
value per day = (expected information gain + gap bonus + money bonus) / days to obtain
```

Expected information gain has three outcomes per request: a result that supports the hypothesis, a result that does not, and no result at all (the record does not exist or is refused), with an elicited chance of the last for each request type:

```
EIG = H(prior) - [ sum over results r in {found, not found} of P(r) H(posterior | r) + P(unavailable) H(prior) ]
```

The prior is a tempered posterior over the hypotheses (scores divided by 3) so that the ranking does not collapse when one explanation dominates. The outcome probabilities are elicited, not measured, and each request says so.

Fragility is measured, not estimated: the strongest supporting links (and groups of links that were counted together) are removed one at a time, then in pairs, and the whole analysis from clustering onward is re-run each time. The result lists which removals change the conclusion, which is what a defence would challenge first.

### 12. Determinism

Every stage is deterministic. The result digest covers all analysis output and excludes only timings, the ledger listing, the freshness check and custody timestamps, so the same inputs give the same digest on any machine and with any Python hash seed.


## Part: Forensic reliability

This document says what each part of Sakshya's output can be relied on for, and where it stops. It is written for investigators, reviewers and anyone who has to explain a Sakshya finding to someone else.

### 1. Original evidence

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

### 2. Custody ledger

Each case has a ledger, and the service has a system ledger. Each entry holds a sequence number, a time, a type, a payload and the hash of the previous entry; the first entry is a genesis entry naming the case. After every append the head is signed with an Ed25519 key and stored as a checkpoint.

Recorded events include case creation, intake, analysis versions (with the digest of the result and what changed), investigator decisions and their revocations, imported decisions (with the SHA-256 of the import), exports, reports (with the SHA-256 of the HTML), case access, access grants and evidence changes.

Verification reports three things:

| Field | Meaning |
| --- | --- |
| `chain_ok` | Every entry links to the one before it and none was altered |
| `anchoring` | `independent` if the key and checkpoints are on storage outside the data folder, `local` if they share it, `none` if no checkpoints are configured |
| `issues` | Checkpoints with bad signatures, entries beyond the last checkpoint, heads that differ from a checkpoint, missing genesis |

With `local` anchoring, someone who controls the whole disk could rewrite the ledger, the checkpoints and the key together. The workbench and report say "locally verified but not independently anchored" in that case.

### 3. Observations

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

### 4. Time and place

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

### 5. Links and their weights

A link weight W is the base ten logarithm of a likelihood ratio: how much more probable the observed records are if the claim is true than if they arose by coincidence. Terms are grouped by dependence group and each group is capped at plus or minus 4, so records that share an origin (an SMS bank alert and the bank's own statement, say) count once. A link is accepted at W of 2 only when at least two independent groups contribute. Coincidence rates are estimated from the case's own records with add-one smoothing so that no rate is zero.

The weights are statistical models, not facts. Section 2 of [MODEL_VALIDATION.md](MODEL_VALIDATION.md) shows how often links in each weight band were true on synthetic data.

### 6. Explanations

A hypothesis score adds the indicators bound to its roles and the links between roles, each counted once: an indicator derived from a link is replaced by the link, and a link resting on records already counted by an indicator is excluded. Missing phases are penalised only to the extent that the sources in the case would have shown them. The five outcomes are:

| Outcome | When |
| --- | --- |
| OFFENCE_SUPPORTED | One offence pattern scores at least 2 and leads every alternative, including no offence, by at least 1 |
| NO_OFFENCE_INDICATED | No suspicious indicators, and the sources present could have shown an offence |
| UNKNOWN_PATTERN | Suspicious indicators exist but no pattern fits clearly |
| INSUFFICIENT_EVIDENCE | No readable records beyond the complaint, or too few sources to see the patterns |
| ANALYSIS_FAILED | No evidence file could be parsed |

"Offence pattern supported" means the records fit a known pattern better than the alternatives. It is not a finding that any person committed an offence; that is for the investigator and the court.

### 7. What is modelled and what is a heuristic

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

### 8. Format-specific limits

| Source | Limit |
| --- | --- |
| Packet captures | Flows, DNS and the TLS server name are read. Payloads are never decrypted. The server name is what the client asked for and may not match the server that answered. |
| Phone databases | Opened read-only on a copy. Text recovered from unallocated space is labelled "Recovered fragment (unverified)", has no time, and its sender and completeness are unknown. |
| Email | Authentication results (DKIM, SPF, DMARC) are reported as stamped by the receiving server; they are not re-verified. |
| Video | Key frames and scene changes are listed with the SHA-256 of their decoded pixels. That hash identifies the picture, not the file; the file hash is in the intake entry. Wall-clock times need a recording start in the manifest or the container's creation time, and are marked with their basis. |
| Social media exports | Parsed as the platform exported them. Display names may be edited by users and are not identity. |

### 9. Reproducibility

Each analysis stores its inputs: evidence digests, parser versions, a configuration digest, the engine version, the decisions and the cut-off time. The SHA-256 of these is the cache key. Each result is kept as a numbered analysis version with its bundle, its tables (Parquet, or JSON Lines if Parquet is unavailable) with per-table hashes, the reason it was run, who ran it and what changed from the previous version. The same inputs give the same result digest on any machine, which the test suite checks with two different Python hash seeds.


## Part: Model validation

Every number here comes from `sakshya/data/evaluation/results.json`, produced on 2026-11-24 by

```bash
python -m sakshya.evaluation.run --fit --per-kind 6 --training 18 --scales 1,5,10,20,100
```

which took 4 minutes 51 seconds on the build machine. The workbench shows the same file under Evaluation.

## What the evaluation can and cannot show

All cases are synthetic. They come from Sakshya's own generator, which writes an answer key beside each case. The engine never reads the answer keys. Training cases (seeds 500 to 517) are used only to fit calibration scales and phase durations; the 30 held-out cases use other seeds.

Because the generator and the engine were written by the same team, the held-out cases share the structure the engine was designed around. High scores here show that the engine does what it was built to do on data of that shape. They are not evidence of accuracy on real case files, and they do not replace a blind evaluation on real, independently labelled cases. Several results below are perfect for exactly this reason.

## Held-out results (30 cases: 6 each of UPI investment fraud, sextortion, SIM swap, no offence, unknown pattern)

| Area | Metric | Result |
| --- | --- | --- |
| Extraction | Records parsed, worst of 16 generated source types | 100% |
| Extraction | Field-level precision and recall on 17 labelled fixture formats (see below) | 1.000 and 1.000 |
| Same-event links | Precision / recall | 0.999 / 0.990 |
| Presence links | Precision, entity recall, impossibility recall | 1.000, 1.000, 1.000 |
| Identity resolution | Precision / recall / F1 | 1.000 / 0.772 / 0.866 |
| Identity resolution | Decoy pairs (same common name, different people) merged | 0 of 20 |
| Clocks | Offset error, median / worst over 24 skewed files | 5.1 s / 9.9 s |
| Clocks | Wrong time zones detected | 6 of 6 |
| Timeline | Kendall tau against true order, before / after correction | 0.975 / 0.998 |
| Traceability | Findings with a resolvable file, line and hash | 2,233 of 2,233 |
| Determinism | Same input, same digest | yes |
| Custody | Tampered CCTV frames caught / false alarms | 4 of 4 / 0 |
| Money | Accounts reached, precision / recall | 1.000 / 1.000 |
| Money | Cash withdrawn, relative error | 0.55% |
| Roles | First-layer mule, cash-out person, mule variant | 100%, 100%, 100% |
| Classification | Offence type including no offence and unknown | 30 of 30 |
| Speed | Analysis time per case, median / worst | 0.43 s / 2.20 s |

Identity resolution recall is the weakest figure. The engine refuses merges that rest on a single shared device used by several identifiers, on names that disagree, or on fixes too far apart to be one person, and it never merges on a common name alone. That keeps precision at 1.0 and decoy merges at zero, at the cost of leaving some true same-person pairs unmerged. Unmerged pairs are still shown as candidate links for the investigator to confirm.

## Link calibration by type

Held-out links, grouped by reported weight W (log10 likelihood ratio). The share that are true is shown with a 95% Wilson interval. Links are accepted at W of 2.

| Type | W band | Links | True | 95% interval |
| --- | --- | --- | --- | --- |
| Co-presence | below 0 | 6,616 | 0.0% | 0.0 to 0.1% |
| | 0 to 1 | 3,232 | 0.0% | 0.0 to 0.1% |
| | 1 to 2 | 1,287 | 0.0% | 0.0 to 0.3% |
| | 2 to 3 | 2 | 100% | 34 to 100% |
| | 3 to 4 | 42 | 100% | 92 to 100% |
| | 4 and above | 13 | 100% | 77 to 100% |
| Same actor | below 0 | 39 | 0.0% | 0 to 9% |
| | 1 to 2 | 13 | 100% | 77 to 100% |
| | 2 to 3 | 78 | 100% | 95 to 100% |
| | 3 to 4 | 8 | 100% | 68 to 100% |
| Same event | 1 to 2 | 8 | 100% | 68 to 100% |
| | 2 to 3 | 313 | 99.4% | 97.7 to 99.8% |
| | 3 to 4 | 395 | 100% | 99.0 to 100% |
| | 4 and above | 158 | 100% | 97.6 to 100% |

Calibration scales fitted on the training links by minimising log loss:

| Type | Training links | Scale | Brier, scaled / unscaled |
| --- | --- | --- | --- |
| Co-presence | 10,170 | 0.655 | 0.0015 / 0.0024 |
| Same actor | 127 | 2.0 | 0.0001 / 0.0478 |
| Same event | 881 | 2.0 | 0.0016 / 0.0758 |

For same actor and same event the fitted scale sits at the upper bound of the allowed range (0.2 to 2.0). On this synthetic data the weights understate the evidence, and the bound stops calibration from inflating them further. The scale changes only the reported likelihood ratio, posterior and verbal strength; acceptance always uses the uncalibrated weight, so calibration never changes which links are accepted. Types with fewer than 50 labelled links or with only one class are reported as not calibrated and keep their raw weights.

## Forecasting cash-out

For each held-out offence case two cut-offs were taken (10 and 40 minutes after layering began). At each cut-off the whole analysis was re-run with `as_of` set to the cut-off, so no record time-stamped later, and no evidence acquired later, was visible. The test `tests/test_pipeline.py::test_adding_future_evidence_does_not_change_a_past_forecast` checks this directly by adding a later bank row and comparing the forecasts.

| Model | Brier score, cash-out within 60 min | Median absolute error | 80% interval coverage | Phase correct |
| --- | --- | --- | --- | --- |
| Base rate from training cases | 0.229 | n/a | n/a | n/a |
| Median duration baseline | 0.167 | 9.3 min | n/a | n/a |
| Hidden Markov model | 0.133 | 9.2 min | 100% | 100% |
| Semi-Markov phase model (default) | 0.133 | 9.2 min | 100% | 100% |

36 forecasts on 18 cases. Both phase models beat both baselines on Brier score. The hidden Markov and semi-Markov models give almost the same numbers because at these cut-offs little time has passed compared with the typical layering duration, so the semi-Markov model's estimate that the next phase has already happened unseen is small. Interval coverage of 100% means the 80% intervals are wider than they need to be on this data. Phase durations were fitted on six training cases per offence type and the fitted spread sits at its floor (0.3), which reflects the low variance of the generator rather than real offences. In the workbench, a forecast based on fewer than five past cases for a transition is labelled as a rough guide, and its median time is not shown.

## Parser validation

`python -m sakshya.evaluation.parsers` builds 17 fixtures in a temporary folder, parses each and compares the result field by field with hand-written labels: record kind, every identifier with its role, time (within one second), direction, duration, amount, text and selected attributes.

| Format | Records | Precision | Recall | Value checks |
| --- | --- | --- | --- | --- |
| Bank statement CSV (multiline narration, failed, reversal, duplicate, fee) | 5 | 1.000 | 1.000 | 14 of 14 |
| WhatsApp text export (multiline, system line) | 2 | 1.000 | 1.000 | 6 of 6 |
| PCAP (DNS, TLS SNI, three flows) | 5 | 1.000 | 1.000 | 8 of 8 |
| Android SMS database with a deleted row | 4 | 1.000 | 1.000 | 9 of 9 |
| Android call log database | 2 | 1.000 | 1.000 | 6 of 6 |
| iOS Messages database | 2 | 1.000 | 1.000 | 4 of 4 |
| Chromium history | 1 | 1.000 | 1.000 | 1 of 1 |
| Binary property list | 2 | 1.000 | 1.000 | 4 of 4 |
| vCard | 2 | 1.000 | 1.000 | 4 of 4 |
| Telegram export | 2 | 1.000 | 1.000 | 4 of 4 |
| Instagram export (with text needing repair) | 2 | 1.000 | 1.000 | 3 of 3 |
| Social media CSV (multiline, malformed row) | 2 | 1.000 | 1.000 | 4 of 4 |
| HTML table | 2 | 1.000 | 1.000 | 4 of 4 |
| mbox (attachment, authentication results, reply) | 2 | 1.000 | 1.000 | 4 of 4 |
| Cloud sign-in JSON | 2 | 1.000 | 1.000 | 2 of 2 |
| Device report JSON | 1 | 1.000 | 1.000 | 1 of 1 |
| MPEG-4 video (key frame and scene change) | 2 | 1.000 | 1.000 | 3 of 3 |

These fixtures were written together with the parsers. They prove the parsers handle the documented structures and the edge cases listed; they do not prove coverage of every version of every vendor's export. Real exports should be checked with a few hand-labelled records before a new format is relied on.

## Scaling

The same UPI fraud scenario generated at increasing size, analysed end to end including the fragility recomputation. Times were measured with Python memory tracing switched on, which slows execution; without tracing the same 1x case took 3.95 s and the 10x case 6.38 s on the build machine.

| Size | Records | Identifiers | Presence pairs kept by blocking | Seconds | Peak traced memory |
| --- | --- | --- | --- | --- | --- |
| 1x | 3,063 | 1,271 | 1,383 of 2,619 | 8.5 | 11 MB |
| 5x | 5,644 | 5,118 | 7,041 of 10,365 | 13.3 | 28 MB |
| 10x | 8,782 | 9,920 | 13,862 of 19,767 | 19.2 | 50 MB |
| 20x | 15,137 | 19,515 | 27,817 of 38,850 | 32.3 | 93 MB |
| 100x | 66,265 | 96,310 | 139,395 of 192,258 | 135.5 | 456 MB |

Time grows much more slowly than the number of identifiers: 76 times the identifiers took 16 times as long. The decision stayed the same at every size. Same-event blocking compared 1,027 candidate pairs in 33 blocks at every size, because added background records do not share references or amounts with the offence.

## Reproducing

```bash
pip install -r requirements-dev.txt
python -m sakshya.evaluation.run --fit --per-kind 6 --training 18 --scales 1,5,10,20,100
python -m sakshya.evaluation.parsers --dir /tmp/sakshya-fixtures
python -m pytest -q
```

`--fit` rewrites `sakshya/config/calibration.json` and `sakshya/config/predict_params.json`. Their digest is part of every analysis cache key, so cases are re-analysed after a refit and each new result is stored as a new analysis version.


## Part: Security remediation

This file maps each of the 22 security findings to the change that addresses it and the regression test that proves it. The findings are numbered and titled as they were listed in the engineering directive. The original findings report was not available while this work was done, so any detail in that report beyond its title was not checked against this list.

All regression tests are in `tests/test_security.py` unless another file is named. Run them with:

```bash
python -m pytest tests/test_security.py -q
```

| # | Finding | Change | Regression test |
| --- | --- | --- | --- |
| 1 | Anonymous users can read cases | Every case, report, export, observation and job endpoint requires a signed-in session. Access is deny by default: a user sees a case only if they are an admin or were granted it. A case the user may not see answers 404, not 403, so its existence is not disclosed. | `test_f01_anonymous_case_access_is_rejected`, `test_role_and_case_isolation` |
| 2 | Anonymous users can record investigator actions | Actions need a session, the `act` permission and a CSRF token sent in the `X-CSRF-Token` header that matches the session. The session cookie is HttpOnly and SameSite=Strict. | `test_f02_anonymous_and_csrf_less_actions_are_rejected` |
| 3 | The client chooses the actor name | The request models forbid unknown fields, so a request that carries `actor` is refused with 422. The actor written to the ledger is always taken from the session. | `test_f03_client_supplied_actor_cannot_spoof_identity` |
| 4 | Map labels can inject markup | All dynamic text in the workbench is set through `textContent`. Map tooltips and popups are DOM nodes, never HTML strings. The report template autoescapes. The test checks the JavaScript for `innerHTML`, `insertAdjacentHTML`, `outerHTML` and `document.write`, and uploads a case whose title is an HTML payload. | `test_f04_markup_in_labels_is_rendered_as_text` |
| 5 | A failed upload leaves an invalid case behind | Uploads are extracted into a staging folder, validated and probe analysed there, and only then renamed into place in one step. Any failure removes the staging folder. Leftovers from a crash are removed at start-up. | `test_f05_failed_upload_never_persists_a_case`, `tests/test_storage.py::test_interrupted_uploads_are_cleaned_on_start` |
| 6 | A malformed action can poison a case | Action bodies are strict models. Each action type has its target checked against the current analysis before anything is written: links must exist, merge targets must be two different identifiers in the case, notes must point at a record. | `test_f06_malformed_actions_cannot_poison_a_case` |
| 7 | Imported decisions are not audited | An import writes one `decision_import` ledger entry with the importer, the stated source and the SHA-256 of the imported items, then one `investigator_action` entry per item that points back to that digest. | `test_f07_imported_decisions_are_audited_with_the_importer` |
| 8 | A missing reference hash is shown as verified | Hash checking has seven explicit states: VERIFIED, MISMATCH, MISSING_REFERENCE_HASH, INVALID_REFERENCE_HASH, UNREADABLE, NOT_VERIFIABLE and NOT_CHECKED. Only a match against a supplied reference is VERIFIED. A CCTV frame without a recorder hash is never VERIFIED. | `test_f08_missing_reference_hash_is_never_verified`, `tests/test_custody.py::test_hash_states` |
| 9 | Cached analysis survives changes to evidence | The analysis cache key is the SHA-256 of the evidence digests, parser versions, configuration digest, engine version, decisions and cut-off time. A request that finds a different key invalidates the cached result, logs `analysis_invalidated` and schedules a new run. The evidence item is marked `changed_since_intake`. | `test_f09_changed_evidence_invalidates_the_cached_analysis` |
| 10 | The ledger can be rewritten, reordered or truncated | Each ledger starts with a genesis entry. After every append the head is signed with an Ed25519 key and stored as a checkpoint. Verification checks the chain and every checkpoint. When the key and checkpoint folders are on separate storage the result says "independent", otherwise "local", and the message says that local anchoring does not protect against someone who controls the whole disk. | `test_f10_ledger_tampering_fails_anchored_verification[rewrite/reorder/truncate]`, `test_direct_ledger_edit_is_detected` |
| 11 | Readiness reports healthy when storage is broken | `/api/health/ready` writes and reads a probe file, checks the databases, configuration, signing key and case folder, and answers 503 if any check fails. `/api/health/live` only says the process is up. | `test_f11_readiness_fails_when_storage_fails` |
| 12 | Uploads are read fully into memory without a limit | The upload is streamed to disk in chunks and stopped at the configured size, before the archive is opened. Declared lengths over the limit are refused at once. Archive entry count, total size, compression ratio and nesting depth are limited during extraction. | `test_f12_streaming_upload_stops_at_the_limit` |
| 13 | No rate limiting | A sliding window limiter covers sign-in (per address and per account), uploads, analysis, reports, exports, actions and the API as a whole. Accounts lock for 15 minutes after five failed sign-ins. | `test_f13_repeated_requests_are_rate_limited`, `tests/test_api.py::test_account_lockout_after_repeated_failures` |
| 14 | Heavy analysis blocks the server | Analysis and uploads run as jobs in a worker pool with a timeout and cancellation. Endpoints return a job identifier at once. | `test_f14_heavy_analysis_does_not_block_the_service` |
| 15 | Invalid YAML or failed parsing leaves partial state | Manifests are size limited, read with `yaml.safe_load` and validated against an allow list of keys. A case is refused if no evidence file yields a readable record. All failure paths remove the staging folder. | `test_f15_invalid_yaml_and_unparseable_evidence_are_cleaned_up` |
| 16 | No content security policy | The policy is `default-src 'none'` with scripts, styles, fonts and connections limited to the same origin and no `unsafe-inline` or `unsafe-eval`. Vendored libraries that inserted inline styles were patched (see the vendor notes). The report page uses a per-response style nonce and contains no script. | `test_f16_csp_blocks_unauthorised_scripts` |
| 17 | Sensitive responses can be cached | Every API response, the application page and map tiles carry `Cache-Control: no-store`. | `test_f17_sensitive_responses_are_not_cached` |
| 18 | The map sends case coordinates to a third party | No base map is loaded by default, so no coordinates leave the server. A local tile folder or an explicit tile URL can be configured; the tile origin is then added to the policy and the workbench shows which server sees the viewed area. | `test_f18_default_map_sends_no_coordinates_anywhere` |
| 19 | Data is lost on restart | All state lives under `SAKSHYA_DATA_DIR`: users and sessions in SQLite, jobs in SQLite, cases with their ledgers, decisions and analysis versions on disk. The Render blueprint mounts a persistent disk. | `test_f19_data_survives_a_restart` |
| 20 | Forwarded headers can spoof the client address | `X-Forwarded-For` is read only when the direct peer is inside `SAKSHYA_TRUSTED_PROXIES`, and then from the right, skipping trusted hops. Uvicorn's own proxy header handling is turned off. | `test_f20_forwarded_headers_are_ignored_unless_the_proxy_is_trusted` |
| 21 | Empty or unreadable evidence still yields a conclusion | Each evidence file gets a parse state (parsed, partial, empty, failed). When too little was read the decision is INSUFFICIENT_EVIDENCE, and when nothing could be read it is ANALYSIS_FAILED. | `test_f21_empty_or_unparseable_evidence_never_claims_an_offence` |
| 22 | Multiline CSV records are split | CSV files are read with a real CSV reader over the whole text, so quoted fields keep their line breaks. Rows with the wrong number of fields are quarantined with their line number. | `test_f22_multiline_csv_records_stay_intact`, `tests/test_adapters.py::test_field_level_precision_and_recall[bank_statement]` |

## Protections that were already present and are still tested

| Protection | Test |
| --- | --- |
| Zip path traversal, absolute paths, executables and scripts in uploads | `test_zip_traversal_absolute_paths_and_executables_are_refused` |
| Report escaping | `test_f04_markup_in_labels_is_rendered_as_text` |
| Direct edits to the ledger file | `test_direct_ledger_edit_is_detected` |
| Container runs as a non-root user | `test_docker_image_runs_as_non_root` |
| Evidence files are read only after intake | `test_original_evidence_is_read_only_after_intake` |
| Roles and per-case access | `test_role_and_case_isolation`, `tests/test_api.py::test_only_auditors_and_admins_read_the_audit_trail` |

## Residual risks

These remain open and are described in [THREAT_MODEL.md](THREAT_MODEL.md):

1. On a single-disk host (such as one Render service with one disk) the signing key and checkpoints sit on the same storage as the ledgers. The ledger then reports "local" anchoring. Someone with full control of that disk could rewrite the ledger, the checkpoints and the key together. Point `SAKSHYA_ANCHOR_DIR` at separate storage, or copy checkpoints off the host regularly, to close this.
2. The backup archive contains the signing key unless `--exclude-keys` is used. Treat backups as secret.
3. Rate limits are kept in memory per process. With several processes behind a load balancer each process counts on its own.
4. There is no multi-factor sign-in. Deploy behind an identity-aware proxy or VPN when that is required.
5. Dependency vulnerabilities are checked with `pip-audit` at release time, not continuously.


## Part: Implementation status

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
