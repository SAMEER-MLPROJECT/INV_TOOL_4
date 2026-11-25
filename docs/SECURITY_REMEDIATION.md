# Security remediation

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
