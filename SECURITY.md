# Security

Sakshya holds evidence from criminal investigations. Treat every deployment as handling sensitive personal and financial data.

## Supported versions

Only the latest release receives fixes. The engine version is shown on each case overview and returned by `/api/auth/state`.

## Reporting a vulnerability

Report suspected vulnerabilities privately to the maintainers of the deployment you use (for the competition build, the EigenThinkers team) and do not open a public issue. Include the version, the steps to reproduce and the impact you expect.

## Before handling real case data

Do not load real case data until all of the following hold:

1. The full test suite passes on the build you deploy (`python -m pytest -q`), including `tests/test_security.py`.
2. `pip-audit -r requirements.lock` reports no known vulnerabilities, or each one is assessed and recorded.
3. The service runs over HTTPS with `SAKSHYA_COOKIE_SECURE=true` and `SAKSHYA_ENV=production`.
4. The data directory is on encrypted, backed-up storage, and backups are tested with `python -m sakshya restore` and `python -m sakshya verify`.
5. The signing key and checkpoints are on storage separate from the data directory (`SAKSHYA_KEY_DIR`, `SAKSHYA_ANCHOR_DIR`), or checkpoints are copied off the host on a schedule.
6. The bootstrap token has been used and removed, and every user has their own account with the least role they need.
7. `SAKSHYA_DEMO_OPEN` is not set (it lets anyone in as a guest investigator and exists only for public demonstrations of synthetic cases).
8. The map is left without a base map, or uses a tile server your organisation controls.

## Summary of controls

| Area | Control |
| --- | --- |
| Identity | Local accounts with Argon2id password hashes, at least 12 characters, account lockout after five failures, idle and absolute session expiry, server-side session revocation |
| Authorisation | Four roles (admin, investigator, reviewer, auditor) and per-case grants, deny by default |
| Requests | CSRF token on every state-changing request, SameSite=Strict HttpOnly cookie, same-origin check on sign-in, strict request models that refuse unknown fields |
| Browser | Content security policy without inline script or style, frame denial, no-store caching, no referrer, restrictive permissions policy |
| Uploads | Streamed with a size cap, zip entries checked for traversal, links, executables, encryption, depth, count, size and compression ratio, staged and committed atomically |
| Evidence | Read only after intake, SHA-256 at intake and on every run, seven explicit hash states, analysis invalidated when evidence changes |
| Custody | Hash-chained ledgers per case and for the system, Ed25519-signed checkpoints after every entry, every decision, import, export, report and case access recorded |
| Availability | Analysis in a bounded worker pool with timeouts, rate limits, readiness checks |
| Logging | Access logs hold the method, the path with the case identifier removed, status, duration, a salted hash of the client address and a request identifier; no bodies, no query strings, no identifiers from evidence |

See [docs/SECURITY_REMEDIATION.md](docs/SECURITY_REMEDIATION.md) for the finding-by-finding record and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for what is and is not covered.

## Scope limits

Sakshya analyses evidence that was lawfully acquired and supplied to it. It does not intercept communications, monitor radio, bypass device locks, recognise faces or identify suspects automatically. A device location never establishes who held the device or where a person was; the workbench says so wherever a location is shown.
