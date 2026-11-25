# Threat model

## Assets

| Asset | Why it matters |
| --- | --- |
| Original evidence files | They are the basis of every finding and may be produced in court |
| Custody ledgers and checkpoints | They show what was received, when, and what was done with it |
| Investigator decisions | They change the analysis and must be attributable |
| Analysis versions and reports | They are what investigators act on and may be disclosed |
| User accounts and sessions | They gate access to all of the above |
| Signing key | It makes checkpoints that a later reviewer trusts |

## Actors

| Actor | Capability assumed |
| --- | --- |
| Internet attacker | Can reach the public URL, has no account |
| Signed-in user acting outside their role | Has a valid account, tries to read other cases or act beyond their role |
| Malicious evidence | A file or archive crafted to break the parser or the browser |
| Host operator or attacker with disk access | Can read and write the data directory |
| Third-party services | Map tile servers, package registries |

## Threats and responses

| Threat | Response | Residual risk |
| --- | --- | --- |
| Unauthenticated access to cases | Sessions required everywhere except health and sign-in; deny-by-default case grants | None known |
| Session theft through script injection | No inline script, strict CSP, all text set as text, report autoescaped | A browser or extension compromise is out of scope |
| Cross-site request forgery | CSRF header token plus SameSite=Strict cookie | None known |
| Password guessing | Argon2id, length rule, lockout, per-address and per-account rate limits | No second factor; use an identity-aware proxy if one is needed |
| Archive bombs, traversal, executables | Streaming size cap, entry checks, staging folder | A file inside the limits can still be slow to parse; jobs have a timeout |
| Parser exploits | Pure Python parsers for CSV, JSON, YAML (safe loader), email, plist, HTML; SQLite opened read-only on a copy; packets read with scapy; video decoded with PyAV | A flaw in a decoding library (PyAV and its bundled FFmpeg, scapy, SQLite) could still be reached by a crafted file; keep dependencies current |
| Altering evidence after intake | Files made read-only, hashed on each run, changes invalidate analysis and are logged | A host operator can still replace files; the change is visible against the intake hash |
| Rewriting the ledger | Hash chain, signed checkpoints, genesis entry | If the key, checkpoints and ledger are on one disk, someone with full disk control can rewrite all three; the ledger reports "local" anchoring in that case |
| Spoofed client address in logs and limits | Forwarded headers trusted only from configured proxy ranges | A wrong proxy range setting weakens this |
| Location data leaking to a map provider | No base map by default | If a remote tile URL is configured, that server sees which areas are viewed |
| Denial of service through analysis | Worker pool, job timeout, rate limits, upload limits | A single process has finite capacity; scale horizontally behind a load balancer if needed |
| Dependency compromise | Pinned versions with hashes in `requirements.lock`, SBOM, `pip-audit` | Pins must be refreshed and audited regularly |

## Out of scope

Live interception, radio monitoring, device unlocking, facial recognition and automated suspect identification are not features of this system and are not covered here.
