# Environment reference

All settings are read from environment variables when the service starts. `.env.example` lists them with their defaults; the service does not read a `.env` file itself, so pass them through your shell, `docker run --env-file`, or the hosting dashboard.

## Storage

| Variable | Default | Meaning |
| --- | --- | --- |
| `SAKSHYA_DATA_DIR` | `data` | Root of all state: cases, ledgers, databases, analysis versions. `SAKSHYA_WORKSPACE` is read as a fallback for older deployments. |
| `SAKSHYA_KEY_DIR` | `<data>/keys` | Folder for the Ed25519 signing key. Created with mode 0700; the key file is 0600. |
| `SAKSHYA_ANCHOR_DIR` | `<data>/anchors` | Folder for signed ledger checkpoints. Anchoring is reported as "independent" only when both this and the key folder are outside the data folder. |

## Service

| Variable | Default | Meaning |
| --- | --- | --- |
| `SAKSHYA_ENV` | `local` | `production` turns on HSTS and turns off the API documentation unless `SAKSHYA_API_DOCS` says otherwise |
| `SAKSHYA_COOKIE_SECURE` | `true` | Send the session cookie only over HTTPS. Set `false` only for plain HTTP on 127.0.0.1. |
| `SAKSHYA_TRUSTED_PROXIES` | empty | Comma-separated networks whose `X-Forwarded-For` header is believed, for example `10.0.0.0/8`. Empty means the direct peer address is always used. |
| `SAKSHYA_API_DOCS` | `true` locally, `false` in production | Serve the OpenAPI description at `/api/docs` |
| `SAKSHYA_BOOTSTRAP_TOKEN` | empty | One-time token that allows the first administrator to be created from the browser. Ignored once any user exists. |
| `SAKSHYA_ADMIN_PASSWORD` | empty | Used by `create-admin` and `create-user` instead of prompting. With `SAKSHYA_ADMIN_USERNAME` also set, the service creates this administrator at start whenever no users exist (for hosts without persistent storage). Demonstrations only. |
| `SAKSHYA_ADMIN_USERNAME` | empty | See `SAKSHYA_ADMIN_PASSWORD` |
| `SAKSHYA_DEMO_OPEN` | `false` | `true` lets visitors in without a password as a shared guest investigator. Synthetic demonstrations only. |
| `PORT` | `8000` | Port for `python -m sakshya serve` |

## Map

| Variable | Default | Meaning |
| --- | --- | --- |
| `SAKSHYA_MAP_TILE_DIR` | empty | Folder of `z/x/y.png` tiles served by Sakshya itself to signed-in users |
| `SAKSHYA_MAP_TILE_URL` | empty | Remote tile template such as `https://tiles.example.org/{z}/{x}/{y}.png`. Its origin is added to the content security policy and the workbench warns that this server sees which areas are viewed. |

With neither set, the map draws evidence points on a blank canvas and no location leaves the server.

## Limits

| Variable | Default | Meaning |
| --- | --- | --- |
| `SAKSHYA_MAX_UPLOAD_MB` | `25` | Largest upload accepted |
| `SAKSHYA_MAX_UNCOMPRESSED_MB` | `200` | Largest total size after extraction |
| `SAKSHYA_MAX_ARCHIVE_ENTRIES` | `400` | Most files in one archive |
| `SAKSHYA_MAX_COMPRESSION_RATIO` | `100` | Highest allowed ratio of extracted to compressed size for any entry |
| `SAKSHYA_USER_QUOTA_MB` | `1024` | Storage each user may fill with uploads |
| `SAKSHYA_USER_CASE_LIMIT` | `200` | Cases each user may upload |
| `SAKSHYA_WORKERS` | `2` | Analysis jobs that run at once |
| `SAKSHYA_JOB_TIMEOUT_S` | `600` | Longest an analysis or upload job may run |
| `SAKSHYA_SESSION_HOURS` | `8` | Absolute session lifetime |
| `SAKSHYA_IDLE_MINUTES` | `60` | Session expires after this long without a request |

## Rate limits

Each is `count/seconds`.

| Variable | Default | Counted per |
| --- | --- | --- |
| `SAKSHYA_RATE_LOGIN` | `10/300` | Client address, and separately address plus user name |
| `SAKSHYA_RATE_UPLOAD` | `10/3600` | User |
| `SAKSHYA_RATE_ANALYSIS` | `30/3600` | User |
| `SAKSHYA_RATE_REPORT` | `60/3600` | User |
| `SAKSHYA_RATE_EXPORT` | `60/3600` | User |
| `SAKSHYA_RATE_ACTION` | `240/3600` | User |
| `SAKSHYA_RATE_API` | `1200/60` | Client address, all API requests |

## Analysis settings

Model settings such as link thresholds, caps per source group, clock correction limits, the freeze latency and the forecast model are in `sakshya/config/settings.yaml`. Their digest is part of every analysis cache key, so a change re-runs analyses and is visible in each analysis version.
