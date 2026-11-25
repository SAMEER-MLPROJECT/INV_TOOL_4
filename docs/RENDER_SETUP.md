# Render setup

This is the short path to a working hosted prototype on Render.

## Option A: Blueprint (recommended)

1. In Render choose **New**, then **Blueprint**, and select this repository. Render reads `render.yaml`.
2. Plan: **Starter** or higher. The blueprint attaches a 10 GB persistent disk at `/data`; disks are not available on the free plan.
3. After the first deploy, open **Environment** and copy `SAKSHYA_BOOTSTRAP_TOKEN` (Render generates it).
4. Open the service URL. The sign-in page offers **Create the first administrator**. Paste the token, choose a user name and a password of at least 12 characters.
5. Remove `SAKSHYA_BOOTSTRAP_TOKEN` and save. Render redeploys. Users, cases and ledgers stay on the disk.

## Option B: Web Service from the dashboard

| Setting | Value |
| --- | --- |
| Runtime / Language | Docker |
| Branch | `main` |
| Dockerfile path | `./Dockerfile` |
| Docker build context | `.` |
| Instance type | Starter (512 MB) or larger |
| Health check path | `/api/health/ready` |
| Disk | Name `sakshya-data`, mount path `/data`, 10 GB |
| Start command | Leave empty (the Dockerfile starts the server on `$PORT`) |
| Auto-deploy | Off, or on if you want each push deployed |

Then open **Environment**, choose **Add from .env**, and paste the contents of the supplied `render.env` file. Deploy, and follow steps 4 and 5 above.

## Variables

| Variable | Value | Why |
| --- | --- | --- |
| `SAKSHYA_ENV` | `production` | Turns on HSTS and hides the API documentation |
| `SAKSHYA_DATA_DIR` | `/data` | Where the persistent disk is mounted |
| `SAKSHYA_COOKIE_SECURE` | `true` | Render serves HTTPS |
| `SAKSHYA_TRUSTED_PROXIES` | `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10` | Render's proxies reach the container from private addresses; only these are believed for `X-Forwarded-For` |
| `SAKSHYA_BOOTSTRAP_TOKEN` | a long random value | Lets you create the first administrator from the browser; remove after use |
| `SAKSHYA_API_DOCS` | `false` | No public API explorer |
| `SAKSHYA_WORKERS` | `1` | One analysis at a time fits a 512 MB instance; use 2 on 1 GB or more |
| `SAKSHYA_JOB_TIMEOUT_S` | `900` | Generous time for the first analysis of the five demonstration cases on a small instance |

`PORT` is set by Render and must not be added.

## What to expect

* The first start copies the five demonstration cases into `/data` and analyses them in the background. Each case shows "Analysing" for a few seconds to a minute on a Starter instance.
* `/api/health/live` answers as soon as the process is up; `/api/health/ready` checks storage, databases, configuration and the signing key.
* With one disk, the custody ledger reports **local** anchoring. That is expected. See `docs/DEPLOYMENT_GUIDE.md` for independent anchoring.

## Open demonstration without a password

Set `SAKSHYA_DEMO_OPEN=true` and anyone who opens the address goes straight into the workbench as a shared guest account ("Demo visitor", role investigator). The guest can view every case, record decisions, upload cases and print reports, but cannot manage users or read the audit trail. Each guest sign-in is still written to the system ledger. A fresh random password is set for the guest account on every start and is never shown, so the account cannot be used except through the open demonstration route.

Use this only with the synthetic demonstration cases. Never enable it on a deployment that holds real case data.

## Free plan

The free plan has no disk and no shell. Every time the service sleeps (after about 15 minutes without visitors) or restarts, users, decisions and uploads are lost and the five demonstration cases are loaded again. To keep a fixed sign-in across restarts, set an administrator in the environment instead of the bootstrap token:

| Variable | Value |
| --- | --- |
| `SAKSHYA_ADMIN_USERNAME` | for example `admin` |
| `SAKSHYA_ADMIN_PASSWORD` | at least 12 characters |

On every start with no users, Sakshya creates this administrator and records it in the system ledger. Leave `SAKSHYA_BOOTSTRAP_TOKEN` unset. The first visit after a sleep takes up to a minute while the service wakes and re-analyses the demonstration cases.

Use these variables only for demonstrations. On a deployment with real case data, create the administrator once with the bootstrap token or `create-admin`, then remove both variables.
