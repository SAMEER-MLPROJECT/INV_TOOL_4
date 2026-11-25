# Deployment guide

Sakshya runs in two modes. Both use the same code; they differ in settings and in where data is kept.

| | Local workstation | Hosted |
| --- | --- | --- |
| Who uses it | One analyst on their own machine | A team over the network |
| Address | `http://127.0.0.1:8000` | Your HTTPS address |
| `SAKSHYA_ENV` | `local` | `production` |
| Cookies | `SAKSHYA_COOKIE_SECURE=false` is acceptable on 127.0.0.1 | `true` (the default) |
| First user | `python -m sakshya create-admin` | Bootstrap token, or `create-admin` in a shell on the host |
| Storage | A folder on an encrypted disk | A persistent volume |
| Checkpoints | Optionally on a second drive | On separate storage where the platform allows |

## Requirements

Python 3.12 or 3.13 on Linux or macOS, or Docker. About 1 GB of memory per worker for large cases. No system packages are needed: PyAV ships its own FFmpeg libraries and scapy reads capture files without libpcap.

## Local workstation

```bash
python -m venv .venv
source .venv/bin/activate
pip install --require-hashes -r requirements.lock
export SAKSHYA_DATA_DIR="$HOME/sakshya-data"
export SAKSHYA_COOKIE_SECURE=false
python -m sakshya create-admin --username analyst
python -m sakshya serve
```

Open http://127.0.0.1:8000 and sign in. The server listens on 127.0.0.1 only unless `--host` is given. The five demonstration cases are copied into the data folder on first start and analysed in the background.

To keep checkpoints off the data drive, set `SAKSHYA_KEY_DIR` and `SAKSHYA_ANCHOR_DIR` to folders on another drive before the first start. The case ledgers then report "independent" anchoring.

Analysing a case folder without the web server:

```bash
python -m sakshya analyse path/to/CASE-FOLDER --state path/to/output
python -m sakshya analyse path/to/CASE-FOLDER --state path/to/output --as-of 1790500000
```

State is written next to the case folder (or to `--state`), never inside it.

## Hosted on Render

The repository has a `render.yaml` blueprint that builds the Docker image, mounts a 10 GB persistent disk at `/data` and generates a bootstrap token.

1. Push the repository to GitHub or GitLab.
2. In Render choose New, then Blueprint, and pick the repository. The blueprint uses the Starter plan because persistent disks are not available on the free plan.
3. When the service is live, open Environment in the Render dashboard and copy `SAKSHYA_BOOTSTRAP_TOKEN`.
4. Open the service address. The sign-in page offers to create the first administrator with that token.
5. Remove `SAKSHYA_BOOTSTRAP_TOKEN` from the environment and redeploy. Bootstrap is refused once any user exists, but removing the token closes it completely.
6. Create accounts for the team under Administration and grant each person the cases they work on.

Render's proxies connect from private addresses, so the blueprint sets `SAKSHYA_TRUSTED_PROXIES=10.0.0.0/8`. Change it if your platform uses a different range. Never set it to `0.0.0.0/0`.

A Render service has one disk, so the signing key and checkpoints share storage with the ledgers and the workbench reports "local" anchoring. To strengthen this, download `/api/cases/<id>/audit` on a schedule and keep the checkpoints elsewhere, or run on a host where `SAKSHYA_ANCHOR_DIR` can be a separate volume.

## Hosted with Docker

```bash
docker build -t sakshya .
docker volume create sakshya-data
docker run -d --name sakshya -p 127.0.0.1:8000:8000 \
  -v sakshya-data:/data \
  -e SAKSHYA_BOOTSTRAP_TOKEN="$(openssl rand -hex 24)" \
  sakshya
```

Put a TLS-terminating reverse proxy in front and set `SAKSHYA_TRUSTED_PROXIES` to its address. To keep checkpoints separate, mount a second volume and set `SAKSHYA_KEY_DIR=/keys` and `SAKSHYA_ANCHOR_DIR=/anchors`. The container runs as an unprivileged user and only needs write access to its volumes.

## Health checks

| Path | Meaning |
| --- | --- |
| `/api/health/live` | The process is running |
| `/api/health/ready` | Storage, databases, configuration, signing key and case folder all work; 503 otherwise |
| `/api/health` | Summary including anchoring mode and map mode |
| `/api/health/diagnostics` | Detailed checks, admin only |

## Upgrading

1. Back up (`python -m sakshya backup --out backup.tar.gz`).
2. Deploy the new version. On start the data layout is migrated if needed and the migration is written to the system ledger.
3. Run `python -m sakshya verify`. Cases are re-analysed on start; each new result is stored as a new analysis version next to the old ones.

## Supply chain

```bash
pip install -r requirements-dev.txt
pip-audit -r requirements.lock
cyclonedx-py requirements --of JSON --output-reproducible -o sbom.cdx.json requirements.lock
```

`requirements.txt` lists the direct dependencies with exact versions. `requirements.lock` pins every transitive dependency with hashes and is what the Docker image installs.

See [ENVIRONMENT.md](ENVIRONMENT.md) for every setting and [BACKUP_RESTORE.md](BACKUP_RESTORE.md) for backups.
