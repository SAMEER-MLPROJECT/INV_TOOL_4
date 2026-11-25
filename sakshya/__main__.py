from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import sys
from pathlib import Path

from sakshya.generator import DEMO_CASES, KINDS, CaseSpec, generate_case

PACKAGE_DEMO = Path(__file__).resolve().parent / "data" / "demo_cases"


def _generate_demo(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for spec in DEMO_CASES:
        path = generate_case(spec, out)
        print(f"generated {spec.case_id} ({spec.kind}) at {path}")


def _analyse(case_dir: Path, state: Path | None, as_of: float | None) -> None:
    from sakshya.custody.anchor import CheckpointStore, Signer
    from sakshya.custody.ledger import Ledger
    from sakshya.pipeline import analyse, bundle, save_bundle

    state = state or case_dir.parent / f"{case_dir.name}.state"
    state.mkdir(parents=True, exist_ok=True)
    signer = Signer.load_or_create(state / "keys")
    ledger = Ledger(state / "ledger.jsonl", case_dir.name, CheckpointStore(state / "anchors", signer, False))
    data = bundle(analyse(case_dir, ledger=ledger, as_of=as_of))
    path = save_bundle(state, data)
    decision = data["decision"]
    summary = {
        "case": data["case"]["id"],
        "outcome": decision.get("outcome"),
        "decision": decision["label"],
        "score": decision["score"],
        "margin": decision["margin"],
        "bundle": str(path),
    }
    print(json.dumps(summary, indent=2))


def _password(prompt: str) -> str:
    value = os.environ.get("SAKSHYA_ADMIN_PASSWORD")
    if value:
        return value
    first = getpass.getpass(prompt)
    if first != getpass.getpass("Repeat password: "):
        raise SystemExit("Passwords do not match")
    return first


def _users(args: argparse.Namespace) -> None:
    from sakshya.api.auth import AuthError, AuthStore
    from sakshya.storage.layout import DataDir

    data = DataDir.from_env(args.data_dir)
    data.prepare()
    store = AuthStore(data.database)
    try:
        if args.command == "create-admin":
            user = store.bootstrap_admin(args.username, _password("Password for the administrator: "), args.name)
        elif args.command == "create-user":
            user = store.create_user(args.username, _password(f"Password for {args.username}: "), args.role, args.name)
        else:
            target = next((u for u in store.users() if u["username"] == args.username), None)
            if target is None:
                raise SystemExit(f"No user {args.username}")
            store.grant(args.case, target["id"], None)
            print(f"granted {args.username} access to {args.case}")
            return
    except AuthError as exc:
        raise SystemExit(str(exc)) from exc
    print(f"created {user.role} {user.username}")


def _storage(args: argparse.Namespace) -> None:
    from sakshya.storage import maintenance
    from sakshya.storage.layout import DataDir

    data = DataDir.from_env(args.data_dir)
    if args.command == "backup":
        report = maintenance.backup(data, args.out, include_keys=not args.exclude_keys)
    elif args.command == "restore":
        report = maintenance.restore(args.archive, data, force=args.force)
    else:
        report = maintenance.verify(data)
    print(json.dumps(report, indent=2, default=str))
    if isinstance(report, dict) and report.get("ok") is False:
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(prog="sakshya", description="Evidence correlation and crime reconstruction engine")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="run the web workbench")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    for name in ("create-admin", "create-user"):
        command = sub.add_parser(name, help=f"{name.replace('-', ' ')} (password from a prompt or SAKSHYA_ADMIN_PASSWORD)")
        command.add_argument("--username", required=True)
        command.add_argument("--name", default=None)
        command.add_argument("--data-dir", type=Path, default=None)
        if name == "create-user":
            command.add_argument("--role", required=True, choices=["admin", "investigator", "reviewer", "auditor"])
    grant = sub.add_parser("grant", help="give a user access to a case")
    grant.add_argument("--username", required=True)
    grant.add_argument("--case", required=True)
    grant.add_argument("--data-dir", type=Path, default=None)
    backup = sub.add_parser("backup", help="write a backup archive of the data directory")
    backup.add_argument("--out", type=Path, required=True)
    backup.add_argument("--exclude-keys", action="store_true")
    backup.add_argument("--data-dir", type=Path, default=None)
    restore = sub.add_parser("restore", help="restore a backup archive and verify it")
    restore.add_argument("archive", type=Path)
    restore.add_argument("--force", action="store_true")
    restore.add_argument("--data-dir", type=Path, default=None)
    verify = sub.add_parser("verify", help="verify evidence, ledgers, checkpoints, actions and analysis versions")
    verify.add_argument("--data-dir", type=Path, default=None)
    demo = sub.add_parser("demo", help="regenerate the bundled demonstration cases")
    demo.add_argument("--out", type=Path, default=PACKAGE_DEMO)
    gen = sub.add_parser("generate", help="generate one synthetic case with an answer key")
    gen.add_argument("kind", choices=KINDS)
    gen.add_argument("--seed", type=int, default=1)
    gen.add_argument("--scale", type=float, default=1.0)
    gen.add_argument("--id", default=None)
    gen.add_argument("--out", type=Path, default=Path("cases"))
    run = sub.add_parser("analyse", help="analyse a case folder; state is written next to it, never inside it")
    run.add_argument("case_dir", type=Path)
    run.add_argument("--state", type=Path, default=None)
    run.add_argument("--as-of", type=float, default=None, help="forecast cutoff as a Unix time")
    sub.add_parser("evaluate", help="run the evaluation suite (see python -m sakshya.evaluation.run --help)")
    args, rest = parser.parse_known_args()
    if args.command == "serve":
        import uvicorn

        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
        uvicorn.run(
            "sakshya.api.app:app",
            host=args.host,
            port=args.port,
            log_level="info",
            proxy_headers=False,
            access_log=False,
            server_header=False,
        )
    elif args.command in {"create-admin", "create-user", "grant"}:
        _users(args)
    elif args.command in {"backup", "restore", "verify"}:
        _storage(args)
    elif args.command == "demo":
        _generate_demo(args.out)
    elif args.command == "generate":
        case_id = args.id or f"CASE-{args.kind[:4].upper()}-{args.seed:04d}"
        path = generate_case(CaseSpec(case_id, args.kind, args.seed, args.scale), args.out)
        print(f"generated {case_id} at {path}")
    elif args.command == "analyse":
        _analyse(args.case_dir, args.state, args.as_of)
    elif args.command == "evaluate":
        from sakshya.evaluation.run import main as evaluate

        sys.argv = ["sakshya.evaluation.run", *rest]
        evaluate()


if __name__ == "__main__":
    main()
