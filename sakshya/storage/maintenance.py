from __future__ import annotations

import io
import json
import shutil
import sqlite3
import tarfile
import time
from pathlib import Path
from typing import Any

from sakshya.core.hashing import load_json, same_digest, sha256_file
from sakshya.custody.anchor import CheckpointStore, Signer
from sakshya.custody.intake import load_manifest
from sakshya.custody.ledger import Ledger
from sakshya.pipeline import analysis_digest
from sakshya.storage.layout import CasePaths, DataDir

SKIP = {"staging"}


def backup(data: DataDir, out: Path, include_keys: bool = True) -> dict[str, Any]:
    out.parent.mkdir(parents=True, exist_ok=True)
    report = {"created": round(time.time(), 3), "root": str(data.root), "keys_included": include_keys, "files": 0}
    with tarfile.open(out, "w:gz") as archive:
        for path in sorted(data.root.rglob("*")):
            relative = path.relative_to(data.root)
            if relative.parts[0] in SKIP or path.is_dir() or path.suffix in {".db-wal", ".db-shm"}:
                continue
            if data.keys in path.parents and not include_keys:
                continue
            if path.suffix == ".db":
                archive.addfile(*_sqlite_member(path, f"data/{relative.as_posix()}"))
            else:
                archive.add(path, arcname=f"data/{relative.as_posix()}", recursive=False)
            report["files"] += 1
        if data.root not in data.keys.parents and include_keys and data.keys.exists():
            for path in sorted(data.keys.rglob("*")):
                if path.is_file():
                    archive.add(path, arcname=f"keys/{path.relative_to(data.keys).as_posix()}")
        if data.root not in data.anchors.parents and data.anchors.exists():
            for path in sorted(data.anchors.rglob("*")):
                if path.is_file():
                    archive.add(path, arcname=f"anchors/{path.relative_to(data.anchors).as_posix()}")
        payload = json.dumps(report, indent=2).encode()
        info = tarfile.TarInfo("BACKUP.json")
        info.size = len(payload)
        info.mtime = int(time.time())
        archive.addfile(info, io.BytesIO(payload))
    report["sha256"] = sha256_file(out)
    return report


def _sqlite_member(path: Path, name: str) -> tuple[tarfile.TarInfo, io.BytesIO]:
    source = sqlite3.connect(path)
    target = sqlite3.connect(":memory:")
    source.backup(target)
    source.close()
    payload = target.serialize()
    target.close()
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    info.mtime = int(time.time())
    return info, io.BytesIO(payload)


def restore(archive_path: Path, data: DataDir, force: bool = False) -> dict[str, Any]:
    if data.root.exists() and any(data.root.iterdir()) and not force:
        raise FileExistsError(f"{data.root} is not empty; restore into an empty directory or pass force")
    staging = data.root.parent / f".restore-{int(time.time())}"
    staging.mkdir(parents=True)
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            archive.extractall(staging, filter="data")
        if data.root.exists():
            shutil.rmtree(data.root)
        shutil.move(str(staging / "data"), str(data.root))
        for part, target in (("keys", data.keys), ("anchors", data.anchors)):
            if (staging / part).exists():
                target.mkdir(parents=True, exist_ok=True)
                for path in (staging / part).rglob("*"):
                    if path.is_file():
                        destination = target / path.relative_to(staging / part)
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(path, destination)
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    return verify(data)


def verify(data: DataDir) -> dict[str, Any]:
    signer = Signer.load_or_create(data.keys)
    store = CheckpointStore(data.anchors, signer, data.independent_anchor)
    results = []
    system = Ledger(data.root / "system_ledger.jsonl", "system", store).verify()
    for case_root in sorted(data.cases.iterdir()) if data.cases.exists() else []:
        if case_root.is_dir():
            results.append(verify_case(CasePaths(case_root), store))
    ok = system.ok and all(r["ok"] for r in results)
    return {"ok": ok, "system_ledger": system.to_dict(), "cases": results}


def verify_case(paths: CasePaths, store: CheckpointStore) -> dict[str, Any]:
    issues: list[str] = []
    ledger = Ledger(paths.ledger, paths.case_id, store)
    check = ledger.verify()
    issues += [check.message] if not check.ok else []
    entries = ledger.entries()
    try:
        manifest = load_manifest(paths.source)
    except Exception as exc:
        return {"case_id": paths.case_id, "ok": False, "issues": [f"Manifest: {exc}"], "ledger": check.to_dict()}
    intake = {e["payload"]["file"]: e["payload"]["sha256"] for e in entries if e["type"] == "intake"}
    for item in manifest["evidence"]:
        expected = intake.get(item["file"])
        path = paths.source / item["file"]
        if expected is None:
            issues.append(f"{item['file']} has no intake entry in the ledger")
        elif not path.exists() or not same_digest(sha256_file(path), expected):
            issues.append(f"{item['file']} differs from its intake hash")
    logged = {e["payload"].get("id") for e in entries if e["type"] == "investigator_action"}
    actions = load_json(paths.actions) if paths.actions.exists() else []
    for action in actions:
        if action.get("id") not in logged:
            issues.append(f"Action {action.get('id')} has no ledger entry")
    runs = load_json(paths.runs / "index.json") if (paths.runs / "index.json").exists() else []
    for run in runs:
        bundle_path = paths.runs / run["run_id"] / "bundle.json"
        if not bundle_path.exists():
            issues.append(f"Run {run['run_id']} is missing its bundle")
            continue
        if analysis_digest(load_json(bundle_path)) != run["result_digest"]:
            issues.append(f"Run {run['run_id']} bundle does not match its recorded digest")
    return {"case_id": paths.case_id, "ok": not issues, "issues": issues, "ledger": check.to_dict(), "runs": len(runs)}
