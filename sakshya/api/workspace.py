from __future__ import annotations

import logging
import re
import shutil
import stat
import threading
import time
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from sakshya import __version__
from sakshya.core.hashing import dump_json, load_json, sha256_bytes, sha256_json
from sakshya.custody.anchor import CheckpointStore, Signer
from sakshya.custody.intake import ManifestError, digest_files, load_manifest
from sakshya.custody.ledger import Ledger
from sakshya.pipeline import Analysis, analyse, analysis_inputs, bundle, ledger_view, load_actions
from sakshya.reach.freeze import linked_cases
from sakshya.storage.artifacts import write_artifacts
from sakshya.storage.layout import STATE_NAMES, CasePaths, DataDir, protect_source

logger = logging.getLogger("sakshya.workspace")
CASE_ID = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
PACKAGE_DEMO = Path(__file__).resolve().parent.parent / "data" / "demo_cases"
ALLOWED_SUFFIXES = {
    ".csv",
    ".txt",
    ".eml",
    ".json",
    ".yaml",
    ".yml",
    ".png",
    ".jpg",
    ".jpeg",
    ".pcap",
    ".pcapng",
    ".db",
    ".sqlite",
    ".db-wal",
    ".sqlite-wal",
    ".wal",
    ".plist",
    ".html",
    ".htm",
    ".mp4",
    ".mov",
    ".avi",
    ".mkv",
    ".xml",
}
ACTION_TYPES = {"confirm_link", "reject_link", "forbid_merge", "revoke", "annotate"}
RESERVED = STATE_NAMES | {"truth.json"}


class WorkspaceError(Exception):
    public = True

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


class NotReady(WorkspaceError):
    def __init__(self, job_id: str | None) -> None:
        super().__init__("The analysis for this case is being prepared", 409)
        self.job_id = job_id


@dataclass
class UploadLimits:
    max_bytes: int
    max_uncompressed: int
    max_entries: int
    max_ratio: float
    max_depth: int


class Workspace:
    def __init__(self, data: DataDir | None = None) -> None:
        self.data = data or DataDir.from_env()
        self.notes = self.data.prepare()
        self.signer = Signer.load_or_create(self.data.keys)
        self.anchors = CheckpointStore(self.data.anchors, self.signer, self.data.independent_anchor)
        self.system = Ledger(self.data.root / "system_ledger.jsonl", "system", self.anchors)
        self._analyses: dict[str, Analysis] = {}
        self._bundles: dict[str, dict[str, Any]] = {}
        self._keys: dict[str, str] = {}
        self._locks: dict[str, threading.RLock] = {}
        self._guard = threading.Lock()
        for note in self.notes:
            self.system.append("storage_maintenance", {"note": note})

    @property
    def root(self) -> Path:
        return self.data.root

    def _lock(self, case_id: str) -> threading.RLock:
        with self._guard:
            return self._locks.setdefault(case_id, threading.RLock())

    def paths(self, case_id: str) -> CasePaths:
        if not isinstance(case_id, str) or not CASE_ID.match(case_id):
            raise WorkspaceError("Invalid case identifier", 400)
        paths = CasePaths((self.data.cases / case_id).resolve())
        if paths.root.parent != self.data.cases.resolve() or not paths.exists():
            raise WorkspaceError("Case not found", 404)
        return paths

    def ledger(self, case_id: str) -> Ledger:
        return Ledger(self.paths(case_id).ledger, case_id, self.anchors)

    def case_ids(self) -> list[str]:
        if not self.data.cases.exists():
            return []
        return sorted(
            p.name for p in self.data.cases.iterdir() if CASE_ID.match(p.name) and (p / "source" / "case.yaml").exists()
        )

    def seed_demo_cases(self) -> list[str]:
        added = []
        if not PACKAGE_DEMO.exists():
            return added
        for source in sorted(PACKAGE_DEMO.iterdir()):
            if not source.is_dir() or not CASE_ID.match(source.name):
                continue
            target = self.data.cases / source.name
            if target.exists():
                continue
            staging = self.data.staging / f"demo-{uuid.uuid4().hex}"
            shutil.copytree(source, staging / "source", ignore=shutil.ignore_patterns("truth.json"))
            (staging / "state").mkdir()
            protect_source(staging / "source")
            staging.rename(target)
            self.ledger(source.name).append("case_created", {"origin": "bundled demonstration case", "engine": __version__})
            added.append(source.name)
        return added

    def actions(self, case_id: str) -> list[dict[str, Any]]:
        return load_actions(self.paths(case_id).actions)

    def current_inputs(self, case_id: str) -> tuple[dict[str, Any], dict[str, str | None], dict[str, Any]]:
        paths = self.paths(case_id)
        manifest = load_manifest(paths.source)
        digests = digest_files(paths.source, manifest)
        inputs = analysis_inputs(manifest, digests, self.actions(case_id), None)
        return manifest, digests, inputs

    def freshness(self, case_id: str) -> dict[str, Any]:
        _, digests, inputs = self.current_inputs(case_id)
        key = sha256_json(inputs)
        analysis = self._analyses.get(case_id)
        changed = []
        if analysis is not None:
            previous = analysis.inputs.get("evidence", {})
            changed = sorted(f for f, d in digests.items() if previous.get(f) != d)
        return {
            "fresh": analysis is not None and self._keys.get(case_id) == key,
            "cache_key": key,
            "changed_files": changed,
            "evidence_modified": bool(changed),
            "checked_at": round(time.time(), 3),
        }

    def run_analysis(self, case_id: str, reason: str, actor: dict[str, Any] | None, control: Any = None) -> Analysis:
        with self._lock(case_id):
            paths = self.paths(case_id)
            _, digests, inputs = self.current_inputs(case_id)
            key = sha256_json(inputs)
            if self._keys.get(case_id) == key and case_id in self._analyses:
                return self._analyses[case_id]
            ledger = Ledger(paths.ledger, case_id, self.anchors)
            cancel = control.cancelled if control is not None else None
            analysis = analyse(paths.source, ledger=ledger, actions=self.actions(case_id), digests=digests, cancel=cancel)
            data = bundle(analysis)
            run = self._record_version(paths, analysis, data, reason, actor)
            data["run"] = run
            self._analyses[case_id] = analysis
            self._bundles[case_id] = data
            self._keys[case_id] = key
            return analysis

    def _record_version(
        self, paths: CasePaths, analysis: Analysis, data: dict[str, Any], reason: str, actor: dict[str, Any] | None
    ) -> dict[str, Any]:
        index_path = paths.runs / "index.json"
        index = load_json(index_path) if index_path.exists() else []
        latest = index[-1] if index else None
        if latest and latest["cache_key"] == analysis.cache_key:
            return latest
        run_id = f"R{len(index) + 1:04d}-{uuid.uuid4().hex[:6]}"
        directory = paths.runs / run_id
        previous = load_json(paths.runs / latest["run_id"] / "bundle.json") if latest else None
        changes = describe_changes(previous, data)
        artifacts = write_artifacts(directory / "artifacts", analysis, data)
        record = {
            "run_id": run_id,
            "time": round(time.time(), 3),
            "reason": reason,
            "actor": actor,
            "cache_key": analysis.cache_key,
            "result_digest": data["digest"],
            "inputs": analysis.inputs,
            "outcome": data["decision"].get("outcome"),
            "decision": data["decision"]["label"],
            "previous": latest["run_id"] if latest else None,
            "changes": changes,
            "artifacts": artifacts,
        }
        dump_json(directory / "bundle.json", data)
        dump_json(directory / "run.json", record)
        index.append({k: record[k] for k in ("run_id", "time", "reason", "cache_key", "result_digest", "outcome", "decision")})
        dump_json(index_path, index)
        Ledger(paths.ledger, paths.case_id, self.anchors).append(
            "analysis_version",
            {
                "run_id": run_id,
                "result_digest": data["digest"],
                "reason": reason,
                "actor": actor,
                "changes": changes[:20],
            },
        )
        return {k: record[k] for k in ("run_id", "time", "reason", "previous", "changes")}

    def runs(self, case_id: str) -> list[dict[str, Any]]:
        path = self.paths(case_id).runs / "index.json"
        return load_json(path) if path.exists() else []

    def run(self, case_id: str, run_id: str) -> dict[str, Any]:
        if not re.match(r"^R\d{4}-[0-9a-f]{6}$", run_id or ""):
            raise WorkspaceError("Invalid run identifier", 400)
        path = self.paths(case_id).runs / run_id / "run.json"
        if not path.exists():
            raise WorkspaceError("Run not found", 404)
        return load_json(path)

    def ready_analysis(self, case_id: str) -> Analysis:
        fresh = self.freshness(case_id)
        if not fresh["fresh"]:
            if fresh["evidence_modified"] and case_id in self._analyses:
                self._invalidate(case_id, fresh["changed_files"])
            raise NotReady(None)
        return self._analyses[case_id]

    def _invalidate(self, case_id: str, changed: list[str]) -> None:
        with self._lock(case_id):
            self._analyses.pop(case_id, None)
            self._bundles.pop(case_id, None)
            self._keys.pop(case_id, None)
            self.ledger(case_id).append("analysis_invalidated", {"reason": "evidence changed", "files": changed[:50]})

    def bundle(self, case_id: str) -> dict[str, Any]:
        analysis = self.ready_analysis(case_id)
        data = dict(self._bundles[case_id])
        data["evidence"] = {**data["evidence"], **ledger_view(self.ledger(case_id))}
        data["freshness"] = self.freshness(case_id)
        data["analysis_cache_key"] = analysis.cache_key
        return data

    def summary(self, case_id: str) -> dict[str, Any]:
        try:
            paths = self.paths(case_id)
            manifest = load_manifest(paths.source)
        except (ManifestError, WorkspaceError) as exc:
            return {"id": case_id, "title": case_id, "error": str(exc), "state": "invalid"}
        data = self._bundles.get(case_id)
        fresh = self._keys.get(case_id) is not None
        item = {
            "id": case_id,
            "title": str(manifest.get("title") or case_id),
            "state": "ready" if fresh else "pending",
        }
        if data:
            item.update(
                {
                    "decision": data["decision"]["label"],
                    "outcome": data["decision"].get("outcome"),
                    "decision_title": data["decision"]["title"],
                    "score": data["decision"]["score"],
                    "evidence": data["counts"]["evidence"],
                    "observations": data["counts"]["observations"],
                    "complaint_time": data["case"]["complaint_time"],
                }
            )
        return item

    def _interest_entities(self, case_id: str) -> set[str]:
        data = self._bundles.get(case_id)
        if not data:
            return set()
        entities = set()
        for person in data["people"]:
            if person["is_seed"]:
                continue
            for member in person["members"]:
                if member["kind"] in {"phone", "account", "upi", "imei", "email", "cloud"}:
                    entities.add(member["entity"])
        return entities

    def linked(self, case_id: str, allowed: set[str]) -> dict[str, Any]:
        index: dict[str, set[str]] = {}
        for other in list(self._bundles):
            for entity in self._interest_entities(other):
                index.setdefault(entity, set()).add(other)
        found = linked_cases(case_id, self._interest_entities(case_id), index)
        visible = [item for item in found if item["case_id"] in allowed]
        hidden = len(found) - len(visible)
        return {"cases": visible, "restricted": hidden}

    def validate_action(self, case_id: str, kind: str, target: Any) -> None:
        if kind not in ACTION_TYPES:
            raise WorkspaceError("Unknown action type", 422)
        analysis = self._analyses.get(case_id)
        if kind in {"confirm_link", "reject_link"}:
            if not isinstance(target, str) or analysis is None:
                raise WorkspaceError("Target must be a link identifier", 422)
            if not any(link.link_id == target for link in analysis.links):
                raise WorkspaceError("No such link in the current analysis", 422)
        elif kind == "forbid_merge":
            if not isinstance(target, list) or len(target) != 2 or not all(isinstance(t, str) for t in target):
                raise WorkspaceError("Target must be two identifiers", 422)
            if target[0] == target[1]:
                raise WorkspaceError("The two identifiers must differ", 422)
            if analysis is None or not all(t in analysis.facts.entities for t in target):
                raise WorkspaceError("Both identifiers must exist in this case", 422)
        elif kind == "annotate":
            if not isinstance(target, str) or analysis is None or target not in analysis.obs.index:
                raise WorkspaceError("Target must be an observation in this case", 422)
        elif kind == "revoke":
            if not isinstance(target, str) or not any(a.get("id") == target for a in self.actions(case_id)):
                raise WorkspaceError("No such action to revoke", 422)

    def act(
        self,
        case_id: str,
        kind: str,
        target: Any,
        reason: str,
        actor: dict[str, Any],
        origin: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        reason = (reason or "").strip()
        if len(reason) < 3:
            raise WorkspaceError("Give a short reason; it is recorded in the custody ledger", 422)
        paths = self.paths(case_id)
        with self._lock(case_id):
            self.ready_analysis(case_id)
            self.validate_action(case_id, kind, target)
            actions = self.actions(case_id)
            action_id = f"A-{uuid.uuid4().hex[:10]}"
            entry = {
                "id": action_id,
                "type": kind,
                "target": target,
                "reason": reason[:500],
                "actor": actor,
                "time": round(time.time(), 3),
            }
            if origin:
                entry["origin"] = origin
            if kind == "revoke":
                entry["revokes"] = target
            actions.append(entry)
            ledger = Ledger(paths.ledger, case_id, self.anchors)
            ledger.append(
                "investigator_action",
                {k: entry[k] for k in ("id", "type", "target", "reason", "actor", *(["origin"] if origin else []))},
            )
            dump_json(paths.actions, actions)
        return entry

    def import_decisions(self, case_id: str, items: list[dict[str, Any]], actor: dict[str, Any], source: str) -> list[str]:
        created = []
        digest = sha256_json(items)
        self.ledger(case_id).append(
            "decision_import", {"items": len(items), "sha256": digest, "source": source[:200], "actor": actor}
        )
        for position, item in enumerate(items, start=1):
            entry = self.act(
                case_id,
                item["type"],
                item["target"],
                item["reason"],
                actor,
                origin={"import_sha256": digest, "position": position, "source": source[:200]},
            )
            created.append(entry["id"])
        return created

    def record_report(self, case_id: str, html: str, actor: dict[str, Any]) -> str:
        digest = sha256_bytes(html.encode("utf-8"))
        self.ledger(case_id).append("report_export", {"sha256": digest, "format": "html", "actor": actor})
        return digest

    def record_access(self, case_id: str, actor: dict[str, Any], what: str) -> None:
        self.ledger(case_id).append("case_access", {"what": what, "actor": actor})

    def stage_upload(self, archive_path: Path, limits: UploadLimits) -> Path:
        staging = self.data.staging / uuid.uuid4().hex
        (staging / "source").mkdir(parents=True)
        try:
            extract_archive(archive_path, staging / "source", limits)
            if not (staging / "source" / "case.yaml").is_file():
                raise WorkspaceError("The archive has no case.yaml at its top level", 422)
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        return staging

    def commit_upload(self, staging: Path, actor: dict[str, Any], control: Any = None) -> str:
        try:
            source = staging / "source"
            try:
                manifest = load_manifest(source)
            except ManifestError as exc:
                raise WorkspaceError(str(exc), 422) from exc
            case_id = str(manifest["id"])
            if not CASE_ID.match(case_id):
                raise WorkspaceError("case.yaml 'id' may only use letters, digits, '-' and '_'", 422)
            if control is not None:
                control.check()
            probe = analyse(source, cancel=control.cancelled if control is not None else None)
            if not probe.coverage.get("records"):
                raise WorkspaceError(
                    "None of the evidence files produced a readable record; check the source types and column maps", 422
                )
            (staging / "state").mkdir(exist_ok=True)
            protect_source(source)
            final = self.data.cases / case_id
            with self._guard:
                if final.exists():
                    raise WorkspaceError(f"A case with id '{case_id}' already exists", 409)
                staging.rename(final)
            size = sum(p.stat().st_size for p in (final / "source").rglob("*") if p.is_file())
            self.ledger(case_id).append(
                "case_created", {"origin": "upload", "actor": actor, "bytes": size, "files": len(manifest["evidence"])}
            )
            return case_id
        finally:
            if staging.exists():
                shutil.rmtree(staging, ignore_errors=True)

    def evaluation(self) -> dict[str, Any] | None:
        path = Path(__file__).resolve().parent.parent / "data" / "evaluation" / "results.json"
        return load_json(path) if path.exists() else None


def describe_changes(previous: dict[str, Any] | None, current: dict[str, Any]) -> list[str]:
    if previous is None:
        return ["First analysis of this case"]
    changes = []
    before, after = previous["decision"], current["decision"]
    if before.get("outcome") != after.get("outcome") or before["label"] != after["label"]:
        changes.append(f"Outcome changed from {before['title']} to {after['title']}")
    elif abs(float(before.get("score", 0)) - float(after.get("score", 0))) >= 0.05:
        changes.append(f"Leading score changed from {before['score']:.2f} to {after['score']:.2f}")
    old = {h["id"]: (h["label"], round(h["score"], 2)) for h in previous.get("hypotheses", [])[:5]}
    new = {h["id"]: (h["label"], round(h["score"], 2)) for h in current.get("hypotheses", [])[:5]}
    for key in sorted(set(old) | set(new)):
        if old.get(key) != new.get(key):
            changes.append(
                f"{key}: {old.get(key, ('none', 0))[0]} {old.get(key, ('', 0))[1]} became "
                f"{new.get(key, ('none', 0))[0]} {new.get(key, ('', 0))[1]}"
            )
    status_before = {l["link_id"]: l["status"] for l in previous.get("links", [])}
    for link in current.get("links", []):
        if status_before.get(link["link_id"]) not in (None, link["status"]):
            changes.append(f"Link {link['link_id']} changed from {status_before[link['link_id']]} to {link['status']}")
    return changes or ["No change in findings"]


def extract_archive(archive_path: Path, target: Path, limits: UploadLimits) -> None:
    try:
        archive = zipfile.ZipFile(archive_path)
    except zipfile.BadZipFile as exc:
        raise WorkspaceError("Upload must be a .zip archive") from exc
    with archive:
        members = [m for m in archive.infolist() if not m.is_dir()]
        if not members:
            raise WorkspaceError("Archive is empty")
        if len(members) > limits.max_entries:
            raise WorkspaceError(f"Archive has more than {limits.max_entries} files", 413)
        total = sum(m.file_size for m in members)
        if total > limits.max_uncompressed:
            raise WorkspaceError("Archive expands beyond the allowed size", 413)
        prefix = _common_prefix([m.filename for m in members])
        seen: set[str] = set()
        root = target.resolve()
        for member in members:
            name = member.filename[len(prefix) :] if prefix else member.filename
            _check_member(member, name, limits)
            if name.lower() in seen:
                raise WorkspaceError("Archive contains duplicate file names")
            seen.add(name.lower())
            destination = (target / name).resolve()
            if root not in destination.parents:
                raise WorkspaceError("Archive contains an unsafe path")
            destination.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with archive.open(member) as source, destination.open("xb") as sink:
                while True:
                    block = source.read(1 << 16)
                    if not block:
                        break
                    written += len(block)
                    if written > member.file_size or written > limits.max_uncompressed:
                        raise WorkspaceError("Archive entry is larger than it declares", 413)
                    sink.write(block)


def _check_member(member: zipfile.ZipInfo, name: str, limits: UploadLimits) -> None:
    if not name or "\\" in member.filename or "\x00" in member.filename:
        raise WorkspaceError("Archive contains an unsafe path")
    path = PurePosixPath(name)
    if path.is_absolute() or name.startswith("/") or ".." in path.parts or ":" in path.parts[0]:
        raise WorkspaceError("Archive contains an unsafe path")
    if len(path.parts) > limits.max_depth:
        raise WorkspaceError("Archive folders are nested too deeply")
    if path.parts[0] in RESERVED or path.name in RESERVED:
        raise WorkspaceError(f"'{path.parts[0]}' is reserved for application state and cannot be uploaded")
    mode = member.external_attr >> 16
    if stat.S_ISLNK(mode):
        raise WorkspaceError("Archive contains a symbolic link")
    if mode & 0o111 and stat.S_ISREG(mode):
        raise WorkspaceError("Archive contains an executable file")
    suffix = path.suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise WorkspaceError(f"File type '{suffix or 'none'}' is not accepted")
    if member.compress_size and member.file_size / member.compress_size > limits.max_ratio:
        raise WorkspaceError("Archive entry is compressed suspiciously well", 413)
    if member.flag_bits & 0x1:
        raise WorkspaceError("Encrypted archive entries are not accepted")


def _common_prefix(names: list[str]) -> str:
    if any("/" not in n for n in names):
        return ""
    first = {n.split("/", 1)[0] for n in names}
    if len(first) == 1:
        root = next(iter(first)) + "/"
        if any(n == root + "case.yaml" for n in names):
            return root
    return ""
