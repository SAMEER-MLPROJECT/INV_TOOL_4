from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from sakshya.core.config import colmap, source_types
from sakshya.core.hashing import is_sha256, same_digest, sha256_file
from sakshya.custody.ledger import Ledger
from sakshya.storage.layout import STATE_NAMES

VERIFIED = "VERIFIED"
MISMATCH = "MISMATCH"
MISSING_REFERENCE_HASH = "MISSING_REFERENCE_HASH"
INVALID_REFERENCE_HASH = "INVALID_REFERENCE_HASH"
UNREADABLE = "UNREADABLE"
NOT_VERIFIABLE = "NOT_VERIFIABLE"
NOT_CHECKED = "NOT_CHECKED"
HASH_STATES = (VERIFIED, MISMATCH, MISSING_REFERENCE_HASH, INVALID_REFERENCE_HASH, UNREADABLE, NOT_VERIFIABLE, NOT_CHECKED)
MAX_MANIFEST_BYTES = 512 * 1024
MANIFEST_KEYS = {"id", "title", "seed", "evidence", "schema", "acquisition", "notes", "complaint_time"}
ENTRY_KEYS = {
    "file",
    "source",
    "sha256",
    "account",
    "owner",
    "owner_name",
    "other",
    "atm_id",
    "clock_domain",
    "colmap",
    "camera",
    "lat",
    "lon",
    "acquired",
    "acquired_by",
    "dependence_group",
    "platform",
    "timezone",
    "recording_start",
    "wal_file",
    "notes",
}


class ManifestError(ValueError):
    pass


@dataclass
class Verification:
    status: str = NOT_CHECKED
    algorithm: str = "sha256"
    reference: str | None = None
    reference_source: str | None = None
    checked_at: float | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Evidence:
    evidence_id: str
    file: str
    source: str
    label: str
    sha256: str
    size: int
    entry: dict[str, Any]
    declared_sha256: str | None = None
    integrity: list[dict[str, str]] = field(default_factory=list)
    verification: Verification = field(default_factory=Verification)
    custody: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["entry"] = {k: v for k, v in self.entry.items() if k not in {"file", "source"}}
        data["verification"] = self.verification.to_dict()
        return data


def _fail(message: str) -> None:
    raise ManifestError(message)


def load_manifest(case_dir: Path) -> dict[str, Any]:
    path = case_dir / "case.yaml"
    if not path.exists():
        _fail("case.yaml is missing")
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        _fail("case.yaml is larger than 512 KB")
    try:
        manifest = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        raise ManifestError(f"case.yaml is not valid YAML: {exc}") from exc
    validate_manifest(manifest, case_dir)
    return manifest


def validate_manifest(manifest: Any, case_dir: Path) -> None:
    if not isinstance(manifest, dict):
        _fail("case.yaml must be a mapping")
    unknown = set(manifest) - MANIFEST_KEYS
    if unknown:
        _fail(f"case.yaml has unknown keys: {', '.join(sorted(map(str, unknown)))}")
    for key in ("id", "evidence"):
        if key not in manifest:
            _fail(f"case.yaml has no '{key}'")
    if not isinstance(manifest["id"], (str, int)):
        _fail("case.yaml 'id' must be text")
    if manifest.get("title") is not None and not isinstance(manifest["title"], str):
        _fail("case.yaml 'title' must be text")
    seed = manifest.get("seed") or {}
    if not isinstance(seed, dict) or not isinstance(seed.get("identifiers", []), list):
        _fail("case.yaml 'seed' must be a mapping with an 'identifiers' list")
    for item in seed.get("identifiers", []):
        if not isinstance(item, dict) or not isinstance(item.get("type"), str) or item.get("value") in (None, ""):
            _fail("Each seed identifier needs a 'type' and a 'value'")
    evidence = manifest["evidence"]
    if not isinstance(evidence, list):
        _fail("case.yaml 'evidence' must be a list")
    known = set(source_types())
    seen: set[str] = set()
    root = case_dir.resolve()
    for item in evidence:
        if not isinstance(item, dict):
            _fail("Each evidence entry must be a mapping")
        if not isinstance(item.get("file"), str) or not isinstance(item.get("source"), str):
            _fail("Each evidence entry needs 'file' and 'source' as text")
        extra = set(item) - ENTRY_KEYS
        if extra:
            _fail(f"Evidence entry '{item['file']}' has unknown keys: {', '.join(sorted(map(str, extra)))}")
        if item["source"] not in known:
            _fail(f"Unknown source type '{item['source']}'")
        if item["file"] in seen:
            _fail(f"Evidence file '{item['file']}' is listed twice")
        seen.add(item["file"])
        relative = Path(item["file"])
        if relative.is_absolute() or ".." in relative.parts:
            _fail(f"Evidence path '{item['file']}' is outside the case folder")
        if relative.parts and relative.parts[0] in STATE_NAMES:
            _fail(f"Evidence path '{item['file']}' uses a name reserved for application state")
        resolved = (case_dir / relative).resolve()
        if root not in resolved.parents:
            _fail(f"Evidence path '{item['file']}' is outside the case folder")
        if not resolved.is_file():
            _fail(f"Evidence file '{item['file']}' was not found")
        if "sha256" in item and item["sha256"] is not None and not isinstance(item["sha256"], str):
            _fail(f"Evidence entry '{item['file']}' has a sha256 that is not text")
        override = item.get("colmap")
        if override is not None:
            _validate_colmap(item["file"], override)
    listed = {item["file"]: item["source"] for item in evidence}
    for item in evidence:
        wal = item.get("wal_file")
        if wal is not None and (not isinstance(wal, str) or listed.get(wal) != "sqlite_wal"):
            _fail(f"wal_file of '{item['file']}' must name another evidence entry with source sqlite_wal")


TIME_UNITS = ("text", "unix_s", "unix_ms", "apple_s", "apple_ns", "chrome_us")


def _validate_colmap(name: str, override: Any) -> None:
    if not isinstance(override, dict):
        _fail(f"colmap for '{name}' must be a mapping")
    allowed = {
        "columns",
        "time_format",
        "timezone",
        "sigma_s",
        "delimiter",
        "encoding",
        "records",
        "fields",
        "time_unit",
        "kind",
        "party_kind",
        "account_path",
        "table",
        "platform",
        "scene_threshold",
        "max_frames",
    }
    extra = set(override) - allowed
    if extra:
        _fail(f"colmap for '{name}' has unknown keys: {', '.join(sorted(map(str, extra)))}")
    columns = override.get("columns", {})
    if not isinstance(columns, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in columns.items()):
        _fail(f"colmap columns for '{name}' must map names to column headers")
    fmt = override.get("time_format")
    if fmt is not None and (not isinstance(fmt, str) or "%" not in fmt):
        _fail(f"colmap time_format for '{name}' must be a strptime format")
    if "sigma_s" in override and not isinstance(override["sigma_s"], (int, float)):
        _fail(f"colmap sigma_s for '{name}' must be a number")
    if "timezone" in override and not isinstance(override["timezone"], str):
        _fail(f"colmap timezone for '{name}' must be text")
    fields = override.get("fields", {})
    if not isinstance(fields, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in fields.items()):
        _fail(f"colmap fields for '{name}' must map names to field paths")
    if "time_unit" in override and override["time_unit"] not in TIME_UNITS:
        _fail(f"colmap time_unit for '{name}' must be one of {', '.join(TIME_UNITS)}")
    if "delimiter" in override and (not isinstance(override["delimiter"], str) or len(override["delimiter"]) != 1):
        _fail(f"colmap delimiter for '{name}' must be one character")


def verify_reference(actual: str | None, reference: Any, source: str | None, now: float) -> Verification:
    if actual is None:
        return Verification(UNREADABLE, reference_source=source, checked_at=now, detail="The file could not be read")
    if reference is None:
        if source is None:
            return Verification(
                NOT_VERIFIABLE, checked_at=now, detail="No acquisition hash was supplied, so the file cannot be verified"
            )
        return Verification(
            MISSING_REFERENCE_HASH,
            reference_source=source,
            checked_at=now,
            detail="A reference hash was expected from the source but none was supplied",
        )
    text = str(reference).strip()
    if not text:
        return Verification(MISSING_REFERENCE_HASH, reference_source=source, checked_at=now, detail="The reference hash is empty")
    if not is_sha256(text):
        return Verification(
            INVALID_REFERENCE_HASH,
            reference=text[:80],
            reference_source=source,
            checked_at=now,
            detail="The reference is not a SHA-256 digest",
        )
    if same_digest(actual, text):
        return Verification(
            VERIFIED,
            reference=text.lower(),
            reference_source=source,
            checked_at=now,
            detail="Matches the reference hash",
        )
    return Verification(
        MISMATCH,
        reference=text.lower(),
        reference_source=source,
        checked_at=now,
        detail="Differs from the reference hash",
    )


def digest_files(case_dir: Path, manifest: dict[str, Any]) -> dict[str, str | None]:
    digests: dict[str, str | None] = {}
    for item in manifest["evidence"]:
        try:
            digests[item["file"]] = sha256_file(case_dir / item["file"])
        except OSError:
            digests[item["file"]] = None
    return digests


def register_evidence(
    case_dir: Path, manifest: dict[str, Any], ledger: Ledger | None, digests: dict[str, str | None] | None = None
) -> list[Evidence]:
    entries = ledger.entries() if ledger is not None else []
    known = {e["payload"]["file"]: e["payload"]["sha256"] for e in entries if e["type"] == "intake"}
    latest = dict(known)
    for entry in entries:
        if entry["type"] == "intake_changed":
            latest[entry["payload"]["file"]] = entry["payload"]["sha256"]
    digests = digests or digest_files(case_dir, manifest)
    now = round(time.time(), 3)
    items: list[Evidence] = []
    for index, item in enumerate(manifest["evidence"], start=1):
        path = case_dir / item["file"]
        digest = digests.get(item["file"])
        size = path.stat().st_size if path.exists() else 0
        source = "manifest" if "sha256" in item else None
        evidence = Evidence(
            evidence_id=f"E{index:02d}",
            file=item["file"],
            source=item["source"],
            label=colmap(item["source"]).get("label", item["source"]),
            sha256=digest or "",
            size=size,
            entry=dict(item),
            declared_sha256=item.get("sha256"),
            verification=verify_reference(digest, item.get("sha256"), source, now),
        )
        if evidence.verification.status == MISMATCH:
            evidence.integrity.append({"level": "critical", "message": "File hash differs from the acquisition hash"})
        elif evidence.verification.status in {INVALID_REFERENCE_HASH, UNREADABLE}:
            evidence.integrity.append({"level": "critical", "message": evidence.verification.detail})
        first = known.get(item["file"])
        if first is None:
            evidence.custody = {"status": "registered_now", "intake_sha256": digest}
            if ledger is not None and digest is not None:
                ledger.append(
                    "intake",
                    {
                        "evidence_id": evidence.evidence_id,
                        "file": item["file"],
                        "source": item["source"],
                        "sha256": digest,
                        "size": size,
                        "verification": evidence.verification.status,
                    },
                )
        elif digest is not None and same_digest(first, digest):
            evidence.custody = {"status": "unchanged_since_intake", "intake_sha256": first}
        else:
            evidence.custody = {"status": "changed_since_intake", "intake_sha256": first}
            evidence.integrity.append(
                {"level": "critical", "message": "File changed after it was first registered in the ledger"}
            )
            if ledger is not None and latest.get(item["file"]) != digest:
                ledger.append(
                    "intake_changed",
                    {
                        "evidence_id": evidence.evidence_id,
                        "file": item["file"],
                        "previous_sha256": latest.get(item["file"]),
                        "sha256": digest,
                    },
                )
        items.append(evidence)
    return items


def check_media(evidence: list[Evidence], frame_hashes: dict[str, tuple[str, str]]) -> list[dict[str, Any]]:
    findings = []
    by_file = {item.file: item for item in evidence}
    now = round(time.time(), 3)
    for frame_file, (declared, log_evidence) in sorted(frame_hashes.items()):
        candidate = by_file.get(f"evidence/{frame_file}") or by_file.get(frame_file)
        if candidate is None:
            findings.append(
                {
                    "file": frame_file,
                    "status": NOT_CHECKED,
                    "log": log_evidence,
                    "message": "Frame listed in the recorder log was not supplied",
                }
            )
            continue
        result = verify_reference(candidate.sha256 or None, declared or None, "recorder_log", now)
        if result.status == VERIFIED:
            message = "Frame matches the recorder export log"
        elif result.status == MISMATCH:
            message = "Frame differs from the recorder export log; it was altered after export or the log is wrong"
            candidate.integrity.append(
                {"level": "critical", "message": f"Hash does not match the recorder export log ({log_evidence})"}
            )
        else:
            message = result.detail
        if candidate.verification.status in {NOT_VERIFIABLE, NOT_CHECKED} or result.status == MISMATCH:
            candidate.verification = result
        findings.append(
            {
                "file": candidate.file,
                "status": result.status,
                "log": log_evidence,
                "evidence_id": candidate.evidence_id,
                "expected": result.reference,
                "actual": candidate.sha256,
                "message": message,
            }
        )
    return findings
