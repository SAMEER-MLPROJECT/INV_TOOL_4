from __future__ import annotations

import json
from pathlib import Path

import pytest

from sakshya.custody.anchor import CheckpointStore, Signer
from sakshya.custody.intake import (
    INVALID_REFERENCE_HASH,
    MISMATCH,
    MISSING_REFERENCE_HASH,
    NOT_VERIFIABLE,
    UNREADABLE,
    VERIFIED,
    ManifestError,
    load_manifest,
    verify_reference,
)
from sakshya.custody.ledger import Ledger

DIGEST = "ab" * 32


def _anchored(tmp_path: Path, independent: bool = True) -> Ledger:
    signer = Signer.load_or_create(tmp_path / "keys")
    return Ledger(tmp_path / "case" / "ledger.jsonl", "CASE-T", CheckpointStore(tmp_path / "anchors", signer, independent))


def test_chain_starts_with_genesis_and_verifies(tmp_path: Path) -> None:
    ledger = _anchored(tmp_path)
    for index in range(4):
        ledger.append("note", {"index": index}, moment=1000.0 + index)
    entries = ledger.entries()
    assert entries[0]["type"] == "genesis" and entries[0]["payload"]["scope"] == "CASE-T"
    check = ledger.verify()
    assert check.ok and check.entries == 5 and check.anchoring == "independent"
    assert not check.issues


def test_local_anchoring_is_reported_honestly(tmp_path: Path) -> None:
    ledger = _anchored(tmp_path, independent=False)
    ledger.append("note", {})
    check = ledger.verify()
    assert check.ok and check.anchoring == "local"
    assert "not independently anchored" in check.message


def test_unanchored_ledger_says_rewrites_would_go_unnoticed(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path / "ledger.jsonl", "CASE-T")
    ledger.append("note", {})
    check = ledger.verify()
    assert check.ok and check.anchoring == "none"
    assert "would not be detected" in check.message


def test_edited_entry_is_located(tmp_path: Path) -> None:
    ledger = _anchored(tmp_path)
    for index in range(4):
        ledger.append("note", {"index": index})
    lines = ledger.path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[2])
    entry["payload"]["index"] = 99
    lines[2] = json.dumps(entry, sort_keys=True)
    ledger.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    broken = ledger.verify()
    assert not broken.ok and broken.broken_at == 3


def test_checkpoint_with_forged_signature_is_rejected(tmp_path: Path) -> None:
    ledger = _anchored(tmp_path)
    ledger.append("note", {})
    files = list((tmp_path / "anchors").rglob("*.jsonl"))
    assert files
    lines = files[0].read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[-1])
    record["signature"] = record["signature"][::-1]
    lines[-1] = json.dumps(record)
    files[0].write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not ledger.verify().ok


def test_signing_key_is_private(tmp_path: Path) -> None:
    Signer.load_or_create(tmp_path / "keys")
    key = tmp_path / "keys" / "ledger_signing.key"
    assert key.stat().st_mode & 0o077 == 0


@pytest.mark.parametrize(
    "actual,reference,source,expected",
    [
        (DIGEST, DIGEST, "manifest", VERIFIED),
        (DIGEST, DIGEST.upper(), "manifest", VERIFIED),
        (DIGEST, "cd" * 32, "manifest", MISMATCH),
        (DIGEST, "not-a-hash", "manifest", INVALID_REFERENCE_HASH),
        (DIGEST, None, "manifest", MISSING_REFERENCE_HASH),
        (DIGEST, None, None, NOT_VERIFIABLE),
        (None, DIGEST, "manifest", UNREADABLE),
    ],
)
def test_hash_states(actual, reference, source, expected) -> None:
    assert verify_reference(actual, reference, source, 0.0).status == expected


def _write_case(root: Path, manifest: str, files: dict[str, str] | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "case.yaml").write_text(manifest, encoding="utf-8")
    for name, text in (files or {"a.csv": "x\n"}).items():
        (root / name).write_text(text, encoding="utf-8")
    return root


@pytest.mark.parametrize(
    "manifest,message",
    [
        ("id: X\nevidence:\n- file: ../a.csv\n  source: bank_statement\n", "outside"),
        ("id: X\nevidence:\n- file: /etc/passwd\n  source: bank_statement\n", "outside"),
        ("id: X\nevidence:\n- file: a.csv\n  source: no_such_type\n", "source"),
        ("id: X\nevidence:\n- file: a.csv\n  source: bank_statement\n  shell: rm\n", "unknown keys"),
        ("id: X\nevidence:\n- file: a.csv\n  source: bank_statement\n- file: a.csv\n  source: bank_statement\n", "twice"),
        ("id: X\nevidence:\n- file: state/a.csv\n  source: bank_statement\n", "reserved"),
        (
            "id: X\nevidence:\n- file: a.csv\n  source: bank_statement\n  colmap:\n    time_unit: weeks\n",
            "time_unit",
        ),
        ("id: X\nevil: true\nevidence: []\n", "unknown"),
    ],
)
def test_manifest_validation_rejects_unsafe_entries(tmp_path: Path, manifest: str, message: str) -> None:
    case = _write_case(tmp_path / "case", manifest)
    (case / "state").mkdir(exist_ok=True)
    (case / "state" / "a.csv").write_text("x\n", encoding="utf-8")
    with pytest.raises(ManifestError) as info:
        load_manifest(case)
    assert message in str(info.value).lower()
