from __future__ import annotations

import json
import shutil
import tarfile
from pathlib import Path

import pytest

from sakshya.api.workspace import Workspace, WorkspaceError
from sakshya.storage.layout import SCHEMA_VERSION, DataDir
from sakshya.storage.maintenance import backup, restore, verify

from .conftest import DEMO, DEMO_IDS

CASE = DEMO_IDS[-1]


def _workspace(root: Path, keys: Path | None = None, anchors: Path | None = None) -> Workspace:
    data = DataDir.from_env(root)
    if keys or anchors:
        data = DataDir(data.root, keys or data.keys, anchors or data.anchors)
    return Workspace(data)


def _seeded(root: Path, monkeypatch: pytest.MonkeyPatch, **dirs: Path) -> Workspace:
    demo = root.parent / f"{root.name}-demo"
    demo.mkdir(parents=True, exist_ok=True)
    if not (demo / CASE).exists():
        shutil.copytree(DEMO / CASE, demo / CASE)
    monkeypatch.setattr("sakshya.api.workspace.PACKAGE_DEMO", demo)
    workspace = _workspace(root, **dirs)
    workspace.seed_demo_cases()
    workspace.run_analysis(CASE, "test", None)
    return workspace


def test_layout_separates_evidence_from_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = _seeded(tmp_path / "data", monkeypatch)
    paths = workspace.paths(CASE)
    assert (paths.source / "case.yaml").exists()
    assert paths.ledger.parent == paths.state and paths.ledger.exists()
    assert not (paths.source / "truth.json").exists()
    assert (workspace.data.root / "SCHEMA_VERSION").read_text().strip() == str(SCHEMA_VERSION)
    runs = json.loads((paths.runs / "index.json").read_text())
    assert (paths.runs / runs[0]["run_id"] / "artifacts" / "manifest.json").exists()


def test_backup_restore_round_trip_verifies(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = _seeded(tmp_path / "data", monkeypatch)
    archive = tmp_path / "backup.tar.gz"
    report = backup(workspace.data, archive)
    assert report["files"] > 0 and len(report["sha256"]) == 64
    with tarfile.open(archive) as tar:
        names = tar.getnames()
    assert "BACKUP.json" in names and any(n.endswith("ledger.jsonl") for n in names)
    target = DataDir.from_env(tmp_path / "restored")
    result = restore(archive, target)
    assert result["ok"], result
    restored = Workspace(target)
    assert restored.case_ids() == [CASE]
    assert restored.ledger(CASE).verify().ok
    with pytest.raises(FileExistsError):
        restore(archive, target)


def test_verify_detects_changed_evidence_and_unlogged_actions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = _seeded(tmp_path / "data", monkeypatch)
    assert verify(workspace.data)["ok"]
    paths = workspace.paths(CASE)
    paths.actions.write_text(json.dumps([{"id": "A-forged", "type": "reject_link", "target": "x"}]), encoding="utf-8")
    report = verify(workspace.data)
    assert not report["ok"]
    assert any("A-forged" in issue for case in report["cases"] for issue in case["issues"])
    paths.actions.unlink()
    evidence = next(p for p in sorted(paths.source.rglob("*.csv")))
    evidence.chmod(0o644)
    evidence.write_text("changed\n", encoding="utf-8")
    report = verify(workspace.data)
    assert any("differs from its intake hash" in issue for case in report["cases"] for issue in case["issues"])


def test_checkpoints_on_separate_storage_are_reported_as_independent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = _seeded(tmp_path / "data", monkeypatch, keys=tmp_path / "keys", anchors=tmp_path / "anchors")
    assert workspace.data.independent_anchor
    check = workspace.ledger(CASE).verify()
    assert check.ok and check.anchoring == "independent"
    local = _seeded(tmp_path / "local", monkeypatch)
    assert local.ledger(CASE).verify().anchoring == "local"


def test_version_one_layout_is_migrated(tmp_path: Path) -> None:
    root = tmp_path / "data"
    legacy = root / "cases" / CASE
    shutil.copytree(DEMO / CASE, legacy)
    (legacy / "truth.json").unlink()
    (legacy / "actions.json").write_text("[]", encoding="utf-8")
    workspace = _workspace(root)
    paths = workspace.paths(CASE)
    assert (paths.source / "case.yaml").exists() and (paths.state / "actions.json").exists()
    assert not (legacy / "case.yaml").exists()
    assert any(e["type"] == "storage_maintenance" for e in workspace.system.entries())


def test_interrupted_uploads_are_cleaned_on_start(tmp_path: Path) -> None:
    root = tmp_path / "data"
    leftover = root / "staging" / "abc123" / "source"
    leftover.mkdir(parents=True)
    (leftover / "case.yaml").write_text("id: X\n", encoding="utf-8")
    workspace = _workspace(root)
    assert list(workspace.data.staging.iterdir()) == []


def test_cases_are_isolated_from_each_other(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    workspace = _seeded(tmp_path / "data", monkeypatch)
    other = DEMO_IDS[-2]
    shutil.copytree(DEMO / other, workspace.data.cases / other / "source", ignore=shutil.ignore_patterns("truth.json"))
    (workspace.data.cases / other / "state").mkdir()
    workspace.run_analysis(other, "test", None)
    first, second = workspace.ledger(CASE), workspace.ledger(other)
    assert first.path != second.path
    assert {c["scope"] for c in workspace.anchors.checkpoints(CASE)} == {CASE}
    second.path.write_text(second.path.read_text().replace('"genesis"', '"edited"', 1), encoding="utf-8")
    assert first.verify().ok and not second.verify().ok
    with pytest.raises(WorkspaceError):
        workspace.paths("../" + CASE)
