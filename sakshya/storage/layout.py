from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from sakshya.core.hashing import atomic_write_bytes

SCHEMA_VERSION = 2
STATE_NAMES = {"actions.json", "ledger.jsonl", "analysis", "state", "runs", "_sakshya"}


@dataclass(frozen=True)
class DataDir:
    root: Path
    keys: Path
    anchors: Path

    @classmethod
    def from_env(cls, root: Path | None = None) -> DataDir:
        base = root or Path(os.environ.get("SAKSHYA_DATA_DIR") or os.environ.get("SAKSHYA_WORKSPACE") or "data")
        base = base.expanduser().resolve()
        keys = Path(os.environ.get("SAKSHYA_KEY_DIR") or base / "keys").expanduser().resolve()
        anchors = Path(os.environ.get("SAKSHYA_ANCHOR_DIR") or base / "anchors").expanduser().resolve()
        return cls(base, keys, anchors)

    @property
    def cases(self) -> Path:
        return self.root / "cases"

    @property
    def staging(self) -> Path:
        return self.root / "staging"

    @property
    def database(self) -> Path:
        return self.root / "sakshya.db"

    @property
    def independent_anchor(self) -> bool:
        return self.root not in self.anchors.parents and self.root not in self.keys.parents

    def prepare(self) -> list[str]:
        for path in (self.root, self.cases, self.staging, self.anchors):
            path.mkdir(parents=True, exist_ok=True)
        self.keys.mkdir(parents=True, exist_ok=True)
        os.chmod(self.keys, 0o700)
        notes = recover_staging(self)
        notes += migrate(self)
        return notes


@dataclass(frozen=True)
class CasePaths:
    root: Path

    @property
    def case_id(self) -> str:
        return self.root.name

    @property
    def source(self) -> Path:
        return self.root / "source"

    @property
    def state(self) -> Path:
        return self.root / "state"

    @property
    def ledger(self) -> Path:
        return self.state / "ledger.jsonl"

    @property
    def actions(self) -> Path:
        return self.state / "actions.json"

    @property
    def runs(self) -> Path:
        return self.state / "runs"

    def exists(self) -> bool:
        return (self.source / "case.yaml").exists()


def recover_staging(data: DataDir) -> list[str]:
    notes = []
    if not data.staging.exists():
        return notes
    for leftover in sorted(data.staging.iterdir()):
        shutil.rmtree(leftover, ignore_errors=True)
        notes.append(f"Removed interrupted upload {leftover.name}")
    return notes


def _version_file(data: DataDir) -> Path:
    return data.root / "SCHEMA_VERSION"


def schema_version(data: DataDir) -> int:
    path = _version_file(data)
    if not path.exists():
        return 1 if any(data.cases.glob("*/case.yaml")) else SCHEMA_VERSION
    return int(path.read_text(encoding="utf-8").strip() or "1")


def migrate(data: DataDir) -> list[str]:
    notes = []
    for legacy in sorted(data.cases.iterdir()) if data.cases.exists() else []:
        if legacy.is_dir() and ((legacy / "case.yaml").exists() or (legacy / ".source-migrating").exists()):
            notes.append(migrate_case_v1(legacy))
    atomic_write_bytes(_version_file(data), f"{SCHEMA_VERSION}\n".encode())
    return notes


def migrate_case_v1(case_root: Path) -> str:
    paths = CasePaths(case_root)
    source = case_root / ".source-migrating"
    source.mkdir(exist_ok=True)
    paths.state.mkdir(exist_ok=True)
    for item in sorted(case_root.iterdir()):
        if item.name in {".source-migrating", "state"}:
            continue
        if item.name in {"actions.json", "ledger.jsonl"}:
            shutil.move(str(item), str(paths.state / item.name))
        elif item.name == "analysis":
            shutil.rmtree(item)
        else:
            shutil.move(str(item), str(source / item.name))
    source.rename(paths.source)
    return f"Moved case {case_root.name} to the version {SCHEMA_VERSION} layout"


def protect_source(source: Path) -> None:
    for path in sorted(source.rglob("*")):
        if path.is_file():
            path.chmod(0o444)
