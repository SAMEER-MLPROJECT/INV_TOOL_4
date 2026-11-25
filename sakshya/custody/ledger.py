from __future__ import annotations

import fcntl
import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sakshya.core.hashing import canonical_json, sha256_bytes
from sakshya.custody.anchor import CheckpointStore

GENESIS = "0" * 64
LEDGER_SCHEMA = 2
_LOCK = threading.Lock()


@dataclass
class LedgerCheck:
    ok: bool
    entries: int
    head: str
    broken_at: int | None
    message: str
    chain_ok: bool = True
    anchoring: str = "none"
    checkpoints: dict[str, Any] = field(default_factory=dict)
    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "chain_ok": self.chain_ok,
            "entries": self.entries,
            "head": self.head,
            "broken_at": self.broken_at,
            "message": self.message,
            "anchoring": self.anchoring,
            "checkpoints": self.checkpoints,
            "issues": self.issues,
        }


def entry_hash(entry: dict[str, Any]) -> str:
    body = {k: entry[k] for k in ("seq", "time", "type", "payload", "prev")}
    return sha256_bytes(canonical_json(body).encode("utf-8"))


class Ledger:
    def __init__(self, path: Path, scope: str | None = None, checkpoints: CheckpointStore | None = None) -> None:
        self.path = path
        self.scope = scope or path.parent.parent.name or "ledger"
        self.store = checkpoints

    def entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        items = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                items.append(json.loads(line))
        return items

    def head(self) -> str:
        items = self.entries()
        return items[-1]["hash"] if items else GENESIS

    def _write(self, handle: Any, items: list[dict[str, Any]], kind: str, payload: dict[str, Any], moment: float) -> dict:
        entry = {
            "seq": len(items) + 1,
            "time": round(moment, 3),
            "type": kind,
            "payload": json.loads(canonical_json(payload)),
            "prev": items[-1]["hash"] if items else GENESIS,
        }
        entry["hash"] = entry_hash(entry)
        handle.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
        items.append(entry)
        return entry

    def append(self, kind: str, payload: dict[str, Any], moment: float | None = None) -> dict[str, Any]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _LOCK, self.path.open("a+", encoding="utf-8") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                handle.seek(0)
                items = [json.loads(line) for line in handle.read().splitlines() if line.strip()]
                stamp = moment if moment is not None else time.time()
                if not items:
                    self._write(handle, items, "genesis", {"scope": self.scope, "schema": LEDGER_SCHEMA}, stamp)
                entry = self._write(handle, items, kind, payload, stamp)
                handle.flush()
                os.fsync(handle.fileno())
                if self.store is not None:
                    self.store.record(self.scope, entry["seq"], entry["hash"])
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)
        return entry

    def last(self, kind: str) -> dict[str, Any] | None:
        for entry in reversed(self.entries()):
            if entry["type"] == kind:
                return entry
        return None

    def verify(self) -> LedgerCheck:
        try:
            items = self.entries()
        except (OSError, json.JSONDecodeError) as exc:
            return LedgerCheck(False, 0, GENESIS, 1, f"The ledger could not be read: {exc}", chain_ok=False)
        check = self._verify_chain(items)
        if self.store is None:
            check.anchoring = "none"
            if check.chain_ok:
                check.message += ". No signed checkpoints are configured, so a rewritten chain would not be detected"
            return check
        anchor = self.store.check(self.scope, items)
        check.checkpoints = anchor
        check.issues.extend(anchor["issues"])
        check.anchoring = "independent" if self.store.independent else "local"
        if anchor["issues"]:
            check.ok = False
            check.message = anchor["issues"][0]
        elif check.chain_ok:
            check.message = "Every entry links to the one before it and matches a signed checkpoint held " + (
                "on separate storage" if self.store.independent else "on the same storage as the case"
            )
            if not self.store.independent:
                check.message += "; the chain is locally verified but not independently anchored"
        return check

    def _verify_chain(self, items: list[dict[str, Any]]) -> LedgerCheck:
        prev = GENESIS
        seen: set[str] = set()
        issues: list[str] = []
        for index, entry in enumerate(items, start=1):
            problem = None
            if entry.get("seq") != index:
                problem = f"Entry {index} is out of sequence"
            elif entry.get("prev") != prev:
                problem = f"Entry {index} does not point to the previous entry"
            elif entry_hash(entry) != entry.get("hash"):
                problem = f"Entry {index} was altered after it was written"
            elif entry["hash"] in seen:
                problem = f"Entry {index} duplicates an earlier entry"
            if problem:
                return LedgerCheck(False, len(items), prev, index, problem, chain_ok=False, issues=[problem])
            seen.add(entry["hash"])
            prev = entry["hash"]
        if items and items[0].get("type") != "genesis":
            issues.append("The ledger has no genesis entry; it was created by an earlier version")
        return LedgerCheck(True, len(items), prev, None, "Every entry links to the one before it", issues=issues)
