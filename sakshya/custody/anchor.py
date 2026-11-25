from __future__ import annotations

import base64
import fcntl
import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from sakshya.core.hashing import canonical_json, sha256_bytes

_LOCK = threading.Lock()
KEY_FILE = "ledger_signing.key"


@dataclass
class Signer:
    private: Ed25519PrivateKey
    public: Ed25519PublicKey
    key_id: str

    @classmethod
    def load_or_create(cls, keys_dir: Path) -> Signer:
        keys_dir.mkdir(parents=True, exist_ok=True)
        path = keys_dir / KEY_FILE
        with _LOCK:
            if not path.exists():
                key = Ed25519PrivateKey.generate()
                pem = key.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
                )
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as handle:
                    handle.write(pem)
            private = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(private, Ed25519PrivateKey):
            raise ValueError("Ledger signing key is not an Ed25519 key")
        public = private.public_key()
        raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return cls(private, public, sha256_bytes(raw)[:16])

    def public_pem(self) -> str:
        return self.public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def sign(self, body: dict[str, Any]) -> str:
        return base64.b64encode(self.private.sign(canonical_json(body).encode("utf-8"))).decode("ascii")

    def verify(self, body: dict[str, Any], signature: str) -> bool:
        try:
            self.public.verify(base64.b64decode(signature), canonical_json(body).encode("utf-8"))
        except (InvalidSignature, ValueError):
            return False
        return True


class CheckpointStore:
    def __init__(self, anchors_dir: Path, signer: Signer, independent: bool) -> None:
        self.dir = anchors_dir
        self.signer = signer
        self.independent = independent
        self.dir.mkdir(parents=True, exist_ok=True)

    def path(self, scope: str) -> Path:
        return self.dir / f"{scope}.checkpoints.jsonl"

    def record(self, scope: str, seq: int, head: str) -> dict[str, Any]:
        body = {"scope": scope, "seq": seq, "head": head, "time": round(time.time(), 3), "key_id": self.signer.key_id}
        entry = {**body, "signature": self.signer.sign(body)}
        path = self.path(scope)
        with path.open("a", encoding="utf-8") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
            fcntl.flock(handle, fcntl.LOCK_UN)
        return entry

    def checkpoints(self, scope: str) -> list[dict[str, Any]]:
        path = self.path(scope)
        if not path.exists():
            return []
        items = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                items.append(json.loads(line))
        return items

    def check(self, scope: str, entries: list[dict[str, Any]]) -> dict[str, Any]:
        points = self.checkpoints(scope)
        issues: list[str] = []
        valid = 0
        last_seq = 0
        for point in points:
            body = {k: point.get(k) for k in ("scope", "seq", "head", "time", "key_id")}
            if point.get("key_id") != self.signer.key_id or not self.signer.verify(body, point.get("signature", "")):
                issues.append(f"Checkpoint for entry {point.get('seq')} has an invalid signature")
                continue
            seq = int(point["seq"])
            if seq > len(entries):
                issues.append(f"Ledger ends at entry {len(entries)} but a signed checkpoint covers entry {seq}")
                continue
            if entries[seq - 1].get("hash") != point["head"]:
                issues.append(f"Entry {seq} differs from the signed checkpoint")
                continue
            valid += 1
            last_seq = max(last_seq, seq)
        if entries and not points:
            issues.append("No signed checkpoint exists for this ledger")
        elif entries and last_seq < len(entries):
            issues.append(f"Entries after {last_seq} are not covered by a signed checkpoint")
        return {"checkpoints": len(points), "valid": valid, "covered_to": last_seq, "issues": issues}
