from __future__ import annotations

import csv
import io
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import tzinfo
from pathlib import Path
from typing import Any

from sakshya.core.identifiers import canonical
from sakshya.core.timeutil import parse_local, tz_from_spec

UPI_PATTERN = re.compile(r"\b[a-zA-Z0-9._\-]{2,64}@[a-zA-Z][a-zA-Z0-9.\-]{1,32}\b")
PHONE_PATTERN = re.compile(r"(?<!\d)(?:\+91[\s\-]?|0)?[6-9]\d{4}[\s\-]?\d{5}(?!\d)")
URL_PATTERN = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)
MAX_WARNINGS = 200
AMOUNT_PATTERN = re.compile(r"(?:Rs\.?|INR|₹)\s?([\d,]+(?:\.\d{1,2})?)", re.IGNORECASE)


@dataclass
class Record:
    row: int
    kind: str
    t_raw: float | None
    raw: str
    ids: list[tuple[str, str, str]] = field(default_factory=list)
    sigma_t: float | None = None
    lat: float | None = None
    lon: float | None = None
    radius_m: float | None = None
    place: str = ""
    amount: float | None = None
    direction: str = ""
    duration_s: float | None = None
    text: str = ""
    anchors: list[str] = field(default_factory=list)
    attrs: dict[str, Any] = field(default_factory=dict)

    def add_id(self, role: str, kind: str, value: Any) -> None:
        identifier = canonical(kind, value)
        if identifier is not None:
            self.ids.append((role, identifier.kind, identifier.value))


@dataclass
class ParseResult:
    records: list[Record] = field(default_factory=list)
    towers: dict[str, dict[str, Any]] = field(default_factory=dict)
    atms: dict[str, dict[str, Any]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class AdapterContext:
    path: Path
    evidence_id: str
    entry: dict[str, Any]
    colmap: dict[str, Any]
    warnings: list[str] = field(default_factory=list)
    quarantined: int = 0
    case_dir: Path | None = None

    def warn(self, message: str) -> None:
        if len(self.warnings) < MAX_WARNINGS:
            self.warnings.append(message)
        elif len(self.warnings) == MAX_WARNINGS:
            self.warnings.append("Further warnings were suppressed")

    def quarantine(self, line_no: int, reason: str) -> None:
        self.quarantined += 1
        self.warn(f"line {line_no}: quarantined, {reason}")

    def read_text(self) -> str:
        encoding = str(self.colmap.get("encoding") or "utf-8-sig")
        data = self.path.read_bytes()
        try:
            return data.decode(encoding)
        except UnicodeDecodeError as exc:
            self.warn(f"File is not valid {encoding} at byte {exc.start}; undecodable bytes were replaced")
            return data.decode(encoding, errors="replace")

    @property
    def tz(self) -> tzinfo:
        return tz_from_spec(self.entry.get("timezone") or self.colmap.get("timezone"))

    @property
    def time_format(self) -> str | None:
        return self.colmap.get("time_format")

    def column(self, name: str) -> str | None:
        return self.colmap.get("columns", {}).get(name)

    def parse_time(self, value: Any, fmt: str | None = None) -> float | None:
        if value is None:
            return None
        text = str(value).strip()
        if not text:
            return None
        return parse_local(text, fmt or self.time_format, self.tz)


def read_rows(ctx: AdapterContext) -> Iterator[tuple[int, dict[str, str], str]]:
    text = ctx.read_text()
    if not text.strip():
        ctx.warn("File is empty")
        return
    delimiter = str(ctx.colmap.get("delimiter") or ",")
    reader = csv.reader(io.StringIO(text, newline=""), delimiter=delimiter, strict=True)
    try:
        header = [h.strip() for h in next(reader)]
    except (csv.Error, StopIteration) as exc:
        ctx.warn(f"Header row could not be read: {exc}")
        return
    if len(set(header)) != len(header):
        ctx.warn("Header has duplicate column names; the last one of each name is used")
    optional = set(ctx.colmap.get("optional") or [])
    mapped = {v for k, v in (ctx.colmap.get("columns") or {}).items() if v and k not in optional}
    missing = sorted(mapped - set(header))
    if missing:
        ctx.warn(f"Expected columns not found: {', '.join(missing)}")
    start = reader.line_num + 1
    while True:
        try:
            values = next(reader)
        except StopIteration:
            return
        except csv.Error as exc:
            ctx.quarantine(start, f"malformed CSV ({exc}); the rest of the file was not read")
            return
        line_no = start
        start = reader.line_num + 1
        if not values or not any(v.strip() for v in values):
            continue
        if len(values) != len(header):
            ctx.quarantine(line_no, f"{len(values)} fields where the header has {len(header)}")
            continue
        buffer = io.StringIO()
        csv.writer(buffer, delimiter=delimiter, lineterminator="").writerow(values)
        yield line_no, dict(zip(header, values)), buffer.getvalue()


def get(ctx: AdapterContext, row: dict[str, str], name: str) -> str:
    column = ctx.column(name)
    if column is None:
        return ""
    return str(row.get(column, "") or "").strip()


def to_float(value: str) -> float | None:
    text = str(value).replace(",", "").strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def mentions(record: Record, text: str) -> None:
    for match in UPI_PATTERN.findall(text):
        domain = match.split("@", 1)[1]
        record.add_id("mentioned", "email" if "." in domain else "upi", match)
    for match in PHONE_PATTERN.findall(text):
        record.add_id("mentioned", "phone", match)
    for match in URL_PATTERN.findall(text):
        record.add_id("mentioned", "domain", match)
