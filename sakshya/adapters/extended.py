from __future__ import annotations

import hashlib
import html.parser
import json
import plistlib
import re
import shutil
import sqlite3
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sakshya.adapters.base import AdapterContext, ParseResult, Record, get, mentions, read_rows, to_float
from sakshya.adapters.device import sms_signals
from sakshya.core.identifiers import canonical_phone

APPLE_EPOCH = 978307200.0
CHROME_EPOCH = 11644473600.0
MAX_PACKETS = 2_000_000
MAX_RECORDS = 200_000
TEXT_RUN = re.compile(rb"[\x20-\x7e]{12,}")


def convert_time(value: Any, unit: str, ctx: AdapterContext) -> float | None:
    if value is None or value == "":
        return None
    if unit == "text":
        return ctx.parse_time(value)
    number = float(value)
    if unit == "unix_s":
        return number
    if unit == "unix_ms":
        return number / 1000.0
    if unit == "apple_s":
        return APPLE_EPOCH + number
    if unit == "apple_ns":
        return APPLE_EPOCH + number / 1e9 if number > 1e11 else APPLE_EPOCH + number
    if unit == "chrome_us":
        return number / 1e6 - CHROME_EPOCH
    raise ValueError(f"unknown time unit '{unit}'")


def dig(item: Any, path: str) -> Any:
    current = item
    for part in [p for p in path.split(".") if p]:
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return None
    return current


def _owner(ctx: AdapterContext) -> str | None:
    return canonical_phone(ctx.entry.get("owner", "")) if ctx.entry.get("owner") else None


def _apply_fields(record: Record, ctx: AdapterContext, values: dict[str, Any]) -> None:
    owner = _owner(ctx)
    direction = str(values.get("direction") or "").lower()
    outgoing = direction in set(ctx.colmap.get("outgoing_values", ["2", "out", "sent", "outgoing", "true"]))
    party = values.get("party")
    party_kind = str(ctx.colmap.get("party_kind", "phone"))
    if party not in (None, ""):
        record.add_id("to" if outgoing else "from", party_kind, party)
    conversational = party not in (None, "") or values.get("sender") or values.get("recipient")
    if owner and conversational:
        record.add_id("from" if outgoing else "to", "phone", owner)
    record.direction = "out" if outgoing else "in"
    for key in ("sender", "recipient"):
        if values.get(key):
            record.add_id("from" if key == "sender" else "to", party_kind, values[key])
    if values.get("url"):
        record.add_id("mentioned", "domain", values["url"])
    if values.get("text"):
        record.text = str(values["text"])
        mentions(record, record.text)
    if values.get("duration") not in (None, ""):
        record.duration_s = to_float(str(values["duration"]))
    lat, lon = to_float(str(values.get("lat", ""))), to_float(str(values.get("lon", "")))
    if lat is not None and lon is not None and (lat or lon):
        record.lat, record.lon = lat, lon
        record.radius_m = to_float(str(values.get("accuracy", ""))) or 100.0
        record.attrs["coord_basis"] = "approximate"
    party_id = canonical_phone(str(party)) if party not in (None, "") and party_kind == "phone" else None
    if owner and party_id and record.kind in {"call", "sms"}:
        record.anchors.append(f"{record.kind}:" + "|".join(sorted([owner, party_id])))
    if record.kind == "sms" and record.text:
        sms_signals(record, record.text)
    for key in ("message_id", "thread", "deleted", "title", "status"):
        if values.get(key) not in (None, ""):
            record.attrs[key] = values[key]


def parse_sqlite(ctx: AdapterContext) -> ParseResult:
    result = ParseResult()
    query = ctx.colmap.get("query")
    if not query or not str(query).lstrip().upper().startswith("SELECT"):
        result.warnings.append("No SELECT query is configured for this database")
        return result
    fields: dict[str, str] = ctx.colmap.get("fields", {})
    unit = str(ctx.colmap.get("time_unit", "unix_ms"))
    kind = str(ctx.colmap.get("kind", "record"))
    with tempfile.TemporaryDirectory(prefix="sakshya-db-") as tmp:
        copy = Path(tmp) / ctx.path.name
        shutil.copy2(ctx.path, copy)
        wal = ctx.entry.get("wal_file")
        if wal:
            shutil.copy2(ctx.case_dir / wal if ctx.case_dir else Path(wal), Path(str(copy) + "-wal"))
            result.meta["wal_file"] = wal
        else:
            for suffix in ("-wal", "-journal"):
                if Path(str(ctx.path) + suffix).exists():
                    result.warnings.append(
                        f"A {suffix[1:]} file sits beside this database but is not listed as evidence, so it was not read"
                    )
        try:
            connection = sqlite3.connect(f"file:{copy}?mode=ro", uri=True)
            connection.row_factory = sqlite3.Row
            rows = connection.execute(query).fetchmany(MAX_RECORDS + 1)
        except sqlite3.DatabaseError as exc:
            result.warnings.append(f"Database could not be read: {exc}")
            return result
        if len(rows) > MAX_RECORDS:
            result.warnings.append(f"Only the first {MAX_RECORDS} rows were read")
        for index, row in enumerate(rows[:MAX_RECORDS], start=1):
            data = dict(row)
            values = {name: data.get(column) for name, column in fields.items()}
            try:
                t = convert_time(values.get("time"), unit, ctx)
            except (ValueError, TypeError) as exc:
                ctx.quarantine(index, f"time could not be read ({exc})")
                continue
            pointer = data.get(fields.get("rowid", "rowid"), index)
            record = Record(row=index, kind=kind, t_raw=t, raw=json.dumps(data, default=str, sort_keys=True))
            _apply_fields(record, ctx, values)
            record.attrs["db_row"] = pointer
            result.records.append(record)
        if ctx.colmap.get("carve_free_pages"):
            result.records += carve_free_pages(connection, copy, kind, len(rows) + 1)
        connection.close()
    owner = _owner(ctx)
    if owner:
        result.meta["subject"] = [("phone", owner)]
    return result


def _freelist_pages(data: bytes, page_size: int) -> list[int]:
    trunk = int.from_bytes(data[32:36], "big")
    pages: list[int] = []
    seen: set[int] = set()
    while trunk and trunk not in seen and len(pages) < 100_000:
        seen.add(trunk)
        block = data[(trunk - 1) * page_size : trunk * page_size]
        if len(block) < 8:
            break
        count = int.from_bytes(block[4:8], "big")
        pages.append(trunk)
        pages.extend(int.from_bytes(block[8 + 4 * i : 12 + 4 * i], "big") for i in range(min(count, (page_size - 8) // 4)))
        trunk = int.from_bytes(block[0:4], "big")
    return pages


def _freeblocks(page: bytes, header_offset: int) -> list[tuple[int, int]]:
    if len(page) <= header_offset + 8 or page[header_offset] not in (0x05, 0x0D, 0x02, 0x0A):
        return []
    blocks = []
    offset = int.from_bytes(page[header_offset + 1 : header_offset + 3], "big")
    seen: set[int] = set()
    while offset and offset not in seen and offset + 4 <= len(page):
        seen.add(offset)
        size = int.from_bytes(page[offset + 2 : offset + 4], "big")
        blocks.append((offset + 4, max(0, min(size - 4, len(page) - offset - 4))))
        offset = int.from_bytes(page[offset : offset + 2], "big")
    header = 8 if page[header_offset] in (0x0D, 0x0A) else 12
    cells = int.from_bytes(page[header_offset + 3 : header_offset + 5], "big")
    content = int.from_bytes(page[header_offset + 5 : header_offset + 7], "big") or 65536
    gap_start = header_offset + header + 2 * cells
    if gap_start < min(content, len(page)):
        blocks.append((gap_start, min(content, len(page)) - gap_start))
    return blocks


def carve_free_pages(connection: sqlite3.Connection, path: Path, kind: str, start_row: int) -> list[Record]:
    page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
    data = path.read_bytes()
    regions: list[tuple[int, str, bytes, int]] = []
    for page in _freelist_pages(data, page_size):
        regions.append((page, "free page", data[(page - 1) * page_size : page * page_size], 0))
    for number in range(1, len(data) // page_size + 1):
        page = data[(number - 1) * page_size : number * page_size]
        for offset, size in _freeblocks(page, 100 if number == 1 else 0):
            regions.append((number, "unallocated space", page[offset : offset + size], offset))
    records = []
    for page, region, block, base in regions:
        for match in TEXT_RUN.finditer(block):
            text = match.group().decode("ascii", errors="replace")
            record = Record(row=start_row + len(records), kind="deleted_fragment", t_raw=None, raw=text, text=text)
            record.attrs = {
                "recovered": True,
                "region": region,
                "page": page,
                "offset": base + match.start(),
                "source_kind": kind,
                "caution": "Unverified remnant from unallocated database space; its time, sender and completeness are unknown",
            }
            mentions(record, text)
            records.append(record)
    return records


WAL_MAGIC = (b"\x37\x7f\x06\x82", b"\x37\x7f\x06\x83")


def parse_wal(ctx: AdapterContext) -> ParseResult:
    result = ParseResult()
    with ctx.path.open("rb") as handle:
        header = handle.read(32)
    if header[:4] not in WAL_MAGIC:
        result.warnings.append("This is not a SQLite write-ahead log")
        return result
    page_size = int.from_bytes(header[8:12], "big")
    frames = max(0, (ctx.path.stat().st_size - 32) // (24 + page_size)) if page_size else 0
    result.meta["wal"] = {"page_size": page_size, "frames": frames, "checkpoint": int.from_bytes(header[12:16], "big")}
    return result


def parse_plist(ctx: AdapterContext) -> ParseResult:
    result = ParseResult()
    try:
        payload = plistlib.loads(ctx.path.read_bytes())
    except (plistlib.InvalidFileException, ValueError) as exc:
        result.warnings.append(f"Property list could not be read: {exc}")
        return result
    items = dig(payload, str(ctx.colmap.get("records", "")))
    if isinstance(items, dict):
        items = [items]
    if not isinstance(items, list):
        result.warnings.append("The configured record path does not hold a list")
        return result
    _records_from_items(ctx, result, items, str(ctx.colmap.get("time_unit", "apple_s")))
    return result


def _jsonable(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    return value


def _records_from_items(ctx: AdapterContext, result: ParseResult, items: list[Any], unit: str) -> None:
    fields: dict[str, str] = ctx.colmap.get("fields", {})
    kind = str(ctx.colmap.get("kind", "record"))
    for index, item in enumerate(items[:MAX_RECORDS], start=1):
        if not isinstance(item, dict):
            ctx.quarantine(index, "record is not an object")
            continue
        values = {name: dig(item, path) for name, path in fields.items()}
        stamp = values.get("time")
        try:
            t = (
                stamp.replace(tzinfo=stamp.tzinfo or UTC).timestamp()
                if isinstance(stamp, datetime)
                else convert_time(stamp, unit, ctx)
            )
        except (ValueError, TypeError) as exc:
            ctx.quarantine(index, f"time could not be read ({exc})")
            continue
        record = Record(row=index, kind=kind, t_raw=t, raw=json.dumps(_jsonable(item), sort_keys=True, default=str))
        _apply_fields(record, ctx, values)
        if values.get("device_id"):
            record.add_id("device", str(ctx.colmap.get("device_kind", "host")), values["device_id"])
        if values.get("ip"):
            record.add_id("ip", "ip", values["ip"])
        if values.get("account"):
            record.add_id("subject", "cloud", values["account"])
        result.records.append(record)


def parse_json_records(ctx: AdapterContext) -> ParseResult:
    result = ParseResult()
    try:
        payload = json.loads(ctx.read_text())
    except json.JSONDecodeError as exc:
        result.warnings.append(f"JSON could not be read: {exc}")
        return result
    items = dig(payload, str(ctx.colmap.get("records", "")))
    if not isinstance(items, list):
        result.warnings.append("The configured record path does not hold a list")
        return result
    _records_from_items(ctx, result, items, str(ctx.colmap.get("time_unit", "text")))
    account = dig(payload, str(ctx.colmap.get("account_path", ""))) if ctx.colmap.get("account_path") else None
    if account:
        result.meta["subject"] = [("cloud", str(account))]
        for record in result.records:
            record.add_id("subject", "cloud", account)
    return result


def parse_vcard(ctx: AdapterContext) -> ParseResult:
    result = ParseResult()
    owner = _owner(ctx)
    current: dict[str, Any] | None = None
    start = 0
    lines = ctx.read_text().replace("\r\n ", "").replace("\n ", "").splitlines()
    for line_no, line in enumerate(lines, start=1):
        upper = line.strip().upper()
        if upper == "BEGIN:VCARD":
            current, start = {"name": "", "phones": [], "emails": [], "raw": [line]}, line_no
            continue
        if current is None:
            continue
        current["raw"].append(line)
        key, _, value = line.partition(":")
        field = key.split(";")[0].upper()
        if field == "FN":
            current["name"] = value.strip()
        elif field == "TEL":
            current["phones"].append(value.strip())
        elif field == "EMAIL":
            current["emails"].append(value.strip())
        elif upper == "END:VCARD":
            record = Record(row=start, kind="contact", t_raw=None, raw="\n".join(current["raw"]))
            for phone in current["phones"]:
                record.add_id("contact", "phone", phone)
            for email in current["emails"]:
                record.add_id("contact", "email", email)
            if owner:
                record.add_id("owner", "phone", owner)
            record.attrs = {"name": current["name"], "saved_as": current["name"]}
            record.text = current["name"]
            result.records.append(record)
            current = None
    if current is not None:
        result.warnings.append(f"line {start}: contact card is not closed")
    if owner:
        result.meta["subject"] = [("phone", owner)]
    return result


def _text_of(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        return "".join(part if isinstance(part, str) else str(part.get("text", "")) for part in value)
    return ""


def _repair(text: str) -> str:
    try:
        return text.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return text


def parse_telegram(ctx: AdapterContext) -> ParseResult:
    result = ParseResult()
    try:
        payload = json.loads(ctx.read_text())
    except json.JSONDecodeError as exc:
        result.warnings.append(f"Telegram export could not be read: {exc}")
        return result
    chats = payload.get("chats", {}).get("list") if isinstance(payload.get("chats"), dict) else None
    chats = chats or [payload]
    owner_id = str(ctx.entry.get("owner", "")).strip()
    row = 0
    for chat in chats:
        chat_name = str(chat.get("name") or chat.get("id") or "")
        members = set()
        for message in chat.get("messages", []):
            row += 1
            if message.get("type", "message") != "message":
                continue
            try:
                t = (
                    convert_time(message.get("date_unixtime"), "unix_s", ctx)
                    if message.get("date_unixtime")
                    else ctx.parse_time(message.get("date"))
                )
            except (ValueError, TypeError) as exc:
                ctx.quarantine(row, f"time could not be read ({exc})")
                continue
            sender = str(message.get("from_id") or message.get("from") or "")
            text = _text_of(message.get("text"))
            record = Record(row=row, kind="chat", t_raw=t, raw=json.dumps(message, sort_keys=True, ensure_ascii=False), text=text)
            if sender:
                record.add_id("from", "handle", f"telegram:{sender}")
                members.add(sender)
            if owner_id and sender != owner_id:
                record.add_id("to", "handle", f"telegram:{owner_id}")
            elif owner_id:
                for other in sorted(members - {owner_id}):
                    record.add_id("to", "handle", f"telegram:{other}")
            record.direction = "out" if owner_id and sender == owner_id else "in"
            record.attrs = {
                "message_id": message.get("id"),
                "thread": chat_name,
                "group": chat.get("type") not in (None, "personal_chat"),
                "attachment": message.get("file") or message.get("photo"),
                "platform": "telegram",
                "sender_name": message.get("from"),
            }
            mentions(record, text)
            result.records.append(record)
    return result


def parse_instagram(ctx: AdapterContext) -> ParseResult:
    result = ParseResult()
    try:
        payload = json.loads(ctx.read_text())
    except json.JSONDecodeError as exc:
        result.warnings.append(f"Instagram export could not be read: {exc}")
        return result
    owner = str(ctx.entry.get("owner", "")).strip()
    participants = [_repair(str(p.get("name", ""))) for p in payload.get("participants", [])]
    thread = _repair(str(payload.get("title", "")))
    for index, message in enumerate(payload.get("messages", []), start=1):
        try:
            t = convert_time(message.get("timestamp_ms"), "unix_ms", ctx)
        except (ValueError, TypeError) as exc:
            ctx.quarantine(index, f"time could not be read ({exc})")
            continue
        sender = _repair(str(message.get("sender_name", "")))
        text = _repair(str(message.get("content", "")))
        record = Record(row=index, kind="chat", t_raw=t, raw=json.dumps(message, sort_keys=True, ensure_ascii=False), text=text)
        if sender:
            record.add_id("from", "handle", f"instagram:{sender}")
        for other in participants:
            if other and other != sender:
                record.add_id("to", "handle", f"instagram:{other}")
        share = (message.get("share") or {}).get("link")
        if share:
            record.add_id("mentioned", "domain", share)
        record.direction = "out" if owner and sender == owner else "in"
        record.attrs = {
            "thread": thread,
            "platform": "instagram",
            "attachments": [p.get("uri") for p in message.get("photos", []) + message.get("videos", []) if p.get("uri")],
            "shared_link": share,
            "group": len(participants) > 2,
        }
        mentions(record, text)
        result.records.append(record)
    return result


class _TableParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tables: list[list[list[str]]] = []
        self._row: list[str] | None = None
        self._cell: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if tag == "table":
            self.tables.append([])
        elif tag == "tr" and self.tables:
            self._row = []
        elif tag in {"td", "th"} and self._row is not None:
            self._cell = []

    def handle_endtag(self, tag: str) -> None:
        if tag in {"td", "th"} and self._row is not None and self._cell is not None:
            self._row.append(" ".join("".join(self._cell).split()))
            self._cell = None
        elif tag == "tr" and self._row is not None and self.tables:
            self.tables[-1].append(self._row)
            self._row = None

    def handle_data(self, data: str) -> None:
        if self._cell is not None:
            self._cell.append(data)


def parse_html_table(ctx: AdapterContext) -> ParseResult:
    result = ParseResult()
    parser = _TableParser()
    parser.feed(ctx.read_text())
    index = int(ctx.colmap.get("table", 0))
    if index >= len(parser.tables) or not parser.tables[index]:
        result.warnings.append("No table was found in the HTML export")
        return result
    header, *rows = parser.tables[index]
    columns: dict[str, str] = ctx.colmap.get("columns", {})
    kind = str(ctx.colmap.get("kind", "chat"))
    for position, cells in enumerate(rows, start=2):
        if len(cells) != len(header):
            ctx.quarantine(position, f"{len(cells)} cells where the header has {len(header)}")
            continue
        data = dict(zip(header, cells))
        values = {name: data.get(column, "") for name, column in columns.items()}
        try:
            t = ctx.parse_time(values.get("time"))
        except ValueError as exc:
            ctx.quarantine(position, f"time could not be read ({exc})")
            continue
        record = Record(row=position, kind=kind, t_raw=t, raw=json.dumps(data, ensure_ascii=False, sort_keys=True))
        _apply_fields(record, ctx, values)
        result.records.append(record)
    return result


def parse_social_csv(ctx: AdapterContext) -> ParseResult:
    result = ParseResult()
    platform = str(ctx.entry.get("platform") or ctx.colmap.get("platform") or "social").lower()
    owner = str(ctx.entry.get("owner", "")).strip().lstrip("@")
    for line_no, row, raw in read_rows(ctx):
        try:
            t = ctx.parse_time(get(ctx, row, "time"))
        except ValueError as exc:
            ctx.quarantine(line_no, f"time could not be read ({exc})")
            continue
        sender = get(ctx, row, "sender").lstrip("@")
        recipient = get(ctx, row, "recipient").lstrip("@")
        text = get(ctx, row, "text")
        record = Record(row=line_no, kind="chat", t_raw=t, raw=raw, text=text)
        if sender:
            record.add_id("from", "handle", f"{platform}:{sender}")
        if recipient:
            record.add_id("to", "handle", f"{platform}:{recipient}")
        record.direction = "out" if owner and sender.lower() == owner.lower() else "in"
        record.attrs = {"platform": platform, "thread": get(ctx, row, "thread"), "message_id": get(ctx, row, "message_id")}
        mentions(record, text)
        result.records.append(record)
    if owner:
        result.meta["subject"] = [("handle", f"{platform}:{owner.lower()}")]
    return result


def parse_device_info(ctx: AdapterContext) -> ParseResult:
    result = ParseResult()
    try:
        payload = json.loads(ctx.read_text())
    except json.JSONDecodeError as exc:
        result.warnings.append(f"Device report could not be read: {exc}")
        return result
    record = Record(row=1, kind="device_info", t_raw=None, raw=json.dumps(payload, sort_keys=True))
    for imei in payload.get("imei", []) if isinstance(payload.get("imei"), list) else [payload.get("imei")]:
        record.add_id("device", "imei", imei)
    for phone in payload.get("phone_numbers", []):
        record.add_id("subject", "phone", phone)
    for imsi in payload.get("imsi", []) if isinstance(payload.get("imsi"), list) else [payload.get("imsi")]:
        record.add_id("sim", "imsi", imsi)
    for account in payload.get("accounts", []):
        kind = "email" if "@" in str(account) else "handle"
        record.add_id("account", kind, account)
    record.attrs = {k: payload.get(k) for k in ("model", "manufacturer", "os_version", "serial", "extraction_tool", "acquired")}
    result.records.append(record)
    phones = payload.get("phone_numbers", [])
    if phones:
        result.meta["subject"] = [("phone", canonical_phone(phones[0]) or phones[0])]
    return result


def parse_pcap(ctx: AdapterContext) -> ParseResult:
    from scapy.layers.dns import DNS
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether
    from scapy.utils import PcapNgReader, PcapReader

    result = ParseResult()
    flows: dict[tuple, dict[str, Any]] = {}
    with ctx.path.open("rb") as handle:
        magic = handle.read(4)
    reader_cls = PcapNgReader if magic == b"\x0a\x0d\x0d\x0a" else PcapReader
    try:
        reader = reader_cls(str(ctx.path))
    except Exception as exc:
        result.warnings.append(f"Capture could not be opened: {exc}")
        return result
    dns_rows: list[Record] = []
    count = 0
    with reader:
        for packet in reader:
            count += 1
            if count > MAX_PACKETS:
                result.warnings.append(f"Only the first {MAX_PACKETS} packets were read")
                break
            layer = packet.getlayer(IP) or packet.getlayer(IPv6)
            if layer is None:
                continue
            t = float(packet.time)
            proto = "TCP" if TCP in packet else "UDP" if UDP in packet else str(layer.proto if IP in packet else layer.nh)
            sport = int(packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0)
            dport = int(packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0)
            a, b = (layer.src, sport), (layer.dst, dport)
            key = (proto, *sorted([a, b]))
            flow = flows.get(key)
            if flow is None:
                flow = flows[key] = {
                    "first": t,
                    "last": t,
                    "src": a,
                    "dst": b,
                    "proto": proto,
                    "packets": 0,
                    "bytes_out": 0,
                    "bytes_in": 0,
                    "first_packet": count,
                    "mac": packet[Ether].src if Ether in packet else None,
                    "sni": None,
                    "syn": False,
                    "fin": False,
                }
            flow["last"] = t
            flow["packets"] += 1
            size = len(layer)
            if (layer.src, sport) == flow["src"]:
                flow["bytes_out"] += size
            else:
                flow["bytes_in"] += size
            if TCP in packet:
                flags = int(packet[TCP].flags)
                flow["syn"] |= bool(flags & 0x02)
                flow["fin"] |= bool(flags & 0x01 or flags & 0x04)
                payload = bytes(packet[TCP].payload)
                if flow["sni"] is None and payload[:1] == b"\x16" and len(payload) > 43:
                    flow["sni"] = _client_hello_sni(payload)
            if DNS in packet and len(packet[DNS].qd or []):
                dns = packet[DNS]
                try:
                    name = dns.qd[0].qname.decode("ascii", errors="replace").rstrip(".")
                except AttributeError:
                    name = ""
                answers = []
                for answer in list(dns.an or [])[:50]:
                    rdata = getattr(answer, "rdata", None)
                    if rdata is not None:
                        answers.append(rdata.decode(errors="replace") if isinstance(rdata, bytes) else str(rdata))
                record = Record(
                    row=count,
                    kind="dns",
                    t_raw=t,
                    raw=f"frame {count}: DNS {'response' if dns.qr else 'query'} {name} {' '.join(answers)}".strip(),
                    text=name,
                )
                record.add_id("client", "ip", layer.dst if dns.qr else layer.src)
                record.add_id("mentioned", "domain", name)
                for answer in answers:
                    record.add_id("resolved", "ip", answer)
                record.attrs = {"packet": count, "query": name, "answers": answers, "response": bool(dns.qr)}
                record.sigma_t = 0.001
                dns_rows.append(record)
    for flow in sorted(flows.values(), key=lambda f: (f["first"], f["first_packet"])):
        (src_ip, sport), (dst_ip, dport) = flow["src"], flow["dst"]
        record = Record(
            row=flow["first_packet"],
            kind="net_flow",
            t_raw=flow["first"],
            raw=(
                f"frames from {flow['first_packet']}: {flow['proto']} {src_ip}:{sport} -> {dst_ip}:{dport}, "
                f"{flow['packets']} packets, {flow['bytes_out']} bytes out, {flow['bytes_in']} bytes in"
            ),
            duration_s=round(flow["last"] - flow["first"], 3),
        )
        record.sigma_t = 0.001
        local, remote = (src_ip, dst_ip) if _private(src_ip) or not _private(dst_ip) else (dst_ip, src_ip)
        record.add_id("lan_ip" if _private(local) else "src", "ip", local)
        record.add_id("dst", "ip", remote)
        if flow["mac"]:
            record.add_id("device", "mac", flow["mac"])
        if flow["sni"]:
            record.add_id("dst_host", "domain", flow["sni"])
        record.attrs = {
            "packet": flow["first_packet"],
            "protocol": flow["proto"],
            "src_port": sport,
            "dst_port": dport,
            "packets": flow["packets"],
            "bytes_out": flow["bytes_out"],
            "bytes_in": flow["bytes_in"],
            "dst_host": flow["sni"] or "",
            "tls_sni": flow["sni"],
            "tcp_handshake": flow["syn"],
            "closed": flow["fin"],
            "payload_decrypted": False,
        }
        result.records.append(record)
    result.records += dns_rows
    result.meta["packets"] = count
    return result


def _private(address: str) -> bool:
    import ipaddress

    try:
        return ipaddress.ip_address(address).is_private
    except ValueError:
        return False


def _client_hello_sni(payload: bytes) -> str | None:
    try:
        if payload[5] != 0x01:
            return None
        position = 43
        session = payload[position]
        position += 1 + session
        ciphers = int.from_bytes(payload[position : position + 2], "big")
        position += 2 + ciphers
        methods = payload[position]
        position += 1 + methods
        end = position + 2 + int.from_bytes(payload[position : position + 2], "big")
        position += 2
        while position + 4 <= end:
            kind = int.from_bytes(payload[position : position + 2], "big")
            length = int.from_bytes(payload[position + 2 : position + 4], "big")
            if kind == 0:
                name_length = int.from_bytes(payload[position + 7 : position + 9], "big")
                return payload[position + 9 : position + 9 + name_length].decode("ascii", errors="replace")
            position += 4 + length
    except IndexError:
        return None
    return None


def parse_mbox(ctx: AdapterContext) -> ParseResult:
    from sakshya.adapters.messages import email_record

    result = ParseResult()
    data = ctx.path.read_bytes()
    starts = [m.start() for m in re.finditer(rb"(?m)^From ", data)]
    if not starts:
        result.warnings.append("No messages found; mbox files start each message with a 'From ' line")
        return result
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else len(data)
        chunk = data[start:end]
        body = chunk.split(b"\n", 1)[1] if b"\n" in chunk else b""
        line_no = data[:start].count(b"\n") + 1
        try:
            record = email_record(body, line_no)
        except (ValueError, TypeError) as exc:
            ctx.quarantine(line_no, f"message could not be read ({exc})")
            continue
        result.records.append(record)
    return result


def parse_video(ctx: AdapterContext) -> ParseResult:
    result = ParseResult()
    try:
        import av
        import numpy as np
    except ImportError:
        result.warnings.append("Video support is not installed (PyAV); the file was hashed but not decoded")
        return result
    camera = str(ctx.entry.get("camera") or ctx.entry.get("atm_id") or "")
    started = ctx.entry.get("recording_start")
    base = ctx.parse_time(started) if started else None
    try:
        container = av.open(str(ctx.path), mode="r")
    except Exception as exc:
        result.warnings.append(f"Video could not be opened: {exc}")
        return result
    with container:
        stream = container.streams.video[0]
        tag = container.metadata.get("creation_time")
        if base is None and tag:
            try:
                base = datetime.fromisoformat(tag.replace("Z", "+00:00")).timestamp()
            except ValueError:
                base = None
        rate = float(stream.average_rate) if stream.average_rate else 0.0
        meta = {
            "codec": stream.codec_context.name,
            "width": stream.codec_context.width,
            "height": stream.codec_context.height,
            "fps": round(rate, 3),
            "duration_s": round(float(container.duration) / 1e6, 3) if container.duration else None,
            "creation_time": tag,
            "camera": camera,
            "time_source": "recording_start in manifest" if started else ("container creation time" if tag else "none"),
        }
        result.meta["video"] = meta
        threshold = float(ctx.colmap.get("scene_threshold", 0.12))
        previous = None
        kept = 0
        for index, frame in enumerate(container.decode(stream)):
            gray = frame.to_ndarray(format="gray")
            small = gray[:: max(1, gray.shape[0] // 64), :: max(1, gray.shape[1] // 64)].astype("float32") / 255.0
            change = float(np.mean(np.abs(small - previous))) if previous is not None and previous.shape == small.shape else 1.0
            previous = small
            if not (frame.key_frame or change >= threshold):
                continue
            seconds = float(frame.pts * stream.time_base) if frame.pts is not None else index / (rate or 1.0)
            digest = hashlib.sha256(frame.to_ndarray(format="rgb24").tobytes()).hexdigest()
            record = Record(
                row=index + 1,
                kind="video_frame",
                t_raw=base + seconds if base is not None else None,
                raw=f"frame {index} at {seconds:.3f} s, {'key frame' if frame.key_frame else 'scene change'}",
            )
            if camera:
                record.add_id("camera", "atm", camera)
            record.attrs = {
                "frame_index": index,
                "pts": seconds,
                "key_frame": bool(frame.key_frame),
                "scene_change": round(change, 4),
                "frame_sha256": digest,
                "frame_hash_basis": "SHA-256 of the decoded RGB pixels",
                "camera": camera,
            }
            if ctx.entry.get("lat") is not None and ctx.entry.get("lon") is not None:
                record.lat, record.lon, record.radius_m = float(ctx.entry["lat"]), float(ctx.entry["lon"]), 30.0
                record.attrs["coord_basis"] = "fixed_site"
            record.sigma_t = 2.0 if started else 600.0
            result.records.append(record)
            kept += 1
            if kept >= int(ctx.colmap.get("max_frames", 500)):
                result.warnings.append("Frame list truncated at the configured maximum")
                break
    if base is None:
        result.warnings.append("No recording start time; frames are listed without wall-clock times")
    return result


def video_frame_png(path: Path, frame_index: int, max_width: int = 960) -> bytes:
    import io

    import av

    with av.open(str(path), mode="r") as container:
        stream = container.streams.video[0]
        for index, frame in enumerate(container.decode(stream)):
            if index == frame_index:
                image = frame.to_image()
                if image.width > max_width:
                    image = image.resize((max_width, int(image.height * max_width / image.width)))
                buffer = io.BytesIO()
                image.save(buffer, format="PNG")
                return buffer.getvalue()
    raise ValueError("frame not found")
