from __future__ import annotations

import hashlib
import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime

from sakshya.adapters.base import AMOUNT_PATTERN, AdapterContext, ParseResult, Record, mentions

IP_IN_HEADER = re.compile(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?")
ACCOUNT_DIGITS = re.compile(r"(?<!\d)(\d{9,18})(?!\d)")


AUTH_RESULT = re.compile(r"\b(dkim|spf|dmarc)=(\w+)", re.IGNORECASE)


def _auth_results(message) -> dict[str, str]:
    found: dict[str, str] = {}
    for header in message.get_all("Authentication-Results") or []:
        for method, verdict in AUTH_RESULT.findall(str(header)):
            found.setdefault(method.lower(), verdict.lower())
    return found


def _attachments(message) -> list[dict[str, object]]:
    items = []
    for part in message.iter_attachments() if message.is_multipart() else []:
        payload = part.get_payload(decode=True) or b""
        items.append(
            {
                "filename": part.get_filename() or "",
                "content_type": part.get_content_type(),
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            }
        )
    return items


def email_record(raw_bytes: bytes, row: int) -> Record:
    message = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    date_header = message.get("Date")
    t = parsedate_to_datetime(str(date_header)).timestamp() if date_header else None
    if message.is_multipart():
        part = message.get_body(preferencelist=("plain", "html"))
        body = part.get_content() if part is not None else ""
    else:
        body = message.get_content()
    record = Record(row=row, kind="email", t_raw=t, raw=raw_bytes.decode("utf-8", errors="replace"), text=str(body).strip())
    for _, address in getaddresses([str(message.get("From", ""))]):
        record.add_id("from", "email", address)
    for _, address in getaddresses([str(message.get("To", ""))]):
        record.add_id("to", "email", address)
    for _, address in getaddresses([str(message.get("Cc", ""))]):
        record.add_id("cc", "email", address)
    for _, address in getaddresses([str(message.get("Reply-To", ""))]):
        record.add_id("reply_to", "email", address)
    origin = message.get("X-Originating-IP")
    received = message.get_all("Received") or []
    source = str(origin) if origin else str(received[-1]) if received else ""
    found = IP_IN_HEADER.search(source)
    if found:
        record.add_id("sender_ip", "ip", found.group(1))
    references = str(message.get("References", "")).split()
    record.attrs = {
        "subject": str(message.get("Subject", "")),
        "message_id": str(message.get("Message-ID", "")).strip(),
        "in_reply_to": str(message.get("In-Reply-To", "")).strip(),
        "references": references,
        "thread_root": references[0] if references else str(message.get("Message-ID", "")).strip(),
        "attachments": _attachments(message),
        "authentication": _auth_results(message),
        "authentication_note": "Authentication results are as stamped by the receiving server; they were not re-verified here",
        "received_hops": len(received),
    }
    mentions(record, record.text)
    return record


def parse_email(ctx: AdapterContext) -> ParseResult:
    result = ParseResult()
    result.records.append(email_record(ctx.path.read_bytes(), 1))
    return result


def _narrative(ctx: AdapterContext, kind: str, header_key: str) -> ParseResult:
    result = ParseResult()
    lines = ctx.read_text().splitlines()
    filed = None
    fields = {}
    for line in lines:
        key, sep, value = line.partition(":")
        if sep and key.strip() and len(key) < 40 and not fields.get(key.strip().lower()):
            fields[key.strip().lower()] = value.strip()
    stamp = fields.get(header_key)
    if stamp:
        try:
            filed = ctx.parse_time(stamp)
        except ValueError as exc:
            result.warnings.append(str(exc))
    text = "\n".join(lines)
    record = Record(row=1, kind=kind, t_raw=filed, raw=text, text=text, sigma_t=float(ctx.colmap.get("sigma_s", 1800)))
    mentions(record, text)
    for line in lines:
        if line.lower().startswith(("mera account", "my account", "account:", "a/c")):
            for digits in ACCOUNT_DIGITS.findall(line):
                record.attrs.setdefault("account_digits", []).append(digits)
    amounts = [float(m.replace(",", "")) for m in AMOUNT_PATTERN.findall(text)]
    if amounts:
        record.attrs["amounts"] = amounts
    record.attrs.update({k: v for k, v in fields.items() if k in {"category", "acknowledgement no", "complainant"}})
    result.records.append(record)
    return result


def parse_complaint(ctx: AdapterContext) -> ParseResult:
    return _narrative(ctx, "complaint", "filed")


def parse_statement(ctx: AdapterContext) -> ParseResult:
    return _narrative(ctx, "testimony", "recorded")
