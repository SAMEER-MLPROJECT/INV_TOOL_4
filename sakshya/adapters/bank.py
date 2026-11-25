from __future__ import annotations

import re

from sakshya.adapters.base import AdapterContext, ParseResult, Record, get, read_rows, to_float
from sakshya.core.identifiers import canonical


def _tail(account: str) -> str:
    return account.split(":")[-1][-4:] if account else ""


FAILED = {"FAILED", "DECLINED", "REJECTED", "TIMEOUT", "CANCELLED", "UNSUCCESSFUL"}
REVERSAL = re.compile(r"\b(REV|REVERSAL|REVERSED|RETURNED|CHARGEBACK)\b", re.IGNORECASE)
REFUND = re.compile(r"\bREFUND", re.IGNORECASE)
FEE = re.compile(r"\b(CHG|CHARGES?|FEE|GST|PENALTY|AMC)\b", re.IGNORECASE)


def txn_type(status: str, narration: str, channel: str, direction: str) -> str:
    if status.upper() in FAILED:
        return "failed"
    if REVERSAL.search(narration):
        return "reversal"
    if REFUND.search(narration):
        return "refund"
    if FEE.search(narration) and direction == "DR":
        return "fee"
    if channel in {"CASH", "CDM"} and direction == "CR":
        return "cash_deposit"
    return "normal"


def parse_bank_statement(ctx: AdapterContext) -> ParseResult:
    result = ParseResult()
    default_account = ctx.entry.get("account", "")
    seen_ids: dict[str, int] = {}
    for line_no, row, raw in read_rows(ctx):
        try:
            t = ctx.parse_time(get(ctx, row, "time"))
        except ValueError as exc:
            result.warnings.append(f"row {line_no}: {exc}")
            continue
        account = get(ctx, row, "account") or default_account
        holder = canonical("account", account)
        amount = to_float(get(ctx, row, "amount"))
        direction = get(ctx, row, "direction").upper()[:2]
        if amount is None or direction not in {"CR", "DR"}:
            ctx.quarantine(line_no, "amount or direction is missing or unreadable")
            continue
        txn = get(ctx, row, "txn_id")
        if txn:
            if txn in seen_ids:
                ctx.quarantine(line_no, f"duplicate of transaction {txn} on line {seen_ids[txn]}")
                continue
            seen_ids[txn] = line_no
        channel = get(ctx, row, "channel").upper()
        atm = get(ctx, row, "atm")
        category = txn_type(get(ctx, row, "status"), get(ctx, row, "narration"), channel, direction)
        kind = "atm_withdrawal" if (channel == "ATM" or atm) and direction == "DR" else "txn"
        if category == "failed":
            kind = "txn_failed"
        record = Record(row=line_no, kind=kind, t_raw=t, raw=raw, amount=amount, direction=direction)
        record.add_id("holder", "account", account)
        record.add_id("counterparty", "account", get(ctx, row, "counterparty_account"))
        record.add_id("counterparty", "upi", get(ctx, row, "counterparty_upi"))
        if atm:
            record.add_id("atm", "atm", atm)
        ref = get(ctx, row, "ref")
        if ref and kind == "txn":
            record.anchors.append(f"ref:{ref}")
        if holder is not None and kind != "txn_failed":
            record.anchors.append(f"amt:{amount:.2f}|a4:{_tail(holder.value)}")
            if kind == "atm_withdrawal" and atm:
                record.anchors.append(f"atm:{atm}|amt:{amount:.2f}")
        record.text = get(ctx, row, "narration")
        record.attrs = {
            "channel": channel,
            "balance": to_float(get(ctx, row, "balance")),
            "counterparty_name": get(ctx, row, "counterparty_name"),
            "ref": ref,
            "txn_id": txn,
            "txn_type": category,
        }
        result.records.append(record)
    if default_account:
        result.meta["subject"] = [("account", default_account)]
    return result


def parse_atm_journal(ctx: AdapterContext) -> ParseResult:
    result = ParseResult()
    for line_no, row, raw in read_rows(ctx):
        try:
            t = ctx.parse_time(get(ctx, row, "time"))
        except ValueError as exc:
            result.warnings.append(f"row {line_no}: {exc}")
            continue
        atm = get(ctx, row, "atm")
        lat, lon = to_float(get(ctx, row, "lat")), to_float(get(ctx, row, "lon"))
        if atm and lat is not None and lon is not None:
            result.atms[atm] = {"lat": lat, "lon": lon, "radius_m": 20.0, "label": atm}
        amount = to_float(get(ctx, row, "amount"))
        failed = get(ctx, row, "status").upper() not in {"", "SUCCESS", "OK"}
        record = Record(
            row=line_no,
            kind="atm_failed" if failed else "atm_withdrawal",
            t_raw=t,
            raw=raw,
            amount=amount,
            direction="DR",
            lat=lat,
            lon=lon,
            radius_m=20.0,
            place=atm,
        )
        record.add_id("atm", "atm", atm)
        record.add_id("holder", "account", get(ctx, row, "account"))
        if amount is not None and not failed:
            record.anchors.append(f"atm:{atm}|amt:{amount:.2f}")
        record.anchors.append(f"atmcam:{atm}")
        record.attrs = {"journal_id": get(ctx, row, "journal_id"), "status": get(ctx, row, "status") or "SUCCESS"}
        result.records.append(record)
    return result


def parse_kyc_account(ctx: AdapterContext) -> ParseResult:
    result = ParseResult()
    for line_no, row, raw in read_rows(ctx):
        try:
            t = ctx.parse_time(get(ctx, row, "time"))
        except ValueError:
            t = None
        record = Record(row=line_no, kind="kyc", t_raw=t, raw=raw, sigma_t=86400.0)
        record.add_id("subject", "account", get(ctx, row, "account"))
        record.add_id("subject", "upi", get(ctx, row, "upi"))
        record.add_id("registered_phone", "phone", get(ctx, row, "phone"))
        record.attrs = {
            "name": get(ctx, row, "name"),
            "address": get(ctx, row, "address"),
            "kyc": "account",
            "opened_on": get(ctx, row, "time"),
        }
        result.records.append(record)
    return result
