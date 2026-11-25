from __future__ import annotations

from collections.abc import Callable

from sakshya.adapters.bank import parse_atm_journal, parse_bank_statement, parse_kyc_account
from sakshya.adapters.base import AdapterContext, ParseResult, Record
from sakshya.adapters.device import parse_call_log, parse_chat, parse_cloud_location, parse_sms
from sakshya.adapters.extended import (
    parse_device_info,
    parse_html_table,
    parse_instagram,
    parse_json_records,
    parse_mbox,
    parse_pcap,
    parse_plist,
    parse_social_csv,
    parse_sqlite,
    parse_telegram,
    parse_vcard,
    parse_video,
    parse_wal,
)
from sakshya.adapters.field import parse_cctv_log, parse_media, parse_seizure_memo
from sakshya.adapters.messages import parse_complaint, parse_email, parse_statement
from sakshya.adapters.network import parse_net_conn, parse_uniaethel
from sakshya.adapters.telecom import parse_cdr, parse_kyc_subscriber, parse_tower_dump, parse_tower_list

ADAPTERS: dict[str, Callable[[AdapterContext], ParseResult]] = {
    "bank_statement": parse_bank_statement,
    "atm_journal": parse_atm_journal,
    "kyc_account": parse_kyc_account,
    "cdr": parse_cdr,
    "tower_list": parse_tower_list,
    "tower_dump": parse_tower_dump,
    "kyc_subscriber": parse_kyc_subscriber,
    "call_log": parse_call_log,
    "sms": parse_sms,
    "chat": parse_chat,
    "cloud_location": parse_cloud_location,
    "email": parse_email,
    "complaint": parse_complaint,
    "statement": parse_statement,
    "net_conn": parse_net_conn,
    "uniaethel": parse_uniaethel,
    "cctv_log": parse_cctv_log,
    "seizure_memo": parse_seizure_memo,
    "media": parse_media,
    "pcap": parse_pcap,
    "android_sms_db": parse_sqlite,
    "android_calls_db": parse_sqlite,
    "ios_sms_db": parse_sqlite,
    "browser_history_db": parse_sqlite,
    "plist": parse_plist,
    "vcard": parse_vcard,
    "device_info": parse_device_info,
    "telegram": parse_telegram,
    "instagram": parse_instagram,
    "social_csv": parse_social_csv,
    "html_table": parse_html_table,
    "mbox": parse_mbox,
    "cloud_activity": parse_json_records,
    "json_records": parse_json_records,
    "video": parse_video,
    "sqlite_wal": parse_wal,
}

PARSER_VERSIONS: dict[str, str] = dict.fromkeys(ADAPTERS, "2.0")


def parser_name(source: str) -> str:
    return f"{ADAPTERS[source].__module__.rsplit('.', 1)[-1]}.{ADAPTERS[source].__name__}"


__all__ = ["ADAPTERS", "PARSER_VERSIONS", "AdapterContext", "ParseResult", "Record", "parser_name"]
