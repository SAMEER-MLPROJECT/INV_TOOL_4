from __future__ import annotations

import json
import plistlib
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

IST = "+05:30"
BASE = datetime(2026, 3, 14, 10, 0, tzinfo=UTC).timestamp()


def _expect(row: int, kind: str, t: float | None, ids: list[tuple[str, str, str]], **extra: Any) -> dict[str, Any]:
    item: dict[str, Any] = {"row": row, "kind": kind, "t": t, "ids": [list(i) for i in ids]}
    item.update(extra)
    return item


def build_pcap(path: Path) -> list[dict[str, Any]]:
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw
    from scapy.utils import wrpcap

    mac = "02:11:22:33:44:55"
    host, server, resolver = "192.168.1.23", "203.0.113.50", "192.168.1.1"
    hello = _client_hello("pay-verify-kyc.example")
    packets = []
    stamps = []

    def add(packet: Any, offset: float) -> None:
        packet.time = BASE + offset
        packets.append(packet)
        stamps.append(BASE + offset)

    add(
        Ether(src=mac)
        / IP(src=host, dst=resolver)
        / UDP(sport=53001, dport=53)
        / DNS(id=7, rd=1, qd=DNSQR(qname="pay-verify-kyc.example")),
        0.0,
    )
    add(
        Ether(dst=mac)
        / IP(src=resolver, dst=host)
        / UDP(sport=53, dport=53001)
        / DNS(id=7, qr=1, qd=DNSQR(qname="pay-verify-kyc.example"), an=DNSRR(rrname="pay-verify-kyc.example", rdata=server)),
        0.02,
    )
    add(Ether(src=mac) / IP(src=host, dst=server) / TCP(sport=51000, dport=443, flags="S"), 0.10)
    add(Ether(dst=mac) / IP(src=server, dst=host) / TCP(sport=443, dport=51000, flags="SA"), 0.15)
    add(Ether(src=mac) / IP(src=host, dst=server) / TCP(sport=51000, dport=443, flags="A") / Raw(hello), 0.20)
    add(
        Ether(dst=mac) / IP(src=server, dst=host) / TCP(sport=443, dport=51000, flags="PA") / Raw(b"\x17\x03\x03" + b"\x00" * 40),
        0.30,
    )
    add(Ether(src=mac) / IP(src=host, dst=server) / TCP(sport=51000, dport=443, flags="FA"), 2.00)
    add(Ether(src=mac) / IP(src=host, dst="198.51.100.7") / UDP(sport=40000, dport=3478) / Raw(b"x" * 64), 5.0)
    wrpcap(str(path), packets)
    return [
        _expect(1, "net_flow", BASE, [("lan_ip", "ip", host), ("dst", "ip", resolver), ("device", "mac", mac)]),
        _expect(
            3,
            "net_flow",
            BASE + 0.10,
            [
                ("lan_ip", "ip", host),
                ("dst", "ip", server),
                ("device", "mac", mac),
                ("dst_host", "domain", "pay-verify-kyc.example"),
            ],
            attrs={"dst_port": 443, "packets": 5, "tls_sni": "pay-verify-kyc.example"},
        ),
        _expect(8, "net_flow", BASE + 5.0, [("lan_ip", "ip", host), ("dst", "ip", "198.51.100.7"), ("device", "mac", mac)]),
        _expect(1, "dns", BASE, [("client", "ip", host), ("mentioned", "domain", "pay-verify-kyc.example")]),
        _expect(
            2,
            "dns",
            BASE + 0.02,
            [("client", "ip", host), ("mentioned", "domain", "pay-verify-kyc.example"), ("resolved", "ip", server)],
        ),
    ]


def _client_hello(name: str) -> bytes:
    encoded = name.encode("ascii")
    server_name = b"\x00" + len(encoded).to_bytes(2, "big") + encoded
    sni = b"\x00\x00" + (len(server_name) + 2).to_bytes(2, "big") + len(server_name).to_bytes(2, "big") + server_name
    extensions = len(sni).to_bytes(2, "big") + sni
    body = b"\x03\x03" + b"\x11" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + extensions
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def build_android_sms(path: Path) -> list[dict[str, Any]]:
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TABLE sms (_id INTEGER PRIMARY KEY, thread_id INTEGER, address TEXT, date INTEGER, type INTEGER, body TEXT)"
    )
    rows = [
        (1, 4, "+91 98450 11223", int((BASE + 60) * 1000), 1, "Your KYC is pending. Update at https://kyc-update.example/x now"),
        (2, 4, "9845011223", int((BASE + 120) * 1000), 2, "ok sending"),
        (3, 9, "AX-HDFCBK", int((BASE + 600) * 1000), 1, "Rs 25,000 debited from A/c XX4411 UPI Ref 512345678901"),
    ]
    connection.executemany("INSERT INTO sms VALUES (?,?,?,?,?,?)", rows)
    connection.execute("INSERT INTO sms VALUES (4, 9, '9000000000', 1, 1, 'DELETED-REMNANT ask for otp from victim urgently')")
    connection.commit()
    connection.execute("DELETE FROM sms WHERE _id = 4")
    connection.commit()
    connection.close()
    owner = "+919811100001"
    return [
        _expect(
            1,
            "sms",
            BASE + 60,
            [("from", "phone", "+919845011223"), ("to", "phone", owner), ("mentioned", "domain", "kyc-update.example")],
            direction="in",
        ),
        _expect(2, "sms", BASE + 120, [("to", "phone", "+919845011223"), ("from", "phone", owner)], direction="out"),
        _expect(3, "sms", BASE + 600, [("to", "phone", owner)], direction="in", amount=25000.0),
        _expect(4, "deleted_fragment", None, [("mentioned", "phone", "+919000000000")], text_contains="ask for otp from victim"),
    ]


def build_android_calls(path: Path) -> list[dict[str, Any]]:
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE calls (_id INTEGER PRIMARY KEY, number TEXT, date INTEGER, duration INTEGER, type INTEGER)")
    connection.executemany(
        "INSERT INTO calls VALUES (?,?,?,?,?)",
        [(1, "+919845011223", int((BASE + 30) * 1000), 182, 1), (2, "09845011223", int((BASE + 900) * 1000), 0, 2)],
    )
    connection.commit()
    connection.close()
    owner = "+919811100001"
    return [
        _expect(
            1, "call", BASE + 30, [("from", "phone", "+919845011223"), ("to", "phone", owner)], duration_s=182.0, direction="in"
        ),
        _expect(
            2, "call", BASE + 900, [("to", "phone", "+919845011223"), ("from", "phone", owner)], duration_s=0.0, direction="out"
        ),
    ]


def _apple(t: float) -> int:
    return int((t - 978307200) * 1e9)


def build_ios_sms(path: Path) -> list[dict[str, Any]]:
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT)")
    connection.execute(
        "CREATE TABLE message (ROWID INTEGER PRIMARY KEY, handle_id INTEGER, date INTEGER, "
        "is_from_me INTEGER, text TEXT, service TEXT)"
    )
    connection.execute("INSERT INTO handle VALUES (1, '+919845011223')")
    connection.executemany(
        "INSERT INTO message VALUES (?,?,?,?,?,?)",
        [(1, 1, _apple(BASE + 200), 0, "send the OTP", "SMS"), (2, 1, _apple(BASE + 260), 1, "482913", "SMS")],
    )
    connection.commit()
    connection.close()
    owner = "+919811100002"
    return [
        _expect(1, "sms", BASE + 200, [("from", "phone", "+919845011223"), ("to", "phone", owner)], direction="in"),
        _expect(2, "sms", BASE + 260, [("to", "phone", "+919845011223"), ("from", "phone", owner)], direction="out"),
    ]


def build_browser(path: Path) -> list[dict[str, Any]]:
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT)")
    connection.execute("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)")
    connection.execute("INSERT INTO urls VALUES (1, 'https://kyc-update.example/x', 'KYC Update')")
    connection.execute("INSERT INTO visits VALUES (1, 1, ?)", (int((BASE + 75 + 11644473600) * 1e6),))
    connection.commit()
    connection.close()
    return [_expect(1, "web_visit", BASE + 75, [("mentioned", "domain", "kyc-update.example")])]


def build_plist(path: Path) -> list[dict[str, Any]]:
    payload = {
        "calls": [
            {
                "address": "+919845011223",
                "date": datetime.fromtimestamp(BASE + 30, tz=UTC).replace(tzinfo=None),
                "originated": False,
                "duration": 40.0,
            },
            {
                "address": "+919845011224",
                "date": datetime.fromtimestamp(BASE + 90, tz=UTC).replace(tzinfo=None),
                "originated": True,
                "duration": 12.0,
            },
        ]
    }
    path.write_bytes(plistlib.dumps(payload, fmt=plistlib.FMT_BINARY))
    owner = "+919811100002"
    return [
        _expect(1, "call", BASE + 30, [("from", "phone", "+919845011223"), ("to", "phone", owner)], duration_s=40.0),
        _expect(2, "call", BASE + 90, [("to", "phone", "+919845011224"), ("from", "phone", owner)], duration_s=12.0),
    ]


def build_vcard(path: Path) -> list[dict[str, Any]]:
    path.write_text(
        "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Bank Helpdesk\r\nTEL;TYPE=CELL:+91 98450 11223\r\nEND:VCARD\r\n"
        "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Ravi\r\nTEL:9811100009\r\nEMAIL:ravi.k@example.com\r\nEND:VCARD\r\n",
        encoding="utf-8",
    )
    owner = "+919811100001"
    return [
        _expect(1, "contact", None, [("contact", "phone", "+919845011223"), ("owner", "phone", owner)], text="Bank Helpdesk"),
        _expect(
            6,
            "contact",
            None,
            [("contact", "phone", "+919811100009"), ("contact", "email", "ravi.k@example.com"), ("owner", "phone", owner)],
            text="Ravi",
        ),
    ]


def build_telegram(path: Path) -> list[dict[str, Any]]:
    payload = {
        "name": "Support Desk",
        "type": "personal_chat",
        "id": 555,
        "messages": [
            {
                "id": 10,
                "type": "message",
                "date": "2026-03-14T15:31:00",
                "date_unixtime": str(int(BASE + 60)),
                "from": "Support Desk",
                "from_id": "user777",
                "text": "Pay the release fee to refund@okaxis",
            },
            {
                "id": 11,
                "type": "service",
                "date": "2026-03-14T15:31:30",
                "date_unixtime": str(int(BASE + 90)),
                "actor": "x",
                "action": "pin_message",
            },
            {
                "id": 12,
                "type": "message",
                "date": "2026-03-14T15:32:00",
                "date_unixtime": str(int(BASE + 120)),
                "from": "Me",
                "from_id": "user111",
                "text": [{"type": "plain", "text": "done "}, {"type": "bold", "text": "paid"}],
            },
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return [
        _expect(
            1,
            "chat",
            BASE + 60,
            [("from", "handle", "telegram:user777"), ("to", "handle", "telegram:user111"), ("mentioned", "upi", "refund@okaxis")],
            text="Pay the release fee to refund@okaxis",
        ),
        _expect(
            3,
            "chat",
            BASE + 120,
            [("from", "handle", "telegram:user111"), ("to", "handle", "telegram:user777")],
            text="done paid",
        ),
    ]


def build_instagram(path: Path) -> list[dict[str, Any]]:
    mojibake = "\u00f0\u009f\u0091\u008b hi"
    payload = {
        "participants": [{"name": "quick.loans.247"}, {"name": "victim_acc"}],
        "title": "quick.loans.247",
        "messages": [
            {
                "sender_name": "quick.loans.247",
                "timestamp_ms": int((BASE + 30) * 1000),
                "content": "Loan approved, pay fee to 9845011223",
            },
            {"sender_name": "victim_acc", "timestamp_ms": int((BASE + 50) * 1000), "content": mojibake},
        ],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return [
        _expect(
            1,
            "chat",
            BASE + 30,
            [
                ("from", "handle", "instagram:quick.loans.247"),
                ("to", "handle", "instagram:victim_acc"),
                ("mentioned", "phone", "+919845011223"),
            ],
        ),
        _expect(
            2,
            "chat",
            BASE + 50,
            [("from", "handle", "instagram:victim_acc"), ("to", "handle", "instagram:quick.loans.247")],
            text="\U0001f44b hi",
        ),
    ]


def build_social_csv(path: Path) -> list[dict[str, Any]]:
    path.write_text(
        "timestamp,sender,recipient,message,thread,message_id\n"
        '2026-03-14 15:30:30,@loan_agent,victim_acc,"Line one\nline two of the same message",t1,m1\n'
        "2026-03-14 15:31:30,victim_acc,@loan_agent,ok,t1,m2\n"
        "broken,row\n",
        encoding="utf-8",
    )
    return [
        _expect(
            2,
            "chat",
            BASE + 30,
            [("from", "handle", "x:loan_agent"), ("to", "handle", "x:victim_acc")],
            text="Line one\nline two of the same message",
        ),
        _expect(4, "chat", BASE + 90, [("from", "handle", "x:victim_acc"), ("to", "handle", "x:loan_agent")], text="ok"),
    ]


def build_html(path: Path) -> list[dict[str, Any]]:
    path.write_text(
        "<html><body><table><tr><th>Time</th><th>From</th><th>To</th><th>Message</th></tr>"
        "<tr><td>2026-03-14 15:30:00</td><td>shop:fake_store</td><td>shop:buyer9</td><td>Pay &amp; confirm</td></tr>"
        "<tr><td>2026-03-14 15:35:00</td><td>shop:buyer9</td><td>shop:fake_store</td><td>sent</td></tr>"
        "</table></body></html>",
        encoding="utf-8",
    )
    return [
        _expect(2, "chat", BASE, [("from", "handle", "shop:fake_store"), ("to", "handle", "shop:buyer9")], text="Pay & confirm"),
        _expect(3, "chat", BASE + 300, [("from", "handle", "shop:buyer9"), ("to", "handle", "shop:fake_store")], text="sent"),
    ]


def build_mbox(path: Path) -> list[dict[str, Any]]:
    first = (
        "From sender@example Sat Mar 14 10:00:00 2026\n"
        "From: Refunds Desk <refunds@bank-help.example>\nTo: victim@example.com\nCc: audit@bank-help.example\n"
        "Subject: Refund\nDate: Sat, 14 Mar 2026 10:00:00 +0000\nMessage-ID: <a1@bank-help.example>\n"
        "Authentication-Results: mx.example.com; dkim=fail; spf=softfail smtp.mailfrom=bank-help.example; dmarc=fail\n"
        "Received: from mail.bank-help.example ([198.51.100.20]) by mx.example.com\n"
        "MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=XYZ\n\n"
        "--XYZ\nContent-Type: text/plain\n\nPay processing fee to refund@okaxis\n"
        "--XYZ\nContent-Type: application/pdf\nContent-Disposition: attachment; filename=notice.pdf\n"
        "Content-Transfer-Encoding: base64\n\nJVBERi0xLjQK\n--XYZ--\n"
    )
    second = (
        "From victim@example Sat Mar 14 10:05:00 2026\n"
        "From: victim@example.com\nTo: refunds@bank-help.example\nSubject: Re: Refund\n"
        "Date: Sat, 14 Mar 2026 10:05:00 +0000\nMessage-ID: <b2@example.com>\nIn-Reply-To: <a1@bank-help.example>\n"
        "References: <a1@bank-help.example>\n\nPaid.\n"
    )
    path.write_text(first + second, encoding="utf-8")
    return [
        _expect(
            1,
            "email",
            BASE,
            [
                ("from", "email", "refunds@bank-help.example"),
                ("to", "email", "victim@example.com"),
                ("cc", "email", "audit@bank-help.example"),
                ("sender_ip", "ip", "198.51.100.20"),
                ("mentioned", "upi", "refund@okaxis"),
            ],
            attrs={"message_id": "<a1@bank-help.example>"},
        ),
        _expect(
            len(first.splitlines()) + 1,
            "email",
            BASE + 300,
            [("from", "email", "victim@example.com"), ("to", "email", "refunds@bank-help.example")],
            attrs={"in_reply_to": "<a1@bank-help.example>"},
        ),
    ]


def build_cloud(path: Path) -> list[dict[str, Any]]:
    payload = {
        "account": "victim@example.com",
        "events": [
            {
                "time": "2026-03-14T15:30:00+05:30",
                "ip_address": "203.0.113.77",
                "device": {"id": "dev-a1"},
                "location": {"lat": 28.61, "lon": 77.2, "accuracy_m": 5000},
                "result": "success",
            },
            {"time": "2026-03-14T15:40:00+05:30", "ip_address": "198.51.100.3", "device": {"id": "dev-b2"}, "result": "failed"},
        ],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return [
        _expect(
            1,
            "cloud_login",
            BASE,
            [("ip", "ip", "203.0.113.77"), ("device", "host", "dev-a1"), ("subject", "cloud", "victim@example.com")],
        ),
        _expect(
            2,
            "cloud_login",
            BASE + 600,
            [("ip", "ip", "198.51.100.3"), ("device", "host", "dev-b2"), ("subject", "cloud", "victim@example.com")],
        ),
    ]


def build_device_info(path: Path) -> list[dict[str, Any]]:
    payload = {
        "model": "Example A12",
        "manufacturer": "Example",
        "imei": ["356938035643809"],
        "imsi": "404451234567890",
        "phone_numbers": ["+919811100001"],
        "accounts": ["victim@example.com"],
        "extraction_tool": "logical export",
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return [
        _expect(
            1,
            "device_info",
            None,
            [
                ("device", "imei", "356938035643809"),
                ("subject", "phone", "+919811100001"),
                ("sim", "imsi", "404451234567890"),
                ("account", "email", "victim@example.com"),
            ],
        )
    ]


def build_video(path: Path) -> list[dict[str, Any]]:
    import av
    import numpy as np

    with av.open(str(path), mode="w") as container:
        stream = container.add_stream("mpeg4", rate=5)
        stream.width, stream.height, stream.pix_fmt = 64, 48, "yuv420p"
        stream.codec_context.gop_size = 50
        for index in range(20):
            shade = 30 if index < 10 else 220
            image = np.full((48, 64, 3), shade, dtype=np.uint8)
            image[:, : index * 3] = 120
            frame = av.VideoFrame.from_ndarray(image, format="rgb24")
            for packet in stream.encode(frame):
                container.mux(packet)
        for packet in stream.encode():
            container.mux(packet)
    return [
        _expect(1, "video_frame", BASE, [("camera", "atm", "ATM-DL-0417")], attrs={"key_frame": True}),
        _expect(11, "video_frame", BASE + 2.0, [("camera", "atm", "ATM-DL-0417")]),
    ]


def build_bank(path: Path) -> list[dict[str, Any]]:
    account = "IVBK0120429:5372509169849"
    path.write_text(
        "txn_id,value_time,account,direction,amount,balance,channel,counterparty_account,counterparty_upi,"
        "counterparty_name,upi_ref,atm_id,narration,status\n"
        f"T1,14-03-2026 15:30:00,{account},CR,25000.00,25001.00,UPI,,victim@okhdfc,Victim,512345678901,,"
        '"UPI/512345678901/refund\nprocessing",SUCCESS\n'
        f"T2,14-03-2026 15:41:00,{account},DR,24000.00,1001.00,UPI,,mule2@okaxis,Mule Two,512345678999,,"
        "UPI/512345678999,SUCCESS\n"
        f"T3,14-03-2026 15:42:00,{account},DR,24000.00,1001.00,UPI,,mule3@okaxis,,512345679000,,UPI/fail,FAILED\n"
        f"T4,14-03-2026 15:50:00,{account},CR,24000.00,25001.00,UPI,,mule2@okaxis,,512345678999,,REV UPI/512345678999,SUCCESS\n"
        f"T4,14-03-2026 15:50:00,{account},CR,24000.00,25001.00,UPI,,mule2@okaxis,,512345678999,,REV UPI/512345678999,SUCCESS\n"
        f"T5,14-03-2026 15:55:00,{account},DR,17.70,24983.30,CHG,,,,,,SMS CHARGES,SUCCESS\n",
        encoding="utf-8",
    )
    holder = ("holder", "account", account)
    return [
        _expect(
            2,
            "txn",
            BASE,
            [holder, ("counterparty", "upi", "victim@okhdfc")],
            amount=25000.0,
            text="UPI/512345678901/refund\nprocessing",
            attrs={"txn_type": "refund"},
        ),
        _expect(
            4, "txn", BASE + 660, [holder, ("counterparty", "upi", "mule2@okaxis")], amount=24000.0, attrs={"txn_type": "normal"}
        ),
        _expect(5, "txn_failed", BASE + 720, [holder, ("counterparty", "upi", "mule3@okaxis")], attrs={"txn_type": "failed"}),
        _expect(6, "txn", BASE + 1200, [holder, ("counterparty", "upi", "mule2@okaxis")], attrs={"txn_type": "reversal"}),
        _expect(8, "txn", BASE + 1500, [holder], amount=17.7, attrs={"txn_type": "fee"}),
    ]


def build_whatsapp(path: Path) -> list[dict[str, Any]]:
    path.write_text(
        "14/03/26, 3:30 pm - +91 98450 11223: Sir your account is blocked\n"
        "send the fee to refund@okaxis\n"
        "14/03/26, 3:32 pm - Asha: ok\n"
        "14/03/26, 3:33 pm - Messages are end-to-end encrypted.\n",
        encoding="utf-8",
    )
    owner = "+919811100001"
    return [
        _expect(
            1,
            "chat",
            BASE,
            [("from", "phone", "+919845011223"), ("to", "phone", owner), ("mentioned", "upi", "refund@okaxis")],
            text="Sir your account is blocked\nsend the fee to refund@okaxis",
            direction="in",
        ),
        _expect(3, "chat", BASE + 120, [("from", "phone", owner), ("to", "phone", "+919845011223")], direction="out", text="ok"),
    ]


FIXTURES: list[dict[str, Any]] = [
    {"file": "statement.csv", "source": "bank_statement", "build": build_bank, "entry": {}},
    {
        "file": "whatsapp.txt",
        "source": "chat",
        "build": build_whatsapp,
        "entry": {"owner": "+919811100001", "owner_name": "Asha", "other": "+919845011223"},
    },
    {"file": "capture.pcap", "source": "pcap", "build": build_pcap, "entry": {}},
    {"file": "mmssms.db", "source": "android_sms_db", "build": build_android_sms, "entry": {"owner": "+919811100001"}},
    {"file": "calllog.db", "source": "android_calls_db", "build": build_android_calls, "entry": {"owner": "+919811100001"}},
    {"file": "sms.db", "source": "ios_sms_db", "build": build_ios_sms, "entry": {"owner": "+919811100002"}},
    {"file": "History", "source": "browser_history_db", "build": build_browser, "entry": {"owner": "+919811100001"}},
    {
        "file": "CallHistory.plist",
        "source": "plist",
        "build": build_plist,
        "entry": {
            "owner": "+919811100002",
            "colmap": {
                "records": "calls",
                "kind": "call",
                "fields": {"time": "date", "party": "address", "direction": "originated", "duration": "duration"},
            },
        },
    },
    {"file": "contacts.vcf", "source": "vcard", "build": build_vcard, "entry": {"owner": "+919811100001"}},
    {"file": "result.json", "source": "telegram", "build": build_telegram, "entry": {"owner": "user111"}},
    {"file": "message_1.json", "source": "instagram", "build": build_instagram, "entry": {"owner": "victim_acc"}},
    {"file": "social.csv", "source": "social_csv", "build": build_social_csv, "entry": {"platform": "x", "owner": "victim_acc"}},
    {"file": "chat.html", "source": "html_table", "build": build_html, "entry": {}},
    {"file": "mail.mbox", "source": "mbox", "build": build_mbox, "entry": {}},
    {"file": "activity.json", "source": "cloud_activity", "build": build_cloud, "entry": {}},
    {"file": "device.json", "source": "device_info", "build": build_device_info, "entry": {}},
    {
        "file": "atm_cam.mp4",
        "source": "video",
        "build": build_video,
        "entry": {"camera": "ATM-DL-0417", "recording_start": "2026-03-14 15:30:00"},
    },
]


def build_all(directory: Path) -> dict[str, Any]:
    directory.mkdir(parents=True, exist_ok=True)
    labels = []
    for spec in FIXTURES:
        expected = spec["build"](directory / spec["file"])
        labels.append({"file": spec["file"], "source": spec["source"], "entry": spec["entry"], "expected": expected})
    payload = {
        "note": "Synthetic fixtures with hand-written labels; they test parsers, not real-world coverage",
        "fixtures": labels,
    }
    (directory / "labels.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return payload
