# Case format

A case is a folder (or a `.zip` of one) with a manifest called `case.yaml` and the evidence files it lists.

```
CASE-2611-0201/
  case.yaml
  evidence/
    complaint.txt
    bank/statement_victim.csv
    telecom/cdr_9800000000.csv
    ...
```

## Manifest

```yaml
id: CASE-2611-0201
title: Short description of the case
seed:
  kind: complaint
  identifiers:
    - {type: phone, value: "+919800000000"}
    - {type: account, value: "IVBK0123456:50100012345678"}
evidence:
  - {file: evidence/complaint.txt, source: complaint}
  - {file: evidence/bank/statement_victim.csv, source: bank_statement, account: "IVBK0123456:50100012345678"}
  - {file: evidence/victim_phone/call_log.csv, source: call_log, owner: "+919800000000"}
  - {file: evidence/victim_phone/chat_9811111111.txt, source: chat, owner: "+919800000000", owner_name: "Asha", other: "+919811111111"}
  - {file: evidence/cctv/ATM-1_dvr_log.csv, source: cctv_log, atm_id: ATM-1}
  - {file: evidence/telecom/cdr.csv, source: cdr, colmap: {columns: {time: "Call Start"}, time_format: "%d/%m/%Y %H:%M"}}
```

| Field | Meaning |
| --- | --- |
| `id` | Case identifier: letters, digits, `-` and `_` only |
| `title` | Shown in the workbench and the report |
| `seed.identifiers` | The complainant's identifiers. Money is traced from the seed accounts and people are numbered by their distance from the seed. |
| `evidence[].file` | Path inside the case folder |
| `evidence[].source` | One of the source types below |
| `evidence[].sha256` | Optional hash recorded when the file was received. A mismatch is flagged as critical. |
| `evidence[].account` | For a bank statement, the account it belongs to |
| `evidence[].owner` | For phone exports, the phone number of the handset they came from |
| `evidence[].owner_name`, `other` | For chats, the name the owner appears under and the other party's number |
| `evidence[].atm_id` | For a CCTV log, the ATM the camera covers |
| `evidence[].clock_domain` | Files with the same clock domain share one clock estimate |
| `evidence[].colmap` | Overrides for the column map of this file (see below for the keys allowed) |
| `evidence[].acquired` | When the file was acquired. A strict forecast with an earlier cut-off leaves the file out. |
| `evidence[].acquired_by` | Who acquired it |
| `evidence[].timezone` | Time zone the file was written in: an offset, `UTC`, `IST` or an IANA name such as `Europe/London` (daylight saving is applied) |
| `evidence[].dependence_group` | Overrides the dependence group, for files that share an origin with another file in a way the defaults do not know |
| `evidence[].platform` | For social media CSV exports, the platform name used in account identifiers |
| `evidence[].camera`, `lat`, `lon` | For video, the camera identifier and its fixed location |
| `evidence[].recording_start` | For video, the wall-clock time of the first frame; without it frames have no time unless the container records one |
| `evidence[].wal_file` | For a SQLite database, the path of its write-ahead log, which must be listed as its own evidence entry with source `sqlite_wal` |
| `evidence[].notes` | Free text kept with the evidence |

## Column maps

Every tabular source has a default column map in `sakshya/config/colmaps/<source>.yaml`:

```yaml
source: cdr
label: Call detail records
reference: true
timezone: "+05:30"
time_format: "%Y-%m-%d %H:%M:%S"
sigma_s: 2
columns:
  record_id: record_id
  time: start_time
  msisdn: msisdn
```

* `reference` sources are trusted for time; other sources are aligned to them.
* `timezone` is the zone the file was written in: an offset such as `+05:30` or `-04:00`, or `UTC` or `IST`. Times that carry their own offset keep it.
* `time_format` is a Python `strptime` format. Set it to `null` to read ISO 8601 times. Rows whose time does not match are listed as warnings.
* `sigma_s` is the timing uncertainty of the source in seconds.
* `columns` maps the engine's field names (left) to the file's column headers (right).

A `colmap` entry in `case.yaml` is merged over the default, so a file with different headers or another date format needs no code change. Allowed keys are `columns`, `time_format`, `timezone`, `sigma_s`, `delimiter`, `encoding`, and for structured sources `records` (dotted path to the list of records), `fields` (field name to dotted path), `time_unit` (`text`, `unix_s`, `unix_ms`, `apple_s`, `apple_ns`, `chrome_us`), `kind`, `party_kind`, `account_path`, `table`, `platform`, `scene_threshold` and `max_frames`. SQL queries for databases come only from the column map files shipped with Sakshya and cannot be set from a manifest.

Each column map also names the source `family`, its default `dependence` group and, for newer formats, which older source type it `observes_as` for the purposes of phase observability (a Telegram export counts as chat, for example).

## Source types

| Source | Format | Engine fields |
| --- | --- | --- |
| `bank_statement` | CSV | txn_id, time, account, direction (CR or DR), amount, balance, channel, counterparty_account, counterparty_upi, counterparty_name, ref (UPI reference), atm, narration |
| `atm_journal` | CSV | journal_id, time, atm, lat, lon, account, amount, status |
| `kyc_account` | CSV | account, upi, name, phone, address, time (account opened) |
| `cdr` | CSV | record_id, time, msisdn, other, call_type, duration, imei, imsi, cell |
| `tower_list` | CSV | cell, lat, lon, radius, address |
| `tower_dump` | CSV | record_id, time, cell, msisdn, imei, imsi |
| `kyc_subscriber` | CSV | msisdn, imsi, name, address, document, time (activation) |
| `call_log` | CSV | time, number, type, duration |
| `sms` | CSV | time, sender, direction, body. Bank alerts are read for masked account numbers, UPI references and amounts. |
| `chat` | WhatsApp text export | `dd/mm/yy, h:mm am - Sender: message` lines; continuation lines are joined |
| `cloud_location` | JSON | `{account, device: {phone}, locations: [{timestamp or timestampMs, latitudeE7 and longitudeE7 or lat and lon, accuracy}]}` |
| `email` | RFC 822 `.eml` | From, To, Date, Subject, Received headers, body; URLs, domains, IPs, phones, UPI IDs and account numbers are extracted |
| `net_conn` | CSV | time, src_ip, src_mac, dst_ip, dst_port, dst_host, bytes_out, bytes_in |
| `uniaethel` | JSON | UniAethel incident export: `incidents[]` with host, label, window, counterparty, scores, reasons |
| `cctv_log` | CSV | time, camera, atm, event, frame_file, frame_sha256 |
| `media` | Image | Hashed and matched to `frame_sha256` in the CCTV log |
| `seizure_memo` | CSV | item, time, premises, lat, lon, item_type, description, imei, msisdn, imsi, mac, hostname, officer |
| `complaint` | Text | `Key: value` header lines (Filed, Category, Complainant, Mobile) followed by the narrative |
| `statement` | Text | Same layout as a complaint, with a `Recorded:` line |

| `pcap` | PCAP or PCAPNG capture | One record per flow (protocol, addresses, ports, packets, bytes, TCP handshake, TLS server name) and one per DNS query or answer, each pointing to its first packet number. Payloads are not decrypted. |
| `android_sms_db` | Android `mmssms.db` | Messages from the `sms` table; text in free pages and unallocated space is recovered as unverified fragments |
| `android_calls_db` | Android `calllog.db` | Calls from the `calls` table |
| `ios_sms_db` | iOS `sms.db` | Messages joined with their handles |
| `browser_history_db` | Chromium `History` | Visits with URL and title |
| `sqlite_wal` | SQLite write-ahead log | Listed with its database through `wal_file`; applied to a working copy of the database |
| `plist` | Binary or XML property list | Records at the configured path with configured fields |
| `vcard` | vCard `.vcf` | Contacts with names, numbers and emails |
| `device_info` | JSON | Device report: IMEI, IMSI, phone numbers, accounts, model |
| `telegram` | Telegram Desktop `result.json` | Messages with sender and chat |
| `instagram` | Instagram `message_N.json` | Messages, shared links and attachments; text stored in Instagram's escaped encoding is repaired |
| `social_csv` | CSV | time, sender, recipient, text, thread, message_id |
| `html_table` | HTML | A table of messages with configurable column headers |
| `mbox` | mbox mailbox | Each message as for `email` |
| `cloud_activity` | JSON | Sign-in events with address, device, result and location with accuracy |
| `json_records` | JSON | Any list of records, with a configurable path and fields |
| `video` | MP4, MOV, AVI, MKV | Container metadata, key frames and scene changes with the SHA-256 of each listed frame's pixels |

`email` also records Cc, Reply-To, Message-ID, In-Reply-To and References (thread root), attachment names, types, sizes and SHA-256, and the DKIM, SPF and DMARC results stamped by the receiving server.

Rows that cannot be parsed are quarantined with their line number and listed as warnings on the evidence page; they never stop an analysis. A CSV field in quotes may span several lines.

## Generating test cases

```bash
python -m sakshya generate upi_investment_fraud --seed 7 --out cases
python -m sakshya generate sextortion --seed 3 --scale 5 --out cases
```

Kinds: `upi_investment_fraud`, `sextortion`, `sim_swap_takeover`, `no_offence`, `unknown`. Each generated case includes `truth.json`, the answer key used by the evaluation. The engine never reads it.
