from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from sakshya.adapters import ADAPTERS, PARSER_VERSIONS, AdapterContext
from sakshya.core.config import colmap, source_types, validate_configuration
from sakshya.core.timeutil import parse_local, tz_from_spec
from sakshya.evaluation.fixtures import FIXTURES, build_all
from sakshya.evaluation.parsers import evaluate_fixture

from .conftest import TOKEN, make_zip


@pytest.fixture(scope="module")
def fixtures(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, dict]:
    directory = tmp_path_factory.mktemp("parser_fixtures")
    return directory, build_all(directory)


def test_every_source_type_has_a_parser_and_a_column_map() -> None:
    validate_configuration()
    assert set(source_types()) == set(ADAPTERS) == set(PARSER_VERSIONS)
    for source in ADAPTERS:
        spec = colmap(source)
        assert spec["family"] in {"financial", "telecom", "mobile", "social", "network", "cctv", "email", "cloud", "records"}


@pytest.mark.parametrize("spec", FIXTURES, ids=[f["source"] for f in FIXTURES])
def test_field_level_precision_and_recall(fixtures, spec: dict) -> None:
    directory, labels = fixtures
    labelled = next(item for item in labels["fixtures"] if item["file"] == spec["file"])
    result = evaluate_fixture(directory, labelled)
    assert "error" not in result, result
    assert result["precision"] >= 0.95 and result["recall"] >= 0.95, result
    assert result["value_checks_passed"] == result["value_checks"], result


def _parse(directory: Path, source: str, name: str, entry: dict | None = None):
    spec = next(f for f in FIXTURES if f["file"] == name)
    entry = entry if entry is not None else spec["entry"]
    ctx = AdapterContext(directory / name, "E1", entry, colmap(source, entry.get("colmap")))
    return ctx, ADAPTERS[source](ctx)


def test_pcap_flows_dns_and_sni_with_packet_references(fixtures) -> None:
    directory, _ = fixtures
    _, result = _parse(directory, "pcap", "capture.pcap")
    flows = [r for r in result.records if r.kind == "net_flow"]
    tls = next(r for r in flows if r.attrs["dst_port"] == 443)
    assert tls.attrs["tls_sni"] == "pay-verify-kyc.example"
    assert tls.attrs["payload_decrypted"] is False and tls.attrs["tcp_handshake"]
    assert tls.attrs["packet"] == 3 and "frames from 3" in tls.raw
    dns = [r for r in result.records if r.kind == "dns"]
    assert any(r.attrs["answers"] == ["203.0.113.50"] for r in dns)
    assert result.meta["packets"] == 8


def test_recovered_database_fragments_are_labelled_unverified(fixtures) -> None:
    directory, _ = fixtures
    _, result = _parse(directory, "android_sms_db", "mmssms.db")
    fragments = [r for r in result.records if r.kind == "deleted_fragment"]
    assert fragments and all(r.t_raw is None for r in fragments)
    assert all(r.attrs["recovered"] and "Unverified" in r.attrs["caution"] for r in fragments)
    live = [r for r in result.records if r.kind == "sms"]
    assert all("DELETED-REMNANT" not in r.text for r in live)


def test_database_parsing_never_touches_the_original(fixtures) -> None:
    directory, _ = fixtures
    target = directory / "calllog.db"
    before = (target.stat().st_mtime_ns, target.read_bytes())
    _parse(directory, "android_calls_db", "calllog.db")
    assert (target.stat().st_mtime_ns, target.read_bytes()) == before
    assert not Path(str(target) + "-wal").exists()


def test_email_headers_attachments_and_authentication(fixtures) -> None:
    directory, _ = fixtures
    _, result = _parse(directory, "mbox", "mail.mbox")
    first, reply = result.records
    assert first.attrs["authentication"] == {"dkim": "fail", "spf": "softfail", "dmarc": "fail"}
    attachment = first.attrs["attachments"][0]
    assert attachment["filename"] == "notice.pdf" and len(attachment["sha256"]) == 64
    assert reply.attrs["in_reply_to"] == first.attrs["message_id"]
    assert reply.attrs["thread_root"] == first.attrs["message_id"]


def test_video_frames_are_hashed_and_scene_changes_found(fixtures) -> None:
    directory, _ = fixtures
    _, result = _parse(directory, "video", "atm_cam.mp4")
    assert result.meta["video"]["width"] == 64 and result.meta["video"]["fps"] == 5
    assert all(len(r.attrs["frame_sha256"]) == 64 for r in result.records)
    assert any(r.attrs["scene_change"] > 0.12 and r.attrs["frame_index"] == 10 for r in result.records)
    _, untimed = _parse(directory, "video", "atm_cam.mp4", {"camera": "ATM-DL-0417"})
    assert all(r.t_raw is None for r in untimed.records)
    assert any("wall-clock" in w for w in untimed.warnings)


def test_cloud_locations_keep_their_accuracy(fixtures) -> None:
    directory, _ = fixtures
    _, result = _parse(directory, "cloud_activity", "activity.json")
    located = result.records[0]
    assert located.radius_m == 5000 and located.attrs["coord_basis"] == "approximate"
    assert result.records[1].lat is None


def test_instagram_mojibake_is_repaired(fixtures) -> None:
    directory, _ = fixtures
    _, result = _parse(directory, "instagram", "message_1.json")
    assert result.records[1].text == "\U0001f44b hi"


def test_iana_time_zones_follow_daylight_saving() -> None:
    zone = tz_from_spec("Europe/London")
    winter = parse_local("2026-01-15 12:00:00", "%Y-%m-%d %H:%M:%S", zone)
    summer = parse_local("2026-07-15 12:00:00", "%Y-%m-%d %H:%M:%S", zone)
    assert datetime.fromtimestamp(winter, tz=tz_from_spec("UTC")).hour == 12
    assert datetime.fromtimestamp(summer, tz=tz_from_spec("UTC")).hour == 11
    with pytest.raises(ValueError):
        tz_from_spec("Mars/Olympus")


def test_video_frames_can_be_viewed_through_the_api(service_factory, fixtures) -> None:
    directory, _ = fixtures
    service = service_factory(demo_ids=[])
    service.bootstrap()
    manifest = (
        "id: CASE-VID-0001\ntitle: Video check\nseed:\n  kind: complaint\n  identifiers: []\n"
        "evidence:\n- file: evidence/atm_cam.mp4\n  source: video\n  camera: ATM-DL-0417\n"
        "  recording_start: '2026-03-14 15:30:00'\n"
    )
    archive = make_zip(
        {"CASE-VID-0001/case.yaml": manifest, "CASE-VID-0001/evidence/atm_cam.mp4": (directory / "atm_cam.mp4").read_bytes()}
    )
    response = service.post("/api/cases", content=archive, headers={"Content-Type": "application/zip"})
    assert service.wait_job(response.json()["job"])["status"] == "completed"
    bundle = service.wait_ready("CASE-VID-0001")
    assert bundle["decision"]["outcome"] in {"INSUFFICIENT_EVIDENCE", "NO_OFFENCE_INDICATED", "UNKNOWN_PATTERN"}
    image = service.client.get("/api/cases/CASE-VID-0001/evidence/E01/frames/10.png")
    assert image.status_code == 200 and image.content[:8] == b"\x89PNG\r\n\x1a\n"
    assert service.client.get("/api/cases/CASE-VID-0001/evidence/E01/frames/99999.png").status_code == 404
    detail = service.client.get("/api/cases/CASE-VID-0001/observations/E01:11").json()
    assert detail["frame_image"] is True and detail["pointer"]["frame_sha256"]
    assert TOKEN


def test_new_formats_count_towards_phase_observability() -> None:
    from sakshya.core.config import channel_of

    assert channel_of("telegram") == "chat" and channel_of("android_sms_db") == "sms"
    assert channel_of("pcap") == "net_conn" and channel_of("video") == "cctv_log"
    assert channel_of("bank_statement") == "bank_statement"


def _wal_case(root: Path, list_wal: bool) -> Path:
    import shutil
    import sqlite3

    live = root / "live"
    live.mkdir(parents=True)
    connection = sqlite3.connect(live / "calllog.db")
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA wal_autocheckpoint=0")
    connection.execute("CREATE TABLE calls (_id INTEGER PRIMARY KEY, number TEXT, date INTEGER, duration INTEGER, type INTEGER)")
    connection.execute("INSERT INTO calls VALUES (1, '+919845011223', 1773482400000, 10, 1)")
    connection.commit()
    case = root / "CASE-WAL-0001"
    (case / "evidence").mkdir(parents=True)
    for suffix in ("", "-wal"):
        shutil.copy(live / f"calllog.db{suffix}", case / "evidence" / f"calllog.db{suffix}")
    connection.close()
    entries = "- file: evidence/calllog.db\n  source: android_calls_db\n  owner: '+919811100001'\n"
    if list_wal:
        entries += "  wal_file: evidence/calllog.db-wal\n- file: evidence/calllog.db-wal\n  source: sqlite_wal\n"
    (case / "case.yaml").write_text(
        "id: CASE-WAL-0001\ntitle: WAL\nseed:\n  kind: complaint\n  identifiers: []\nevidence:\n" + entries, encoding="utf-8"
    )
    return case


def test_write_ahead_logs_are_read_only_when_listed_as_evidence(tmp_path: Path) -> None:
    from sakshya.pipeline import analyse

    listed = analyse(_wal_case(tmp_path / "a", True))
    assert (listed.obs["kind"] == "call").sum() == 1
    assert {e.source for e in listed.evidence} == {"android_calls_db", "sqlite_wal"}
    assert all(len(e.sha256) == 64 for e in listed.evidence)
    unlisted = analyse(_wal_case(tmp_path / "b", False))
    assert (unlisted.obs["kind"] == "call").sum() == 0
    assert any("not listed as evidence" in w for ws in unlisted.warnings.values() for w in ws)
