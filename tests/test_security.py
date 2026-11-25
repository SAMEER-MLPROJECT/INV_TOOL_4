from __future__ import annotations

import io
import ipaddress
import json
import re
import shutil
import threading
import time
import zipfile
from pathlib import Path

import pytest
from starlette.requests import Request

from sakshya.adapters import AdapterContext
from sakshya.adapters.base import read_rows
from sakshya.api.security import RATE_DEFAULTS, ServiceConfig, client_ip
from sakshya.core.config import colmap
from sakshya.custody.anchor import CheckpointStore, Signer
from sakshya.custody.intake import (
    MISSING_REFERENCE_HASH,
    NOT_VERIFIABLE,
    VERIFIED,
    Evidence,
    check_media,
    verify_reference,
)
from sakshya.custody.ledger import Ledger, entry_hash
from sakshya.pipeline import analyse

from .conftest import DEMO, DEMO_IDS, TOKEN, USER_PASSWORD, case_archive, make_zip

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "sakshya" / "web"
CASE = DEMO_IDS[0]


def _config(**overrides) -> ServiceConfig:
    rates = dict.fromkeys(RATE_DEFAULTS, (10000, 60))
    rates.update(overrides.pop("rates", {}))
    return ServiceConfig(cookie_secure=False, bootstrap_token=TOKEN, rates=rates, **overrides)


def _first_inferred_link(bundle: dict) -> dict:
    return next(link for link in bundle["links"] if link["status"] == "inferred")


def test_f01_anonymous_case_access_is_rejected(shared_service) -> None:
    anonymous = shared_service.client.__class__(shared_service.client.app, base_url="http://testserver")
    for url in ("/api/cases", f"/api/cases/{CASE}", f"/api/cases/{CASE}/report", f"/api/cases/{CASE}/export.json"):
        assert anonymous.get(url).status_code == 401, url
    assert anonymous.get(f"/api/cases/{CASE}/observations").status_code == 401


def test_f02_anonymous_and_csrf_less_actions_are_rejected(shared_service) -> None:
    anonymous = shared_service.client.__class__(shared_service.client.app, base_url="http://testserver")
    body = {"type": "reject_link", "target": "L0001", "reason": "anonymous attempt"}
    assert anonymous.post(f"/api/cases/{CASE}/actions", json=body).status_code == 401
    response = shared_service.client.post(f"/api/cases/{CASE}/actions", json=body)
    assert response.status_code == 403


def test_f03_client_supplied_actor_cannot_spoof_identity(shared_service) -> None:
    bundle = shared_service.wait_ready(CASE)
    link = _first_inferred_link(bundle)
    spoof = {"type": "reject_link", "target": link["link_id"], "reason": "spoof", "actor": "someone else"}
    assert shared_service.post(f"/api/cases/{CASE}/actions", json=spoof).status_code == 422
    real = {"type": "confirm_link", "target": link["link_id"], "reason": "checked against the CDR"}
    response = shared_service.post(f"/api/cases/{CASE}/actions", json=real)
    assert response.status_code == 200, response.text
    shared_service.wait_job(response.json()["job"])
    entry = shared_service.workspace.ledger(CASE).last("investigator_action")
    assert entry["payload"]["actor"]["username"] == "admin"
    assert entry["payload"]["actor"]["role"] == "admin"


def test_f04_markup_in_labels_is_rendered_as_text(shared_service) -> None:
    for path in WEB.joinpath("js").rglob("*.js"):
        source = path.read_text(encoding="utf-8")
        assert not re.search(r"\.innerHTML\s*=|insertAdjacentHTML|outerHTML\s*=|document\.write", source), path
        for call in re.findall(r"\.bind(?:Tooltip|Popup)\(([^)]*)\)", source):
            assert call.startswith(("tip(", "popup")), f"{path.name}: {call}"
    archive = case_archive(CASE, "CASE-XSS-0001")
    service = shared_service
    marker = "<img src=x onerror=alert(1)>"
    files = {}
    with zipfile.ZipFile(io.BytesIO(archive)) as source:
        for name in source.namelist():
            data = source.read(name)
            if name.endswith("case.yaml"):
                text = data.decode()
                text = re.sub(r"^title: .*$", f"title: '{marker}'", text, count=1, flags=re.M)
                data = text.encode()
            files[name] = data
    response = service.post("/api/cases", content=make_zip(files), headers={"Content-Type": "application/zip"})
    assert response.status_code == 202, response.text
    assert service.wait_job(response.json()["job"])["status"] == "completed"
    service.wait_ready("CASE-XSS-0001")
    report = service.client.get("/api/cases/CASE-XSS-0001/report")
    assert report.status_code == 200
    assert marker not in report.text
    assert "&lt;img src=x onerror=alert(1)&gt;" in report.text
    assert "'unsafe-inline'" not in report.headers["content-security-policy"]


def test_f05_failed_upload_never_persists_a_case(service_factory) -> None:
    service = service_factory(demo_ids=[], config=_config())
    service.bootstrap()
    bad = make_zip({"CASE-BAD-0001/case.yaml": "id: CASE-BAD-0001\ntitle: x\nevidence: [", "CASE-BAD-0001/a.csv": "a\n"})
    response = service.post("/api/cases", content=bad, headers={"Content-Type": "application/zip"})
    assert response.status_code == 202
    job = service.wait_job(response.json()["job"])
    assert job["status"] == "failed"
    assert not (service.workspace.data.cases / "CASE-BAD-0001").exists()
    assert list(service.workspace.data.staging.iterdir()) == []
    assert service.client.get("/api/cases").json() == []


def test_f06_malformed_actions_cannot_poison_a_case(shared_service) -> None:
    before = shared_service.workspace.actions(CASE)
    bad_bodies = [
        {"type": "delete_everything", "target": "L0001", "reason": "nope"},
        {"type": "reject_link", "target": "L9999", "reason": "no such link"},
        {"type": "forbid_merge", "target": ["phone:+911", "phone:+912", "phone:+913"], "reason": "three"},
        {"type": "forbid_merge", "target": ["phone:+910000000000", "phone:+910000000000"], "reason": "same"},
        {"type": "annotate", "target": "E99:1", "reason": "missing record"},
        {"type": "reject_link", "target": "L0001", "reason": "x"},
        {"type": "reject_link", "target": "L0001"},
    ]
    for body in bad_bodies:
        response = shared_service.post(f"/api/cases/{CASE}/actions", json=body)
        assert response.status_code == 422, (body, response.text)
    assert shared_service.workspace.actions(CASE) == before
    assert shared_service.client.get(f"/api/cases/{CASE}").status_code == 200


def test_f07_imported_decisions_are_audited_with_the_importer(shared_service) -> None:
    bundle = shared_service.wait_ready(CASE)
    link = _first_inferred_link(bundle)
    body = {
        "source": "reviewed offline by the case team",
        "decisions": [{"type": "reject_link", "target": link["link_id"], "reason": "imported review"}],
    }
    response = shared_service.post(f"/api/cases/{CASE}/decisions/import", json=body)
    assert response.status_code == 200, response.text
    shared_service.wait_job(response.json()["job"])
    ledger = shared_service.workspace.ledger(CASE)
    imported = ledger.last("decision_import")
    assert imported["payload"]["actor"]["username"] == "admin"
    assert imported["payload"]["source"] == body["source"]
    action = ledger.last("investigator_action")
    assert action["payload"]["origin"]["import_sha256"] == imported["payload"]["sha256"]
    spoof = {**body, "decisions": [{**body["decisions"][0], "actor": "x"}]}
    assert shared_service.post(f"/api/cases/{CASE}/decisions/import", json=spoof).status_code == 422


def test_f08_missing_reference_hash_is_never_verified() -> None:
    digest = "a" * 64
    assert verify_reference(digest, None, None, 0.0).status == NOT_VERIFIABLE
    assert verify_reference(digest, None, "manifest", 0.0).status == MISSING_REFERENCE_HASH
    assert verify_reference(digest, digest, "manifest", 0.0).status == VERIFIED
    item = Evidence("E01", "evidence/frame.jpg", "media", "Media", digest, 10, {})
    findings = check_media([item], {"frame.jpg": ("", "E02")})
    assert findings[0]["status"] != VERIFIED
    assert item.verification.status != VERIFIED


def test_f09_changed_evidence_invalidates_the_cached_analysis(service_factory) -> None:
    service = service_factory(config=_config())
    service.bootstrap()
    service.wait_ready(CASE)
    paths = service.workspace.paths(CASE)
    target = next(p for p in sorted(paths.source.rglob("*.csv")))
    target.chmod(0o644)
    target.write_bytes(target.read_bytes() + b"\n")
    response = service.client.get(f"/api/cases/{CASE}")
    assert response.status_code == 409
    assert service.workspace.ledger(CASE).last("analysis_invalidated") is not None
    bundle = service.wait_ready(CASE)
    assert bundle["freshness"]["fresh"] is True
    changed = [e for e in bundle["evidence"]["items"] if e["custody"]["status"] == "changed_since_intake"]
    assert [e["file"] for e in changed] == [str(target.relative_to(paths.source))]


@pytest.mark.parametrize("attack", ["rewrite", "reorder", "truncate"])
def test_f10_ledger_tampering_fails_anchored_verification(tmp_path: Path, attack: str) -> None:
    signer = Signer.load_or_create(tmp_path / "keys")
    store = CheckpointStore(tmp_path / "anchors", signer, True)
    ledger = Ledger(tmp_path / "case" / "ledger.jsonl", "CASE-X", store)
    for index in range(5):
        ledger.append("note", {"index": index})
    assert ledger.verify().ok
    entries = ledger.entries()
    if attack == "rewrite":
        entries[2]["payload"] = {"index": 99}
        previous = entries[1]["hash"]
        for entry in entries[2:]:
            entry["prev"] = previous
            entry["hash"] = entry_hash(entry)
            previous = entry["hash"]
    elif attack == "reorder":
        entries[2], entries[3] = entries[3], entries[2]
    else:
        entries = entries[:-2]
    ledger.path.write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in entries), encoding="utf-8")
    check = ledger.verify()
    assert not check.ok
    assert check.issues or not check.chain_ok


def test_f11_readiness_fails_when_storage_fails(service_factory, monkeypatch: pytest.MonkeyPatch) -> None:
    service = service_factory(demo_ids=[], config=_config())
    assert service.client.get("/api/health/ready").status_code == 200
    original = Path.write_bytes

    def broken(self: Path, data: bytes) -> int:
        if self.name.startswith(".ready-"):
            raise OSError("read-only file system")
        return original(self, data)

    monkeypatch.setattr(Path, "write_bytes", broken)
    response = service.client.get("/api/health/ready")
    assert response.status_code == 503
    assert service.client.get("/api/health/live").status_code == 200


def test_f12_streaming_upload_stops_at_the_limit(service_factory) -> None:
    service = service_factory(demo_ids=[], config=_config(max_upload_mb=1))
    service.bootstrap()
    sent = {"bytes": 0}

    def body():
        for _ in range(64):
            sent["bytes"] += 64 * 1024
            yield b"\0" * (64 * 1024)

    response = service.post("/api/cases", content=body(), headers={"Content-Type": "application/zip"})
    assert response.status_code == 413
    leftovers = list(service.workspace.data.staging.glob("upload-*"))
    assert leftovers == []
    big = service.post(
        "/api/cases", content=b"\0" * 10, headers={"Content-Type": "application/zip", "Content-Length": str(5 * 1024 * 1024)}
    )
    assert big.status_code in {400, 413}


def test_f13_repeated_requests_are_rate_limited(service_factory) -> None:
    service = service_factory(demo_ids=[], config=_config(rates={"login": (3, 60)}))
    service.bootstrap()
    codes = [
        service.client.post("/api/auth/login", json={"username": "admin", "password": "wrong password value"}).status_code
        for _ in range(5)
    ]
    assert 429 in codes
    assert codes.index(429) <= 3
    limited = service.client.post("/api/auth/login", json={"username": "admin", "password": "wrong password value"})
    assert "retry-after" in {k.lower() for k in limited.headers}


def test_f14_heavy_analysis_does_not_block_the_service(service_factory, monkeypatch: pytest.MonkeyPatch) -> None:
    service = service_factory(config=_config())
    service.bootstrap()
    service.wait_ready(CASE)
    started = threading.Event()
    release = threading.Event()

    def slow(*args, **kwargs):
        started.set()
        release.wait(10)
        return service.workspace._analyses[CASE]

    monkeypatch.setattr(service.workspace, "run_analysis", slow)
    job = service.post(f"/api/cases/{CASE}/analyse").json()["job"]
    assert started.wait(5)
    begin = time.perf_counter()
    assert service.client.get("/api/health/live").status_code == 200
    assert service.client.get("/api/cases").status_code == 200
    assert time.perf_counter() - begin < 1.0
    assert service.client.get(f"/api/jobs/{job}").json()["status"] == "running"
    release.set()
    assert service.wait_job(job)["status"] == "completed"


def test_f15_invalid_yaml_and_unparseable_evidence_are_cleaned_up(service_factory) -> None:
    service = service_factory(demo_ids=[], config=_config())
    service.bootstrap()
    unparseable = make_zip(
        {
            "CASE-EMPTY-0001/case.yaml": (
                "id: CASE-EMPTY-0001\ntitle: Empty\nseed:\n  kind: complaint\n  identifiers: []\n"
                "evidence:\n- file: bank.csv\n  source: bank_statement\n"
            ),
            "CASE-EMPTY-0001/bank.csv": b"\xff\xfe\x00garbage",
        }
    )
    yaml_error = make_zip({"CASE-Y-0001/case.yaml": "id: [unclosed", "CASE-Y-0001/a.csv": "x\n"})
    for archive, case_id in ((unparseable, "CASE-EMPTY-0001"), (yaml_error, "CASE-Y-0001")):
        response = service.post("/api/cases", content=archive, headers={"Content-Type": "application/zip"})
        assert response.status_code in {202, 400, 422}, response.text
        if response.status_code == 202:
            job = service.wait_job(response.json()["job"])
            assert job["status"] == "failed", job
        assert not (service.workspace.data.cases / case_id).exists()
    assert list(service.workspace.data.staging.iterdir()) == []


def test_f16_csp_blocks_unauthorised_scripts(shared_service) -> None:
    policy = shared_service.client.get("/").headers["content-security-policy"]
    assert "script-src 'self'" in policy
    assert "unsafe-inline" not in policy and "unsafe-eval" not in policy
    assert "default-src 'none'" in policy and "frame-ancestors 'none'" in policy
    html = (WEB / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html)
    assert not re.search(r"\son[a-z]+=", html)
    assert not re.search(r"\sstyle=", html)
    report = shared_service.client.get(f"/api/cases/{CASE}/report")
    report_policy = report.headers["content-security-policy"]
    nonce = re.search(r"'nonce-([^']+)'", report_policy).group(1)
    assert f'nonce="{nonce}"' in report.text
    assert "<script" not in report.text


def test_f17_sensitive_responses_are_not_cached(shared_service) -> None:
    for url in (
        "/api/cases",
        f"/api/cases/{CASE}",
        f"/api/cases/{CASE}/report",
        f"/api/cases/{CASE}/export.json",
        "/api/auth/me",
        "/",
    ):
        response = shared_service.client.get(url)
        assert response.status_code == 200, url
        assert response.headers["cache-control"] == "no-store", url


def test_f18_default_map_sends_no_coordinates_anywhere(shared_service) -> None:
    state = shared_service.client.get("/api/auth/state").json()
    assert state["map"]["mode"] == "none"
    policy = shared_service.client.get("/").headers["content-security-policy"]
    images = re.search(r"img-src ([^;]+)", policy).group(1).split()
    assert all(item in {"'self'", "data:", "blob:"} for item in images)
    assert "connect-src 'self'" in policy
    for path in WEB.joinpath("js").rglob("*.js"):
        assert not re.search(r"https?://[a-z{}.]*tile|openstreetmap|cartocdn|mapbox", path.read_text(encoding="utf-8")), path


def test_f19_data_survives_a_restart(service_factory, tmp_path: Path) -> None:
    root = tmp_path / "persistent"
    first = service_factory(config=_config(), root=root)
    first.bootstrap()
    bundle = first.wait_ready(CASE)
    link = _first_inferred_link(bundle)
    response = first.post(
        f"/api/cases/{CASE}/actions", json={"type": "reject_link", "target": link["link_id"], "reason": "before restart"}
    )
    first.wait_job(response.json()["job"])
    first.client.__exit__(None, None, None)
    second = service_factory(config=_config(), root=root)
    second.login("admin", "correct horse battery 9")
    after = second.wait_ready(CASE)
    assert any(a["reason"] == "before restart" for a in after["actions"])
    assert next(item for item in after["links"] if item["link_id"] == link["link_id"])["status"] == "rejected"
    assert after["evidence"]["ledger"]["ok"] is True
    assert len(second.client.get(f"/api/cases/{CASE}/runs").json()) >= 2


def _request(peer: str, forwarded: str | None) -> Request:
    headers = [(b"x-forwarded-for", forwarded.encode())] if forwarded else []
    return Request({"type": "http", "client": (peer, 1234), "headers": headers, "method": "GET", "path": "/"})


def test_f20_forwarded_headers_are_ignored_unless_the_proxy_is_trusted() -> None:
    assert client_ip(_request("203.0.113.9", "1.2.3.4"), []) == "203.0.113.9"
    trusted = [ipaddress.ip_network("10.0.0.0/8")]
    assert client_ip(_request("203.0.113.9", "1.2.3.4"), trusted) == "203.0.113.9"
    assert client_ip(_request("10.0.0.5", "1.2.3.4"), trusted) == "1.2.3.4"
    assert client_ip(_request("10.0.0.5", "1.2.3.4, 10.0.0.7"), trusted) == "1.2.3.4"
    assert client_ip(_request("10.0.0.5", "not-an-ip"), trusted) == "10.0.0.5"


def test_f21_empty_or_unparseable_evidence_never_claims_an_offence(tmp_path: Path) -> None:
    case = tmp_path / "CASE-NONE-0001"
    case.mkdir()
    (case / "bank.csv").write_text("", encoding="utf-8")
    (case / "chat.txt").write_bytes(b"\x00\x01binary")
    (case / "case.yaml").write_text(
        "id: CASE-NONE-0001\ntitle: Empty\nseed:\n  kind: complaint\n  identifiers: []\n"
        "evidence:\n- file: bank.csv\n  source: bank_statement\n- file: chat.txt\n  source: chat\n",
        encoding="utf-8",
    )
    outcome = analyse(case).explained["decision"]["outcome"]
    assert outcome in {"INSUFFICIENT_EVIDENCE", "ANALYSIS_FAILED"}


def test_f22_multiline_csv_records_stay_intact(tmp_path: Path) -> None:
    path = tmp_path / "statement.csv"
    path.write_text(
        "txn_id,value_time,account,direction,amount,narration\n"
        'T1,14-03-2026 15:30:00,HDFC:501000123,CR,10.00,"first line\nsecond line, with comma"\n'
        "T2,14-03-2026 15:31:00,HDFC:501000123,DR,5.00,plain\n"
        "T3,14-03-2026 15:32:00,HDFC:501000123,DR\n",
        encoding="utf-8",
    )
    ctx = AdapterContext(path, "E1", {}, colmap("bank_statement"))
    rows = list(read_rows(ctx))
    assert [r[0] for r in rows] == [2, 4]
    assert rows[0][1]["narration"] == "first line\nsecond line, with comma"
    assert ctx.quarantined == 1


def test_zip_traversal_absolute_paths_and_executables_are_refused(shared_service) -> None:
    attacks = [
        {"../evil/case.yaml": "id: x"},
        {"/etc/case.yaml": "id: x"},
        {"CASE-E-0001/case.yaml": "id: CASE-E-0001", "CASE-E-0001/run.sh": "#!/bin/sh\n"},
        {"CASE-E-0001/case.yaml": "id: CASE-E-0001", "CASE-E-0001/tool.exe": "MZ"},
    ]
    for files in attacks:
        response = shared_service.post("/api/cases", content=make_zip(files), headers={"Content-Type": "application/zip"})
        assert response.status_code in {400, 413, 422}, (files.keys(), response.text)
    assert list(shared_service.workspace.data.staging.iterdir()) == []


def test_direct_ledger_edit_is_detected(service_factory) -> None:
    service = service_factory(config=_config())
    service.bootstrap()
    service.wait_ready(CASE)
    ledger = service.workspace.ledger(CASE)
    lines = ledger.path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[1])
    entry["payload"]["origin"] = "edited by hand"
    lines[1] = json.dumps(entry, sort_keys=True)
    ledger.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert service.client.get(f"/api/cases/{CASE}").json()["evidence"]["ledger"]["ok"] is False


def test_role_and_case_isolation(service_factory) -> None:
    service = service_factory(demo_ids=DEMO_IDS[:2], config=_config())
    service.bootstrap()
    reviewer_id = service.create_user("reviewer1", "reviewer")
    service.post(f"/api/cases/{DEMO_IDS[1]}/access", json={"user_id": reviewer_id})
    service.wait_ready(DEMO_IDS[1])
    service.logout()
    service.login("reviewer1", USER_PASSWORD)
    assert [c["id"] for c in service.client.get("/api/cases").json()] == [DEMO_IDS[1]]
    assert service.client.get(f"/api/cases/{DEMO_IDS[0]}").status_code == 404
    action = {"type": "annotate", "target": "E01:2", "reason": "reviewers cannot act"}
    assert service.post(f"/api/cases/{DEMO_IDS[1]}/actions", json=action).status_code == 403
    assert service.client.get("/api/admin/users").status_code == 403
    assert service.post("/api/cases", content=b"x", headers={"Content-Type": "application/zip"}).status_code == 403


def test_docker_image_runs_as_non_root() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    users = re.findall(r"^USER\s+(\S+)", dockerfile, flags=re.M)
    assert users and users[-1] not in {"root", "0"}


def test_original_evidence_is_read_only_after_intake(shared_service) -> None:
    source = shared_service.workspace.paths(CASE).source
    modes = {p.stat().st_mode & 0o222 for p in source.rglob("*") if p.is_file()}
    assert modes == {0}


def test_uploaded_demo_copy_is_isolated_from_the_package(tmp_path: Path) -> None:
    copy = tmp_path / CASE
    shutil.copytree(DEMO / CASE, copy)
    assert analyse(copy).manifest["id"] == CASE
    assert not (copy / "state").exists()
