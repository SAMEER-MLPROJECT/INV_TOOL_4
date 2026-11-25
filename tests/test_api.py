from __future__ import annotations

import pytest

from .conftest import ADMIN_PASSWORD, DEMO_IDS, USER_PASSWORD, case_archive, make_zip

CASE = DEMO_IDS[0]


def test_health_endpoints(shared_service) -> None:
    client = shared_service.client
    assert client.get("/api/health/live").json()["status"] == "alive"
    ready = client.get("/api/health/ready")
    assert ready.status_code == 200 and all(check["ok"] for check in ready.json()["checks"].values())
    assert client.get("/").status_code == 200
    assert client.get("/").headers["x-content-type-options"] == "nosniff"


def test_auth_state_and_identity(shared_service) -> None:
    state = shared_service.client.get("/api/auth/state").json()
    assert state["bootstrapped"] and not state["bootstrap_enabled"]
    me = shared_service.client.get("/api/auth/me").json()
    assert me["user"]["username"] == "admin" and "manage" in me["user"]["permissions"]


def test_case_listing_link_and_observation(shared_service) -> None:
    client = shared_service.client
    assert CASE in {c["id"] for c in client.get("/api/cases").json()}
    data = shared_service.wait_ready(CASE)
    assert data["you"]["username"] == "admin"
    link = next(item for item in data["links"] if item["status"] in {"inferred", "confirmed", "rejected"})
    detail = client.get(f"/api/cases/{CASE}/links/{link['link_id']}").json()
    assert detail["link_id"] == link["link_id"]
    obs_id = data["timeline"]["items"][0]["obs_id"]
    observation = client.get(f"/api/cases/{CASE}/observations/{obs_id}").json()
    assert len(observation["sha256"]) == 64 and observation["row"] >= 1
    assert observation["parser"] and observation["dependence_group"] and observation["pointer"]["line"] >= 1


def test_observation_pagination(shared_service) -> None:
    client = shared_service.client
    first = client.get(f"/api/cases/{CASE}/observations", params={"limit": 5}).json()
    second = client.get(f"/api/cases/{CASE}/observations", params={"limit": 5, "offset": 5}).json()
    assert first["total"] > 10 and len(first["items"]) == 5
    assert {i["obs_id"] for i in first["items"]}.isdisjoint({i["obs_id"] for i in second["items"]})
    assert client.get(f"/api/cases/{CASE}/observations", params={"limit": 5000}).status_code == 422
    filtered = client.get(f"/api/cases/{CASE}/observations", params={"evidence_id": "E01", "limit": 500}).json()
    assert all(item["evidence_id"] == "E01" for item in filtered["items"])


def test_unknown_case_and_bad_identifiers(shared_service) -> None:
    client = shared_service.client
    assert client.get("/api/cases/NOPE-0000").status_code == 404
    assert client.get("/api/cases/..%2F..%2Fetc").status_code in {400, 404}
    assert client.get(f"/api/cases/{CASE}/observations/../../x").status_code == 404
    assert client.get(f"/api/cases/{CASE}/runs/not-a-run").status_code == 400


def test_reach_as_of_and_policy(shared_service) -> None:
    client = shared_service.client
    full = client.get(f"/api/cases/{CASE}/reach", params={"policy": "fifo"}).json()
    assert full["trace"]["convention"] and full["policy"] == "fifo"
    early = client.get(f"/api/cases/{CASE}/reach", params={"as_of": 0}).json()
    assert early["trace"]["victim_out"] == 0
    assert client.get(f"/api/cases/{CASE}/reach", params={"policy": "lifo"}).status_code == 422
    for item in full["freeze"]:
        assert item["priority_basis"] in {"model estimate", "heuristic"}
        assert "verified_balance" in item


def test_strict_forecast_endpoint(shared_service) -> None:
    data = shared_service.wait_ready(CASE)
    earliest = min(item["t"] for item in data["timeline"]["items"] if item.get("t"))
    result = shared_service.client.get(f"/api/cases/{CASE}/forecast", params={"cutoff": earliest + 60}).json()
    assert result["cutoff"] == earliest + 60
    assert result["evidence_available"]["latest_record"] is None or result["evidence_available"]["latest_record"] <= earliest + 60


def test_decision_versioning_revoke_and_idempotency(shared_service) -> None:
    service = shared_service
    data = service.wait_ready(CASE)
    link = next(item for item in data["links"] if item["type"] == "co_presence" and item["status"] == "inferred")
    runs_before = len(service.client.get(f"/api/cases/{CASE}/runs").json())
    body = {"type": "reject_link", "target": link["link_id"], "reason": "Phone was with the police at the time"}
    first = service.post(f"/api/cases/{CASE}/actions", json=body, headers={"Idempotency-Key": "key-reject-1"})
    repeat = service.post(f"/api/cases/{CASE}/actions", json=body, headers={"Idempotency-Key": "key-reject-1"})
    assert repeat.json()["repeated"] is True
    service.wait_job(first.json()["job"])
    updated = service.wait_ready(CASE)
    assert next(item for item in updated["links"] if item["link_id"] == link["link_id"])["status"] == "rejected"
    assert sum(1 for a in updated["actions"] if a["target"] == link["link_id"] and a["type"] == "reject_link") == 1
    runs = service.client.get(f"/api/cases/{CASE}/runs").json()
    assert len(runs) == runs_before + 1
    run = service.client.get(f"/api/cases/{CASE}/runs/{runs[-1]['run_id']}").json()
    assert run["changes"] and run["artifacts"]
    action_id = first.json()["action"]["id"]
    revoke = service.post(
        f"/api/cases/{CASE}/actions", json={"type": "revoke", "target": action_id, "reason": "Entered in error"}
    )
    service.wait_job(revoke.json()["job"])
    restored = service.wait_ready(CASE)
    assert next(item for item in restored["links"] if item["link_id"] == link["link_id"])["status"] == "inferred"
    assert any(a["id"] == action_id for a in restored["actions"])


def test_annotations_are_kept_with_the_record(shared_service) -> None:
    service = shared_service
    data = service.wait_ready(CASE)
    obs_id = data["timeline"]["items"][0]["obs_id"]
    response = service.post(
        f"/api/cases/{CASE}/actions", json={"type": "annotate", "target": obs_id, "reason": "Matches the CCTV still"}
    )
    assert response.status_code == 200, response.text
    service.wait_job(response.json()["job"])
    service.wait_ready(CASE)
    detail = service.client.get(f"/api/cases/{CASE}/observations/{obs_id}").json()
    assert detail["annotations"][-1]["note"] == "Matches the CCTV still"
    assert detail["annotations"][-1]["actor"]["username"] == "admin"


def test_report_export_and_audit_are_logged(shared_service) -> None:
    service = shared_service
    report = service.client.get(f"/api/cases/{CASE}/report")
    assert report.status_code == 200 and "Annex A" in report.text
    digest = report.headers["x-report-sha256"]
    export = service.client.get(f"/api/cases/{CASE}/export.json")
    assert export.status_code == 200
    audit = service.client.get(f"/api/cases/{CASE}/audit").json()
    types = [e["type"] for e in audit["entries"]]
    assert any(e["type"] == "report_export" and e["payload"]["sha256"] == digest for e in audit["entries"])
    assert "export" in types and "case_access" in types
    assert audit["verification"]["ok"] and "BEGIN PUBLIC KEY" in audit["public_key"]


def test_frame_endpoint_only_serves_video(shared_service) -> None:
    assert shared_service.client.get(f"/api/cases/{CASE}/evidence/E01/frames/0.png").status_code == 404
    assert shared_service.client.get(f"/api/cases/{CASE}/evidence/../frames/0.png").status_code in {404, 422}


def test_upload_is_analysed_and_duplicates_are_refused(shared_service) -> None:
    service = shared_service
    archive = case_archive(DEMO_IDS[-1], "CASE-UPLOAD-0001")
    response = service.post("/api/cases", content=archive, headers={"Content-Type": "application/zip"})
    assert response.status_code == 202, response.text
    job = service.wait_job(response.json()["job"])
    assert job["status"] == "completed" and job["result"]["case_id"] == "CASE-UPLOAD-0001"
    assert service.wait_ready("CASE-UPLOAD-0001")["decision"]["outcome"]
    again = service.post("/api/cases", content=archive, headers={"Content-Type": "application/zip"})
    assert service.wait_job(again.json()["job"])["status"] == "failed"
    assert service.post("/api/cases", content=b"plain text", headers={"Content-Type": "application/zip"}).status_code == 400
    assert service.post("/api/cases", content=make_zip({"a/notes.csv": "x"}), headers={}).status_code in {400, 422}


def test_user_administration_and_password_rules(service_factory) -> None:
    service = service_factory(demo_ids=[])
    service.bootstrap()
    weak = service.post("/api/admin/users", json={"username": "short", "password": "short", "role": "reviewer"})
    assert weak.status_code == 422
    user_id = service.create_user("auditor1", "auditor")
    me = service.client.get("/api/auth/me").json()["user"]["id"]
    assert service.client.patch(f"/api/admin/users/{me}", json={"role": "reviewer"}, headers=service.headers()).status_code == 422
    assert (
        service.client.patch(f"/api/admin/users/{user_id}", json={"disabled": True}, headers=service.headers()).status_code == 200
    )
    service.logout()
    assert service.client.post("/api/auth/login", json={"username": "auditor1", "password": USER_PASSWORD}).status_code == 401
    service.login("admin", ADMIN_PASSWORD)
    assert service.post("/api/auth/password", json={"current": "wrong one", "new": "a brand new passphrase 1"}).status_code == 401


def test_account_lockout_after_repeated_failures(service_factory) -> None:
    service = service_factory(demo_ids=[])
    service.bootstrap()
    service.create_user("investigator1", "investigator")
    for _ in range(5):
        service.client.post("/api/auth/login", json={"username": "investigator1", "password": "definitely wrong"})
    locked = service.client.post("/api/auth/login", json={"username": "investigator1", "password": USER_PASSWORD})
    assert locked.status_code in {401, 423, 429}
    assert "locked" in locked.text.lower() or "too many" in locked.text.lower()


@pytest.mark.parametrize("role,allowed", [("reviewer", False), ("auditor", True), ("investigator", False)])
def test_only_auditors_and_admins_read_the_audit_trail(service_factory, role: str, allowed: bool) -> None:
    service = service_factory()
    service.bootstrap()
    user_id = service.create_user(f"{role}1", role)
    service.post(f"/api/cases/{CASE}/access", json={"user_id": user_id})
    service.wait_ready(CASE)
    service.logout()
    service.login(f"{role}1", USER_PASSWORD)
    assert (service.client.get(f"/api/cases/{CASE}/audit").status_code == 200) is allowed


def test_administrator_from_environment_is_created_once(service_factory, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SAKSHYA_ADMIN_USERNAME", "judge")
    monkeypatch.setenv("SAKSHYA_ADMIN_PASSWORD", "sutram demo passphrase 26")
    service = service_factory(demo_ids=[])
    assert service.client.get("/api/auth/state").json()["bootstrapped"]
    service.login("judge", "sutram demo passphrase 26")
    assert service.client.get("/api/auth/me").json()["user"]["role"] == "admin"
    assert service.workspace.system.last("user_bootstrap")["payload"]["origin"] == "environment"


def test_open_demo_mode_signs_visitors_in_as_a_limited_guest(service_factory) -> None:
    from sakshya.api.security import RATE_DEFAULTS, ServiceConfig

    config = ServiceConfig(cookie_secure=False, demo_open=True, rates=dict.fromkeys(RATE_DEFAULTS, (10000, 60)))
    service = service_factory(config=config)
    state = service.client.get("/api/auth/state").json()
    assert state["demo_open"] is True and state["user"]["username"] == "guest"
    service.client.cookies.clear()
    response = service.client.post("/api/auth/demo", headers={"Origin": "http://testserver"})
    assert response.status_code == 200, response.text
    service.csrf = response.json()["csrf"]
    user = response.json()["user"]
    assert user["username"] == "guest" and user["role"] == "investigator"
    assert service.client.get("/api/cases").json()
    assert service.client.get("/api/admin/users").status_code == 403
    service.wait_ready(CASE)


def test_demo_login_is_closed_unless_enabled(shared_service) -> None:
    assert shared_service.client.post("/api/auth/demo", headers={"Origin": "http://testserver"}).status_code == 404
