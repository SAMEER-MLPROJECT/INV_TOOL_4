from __future__ import annotations

import io
import shutil
import time
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from sakshya.api import workspace as workspace_module
from sakshya.api.app import create_app
from sakshya.api.security import RATE_DEFAULTS, ServiceConfig
from sakshya.api.workspace import Workspace
from sakshya.pipeline import Analysis, analyse
from sakshya.storage.layout import DataDir

DEMO = Path(__file__).resolve().parent.parent / "sakshya" / "data" / "demo_cases"
DEMO_IDS = sorted(p.name for p in DEMO.iterdir() if (p / "case.yaml").exists())
TOKEN = "bootstrap-token-for-tests"
ADMIN_PASSWORD = "correct horse battery 9"
USER_PASSWORD = "another long passphrase 7"


@pytest.fixture(scope="session")
def demo_copy(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("cases")
    for case_id in DEMO_IDS:
        shutil.copytree(DEMO / case_id, root / case_id)
    return root


@pytest.fixture(scope="session")
def analyses(demo_copy: Path) -> dict[str, Analysis]:
    return {case_id: analyse(demo_copy / case_id) for case_id in DEMO_IDS}


def make_zip(files: dict[str, bytes | str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def case_archive(case_id: str, new_id: str | None = None) -> bytes:
    files: dict[str, bytes | str] = {}
    for path in (DEMO / case_id).rglob("*"):
        if path.is_file() and path.name != "truth.json":
            files[f"{new_id or case_id}/{path.relative_to(DEMO / case_id)}"] = path.read_bytes()
    if new_id:
        manifest = files[f"{new_id}/case.yaml"]
        files[f"{new_id}/case.yaml"] = manifest.replace(case_id.encode(), new_id.encode())
    return make_zip(files)


class Service:
    def __init__(self, client: TestClient, workspace: Workspace) -> None:
        self.client = client
        self.workspace = workspace
        self.csrf = ""

    def bootstrap(self) -> None:
        response = self.client.post("/api/auth/bootstrap", json={"token": TOKEN, "username": "admin", "password": ADMIN_PASSWORD})
        assert response.status_code == 200, response.text
        self.login("admin", ADMIN_PASSWORD)

    def login(self, username: str, password: str) -> None:
        response = self.client.post("/api/auth/login", json={"username": username, "password": password})
        assert response.status_code == 200, response.text
        self.csrf = response.json()["csrf"]

    def logout(self) -> None:
        self.client.post("/api/auth/logout", headers=self.headers())
        self.client.cookies.clear()
        self.csrf = ""

    def headers(self, **extra: str) -> dict[str, str]:
        return {"X-CSRF-Token": self.csrf, **extra}

    def post(self, url: str, **kwargs: Any):
        headers = {**self.headers(), **kwargs.pop("headers", {})}
        return self.client.post(url, headers=headers, **kwargs)

    def create_user(self, username: str, role: str) -> int:
        response = self.post("/api/admin/users", json={"username": username, "password": USER_PASSWORD, "role": role})
        assert response.status_code == 200, response.text
        return response.json()["id"]

    def wait_job(self, job_id: str, timeout: float = 60.0) -> dict[str, Any]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            data = self.client.get(f"/api/jobs/{job_id}").json()
            if data["status"] in {"completed", "failed", "cancelled"}:
                return data
            time.sleep(0.1)
        raise AssertionError(f"job {job_id} did not finish")

    def wait_ready(self, case_id: str, timeout: float = 60.0) -> dict[str, Any]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            response = self.client.get(f"/api/cases/{case_id}")
            if response.status_code == 200:
                return response.json()
            assert response.status_code == 409, response.text
            time.sleep(0.1)
        raise AssertionError(f"case {case_id} did not become ready")


def build_service(root: Path, demo_ids: list[str], config: ServiceConfig | None = None) -> tuple[Workspace, Any]:
    demo_root = root / "demo"
    demo_root.mkdir(parents=True, exist_ok=True)
    for case_id in demo_ids:
        if not (demo_root / case_id).exists():
            shutil.copytree(DEMO / case_id, demo_root / case_id)
    workspace_module.PACKAGE_DEMO = demo_root
    config = config or ServiceConfig(cookie_secure=False, bootstrap_token=TOKEN, rates=dict.fromkeys(RATE_DEFAULTS, (10000, 60)))
    workspace = Workspace(DataDir.from_env(root / "data"))
    return workspace, create_app(workspace, config)


@pytest.fixture
def service_factory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    monkeypatch.setattr(workspace_module, "PACKAGE_DEMO", workspace_module.PACKAGE_DEMO)
    clients: list[TestClient] = []

    def factory(demo_ids: list[str] | None = None, config: ServiceConfig | None = None, root: Path | None = None) -> Service:
        workspace, app = build_service(root or tmp_path, [DEMO_IDS[0]] if demo_ids is None else demo_ids, config)
        client = TestClient(app, base_url="http://testserver")
        client.__enter__()
        clients.append(client)
        return Service(client, workspace)

    yield factory
    for client in clients:
        client.__exit__(None, None, None)


@pytest.fixture(scope="module")
def shared_service(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Service]:
    original = workspace_module.PACKAGE_DEMO
    root = tmp_path_factory.mktemp("service")
    workspace, app = build_service(root, [DEMO_IDS[0]])
    with TestClient(app, base_url="http://testserver") as client:
        service = Service(client, workspace)
        service.bootstrap()
        service.wait_ready(DEMO_IDS[0])
        yield service
    workspace_module.PACKAGE_DEMO = original
