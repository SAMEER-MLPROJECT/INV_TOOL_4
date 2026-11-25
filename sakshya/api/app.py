from __future__ import annotations

import hashlib
import logging
import os
import re
import secrets
import shutil
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi import Path as FastPath
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator
from starlette.concurrency import run_in_threadpool

from sakshya import __version__
from sakshya.adapters.extended import video_frame_png
from sakshya.api.auth import AuthError, AuthStore, Session, User, same_secret
from sakshya.api.jobs import JobControl, JobManager
from sakshya.api.security import RateLimiter, ServiceConfig, client_ip
from sakshya.api.workspace import NotReady, UploadLimits, Workspace, WorkspaceError
from sakshya.core.config import validate_configuration
from sakshya.core.hashing import sha256_file
from sakshya.custody.intake import ManifestError
from sakshya.pipeline import analyse, bundle
from sakshya.report.render import render_report
from sakshya.views import link_detail, observation_detail, observation_page

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
COOKIE = "sakshya_session"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
logger = logging.getLogger("sakshya")
access_log = logging.getLogger("sakshya.access")
LOG_SALT = secrets.token_bytes(16)
CASE_IN_PATH = re.compile(r"(/api/cases/)[^/]+")


def _log_path(path: str) -> str:
    return CASE_IN_PATH.sub(r"\1{case}", path)


def _client_tag(ip: str) -> str:
    return hashlib.blake2b(ip.encode(), key=LOG_SALT, digest_size=6).hexdigest()


LINK_ID = re.compile(r"^[A-Za-z_]{2,8}-[0-9a-f]{6,16}$")
OBS_ID = re.compile(r"^E\d{2,4}:\d{1,9}$")
JOB_ID = re.compile(r"^[0-9a-f]{32}$")


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ActionRequest(Strict):
    type: Literal["confirm_link", "reject_link", "forbid_merge", "revoke", "annotate"]
    target: str | list[str]
    reason: str = Field(min_length=3, max_length=500)

    @field_validator("target")
    @classmethod
    def _target(cls, value: str | list[str]) -> str | list[str]:
        if isinstance(value, str):
            if not 1 <= len(value) <= 200:
                raise ValueError("target is too long")
        elif len(value) != 2 or any(not isinstance(v, str) or not 1 <= len(v) <= 200 for v in value):
            raise ValueError("target must be one identifier or two identifiers")
        return value


class ImportRequest(Strict):
    source: str = Field(min_length=3, max_length=200)
    decisions: list[ActionRequest] = Field(min_length=1, max_length=500)


class LoginRequest(Strict):
    username: str = Field(min_length=1, max_length=40)
    password: str = Field(min_length=1, max_length=256)


class BootstrapRequest(Strict):
    token: str = Field(min_length=16, max_length=200)
    username: str = Field(min_length=3, max_length=40)
    password: str = Field(min_length=12, max_length=256)
    display_name: str | None = Field(default=None, max_length=80)


class PasswordRequest(Strict):
    current: str = Field(min_length=1, max_length=256)
    new: str = Field(min_length=12, max_length=256)


class UserCreate(Strict):
    username: str = Field(min_length=3, max_length=40)
    password: str = Field(min_length=12, max_length=256)
    role: Literal["admin", "investigator", "reviewer", "auditor"]
    display_name: str | None = Field(default=None, max_length=80)


class UserUpdate(Strict):
    role: Literal["admin", "investigator", "reviewer", "auditor"] | None = None
    disabled: bool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=256)


class GrantRequest(Strict):
    user_id: int


def _error(status: int, message: str, code: str = "error", extra: dict[str, Any] | None = None) -> JSONResponse:
    body = {"detail": message, "error": {"code": code, "message": message}}
    if extra:
        body.update(extra)
    return JSONResponse(body, status_code=status)


@asynccontextmanager
def seed_admin(auth: AuthStore, workspace: Workspace) -> None:
    username = os.environ.get("SAKSHYA_ADMIN_USERNAME", "").strip()
    password = os.environ.get("SAKSHYA_ADMIN_PASSWORD", "")
    if not username or not password or auth.user_count():
        return
    try:
        created = auth.bootstrap_admin(username, password)
    except AuthError as exc:
        logger.error("Administrator from the environment was not created: %s", exc)
        return
    workspace.system.append("user_bootstrap", {"user_id": created.user_id, "username": created.username, "origin": "environment"})


DEMO_USER = "guest"


def prepare_demo_user(auth: AuthStore) -> str | None:
    password = secrets.token_urlsafe(32)
    existing = next((u for u in auth.users() if u["username"] == DEMO_USER), None)
    if existing is None:
        auth.create_user(DEMO_USER, password, "investigator", "Demo visitor")
    else:
        auth.set_password(existing["id"], password)
        auth.set_disabled(existing["id"], False)
    return password


async def lifespan(app: FastAPI):
    workspace: Workspace = app.state.workspace
    seed_admin(app.state.auth, workspace)
    if app.state.config.demo_open:
        app.state.demo_password = prepare_demo_user(app.state.auth)
    workspace.seed_demo_cases()
    for case_id in workspace.case_ids():
        app.state.schedule_analysis(case_id, "service start", None)
    yield
    app.state.jobs.shutdown()


def create_app(workspace: Workspace | None = None, config: ServiceConfig | None = None) -> FastAPI:
    config = config or ServiceConfig.from_env()
    validate_configuration()
    workspace = workspace or Workspace()
    docs = config.docs_enabled
    app = FastAPI(
        title="Sakshya",
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs" if docs else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if docs else None,
    )
    app.state.workspace = workspace
    app.state.config = config
    app.state.auth = AuthStore(workspace.data.database, config.session_hours, config.idle_minutes)
    app.state.jobs = JobManager(workspace.data.root / "jobs.db", config.workers, config.job_timeout_s)
    app.state.limiter = RateLimiter(config.rates)
    app.state.viewed: set[tuple[str, str]] = set()
    auth: AuthStore = app.state.auth
    jobs: JobManager = app.state.jobs
    limiter: RateLimiter = app.state.limiter

    def schedule_analysis(case_id: str, reason: str, actor: dict[str, Any] | None) -> str:
        active = jobs.active_for_case(case_id, "analysis")
        if active:
            return active

        def work(control: JobControl) -> dict[str, Any]:
            control.progress(0.1, "analysing")
            analysis = workspace.run_analysis(case_id, reason, actor, control)
            return {"case_id": case_id, "outcome": analysis.explained["decision"].get("outcome")}

        return jobs.submit("analysis", case_id, actor["user_id"] if actor else None, work)

    app.state.schedule_analysis = schedule_analysis

    @app.exception_handler(WorkspaceError)
    async def workspace_error(_: Request, exc: WorkspaceError) -> JSONResponse:
        if isinstance(exc, NotReady):
            case_jobs = getattr(exc, "job_id", None)
            return _error(409, str(exc), "analysis_pending", {"job": case_jobs})
        return _error(exc.status, str(exc), "workspace")

    @app.exception_handler(ManifestError)
    async def manifest_error(_: Request, exc: ManifestError) -> JSONResponse:
        return _error(422, str(exc), "manifest")

    @app.exception_handler(AuthError)
    async def auth_error(_: Request, exc: AuthError) -> JSONResponse:
        return _error(exc.status, str(exc), "auth")

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        problems = [{"field": ".".join(str(p) for p in e.get("loc", [])[1:]), "message": e.get("msg", "")} for e in exc.errors()]
        return _error(422, "The request is not valid", "validation", {"problems": problems[:20]})

    @app.exception_handler(HTTPException)
    async def http_error(_: Request, exc: HTTPException) -> JSONResponse:
        response = _error(exc.status_code, str(exc.detail), "http")
        for key, value in (exc.headers or {}).items():
            response.headers[key] = value
        return response

    @app.exception_handler(Exception)
    async def unexpected(_: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled error: %s", type(exc).__name__)
        return _error(500, "The server could not complete the request", "internal")

    csp = config.content_security_policy()

    def _limited(wait: float) -> JSONResponse:
        response = _error(429, "Too many requests; slow down and try again shortly", "rate_limited")
        response.headers["Retry-After"] = str(int(wait) + 1)
        return response

    @app.middleware("http")
    async def guard(request: Request, call_next):
        request.state.ip = client_ip(request, config.trusted_proxies)
        request.state.request_id = uuid.uuid4().hex[:12]
        if request.url.path.startswith("/api/") and request.url.path not in {"/api/health/live", "/api/health/ready"}:
            wait = limiter.check("api", request.state.ip)
            if wait:
                return _limited(wait)
        started = time.perf_counter()
        response = await call_next(request)
        access_log.info(
            "%s %s %s %.0fms client=%s id=%s",
            request.method,
            _log_path(request.url.path),
            response.status_code,
            (time.perf_counter() - started) * 1000,
            _client_tag(request.state.ip),
            request.state.request_id,
        )
        headers = response.headers
        headers.setdefault("Content-Security-Policy", csp)
        headers.setdefault("X-Content-Type-Options", "nosniff")
        headers.setdefault("Referrer-Policy", "no-referrer")
        headers.setdefault("X-Frame-Options", "DENY")
        headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
        headers.setdefault("X-Request-ID", request.state.request_id)
        if request.url.path.startswith(("/api/", "/tiles/")) or request.url.path == "/":
            headers["Cache-Control"] = "no-store"
            headers["Pragma"] = "no-cache"
        elif request.url.path.startswith("/static/"):
            headers["Cache-Control"] = "no-cache"
        if config.cookie_secure and config.environment == "production":
            headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    def rate(category: str, principal: str) -> None:
        wait = limiter.check(category, principal)
        if wait:
            raise HTTPException(429, "Too many requests; slow down and try again shortly", {"Retry-After": str(int(wait) + 1)})

    def session(request: Request) -> Session:
        current = auth.session(request.cookies.get(COOKIE))
        if current is None:
            raise HTTPException(401, "Sign in to continue")
        if request.method not in SAFE_METHODS and not same_secret(request.headers.get("x-csrf-token"), current.csrf):
            raise HTTPException(403, "Missing or invalid CSRF token")
        request.state.user = current.user
        return current

    def user(current: Session = Depends(session)) -> User:
        return current.user

    def need(permission: str):
        def check(current: User = Depends(user)) -> User:
            if not current.can(permission):
                raise HTTPException(403, "Your role does not allow this")
            return current

        return check

    def case_for(case_id: str, current: User) -> str:
        if not auth.can_access(current, case_id):
            raise HTTPException(404, "Case not found")
        workspace.paths(case_id)
        return case_id

    def ready(case_id: str, current: User) -> Any:
        case_for(case_id, current)
        try:
            return workspace.ready_analysis(case_id)
        except NotReady as exc:
            exc.job_id = schedule_analysis(case_id, "evidence or configuration changed", None)
            raise

    def note_view(current: Session, case_id: str, what: str) -> None:
        key = (current.token_hash, case_id)
        if key not in app.state.viewed:
            app.state.viewed.add(key)
            workspace.record_access(case_id, current.user.actor(), what)

    def check_origin(request: Request) -> None:
        origin = request.headers.get("origin")
        if origin and urlparse(origin).netloc != request.headers.get("host", ""):
            raise HTTPException(403, "Cross-site request refused")

    @app.get("/api/health/live")
    def live() -> dict[str, Any]:
        return {"status": "alive", "version": __version__}

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        return {"status": "alive", "version": __version__}

    @app.get("/api/health/ready")
    def readiness() -> JSONResponse:
        checks = readiness_checks(workspace, auth, jobs)
        ok = all(c["ok"] for c in checks.values())
        return JSONResponse({"status": "ready" if ok else "not_ready", "checks": checks}, status_code=200 if ok else 503)

    @app.get("/api/health/diagnostics")
    def diagnostics(current: User = Depends(need("manage"))) -> dict[str, Any]:
        checks = readiness_checks(workspace, auth, jobs)
        return {
            "version": __version__,
            "checks": checks,
            "cases": len(workspace.case_ids()),
            "anchoring": "independent" if workspace.data.independent_anchor else "local",
            "map": config.map_mode()["mode"],
            "environment": config.environment,
            "system_ledger": workspace.system.verify().to_dict(),
        }

    def open_demo_session(request: Request, response: Response) -> Session | None:
        password = getattr(app.state, "demo_password", None)
        if not config.demo_open or not password:
            return None
        rate("login", request.state.ip)
        token, current = auth.login(DEMO_USER, password)
        for case_id in workspace.case_ids():
            auth.grant(case_id, current.user.user_id, None)
        workspace.system.append("login", {"user_id": current.user.user_id, "ip": request.state.ip, "demo": True})
        response.set_cookie(
            COOKIE,
            token,
            max_age=int(config.session_hours * 3600),
            httponly=True,
            secure=config.cookie_secure,
            samesite="strict",
            path="/",
        )
        return current

    @app.get("/api/auth/state")
    def auth_state(request: Request, response: Response) -> dict[str, Any]:
        current = auth.session(request.cookies.get(COOKIE))
        if current is None:
            current = open_demo_session(request, response)
        elif config.demo_open and current.user.username == DEMO_USER:
            for case_id in workspace.case_ids():
                auth.grant(case_id, current.user.user_id, None)
        return {
            "bootstrapped": auth.user_count() > 0,
            "bootstrap_enabled": bool(config.bootstrap_token) and auth.user_count() == 0,
            "user": current.user.public() if current else None,
            "csrf": current.csrf if current else None,
            "map": config.map_mode(),
            "version": __version__,
            "demo_open": config.demo_open,
        }

    @app.post("/api/auth/demo")
    def demo_login(request: Request, response: Response) -> dict[str, Any]:
        check_origin(request)
        current = open_demo_session(request, response)
        if current is None:
            raise HTTPException(404, "Not found")
        return {"user": current.user.public(), "csrf": current.csrf}

    @app.post("/api/auth/bootstrap")
    def bootstrap(body: BootstrapRequest, request: Request) -> dict[str, Any]:
        check_origin(request)
        rate("login", request.state.ip)
        if not config.bootstrap_token or not same_secret(body.token, config.bootstrap_token):
            raise HTTPException(403, "Bootstrap is not enabled or the token is wrong")
        created = auth.bootstrap_admin(body.username, body.password, body.display_name)
        workspace.system.append("user_bootstrap", {"user_id": created.user_id, "username": created.username})
        return {"user": created.public()}

    @app.post("/api/auth/login")
    def login(body: LoginRequest, request: Request, response: Response) -> dict[str, Any]:
        check_origin(request)
        rate("login", f"{request.state.ip}|{body.username.lower()}")
        rate("login", request.state.ip)
        try:
            token, current = auth.login(body.username, body.password)
        except AuthError:
            workspace.system.append("login_failed", {"username": body.username.lower()[:40], "ip": request.state.ip})
            raise
        workspace.system.append("login", {"user_id": current.user.user_id, "ip": request.state.ip})
        response.set_cookie(
            COOKIE,
            token,
            max_age=int(config.session_hours * 3600),
            httponly=True,
            secure=config.cookie_secure,
            samesite="strict",
            path="/",
        )
        return {"user": current.user.public(), "csrf": current.csrf}

    @app.post("/api/auth/logout")
    def logout(response: Response, current: Session = Depends(session)) -> dict[str, Any]:
        auth.logout(current.token_hash)
        workspace.system.append("logout", {"user_id": current.user.user_id})
        response.delete_cookie(COOKIE, path="/")
        return {"ok": True}

    @app.get("/api/auth/me")
    def me(current: Session = Depends(session)) -> dict[str, Any]:
        return {"user": current.user.public(), "csrf": current.csrf}

    @app.post("/api/auth/password")
    def change_password(body: PasswordRequest, current: Session = Depends(session)) -> dict[str, Any]:
        auth.login(current.user.username, body.current)
        auth.set_password(current.user.user_id, body.new)
        workspace.system.append("password_changed", {"user_id": current.user.user_id})
        return {"ok": True, "message": "Password changed; sign in again"}

    @app.get("/api/admin/users")
    def list_users(current: User = Depends(need("manage"))) -> list[dict[str, Any]]:
        return auth.users()

    @app.post("/api/admin/users")
    def add_user(body: UserCreate, current: User = Depends(need("manage"))) -> dict[str, Any]:
        created = auth.create_user(body.username, body.password, body.role, body.display_name)
        workspace.system.append("user_created", {"user_id": created.user_id, "role": created.role, "by": current.actor()})
        return created.public()

    @app.patch("/api/admin/users/{user_id}")
    def update_user(user_id: int, body: UserUpdate, current: User = Depends(need("manage"))) -> dict[str, Any]:
        target = auth.user(user_id)
        if target is None:
            raise HTTPException(404, "User not found")
        if user_id == current.user_id and (body.disabled or (body.role and body.role != "admin")):
            raise HTTPException(422, "You cannot disable or demote your own account")
        if body.role:
            auth.set_role(user_id, body.role)
        if body.disabled is not None:
            auth.set_disabled(user_id, body.disabled)
        if body.password:
            auth.set_password(user_id, body.password)
        workspace.system.append(
            "user_updated",
            {
                "user_id": user_id,
                "role": body.role,
                "disabled": body.disabled,
                "password_reset": bool(body.password),
                "by": current.actor(),
            },
        )
        return (auth.user(user_id) or target).public()

    @app.post("/api/admin/users/{user_id}/revoke-sessions")
    def revoke_sessions(user_id: int, current: User = Depends(need("manage"))) -> dict[str, Any]:
        count = auth.revoke_user_sessions(user_id)
        workspace.system.append("sessions_revoked", {"user_id": user_id, "count": count, "by": current.actor()})
        return {"revoked": count}

    @app.get("/api/cases/{case_id}/access")
    def case_access(case_id: str, current: User = Depends(need("manage"))) -> list[dict[str, Any]]:
        workspace.paths(case_id)
        return auth.access_list(case_id)

    @app.post("/api/cases/{case_id}/access")
    def grant(case_id: str, body: GrantRequest, current: User = Depends(need("manage"))) -> dict[str, Any]:
        workspace.paths(case_id)
        if auth.user(body.user_id) is None:
            raise HTTPException(404, "User not found")
        auth.grant(case_id, body.user_id, current.user_id)
        workspace.ledger(case_id).append("access_granted", {"user_id": body.user_id, "by": current.actor()})
        return {"ok": True}

    @app.delete("/api/cases/{case_id}/access/{user_id}")
    def revoke(case_id: str, user_id: int, current: User = Depends(need("manage"))) -> dict[str, Any]:
        workspace.paths(case_id)
        auth.revoke(case_id, user_id)
        workspace.ledger(case_id).append("access_revoked", {"user_id": user_id, "by": current.actor()})
        return {"ok": True}

    @app.get("/api/cases")
    def cases(current: User = Depends(need("view"))) -> list[dict[str, Any]]:
        return [workspace.summary(case_id) for case_id in auth.accessible(current, workspace.case_ids())]

    @app.get("/api/cases/{case_id}")
    def case(case_id: str, current: Session = Depends(session)) -> dict[str, Any]:
        _require(current.user, "view")
        ready(case_id, current.user)
        note_view(current, case_id, "case_bundle")
        data = workspace.bundle(case_id)
        data["linked_cases"] = workspace.linked(case_id, set(auth.accessible(current.user, workspace.case_ids())))
        data["you"] = current.user.public()
        return data

    @app.get("/api/cases/{case_id}/reach")
    def reach(
        case_id: str,
        current: User = Depends(need("view")),
        as_of: float | None = Query(default=None, ge=0, le=4102444800),
        policy: str = Query(default="pro_rata", pattern=r"^(pro_rata|fifo)$"),
    ) -> dict[str, Any]:
        return ready(case_id, current).reach(as_of, policy)

    @app.get("/api/cases/{case_id}/forecast")
    def forecast(
        case_id: str,
        current: User = Depends(need("view")),
        cutoff: float = Query(ge=0, le=4102444800),
    ) -> dict[str, Any]:
        rate("analysis", str(current.user_id))
        ready(case_id, current)
        paths = workspace.paths(case_id)
        snapshot = analyse(paths.source, actions=workspace.actions(case_id), as_of=cutoff)
        data = snapshot.forecast()
        data["analysis_inputs"] = snapshot.cache_key
        return data

    @app.get("/api/cases/{case_id}/links/{link_id}")
    def link(case_id: str, link_id: str, current: User = Depends(need("view"))) -> dict[str, Any]:
        if not LINK_ID.match(link_id):
            raise HTTPException(404, "Link not found")
        detail = link_detail(ready(case_id, current), link_id)
        if detail is None:
            raise HTTPException(404, "Link not found")
        return detail

    @app.get("/api/cases/{case_id}/observations/{obs_id}")
    def observation(case_id: str, obs_id: str, current: User = Depends(need("view"))) -> dict[str, Any]:
        if not OBS_ID.match(obs_id):
            raise HTTPException(404, "Observation not found")
        detail = observation_detail(ready(case_id, current), obs_id)
        if detail is None:
            raise HTTPException(404, "Observation not found")
        return detail

    @app.get("/api/cases/{case_id}/evidence/{evidence_id}/frames/{frame_index}.png", include_in_schema=False)
    def video_frame(
        case_id: str,
        evidence_id: str = FastPath(pattern=r"^E\d{2,4}$"),
        frame_index: int = FastPath(ge=0, le=10_000_000),
        current: User = Depends(need("view")),
    ) -> Response:
        analysis = ready(case_id, current)
        item = next((e for e in analysis.evidence if e.evidence_id == evidence_id and e.source == "video"), None)
        if item is None:
            raise HTTPException(404, "Video evidence not found")
        path = workspace.paths(case_id).source / item.file
        if not path.is_file() or sha256_file(path) != item.sha256:
            raise HTTPException(409, "The video changed since it was analysed; re-run the analysis first")
        try:
            png = video_frame_png(path, frame_index)
        except (ValueError, ImportError) as exc:
            raise HTTPException(404, "Frame could not be decoded") from exc
        return Response(png, media_type="image/png", headers={"X-Evidence-SHA256": item.sha256})

    @app.get("/api/cases/{case_id}/observations")
    def observations(
        case_id: str,
        current: User = Depends(need("view")),
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=100, ge=1, le=500),
        evidence_id: str | None = Query(default=None, pattern=r"^E\d{2,4}$"),
        kind: str | None = Query(default=None, max_length=40),
    ) -> dict[str, Any]:
        return observation_page(ready(case_id, current), offset, limit, evidence_id, kind)

    @app.post("/api/cases/{case_id}/actions")
    def act(
        case_id: str,
        body: ActionRequest,
        current: User = Depends(need("act")),
        idempotency_key: Annotated[str | None, Header(max_length=80)] = None,
    ) -> dict[str, Any]:
        rate("action", str(current.user_id))
        case_for(case_id, current)
        if idempotency_key:
            previous = auth.reserve(idempotency_key, current.user_id, case_id)
            if previous is not None:
                return {
                    "action": {"id": previous},
                    "job": schedule_analysis(case_id, "investigator decision", current.actor()),
                    "repeated": True,
                }
        try:
            ready(case_id, current)
            entry = workspace.act(case_id, body.type, body.target, body.reason, current.actor())
        except Exception:
            if idempotency_key:
                auth.release(idempotency_key)
            raise
        if idempotency_key:
            auth.complete(idempotency_key, entry["id"])
        job = schedule_analysis(case_id, f"investigator decision {entry['id']}", current.actor())
        return {"action": entry, "job": job, "repeated": False}

    @app.post("/api/cases/{case_id}/decisions/import")
    def import_decisions(case_id: str, body: ImportRequest, current: User = Depends(need("import"))) -> dict[str, Any]:
        rate("action", str(current.user_id))
        ready(case_id, current)
        for item in body.decisions:
            workspace.validate_action(case_id, item.type, item.target)
        created = workspace.import_decisions(case_id, [d.model_dump() for d in body.decisions], current.actor(), body.source)
        job = schedule_analysis(case_id, f"imported {len(created)} decisions", current.actor())
        return {"actions": created, "job": job}

    @app.post("/api/cases/{case_id}/analyse")
    def reanalyse(case_id: str, current: User = Depends(need("act"))) -> dict[str, Any]:
        rate("analysis", str(current.user_id))
        case_for(case_id, current)
        return {"job": schedule_analysis(case_id, "requested by investigator", current.actor())}

    @app.get("/api/cases/{case_id}/runs")
    def runs(case_id: str, current: User = Depends(need("view"))) -> list[dict[str, Any]]:
        case_for(case_id, current)
        return workspace.runs(case_id)

    @app.get("/api/cases/{case_id}/runs/{run_id}")
    def run(case_id: str, run_id: str, current: User = Depends(need("view"))) -> dict[str, Any]:
        case_for(case_id, current)
        return workspace.run(case_id, run_id)

    @app.get("/api/cases/{case_id}/report", response_class=HTMLResponse)
    def report(case_id: str, current: User = Depends(need("report"))) -> HTMLResponse:
        rate("report", str(current.user_id))
        analysis = ready(case_id, current)
        nonce = secrets.token_urlsafe(16)
        ledger = workspace.ledger(case_id)
        html = render_report(analysis, workspace.bundle(case_id), ledger.entries(), nonce)
        digest = workspace.record_report(case_id, html, current.actor())
        policy = csp.replace("style-src 'self'", f"style-src 'nonce-{nonce}'")
        return HTMLResponse(
            html,
            headers={
                "X-Report-SHA256": digest,
                "Content-Security-Policy": policy,
                "Content-Disposition": f'inline; filename="{case_id}_report.html"',
            },
        )

    @app.get("/api/cases/{case_id}/export.json")
    def export(case_id: str, current: User = Depends(need("export"))) -> JSONResponse:
        rate("export", str(current.user_id))
        analysis = ready(case_id, current)
        data = bundle(analysis)
        workspace.ledger(case_id).append("export", {"format": "json", "digest": data["digest"], "actor": current.actor()})
        return JSONResponse(data, headers={"Content-Disposition": f'attachment; filename="{case_id}_analysis.json"'})

    @app.get("/api/cases/{case_id}/audit")
    def audit(case_id: str, current: User = Depends(need("audit"))) -> dict[str, Any]:
        case_for(case_id, current)
        ledger = workspace.ledger(case_id)
        check = ledger.verify().to_dict()
        workspace.record_access(case_id, current.actor(), "audit_export")
        return {
            "case_id": case_id,
            "verification": check,
            "entries": ledger.entries(),
            "checkpoints": workspace.anchors.checkpoints(case_id),
            "public_key": workspace.signer.public_pem(),
            "anchoring": check["anchoring"],
        }

    @app.post("/api/cases", status_code=202)
    async def upload(request: Request, current: User = Depends(need("upload"))) -> dict[str, Any]:
        rate("upload", str(current.user_id))
        count, used = auth.usage(current.user_id)
        if count >= config.user_case_limit:
            raise HTTPException(413, "You have reached the limit on the number of cases")
        limit = config.max_upload_mb * 1024 * 1024
        remaining = config.user_quota_mb * 1024 * 1024 - used
        cap = min(limit, remaining)
        if cap <= 0:
            raise HTTPException(413, "Your storage quota is used up")
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > cap:
            raise HTTPException(413, f"Upload is larger than {cap // (1024 * 1024)} MB")
        workspace.data.staging.mkdir(parents=True, exist_ok=True)
        temp = workspace.data.staging / f"upload-{uuid.uuid4().hex}.zip"
        received = 0
        try:
            with temp.open("xb") as handle:
                async for chunk in request.stream():
                    received += len(chunk)
                    if received > cap:
                        raise HTTPException(413, f"Upload is larger than {cap // (1024 * 1024)} MB")
                    handle.write(chunk)
            if received == 0:
                raise HTTPException(400, "The upload was empty")
            limits = UploadLimits(
                cap, config.max_uncompressed_mb * 1024 * 1024, config.max_entries, config.max_ratio, config.max_depth
            )
            staging = await run_in_threadpool(workspace.stage_upload, temp, limits)
        finally:
            temp.unlink(missing_ok=True)
        actor = current.actor()

        def work(control: JobControl) -> dict[str, Any]:
            control.progress(0.1, "validating")
            case_id = workspace.commit_upload(staging, actor, control)
            size = sum(p.stat().st_size for p in workspace.paths(case_id).source.rglob("*") if p.is_file())
            auth.set_owner(case_id, actor["user_id"], size)
            auth.grant(case_id, actor["user_id"], actor["user_id"])
            control.progress(0.4, "analysing")
            analysis = workspace.run_analysis(case_id, "case uploaded", actor, control)
            return {"case_id": case_id, "outcome": analysis.explained["decision"].get("outcome")}

        def cleanup_on_failure(control: JobControl) -> dict[str, Any]:
            try:
                return work(control)
            finally:
                if staging.exists():
                    shutil.rmtree(staging, ignore_errors=True)

        job = jobs.submit("upload", None, current.user_id, cleanup_on_failure)
        return {"job": job, "received_bytes": received}

    @app.get("/api/jobs/{job_id}")
    def job(job_id: str, current: User = Depends(user)) -> dict[str, Any]:
        if not JOB_ID.match(job_id):
            raise HTTPException(404, "Job not found")
        data = jobs.get(job_id)
        if data is None or not _job_visible(data, current, auth):
            raise HTTPException(404, "Job not found")
        return {
            k: data[k]
            for k in ("id", "kind", "case_id", "status", "progress", "note", "created", "started", "finished", "error", "result")
        }

    @app.post("/api/jobs/{job_id}/cancel")
    def cancel_job(job_id: str, current: User = Depends(user)) -> dict[str, Any]:
        if not JOB_ID.match(job_id):
            raise HTTPException(404, "Job not found")
        data = jobs.get(job_id)
        if (
            data is None
            or not _job_visible(data, current, auth)
            or not (current.role == "admin" or data["user_id"] == current.user_id)
        ):
            raise HTTPException(404, "Job not found")
        return {"cancelled": jobs.cancel(job_id)}

    @app.get("/api/evaluation")
    def evaluation(current: User = Depends(user)) -> dict[str, Any]:
        data = workspace.evaluation()
        if data is None:
            raise HTTPException(404, "Evaluation results have not been generated")
        return data

    if config.tile_dir:
        tile_root = Path(config.tile_dir).resolve()

        @app.get("/tiles/{z}/{x}/{y}.png", include_in_schema=False)
        def tile(z: int, x: int, y: int, current: User = Depends(user)) -> Response:
            path = (tile_root / str(z) / str(x) / f"{y}.png").resolve()
            if tile_root not in path.parents or not path.is_file():
                return Response(status_code=404)
            return FileResponse(path, media_type="image/png")

    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html")

    return app


def _require(current: User, permission: str) -> None:
    if not current.can(permission):
        raise HTTPException(403, "Your role does not allow this")


def _job_visible(data: dict[str, Any], current: User, auth: AuthStore) -> bool:
    if current.role == "admin" or data.get("user_id") == current.user_id:
        return True
    return bool(data.get("case_id")) and auth.can_access(current, data["case_id"])


def readiness_checks(workspace: Workspace, auth: AuthStore, jobs: JobManager) -> dict[str, dict[str, Any]]:
    checks: dict[str, dict[str, Any]] = {}
    probe = workspace.data.root / f".ready-{uuid.uuid4().hex}"
    try:
        probe.write_bytes(b"ok")
        ok = probe.read_bytes() == b"ok"
        probe.unlink()
        checks["storage"] = {"ok": ok}
    except OSError:
        checks["storage"] = {"ok": False, "message": "The data directory is not writable"}
    try:
        auth.user_count()
        jobs.get("0" * 32)
        checks["database"] = {"ok": True}
    except Exception:
        checks["database"] = {"ok": False, "message": "The database is not available"}
    try:
        validate_configuration()
        checks["configuration"] = {"ok": True}
    except Exception:
        checks["configuration"] = {"ok": False, "message": "The configuration or crime templates are invalid"}
    checks["signing_key"] = {"ok": workspace.signer is not None}
    checks["cases_directory"] = {"ok": workspace.data.cases.is_dir()}
    checks["users"] = {"ok": True, "bootstrapped": auth.user_count() > 0}
    return checks


_INSTANCE: dict[str, FastAPI] = {}


def __getattr__(name: str) -> Any:
    if name == "app":
        if "app" not in _INSTANCE:
            _INSTANCE["app"] = create_app()
        return _INSTANCE["app"]
    raise AttributeError(name)
