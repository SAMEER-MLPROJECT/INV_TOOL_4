from __future__ import annotations

import ipaddress
import os
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urlparse

from starlette.requests import Request

RATE_DEFAULTS = {
    "login": (10, 300),
    "upload": (10, 3600),
    "analysis": (30, 3600),
    "report": (60, 3600),
    "export": (60, 3600),
    "action": (240, 3600),
    "api": (1200, 60),
}


def _flag(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _networks(text: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks = []
    for part in text.split(","):
        part = part.strip()
        if part:
            networks.append(ipaddress.ip_network(part, strict=False))
    return networks


@dataclass
class ServiceConfig:
    environment: str = "local"
    cookie_secure: bool = True
    trusted_proxies: list = field(default_factory=list)
    tile_url: str = ""
    tile_dir: str = ""
    docs_enabled: bool = True
    bootstrap_token: str = ""
    demo_open: bool = False
    max_upload_mb: int = 25
    max_uncompressed_mb: int = 200
    max_entries: int = 400
    max_ratio: float = 100.0
    max_depth: int = 8
    user_quota_mb: int = 1024
    user_case_limit: int = 200
    workers: int = 2
    job_timeout_s: float = 600.0
    session_hours: float = 8.0
    idle_minutes: float = 60.0
    rates: dict[str, tuple[int, int]] = field(default_factory=lambda: dict(RATE_DEFAULTS))

    @classmethod
    def from_env(cls) -> ServiceConfig:
        environment = os.environ.get("SAKSHYA_ENV", "local").strip().lower()
        production = environment == "production"
        rates = dict(RATE_DEFAULTS)
        for name in rates:
            raw = os.environ.get(f"SAKSHYA_RATE_{name.upper()}")
            if raw and "/" in raw:
                count, window = raw.split("/", 1)
                rates[name] = (int(count), int(window))
        return cls(
            environment=environment,
            cookie_secure=_flag("SAKSHYA_COOKIE_SECURE", True),
            trusted_proxies=_networks(os.environ.get("SAKSHYA_TRUSTED_PROXIES", "")),
            tile_url=os.environ.get("SAKSHYA_MAP_TILE_URL", "").strip(),
            tile_dir=os.environ.get("SAKSHYA_MAP_TILE_DIR", "").strip(),
            docs_enabled=_flag("SAKSHYA_API_DOCS", not production),
            bootstrap_token=os.environ.get("SAKSHYA_BOOTSTRAP_TOKEN", "").strip(),
            demo_open=_flag("SAKSHYA_DEMO_OPEN", False),
            max_upload_mb=int(os.environ.get("SAKSHYA_MAX_UPLOAD_MB", "25")),
            max_uncompressed_mb=int(os.environ.get("SAKSHYA_MAX_UNCOMPRESSED_MB", "200")),
            max_entries=int(os.environ.get("SAKSHYA_MAX_ARCHIVE_ENTRIES", "400")),
            max_ratio=float(os.environ.get("SAKSHYA_MAX_COMPRESSION_RATIO", "100")),
            user_quota_mb=int(os.environ.get("SAKSHYA_USER_QUOTA_MB", "1024")),
            user_case_limit=int(os.environ.get("SAKSHYA_USER_CASE_LIMIT", "200")),
            workers=int(os.environ.get("SAKSHYA_WORKERS", "2")),
            job_timeout_s=float(os.environ.get("SAKSHYA_JOB_TIMEOUT_S", "600")),
            session_hours=float(os.environ.get("SAKSHYA_SESSION_HOURS", "8")),
            idle_minutes=float(os.environ.get("SAKSHYA_IDLE_MINUTES", "60")),
            rates=rates,
        )

    def tile_origin(self) -> str:
        if not self.tile_url:
            return ""
        parsed = urlparse(self.tile_url.replace("{s}", "a").replace("{z}", "0").replace("{x}", "0").replace("{y}", "0"))
        return f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme in {"https", "http"} and parsed.netloc else ""

    def map_mode(self) -> dict[str, str]:
        if self.tile_dir:
            return {"mode": "local", "url": "/tiles/{z}/{x}/{y}.png", "notice": "Map tiles are served by this server"}
        if self.tile_url and self.tile_origin():
            return {
                "mode": "remote",
                "url": self.tile_url,
                "notice": f"Map tiles are fetched from {self.tile_origin()}, which can see which areas are viewed",
            }
        return {"mode": "none", "url": "", "notice": "No base map is loaded, so no location leaves this server"}

    def content_security_policy(self) -> str:
        images = ["'self'", "data:", "blob:"]
        origin = self.tile_origin()
        if origin and not self.tile_dir:
            images.append(origin)
        return "; ".join(
            [
                "default-src 'none'",
                "script-src 'self'",
                "style-src 'self'",
                f"img-src {' '.join(images)}",
                "font-src 'self'",
                "connect-src 'self'",
                "worker-src 'self' blob:",
                "manifest-src 'self'",
                "base-uri 'none'",
                "form-action 'self'",
                "frame-ancestors 'none'",
                "object-src 'none'",
            ]
        )


def client_ip(request: Request, trusted: list) -> str:
    peer = request.client.host if request.client else ""
    try:
        address = ipaddress.ip_address(peer)
    except ValueError:
        return peer or "unknown"
    if not trusted or not any(address in network for network in trusted):
        return str(address)
    forwarded = request.headers.get("x-forwarded-for", "")
    hops = [h.strip() for h in forwarded.split(",") if h.strip()]
    for hop in reversed(hops):
        try:
            candidate = ipaddress.ip_address(hop)
        except ValueError:
            return str(address)
        if not any(candidate in network for network in trusted):
            return str(candidate)
    return str(address)


class RateLimiter:
    def __init__(self, rates: dict[str, tuple[int, int]]) -> None:
        self.rates = rates
        self._hits: dict[tuple[str, str], deque] = {}
        self._lock = threading.Lock()

    def check(self, category: str, principal: str) -> float | None:
        limit, window = self.rates.get(category, (0, 0))
        if limit <= 0:
            return None
        now = time.monotonic()
        key = (category, principal)
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and now - hits[0] > window:
                hits.popleft()
            if len(hits) >= limit:
                return max(1.0, window - (now - hits[0]))
            hits.append(now)
            if len(self._hits) > 50000:
                self._hits = {k: v for k, v in self._hits.items() if v and now - v[-1] < 3600}
        return None
