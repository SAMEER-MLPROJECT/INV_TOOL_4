from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

ROLES = ("admin", "investigator", "reviewer", "auditor")
PERMISSIONS: dict[str, set[str]] = {
    "admin": {"view", "act", "upload", "report", "export", "audit", "manage", "import"},
    "investigator": {"view", "act", "upload", "report", "export", "import"},
    "reviewer": {"view", "report"},
    "auditor": {"view", "audit"},
}
USERNAME = re.compile(r"^[a-z0-9][a-z0-9._-]{2,39}$")
MIN_PASSWORD = 12


class AuthError(Exception):
    def __init__(self, message: str, status: int = 401) -> None:
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class User:
    user_id: int
    username: str
    role: str
    display_name: str

    def can(self, permission: str) -> bool:
        return permission in PERMISSIONS.get(self.role, set())

    def public(self) -> dict[str, Any]:
        return {
            "id": self.user_id,
            "username": self.username,
            "role": self.role,
            "display_name": self.display_name,
            "permissions": sorted(PERMISSIONS.get(self.role, set())),
        }

    def actor(self) -> dict[str, Any]:
        return {"user_id": self.user_id, "username": self.username, "role": self.role}


@dataclass(frozen=True)
class Session:
    user: User
    token_hash: str
    csrf: str
    expires: float


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class AuthStore:
    def __init__(self, database: Path, session_hours: float = 8.0, idle_minutes: float = 60.0) -> None:
        self.database = database
        self.session_s = session_hours * 3600.0
        self.idle_s = idle_minutes * 60.0
        self.hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
        self._lock = threading.Lock()
        self._init()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _init(self) -> None:
        with self._connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    display_name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    created REAL NOT NULL,
                    disabled INTEGER NOT NULL DEFAULT 0,
                    failed_logins INTEGER NOT NULL DEFAULT 0,
                    locked_until REAL NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    csrf TEXT NOT NULL,
                    created REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    expires REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS case_access (
                    case_id TEXT NOT NULL,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    granted_by INTEGER,
                    granted REAL NOT NULL,
                    PRIMARY KEY (case_id, user_id)
                );
                CREATE TABLE IF NOT EXISTS case_owner (
                    case_id TEXT PRIMARY KEY,
                    user_id INTEGER,
                    bytes INTEGER NOT NULL DEFAULT 0,
                    created REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS idempotency (
                    key TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    case_id TEXT NOT NULL,
                    action_id TEXT,
                    created REAL NOT NULL
                );
                """
            )

    def user_count(self) -> int:
        with self._connect() as db:
            return int(db.execute("SELECT COUNT(*) FROM users").fetchone()[0])

    def create_user(self, username: str, password: str, role: str, display_name: str | None = None) -> User:
        username = username.strip().lower()
        if not USERNAME.match(username):
            raise AuthError("Usernames use 3 to 40 lower case letters, digits, '.', '_' or '-'", 422)
        if role not in ROLES:
            raise AuthError(f"Role must be one of {', '.join(ROLES)}", 422)
        check_password(password, username)
        digest = self.hasher.hash(password)
        name = (display_name or username).strip()[:80] or username
        try:
            with self._connect() as db:
                cursor = db.execute(
                    "INSERT INTO users (username, display_name, role, password_hash, created) VALUES (?,?,?,?,?)",
                    (username, name, role, digest, time.time()),
                )
        except sqlite3.IntegrityError as exc:
            raise AuthError("That username is already taken", 409) from exc
        return User(int(cursor.lastrowid), username, role, name)

    def bootstrap_admin(self, username: str, password: str, display_name: str | None = None) -> User:
        with self._lock:
            if self.user_count():
                raise AuthError("The first administrator has already been created", 409)
            return self.create_user(username, password, "admin", display_name)

    def set_password(self, user_id: int, password: str) -> None:
        user = self.user(user_id)
        if user is None:
            raise AuthError("User not found", 404)
        check_password(password, user.username)
        with self._connect() as db:
            db.execute("UPDATE users SET password_hash=? WHERE id=?", (self.hasher.hash(password), user_id))
            db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))

    def set_disabled(self, user_id: int, disabled: bool) -> None:
        with self._connect() as db:
            db.execute("UPDATE users SET disabled=? WHERE id=?", (1 if disabled else 0, user_id))
            if disabled:
                db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))

    def set_role(self, user_id: int, role: str) -> None:
        if role not in ROLES:
            raise AuthError(f"Role must be one of {', '.join(ROLES)}", 422)
        with self._connect() as db:
            db.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))

    def user(self, user_id: int) -> User | None:
        with self._connect() as db:
            row = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return User(row["id"], row["username"], row["role"], row["display_name"]) if row else None

    def users(self) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute("SELECT id, username, display_name, role, disabled, created FROM users ORDER BY id").fetchall()
        return [dict(row) for row in rows]

    def login(self, username: str, password: str) -> tuple[str, Session]:
        username = (username or "").strip().lower()
        with self._connect() as db:
            row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        now = time.time()
        if row is None:
            self.hasher.hash(password or "x")
            raise AuthError("Wrong username or password")
        if row["disabled"]:
            raise AuthError("Wrong username or password")
        if row["locked_until"] > now:
            raise AuthError("Too many failed attempts; try again later", 429)
        try:
            self.hasher.verify(row["password_hash"], password or "")
        except (VerifyMismatchError, VerificationError, InvalidHashError) as exc:
            failures = row["failed_logins"] + 1
            locked = now + 900 if failures >= 5 else 0
            with self._connect() as db:
                db.execute(
                    "UPDATE users SET failed_logins=?, locked_until=? WHERE id=?",
                    (0 if locked else failures, locked, row["id"]),
                )
            raise AuthError("Wrong username or password") from exc
        updates: list[tuple[str, Any]] = [("failed_logins", 0), ("locked_until", 0)]
        if self.hasher.check_needs_rehash(row["password_hash"]):
            updates.append(("password_hash", self.hasher.hash(password)))
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(24)
        expires = now + self.session_s
        with self._connect() as db:
            for column, value in updates:
                db.execute(f"UPDATE users SET {column}=? WHERE id=?", (value, row["id"]))
            db.execute("DELETE FROM sessions WHERE expires < ?", (now,))
            db.execute(
                "INSERT INTO sessions (token_hash, user_id, csrf, created, last_seen, expires) VALUES (?,?,?,?,?,?)",
                (_hash_token(token), row["id"], csrf, now, now, expires),
            )
        user = User(row["id"], row["username"], row["role"], row["display_name"])
        return token, Session(user, _hash_token(token), csrf, expires)

    def session(self, token: str | None) -> Session | None:
        if not token or len(token) > 200:
            return None
        token_hash = _hash_token(token)
        now = time.time()
        with self._connect() as db:
            row = db.execute(
                "SELECT s.*, u.username, u.role, u.display_name, u.disabled FROM sessions s JOIN users u ON u.id = s.user_id "
                "WHERE s.token_hash=?",
                (token_hash,),
            ).fetchone()
            if row is None:
                return None
            if row["disabled"] or row["expires"] < now or now - row["last_seen"] > self.idle_s:
                db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
                return None
            if now - row["last_seen"] > 30:
                db.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (now, token_hash))
        user = User(row["user_id"], row["username"], row["role"], row["display_name"])
        return Session(user, token_hash, row["csrf"], row["expires"])

    def logout(self, token_hash: str) -> None:
        with self._connect() as db:
            db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))

    def revoke_user_sessions(self, user_id: int) -> int:
        with self._connect() as db:
            return db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,)).rowcount

    def grant(self, case_id: str, user_id: int, granted_by: int | None) -> None:
        with self._connect() as db:
            db.execute(
                "INSERT OR IGNORE INTO case_access (case_id, user_id, granted_by, granted) VALUES (?,?,?,?)",
                (case_id, user_id, granted_by, time.time()),
            )

    def revoke(self, case_id: str, user_id: int) -> None:
        with self._connect() as db:
            db.execute("DELETE FROM case_access WHERE case_id=? AND user_id=?", (case_id, user_id))

    def can_access(self, user: User, case_id: str) -> bool:
        if user.role == "admin":
            return True
        with self._connect() as db:
            row = db.execute("SELECT 1 FROM case_access WHERE case_id=? AND user_id=?", (case_id, user.user_id)).fetchone()
        return row is not None

    def accessible(self, user: User, case_ids: list[str]) -> list[str]:
        if user.role == "admin":
            return list(case_ids)
        with self._connect() as db:
            rows = db.execute("SELECT case_id FROM case_access WHERE user_id=?", (user.user_id,)).fetchall()
        allowed = {row["case_id"] for row in rows}
        return [c for c in case_ids if c in allowed]

    def access_list(self, case_id: str) -> list[dict[str, Any]]:
        with self._connect() as db:
            rows = db.execute(
                "SELECT u.id, u.username, u.role, a.granted FROM case_access a JOIN users u ON u.id = a.user_id "
                "WHERE a.case_id=? ORDER BY u.username",
                (case_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def set_owner(self, case_id: str, user_id: int | None, size: int) -> None:
        with self._connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO case_owner (case_id, user_id, bytes, created) VALUES (?,?,?,?)",
                (case_id, user_id, size, time.time()),
            )

    def usage(self, user_id: int) -> tuple[int, int]:
        with self._connect() as db:
            row = db.execute("SELECT COUNT(*), COALESCE(SUM(bytes), 0) FROM case_owner WHERE user_id=?", (user_id,)).fetchone()
        return int(row[0]), int(row[1])

    def reserve(self, key: str, user_id: int, case_id: str) -> str | None:
        with self._lock, self._connect() as db:
            row = db.execute("SELECT action_id, user_id, case_id FROM idempotency WHERE key=?", (key,)).fetchone()
            if row is not None:
                if row["user_id"] != user_id or row["case_id"] != case_id:
                    raise AuthError("Idempotency key was already used for another request", 409)
                return row["action_id"] or "pending"
            db.execute(
                "INSERT INTO idempotency (key, user_id, case_id, action_id, created) VALUES (?,?,?,?,?)",
                (key, user_id, case_id, None, time.time()),
            )
        return None

    def complete(self, key: str, action_id: str) -> None:
        with self._connect() as db:
            db.execute("UPDATE idempotency SET action_id=? WHERE key=?", (action_id, key))

    def release(self, key: str) -> None:
        with self._connect() as db:
            db.execute("DELETE FROM idempotency WHERE key=? AND action_id IS NULL", (key,))


def check_password(password: str, username: str) -> None:
    if not isinstance(password, str) or len(password) < MIN_PASSWORD:
        raise AuthError(f"Passwords need at least {MIN_PASSWORD} characters", 422)
    if len(password) > 256:
        raise AuthError("Password is too long", 422)
    if username and username.lower() in password.lower():
        raise AuthError("The password must not contain the username", 422)
    if len(set(password)) < 6:
        raise AuthError("The password is too repetitive", 422)


def same_secret(a: str | None, b: str | None) -> bool:
    if not a or not b:
        return False
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
