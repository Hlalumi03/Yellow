from __future__ import annotations

import hashlib
import html
import hmac
import json
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Iterator, TypedDict
from urllib.parse import parse_qs


PROJECT_PATH = Path(__file__).resolve().parent.parent
DATABASE_PATH = PROJECT_PATH / "accounts.sqlite3"
LEGACY_STORE_PATH = PROJECT_PATH / "auth.json"
FRONTEND_PATH = PROJECT_PATH / "frontend"
SESSION_COOKIE = "auth_session"
SESSION_LIFETIME = 7 * 24 * 60 * 60
PASSWORD_ITERATIONS = 310_000
MAX_REQUEST_SIZE = 16_384


class UserRecord(TypedDict):
    id: str
    name: str
    surname: str
    email: str
    password_hash: str
    created_at: int


@contextmanager
def database() -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(DATABASE_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def user_from_row(row: sqlite3.Row) -> UserRecord:
    return {
        "id": row["id"],
        "name": row["name"],
        "surname": row["surname"],
        "email": row["email"],
        "password_hash": row["password_hash"],
        "created_at": row["created_at"],
    }


def get_user_by_id(user_id: str) -> UserRecord | None:
    with database() as connection:
        row = connection.execute(
            "SELECT id, name, surname, email, password_hash, created_at "
            "FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    return user_from_row(row) if row else None


def get_user_by_email(email: str) -> UserRecord | None:
    with database() as connection:
        row = connection.execute(
            "SELECT id, name, surname, email, password_hash, created_at "
            "FROM users WHERE email = ?",
            (email,),
        ).fetchone()
    return user_from_row(row) if row else None


def create_user(user: UserRecord) -> bool:
    try:
        with database() as connection:
            connection.execute(
                "INSERT INTO users "
                "(id, name, surname, email, password_hash, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    user["id"],
                    user["name"],
                    user["surname"],
                    user["email"],
                    user["password_hash"],
                    user["created_at"],
                ),
            )
    except sqlite3.IntegrityError:
        return False
    return True


def get_session(token_hash: str, now: int) -> sqlite3.Row | None:
    with database() as connection:
        return connection.execute(
            "SELECT token_hash, csrf_token, user_id, expires_at "
            "FROM sessions WHERE token_hash = ? AND expires_at > ?",
            (token_hash, now),
        ).fetchone()


def create_session(
    token_hash: str,
    csrf_token: str,
    user_id: str | None,
    expires_at: int,
) -> None:
    with database() as connection:
        connection.execute(
            "DELETE FROM sessions WHERE expires_at <= ?",
            (int(time.time()),),
        )
        connection.execute(
            "INSERT INTO sessions (token_hash, csrf_token, user_id, expires_at) "
            "VALUES (?, ?, ?, ?)",
            (token_hash, csrf_token, user_id, expires_at),
        )


def delete_session(token_hash: str) -> None:
    with database() as connection:
        connection.execute(
            "DELETE FROM sessions WHERE token_hash = ?",
            (token_hash,),
        )


def initialize_store() -> None:
    with database() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                surname TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                csrf_token TEXT NOT NULL,
                user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS sessions_expires_at_idx
                ON sessions(expires_at);
            CREATE TABLE IF NOT EXISTS app_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        imported = connection.execute(
            "SELECT 1 FROM app_metadata WHERE key = 'legacy_json_imported'"
        ).fetchone()
        if not imported and LEGACY_STORE_PATH.exists():
            with LEGACY_STORE_PATH.open("r", encoding="utf-8") as store_file:
                legacy_store = json.load(store_file)
            if (
                not isinstance(legacy_store, dict)
                or legacy_store.get("version") != 1
                or not isinstance(legacy_store.get("users"), list)
                or not isinstance(legacy_store.get("sessions"), list)
            ):
                raise ValueError(f"Invalid account data format in {LEGACY_STORE_PATH}")
            users = legacy_store["users"]
            sessions = legacy_store["sessions"]
            if any(
                not isinstance(user, dict)
                or any(
                    not isinstance(user.get(field), str)
                    for field in ("id", "name", "surname", "email", "password_hash")
                )
                or not isinstance(user.get("created_at"), int)
                for user in users
            ) or any(
                not isinstance(session, dict)
                or any(
                    not isinstance(session.get(field), str)
                    for field in ("token_hash", "csrf_token")
                )
                or (
                    session.get("user_id") is not None
                    and not isinstance(session.get("user_id"), str)
                )
                or not isinstance(session.get("expires_at"), int)
                for session in sessions
            ):
                raise ValueError(f"Invalid account record in {LEGACY_STORE_PATH}")

            connection.executemany(
                "INSERT INTO users "
                "(id, name, surname, email, password_hash, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                [
                    (
                        user["id"],
                        user["name"],
                        user["surname"],
                        user["email"],
                        user["password_hash"],
                        user["created_at"],
                    )
                    for user in users
                ],
            )
            now = int(time.time())
            connection.executemany(
                "INSERT INTO sessions "
                "(token_hash, csrf_token, user_id, expires_at) VALUES (?, ?, ?, ?)",
                [
                    (
                        session["token_hash"],
                        session["csrf_token"],
                        session["user_id"],
                        session["expires_at"],
                    )
                    for session in sessions
                    if session["expires_at"] > now
                ],
            )
            connection.execute(
                "INSERT INTO app_metadata (key, value) "
                "VALUES ('legacy_json_imported', '1')"
            )
        connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (int(time.time()),))


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return f"{salt.hex()}:{digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, expected_hex = stored_hash.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(expected_hex)
    except ValueError:
        return False
    actual = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return hmac.compare_digest(actual, expected)


DUMMY_PASSWORD_HASH = hash_password("not-a-real-user-password")


def escape(value: str) -> str:
    return html.escape(value, quote=True)


def render_template(template_name: str, **values: str) -> str:
    template_path = FRONTEND_PATH / template_name
    template = template_path.read_text(encoding="utf-8")
    for key, value in values.items():
        template = template.replace("{{" + key + "}}", value)
    return template


def page(title: str, content: str) -> bytes:
    return render_template(
        "base.html",
        title=escape(title),
        content=content,
    ).encode("utf-8")


def alert(message: str, kind: str = "danger") -> str:
    return render_template(
        "alert.html",
        kind=escape(kind),
        message=escape(message),
    )


def signup_page(csrf_token: str, message: str = "", values: dict[str, str] | None = None) -> bytes:
    values = values or {}
    notice = alert(message) if message else ""
    content = render_template(
        "signup.html",
        csrf_token=escape(csrf_token),
        notice=notice,
        name=escape(values.get("name", "")),
        surname=escape(values.get("surname", "")),
        email=escape(values.get("email", "")),
    )
    return page("Sign up", content)


def signin_page(csrf_token: str, message: str = "", email: str = "") -> bytes:
    notice = alert(message) if message else ""
    content = render_template(
        "signin.html",
        csrf_token=escape(csrf_token),
        notice=notice,
        email=escape(email),
    )
    return page("Sign in", content)


def dashboard_page(user: UserRecord, csrf_token: str) -> bytes:
    content = render_template(
        "home.html",
        csrf_token=escape(csrf_token),
        name=escape(user["name"]),
        email=escape(user["email"]),
    )
    return content.encode("utf-8")


class AuthHandler(BaseHTTPRequestHandler):
    server_version = "AccountApp"

    def _session(self) -> tuple[str, str, str | None, bool]:
        cookie = SimpleCookie()
        cookie.load(self.headers.get("Cookie", ""))
        morsel = cookie.get(SESSION_COOKIE)
        token = morsel.value if morsel else ""
        now = int(time.time())
        token_hash = hashlib.sha256(token.encode("ascii", errors="ignore")).hexdigest()

        if token:
            session = get_session(token_hash, now)
            if session:
                return token, session["csrf_token"], session["user_id"], False

        token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        create_session(
            hashlib.sha256(token.encode("ascii")).hexdigest(),
            csrf_token,
            None,
            now + SESSION_LIFETIME,
        )
        return token, csrf_token, None, True

    def _csrf_matches(self, csrf_token: str, form: dict[str, list[str]]) -> bool:
        submitted = form.get("csrf_token", [""])[0]
        if not submitted or not submitted.isascii():
            return False
        return hmac.compare_digest(csrf_token, submitted)

    def _send(
        self,
        status: HTTPStatus,
        body: bytes = b"",
        *,
        token: str | None = None,
        clear_cookie: bool = False,
        content_type: str = "text/html; charset=utf-8",
        location: str | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' https://cdn.jsdelivr.net; "
            "form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        )
        if token is not None:
            self.send_header(
                "Set-Cookie",
                f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; "
                f"Max-Age={SESSION_LIFETIME}",
            )
        elif clear_cookie:
            self.send_header(
                "Set-Cookie",
                f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
            )
        if location:
            self.send_header("Location", location)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _redirect(
        self,
        location: str,
        token: str | None = None,
        *,
        clear_cookie: bool = False,
    ) -> None:
        self._send(
            HTTPStatus.SEE_OTHER,
            token=token,
            clear_cookie=clear_cookie,
            location=location,
        )

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/style.css":
            stylesheet = (FRONTEND_PATH / "style.css").read_bytes()
            self._send(
                HTTPStatus.OK,
                stylesheet,
                content_type="text/css; charset=utf-8",
            )
            return

        token, csrf_token, user_id, is_new = self._session()

        if path == "/":
            self._redirect("/account" if user_id is not None else "/signup", token if is_new else None)
        elif path in ("/signup", "/signin"):
            if user_id is not None:
                self._redirect("/account", token if is_new else None)
            elif path == "/signup":
                self._send(HTTPStatus.OK, signup_page(csrf_token), token=token if is_new else None)
            else:
                self._send(HTTPStatus.OK, signin_page(csrf_token), token=token if is_new else None)
        elif path == "/account":
            if user_id is None:
                self._redirect("/signin", token if is_new else None)
                return
            user = get_user_by_id(user_id)
            if user is None:
                self._redirect("/signin", token if is_new else None)
                return
            self._send(
                HTTPStatus.OK,
                dashboard_page(user, csrf_token),
                token=token if is_new else None,
            )
        else:
            self._send(HTTPStatus.NOT_FOUND, page("Not found", alert("Page not found.")))

    def do_POST(self) -> None:
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = MAX_REQUEST_SIZE + 1
        if content_length < 0 or content_length > MAX_REQUEST_SIZE:
            self._send(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                page("Request too large", alert("The submitted form is too large.")),
            )
            return

        body = self.rfile.read(content_length)
        form = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
        token, csrf_token, user_id, is_new = self._session()
        if is_new or not self._csrf_matches(csrf_token, form):
            self._send(
                HTTPStatus.FORBIDDEN,
                page("Form expired", alert("This form has expired. Please reload and try again.")),
                token=token if is_new else None,
            )
            return

        path = self.path.split("?", 1)[0]
        if path == "/signup":
            self._signup(form, token)
        elif path == "/signin":
            self._signin(form, token)
        elif path == "/logout":
            if user_id is None:
                self._redirect("/signin")
                return
            token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
            delete_session(token_hash)
            self._redirect("/signin", clear_cookie=True)
        else:
            self._send(HTTPStatus.NOT_FOUND, page("Not found", alert("Page not found.")))

    def _signup(self, form: dict[str, list[str]], token: str) -> None:
        name = form.get("name", [""])[0].strip()
        surname = form.get("surname", [""])[0].strip()
        email = form.get("email", [""])[0].strip().lower()
        password = form.get("password", [""])[0]
        values = {"name": name, "surname": surname, "email": email}

        if (
            not name
            or len(name) > 80
            or not surname
            or len(surname) > 80
            or len(email) > 254
            or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email)
            or len(password) < 8
            or len(password) > 1024
        ):
            self._render_signup_error(
                token,
                "Check the fields and try again. Passwords must be at least 8 characters.",
                values,
            )
            return

        user_id = secrets.token_urlsafe(16)
        user: UserRecord = {
            "id": user_id,
            "name": name,
            "surname": surname,
            "email": email,
            "password_hash": hash_password(password),
            "created_at": int(time.time()),
        }
        if not create_user(user):
            self._render_signup_error(token, "An account with that email already exists.", values)
            return
        new_token = self._replace_session(token, user_id)
        self._redirect("/account", new_token)

    def _render_signup_error(self, token: str, message: str, values: dict[str, str]) -> None:
        csrf_token = self._rotate_csrf(token)
        self._send(
            HTTPStatus.BAD_REQUEST,
            signup_page(csrf_token, message, values),
            token=token,
        )

    def _signin(self, form: dict[str, list[str]], token: str) -> None:
        email = form.get("email", [""])[0].strip().lower()
        password = form.get("password", [""])[0]
        user = get_user_by_email(email)

        stored_hash = user["password_hash"] if user else DUMMY_PASSWORD_HASH
        password_is_valid = verify_password(password[:1024], stored_hash)
        if not user or not password_is_valid or len(password) > 1024:
            csrf_token = self._rotate_csrf(token)
            self._send(
                HTTPStatus.UNAUTHORIZED,
                signin_page(csrf_token, "Email or password is incorrect.", email),
                token=token,
            )
            return

        new_token = self._replace_session(token, user["id"])
        self._redirect("/account", new_token)

    def _rotate_csrf(self, token: str) -> str:
        csrf_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
        with database() as connection:
            connection.execute(
                "UPDATE sessions SET csrf_token = ? WHERE token_hash = ?",
                (csrf_token, token_hash),
            )
        return csrf_token

    def _replace_session(self, old_token: str, user_id: str) -> str:
        new_token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        old_hash = hashlib.sha256(old_token.encode("ascii")).hexdigest()
        with database() as connection:
            connection.execute(
                "DELETE FROM sessions WHERE token_hash = ?",
                (old_hash,),
            )
            connection.execute(
                "INSERT INTO sessions (token_hash, csrf_token, user_id, expires_at) "
                "VALUES (?, ?, ?, ?)",
                (
                    hashlib.sha256(new_token.encode("ascii")).hexdigest(),
                    csrf_token,
                    user_id,
                    int(time.time()) + SESSION_LIFETIME,
                ),
            )
        return new_token
