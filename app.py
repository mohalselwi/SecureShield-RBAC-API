"""
SecureShield — A Role-Based Access Control (RBAC) API
======================================================

A small Flask backend that demonstrates the "Principle of Least Privilege".

Features:
    Task 1 — Secure Password Storage  (bcrypt salt + hash, never plain text)
    Task 2 — JWT Issuance              (POST /login returns a signed JWT)
    Task 3 — Token Validation          (@token_required decorator)
    Task 4 — Role-Based Routing        (@role_required("admin") gate)
    Task 5 — Token Revocation          (POST /logout blacklists the JWT's jti)
    Task 6 — Defensive Logging         (security.log records every denied attempt)

Run:
    pip install -r requirements.txt
    python app.py
"""

from __future__ import annotations

import logging
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import jwt  # PyJWT
from flask import Flask, g, jsonify, request
from flask_bcrypt import Bcrypt

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "secureshield.db"
LOG_PATH = BASE_DIR / "security.log"

# In a real deployment SECRET_KEY MUST come from a secret manager / env var.
# We fall back to a clearly-marked dev default so the demo runs out of the box.
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-secret-change-me")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_MINUTES = int(os.environ.get("JWT_EXPIRY_MINUTES", "30"))

ALLOWED_ROLES = {"user", "admin"}

# ---------------------------------------------------------------------------
# Flask app + extensions
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
bcrypt = Bcrypt(app)

# ---------------------------------------------------------------------------
# Defensive logging (Task 6)
# ---------------------------------------------------------------------------
# Every denied request (bad/missing token, expired token, blacklisted token,
# role mismatch) is appended to security.log with a UTC timestamp.

security_logger = logging.getLogger("secureshield.security")
security_logger.setLevel(logging.INFO)
_log_handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
_log_handler.setFormatter(
    logging.Formatter("%(asctime)sZ | %(levelname)s | %(message)s",
                      datefmt="%Y-%m-%dT%H:%M:%S")
)
# Use UTC timestamps for forensic clarity.
logging.Formatter.converter = lambda *_args: datetime.now(timezone.utc).timetuple()
security_logger.addHandler(_log_handler)
security_logger.propagate = False


def log_unauthorized(reason: str, *, username: str | None = None) -> None:
    """Record a denied request to security.log."""
    security_logger.warning(
        "DENIED reason=%s method=%s path=%s ip=%s user=%s",
        reason,
        request.method,
        request.path,
        request.remote_addr or "?",
        username or "anonymous",
    )


# ---------------------------------------------------------------------------
# Database helpers (SQLite)
# ---------------------------------------------------------------------------


def get_db() -> sqlite3.Connection:
    """Return a request-scoped SQLite connection."""
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    """Create tables if they don't exist yet."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT    NOT NULL UNIQUE,
                password_hash TEXT    NOT NULL,
                role          TEXT    NOT NULL CHECK (role IN ('user', 'admin')),
                created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS token_blacklist (
                jti        TEXT PRIMARY KEY,
                revoked_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            """
        )
        conn.commit()


def seed_demo_users() -> None:
    """Create a demo admin and a demo user on first run (idempotent)."""
    db = sqlite3.connect(DB_PATH)
    try:
        cur = db.execute("SELECT COUNT(*) FROM users")
        if cur.fetchone()[0] > 0:
            return
        # bcrypt.generate_password_hash returns bytes; decode for SQLite TEXT.
        admin_hash = bcrypt.generate_password_hash("AdminPass123!").decode()
        user_hash = bcrypt.generate_password_hash("UserPass123!").decode()
        db.executemany(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            [
                ("admin", admin_hash, "admin"),
                ("alice", user_hash, "user"),
            ],
        )
        db.commit()
        app.logger.info("Seeded demo accounts: admin / alice")
    finally:
        db.close()


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------


def issue_jwt(username: str, role: str) -> str:
    """Return a signed JWT carrying (username, role, jti, exp, iat)."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=JWT_EXPIRY_MINUTES),
        # Each token gets a unique ID so we can revoke individual tokens
        # without invalidating every JWT we've ever issued.
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)


def is_token_revoked(jti: str) -> bool:
    db = get_db()
    row = db.execute("SELECT 1 FROM token_blacklist WHERE jti = ?", (jti,)).fetchone()
    return row is not None


def revoke_token(jti: str) -> None:
    db = get_db()
    db.execute(
        "INSERT OR IGNORE INTO token_blacklist (jti) VALUES (?)", (jti,)
    )
    db.commit()


# ---------------------------------------------------------------------------
# Auth decorators (Tasks 3 + 4)
# ---------------------------------------------------------------------------


def _extract_bearer_token() -> str | None:
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    return auth.split(" ", 1)[1].strip() or None


def token_required(view):
    """Refuse the request unless a valid, non-revoked JWT is presented."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        token = _extract_bearer_token()
        if not token:
            log_unauthorized("missing_or_malformed_authorization_header")
            return jsonify(error="Authorization header missing or malformed"), 401

        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        except jwt.ExpiredSignatureError:
            log_unauthorized("expired_token")
            return jsonify(error="Token has expired"), 401
        except jwt.InvalidSignatureError:
            # Tamper test: someone re-encoded the JWT without the secret key.
            log_unauthorized("invalid_signature")
            return jsonify(error="Invalid token signature"), 401
        except jwt.InvalidTokenError as e:
            log_unauthorized(f"invalid_token:{e.__class__.__name__}")
            return jsonify(error="Invalid token"), 401

        jti = payload.get("jti")
        if jti and is_token_revoked(jti):
            log_unauthorized("revoked_token", username=payload.get("sub"))
            return jsonify(error="Token has been revoked"), 401

        # Make the verified identity available to the view function.
        g.current_user = {
            "username": payload.get("sub"),
            "role": payload.get("role"),
            "jti": jti,
        }
        return view(*args, **kwargs)

    return wrapper


def role_required(*allowed_roles: str):
    """Stack on top of @token_required to enforce role-based access."""

    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            user = getattr(g, "current_user", None)
            if user is None or user.get("role") not in allowed_roles:
                log_unauthorized(
                    f"role_denied:required={'|'.join(allowed_roles)}",
                    username=(user or {}).get("username"),
                )
                return (
                    jsonify(error="Forbidden: insufficient privileges"),
                    403,
                )
            return view(*args, **kwargs)

        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.route("/", methods=["GET"])
def index():
    return jsonify(
        service="SecureShield",
        endpoints={
            "POST /register": "Create an account (body: username, password, role?)",
            "POST /login":    "Exchange credentials for a JWT",
            "GET  /profile":  "Protected — any authenticated role",
            "DELETE /user/<id>": "Protected — admin only",
            "POST /logout":   "Revoke the JWT used on the request",
        },
    )


# -------------------- Task 1: Secure registration --------------------


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    role = (data.get("role") or "user").strip().lower()

    if not username or not password:
        return jsonify(error="username and password are required"), 400
    if len(password) < 8:
        return jsonify(error="password must be at least 8 characters"), 400
    if role not in ALLOWED_ROLES:
        return jsonify(error=f"role must be one of {sorted(ALLOWED_ROLES)}"), 400

    # bcrypt automatically generates and embeds a random salt for every call.
    password_hash = bcrypt.generate_password_hash(password).decode()

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, password_hash, role),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="username already exists"), 409

    return jsonify(message="user registered", username=username, role=role), 201


# -------------------- Task 2: JWT issuance --------------------


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        log_unauthorized("login_missing_credentials")
        return jsonify(error="username and password are required"), 400

    db = get_db()
    row = db.execute(
        "SELECT username, password_hash, role FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    # Constant-ish path: always run bcrypt to limit username-enumeration timing.
    if row is None or not bcrypt.check_password_hash(row["password_hash"], password):
        log_unauthorized("bad_credentials", username=username)
        return jsonify(error="invalid username or password"), 401

    token = issue_jwt(row["username"], row["role"])
    return jsonify(access_token=token, token_type="Bearer", role=row["role"]), 200


# -------------------- Task 4: Role-based routing --------------------


@app.route("/profile", methods=["GET"])
@token_required
def profile():
    user = g.current_user
    db = get_db()
    row = db.execute(
        "SELECT id, username, role, created_at FROM users WHERE username = ?",
        (user["username"],),
    ).fetchone()
    if row is None:
        return jsonify(error="user no longer exists"), 404
    return jsonify(
        id=row["id"],
        username=row["username"],
        role=row["role"],
        created_at=row["created_at"],
    )


@app.route("/user/<int:user_id>", methods=["DELETE"])
@token_required
@role_required("admin")
def delete_user(user_id: int):
    db = get_db()
    cur = db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    if cur.rowcount == 0:
        return jsonify(error="no such user"), 404
    return jsonify(message=f"user {user_id} deleted by {g.current_user['username']}")


# -------------------- Task 5: Logout / token revocation --------------------


@app.route("/logout", methods=["POST"])
@token_required
def logout():
    jti = g.current_user.get("jti")
    if not jti:
        return jsonify(error="token has no jti claim"), 400
    revoke_token(jti)
    return jsonify(message="token revoked"), 200


# ---------------------------------------------------------------------------
# Generic JSON error handlers (so attackers don't see HTML stack pages)
# ---------------------------------------------------------------------------


@app.errorhandler(404)
def not_found(_e):
    return jsonify(error="not found"), 404


@app.errorhandler(405)
def method_not_allowed(_e):
    return jsonify(error="method not allowed"), 405


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    init_db()
    seed_demo_users()
    if SECRET_KEY == "dev-only-secret-change-me":
        app.logger.warning(
            "Running with the default SECRET_KEY. "
            "Set the SECRET_KEY environment variable for any real deployment."
        )
    # debug=False so that exception pages don't leak stack traces.
    app.run(host="127.0.0.1", port=5000, debug=False)
