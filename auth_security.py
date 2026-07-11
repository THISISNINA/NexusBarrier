"""
auth_security.py — Hardened auth + structural tenant isolation.

Extends auth_reference.py with the five things that were missing:
  1. Brute-force lockout (DB-backed, survives restarts — in-memory
     lockout tracking would reset every deploy, defeating the point).
  2. CSRF protection on both forms.
  3. JWT delivered via HttpOnly, Secure, SameSite cookie — never
     localStorage, which is readable by any XSS bug on the page.
  4. Revocable sessions via a refresh-token table — a bare JWT can't be
     revoked before it expires; this makes "log this session out right
     now" actually possible.
  5. Structural tenant isolation: TenantScopedDB below is the ONLY
     sanctioned way route code touches tenant data. It takes company_id
     exactly once, at construction, from the verified token — never as
     a per-call argument — so there is no method signature that could
     accept a forged/tampered company_id from a request. Contrast this
     with "remember to add WHERE company_id = ? to every query" — that
     approach fails the moment one developer forgets one query, which
     is the actual root cause of most real-world cross-tenant leaks.
"""
import hashlib
import os
import re
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Optional, Dict, Any

import jwt
from flask import g, request, redirect, url_for, session, abort, flash
from werkzeug.security import generate_password_hash, check_password_hash

# From env when deployed; otherwise a fresh random key per process. The
# fallback means a restart signs everyone out (tokens no longer verify) —
# an acceptable demo trade-off, and strictly safer than every clone of
# this repo sharing one hardcoded signing key an attacker can read on
# GitHub and use to forge any user's (or the platform admin's) token.
JWT_SECRET = os.environ.get("JWT_SECRET") or secrets.token_hex(32)
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRY_MINUTES = 15     # short-lived — this is what limits blast radius if one leaks
REFRESH_TOKEN_EXPIRY_DAYS = 7

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_WINDOW_MINUTES = 15

# The three tenant-side roles. TENANT_ADMIN is the workspace root the
# Super Admin creates at provisioning time — it owns team management
# (approvals, role changes, access removal) for its company_id and
# nothing outside it. L1_ANALYST / MLRO keep their existing meanings in
# the alert workflow (aml_engine still restricts ESCALATED/DRAFT_SAR
# transitions to MLRO specifically — admin of the workspace does not
# imply SAR sign-off authority).
TENANT_ROLES = ("L1_ANALYST", "MLRO", "TENANT_ADMIN")

SIGNUP_RATE_LIMIT_MAX_ATTEMPTS = 5   # per IP, counts successes AND failures — unlike login lockout
SIGNUP_RATE_LIMIT_WINDOW_MINUTES = 60

# Tenant that all pre-multi-tenancy demo data (every row that existed
# before company_id columns did) is backfilled onto during migration, so
# that data has a real, queryable owning company instead of an orphaned
# or NULL company_id. Not a "real" customer — just where history lands.
LEGACY_COMPANY_ID = "legacy-demo"

PLATFORM_ACCESS_TOKEN_EXPIRY_MINUTES = 30

# Platform Super Admin — a genuinely separate identity, not a role value
# "Zero access to compliance data" is a structural claim, not a policy one —
# it has to be true even if some future route handler gets sloppy. Two
# things make it true here:
#   1. platform_admins lives in its OWN database file (platform.db), not
#      aml_monitoring.db — the same "mirrors real-world separation" pattern
#      aml_engine.py already uses for screening.db. A platform-admin session
#      literally cannot JOIN against aml_alerts/transactions/customer_profiles
#      by accident, because those tables aren't in this connection at all.
#   2. The platform-admin JWT has a completely different shape — no
#      company_id claim anywhere in it — so TenantScopedDB-style tenant code
#      structurally cannot be invoked with a platform-admin token even if
#      someone tried; there's no company_id to read.
_BASE_DIR = Path(__file__).resolve().parent
PLATFORM_DB_PATH = _BASE_DIR / "data" / "database" / "platform.db"

PLATFORM_ADMIN_SCHEMA = """
CREATE TABLE IF NOT EXISTS platform_admins (
    admin_id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS platform_login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    success INTEGER NOT NULL,
    attempted_at TEXT NOT NULL,
    ip_address TEXT
);
"""


def get_platform_conn() -> sqlite3.Connection:
    """Opens a connection to platform.db, creating the schema if needed.
    Callers are responsible for closing it — same short-lived-connection
    convention as AMLService._connect()."""
    PLATFORM_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(PLATFORM_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript(PLATFORM_ADMIN_SCHEMA)
    conn.commit()
    return conn


def ensure_platform_admin_seed() -> None:
    """Bootstraps the first Super Admin from PLATFORM_ADMIN_USERNAME /
    PLATFORM_ADMIN_PASSWORD env vars, and only when that username doesn't
    exist yet — a deploy restart never resets a changed password back to
    the env value. Without a seeded admin the /platform routes are simply
    unreachable (login always fails), which is the safe default: no
    hardcoded fallback credential ships in the codebase."""
    username = os.environ.get("PLATFORM_ADMIN_USERNAME")
    password = os.environ.get("PLATFORM_ADMIN_PASSWORD")
    if not username or not password:
        return
    conn = get_platform_conn()
    try:
        exists = conn.execute(
            "SELECT 1 FROM platform_admins WHERE username = ?", (username,)
        ).fetchone()
        if exists:
            return
        conn.execute(
            "INSERT INTO platform_admins (admin_id, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (secrets.token_hex(16), username, generate_password_hash(password),
             datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
    finally:
        conn.close()


def is_platform_locked_out(conn, username: str) -> bool:
    """Same window/threshold as the tenant lockout, but keyed on username
    alone (there's no company_id at the platform layer) and stored in
    platform.db — platform auth never touches aml_monitoring.db."""
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=LOCKOUT_WINDOW_MINUTES)).isoformat()
    count = conn.execute(
        """SELECT COUNT(*) FROM platform_login_attempts
           WHERE username = ? AND success = 0 AND attempted_at > ?""",
        (username, cutoff),
    ).fetchone()[0]
    return count >= MAX_FAILED_ATTEMPTS


def record_platform_attempt(conn, username: str, success: bool, ip_address: Optional[str] = None) -> None:
    conn.execute(
        """INSERT INTO platform_login_attempts (username, success, attempted_at, ip_address)
           VALUES (?, ?, ?, ?)""",
        (username, 1 if success else 0, datetime.now(timezone.utc).isoformat(), ip_address),
    )
    conn.commit()


# Base identity tables (every other table's company_id points here)
# companies.status: ACTIVE / SUSPENDED — Super Admin's tenant-licensing
# control. A suspended company blocks login and signup for every one of
# its users regardless of their own individual status.
# users.status: ACTIVE / REJECTED / SUSPENDED — the ongoing lifecycle
# state a Tenant Admin (MLRO) puts a specific user into, independent of
# is_approved (see below).
# users.is_approved: the onboarding gate specifically. A user can be
# is_approved=0 (never yet reviewed) or is_approved=1 (reviewed and let
# in) — status is what happens to them AFTER that initial review, so the
# two aren't collapsed into one field: "rejected" and "never reviewed"
# are different states an approval-queue UI needs to tell apart.
BASE_AUTH_SCHEMA = """
CREATE TABLE IF NOT EXISTS companies (
    company_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    contact_email TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    company_id TEXT NOT NULL,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    is_approved INTEGER NOT NULL DEFAULT 0,
    full_name TEXT,
    nickname TEXT,
    requested_role TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (company_id, username),
    FOREIGN KEY (company_id) REFERENCES companies(company_id)
);

CREATE INDEX IF NOT EXISTS idx_users_company ON users(company_id);
"""


def _add_column_if_missing(conn, table: str, column: str, ddl_type: str) -> None:
    """Same additive-migration guard as aml_engine.py's helper of the same
    name — duplicated rather than imported so this module doesn't need a
    module-level dependency on aml_engine (which itself imports this
    module; see _current_standing for why that direction only works as a
    local import, not a circular module-level one)."""
    existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl_type}")


def _apply_auth_schema_migrations(conn) -> None:
    """Backfills companies.status/contact_email and users.is_approved onto
    databases created before the platform-admin/approval-queue feature
    existed. DEFAULT 'ACTIVE' / DEFAULT 1 here grandfather in every
    pre-existing company/user as already-active and already-approved —
    nobody who could log in yesterday should suddenly be locked out by
    this migration running. New rows going forward get their real value
    from the code path that inserts them (provisioning, signup, etc.),
    not from this default."""
    _add_column_if_missing(conn, "companies", "status", "TEXT NOT NULL DEFAULT 'ACTIVE'")
    _add_column_if_missing(conn, "companies", "contact_email", "TEXT")
    _add_column_if_missing(conn, "users", "is_approved", "INTEGER NOT NULL DEFAULT 1")
    # Approval audit trail: which Tenant Admin let this user in, and when.
    # NULL means either "not yet reviewed" or "grandfathered by migration".
    _add_column_if_missing(conn, "users", "approved_by", "TEXT")
    _add_column_if_missing(conn, "users", "approved_at", "TEXT")
    # Onboarding identity profile: full_name is the legal name for audit trails,
    # nickname is the casual display name. requested_role is display-only for the
    # approval queue and is never applied to the role column automatically.
    _add_column_if_missing(conn, "users", "full_name", "TEXT")
    _add_column_if_missing(conn, "users", "nickname", "TEXT")
    _add_column_if_missing(conn, "users", "requested_role", "TEXT")
    conn.commit()


# Schema additions (on top of the users/companies tables above)
AUTH_SECURITY_SCHEMA = """
CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    company_id TEXT NOT NULL,
    username TEXT NOT NULL,
    success INTEGER NOT NULL,
    attempted_at TEXT NOT NULL,
    ip_address TEXT
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    company_id TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS signup_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    attempted_at TEXT NOT NULL
);
"""


def ensure_auth_schema(conn) -> None:
    """The one entry point aml_engine.init_schema() calls. Creates
    companies/users (BASE_AUTH_SCHEMA) before login_attempts/refresh_tokens/
    signup_attempts (AUTH_SECURITY_SCHEMA), since the latter reference
    company_id values that should correspond to real rows in the former.
    Also bootstraps LEGACY_COMPANY_ID so every company_id column elsewhere
    that backfills existing rows onto that id points at an actual company,
    not a dangling reference."""
    conn.executescript(BASE_AUTH_SCHEMA)
    conn.executescript(AUTH_SECURITY_SCHEMA)
    _apply_auth_schema_migrations(conn)
    conn.execute(
        "INSERT OR IGNORE INTO companies (company_id, display_name, created_at) VALUES (?, ?, ?)",
        (LEGACY_COMPANY_ID, "Legacy Demo Data (pre-tenancy)", datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


# Workspace provisioning (Super Admin only)
# These two are the ONLY write paths that create a company or a
# TENANT_ADMIN. Public signup can do neither: it requires an existing
# company_id and always produces an unapproved L1_ANALYST (see app.py's
# /signup). That asymmetry is the whole onboarding model — workspaces
# come into existence at the platform layer, people join them at the
# tenant layer.

def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "workspace"


def provision_company(conn, display_name: str, contact_email: str) -> str:
    """Registers a new workspace and returns its generated company_id —
    a readable slug plus a short random suffix. The suffix matters:
    company_id doubles as the 'workspace key' users must know to request
    access, so it shouldn't be guessable from the company's public name
    alone (login/signup pages deliberately have no workspace directory)."""
    now = datetime.now(timezone.utc).isoformat()
    slug = _slugify(display_name)
    for _ in range(20):
        company_id = f"{slug}-{secrets.token_hex(2)}"
        try:
            conn.execute(
                """INSERT INTO companies (company_id, display_name, contact_email, status, created_at)
                   VALUES (?, ?, ?, 'ACTIVE', ?)""",
                (company_id, display_name.strip(), contact_email.strip(), now),
            )
            conn.commit()
            return company_id
        except sqlite3.IntegrityError:
            continue  # suffix collision — roll a new one
    raise RuntimeError("Could not generate a unique company_id.")


def create_tenant_admin(conn, company_id: str, username: str, password: str) -> str:
    """Creates the workspace's root TENANT_ADMIN, pre-approved
    (is_approved=1) — this is the one account per company that never
    goes through the access-request queue, because it's the account the
    queue is reviewed BY. approved_by records the provisioning origin.
    Raises sqlite3.IntegrityError if the username is taken."""
    user_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        """INSERT INTO users (user_id, company_id, username, password_hash, role,
                              status, is_approved, approved_by, approved_at, created_at)
           VALUES (?, ?, ?, ?, 'TENANT_ADMIN', 'ACTIVE', 1, 'PLATFORM_PROVISIONING', ?, ?)""",
        (user_id, company_id, username.strip(), generate_password_hash(password), now, now),
    )
    conn.commit()
    return user_id


def set_company_status(conn, company_id: str, status: str) -> None:
    """ACTIVE / SUSPENDED — the Super Admin's licensing lever. Suspension
    takes effect on every user's very next request, not their next login,
    because require_auth re-checks company status live per request."""
    if status not in ("ACTIVE", "SUSPENDED"):
        raise ValueError(f"Invalid company status: {status}")
    conn.execute("UPDATE companies SET status = ? WHERE company_id = ?", (status, company_id))
    conn.commit()


# Brute-force lockout

def is_locked_out(conn, company_id: str, username: str) -> bool:
    """Checked BEFORE the password is verified — a locked-out account
    should never reach check_password_hash at all, both so the lockout
    is absolute and so failed/locked-out responses take the same code
    path (no timing difference an attacker could use to distinguish
    'locked out' from 'wrong password')."""
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=LOCKOUT_WINDOW_MINUTES)).isoformat()
    count = conn.execute(
        """SELECT COUNT(*) FROM login_attempts
           WHERE company_id = ? AND username = ? AND success = 0 AND attempted_at > ?""",
        (company_id, username, cutoff),
    ).fetchone()[0]
    return count >= MAX_FAILED_ATTEMPTS


def record_attempt(conn, company_id: str, username: str, success: bool, ip_address: Optional[str] = None) -> None:
    """Every attempt — success or failure — also doubles as the audit
    trail: who tried to sign in, when, from where, and whether it worked.
    Relevant for a compliance platform specifically, not just a general
    security nicety."""
    conn.execute(
        """INSERT INTO login_attempts (company_id, username, success, attempted_at, ip_address)
           VALUES (?, ?, ?, ?, ?)""",
        (company_id, username, 1 if success else 0, datetime.now(timezone.utc).isoformat(), ip_address),
    )
    conn.commit()


# Signup rate limiting
# Separate from login lockout, and keyed differently: login lockout keys
# on (company_id, username) because that identity already exists and
# only failures count (a legitimate user logging in successfully many
# times should never get locked out of their own account). Signup has
# no existing identity to key on — that's literally what's being
# created — so this keys on IP address instead, and counts BOTH
# successes and failures, since 5 accounts created from one IP in an
# hour is suspicious regardless of whether each individual signup
# "succeeded". Bounds both spam account creation and using repeated
# signup attempts to enumerate which (company_id, username) pairs
# already exist.

def is_signup_rate_limited(conn, ip_address: str) -> bool:
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=SIGNUP_RATE_LIMIT_WINDOW_MINUTES)).isoformat()
    count = conn.execute(
        "SELECT COUNT(*) FROM signup_attempts WHERE ip_address = ? AND attempted_at > ?",
        (ip_address, cutoff),
    ).fetchone()[0]
    return count >= SIGNUP_RATE_LIMIT_MAX_ATTEMPTS


def record_signup_attempt(conn, ip_address: str) -> None:
    conn.execute(
        "INSERT INTO signup_attempts (ip_address, attempted_at) VALUES (?, ?)",
        (ip_address, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


# CSRF

def get_csrf_token() -> str:
    """One token per session, generated on first use. Templates render
    it as a hidden field; verify_csrf() checks it on every POST."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def verify_csrf(form_token: Optional[str]) -> bool:
    session_token = session.get("csrf_token")
    if not session_token or not form_token:
        return False
    return secrets.compare_digest(session_token, form_token)  # constant-time — a naive == leaks timing info


def require_csrf(f):
    """Decorator form of verify_csrf for every state-changing POST route —
    one line instead of repeating the same 'if not verify_csrf(...): abort'
    check inline at the top of each view function. Reads request.form
    directly, so it doesn't need g.user to already be set; safe to stack
    in any order relative to require_auth/require_role."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not verify_csrf(request.form.get("csrf_token")):
            abort(400)
        return f(*args, **kwargs)
    return wrapper


# JWT issuance, delivered via secure cookie

def _hash_refresh_token(raw_token: str) -> str:
    """SHA-256, not werkzeug's slow password hash. A refresh token is
    already 48 bytes of high-entropy randomness — not a guessable human
    password — so it doesn't need brute-force-resistant slow hashing.
    More importantly, a fast deterministic hash is what makes direct
    indexed lookup (SELECT WHERE token_hash = ?) possible at all; a
    salted slow hash can't be queried that way, only re-verified row by
    row against a candidate, which doesn't work when you don't already
    know which row to check."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def issue_tokens(conn, company_id: str, user_id: str, role: str, username: str,
                 nickname: Optional[str] = None) -> Dict[str, str]:
    """Returns {"access_token": ..., "refresh_token": ...}. The route
    handler sets these as cookies (see login.html integration notes at
    the bottom of this file) — this function never returns anything the
    caller should put in a JSON response body or localStorage.

    `username` and `nickname` are display-only claims, never used for any
    authorization decision (company_id/role/sub are). nickname falls back
    to username so templates can always render the claim."""
    now = datetime.now(timezone.utc)

    access_payload = {
        "sub": user_id, "company_id": company_id, "role": role, "username": username,
        "nickname": (nickname or "").strip() or username,
        "jti": secrets.token_hex(16),  # unique per token, independent of timing — also what a future per-token revocation list would key on
        "iat": now, "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRY_MINUTES),
    }
    access_token = jwt.encode(access_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    refresh_token = secrets.token_urlsafe(48)
    refresh_hash = _hash_refresh_token(refresh_token)
    expires_at = now + timedelta(days=REFRESH_TOKEN_EXPIRY_DAYS)
    conn.execute(
        """INSERT INTO refresh_tokens (token_hash, user_id, company_id, issued_at, expires_at, revoked)
           VALUES (?, ?, ?, ?, ?, 0)""",
        (refresh_hash, user_id, company_id, now.isoformat(), expires_at.isoformat()),
    )
    conn.commit()

    return {"access_token": access_token, "refresh_token": refresh_token}


def refresh_access_token(conn, raw_refresh_token: str) -> Optional[Dict[str, str]]:
    """
    Verifies the refresh token, then ROTATES it: the old one is revoked
    immediately and a new access+refresh pair is issued. Rotation means
    a stolen refresh token that gets reused after the legitimate client
    has already rotated it is detectably invalid — the old token simply
    stops working the moment it's used once. That's most of the safety
    value of rotation even without building the "alert on reuse of a
    revoked token" detection on top, which a real deployment should add.

    Role is looked up fresh from `users`, not carried over from the old
    token — if an admin demoted or deactivated this person since the
    refresh token was issued, refreshing must reflect that, not hand
    out a new valid token for a role/account that's no longer current.
    """
    token_hash = _hash_refresh_token(raw_refresh_token)
    row = conn.execute(
        "SELECT * FROM refresh_tokens WHERE token_hash = ? AND revoked = 0",
        (token_hash,),
    ).fetchone()

    if row is None:
        return None
    if row["expires_at"] < datetime.now(timezone.utc).isoformat():
        return None

    conn.execute("UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?", (token_hash,))
    conn.commit()

    user = conn.execute("SELECT * FROM users WHERE user_id = ?", (row["user_id"],)).fetchone()
    if user is None or user["status"] != "ACTIVE":
        return None

    return issue_tokens(conn, row["company_id"], row["user_id"], user["role"], user["username"],
                        nickname=user["nickname"])


def revoke_all_sessions_for_user(conn, user_id: str) -> None:
    """'Log this user out everywhere right now' — e.g. on password
    change, suspected compromise, or an admin forcing a sign-out. A
    bare JWT can't be un-issued; the refresh token is what actually
    gets revoked, and short access-token expiry (15 min) bounds how
    long an already-issued access token stays usable after that."""
    conn.execute("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?", (user_id,))
    conn.commit()


def verify_access_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError:
        return None


def _cookie_secure() -> bool:
    """Secure=True everywhere except a plain-HTTP request (i.e. local
    dev on http://127.0.0.1). A hardcoded True there means the browser
    silently refuses to STORE the cookie at all, so login 'succeeds'
    then instantly bounces back to the login page with no error — the
    worst kind of failure to debug. Production traffic is HTTPS (app.py
    installs ProxyFix so Flask sees the proxy's X-Forwarded-Proto and
    request.is_secure is True behind Render/gunicorn), so deployed
    cookies keep the Secure flag."""
    return request.is_secure


def set_auth_cookies(response, tokens: Dict[str, str]):
    """HttpOnly means client-side JS cannot read this cookie at all —
    the standard defense against token theft via XSS. Secure means it's
    never sent over plain HTTP. SameSite=Lax is the standard CSRF
    mitigation for cookies specifically (separate from, and in addition
    to, the CSRF token above which covers the form-submission path)."""
    response.set_cookie(
        "access_token", tokens["access_token"],
        httponly=True, secure=_cookie_secure(), samesite="Lax",
        max_age=ACCESS_TOKEN_EXPIRY_MINUTES * 60,
    )
    response.set_cookie(
        "refresh_token", tokens["refresh_token"],
        httponly=True, secure=_cookie_secure(), samesite="Lax",
        max_age=REFRESH_TOKEN_EXPIRY_DAYS * 24 * 60 * 60,
        path="/",  # NOT scoped to /refresh — see correction note below
    )
    return response

# Correction from the previous version of this file: path="/refresh" only
# was wrong for this app's actual usage pattern. That scoping meant the
# browser would only ever send the refresh cookie to a dedicated
# /refresh endpoint — but transparent, automatic refresh on ANY page
# request (so a user's session doesn't die mid-read every 15 minutes)
# needs the cookie present on every request. HttpOnly already stops
# client-side JS from reading this cookie regardless of path, which was
# the actual protection that mattered; the path restriction wasn't
# adding real security, just breaking the auto-refresh flow.


# Platform Super Admin tokens
# Deliberately simpler than the tenant token pair above: no refresh token,
# no rotation. Platform-admin usage is infrequent (provisioning a new
# tenant, suspending one) — re-logging in every 30 minutes is a non-issue,
# and not building a second refresh-token table keeps this identity system
# minimal, which matters more here than convenience: less code touching
# the one credential that can provision/suspend tenants, the easier it is
# to audit.

def issue_platform_token(admin_id: str, username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "scope": "platform", "sub": admin_id, "username": username,
        "jti": secrets.token_hex(16),
        "iat": now, "exp": now + timedelta(minutes=PLATFORM_ACCESS_TOKEN_EXPIRY_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_platform_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError:
        return None
    # Not just "does this JWT verify" — it must be a platform-scoped token
    # specifically. Without this check, a tenant user's own valid
    # access_token (different cookie, but the same secret/algorithm) would
    # decode successfully here too, and this function would hand back
    # whatever fields happen to overlap (sub, username) as if they were a
    # platform admin's.
    if payload.get("scope") != "platform":
        return None
    return payload


def set_platform_auth_cookie(response, token: str):
    """Own cookie name (platform_access_token), never access_token — a
    browser signed in as both a tenant user and a platform admin (e.g. two
    tabs) must not have one cookie clobber the other."""
    response.set_cookie(
        "platform_access_token", token,
        httponly=True, secure=_cookie_secure(), samesite="Lax",
        max_age=PLATFORM_ACCESS_TOKEN_EXPIRY_MINUTES * 60,
    )
    return response


def require_platform_admin(f):
    """Sets g.platform_admin = {"sub", "username"} from the verified
    platform cookie. Completely separate from require_auth/g.user below —
    a route decorated with this one has no company_id in scope at all."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.cookies.get("platform_access_token")
        payload = verify_platform_token(token) if token else None
        if payload is None:
            return redirect(url_for("platform_login"))
        g.platform_admin = payload
        return f(*args, **kwargs)
    return wrapper


# Route protection

def _current_standing(user_id: str) -> Optional[Dict[str, Any]]:
    """Live is_approved/status/company-status lookup, run on every
    authenticated request — not just at login. A bare JWT can't reflect
    an approval revoked, a user suspended, or a company suspended AFTER
    it was issued; the 15-minute expiry bounds the exposure but doesn't
    close it to zero, and for 'immediately destroy the session' to be
    true, this has to be a live check, not a claim baked into the token
    at issuance. Local import of aml_engine avoids a circular import —
    aml_engine already imports this module at module level, so the
    reverse import can only happen lazily, inside a function, the same
    way aml_loader.init_db() imports aml_engine locally for the same
    reason."""
    import aml_engine
    conn = sqlite3.connect(aml_engine.DB_PATH)
    try:
        row = conn.execute(
            """SELECT u.is_approved, u.status AS user_status, c.status AS company_status
               FROM users u JOIN companies c ON c.company_id = u.company_id
               WHERE u.user_id = ?""",
            (user_id,),
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    return {"is_approved": row[0], "user_status": row[1], "company_status": row[2]}


def _reject_session(reason: str):
    """Shared by require_auth's live-standing check: flashes why, clears
    both tenant cookies so the browser stops resending a token that will
    only ever be rejected again, and sends them back to /login."""
    flash(reason, "error")
    resp = redirect(url_for("login"))
    resp.delete_cookie("access_token")
    resp.delete_cookie("refresh_token")
    return resp


def require_auth(f):
    """Sets g.user = {"sub", "company_id", "role"} from the verified
    cookie. Every tenant-scoped route reads company_id from g.user —
    never from anything else — see TenantScopedDB below."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.cookies.get("access_token")
        payload = verify_access_token(token) if token else None
        if payload is None:
            return redirect(url_for("login"))

        standing = _current_standing(payload["sub"])
        if standing is None:
            return _reject_session("Please sign in again.")
        if not standing["is_approved"]:
            return _reject_session("Your registration is pending administrator approval.")
        if standing["user_status"] == "REJECTED":
            return _reject_session("Your access request was declined. Contact your workspace administrator.")
        if standing["user_status"] != "ACTIVE":
            return _reject_session("Your account has been suspended. Contact your workspace administrator.")
        if standing["company_status"] != "ACTIVE":
            return _reject_session("This workspace has been suspended. Contact your administrator.")

        g.user = payload
        return f(*args, **kwargs)
    return wrapper


def require_role(*allowed_roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if g.user.get("role") not in allowed_roles:
                return "Forbidden", 403
            return f(*args, **kwargs)
        return wrapper
    return decorator


# Structural tenant isolation

class TenantScopedDB:
    """
    The only sanctioned way route code touches tenant data. company_id
    is fixed at construction from g.user["company_id"] (the verified
    token) and is never a parameter on any method below — there is
    structurally no way to call this class asking for a different
    tenant's data than the one the current session authenticated as.

    IDOR-safe by construction: get_alert() below filters by BOTH
    company_id and alert_id. A user guessing/incrementing another
    company's alert_id gets nothing back, even though that ID is
    perfectly valid in the database — it just doesn't belong to their
    company_id.
    """
    def __init__(self, conn, company_id: str):
        self._conn = conn
        self._company_id = company_id

    def get_alerts(self):
        return self._conn.execute(
            "SELECT * FROM aml_alerts WHERE company_id = ?", (self._company_id,)
        ).fetchall()

    def get_alert(self, alert_id: str):
        return self._conn.execute(
            "SELECT * FROM aml_alerts WHERE company_id = ? AND alert_id = ?",
            (self._company_id, alert_id),
        ).fetchone()

    # Team management (Tenant Admin surface)
    # Same structural guarantee as the alert methods above: user_id alone
    # is never enough to touch a row — every statement also filters on
    # self._company_id, so a Tenant Admin who guesses/enumerates another
    # workspace's user_id gets zero rows affected, not a cross-tenant
    # approval or deletion.

    def pending_access_requests(self):
        """The Access Requests queue: signed up, never yet reviewed.
        Excludes REJECTED so a declined request doesn't reappear as
        actionable — 'rejected' and 'never reviewed' are different states
        (see the is_approved/status comment above BASE_AUTH_SCHEMA)."""
        return self._conn.execute(
            """SELECT user_id, username, full_name, nickname, requested_role, created_at FROM users
               WHERE company_id = ? AND is_approved = 0 AND status != 'REJECTED'
               ORDER BY created_at ASC""",
            (self._company_id,),
        ).fetchall()

    def team_members(self):
        return self._conn.execute(
            """SELECT user_id, username, full_name, nickname, role, status, is_approved,
                      approved_by, approved_at, created_at
               FROM users WHERE company_id = ? ORDER BY created_at ASC""",
            (self._company_id,),
        ).fetchall()

    def get_user(self, user_id: str):
        return self._conn.execute(
            "SELECT * FROM users WHERE company_id = ? AND user_id = ?",
            (self._company_id, user_id),
        ).fetchone()

    def approve_user(self, user_id: str, approved_by_username: str) -> bool:
        """Returns True iff a row was actually flipped — routes use that
        to distinguish 'approved' from 'no such pending request in YOUR
        workspace' without ever revealing whether the id exists elsewhere."""
        cur = self._conn.execute(
            """UPDATE users SET is_approved = 1, status = 'ACTIVE', approved_by = ?, approved_at = ?
               WHERE company_id = ? AND user_id = ? AND is_approved = 0""",
            (approved_by_username, datetime.now(timezone.utc).isoformat(), self._company_id, user_id),
        )
        self._conn.commit()
        return cur.rowcount == 1

    def reject_user(self, user_id: str) -> bool:
        """Blocks rather than purges: the row stays (status=REJECTED,
        still unapproved) so the audit trail of who requested access and
        was declined survives — and the username stays reserved, so a
        rejected requester can't simply re-register the same identity."""
        cur = self._conn.execute(
            """UPDATE users SET status = 'REJECTED'
               WHERE company_id = ? AND user_id = ? AND is_approved = 0""",
            (self._company_id, user_id),
        )
        self._conn.commit()
        return cur.rowcount == 1

    def set_user_role(self, user_id: str, role: str) -> bool:
        if role not in TENANT_ROLES:
            raise ValueError(f"Invalid role: {role}")
        cur = self._conn.execute(
            "UPDATE users SET role = ? WHERE company_id = ? AND user_id = ?",
            (role, self._company_id, user_id),
        )
        self._conn.commit()
        return cur.rowcount == 1

    def remove_user(self, user_id: str) -> bool:
        """Hard access removal (distinct from reject_user's block): the
        credential row is deleted outright. Callers must also revoke the
        user's refresh tokens (revoke_all_sessions_for_user) — deleting
        the row kills future logins and, via _current_standing returning
        None, every in-flight session on its next request."""
        cur = self._conn.execute(
            "DELETE FROM users WHERE company_id = ? AND user_id = ?",
            (self._company_id, user_id),
        )
        self._conn.commit()
        return cur.rowcount == 1

    def count_active_admins(self) -> int:
        """Guard rail for role changes / removals: a workspace must never
        end up with zero approved, active TENANT_ADMINs — there'd be
        nobody left who can approve anyone, and only platform
        provisioning (not signup) can mint a new admin."""
        return self._conn.execute(
            """SELECT COUNT(*) FROM users
               WHERE company_id = ? AND role = 'TENANT_ADMIN' AND status = 'ACTIVE' AND is_approved = 1""",
            (self._company_id,),
        ).fetchone()[0]


# Route integration sketch (not runnable as-is — shows how the pieces
# above compose in app.py):
#
# app.jinja_env.globals["csrf_token"] = get_csrf_token
# # ^ required for {{ csrf_token() }} in login.html/signup.html to resolve
# # at all — without this line those templates throw a Jinja UndefinedError.
#
# @app.route("/login", methods=["POST"])
# def login():
#     company_id = request.form["company_id"]
#     username = request.form["username"]
#     password = request.form["password"]
#
#     if not verify_csrf(request.form.get("csrf_token")):
#         abort(400)
#     if is_locked_out(conn, company_id, username):
#         flash("Too many failed attempts. Try again in 15 minutes.", "error")
#         return redirect(url_for("login"))
#
#     row = conn.execute("SELECT * FROM users WHERE company_id=? AND username=?",
#                         (company_id, username)).fetchone()
#     ok = row and row["status"] == "ACTIVE" and check_password_hash(row["password_hash"], password)
#     record_attempt(conn, company_id, username, success=bool(ok), ip_address=request.remote_addr)
#     if not ok:
#         flash("Invalid credentials.", "error")   # never reveal WHICH part was wrong
#         return redirect(url_for("login"))
#
#     tokens = issue_tokens(conn, company_id, row["user_id"], row["role"], row["username"])
#     resp = redirect(url_for("dashboard"))
#     return set_auth_cookies(resp, tokens)
#
# @app.route("/signup", methods=["POST"])
# def signup():
#     ip = request.remote_addr
#     if not verify_csrf(request.form.get("csrf_token")):
#         abort(400)
#     if is_signup_rate_limited(conn, ip):
#         flash("Too many signup attempts from this network. Try again later.", "error")
#         return redirect(url_for("signup"))
#     record_signup_attempt(conn, ip)   # count it regardless of outcome below
#     ... validate + create the user (see auth_reference.py's signup()) ...
#
# @app.route("/refresh", methods=["POST"])
# def refresh():
#     raw = request.cookies.get("refresh_token")
#     if not raw:
#         return redirect(url_for("login"))
#     tokens = refresh_access_token(conn, raw)
#     if tokens is None:
#         return redirect(url_for("login"))   # expired, revoked, or account deactivated
#     resp = redirect(request.referrer or url_for("dashboard"))
#     return set_auth_cookies(resp, tokens)
#
# @app.route("/alerts")
# @require_auth
# def alerts():
#     db = TenantScopedDB(get_db_conn(), g.user["company_id"])
#     return render_template("alerts.html", alerts=db.get_alerts())
