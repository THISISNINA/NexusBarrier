import os

# Load .env into os.environ BEFORE any project import. Several modules
# (auth_security.JWT_SECRET, this file's secret_key, pii_crypto's key) read
# their configuration at import time, so the environment must be populated
# first. load_dotenv() is a no-op in production, where real environment
# variables are set by the platform and take precedence over any .env file.
# Subprocesses launched by /run-pipeline inherit this populated os.environ.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv optional at runtime; real env vars still work

import re
import sqlite3
import subprocess
import time
import uuid
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, abort, session, Response, g
from werkzeug.exceptions import HTTPException

from aml_service import AMLService
from aml_engine import AMLWorkflowManager, WorkflowError
import aml_pdf
import auth_security

base_dir = os.path.abspath(os.path.dirname(__file__))
template_dir = os.path.join(base_dir, "templates")

app = Flask(__name__, template_folder=template_dir)
# One trusted proxy hop (Render/gunicorn): without this, Flask sees the
# proxy's plain-HTTP side and request.is_secure is False even on HTTPS
# deployments, which would strip the Secure flag off auth cookies there
# (see auth_security._cookie_secure).
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
# ── Task 4: stable, environment-backed secret key ────────────────────────
# `os.urandom(24)` minted a FRESH key every time this module was imported.
# Under any multi-process server (Gunicorn's `--workers N`, or even a single
# worker that gets restarted) each process would hold a different key, so a
# session cookie or CSRF token signed by one worker fails verification on the
# next — users get silently logged out and forms 400 at random. The key must
# be one shared, persistent value across every worker and restart.
#
# Production: set NEXUSBARRIER_SECRET_KEY to a long random string (shared by
# all workers). Development: fall back to a fixed, clearly-non-secret constant
# so a local run stays stable across reloads without forcing env setup —
# announced with a warning so it can never be mistaken for production-safe.
_secret_key = os.environ.get("NEXUSBARRIER_SECRET_KEY")
if not _secret_key:
    print(
        "WARNING: NEXUSBARRIER_SECRET_KEY is not set — using a fixed development "
        "secret key. Set NEXUSBARRIER_SECRET_KEY to a random value in any "
        "non-development environment (sessions/CSRF are unsafe without it)."
    )
    _secret_key = "nexusbarrier-development-secret-key-not-for-production"
app.secret_key = _secret_key
app.jinja_env.globals["csrf_token"] = auth_security.get_csrf_token
NO_SAR_CLOSURE_CODES = [
    "FALSE_POSITIVE",
    "LEGITIMATE_BUSINESS",
    "DATA_ERROR",
    "BELOW_REGULATORY_THRESHOLD",
    "MONITORING_ONLY",
]
SAR_CLOSURE_CODES = list(AMLService.SAR_CLOSURE_CODES)

# Schema readiness check runs here — at import time — rather than only
# inside `if __name__ == "__main__":` below. That guard never executes
# when the app is launched via `flask run`, gunicorn, or an IDE's Flask
# runner (all of which import this module without running it as a
# script), which meant every page would crash on a fresh database
# unless you happened to start the app with `python app.py` specifically.
try:
    AMLService.ensure_db_ready()
except Exception as e:
    print(f"Warning initializing DB schema mapping components: {e}")

# Bootstraps the first Platform Super Admin from PLATFORM_ADMIN_USERNAME /
# PLATFORM_ADMIN_PASSWORD env vars (no-op if unset or already created).
# Without it the /platform routes are unreachable — safe default, no
# credential ships in code.
try:
    auth_security.ensure_platform_admin_seed()
except Exception as e:
    print(f"Warning seeding platform admin: {e}")

# ── Real auth ────────────────────────────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        # An already-signed-in user typing /login into the address bar should
        # not see the login form (and must not have their session silently
        # dropped) — bounce them straight to the dashboard. "Valid and active"
        # is checked with the exact same access-token cookie + verifier that
        # require_auth uses everywhere else, so the two can never disagree.
        # A token that verifies but whose account/company standing was revoked
        # after issuance is handled on the dashboard request: require_auth's
        # live standing check clears the cookies and returns the user here,
        # where the token is now absent and the form renders normally.
        token = request.cookies.get("access_token")
        if token and auth_security.verify_access_token(token):
            session["seen_welcome"] = True
            return redirect(url_for("dashboard"))
        return render_template("login.html")

    if not auth_security.verify_csrf(request.form.get("csrf_token")):
        abort(400)

    company_id = (request.form.get("company_id") or "").strip()
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    conn = AMLService._connect()
    try:
        if auth_security.is_locked_out(conn, company_id, username):
            flash("Too many failed attempts. Try again in 15 minutes.", "error")
            return redirect(url_for("login"))

        row = conn.execute(
            "SELECT * FROM users WHERE company_id = ? AND username = ?", (company_id, username)
        ).fetchone()
        ok = (
            row is not None and row["status"] == "ACTIVE"
            and auth_security.check_password_hash(row["password_hash"], password)
        )
        auth_security.record_attempt(conn, company_id, username, success=bool(ok), ip_address=request.remote_addr)
        if not ok:
            flash("Invalid credentials.", "error")
            return redirect(url_for("login"))

        # Password was right, so telling THIS person their true account
        # state leaks nothing — these gates run only after authentication.
        # No tokens are ever issued on either path: an unapproved user has
        # no session to destroy because one is never created. require_auth's
        # live standing check remains the backstop for approvals/suspensions
        # revoked AFTER a session already exists.
        if not row["is_approved"]:
            flash("Your registration is pending administrator approval.", "error")
            return redirect(url_for("login"))
        company = conn.execute(
            "SELECT status FROM companies WHERE company_id = ?", (company_id,)
        ).fetchone()
        if company is None or company["status"] != "ACTIVE":
            flash("This workspace has been suspended. Contact your administrator.", "error")
            return redirect(url_for("login"))

        tokens = auth_security.issue_tokens(conn, company_id, row["user_id"], row["role"], row["username"],
                                            nickname=row["nickname"])
    finally:
        conn.close()

    # Mark the landing page as seen so signed-in sessions are never bounced to /welcome.
    session["seen_welcome"] = True
    resp = redirect(url_for("dashboard"))
    return auth_security.set_auth_cookies(resp, tokens)


@app.route("/logout", methods=["POST"])
@auth_security.require_csrf
def logout():
    token = request.cookies.get("access_token")
    payload = auth_security.verify_access_token(token) if token else None
    if payload:
        conn = AMLService._connect()
        try:
            auth_security.revoke_all_sessions_for_user(conn, payload["sub"])
        finally:
            conn.close()
    # Not session.clear(): the only things left in the Flask session are
    # csrf_token and seen_welcome, neither auth-related (the JWT lives in
    # cookies, cleared below). Clearing the whole session would also wipe
    # seen_welcome and send a just-logged-out user back through the
    # welcome splash instead of straight to /login.
    resp = redirect(url_for("login"))
    resp.delete_cookie("access_token")
    resp.delete_cookie("refresh_token")
    return resp


def _password_meets_requirements(password: str) -> bool:
    """The real rule signup.html's field-hint promises the server
    enforces — length plus all three character-class requirements the
    hint text lists, not just the 'some of these' heuristic the
    client-side strength-meter color coding uses."""
    if len(password) < 12:
        return False
    return bool(
        re.search(r"[a-z]", password) and re.search(r"[A-Z]", password)
        and re.search(r"[0-9]", password) and re.search(r"[^A-Za-z0-9]", password)
    )


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    if not auth_security.verify_csrf(request.form.get("csrf_token")):
        abort(400)

    ip = request.remote_addr
    company_id = (request.form.get("company_id") or "").strip()
    full_name = (request.form.get("full_name") or "").strip()[:120]
    nickname = (request.form.get("nickname") or "").strip()[:60]
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    password_confirm = request.form.get("password_confirm") or ""
    requested_role = (request.form.get("requested_role") or "L1_ANALYST").strip().upper()
    # Blank nickname defaults to the first name so the UI always has a friendly greeting.
    if not nickname and full_name:
        nickname = full_name.split()[0]

    conn = AMLService._connect()
    try:
        # Counts regardless of outcome below — see auth_security's own
        # comment on is_signup_rate_limited for why (bounds both spam
        # account creation and using signup itself to enumerate which
        # (company_id, username) pairs already exist).
        if auth_security.is_signup_rate_limited(conn, ip):
            flash("Too many signup attempts from this network. Try again later.", "error")
            return redirect(url_for("signup"))
        auth_security.record_signup_attempt(conn, ip)

        if not company_id or not username or not password:
            flash("Workspace ID, username, and password are all required.", "error")
            return redirect(url_for("signup"))
        if not full_name:
            flash("Full name is required for audit trails and compliance documentation.", "error")
            return redirect(url_for("signup"))
        if requested_role not in ("L1_ANALYST", "MLRO"):
            flash("Invalid role selection.", "error")
            return redirect(url_for("signup"))
        if password != password_confirm:
            flash("Passwords don't match.", "error")
            return redirect(url_for("signup"))
        if not _password_meets_requirements(password):
            flash("Password must be at least 12 characters and include lowercase, uppercase, a number, and a symbol.", "error")
            return redirect(url_for("signup"))

        # Signup can only JOIN a workspace, never create one — workspaces
        # exist solely via platform provisioning (/platform). The error is
        # deliberately the same for "doesn't exist" and "suspended": a
        # public form must not confirm which workspace IDs are live.
        company = conn.execute(
            "SELECT status FROM companies WHERE company_id = ?", (company_id,)
        ).fetchone()
        if company is None or company["status"] != "ACTIVE":
            flash("Invalid Workspace ID.", "error")
            return redirect(url_for("signup"))

        # The granted role stays fixed server-side: everyone enters as an
        # unapproved L1_ANALYST. The toggle only fills requested_role, a display
        # field the Tenant Admin honors with an explicit role change after
        # approving, so a public form can't self-grant MLRO. is_approved=0 is set
        # explicitly because migrated databases default that column to 1.
        now = datetime.now(timezone.utc).isoformat()
        try:
            conn.execute(
                """INSERT INTO users (user_id, company_id, username, password_hash, role,
                                      status, is_approved, full_name, nickname, requested_role, created_at)
                   VALUES (?, ?, ?, ?, 'L1_ANALYST', 'ACTIVE', 0, ?, ?, ?, ?)""",
                (str(uuid.uuid4()), company_id, username,
                 auth_security.generate_password_hash(password),
                 full_name, nickname, requested_role, now),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            flash("That username is already taken in this workspace.", "error")
            return redirect(url_for("signup"))
    finally:
        conn.close()

    flash("Access request submitted. A workspace administrator must approve your account before you can sign in.", "success")
    return redirect(url_for("login"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    flash("Password reset isn't wired up yet — contact an administrator.", "error")
    return redirect(url_for("login"))


# ── Platform Super Admin (infrastructure layer only) ──────────────────────
# The Super Admin's identity lives in platform.db and their token carries
# no company_id (see auth_security's platform section). The routes below
# touch exactly two things in the main database — the companies and users
# IDENTITY tables (provisioning/licensing metadata) — and never any
# analytical table. No query here can return alert counts, transaction
# volumes, decisions, or trends; the dashboard's "system health" block is
# file sizes and engine versions, not row counts of compliance data.

@app.route("/platform/login", methods=["GET", "POST"])
def platform_login():
    if request.method == "GET":
        # Same already-authenticated bounce as the tenant /login above, on the
        # platform-scoped cookie. A live Super Admin session shouldn't be sent
        # back through the login form.
        token = request.cookies.get("platform_access_token")
        if token and auth_security.verify_platform_token(token):
            return redirect(url_for("platform_dashboard"))
        return render_template("platform_login.html")

    if not auth_security.verify_csrf(request.form.get("csrf_token")):
        abort(400)

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    conn = auth_security.get_platform_conn()
    try:
        if auth_security.is_platform_locked_out(conn, username):
            flash("Too many failed attempts. Try again in 15 minutes.", "error")
            return redirect(url_for("platform_login"))
        row = conn.execute(
            "SELECT * FROM platform_admins WHERE username = ?", (username,)
        ).fetchone()
        ok = row is not None and auth_security.check_password_hash(row["password_hash"], password)
        auth_security.record_platform_attempt(conn, username, success=bool(ok), ip_address=request.remote_addr)
    finally:
        conn.close()

    if not ok:
        flash("Invalid credentials.", "error")
        return redirect(url_for("platform_login"))

    token = auth_security.issue_platform_token(row["admin_id"], row["username"])
    resp = redirect(url_for("platform_dashboard"))
    return auth_security.set_platform_auth_cookie(resp, token)


@app.route("/platform/logout", methods=["POST"])
@auth_security.require_csrf
def platform_logout():
    resp = redirect(url_for("platform_login"))
    resp.delete_cookie("platform_access_token")
    return resp


@app.route("/platform")
@auth_security.require_platform_admin
def platform_dashboard():
    conn = AMLService._connect()
    try:
        tenants = conn.execute(
            """SELECT c.company_id, c.display_name, c.contact_email, c.status, c.created_at,
                      COUNT(u.user_id) AS user_count
               FROM companies c LEFT JOIN users u ON u.company_id = c.company_id
               GROUP BY c.company_id ORDER BY c.created_at DESC"""
        ).fetchall()
    finally:
        conn.close()

    def _db_size_mb(path):
        try:
            return round(os.path.getsize(path) / (1024 * 1024), 2)
        except OSError:
            return None

    import aml_engine
    health = {
        "sqlite_version": sqlite3.sqlite_version,
        "monitoring_db_mb": _db_size_mb(aml_engine.DB_PATH),
        "screening_db_mb": _db_size_mb(aml_engine.SCREENING_DB_PATH),
        "platform_db_mb": _db_size_mb(auth_security.PLATFORM_DB_PATH),
        "tenant_count": len(tenants),
        "active_tenant_count": sum(1 for t in tenants if t["status"] == "ACTIVE"),
    }
    return render_template("platform_dashboard.html", tenants=tenants, health=health,
                           platform_admin=g.platform_admin)


@app.route("/platform/provision", methods=["POST"])
@auth_security.require_platform_admin
@auth_security.require_csrf
def platform_provision():
    company_name = (request.form.get("company_name") or "").strip()
    contact_email = (request.form.get("contact_email") or "").strip()
    admin_username = (request.form.get("admin_username") or "").strip()
    admin_password = request.form.get("admin_password") or ""

    if not company_name or not contact_email or not admin_username or not admin_password:
        flash("Company name, contact email, and the initial admin's username and password are all required.", "error")
        return redirect(url_for("platform_dashboard"))
    if not _password_meets_requirements(admin_password):
        flash("Admin password must be at least 12 characters and include lowercase, uppercase, a number, and a symbol.", "error")
        return redirect(url_for("platform_dashboard"))

    conn = AMLService._connect()
    try:
        company_id = auth_security.provision_company(conn, company_name, contact_email)
        auth_security.create_tenant_admin(conn, company_id, admin_username, admin_password)
    finally:
        conn.close()

    flash(f"Workspace provisioned. Company ID: {company_id} — share it (privately) with "
          f"{company_name}'s team; employees need it to request access, and it is "
          f"deliberately never listed on any public page.", "success")
    return redirect(url_for("platform_dashboard"))


@app.route("/platform/company/<company_id>/users")
@auth_security.require_platform_admin
def platform_company_users(company_id):
    """Read-only drill-down into a tenant's roster. Deliberately shows only
    IDENTITY metadata (username, name, role, lifecycle status) — never a
    password_hash, and never any analytical/compliance table. The platform
    console can see WHO is in a workspace for support/oversight, but it
    still can't read that workspace's alerts, transactions, or decisions,
    and it has no write action here (governance stays with the Tenant
    Admin — see /admin/team)."""
    conn = AMLService._connect()
    try:
        company = conn.execute(
            "SELECT company_id, display_name, contact_email, status FROM companies WHERE company_id = ?",
            (company_id,),
        ).fetchone()
        if company is None:
            flash("No such workspace.", "error")
            return redirect(url_for("platform_dashboard"))
        users = conn.execute(
            """SELECT username, full_name, nickname, role, status, is_approved,
                      requested_role, approved_by, created_at
               FROM users WHERE company_id = ? ORDER BY created_at ASC""",
            (company_id,),
        ).fetchall()
    finally:
        conn.close()
    return render_template("platform_company_users.html", company=company, users=users)


@app.route("/platform/company/<company_id>/status", methods=["POST"])
@auth_security.require_platform_admin
@auth_security.require_csrf
def platform_company_status(company_id):
    """Licensing lever: ACTIVE <-> SUSPENDED. Effective on every tenant
    user's NEXT request (require_auth re-checks company status live),
    not just their next login."""
    new_status = request.form.get("status") or ""
    conn = AMLService._connect()
    try:
        try:
            auth_security.set_company_status(conn, company_id, new_status)
        except ValueError as e:
            flash(str(e), "error")
            return redirect(url_for("platform_dashboard"))
    finally:
        conn.close()
    flash(f"Workspace {company_id} is now {new_status}.", "success")
    return redirect(url_for("platform_dashboard"))


# ── Tenant Admin: team management & access requests ───────────────────────
# Everything below runs through TenantScopedDB, so every read and write is
# structurally pinned to the session's own company_id — a Tenant Admin
# acting on another workspace's user_id affects zero rows, and the flash
# message is the same as for a nonexistent id (no cross-tenant existence
# oracle).

@app.route("/admin/team")
@auth_security.require_auth
@auth_security.require_role("TENANT_ADMIN")
def admin_team():
    conn = AMLService._connect()
    try:
        db = auth_security.TenantScopedDB(conn, g.user["company_id"])
        pending = db.pending_access_requests()
        members = db.team_members()
    finally:
        conn.close()
    return render_template("admin_team.html", pending=pending, members=members,
                           roles=auth_security.TENANT_ROLES, current_role=g.user["role"])


@app.route("/admin/users/<user_id>/approve", methods=["POST"])
@auth_security.require_auth
@auth_security.require_role("TENANT_ADMIN")
@auth_security.require_csrf
def admin_approve_user(user_id):
    conn = AMLService._connect()
    try:
        db = auth_security.TenantScopedDB(conn, g.user["company_id"])
        if db.approve_user(user_id, g.user.get("username", "TENANT_ADMIN")):
            flash("Access request approved — the user can sign in now.", "success")
        else:
            flash("No such pending request in your workspace.", "error")
    finally:
        conn.close()
    return redirect(url_for("admin_team"))


@app.route("/admin/users/<user_id>/reject", methods=["POST"])
@auth_security.require_auth
@auth_security.require_role("TENANT_ADMIN")
@auth_security.require_csrf
def admin_reject_user(user_id):
    conn = AMLService._connect()
    try:
        db = auth_security.TenantScopedDB(conn, g.user["company_id"])
        if db.reject_user(user_id):
            flash("Access request declined. The record is kept (blocked) for audit.", "success")
        else:
            flash("No such pending request in your workspace.", "error")
    finally:
        conn.close()
    return redirect(url_for("admin_team"))


@app.route("/admin/users/<user_id>/role", methods=["POST"])
@auth_security.require_auth
@auth_security.require_role("TENANT_ADMIN")
@auth_security.require_csrf
def admin_change_role(user_id):
    new_role = request.form.get("role") or ""
    if user_id == g.user["sub"]:
        flash("You can't change your own role — ask another workspace admin.", "error")
        return redirect(url_for("admin_team"))

    conn = AMLService._connect()
    try:
        db = auth_security.TenantScopedDB(conn, g.user["company_id"])
        target = db.get_user(user_id)
        if target is None:
            flash("No such user in your workspace.", "error")
            return redirect(url_for("admin_team"))
        if target["role"] == "TENANT_ADMIN" and new_role != "TENANT_ADMIN" and db.count_active_admins() <= 1:
            flash("This is the workspace's only active admin — promote someone else to TENANT_ADMIN first.", "error")
            return redirect(url_for("admin_team"))
        try:
            db.set_user_role(user_id, new_role)
        except ValueError as e:
            flash(str(e), "error")
            return redirect(url_for("admin_team"))
        # Old-role sessions must not linger: refresh tokens die now, and
        # the 15-minute access-token expiry bounds what's already issued.
        auth_security.revoke_all_sessions_for_user(conn, user_id)
        flash(f"{target['username']} is now {new_role}. Their active sessions were signed out.", "success")
    finally:
        conn.close()
    return redirect(url_for("admin_team"))


@app.route("/admin/users/<user_id>/delete", methods=["POST"])
@auth_security.require_auth
@auth_security.require_role("TENANT_ADMIN")
@auth_security.require_csrf
def admin_delete_user(user_id):
    if user_id == g.user["sub"]:
        flash("You can't remove your own access — ask another workspace admin.", "error")
        return redirect(url_for("admin_team"))

    conn = AMLService._connect()
    try:
        db = auth_security.TenantScopedDB(conn, g.user["company_id"])
        target = db.get_user(user_id)
        if target is None:
            flash("No such user in your workspace.", "error")
            return redirect(url_for("admin_team"))
        if target["role"] == "TENANT_ADMIN" and db.count_active_admins() <= 1:
            flash("This is the workspace's only active admin — promote someone else to TENANT_ADMIN first.", "error")
            return redirect(url_for("admin_team"))
        # Revoke BEFORE deleting so no window exists where the user row is
        # gone but a live refresh token could still be presented.
        auth_security.revoke_all_sessions_for_user(conn, user_id)
        db.remove_user(user_id)
        flash(f"{target['username']}'s access has been removed and all their sessions revoked.", "success")
    finally:
        conn.close()
    return redirect(url_for("admin_team"))


# ── Cooldowns on the two destructive/expensive admin actions ──────────────
# Both actions are now MLRO-only and company-scoped (see /reset-demo and
# /run-pipeline below), but the client-side confirm() dialog on their
# buttons is still just a UX nicety, not a real gate — a logged-in MLRO
# could still spam either one via direct POST, so server-side cooldowns
# remain the actual enforcement.
#
# Two distinct concerns get two distinct cooldowns:
#   - /reset-demo is cheap to run but griefs OTHER visitors if spammed
#     (wipes whatever they were mid-walkthrough on) — short cooldown is
#     enough to stop rapid-fire abuse while still feeling instant to a
#     legitimate single use.
#   - /run-pipeline is expensive (regenerates 5000+ transactions, reseeds,
#     reruns all 12 detection scenarios across the full customer base) —
#     this is the one that can actually exhaust a free-tier instance's
#     CPU allowance if hammered, so it gets a longer cooldown plus a
#     "currently running" lock so a second request can't start a second
#     pipeline run on top of one still in progress.
#
# Same plain-module-memory pattern as the idle-reset above — correct only
# under a single worker process (`gunicorn -w 1`), which this app already
# requires for the SQLite-locking reason explained there.
RESET_COOLDOWN_SECONDS = int(os.environ.get("RESET_COOLDOWN_SECONDS", 30))
PIPELINE_COOLDOWN_SECONDS = int(os.environ.get("PIPELINE_COOLDOWN_SECONDS", 120))

_reset_state = {"last_run_at": 0.0}
_pipeline_state = {"last_run_at": 0.0, "running": False}


def _seconds_remaining(last_run_at: float, cooldown: float) -> float:
    elapsed = time.time() - last_run_at
    return max(0.0, cooldown - elapsed)


@app.route("/reset-demo", methods=["POST"])
@auth_security.require_auth
@auth_security.require_role("MLRO", "TENANT_ADMIN")
@auth_security.require_csrf
def reset_demo():
    """Company-scoped factory reset — wipes only the caller's own company's
    demo data (see AMLService.reset_demo_data), never another tenant's.
    MLRO-only: this is destructive enough that it shouldn't be self-service
    for every analyst. Cooldown-gated server-side (see comment above
    _reset_state) so it can't be spammed via direct POST even though the
    confirm() dialog is bypassable."""
    remaining = _seconds_remaining(_reset_state["last_run_at"], RESET_COOLDOWN_SECONDS)
    if remaining > 0:
        flash(f"Demo was just reset — please wait {int(remaining)}s before resetting again.", "error")
        return redirect(url_for("dashboard"))

    try:
        AMLService.reset_demo_data(g.user["company_id"])
        _reset_state["last_run_at"] = time.time()
        flash("Your workspace's demo data has been reset. Run the data pipeline below to start fresh.", "success")
    except Exception as e:
        flash(f"Reset failed: {e}", "error")
    return redirect(url_for("dashboard"))

@app.before_request
def _redirect_first_time_visitors_to_welcome():
    exempt_endpoints = {
        "welcome", "acknowledge_welcome", "static", "reset_demo",
        "login", "logout", "signup", "forgot_password",
    }
    if request.endpoint in exempt_endpoints:
        return None
    # The entire platform layer is exempt — a Super Admin provisioning
    # tenants must never be bounced through the tenant product tour.
    if request.endpoint and request.endpoint.startswith("platform"):
        return None
    if not session.get("seen_welcome"):
        return redirect(url_for("welcome"))
    return None

@app.route("/welcome")
def welcome():
    # Public pre-auth landing page. Only an aggregate scenario count is exposed;
    # scenario codes, thresholds, and windows stay behind login.
    try:
        scenario_count = len(AMLService.get_all_scenarios())
    except Exception:
        scenario_count = 0
    return render_template("welcome.html", scenario_count=scenario_count)

@app.route("/welcome/continue", methods=["POST"])
def acknowledge_welcome():
    session["seen_welcome"] = True
    return redirect(url_for("dashboard"))

@app.route("/dashboard")
@auth_security.require_auth
def dashboard():
    company_id = g.user["company_id"]
    summary = AMLService.get_dashboard_summary(company_id)
    time_in_review = {}
    ctr_count = 0
    try:
        time_in_review = AMLService.get_time_in_review_metrics(company_id)
    except Exception:
        pass
    try:
        ctr_data = AMLService.get_ctr_filings(company_id, limit=1)
        ctr_count = ctr_data["stats"].get("total_filings", 0)
    except Exception:
        pass
    last_engine_run = None
    try:
        last_engine_run = AMLService.get_last_engine_run(company_id)
    except Exception:
        pass
    return render_template(
        "dashboard.html", summary=summary, current_role=g.user["role"],
        time_in_review=time_in_review,
        ctr_count=ctr_count,
        last_engine_run=last_engine_run,
        pipeline_running=_pipeline_state["running"],
        pipeline_cooldown_remaining=int(_seconds_remaining(_pipeline_state["last_run_at"], PIPELINE_COOLDOWN_SECONDS)),
        reset_cooldown_remaining=int(_seconds_remaining(_reset_state["last_run_at"], RESET_COOLDOWN_SECONDS)),
    )

@app.route("/")
@auth_security.require_auth
def alert_queue():
    role = g.user["role"]
    company_id = g.user["company_id"]
    # TENANT_ADMIN gets the same full-visibility queue as MLRO — root
    # admin of the workspace sees everything in it (but aml_engine still
    # restricts ESCALATED/DRAFT_SAR transitions to MLRO specifically).
    if role in ("MLRO", "TENANT_ADMIN"):
        alerts = AMLService.get_open_and_escalated_alerts(company_id)
    else:
        alerts = AMLService.get_alerts_for_role(company_id, role)
    return render_template("alerts.html", alerts=alerts, current_role=role)

@app.route("/alerts/escalated")
@auth_security.require_auth
def alert_queue_escalated():
    alerts = AMLService.get_alerts_for_role(g.user["company_id"], "MLRO")
    return render_template("alerts.html", alerts=alerts, show_escalated=True, current_role=g.user["role"])

@app.route("/alerts/my-reviews")
@auth_security.require_auth
def alert_queue_my_reviews():
    role = g.user["role"]
    user_id = g.user["sub"]

    company_id = g.user["company_id"]
    if role in ("MLRO", "TENANT_ADMIN"):
        all_alerts = AMLService.get_all_alerts(company_id)
        viewed_ids = AMLService.get_viewed_alert_ids(company_id, user_id)
        my_alerts = [
            a for a in all_alerts
            if a["alert_id"] in viewed_ids and a["status"] in ("UNDER_REVIEW", "ESCALATED")
        ]
    else:
        all_alerts = AMLService.get_all_alerts(company_id)
        my_alerts = [a for a in all_alerts if a["status"] == "UNDER_REVIEW"]

    return render_template("alerts.html", alerts=my_alerts, show_my_reviews=True, current_role=role)

@app.route("/alerts/all")
@auth_security.require_auth
def alert_queue_all():
    alerts = AMLService.get_all_alerts(g.user["company_id"])
    return render_template("alerts.html", alerts=alerts, show_all=True, current_role=g.user["role"])

@app.route("/alert/<alert_id>")
@auth_security.require_auth
def alert_detail(alert_id):
    company_id = g.user["company_id"]
    alert = AMLService.get_alert(company_id, alert_id)
    if alert is None:
        abort(404)

    role = g.user["role"]
    user_id = g.user["sub"]

    try:
        AMLService.log_alert_view(company_id, alert_id, user_id, role)
    except Exception:
        pass

    time_in_review = {}
    try:
        time_in_review = AMLService.get_time_in_review(company_id, alert_id)
    except Exception:
        pass

    rule_version = None
    try:
        rule_version = AMLService.get_rule_version_for_alert(company_id, alert_id)
    except Exception:
        pass

    customer = AMLService.get_customer_profile(company_id, alert.get("account_id") if isinstance(alert, dict) else alert[1])
    transactions = AMLService.get_alert_transactions(company_id, alert_id) or []
    decisions = AMLService.get_decision_history(company_id, alert_id) or []
    status = AMLService.get_alert_status(company_id, alert_id) or "OPEN"
    valid_next_states = AMLService.get_valid_next_states(company_id, alert_id) or []

    current_case = None
    try:
        current_case = AMLService.get_case_for_alert(company_id, alert_id)
    except Exception:
        pass

    related_alerts = []
    open_cases_for_account = []
    if current_case is None:
        try:
            related_alerts = AMLService.find_related_open_alerts(company_id, alert_id) or []
        except Exception:
            pass
        try:
            account_id = alert.get("account_id") if isinstance(alert, dict) else alert[1]
            open_cases_for_account = AMLService.get_open_cases_for_account(company_id, account_id) or []
        except Exception:
            pass

    # Unconditional (unlike related_alerts above) — this is "these other
    # alerts share literal transaction evidence with this one", useful
    # investigative context regardless of whether a case already exists,
    # not a case-grouping suggestion that stops mattering once grouped.
    overlapping_alerts = []
    try:
        overlapping_alerts = AMLService.find_overlapping_alerts(company_id, alert_id) or []
    except Exception:
        pass

    return render_template(
        "alert_detail.html",
        alert=alert,
        customer=customer,
        transactions=transactions,
        decisions=decisions,
        status=status,
        valid_next_states=valid_next_states,
        no_sar_closure_codes=NO_SAR_CLOSURE_CODES,
        sar_closure_codes=SAR_CLOSURE_CODES,
        all_closure_codes=sorted(AMLWorkflowManager.VALID_CLOSURE_CODES),
        current_case=current_case,
        related_alerts=related_alerts,
        overlapping_alerts=overlapping_alerts,
        open_cases_for_account=open_cases_for_account,
        time_in_review=time_in_review,
        rule_version=rule_version,
        current_role=role
    )

@app.route("/claim/<alert_id>", methods=["POST"])
@auth_security.require_auth
@auth_security.require_csrf
def claim_alert(alert_id):
    try:
        AMLService.claim_alert(g.user["company_id"], alert_id, g.user["sub"], g.user["role"])
        try:
            AMLService.log_alert_view(g.user["company_id"], alert_id, g.user["sub"], g.user["role"])
        except Exception:
            pass
        flash("Alert claimed.", "success")
    except WorkflowError as e: flash(str(e), "error")
    return redirect(url_for("alert_detail", alert_id=alert_id))

@app.route("/close/<alert_id>", methods=["POST"])
@auth_security.require_auth
@auth_security.require_csrf
def close_alert(alert_id):
    try:
        # Task 1: sole-MLRO self-review attestation. A checkbox, so it's only
        # present in the POST when actually ticked; the engine decides whether
        # it's permitted/required, so a spurious flag on a normal closure is
        # simply ignored (self_reviewed stays 0 unless the sole-MLRO path fires).
        self_attested = request.form.get("self_review_attestation") == "on"
        AMLService.close_alert(g.user["company_id"], alert_id, g.user["sub"], request.form.get("narrative"),
                               request.form.get("closure_reason_code"), request.form.get("sar_reference"),
                               g.user["role"], mlro_rationale=request.form.get("mlro_rationale"),
                               self_attested=self_attested)
        flash("Alert closed.", "success")
    except WorkflowError as e: flash(str(e), "error")
    return redirect(url_for("alert_detail", alert_id=alert_id))

@app.route("/escalate/<alert_id>", methods=["POST"])
@auth_security.require_auth
@auth_security.require_csrf
def escalate_alert(alert_id):
    try:
        narrative = request.form.get("narrative", "")
        # Same 15-char floor as bulk escalation (see /bulk-action) and the
        # closure narrative check in transition_alert — the shared textarea
        # in alert_detail.html enforces this client-side via minlength="15",
        # but that's a UX nicety, not a security boundary; a direct POST
        # bypassing the browser must be rejected here too, server-side.
        if len(narrative.strip()) < 15:
            flash("A narrative of at least 15 characters is required to escalate.", "error")
            return redirect(url_for("alert_detail", alert_id=alert_id))
        AMLService.escalate_alert(g.user["company_id"], alert_id, g.user["sub"], g.user["role"], narrative=narrative)
        flash("Alert escalated.", "success")
    except WorkflowError as e:
        flash(str(e), "error")
    return redirect(url_for("alert_detail", alert_id=alert_id))

@app.route("/return-to-analyst/<alert_id>", methods=["POST"])
@auth_security.require_auth
@auth_security.require_csrf
def return_to_analyst(alert_id):
    try:
        AMLService.return_to_analyst(
            g.user["company_id"], alert_id, g.user["sub"], request.form.get("return_note"), g.user["role"]
        )
        try:
            AMLService.log_alert_view(g.user["company_id"], alert_id, g.user["sub"], g.user["role"])
        except Exception:
            pass
        flash("Alert returned to analyst for further review.", "success")
    except WorkflowError as e:
        flash(str(e), "error")
    return redirect(url_for("alert_detail", alert_id=alert_id))

@app.route("/bulk-action", methods=["POST"])
@auth_security.require_auth
@auth_security.require_csrf
def bulk_action():
    action = request.form.get("action")
    alert_ids = request.form.getlist("alert_ids")
    narrative = request.form.get("narrative", "")

    if not alert_ids:
        flash("No alerts selected.", "error")
        return redirect(request.referrer or url_for("alert_queue"))

    # Item 6: bulk actions are restricted to claim + false-positive
    # closure. Escalation and SAR filing are per-alert compliance
    # judgments and must go through the single-alert forms.
    if action not in ("claim", "false_positive"):
        flash(f"Unsupported bulk action: {action}. Bulk actions are limited to claim and false-positive closure.", "error")
        return redirect(request.referrer or url_for("alert_queue"))

    if action == "false_positive" and len(narrative.strip()) < 15:
        flash("A narrative of at least 15 characters is required to bulk-close as false positive.", "error")
        return redirect(request.referrer or url_for("alert_queue"))

    try:
        result = AMLService.bulk_transition(g.user["company_id"], alert_ids, action, g.user["sub"], g.user["role"], narrative=narrative)
    except ValueError as e:
        flash(str(e), "error")
        return redirect(request.referrer or url_for("alert_queue"))

    succeeded, failed = result["succeeded"], result["failed"]
    if succeeded:
        flash(f"{len(succeeded)} alert(s) actioned successfully ({action}).", "success")
    if failed:
        detail = "; ".join(f"{aid[:8]}…: {reason}" for aid, reason in failed[:3])
        more = f" (+{len(failed) - 3} more)" if len(failed) > 3 else ""
        flash(f"{len(failed)} alert(s) failed: {detail}{more}", "error")

    return redirect(request.referrer or url_for("alert_queue"))

@app.route("/case/create/<alert_id>", methods=["POST"])
@auth_security.require_auth
@auth_security.require_csrf
def create_case(alert_id):
    try:
        case_id = AMLService.create_case(g.user["company_id"], alert_id)
        flash(f"Case created successfully: {case_id}", "success")
    except Exception as e:
        flash(f"Error creating case: {str(e)}", "error")
    return redirect(url_for("alert_detail", alert_id=alert_id))

@app.route("/case/<case_id>/link/<alert_id>", methods=["POST"])
@auth_security.require_auth
@auth_security.require_csrf
def link_alert_to_case(case_id, alert_id):
    try:
        AMLService.link_alert_to_case(g.user["company_id"], alert_id, case_id)
        flash("Alert linked to case.", "success")
    except ValueError as e:
        flash(str(e), "error")
    except Exception as e:
        flash(f"Unexpected error: {e}", "error")
    return redirect(url_for("alert_detail", alert_id=alert_id))

@app.route("/case/<case_id>")
@auth_security.require_auth
def case_detail(case_id):
    try:
        result = AMLService.get_case(g.user["company_id"], case_id)
        if result is None:
            abort(404)
        return render_template("case_detail.html", case=result["case"], alerts=result["alerts"])
    except HTTPException:
        raise
    except Exception as e:
        flash(f"Error accessing case records: {e}", "error")
        return redirect(url_for("alert_queue"))

@app.route("/run-pipeline", methods=["POST"])
@auth_security.require_auth
@auth_security.require_role("MLRO", "TENANT_ADMIN")
@auth_security.require_csrf
def run_pipeline():
    if _pipeline_state["running"]:
        flash("A data pipeline run is already in progress — please wait for it to finish.", "error")
        return redirect(request.referrer or url_for("alert_queue"))

    remaining = _seconds_remaining(_pipeline_state["last_run_at"], PIPELINE_COOLDOWN_SECONDS)
    if remaining > 0:
        flash(f"The pipeline was just run — please wait {int(remaining)}s before running it again.", "error")
        return redirect(request.referrer or url_for("alert_queue"))

    _pipeline_state["running"] = True
    try:
        company_id = g.user["company_id"]
        root_dir = os.path.dirname(os.path.abspath(__file__))
        subprocess.run(["python", "sanctions_pep_seed.py", company_id], cwd=root_dir, check=True)
        subprocess.run(["python", "generator.py", company_id], cwd=root_dir, check=True)
        subprocess.run(["python", "aml_loader.py", company_id], cwd=root_dir, check=True)
        subprocess.run(["python", "aml_engine.py", company_id], cwd=root_dir, check=True)
        flash("Data pipeline executed successfully! Your workspace's data has been regenerated.", "success")
    except Exception as e:
        flash(f"Pipeline Execution Failed: {str(e)}", "error")
    finally:
        _pipeline_state["running"] = False
        _pipeline_state["last_run_at"] = time.time()
    return redirect(request.referrer or url_for("alert_queue"))

@app.route("/draft-sar/<alert_id>", methods=["POST"])
@auth_security.require_auth
@auth_security.require_csrf
def draft_sar(alert_id):
    """Item 13: ESCALATED -> DRAFT_SAR. MLRO-only."""
    try:
        mlro_rationale = request.form.get("mlro_rationale", "")
        if len(mlro_rationale.strip()) < 15:
            flash("A detailed MLRO rationale (at least 15 characters) is required to draft a SAR.", "error")
            return redirect(url_for("alert_detail", alert_id=alert_id))
        AMLService.draft_sar(g.user["company_id"], alert_id, g.user["sub"], g.user["role"], mlro_rationale)
        flash("SAR draft created.", "success")
    except WorkflowError as e:
        flash(str(e), "error")
    return redirect(url_for("alert_detail", alert_id=alert_id))

@app.route("/submit-sar/<alert_id>", methods=["POST"])
@auth_security.require_auth
@auth_security.require_csrf
def submit_sar(alert_id):
    """Item 13: DRAFT_SAR -> CLOSED_SAR. Prompts for the goAML reference."""
    try:
        goaml_ref = request.form.get("goaml_reference_number", "")
        narrative = request.form.get("narrative") or "SAR drafted and submitted following MLRO review."
        if not goaml_ref.strip():
            flash("A goAML reference number is required to submit the SAR.", "error")
            return redirect(url_for("alert_detail", alert_id=alert_id))
        self_attested = request.form.get("self_review_attestation") == "on"
        AMLService.submit_sar(g.user["company_id"], alert_id, g.user["sub"], g.user["role"], goaml_ref, narrative,
                              self_attested=self_attested)
        flash("SAR submitted and alert closed.", "success")
    except WorkflowError as e:
        flash(str(e), "error")
    return redirect(url_for("alert_detail", alert_id=alert_id))

@app.route("/case/<case_id>/narrative", methods=["POST"])
@auth_security.require_auth
@auth_security.require_csrf
def update_case_narrative(case_id):
    """Item 10: single overall case-assessment narrative."""
    try:
        AMLService.update_case_narrative(g.user["company_id"], case_id, request.form.get("case_narrative", ""))
        flash("Case narrative updated.", "success")
    except Exception as e:
        flash(f"Error updating case narrative: {e}", "error")
    return redirect(url_for("case_detail", case_id=case_id))

@app.route("/customers")
@auth_security.require_auth
def customers():
    """Item 9: customer profiles with CRR, last review date, open alert count."""
    search = request.args.get("q")
    edd_only = request.args.get("edd_only") == "1"
    rows = AMLService.get_customers(g.user["company_id"], search=search, edd_only=edd_only)
    return render_template("customers.html", customers=rows, search=search or "",
                            edd_only=edd_only, current_role=g.user["role"])

@app.route("/customer/<account_id>")
@auth_security.require_auth
def customer_detail(account_id):
    """Single-customer KYC profile view: identity, Initial Risk Matrix,
    and the account's full alert history."""
    customer = AMLService.get_customer_profile(g.user["company_id"], account_id)
    if customer is None:
        abort(404)
    account_alerts = AMLService.get_alerts_for_account(g.user["company_id"], account_id)
    return render_template("customer_detail.html", customer=customer,
                           account_alerts=account_alerts, current_role=g.user["role"])

@app.route("/rule-performance")
@auth_security.require_auth
def rule_performance():
    """Item 17: false-positive rate per scenario."""
    rows = AMLService.get_rule_performance(g.user["company_id"])
    return render_template("rule_performance.html", rows=rows, current_role=g.user["role"])

# ── Item 2: Wire interdiction routes ──────────────────────────────────────

@app.route("/wire")
@auth_security.require_auth
def wire_submit_form():
    """Pre-transaction wire submission form — simulates a payments ops
    user releasing a correspondent-banking wire. Screen happens here,
    before the payment posts, not in the next batch run."""
    accounts = AMLService.get_correspondent_accounts(g.user["company_id"])
    return render_template("wire_submit.html", accounts=accounts, current_role=g.user["role"])

@app.route("/wire/submit", methods=["POST"])
@auth_security.require_auth
@auth_security.require_csrf
def wire_submit():
    try:
        account_id = request.form.get("account_id", "").strip()
        amount = float(request.form.get("amount", 0) or 0)
        country = request.form.get("country", "").strip().upper()
        ordering = request.form.get("ordering_customer_name", "").strip()
        beneficiary = request.form.get("beneficiary_name", "").strip()
        bic = request.form.get("originating_bank_bic", "").strip() or None
        ref = request.form.get("reference", "").strip() or None

        if not account_id or amount <= 0 or not country or not ordering or not beneficiary:
            flash("All fields except BIC and Reference are required.", "error")
            return redirect(url_for("wire_submit_form"))

        result = AMLService.submit_wire_transfer(
            g.user["company_id"], account_id, amount, country, ordering, beneficiary, bic, ref,
        )
        return render_template(
            "wire_result.html", result=result, current_role=g.user["role"],
        )
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("wire_submit_form"))

@app.route("/wire/log")
@auth_security.require_auth
def wire_log():
    log_entries = AMLService.get_wire_interdiction_log(g.user["company_id"])
    return render_template("wire_log.html", entries=log_entries, current_role=g.user["role"])

# ── Item 7: Network / link analysis routes ────────────────────────────────

@app.route("/network/<account_id>")
@auth_security.require_auth
def account_network(account_id):
    data = AMLService.get_account_network(g.user["company_id"], account_id)
    if not data:
        abort(404)
    return render_template("account_network.html", data=data, current_role=g.user["role"])

@app.route("/ctr-filings")
@auth_security.require_auth
def ctr_filings():
    """Mandatory Currency Transaction Reports — auto-filed by the engine,
    visible here so a compliance supervisor can confirm the obligation was
    met and pull individual filings for a regulator."""
    data = AMLService.get_ctr_filings(
        g.user["company_id"],
        account_id=request.args.get("account_id") or None,
        date_from=request.args.get("date_from") or None,
        date_to=request.args.get("date_to") or None,
    )
    return render_template("ctr_filings.html", data=data, current_role=g.user["role"])

@app.route("/regulatory-report")
@auth_security.require_auth
def regulatory_report():
    """Item 18: regulator-facing monthly summary."""
    period_start = request.args.get("period_start")
    period_end = request.args.get("period_end")
    report = AMLService.get_regulatory_report(g.user["company_id"], period_start, period_end)
    return render_template("regulatory_report.html", report=report, current_role=g.user["role"])

@app.route("/reports")
@auth_security.require_auth
def reports():
    return render_template("reports.html", report=AMLService.get_sla_report(g.user["company_id"]))

@app.route("/reports/export.pdf")
@auth_security.require_auth
def export_sla_report_pdf():
    report = AMLService.get_sla_report(g.user["company_id"])
    pdf_bytes = aml_pdf.render_sla_report_pdf(report)

    filename = f"aml_sla_report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )

if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)