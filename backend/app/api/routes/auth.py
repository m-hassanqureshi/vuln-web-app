"""HTTP route handlers.

All eight endpoints of the lab app live here. The handlers are
deliberately thin: they parse request inputs, call into the service layer
(`auth_service`) or directly query the DB for read-only routes, render or
escape any HTML, and return a Response. No business logic, no SQL string
construction, and no password hashing happens in this module.

Route summary:
- GET  /         redirect to /signup (default landing page)
- GET  /signup   render signup form (issues CSRF token)
- POST /signup   create account, redirect to /login
- GET  /login    render login form (issues CSRF token)
- POST /login    authenticate, write session, return JSON
- GET  /search   case-insensitive search across users (intentionally public)
- GET  /welcome  protected dashboard (requires session)
- GET  /logout   clear session, redirect to /login

Closed vulnerabilities relevant to this file:
- VULN-1 (SQL Injection): `/search` uses parameterized `LIKE ?`.
- VULN-2 (Stored XSS): `/welcome` escapes the username before splicing
  into the dashboard template.
- VULN-3 (Reflected XSS): `/search` escapes q, every row column, and the
  exception text before splicing into the response HTML.
- VULN-6 (Exposed Database): the pre-fix `/download/db` route is gone.
- VULN-8 (CSRF): GET /signup and GET /login splice a per-session token
  into a hidden form field; the CSRFMiddleware validates it on POST.
"""

import os
import html
import logging

from fastapi import APIRouter, Form, Request, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse

from app.core.csrf import get_or_create_csrf_token
from app.core import config
from app.core import qr_login
from app.core import captcha
from app.core.oauth import oauth
from app.services import auth_service
from app.services import oauth_service
from app.services import verification_service
from app.services import otp_service
from app.services import totp_service
from app.services import password_reset_service
from app.services import avatar_service
from app.services import session_service
from app.db.session import get_db
from app.core import audit_logger

logger = logging.getLogger(__name__)

router = APIRouter()

# Absolute path to frontend/templates. The four `..` segments climb from
# this file (backend/app/api/routes/auth.py) back up to the repo root.
# Resolved at import time so the path is stable regardless of CWD.
BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
TEMPLATE_DIR = os.path.join(BASE_DIR, "frontend", "templates")


def _load_template(name: str) -> str:
    """Read a template file from disk on every call (no caching, no engine).

    Mirrors the inline `with open(...)` pattern used elsewhere in this module,
    factored out so the new routes that just render a static page (and the
    email-not-configured gate used in two places) stay one-liners.
    """
    with open(os.path.join(TEMPLATE_DIR, name), "r", encoding="utf-8") as f:
        return f.read()



def _render_page(name: str, replacements: dict[str, str]) -> str:
    """Load a page template and splice in shared partials + caller tokens.

    UI/UX polish: every page shares the same theme-init <script>, <header>,
    and theme-toggle IIFE. Centralizing that in `frontend/templates/_header.html`
    removes ~12x duplication. This helper is the server-side equivalent: it
    reads the page template, reads the shared header partial once, splices the
    partial into the page wherever `{{partial:header}}` appears, then applies
    the caller-supplied token replacements (csrf_token, title, body_attrs,
    turnstile_*, username, email, token, valid, twofa_enabled, etc.).

    Pure string substitution -- no SQL, no auth, no middleware. The XSS posture
    is unchanged: every attacker-controllable replacement (csrf_token, username,
    email, token, title, message) is still HTML-escaped by the caller before
    being placed in the dict, exactly as it was when the route did its own
    str.replace() calls.
    """
    page = _load_template(name)
    # Splice the shared header partial once per render. The partial is loaded
    # from disk and embedded as a literal string, so its own {{csrf_token}}
    # placeholder is a *server-time* splice, not a client-side reflection
    # (same posture as every other VULN-2/3 splice in this module).
    header = _load_template("_header.html")
    page = page.replace("{{partial:header}}", header)
    # Then apply all caller-supplied tokens.
    for token, value in replacements.items():
        page = page.replace(token, value)
    # Clean up Turnstile header placeholder if not replaced by route
    if "{{turnstile_head}}" in page:
        page = page.replace("{{turnstile_head}}", "")
    return page


@router.get("/")
async def index():
    """Default landing page -- send first-time visitors straight to signup."""
    return RedirectResponse(url="/signup", status_code=302)


@router.get("/signup")
async def signup_page(request: Request):
    """Render the signup HTML form with a per-session CSRF token spliced in.

    Templates are loaded from disk on every request (no caching, no
    template engine) so live edits to the HTML files take effect on
    refresh. The CSRF token splice uses the same str.replace pattern as
    /welcome -- minimal infrastructure, easy for students to read.

    Email-verification gate (v1.0.4): signup creates an UNVERIFIED account and
    emails a confirmation link, so it cannot work without SMTP. When email is
    not configured we render the friendly setup page instead of a form that
    can't succeed -- mirrors the Continue-with-Google "not configured" degrade.
    """
    if not config.is_email_configured():
        page = _render_page(
            "email_not_configured.html",
            {
                "{{title}}": "Email Verification Not Configured - Security Vulnerability Lab",
                "{{body_attrs}}": "",
            },
        )
        return HTMLResponse(content=page)

    # FIXED: CSRF closed -- splice the per-session token into the form's hidden field.
    # get_or_create_csrf_token() is idempotent: it returns the existing
    # token if one is already in the session, or generates one if not.
    # html.escape is defensive only -- the token alphabet (URL-safe Base64)
    # contains no HTML-significant characters today, but escaping keeps the
    # splice safe under future token-format changes.
    token = get_or_create_csrf_token(request)
    page = _render_page(
        "signup.html",
        {
            "{{title}}": "Sign Up - Security Vulnerability Lab",
            "{{body_attrs}}": "",
            "{{csrf_token}}": html.escape(token, quote=True),
        },
    )
    return HTMLResponse(content=page)


@router.post("/signup")
async def signup_post(
    request: Request,
    username: str = Form(""),
    email: str = Form(""),
    password: str = Form(""),
):
    """Handle signup form submission.

    Defaults of `Form("")` mean missing fields become empty strings rather
    than raising 422 -- the service layer handles the "all fields required"
    case with a user-friendly HTML error.

    The hidden `csrf_token` field is also POSTed but is consumed and
    validated by CSRFMiddleware before this handler runs; FastAPI's
    Form() ignores unknown form fields, so it transparently disappears.

    Email-verification gate (v1.0.4): refuse to create an account that could
    never be verified. Defense in depth against a direct POST that skips the
    gated GET /signup page -- same not-configured page, no row inserted.
    """
    if not config.is_email_configured():
        page = _render_page(
            "email_not_configured.html",
            {
                "{{title}}": "Email Verification Not Configured - Security Vulnerability Lab",
                "{{body_attrs}}": "",
            },
        )
        return HTMLResponse(content=page)

    return auth_service.signup(username, email, password, request)


@router.get("/check-email")
async def check_email_page():
    """Static "we sent you a verification link" page shown right after signup.

    No user input is reflected here (intentionally generic -- it does not name
    the address), so there is no sink to escape. Loaded fresh from disk like
    every other template.
    """
    page = _render_page(
        "check_email.html",
        {
            "{{title}}": "Check Your Inbox - Security Vulnerability Lab",
            "{{body_attrs}}": "",
        },
    )
    return HTMLResponse(content=page)


@router.get("/verify")
async def verify_email(request: Request):
    """Consume an email-verification link.

    Reads the high-entropy token from the query string and asks the service to
    validate it. Renders a fixed, server-controlled outcome message -- the raw
    token is NEVER reflected back into the page (VULN-3 posture). This is a GET
    because the capability is the unguessable token in the link itself, exactly
    like the OAuth GET callback; the POST-only CSRF/rate-limit middleware
    correctly ignore it.
    """
    token = request.query_params.get("token", "")
    result = verification_service.verify_email_token(token, request)

    # On success, log the user straight in (clicking the emailed link proves
    # control of the address) by writing the SAME session keys as
    # auth_service.login(), then send them to their dashboard. This mutation is
    # what makes SessionMiddleware emit the signed Set-Cookie.
    if result["status"] == "ok":
        user = result["user"]
        session_service.establish_session(request, user["id"], user["username"], user["email"])
        return RedirectResponse(url="/welcome", status_code=302)

    # Expired / invalid: render a fixed, HTML-escaped outcome message. These
    # strings are author-controlled, but we still html.escape() them before
    # splicing -- same defensive output-encoding discipline used throughout
    # this module. The raw token is never reflected (VULN-3 posture).
    outcomes = {
        "expired": (
            "Link expired",
            "This verification link has expired. Go to the login page, enter "
            "your username and password, and use “Resend verification email”.",
        ),
        "invalid": (
            "Invalid link",
            "This verification link is invalid or has already been used.",
        ),
    }
    title, message = outcomes.get(result["status"], outcomes["invalid"])

    page = _render_page(
        "verify_result.html",
        {
            "{{title}}": "Email Verification - Security Vulnerability Lab",
            "{{body_attrs}}": "",
            "{{title_msg}}": html.escape(title, quote=True),
            "{{message}}": html.escape(message, quote=True),
        },
    )
    return HTMLResponse(content=page)


@router.post("/verify/resend")
async def verify_resend(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
):
    """Re-issue + re-send the verification email, gated on valid credentials.

    Login is blocked until verification, so an unverified user has no session
    to gate on. The login page calls this with the username + password the user
    just entered; verification_service.resend_for_credentials() re-checks them
    with bcrypt (the password is the authorization) and re-issues the link.
    Thin handler -- same shape as login_post(). The hidden csrf_token and the
    per-IP rate limit are enforced by middleware before this runs (it is a
    POST); FastAPI's Form() ignores the extra csrf_token field.
    """
    return verification_service.resend_for_credentials(username, password)


@router.get("/login")
async def login_page(request: Request):
    """Render the login HTML form with a per-session CSRF token spliced in.

    Same pattern as signup_page(): load template, issue/read token,
    splice via _render_page (which embeds the shared header partial).
    """
    # FIXED: CSRF closed -- splice the per-session token into the form's hidden field.
    token = get_or_create_csrf_token(request)
    # CAPTCHA on Login (v2.0.0): render the Cloudflare Turnstile widget + script
    # only when both keys are configured; otherwise both placeholders collapse to
    # "" and the login page is byte-for-byte the pre-CAPTCHA page (graceful degrade).
    if config.is_captcha_configured():
        turnstile_head = (
            '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"'
            " async defer></script>"
        )
        turnstile_widget = (
            '<div class="cf-turnstile" data-sitekey="'
            + html.escape(config.TURNSTILE_SITE_KEY, quote=True)
            + '"></div>'
        )
    else:
        turnstile_head = turnstile_widget = ""
    page = _render_page(
        "login.html",
        {
            "{{csrf_token}}": html.escape(token, quote=True),
            "{{title}}": "Login - Security Vulnerability Lab",
            "{{body_attrs}}": "",
            "{{turnstile_head}}": turnstile_head,
            "{{turnstile_widget}}": turnstile_widget,
        },
    )
    return HTMLResponse(content=page)


@router.post("/login")
async def login_post(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    cf_turnstile_response: str = Form("", alias="cf-turnstile-response"),
):
    """Handle login form submission.

    CAPTCHA on Login (v2.0.0): when Turnstile is configured, the token is
    verified BEFORE auth_service.login() -- a request that fails the CAPTCHA
    never reaches the lockout gate, bcrypt, or the DB, and writes no session.
    A failed check returns 400 with a fixed message (the raw token is never
    reflected or logged -- VULN-3). When Turnstile is unconfigured the check is
    skipped entirely (graceful degrade). The Form alias is required because the
    Turnstile field name (`cf-turnstile-response`) contains hyphens.

    The Request parameter is forwarded to the service layer so it can
    write user_id/username/email into `request.session` on success --
    that mutation is what triggers SessionMiddleware to write the
    Set-Cookie header on the response.
    """
    if config.is_captcha_configured() and not captcha.verify(cf_turnstile_response):
        return JSONResponse(
            {"error": "CAPTCHA verification failed. Please try again."},
            status_code=400,
        )
    return auth_service.login(request, username, password)


@router.get("/search")
async def search_user(q: str = ""):
    """Public, unauthenticated user search by partial username or email.

    Intentionally accessible without a session -- exists for students to
    practice reflected-XSS and SQLi against. Both classes of attack are
    now closed (see FIXED comments below), but the endpoint itself stays.
    """
    if not q:
        return HTMLResponse(content="<h3>No search query provided</h3>")

    # FIXED: SQL Injection closed by using parameterized query
    # FIXED: Reflected XSS closed -- q, row columns, and exception text are HTML-escaped before splicing.
    # The raw values remain in the URL and in the database (output-encoding fix, not input filtering).
    #
    # Why parameterize the LIKE wildcards too? The `?` binds the WHOLE
    # value including the surrounding `%`, so `q = '%foo'` would not let
    # an attacker break out of the LIKE clause -- the `%` is data, not
    # syntax. This is the canonical safe LIKE pattern.
    query = "SELECT username, email FROM users WHERE username LIKE ? OR email LIKE ?"

    conn = get_db()
    try:
        cursor = conn.execute(query, [f"%{q}%", f"%{q}%"])
        rows = cursor.fetchall()

        # Every sink that gets spliced back into HTML gets html.escape()'d
        # with quote=True. quote=True is essential because the values flow
        # into an HTML body -- if any of them later move into an attribute
        # context, the quoted form prevents attribute-injection too.
        safe_q = html.escape(q, quote=True)
        results = ""
        for row in rows:
            safe_username = html.escape(row[0], quote=True)
            safe_email = html.escape(row[1], quote=True)
            results += f"<li>{safe_username} ({safe_email})</li>"

        page = f"<h3>Search results for: {safe_q}</h3><ul>{results}</ul>"
        return HTMLResponse(content=page)
    except Exception as e:
        # Even the exception text is escaped before being reflected --
        # sqlite3 occasionally surfaces user-controlled bytes in its
        # error messages, so this is a real sink, not a paranoia escape.
        safe_error = html.escape(str(e), quote=True)
        return HTMLResponse(content=f"<h3>Error: {safe_error}</h3>")
    finally:
        conn.close()


@router.get("/welcome")
async def welcome_page(request: Request):
    """Render the post-login dashboard.

    Auth check happens here, not in middleware: the only protected route
    is /welcome, so a per-route check is simpler than a route-table or
    decorator-based scheme.
    """
    # If no session cookie or the cookie's payload doesn't carry user_id,
    # the user has not logged in -- bounce them to /login. This is the
    # only authorization gate in the app.
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)

    # Username is written into the session by auth_service.login(). The
    # "" default lets the template render with an empty <strong> tag if
    # the session was somehow torn (shouldn't happen, defensive only).
    #
    # Note: only verified users ever reach here -- login() refuses to create a
    # session for an unverified account (Email-Verification, v1.0.4) -- so the
    # dashboard needs no verification check or banner.
    username = request.session.get("username", "")

    # FIXED: Stored XSS closed -- username escaped before substitution.
    # The raw value remains in the session/database (output-encoding fix, not input filtering).
    #
    # The raw username can contain `<script>` from a malicious signup --
    # we do NOT sanitize on the way in (that would lose information and
    # is famously fragile). Instead we escape on the way out, so the
    # rendered HTML treats the username as text, never as markup.
    conn = get_db()
    try:
        user_row = conn.execute("SELECT role FROM users WHERE id = ?", [user_id]).fetchone()
    finally:
        conn.close()
    
    is_admin = bool(user_row and user_row["role"] == "admin")
    admin_link_html = '<a href="/admin" class="btn btn-logout">Admin Panel</a>' if is_admin else ''

    # Fetch status of advanced vulnerability labs
    ci_status = get_lab_status(user_id, "command_injection")
    ssrf_status = get_lab_status(user_id, "ssrf")
    xxe_status = get_lab_status(user_id, "xxe")

    def make_badge(status):
        if status == "solved":
            return '<span class="badge badge-verified" style="background: rgba(46, 117, 89, 0.15); color: var(--color-success); font-size: 0.75rem; font-weight: 600; padding: 3px 10px; border-radius: 9999px; display: inline-flex; align-items: center; border: 1px solid rgba(46, 117, 89, 0.2);">Solved</span>'
        elif status == "exploited":
            return '<span class="badge badge-unverified" style="background: rgba(186, 26, 26, 0.15); color: var(--color-error); font-size: 0.75rem; font-weight: 600; padding: 3px 10px; border-radius: 9999px; display: inline-flex; align-items: center; border: 1px solid rgba(186, 26, 26, 0.2);">Exploited</span>'
        return '<span class="badge badge-none" style="background: var(--color-border-soft); color: var(--color-text-secondary); font-size: 0.75rem; font-weight: 600; padding: 3px 10px; border-radius: 9999px; display: inline-flex; align-items: center;">Unsolved</span>'

    ci_badge = make_badge(ci_status)
    ssrf_badge = make_badge(ssrf_status)
    xxe_badge = make_badge(xxe_status)

    page = _render_page(
        "dashboard.html",
        {
            "{{title}}": "Dashboard - Security Vulnerability Lab",
            "{{body_attrs}}": 'class="dashboard-body"',
            "{{username}}": html.escape(username, quote=True),
            "{{admin_link}}": admin_link_html,
            "{{ci_badge}}": ci_badge,
            "{{ssrf_badge}}": ssrf_badge,
            "{{xxe_badge}}": xxe_badge,
        },
    )

    return HTMLResponse(content=page)


@router.get("/profile")
async def profile_page(request: Request):
    """Render the authenticated profile page.

    Same auth gate as /welcome: no user_id in the session -> bounce to
    /login. Splices the per-session CSRF token (for the change-password
    form) plus the HTML-escaped username and email read from the session.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)

    username = request.session.get("username", "")
    email = request.session.get("email", "")

    # 2FA cards (Email OTP v1.0.6 + Authenticator-App TOTP v1.0.7): the session
    # does not carry either flag, so read both for the cards' initial state
    # (parameterized SELECT -- VULN-1). Also SELECT picture and role.
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT two_factor_enabled, totp_enabled, picture, role FROM users WHERE id = ?",
            [user_id],
        ).fetchone()
    finally:
        conn.close()
    twofa_enabled = bool(row["two_factor_enabled"]) if row else False
    totp_enabled = bool(row["totp_enabled"]) if row else False
    picture = row["picture"] if row and row["picture"] else ""
    is_admin = bool(row and row["role"] == "admin")
    admin_link_html = '<a href="/admin" class="btn btn-logout">Admin Panel</a>' if is_admin else ''

    import json
    active_sessions = session_service.get_active_sessions(user_id)
    current_session_id = request.session.get("session_id")
    for s in active_sessions:
        s["is_current"] = (s["session_id"] == current_session_id)
    sessions_json = json.dumps(active_sessions).replace("</script>", "<\\/script>")

    # FIXED: CSRF closed -- issue/splice the per-session token for the form.
    token = get_or_create_csrf_token(request)

    # FIXED: Stored XSS closed -- escape every user-controlled value before
    # splicing (output encoding, same posture as the dashboard username).
    page = _render_page(
        "profile.html",
        {
            "{{title}}": "Profile - Security Vulnerability Lab",
            "{{body_attrs}}": 'class="dashboard-body"',
            "{{csrf_token}}": html.escape(token, quote=True),
            "{{username}}": html.escape(username, quote=True),
            "{{email}}": html.escape(email, quote=True),
            # Server-controlled "0"/"1" flags for the 2FA cards (not user input).
            "{{twofa_enabled}}": "1" if twofa_enabled else "0",
            "{{email_configured}}": "1" if config.is_email_configured() else "0",
            "{{totp_enabled}}": "1" if totp_enabled else "0",
            "{{picture}}": html.escape(picture, quote=True),
            "{{active_sessions}}": sessions_json,
            "{{admin_link}}": admin_link_html,
        },
    )

    return HTMLResponse(content=page)


@router.post("/profile/2fa")
async def profile_2fa_post(request: Request, enable: str = Form("")):
    """Enable/disable Email OTP 2FA for the logged-in user (v1.0.6).

    Session-gated only -- no current-password re-prompt (a deliberate product
    choice favouring UX; see the spec's NFR-09). The hidden csrf_token and the
    per-IP rate limit are enforced by middleware before this runs; FastAPI's
    Form() ignores the extra csrf_token field. Enabling is refused when SMTP is
    not configured, because a future login could not deliver the OTP.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)

    want_enable = enable == "1"
    if want_enable and not config.is_email_configured():
        return JSONResponse(
            content={
                "error": "Email delivery is not configured, so OTP 2FA can't be enabled."
            },
            status_code=400,
        )
    if not otp_service.set_two_factor(user_id, want_enable):
        return JSONResponse(
            content={"error": "Could not update the 2FA setting."}, status_code=400
        )
    username = request.session.get("username", "")
    ip = request.client.host if request and request.client else ""
    audit_logger.log_security_event("2fa_toggle", username, ip, f"Status: {'enabled' if want_enable else 'disabled'}")
    return JSONResponse(
        content={
            "success": True,
            "two_factor_enabled": want_enable,
            "message": "Two-factor authentication "
            + ("enabled." if want_enable else "disabled."),
        }
    )


@router.post("/profile/avatar")
async def profile_avatar_post(
    request: Request,
    avatar: UploadFile = File(...)
):
    """Handle avatar profile picture upload.

    Session-gated and CSRF-protected.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)

    try:
        file_data = await avatar.read()
    except Exception:
        logger.exception("Failed to read uploaded avatar file data")
        return JSONResponse(content={"error": "Failed to read file data."}, status_code=400)

    res = avatar_service.save_avatar(
        user_id=user_id,
        file_data=file_data,
        client_filename=avatar.filename or "",
        content_type=avatar.content_type or "",
        request=request
    )

    if res["status"] != "success":
        return JSONResponse(content={"error": res["error"]}, status_code=400)

    return JSONResponse(
        content={
            "success": True,
            "message": "Profile picture updated successfully.",
            "url": f"/static/uploads/{res['filename']}"
        }
    )


@router.post("/profile/sessions/revoke")
async def profile_sessions_revoke_post(
    request: Request,
    session_id: str = Form("")
):
    """Revoke a specific database session for the logged-in user.

    Session-gated and CSRF-protected.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)

    if not session_id:
        return JSONResponse(content={"error": "Session ID is required."}, status_code=400)

    ok = session_service.revoke_session(session_id, user_id)
    if not ok:
        return JSONResponse(content={"error": "Could not revoke the session."}, status_code=400)

    username = request.session.get("username", "")
    ip = request.client.host if request and request.client else ""
    audit_logger.log_security_event("session_revoke", username, ip, f"Revoked session_id: {session_id}")
    return JSONResponse(
        content={
            "success": True,
            "message": "Session revoked successfully."
        }
    )


@router.post("/profile/sessions/revoke-all")
async def profile_sessions_revoke_all_post(
    request: Request
):
    """Revoke all other database sessions for the logged-in user.

    Session-gated and CSRF-protected.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)

    current_session_id = request.session.get("session_id")
    if not current_session_id:
        return JSONResponse(content={"error": "Current session not found."}, status_code=400)

    ok = session_service.revoke_all_other_sessions(current_session_id, user_id)
    if not ok:
        return JSONResponse(content={"error": "Could not revoke other sessions."}, status_code=400)

    username = request.session.get("username", "")
    ip = request.client.host if request and request.client else ""
    audit_logger.log_security_event("session_revoke_all", username, ip, f"Revoked all other sessions except: {current_session_id}")
    return JSONResponse(
        content={
            "success": True,
            "message": "All other sessions revoked successfully."
        }
    )


@router.get("/login/otp")
async def login_otp_page(request: Request):
    """Render the OTP entry screen -- only mid-2FA-login (pending marker set).

    Gated on request.session["pending_2fa_user_id"], which auth_service.login()
    writes after a correct password + verified gate when 2FA is on. With no
    pending marker (deep link, or after logout) we bounce to /login. The screen
    reflects NO user input (no email, no code) -- a fixed prompt only (VULN-3).
    """
    if not request.session.get("pending_2fa_user_id"):
        return RedirectResponse(url="/login", status_code=302)
    # FIXED: CSRF closed -- splice the per-session token into the form's hidden field.
    token = get_or_create_csrf_token(request)
    page = _render_page(
        "otp_verify.html",
        {
            "{{title}}": "Verify Login - Security Vulnerability Lab",
            "{{body_attrs}}": "",
            "{{csrf_token}}": html.escape(token, quote=True),
        },
    )
    return HTMLResponse(content=page)


@router.post("/login/otp")
async def login_otp_post(request: Request, otp: str = Form("")):
    """Verify the OTP and complete the login by writing the full session.

    Reads the pending user id from the session (set by login()) and the submitted
    code. On success it clears the pending keys, writes the SAME session keys as
    a normal login (user_id/username/email) -- this mutation is what makes
    SessionMiddleware emit the signed Set-Cookie -- and 302-able-redirects to
    /welcome. Every other outcome returns a fixed JSON error and no session
    (the raw code is never echoed -- VULN-3).
    """
    user_id = request.session.get("pending_2fa_user_id")
    if not user_id:
        return JSONResponse(
            content={"error": "Your login session expired. Please sign in again."},
            status_code=401,
        )

    result = otp_service.verify(user_id, otp)
    if result["status"] == "ok":
        user = result["user"]
        request.session.pop("pending_2fa_user_id", None)
        request.session.pop("pending_2fa_username", None)
        session_service.establish_session(request, user["id"], user["username"], user["email"])
        return JSONResponse(content={"success": True, "redirect": "/welcome"})

    messages = {
        "invalid": "Incorrect code. Please try again.",
        "too_many": "Too many incorrect attempts. Request a new code.",
        "expired": "This code has expired. Request a new one.",
        "no_challenge": "No active code. Please sign in again.",
    }
    return JSONResponse(
        content={"error": messages.get(result["status"], messages["invalid"])},
        status_code=401,
    )


@router.post("/login/otp/resend")
async def login_otp_resend(request: Request):
    """Re-send the OTP during a pending 2FA login, honouring the cooldown.

    Identified by the session's pending marker (no credentials re-submitted). The
    per-account resend cooldown is enforced via seconds_until_resend; the hidden
    csrf_token and per-IP rate limit are enforced by middleware (it is a POST).
    """
    user_id = request.session.get("pending_2fa_user_id")
    username = request.session.get("pending_2fa_username", "")
    if not user_id:
        return JSONResponse(
            content={"error": "Your login session expired. Please sign in again."},
            status_code=401,
        )

    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized SELECT by primary key.
        row = conn.execute(
            "SELECT email, otp_last_sent FROM users WHERE id = ?", [user_id]
        ).fetchone()
    finally:
        conn.close()
    if not row:
        return JSONResponse(content={"error": "Please sign in again."}, status_code=401)

    wait = otp_service.seconds_until_resend(row)
    if wait > 0:
        return JSONResponse(
            content={
                "error": f"Please wait {wait} seconds before requesting another code."
            },
            status_code=429,
        )
    if otp_service.start_challenge(user_id, username, row["email"], background=False):
        return JSONResponse(
            content={
                "success": True,
                "message": "Verification code sent. Check your inbox.",
            }
        )
    return JSONResponse(
        content={"error": "Could not send the code. Please try again later."},
        status_code=400,
    )


@router.post("/profile/totp/setup")
async def profile_totp_setup(request: Request):
    """Begin authenticator-app (TOTP) enrollment for the logged-in user (v1.0.7).

    Session-gated only -- no current-password re-prompt (same deliberate product
    choice as the Email-OTP toggle; see the spec's NFR-09). Generates a fresh
    PENDING secret and returns the QR + manual-entry key for the user to scan; the
    secret is not active until POST /profile/totp/confirm validates a code.
    Refused when TOTP is already enabled, so an active secret is never overwritten
    mid-use (the user must disable first to re-enroll). The hidden csrf_token and
    per-IP rate limit are enforced by middleware before this runs.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)

    username = request.session.get("username", "")
    # Re-enroll only after disabling, so an active secret is never overwritten.
    conn = get_db()
    try:
        # FIXED: SQL Injection closed -- parameterized SELECT by primary key.
        row = conn.execute(
            "SELECT totp_enabled FROM users WHERE id = ?", [user_id]
        ).fetchone()
    finally:
        conn.close()
    if row and row["totp_enabled"]:
        return JSONResponse(
            content={
                "error": "Authenticator 2FA is already enabled. Disable it first to re-enroll."
            },
            status_code=400,
        )

    data = totp_service.start_enrollment(user_id, username)
    if not data:
        return JSONResponse(
            content={"error": "Could not start enrollment. Please try again."},
            status_code=400,
        )
    # The secret/QR go ONLY to the authenticated owner (VULN-3): this is the
    # enrollment payload, not a reflection of attacker input.
    return JSONResponse(content={"success": True, **data})


@router.post("/profile/totp/confirm")
async def profile_totp_confirm(request: Request, code: str = Form("")):
    """Confirm enrollment by validating a current code, then activate TOTP (v1.0.7).

    Session-gated. Requiring a valid code proves the authenticator was provisioned
    correctly (prevents self-lockout from a mis-scanned QR). The raw code is never
    reflected back (VULN-3). On success totp_enabled flips to 1.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)

    result = totp_service.confirm(user_id, code)
    username = request.session.get("username", "")
    ip = request.client.host if request and request.client else ""
    if result["status"] == "ok":
        audit_logger.log_security_event("totp_confirm", username, ip, "success: Enabled Authenticator App")
        return JSONResponse(
            content={"success": True, "message": "Authenticator app enabled."}
        )
    messages = {
        "invalid": (
            "That code didn't match. Make sure your authenticator is set up and "
            "enter the current code."
        ),
        "no_pending": "Start setup first, then enter the code from your authenticator app.",
    }
    audit_logger.log_security_event("totp_confirm", username, ip, f"failure: status {result['status']}")
    return JSONResponse(
        content={"error": messages.get(result["status"], messages["invalid"])},
        status_code=400,
    )


@router.post("/profile/totp/disable")
async def profile_totp_disable(request: Request):
    """Disable authenticator-app (TOTP) 2FA for the logged-in user (v1.0.7).

    Session-gated (no password re-prompt; see NFR-09). Clears the secret, the
    flag, and the replay-guard step. The hidden csrf_token and per-IP rate limit
    are enforced by middleware before this runs.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)
    if not totp_service.disable(user_id):
        return JSONResponse(
            content={"error": "Could not update the setting."}, status_code=400
        )
    username = request.session.get("username", "")
    ip = request.client.host if request and request.client else ""
    audit_logger.log_security_event("totp_disable", username, ip, "success: Disabled Authenticator App")
    return JSONResponse(
        content={"success": True, "message": "Authenticator app disabled."}
    )


@router.get("/login/totp")
async def login_totp_page(request: Request):
    """Render the authenticator-code screen -- only mid-2FA-login via TOTP (v1.0.7).

    Gated on request.session["pending_2fa_user_id"] AND a "totp" method marker,
    both written by auth_service.login() after a correct password + verified gate
    when TOTP is enrolled. With no/other pending marker (deep link, after logout,
    or an email-OTP login) we bounce to /login. The screen reflects NO user input
    (no secret, no code) -- a fixed prompt only (VULN-3).
    """
    if (
        not request.session.get("pending_2fa_user_id")
        or request.session.get("pending_2fa_method") != "totp"
    ):
        return RedirectResponse(url="/login", status_code=302)
    # FIXED: CSRF closed -- splice the per-session token into the form's hidden field.
    token = get_or_create_csrf_token(request)
    page = _render_page(
        "totp_verify.html",
        {
            "{{title}}": "Verify Login - Security Vulnerability Lab",
            "{{body_attrs}}": "",
            "{{csrf_token}}": html.escape(token, quote=True),
        },
    )
    return HTMLResponse(content=page)


@router.post("/login/totp")
async def login_totp_post(request: Request, code: str = Form("")):
    """Verify the authenticator code and complete the login by writing the session.

    Reads the pending user id from the session (set by login()) and the submitted
    code. On success it clears the pending keys, writes the SAME session keys as a
    normal login (user_id/username/email) -- this mutation is what makes
    SessionMiddleware emit the signed Set-Cookie -- and redirects to /welcome.
    Every other outcome returns a fixed JSON error and no session (the raw code is
    never echoed -- VULN-3).
    """
    user_id = request.session.get("pending_2fa_user_id")
    if not user_id:
        return JSONResponse(
            content={"error": "Your login session expired. Please sign in again."},
            status_code=401,
        )

    result = totp_service.verify(user_id, code)
    ip = request.client.host if request and request.client else ""
    if result["status"] == "ok":
        user = result["user"]
        request.session.pop("pending_2fa_user_id", None)
        request.session.pop("pending_2fa_username", None)
        request.session.pop("pending_2fa_method", None)
        session_service.establish_session(request, user["id"], user["username"], user["email"])
        audit_logger.log_auth_event("login_totp", user["username"], ip, "success")
        return JSONResponse(content={"success": True, "redirect": "/welcome"})

    messages = {
        "invalid": "Incorrect code. Open your authenticator app and try again.",
        "no_challenge": "No active authenticator challenge. Please sign in again.",
    }
    username = request.session.get("pending_2fa_username", "unknown")
    audit_logger.log_auth_event("login_totp", username, ip, f"failure: {result['status']}")
    return JSONResponse(
        content={"error": messages.get(result["status"], messages["invalid"])},
        status_code=401,
    )


@router.post("/profile/password")
async def profile_password_post(
    request: Request,
    current_password: str = Form(""),
    new_password: str = Form(""),
):
    """Handle a change-password submission.

    Thin wrapper over auth_service.change_password() -- same shape as
    login_post(). The Request is forwarded so the service can read
    request.session["user_id"]. The CSRF token and per-IP rate limit are
    enforced by middleware before this handler runs; FastAPI's Form()
    ignores the extra csrf_token field.
    """
    return auth_service.change_password(request, current_password, new_password)


@router.get("/auth/google/login")
async def google_login(request: Request):
    """Start the Google OAuth 2.0 Authorization Code flow.

    Worker endpoint (no page of its own): when Google is configured it 302-
    redirects the browser to Google's consent screen; Authlib stashes the
    anti-CSRF `state` and anti-replay `nonce` in the session on the way out.

    If Google is NOT configured, we render a friendly setup page (HTTP 200)
    instead of crashing or redirecting nowhere -- a fresh clone stays usable
    and the password flow is unaffected.
    """
    if not config.is_google_configured():
        page = _render_page(
            "oauth_not_configured.html",
            {
                "{{title}}": "Google Login Not Configured - Security Vulnerability Lab",
                "{{body_attrs}}": "",
            },
        )
        return HTMLResponse(content=page)
    return await oauth.google.authorize_redirect(request, config.GOOGLE_REDIRECT_URI)


@router.get("/auth/google/callback")
async def google_callback(request: Request):
    """Handle Google's redirect back to the app (the registered redirect URI).

    Worker endpoint (no page of its own): it verifies the response, logs the
    user in via the SAME signed session cookie the password flow uses, and
    302s to /welcome. There is no JWT and no extra cookie -- the session is
    the single auth mechanism.

    Every failure mode degrades to /login WITHOUT leaking any detail to the
    client (the specifics are logged server-side):
      - user denied consent / provider error (`?error=...`)
      - invalid token / state mismatch / expired session (Authlib raises)
      - missing user information (no email/sub from Google)
    """
    # 1) User denied consent, or Google reported an error on the redirect.
    error = request.query_params.get("error")
    if error:
        logger.warning("Google OAuth callback returned error=%s", error)
        ip = request.client.host if request and request.client else ""
        audit_logger.log_auth_event("oauth_login", "unknown", ip, "failure", f"Google OAuth callback returned error: {error}")
        return RedirectResponse(url="/login", status_code=302)

    # 2) Exchange the code + verify the ID token. authorize_access_token()
    #    validates `state` (anti-CSRF), swaps the code for tokens, and verifies
    #    the ID token signature + iss/aud/exp/nonce. It raises on any mismatch
    #    or when the session (holding `state`/`nonce`) has expired.
    try:
        token = await oauth.google.authorize_access_token(request)
    except Exception as e:
        logger.warning("Google OAuth token exchange/verification failed", exc_info=True)
        ip = request.client.host if request and request.client else ""
        audit_logger.log_auth_event("oauth_login", "unknown", ip, "failure", f"Google OAuth token exchange failed: {str(e)}")
        return RedirectResponse(url="/login", status_code=302)

    # 3) Pull the verified profile claims.
    userinfo = token.get("userinfo") or {}
    google_id = userinfo.get("sub")
    email = userinfo.get("email")
    name = userinfo.get("name", "")
    picture = userinfo.get("picture", "")

    # 4) Resolve to a user row (create / link / return). None => missing info.
    user = oauth_service.find_or_create_google_user(google_id, email, name, picture)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    # 5) Log in by writing the SAME session keys as auth_service.login(). This
    #    mutation is what makes SessionMiddleware emit the signed Set-Cookie.
    #    Existing keys (e.g. csrf_token) are preserved -- we merge, not replace.
    session_service.establish_session(request, user["id"], user["username"], user["email"])
    ip = request.client.host if request and request.client else ""
    audit_logger.log_auth_event("oauth_login", user["username"], ip, "success", "Google OAuth")

    return RedirectResponse(url="/welcome", status_code=302)


@router.get("/qr/create")
async def qr_create(request: Request):
    """Vend a fresh QR-login token, bound to THIS browser's session (v1.0.8).

    Worker endpoint (returns JSON, no page): mint a token, render the QR for
    ``{APP_BASE_URL}/qr/scan/{token}``, and return both to the login page, which
    shows the QR and polls ``GET /qr/status``.

    GET on purpose: it vends an UNAUTHENTICATED capability that is useless until an
    already-authenticated device approves it -- there is nothing CSRF-sensitive to
    protect (mirrors the OAuth GET login). The crucial step is recording the token
    in ``request.session["qr_login_token"]``: this **owner-binding** is what later
    lets ONLY this browser be logged in by the token (see ``qr_status`` -- it closes
    the login-CSRF / session-fixation vector).
    """
    token = qr_login.create_token()
    request.session["qr_login_token"] = token
    qr_url = f"{config.APP_BASE_URL}/qr/scan/{token}"
    return JSONResponse(
        content={
            "token": token,
            "qr_url": qr_url,
            "qr_data_uri": qr_login.render_qr(qr_url),
            "poll_interval": config.QR_LOGIN_POLL_INTERVAL_SECONDS,
            "expires_in": config.QR_LOGIN_TTL_SECONDS,
        }
    )


@router.get("/qr/status")
async def qr_status(request: Request, token: str = ""):
    """Desktop poll. Owner-bound: only the browser that created ``token`` is promoted.

    Returns ``{"status": ...}`` where status is ``pending`` / ``rejected`` /
    ``expired`` / ``invalid``, or ``approved`` plus a ``redirect``. On ``approved``
    it claims the (single-use) token and writes the SAME session keys as
    ``auth_service.login()`` (``user_id`` / ``username`` / ``email``) -- this
    mutation is what makes SessionMiddleware emit the signed Set-Cookie, completing
    the login on this device with no password/2FA entered here.

    This is a GET that promotes the session -- justified exactly like the OAuth /
    verify GET callbacks, and ADDITIONALLY gated two ways: the unguessable token,
    and **owner-binding** (the polling browser's signed session must already own
    this token). A cross-site ``GET /qr/status`` forced into a victim's browser
    carries no matching ``qr_login_token`` and is ignored -- closing login-CSRF.
    """
    if not token or request.session.get("qr_login_token") != token:
        return JSONResponse(content={"status": "invalid"})

    st = qr_login.status(token)
    if st == "approved":
        identity = qr_login.claim(token)
        if not identity:
            return JSONResponse(content={"status": "expired"})
        request.session.pop("qr_login_token", None)
        session_service.establish_session(request, identity["user_id"], identity["username"], identity["email"])
        ip = request.client.host if request and request.client else ""
        audit_logger.log_auth_event("qr_login", identity["username"], ip, "success")
        return JSONResponse(content={"status": "approved", "redirect": "/welcome"})
    return JSONResponse(content={"status": st})


@router.get("/qr/scan/{token}")
async def qr_scan(request: Request, token: str):
    """Phone landing page the QR encodes (v1.0.8).

    **Session-gated:** you must be logged in to approve a new device. With no
    session we 302 to ``/login`` (the phone logs in, then re-scans). Logged in, we
    render ``qr_approve.html`` with the HTML-escaped approver ``{{username}}``, the
    ``{{token}}``, and a CSRF token. An unknown / expired / already-acted-on token
    renders a fixed "no longer valid" state (buttons hidden) -- the raw token is
    never reflected as markup (VULN-3 posture; the token is escaped on splice).
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)

    username = request.session.get("username", "")
    entry = qr_login.get(token)
    valid = bool(entry and entry["status"] == "pending")

    # FIXED: CSRF closed -- splice the per-session token into the form's hidden field.
    csrf = get_or_create_csrf_token(request)
    # FIXED: Stored/Reflected XSS closed -- escape every value before splicing.
    page = _render_page(
        "qr_approve.html",
        {
            "{{title}}": "Approve Sign-in - Security Vulnerability Lab",
            "{{body_attrs}}": "",
            "{{csrf_token}}": html.escape(csrf, quote=True),
            "{{token}}": html.escape(token, quote=True),
            "{{username}}": html.escape(username, quote=True),
            # Server-controlled "0"/"1" flag (not user input).
            "{{valid}}": "1" if valid else "0",
        },
    )
    return HTMLResponse(content=page)


@router.post("/qr/approve")
async def qr_approve_post(request: Request, token: str = Form("")):
    """Approve a pending QR-login as the logged-in user (v1.0.8).

    Session-gated (no password re-prompt; see the spec's NFR-09). The approver's
    identity is read from THIS device's signed session -- the desktop inherits it
    on its next poll. The hidden csrf_token and per-IP rate limit are enforced by
    middleware before this runs.
    """
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)
    username = request.session.get("username", "")
    ip = request.client.host if request and request.client else ""
    ok = qr_login.approve(
        token,
        user_id,
        username,
        request.session.get("email", ""),
    )
    if ok:
        audit_logger.log_security_event("qr_login_approve", username, ip, f"Approved token: {token}")
        return JSONResponse(
            content={
                "success": True,
                "message": "Login approved. Return to the other device.",
            }
        )
    audit_logger.log_security_event("qr_login_approve", username, ip, f"failure: Token expired or used: {token}")
    return JSONResponse(
        content={"error": "This QR code has expired or was already used."},
        status_code=400,
    )


@router.post("/qr/reject")
async def qr_reject_post(request: Request, token: str = Form("")):
    """Reject a pending QR-login (v1.0.8). Session-gated; CSRF + rate-limit apply."""
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse(content={"error": "Not authenticated"}, status_code=401)
    username = request.session.get("username", "")
    ip = request.client.host if request and request.client else ""
    qr_login.reject(token)
    audit_logger.log_security_event("qr_login_reject", username, ip, f"Rejected token: {token}")
    return JSONResponse(content={"success": True, "message": "Login request denied."})


@router.get("/forgot-password")
async def forgot_password_page(request: Request):
    """Render the forgot-password email request page."""
    # If email is not configured, show the unconfigured page
    if not config.is_email_configured():
        page = _render_page(
            "email_not_configured.html",
            {
                "{{title}}": "Email Delivery Not Configured - Security Vulnerability Lab",
                "{{body_attrs}}": "",
            },
        )
        return HTMLResponse(content=page)

    token = get_or_create_csrf_token(request)
    page = _render_page(
        "forgot_password.html",
        {
            "{{title}}": "Forgot Password - Security Vulnerability Lab",
            "{{body_attrs}}": "",
            "{{csrf_token}}": html.escape(token, quote=True),
        },
    )
    return HTMLResponse(content=page)


@router.post("/forgot-password")
async def forgot_password_post(
    request: Request,
    username_or_email: str = Form(""),
):
    """Handle forgot-password form submission."""
    res = password_reset_service.request_reset(username_or_email, request)
    if res.get("status") == "email_not_configured":
        return JSONResponse(
            content={"error": "Email delivery is not configured."},
            status_code=400,
        )
    return JSONResponse(content={"message": res["message"]})


@router.get("/reset-password")
async def reset_password_page(request: Request):
    """Render the password-reset page if the token is valid."""
    token = request.query_params.get("token", "")
    verify_res = password_reset_service.verify_reset_token(token)
    
    if verify_res["status"] != "ok":
        outcomes = {
            "expired": (
                "Link expired",
                "This password reset link has expired. Please go back to the login page and request a new one.",
            ),
            "invalid": (
                "Invalid link",
                "This password reset link is invalid or has already been used.",
            ),
        }
        title, message = outcomes.get(verify_res["status"], outcomes["invalid"])
        page = _render_page(
            "verify_result.html",
            {
                "{{title}}": "Password Reset - Security Vulnerability Lab",
                "{{body_attrs}}": "",
                "{{title_msg}}": html.escape(title, quote=True),
                "{{message}}": html.escape(message, quote=True),
            },
        )
        return HTMLResponse(content=page)

    csrf = get_or_create_csrf_token(request)
    page = _render_page(
        "reset_password.html",
        {
            "{{title}}": "Reset Password - Security Vulnerability Lab",
            "{{body_attrs}}": "",
            "{{csrf_token}}": html.escape(csrf, quote=True),
            "{{token}}": html.escape(token, quote=True),
        },
    )
    return HTMLResponse(content=page)


@router.post("/reset-password")
async def reset_password_post(
    request: Request,
    token: str = Form(""),
    new_password: str = Form(""),
):
    """Handle password reset form submission."""
    res = password_reset_service.reset_password(token, new_password, request)
    if res["status"] != "success":
        return JSONResponse(content={"error": res.get("error") or "Invalid or expired token"}, status_code=400)
    return JSONResponse(content={"success": True, "message": res["message"]})


@router.get("/logout")
async def logout(request: Request):
    """Destroy the session and redirect to the login page.

    request.session.clear() wipes every key (user_id, username, email,
    AND csrf_token). That last point is intentional -- a new GET /login
    will re-issue a fresh CSRF token tied to the new session, so any
    forms cached in the browser from before logout cannot be replayed.
    """
    user_id = request.session.get("user_id")
    session_id = request.session.get("session_id")
    if user_id and session_id:
        session_service.revoke_session(session_id, user_id)

    username = request.session.get("username", "")
    ip = request.client.host if request and request.client else ""
    if username:
        audit_logger.log_auth_event("logout", username, ip, "success")

    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)


@router.get("/admin")
async def admin_page(request: Request):
    """Render the admin dashboard control panel."""
    # 1. Authentication Check
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)

    # 2. Authorization Check (RBAC)
    conn = get_db()
    try:
        user_row = conn.execute("SELECT username, role FROM users WHERE id = ?", [user_id]).fetchone()
        if not user_row or user_row["role"] != "admin":
            # Reject unauthorized attempt with 403 Forbidden
            # Reuse verify_result.html for a clean styled access denied page
            page = _render_page(
                "verify_result.html",
                {
                    "{{title}}": "Forbidden - Security Vulnerability Lab",
                    "{{body_attrs}}": "",
                    "{{title_msg}}": "403 Forbidden - Access Denied",
                    "{{message}}": "You do not have permission to access the Administrator Control Panel.",
                }
            )
            ip = request.client.host if request and request.client else ""
            audit_logger.log_security_event("admin_access_attempt", user_row["username"] if user_row else "unknown", ip, "failure: Unauthorized role")
            return HTMLResponse(content=page, status_code=403)

        admin_username = user_row["username"]

        # Fetch all registered users, their roles, 2FA states, verification status, and active session count
        users = conn.execute(
            """SELECT u.id, u.username, u.email, u.role, u.is_verified, 
                      u.two_factor_enabled, u.totp_enabled, u.picture,
                      (SELECT COUNT(*) FROM sessions s WHERE s.user_id = u.id) as session_count
               FROM users u"""
        ).fetchall()

        total_users = len(users)
        total_sessions = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]

    finally:
        conn.close()

    # Generate user rows HTML programmatically to support the custom templating architecture
    user_rows = []
    csrf = get_or_create_csrf_token(request)

    for u in users:
        u_id = u["id"]
        u_username = u["username"]
        u_email = u["email"]
        u_role = u["role"]
        u_is_verified = bool(u["is_verified"])
        u_two_factor_enabled = bool(u["two_factor_enabled"])
        u_totp_enabled = bool(u["totp_enabled"])
        u_picture = u["picture"]
        u_session_count = u["session_count"]

        # Escaping user-controllable outputs to prevent Stored XSS
        esc_username = html.escape(u_username, quote=True)
        esc_email = html.escape(u_email or "", quote=True)
        esc_role = html.escape(u_role or "user", quote=True)

        # Avatar column HTML
        avatar_html = ""
        if u_picture:
            esc_pic = html.escape(u_picture, quote=True)
            avatar_html = f'<img class="admin-avatar-img" src="/static/uploads/{esc_pic}" alt="Avatar">'
        else:
            # Fallback SVG placeholder
            avatar_html = (
                '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" '
                'stroke-linecap="round" stroke-linejoin="round" style="width: 18px; height: 18px; color: var(--color-text-muted);">'
                '<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path>'
                '<circle cx="12" cy="7" r="4"></circle>'
                '</svg>'
            )

        # Role Badge HTML
        role_badge_class = "badge-admin" if u_role == "admin" else "badge-user"
        role_html = f'<span class="badge {role_badge_class}">{esc_role}</span>'

        # Verification Badge HTML
        verify_class = "badge-verified" if u_is_verified else "badge-unverified"
        verify_label = "Verified" if u_is_verified else "Unverified"
        verify_html = f'<span class="badge {verify_class}">{verify_label}</span>'

        # MFA Badge HTML
        mfa_html = ""
        if u_totp_enabled:
            mfa_html = '<span class="badge badge-mfa">Authenticator</span>'
        elif u_two_factor_enabled:
            mfa_html = '<span class="badge badge-mfa">Email OTP</span>'
        else:
            mfa_html = '<span class="badge badge-none">None</span>'

        # Actions Column HTML
        actions_html = []
        
        # Guard: Prevent the current admin from modifying/deleting themselves
        if u_id == user_id:
            actions_html.append('<span style="font-size: 0.8rem; color: var(--color-text-muted); font-style: italic;">Self (No Actions)</span>')
        else:
            # Toggle Role
            role_btn_label = "Demote to User" if u_role == "admin" else "Promote to Admin"
            actions_html.append(
                f'<form action="/admin/user/promote" method="post" style="display:inline;">'
                f'<input type="hidden" name="csrf_token" value="{csrf}">'
                f'<input type="hidden" name="user_id" value="{u_id}">'
                f'<button type="submit" class="btn-admin-action">{role_btn_label}</button>'
                f'</form>'
            )

            # Revoke Sessions
            if u_session_count > 0:
                actions_html.append(
                    f'<form action="/admin/user/revoke-sessions" method="post" style="display:inline;">'
                    f'<input type="hidden" name="csrf_token" value="{csrf}">'
                    f'<input type="hidden" name="user_id" value="{u_id}">'
                    f'<button type="submit" class="btn-admin-action">Revoke Sessions</button>'
                    f'</form>'
                )

            # Delete User
            actions_html.append(
                f'<form action="/admin/user/delete" method="post" style="display:inline;" onsubmit="return confirm(\'Are you sure you want to permanently delete user {esc_username}?\');">'
                f'<input type="hidden" name="csrf_token" value="{csrf}">'
                f'<input type="hidden" name="user_id" value="{u_id}">'
                f'<button type="submit" class="btn-admin-action btn-admin-danger">Delete</button>'
                f'</form>'
            )

        actions_str = " ".join(actions_html)

        # Build Row HTML
        row_html = (
            f'<tr>'
            f'  <td style="padding: 14px 16px;"><span class="admin-avatar-small">{avatar_html}</span><strong>{esc_username}</strong></td>'
            f'  <td style="padding: 14px 16px;">{esc_email}</td>'
            f'  <td style="padding: 14px 16px;">{role_html}</td>'
            f'  <td style="padding: 14px 16px;">{verify_html}</td>'
            f'  <td style="padding: 14px 16px;">{mfa_html}</td>'
            f'  <td style="padding: 14px 16px; font-weight: 600;">{u_session_count}</td>'
            f'  <td style="padding: 14px 16px; text-align: right;">{actions_str}</td>'
            f'</tr>'
        )
        user_rows.append(row_html)

    user_rows_str = "\n".join(user_rows)

    page = _render_page(
        "admin.html",
        {
            "{{title}}": "Admin Dashboard - Security Vulnerability Lab",
            "{{body_attrs}}": 'class="dashboard-body"',
            "{{csrf_token}}": html.escape(csrf, quote=True),
            "{{total_users}}": str(total_users),
            "{{total_sessions}}": str(total_sessions),
            "{{user_rows}}": user_rows_str,
        }
    )
    return HTMLResponse(content=page)


@router.post("/admin/user/promote")
async def promote_user(request: Request, user_id: int = Form(None)):
    """Toggle a user's role between admin and user."""
    # 1. Auth & Admin Authorization check
    current_user_id = request.session.get("user_id")
    if not current_user_id:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db()
    try:
        admin_row = conn.execute("SELECT username, role FROM users WHERE id = ?", [current_user_id]).fetchone()
        if not admin_row or admin_row["role"] != "admin":
            return HTMLResponse(content="Forbidden", status_code=403)

        admin_username = admin_row["username"]
        ip = request.client.host if request and request.client else ""

        # 2. Input check & self-promotion guard
        if user_id is None or user_id == current_user_id:
            audit_logger.log_security_event("role_change_attempt", admin_username, ip, "failure: Invalid user ID or self-demotion attempt")
            return RedirectResponse(url="/admin", status_code=303)

        # Check target user
        target_row = conn.execute("SELECT username, role FROM users WHERE id = ?", [user_id]).fetchone()
        if not target_row:
            return RedirectResponse(url="/admin", status_code=303)

        target_username = target_row["username"]
        new_role = "user" if target_row["role"] == "admin" else "admin"

        conn.execute("UPDATE users SET role = ? WHERE id = ?", [new_role, user_id])
        conn.commit()

        audit_logger.log_security_event("role_change", admin_username, ip, f"Changed role for user {target_username} to {new_role}")
    finally:
        conn.close()

    return RedirectResponse(url="/admin", status_code=303)


@router.post("/admin/user/delete")
async def delete_user(request: Request, user_id: int = Form(None)):
    """Delete a user account entirely."""
    # 1. Auth & Admin Authorization check
    current_user_id = request.session.get("user_id")
    if not current_user_id:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db()
    try:
        admin_row = conn.execute("SELECT username, role FROM users WHERE id = ?", [current_user_id]).fetchone()
        if not admin_row or admin_row["role"] != "admin":
            return HTMLResponse(content="Forbidden", status_code=403)

        admin_username = admin_row["username"]
        ip = request.client.host if request and request.client else ""

        # 2. Input check & self-deletion guard
        if user_id is None or user_id == current_user_id:
            audit_logger.log_security_event("user_delete_attempt", admin_username, ip, "failure: Invalid user ID or self-delete attempt")
            return RedirectResponse(url="/admin", status_code=303)

        # Check target user
        target_row = conn.execute("SELECT username FROM users WHERE id = ?", [user_id]).fetchone()
        if not target_row:
            return RedirectResponse(url="/admin", status_code=303)

        target_username = target_row["username"]

        conn.execute("DELETE FROM users WHERE id = ?", [user_id])
        conn.commit()

        audit_logger.log_security_event("user_delete", admin_username, ip, f"Deleted user {target_username}")
    finally:
        conn.close()

    return RedirectResponse(url="/admin", status_code=303)


@router.post("/admin/user/revoke-sessions")
async def revoke_user_sessions(request: Request, user_id: int = Form(None)):
    """Revoke all active sessions for a user."""
    # 1. Auth & Admin Authorization check
    current_user_id = request.session.get("user_id")
    if not current_user_id:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db()
    try:
        admin_row = conn.execute("SELECT username, role FROM users WHERE id = ?", [current_user_id]).fetchone()
        if not admin_row or admin_row["role"] != "admin":
            return HTMLResponse(content="Forbidden", status_code=403)

        admin_username = admin_row["username"]
        ip = request.client.host if request and request.client else ""

        # 2. Input check
        if user_id is None:
            return RedirectResponse(url="/admin", status_code=303)

        # Check target user
        target_row = conn.execute("SELECT username FROM users WHERE id = ?", [user_id]).fetchone()
        if not target_row:
            return RedirectResponse(url="/admin", status_code=303)

        target_username = target_row["username"]

        # Revoke all sessions
        conn.execute("DELETE FROM sessions WHERE user_id = ?", [user_id])
        conn.commit()

        audit_logger.log_security_event("sessions_revoke_all", admin_username, ip, f"Revoked all sessions for user {target_username}")
    finally:
        conn.close()

    return RedirectResponse(url="/admin", status_code=303)


# =========================================================================
# ADVANCED VULNERABILITY LABS ROUTES (Command Injection, SSRF, XXE)
# =========================================================================

def get_lab_status(user_id: int, lab_name: str) -> str:
    """Get the current progress status of a specific lab for a user."""
    conn = get_db()
    try:
        row = conn.execute("SELECT status FROM lab_progress WHERE user_id = ? AND lab_name = ?", [user_id, lab_name]).fetchone()
        return row["status"] if row else "unsolved"
    finally:
        conn.close()


def update_lab_status(user_id: int, lab_name: str, status: str):
    """Update or insert the progress status of a lab for a user."""
    conn = get_db()
    try:
        conn.execute(
            """INSERT INTO lab_progress (user_id, lab_name, status) 
               VALUES (?, ?, ?) 
               ON CONFLICT(user_id, lab_name) DO UPDATE SET status = ?""",
            [user_id, lab_name, status, status]
        )
        conn.commit()
    finally:
        conn.close()


@router.get("/labs/command-injection")
async def lab_command_injection_page(request: Request):
    """Render the Command Injection Lab page."""
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db()
    try:
        user_row = conn.execute("SELECT username, role FROM users WHERE id = ?", [user_id]).fetchone()
        username = user_row["username"] if user_row else "unknown"
        is_admin = user_row and user_row["role"] == "admin"
    finally:
        conn.close()

    admin_link_html = '<a href="/admin" class="btn btn-logout">Admin Panel</a>' if is_admin else ''
    status = get_lab_status(user_id, "command_injection")

    page = _render_page(
        "labs_command_injection.html",
        {
            "{{title}}": "Command Injection Lab - Security Lab",
            "{{body_attrs}}": 'class="dashboard-body"',
            "{{username}}": html.escape(username, quote=True),
            "{{admin_link}}": admin_link_html,
            "{{status}}": html.escape(status, quote=True),
            "{{csrf_token}}": html.escape(get_or_create_csrf_token(request), quote=True),
        }
    )
    return HTMLResponse(content=page)


@router.post("/labs/command-injection")
async def lab_command_injection_post(
    request: Request,
    host: str = Form(""),
    mode: str = Form("vulnerable")
):
    """Execute ping command to demonstrate Command Injection."""
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    conn = get_db()
    try:
        user_row = conn.execute("SELECT username FROM users WHERE id = ?", [user_id]).fetchone()
        username = user_row["username"] if user_row else "unknown"
    finally:
        conn.close()

    ip = request.client.host if request and request.client else ""
    audit_logger.log_security_event("lab_command_injection", username, ip, f"Mode: {mode} | Host: {host}")

    import sys
    import subprocess

    output = ""
    # Define ping parameter based on OS
    ping_param = "-n" if sys.platform == "win32" else "-c"

    if mode == "vulnerable":
        # Vulnerable string concatenation running via shell=True
        cmd = f"ping {ping_param} 1 {host}"
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5).decode("utf-8", errors="ignore")
        except subprocess.CalledProcessError as e:
            output = e.output.decode("utf-8", errors="ignore")
        except Exception as e:
            output = str(e)

        # Detect exploitation: metacharacters present in input and command executed
        if any(char in host for char in ["&", ";", "|", "$", "`"]):
            update_lab_status(user_id, "command_injection", "exploited")

    else:
        # Secure implementation: input validation and shell=False list execution
        # Strict validation: only allow alphanumerics, dots, and hyphens (hostnames and IPs)
        import re
        if not re.match(r"^[a-zA-Z0-9.-]+$", host):
            return JSONResponse({
                "output": "Execution blocked: Invalid input format. Metacharacters are forbidden.",
                "status": get_lab_status(user_id, "command_injection")
            })

        try:
            output = subprocess.check_output(["ping", ping_param, "1", host], shell=False, stderr=subprocess.STDOUT, timeout=5).decode("utf-8", errors="ignore")
            # If successfully verified in secure mode after being exploited, mark as solved
            current_status = get_lab_status(user_id, "command_injection")
            if current_status == "exploited":
                update_lab_status(user_id, "command_injection", "solved")
        except subprocess.CalledProcessError as e:
            output = e.output.decode("utf-8", errors="ignore")
        except Exception as e:
            output = str(e)

    return JSONResponse({
        "output": html.escape(output, quote=True),
        "status": get_lab_status(user_id, "command_injection")
    })


@router.get("/labs/ssrf")
async def lab_ssrf_page(request: Request):
    """Render the SSRF Lab page."""
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db()
    try:
        user_row = conn.execute("SELECT username, role FROM users WHERE id = ?", [user_id]).fetchone()
        username = user_row["username"] if user_row else "unknown"
        is_admin = user_row and user_row["role"] == "admin"
    finally:
        conn.close()

    admin_link_html = '<a href="/admin" class="btn btn-logout">Admin Panel</a>' if is_admin else ''
    status = get_lab_status(user_id, "ssrf")

    page = _render_page(
        "labs_ssrf.html",
        {
            "{{title}}": "SSRF Lab - Security Lab",
            "{{body_attrs}}": 'class="dashboard-body"',
            "{{username}}": html.escape(username, quote=True),
            "{{admin_link}}": admin_link_html,
            "{{status}}": html.escape(status, quote=True),
            "{{csrf_token}}": html.escape(get_or_create_csrf_token(request), quote=True),
        }
    )
    return HTMLResponse(content=page)


@router.post("/labs/ssrf")
async def lab_ssrf_post(
    request: Request,
    url: str = Form(""),
    mode: str = Form("vulnerable")
):
    """Fetch URL preview to demonstrate Server-Side Request Forgery."""
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    conn = get_db()
    try:
        user_row = conn.execute("SELECT username FROM users WHERE id = ?", [user_id]).fetchone()
        username = user_row["username"] if user_row else "unknown"
    finally:
        conn.close()

    ip = request.client.host if request and request.client else ""
    audit_logger.log_security_event("lab_ssrf", username, ip, f"Mode: {mode} | URL: {url}")

    from urllib.parse import urlparse
    import socket
    import httpx

    content = ""

    if mode == "vulnerable":
        # Check for SSRF exploitation (accessing localhost admin/welcome)
        # Check this before requesting so it succeeds even if connection is refused
        try:
            parsed = urlparse(url)
            is_local = parsed.hostname in ["localhost", "127.0.0.1", "0.0.0.0", "::1"] or (parsed.netloc and (parsed.netloc.startswith("localhost") or parsed.netloc.startswith("127.0.0.1")))
            if is_local and ("/admin" in parsed.path or "/welcome" in parsed.path):
                update_lab_status(user_id, "ssrf", "exploited")
        except Exception:
            pass

        try:
            with httpx.Client(timeout=3.0) as client:
                resp = client.get(url, follow_redirects=True)
                content = resp.text[:1500]
        except Exception as e:
            content = f"Error fetching URL: {str(e)}"
    else:
        # Secure implementation: URL validation + IP blacklist resolution
        parsed = urlparse(url)
        if parsed.scheme not in ["http", "https"]:
            return JSONResponse({
                "error": "Access blocked: Only HTTP and HTTPS protocols are allowed.",
                "status": get_lab_status(user_id, "ssrf")
            }, status_code=400)

        hostname = parsed.hostname
        if not hostname:
            return JSONResponse({
                "error": "Access blocked: Invalid host in URL.",
                "status": get_lab_status(user_id, "ssrf")
            }, status_code=400)

        try:
            resolved_ip = socket.gethostbyname(hostname)
        except Exception:
            return JSONResponse({
                "error": f"Access blocked: Could not resolve hostname '{hostname}'.",
                "status": get_lab_status(user_id, "ssrf")
            }, status_code=400)

        # Basic private/loopback check
        def is_private_or_loopback(ip_str):
            try:
                parts = list(map(int, ip_str.split(".")))
                if len(parts) != 4:
                    return True
                # Loopback (127.0.0.0/8)
                if parts[0] == 127:
                    return True
                # Private A (10.0.0.0/8)
                if parts[0] == 10:
                    return True
                # Private B (172.16.0.0/12)
                if parts[0] == 172 and (16 <= parts[1] <= 31):
                    return True
                # Private C (192.168.0.0/16)
                if parts[0] == 192 and parts[1] == 168:
                    return True
                # Link-local (169.254.0.0/16)
                if parts[0] == 169 and parts[1] == 254:
                    return True
                return False
            except Exception:
                return True

        if is_private_or_loopback(resolved_ip) or hostname.lower() in ["localhost", "loopback"]:
            return JSONResponse({
                "error": "Access blocked: Request to internal/private network addresses is forbidden.",
                "status": get_lab_status(user_id, "ssrf")
            }, status_code=400)

        try:
            with httpx.Client(timeout=3.0) as client:
                resp = client.get(url, follow_redirects=True)
                content = resp.text[:1500]
            # Verify and solve the lab
            current_status = get_lab_status(user_id, "ssrf")
            if current_status == "exploited":
                update_lab_status(user_id, "ssrf", "solved")
        except Exception as e:
            content = f"Error fetching URL: {str(e)}"

    return JSONResponse({
        "content": html.escape(content, quote=True),
        "status": get_lab_status(user_id, "ssrf")
    })


@router.get("/labs/xxe")
async def lab_xxe_page(request: Request):
    """Render the XML External Entity (XXE) Lab page."""
    user_id = request.session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)

    conn = get_db()
    try:
        user_row = conn.execute("SELECT username, role FROM users WHERE id = ?", [user_id]).fetchone()
        username = user_row["username"] if user_row else "unknown"
        is_admin = user_row and user_row["role"] == "admin"
    finally:
        conn.close()

    admin_link_html = '<a href="/admin" class="btn btn-logout">Admin Panel</a>' if is_admin else ''
    status = get_lab_status(user_id, "xxe")

    page = _render_page(
        "labs_xxe.html",
        {
            "{{title}}": "XXE Lab - Security Lab",
            "{{body_attrs}}": 'class="dashboard-body"',
            "{{username}}": html.escape(username, quote=True),
            "{{admin_link}}": admin_link_html,
            "{{status}}": html.escape(status, quote=True),
            "{{csrf_token}}": html.escape(get_or_create_csrf_token(request), quote=True),
        }
    )
    return HTMLResponse(content=page)


@router.post("/labs/xxe")
async def lab_xxe_post(
    request: Request,
    xml_data: str = Form(""),
    mode: str = Form("vulnerable")
):
    """Parse XML config upload to demonstrate XXE injection."""
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    conn = get_db()
    try:
        user_row = conn.execute("SELECT username FROM users WHERE id = ?", [user_id]).fetchone()
        username = user_row["username"] if user_row else "unknown"
    finally:
        conn.close()

    ip = request.client.host if request and request.client else ""
    audit_logger.log_security_event("lab_xxe", username, ip, f"Mode: {mode}")

    from lxml import etree

    result = ""

    if mode == "vulnerable":
        try:
            # Vulnerable parser: resolves external entities and loads DTDs
            parser = etree.XMLParser(resolve_entities=True, no_network=False, load_dtd=True)
            root = etree.fromstring(xml_data.encode("utf-8"), parser=parser)
            
            name_node = root.find("name")
            email_node = root.find("email")
            
            name_val = name_node.text if name_node is not None else ""
            email_val = email_node.text if email_node is not None else ""
            
            result = f"Profile Updated: Name = {name_val}, Email = {email_val}"
            
            # Detect XXE exploitation: input uses SYSTEM and entity was successfully resolved
            if "SYSTEM" in xml_data and (name_val or email_val):
                update_lab_status(user_id, "xxe", "exploited")
        except Exception as e:
            result = f"XML Parsing Error: {str(e)}"
    else:
        try:
            # Secure parser: resolve_entities=False, load_dtd=False, no_network=True
            parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, dtd_validation=False)
            root = etree.fromstring(xml_data.encode("utf-8"), parser=parser)
            
            name_node = root.find("name")
            email_node = root.find("email")
            
            name_val = name_node.text if name_node is not None else ""
            email_val = email_node.text if email_node is not None else ""
            
            result = f"Profile Updated: Name = {name_val}, Email = {email_val}"
            
            # Verify and solve
            current_status = get_lab_status(user_id, "xxe")
            if current_status == "exploited":
                update_lab_status(user_id, "xxe", "solved")
        except Exception as e:
            result = f"XML Parsing Error: {str(e)}"

    return JSONResponse({
        "result": html.escape(result, quote=True),
        "status": get_lab_status(user_id, "xxe")
    })


@router.post("/labs/reset")
async def lab_reset_post(
    request: Request,
    lab_name: str = Form("")
):
    """Reset the progress status of a specific lab."""
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    conn = get_db()
    try:
        user_row = conn.execute("SELECT username FROM users WHERE id = ?", [user_id]).fetchone()
        username = user_row["username"] if user_row else "unknown"
        
        conn.execute("DELETE FROM lab_progress WHERE user_id = ? AND lab_name = ?", [user_id, lab_name])
        conn.commit()
    finally:
        conn.close()

    ip = request.client.host if request and request.client else ""
    audit_logger.log_security_event("lab_reset", username, ip, f"Lab: {lab_name}")

    return JSONResponse({"status": "unsolved"})
