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

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app.core.csrf import get_or_create_csrf_token
from app.core import config
from app.core.oauth import oauth
from app.services import auth_service
from app.services import oauth_service
from app.services import verification_service
from app.db.session import get_db

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
    with open(os.path.join(TEMPLATE_DIR, name), "r") as f:
        return f.read()


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
        return HTMLResponse(content=_load_template("email_not_configured.html"))

    with open(os.path.join(TEMPLATE_DIR, "signup.html"), "r") as f:
        page = f.read()
    # FIXED: CSRF closed -- splice the per-session token into the form's hidden field.
    # get_or_create_csrf_token() is idempotent: it returns the existing
    # token if one is already in the session, or generates one if not.
    # html.escape is defensive only -- the token alphabet (URL-safe Base64)
    # contains no HTML-significant characters today, but escaping keeps the
    # splice safe under future token-format changes.
    token = get_or_create_csrf_token(request)
    page = page.replace("{{csrf_token}}", html.escape(token, quote=True))
    return HTMLResponse(content=page)


@router.post("/signup")
async def signup_post(
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
        return HTMLResponse(content=_load_template("email_not_configured.html"))

    return auth_service.signup(username, email, password)


@router.get("/check-email")
async def check_email_page():
    """Static "we sent you a verification link" page shown right after signup.

    No user input is reflected here (intentionally generic -- it does not name
    the address), so there is no sink to escape. Loaded fresh from disk like
    every other template.
    """
    return HTMLResponse(content=_load_template("check_email.html"))


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
    result = verification_service.verify_email_token(token)

    # On success, log the user straight in (clicking the emailed link proves
    # control of the address) by writing the SAME session keys as
    # auth_service.login(), then send them to their dashboard. This mutation is
    # what makes SessionMiddleware emit the signed Set-Cookie.
    if result["status"] == "ok":
        user = result["user"]
        request.session["user_id"] = user["id"]
        request.session["username"] = user["username"]
        request.session["email"] = user["email"]
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

    page = _load_template("verify_result.html")
    page = page.replace("{{title}}", html.escape(title, quote=True))
    page = page.replace("{{message}}", html.escape(message, quote=True))
    return HTMLResponse(content=page)


@router.post("/verify/resend")
async def verify_resend(
    username: str = Form(""),
    password: str = Form(""),
):
    """Re-send the verification email, gated on valid credentials.

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
    splice via str.replace.
    """
    with open(os.path.join(TEMPLATE_DIR, "login.html"), "r") as f:
        page = f.read()
    # FIXED: CSRF closed -- splice the per-session token into the form's hidden field.
    token = get_or_create_csrf_token(request)
    page = page.replace("{{csrf_token}}", html.escape(token, quote=True))
    return HTMLResponse(content=page)


@router.post("/login")
async def login_post(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
):
    """Handle login form submission.

    The Request parameter is forwarded to the service layer so it can
    write user_id/username/email into `request.session` on success --
    that mutation is what triggers SessionMiddleware to write the
    Set-Cookie header on the response.
    """
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

    with open(os.path.join(TEMPLATE_DIR, "dashboard.html"), "r") as f:
        page = f.read()

    # FIXED: Stored XSS closed -- username escaped before substitution.
    # The raw value remains in the session/database (output-encoding fix, not input filtering).
    #
    # The raw username can contain `<script>` from a malicious signup --
    # we do NOT sanitize on the way in (that would lose information and
    # is famously fragile). Instead we escape on the way out, so the
    # rendered HTML treats the username as text, never as markup.
    safe_username = html.escape(username, quote=True)
    page = page.replace("{{username}}", safe_username)

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

    with open(os.path.join(TEMPLATE_DIR, "profile.html"), "r") as f:
        page = f.read()

    # FIXED: CSRF closed -- issue/splice the per-session token for the form.
    token = get_or_create_csrf_token(request)
    page = page.replace("{{csrf_token}}", html.escape(token, quote=True))

    # FIXED: Stored XSS closed -- escape every user-controlled value before
    # splicing (output encoding, same posture as the dashboard username).
    page = page.replace("{{username}}", html.escape(username, quote=True))
    page = page.replace("{{email}}", html.escape(email, quote=True))

    return HTMLResponse(content=page)


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
        with open(os.path.join(TEMPLATE_DIR, "oauth_not_configured.html"), "r") as f:
            return HTMLResponse(content=f.read())
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
        return RedirectResponse(url="/login", status_code=302)

    # 2) Exchange the code + verify the ID token. authorize_access_token()
    #    validates `state` (anti-CSRF), swaps the code for tokens, and verifies
    #    the ID token signature + iss/aud/exp/nonce. It raises on any mismatch
    #    or when the session (holding `state`/`nonce`) has expired.
    try:
        token = await oauth.google.authorize_access_token(request)
    except Exception:
        logger.warning("Google OAuth token exchange/verification failed", exc_info=True)
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
    request.session["user_id"] = user["id"]
    request.session["username"] = user["username"]
    request.session["email"] = user["email"]

    return RedirectResponse(url="/welcome", status_code=302)


@router.get("/logout")
async def logout(request: Request):
    """Destroy the session and redirect to the login page.

    request.session.clear() wipes every key (user_id, username, email,
    AND csrf_token). That last point is intentional -- a new GET /login
    will re-issue a fresh CSRF token tied to the new session, so any
    forms cached in the browser from before logout cannot be replayed.
    """
    request.session.clear()
    return RedirectResponse(url="/login", status_code=302)
