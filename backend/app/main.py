"""Application entry point.

Bootstraps the FastAPI app, wires three custom middlewares (in a very
specific order -- see the NOTE below), mounts the static-file directories,
initializes the SQLite schema, and starts uvicorn when invoked directly.

Run with: `uv run backend/app/main.py` from the project root.
"""

import sys
import os
import secrets

# Add backend/ to sys.path so `from app.<...> import` works regardless of
# which directory the script is launched from. Without this, running the
# file directly (`uv run backend/app/main.py`) would fail to import the
# `app` package because Python's default sys.path only includes the
# directory containing main.py itself.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.api.routes.auth import router
from app.core.csrf import CSRFMiddleware
from app.core.rate_limit import RateLimitMiddleware
from app.db.session import init_db
from app.services import session_service

app = FastAPI(title="Vulnerable Web Application - Security Lab")


@app.middleware("http")
async def verify_db_session_middleware(request: Request, call_next):
    """Intercept requests to verify the session_id is active in the database.

    If the session is invalid/revoked, clears the cookie and redirects to login.
    """
    # Bypass verification for static files to save DB queries
    if request.url.path.startswith("/static"):
        return await call_next(request)

    user_id = request.session.get("user_id")
    session_id = request.session.get("session_id")

    if user_id and session_id:
        if not session_service.verify_session(session_id):
            # Session was deleted/revoked. Clear session cookie.
            request.session.clear()
            
            # Bypass redirect if requesting public endpoints to prevent loops
            public_paths = [
                "/login",
                "/signup",
                "/forgot-password",
                "/reset-password",
                "/auth/google",
                "/check-email",
                "/verify",
                "/verify/resend"
            ]
            is_public = any(request.url.path == p or request.url.path.startswith(p) for p in public_paths)
            
            if not is_public:
                if request.headers.get("x-requested-with") == "XMLHttpRequest" or "application/json" in request.headers.get("accept", ""):
                    from fastapi.responses import JSONResponse
                    return JSONResponse(content={"error": "Session expired or revoked."}, status_code=401)
                return RedirectResponse(url="/login", status_code=302)
                
    return await call_next(request)


# NOTE on Starlette middleware ordering: add_middleware() PREPENDS to the
# internal middleware list, so the LAST add_middleware call is the
# OUTERMOST layer on the request path. Counter-intuitive but important.
#
# Desired layering: RateLimit (outer) -> Session -> CSRF (inner) -> handler
#   - RateLimit outermost: throttled floods never reach the body-reading
#     CSRF stage, so an attacker cannot CPU-burn the CSRF parser.
#   - Session in the middle: decodes the signed cookie into
#     scope["session"] before CSRF tries to read it.
#   - CSRF innermost: validates the per-session token, then re-streams
#     the buffered body to the handler.
#
# To achieve that flow, registrations go INNER-to-OUTER below: CSRF,
# Session, RateLimit. You can verify the final order at runtime with:
#   python -c "from app.main import app; print([m.cls.__name__ for m in app.user_middleware])"
# Expected: ['RateLimitMiddleware', 'SessionMiddleware', 'CSRFMiddleware']
# (outer -> inner on the request path).

# FIXED: CSRF closed -- synchronizer-token middleware rejects every POST whose
# csrf_token form field does not match request.session["csrf_token"].
app.add_middleware(CSRFMiddleware)

# FIXED: Session Hijacking closed -- secret loaded from the environment,
# with a strong random fallback so a fresh checkout never ships a known key.
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

# FIXED: No Rate Limiting closed -- per-IP sliding-window throttle on every POST.
# Defaults: 5 POSTs per 60 s per IP. Tune via RATE_LIMIT_MAX / RATE_LIMIT_WINDOW_SECONDS.
RATE_LIMIT_MAX = int(os.environ.get("RATE_LIMIT_MAX", "5"))
RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", "60"))
app.add_middleware(
    RateLimitMiddleware,
    max_requests=RATE_LIMIT_MAX,
    window_seconds=RATE_LIMIT_WINDOW_SECONDS,
)

# Wire every @router.get/post in api/routes/auth.py into the app at /.
app.include_router(router)

# Mount static files. We split CSS and images under separate prefixes
# rather than one big /static mount because it's slightly more explicit
# about what's served, and lets us point each mount at exactly one folder.
BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..")
app.mount("/static/css", StaticFiles(directory=os.path.join(BASE_DIR, "frontend", "static", "css")), name="css")
app.mount("/static/images", StaticFiles(directory=os.path.join(BASE_DIR, "frontend", "static", "images")), name="images")
# Mount for any future /static/js assets. Created for the toast helper
# (frontend/static/js/toast.js) loaded by the shared header partial. Like
# the other mounts, it serves files straight off disk -- no caching, no
# transformation -- so a future change to toast.js is picked up on the
# next page load without a server restart.
app.mount("/static/js", StaticFiles(directory=os.path.join(BASE_DIR, "frontend", "static", "js")), name="js")

# Mount for profile picture uploads (avatars). Auto-created on startup so the
# directory is guaranteed to exist without manual developer intervention.
UPLOADS_DIR = os.path.join(BASE_DIR, "frontend", "static", "uploads")
os.makedirs(UPLOADS_DIR, exist_ok=True)
app.mount("/static/uploads", StaticFiles(directory=UPLOADS_DIR), name="uploads")


# Create the users table if it doesn't exist. Idempotent -- safe across
# restarts. Existing user rows are preserved.
init_db()

if __name__ == "__main__":
    # Only runs when launched directly (e.g. `uv run backend/app/main.py`).
    # When the module is imported by another process (e.g. by gunicorn or
    # by the test client), this block is skipped.
    import uvicorn
    port = int(os.environ.get("PORT", 3001))
    # host="0.0.0.0" makes the app reachable from outside localhost --
    # useful when running inside a container or VM. The default port
    # 3001 is hardcoded so students don't need to set anything to get
    # started; override with PORT=<n> for e.g. cloud deploys.
    uvicorn.run(app, host="0.0.0.0", port=port)
