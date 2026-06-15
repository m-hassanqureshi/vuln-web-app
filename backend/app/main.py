import sys
import os
import secrets

# Add backend/ directory to sys.path so 'app' package resolves correctly
# regardless of which directory the script is launched from
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.api.routes.auth import router
from app.core.rate_limit import RateLimitMiddleware
from app.db.session import init_db

app = FastAPI(title="Vulnerable Web Application - Security Lab")

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

app.include_router(router)

# Mount static files
BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..")
app.mount("/static/css", StaticFiles(directory=os.path.join(BASE_DIR, "frontend", "static", "css")), name="css")
app.mount("/static/images", StaticFiles(directory=os.path.join(BASE_DIR, "frontend", "static", "images")), name="images")

# Initialize database on startup
init_db()

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 3001))
    uvicorn.run(app, host="0.0.0.0", port=port)
