"""Configuration + .env loading for the Continue-with-Google and Email
Verification features.

Stdlib only -- no python-dotenv dependency. This module:

1. Loads a repo-root `.env` file (if present) into ``os.environ`` so a local
   developer can keep their Google credentials AND SMTP credentials in one
   git-ignored file.
2. Exposes the Google OAuth settings and an ``is_google_configured()`` gate.
3. Exposes the SMTP / email-verification settings and an
   ``is_email_configured()`` gate.

Design notes (production posture):
- **Real environment variables always win** over ``.env`` values. A container,
  CI runner, or hosting platform injects config through the real environment;
  we never let a stale committed-by-mistake ``.env`` override it.
- **Importing this module is non-fatal.** A missing or unreadable ``.env`` is
  ignored, and absent credentials simply make ``is_google_configured()`` return
  ``False`` -- the app still boots and the password flow is unaffected.
- **No secret is hardcoded here.** Everything comes from the environment.
"""

import logging
import os

logger = logging.getLogger(__name__)

# Repo root: climb from backend/app/core/config.py up three levels to the
# directory that holds `.env` (resolved at import time, CWD-independent).
_BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..")
_ENV_PATH = os.path.join(_BASE_DIR, ".env")


def _load_dotenv(path: str) -> None:
    """Seed ``os.environ`` from a minimal ``KEY=VALUE`` ``.env`` file.

    Ignores blank lines and ``#`` comments, strips surrounding quotes, and only
    sets keys that are NOT already present in the environment (real env vars
    take precedence). A missing or unreadable file is silently skipped so a
    fresh clone with no ``.env`` still starts cleanly.
    """
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except OSError as exc:
        # A broken/unreadable .env must never crash startup -- log and move on.
        logger.warning("Could not read .env at %s: %s", path, exc)


_load_dotenv(_ENV_PATH)

# --- Google OAuth settings (all sourced from the environment) ----------------
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.environ.get(
    "GOOGLE_REDIRECT_URI", "http://localhost:3001/auth/google/callback"
)

# Network timeout (seconds) for the OIDC discovery + token-exchange calls, so a
# slow/hung Google endpoint cannot pin a worker indefinitely.
OAUTH_HTTP_TIMEOUT = float(os.environ.get("OAUTH_HTTP_TIMEOUT", "10"))


def is_google_configured() -> bool:
    """Return True only when both the client id and secret are present.

    The login route uses this to decide whether to start the real OAuth flow
    or render the friendly "not configured" page.
    """
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)


# --- SMTP / Email-verification settings (all sourced from the environment) ----
# Same posture as the Google block above: every value comes from env/.env, no
# secret is hardcoded, and a missing config simply disables the feature (the
# signup flow then shows the friendly "email not configured" page).
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
# SMTP_FROM defaults to the authenticating user (most providers require the
# From address to match the authenticated mailbox anyway).
SMTP_FROM = os.environ.get("SMTP_FROM", "") or SMTP_USER

# Network timeout (seconds) for the SMTP connect/login/send, so a slow or hung
# mail server cannot pin a worker indefinitely.
SMTP_TIMEOUT = float(os.environ.get("SMTP_TIMEOUT", "10"))

# Public base URL used to build the verification link spliced into the email
# body. Trailing slash trimmed so f"{APP_BASE_URL}/verify?..." is always clean.
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:3001").rstrip("/")

# Verification-token lifetime in seconds. Default 1 hour.
EMAIL_VERIFICATION_TTL_SECONDS = int(
    os.environ.get("EMAIL_VERIFICATION_TTL_SECONDS", "3600")
)


def is_email_configured() -> bool:
    """Return True only when host + user + password are all present.

    The signup routes use this to decide whether to run the real verification
    flow or render the friendly "email not configured" setup page. Mirrors
    is_google_configured() above.
    """
    return bool(SMTP_HOST and SMTP_USER and SMTP_PASSWORD)
