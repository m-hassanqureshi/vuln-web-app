"""CSRF protection (synchronizer-token pattern, stdlib only).

Closes VULN-8 (Cross-Site Request Forgery). Pre-fix, an attacker hosting
evil.com could trick a victim's browser into POSTing to /signup or /login
on this app -- the browser would automatically attach the victim's
session cookie, and the server would happily process the forged request.

The fix is the textbook synchronizer-token pattern:
  1. On GET /signup or GET /login, we lazily generate a per-session token
     (`secrets.token_urlsafe(32)` -> 256 bits of entropy) and stash it in
     `request.session["csrf_token"]`. SessionMiddleware then serializes
     and signs the whole session dict into the response cookie.
  2. The GET handlers splice that token into a hidden <input name="csrf_token">
     inside the rendered form.
  3. On POST, this middleware reads the same token out of the session and
     out of the form body, and compares them with `secrets.compare_digest`
     (constant-time). If they don't match -> HTTP 403, handler never runs.

evil.com cannot read the session cookie (it lives on this app's origin),
so it cannot learn the token and cannot include it in a forged POST.

Two implementation realities worth flagging for a new reader:

* **Pure ASGI, not BaseHTTPMiddleware.** Wrapping with BaseHTTPMiddleware
  and calling `await request.form()` consumes the body on a Request
  wrapper that FastAPI's downstream handler never sees -- the handler
  then reads an exhausted stream and reports "All fields required" (400).
  Pure ASGI lets us read the body, validate the token, and explicitly
  REPLAY the same bytes to the handler via a wrapped `receive` callable.
* **Middleware ordering.** This middleware needs `scope["session"]`
  populated, which means SessionMiddleware must wrap CSRFMiddleware on
  the request path. Because Starlette's `add_middleware()` prepends, we
  register CSRF FIRST in main.py (so it ends up INNERMOST). See main.py's
  NOTE block for the full picture.

Spec refs (FR-XX / NFR-XX / EC-XX) in the inline comments below point at
the source-of-truth requirements in .claude/specs/csrf-fix.md.
"""

import json
import secrets
from urllib.parse import parse_qs

from starlette.requests import Request
from starlette.responses import JSONResponse


# Same string for both -- the form field and the session key are
# intentionally identical to avoid magic-string drift between this file
# and the HTML templates.
_SESSION_KEY = "csrf_token"
_FORM_FIELD = "csrf_token"


def get_or_create_csrf_token(request: Request) -> str:
    """Return the per-session CSRF token, lazily generating one on first read.

    The token is a 43-character URL-safe Base64 string carrying 256 bits of
    entropy from secrets.token_urlsafe(32). It is generated once per session
    (NFR-10) and lives only inside the signed session cookie -- no database
    column, no in-process map.

    Idempotent within a session: a user who hits GET /login then GET /signup
    sees the SAME token in both rendered forms. That matters because the
    middleware validates against a single per-session value -- rotating
    per-request would break the login JS submit-and-show-error flow without
    adding meaningful defense once XSS (VULN-2 / VULN-3) is also closed.

    Called by signup_page() and login_page() in api/routes/auth.py.
    """
    existing = request.session.get(_SESSION_KEY)
    # isinstance + truthy check: covers both "key missing" and "value got
    # overwritten to something weird" (e.g. None, "", 0). Either way we
    # treat it as needing a fresh token.
    if not isinstance(existing, str) or not existing:
        existing = secrets.token_urlsafe(32)
        request.session[_SESSION_KEY] = existing
    return existing


def _reject_response_bytes() -> tuple[bytes, list[tuple[bytes, bytes]]]:
    """Build the 403 response payload as raw bytes + header pairs.

    Returns a (body, headers) tuple ready for direct ASGI emission. Kept
    as a helper so the body/header shape is defined in one place.
    """
    # FR-05 + NFR-06: generic body, no IP/path/UA leakage. The same body
    # is sent for missing-token, empty-token, wrong-token, and internal-
    # error cases -- the attacker should not learn WHY their request was
    # rejected.
    body = json.dumps({"error": "CSRF token missing or invalid"}).encode()
    headers = [
        (b"content-type", b"application/json"),
        # Explicit content-length so the client doesn't have to wait on EOF.
        (b"content-length", str(len(body)).encode()),
    ]
    return body, headers


async def _send_reject(send) -> None:
    """Emit the 403 response directly via the ASGI `send` callable.

    Two ASGI events are required: `http.response.start` (status + headers)
    followed by `http.response.body` (the JSON body, with more_body=False
    to signal end-of-response).
    """
    body, headers = _reject_response_bytes()
    await send({"type": "http.response.start", "status": 403, "headers": headers})
    await send({"type": "http.response.body", "body": body, "more_body": False})


class CSRFMiddleware:
    """Synchronizer-token CSRF validator for every POST request.

    Pure ASGI middleware (not BaseHTTPMiddleware) so the request body can be
    read for token validation and then re-streamed to the downstream handler
    without consumption. Token lives in the session
    (request.session["csrf_token"]) -- see get_or_create_csrf_token for the
    issuance contract. Fail-closed on any validation failure (NFR-07).
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        # FR-01 / FR-07: method check is the first statement. Every non-POST
        # request and every non-HTTP scope bypasses the validator with zero
        # session/form access.
        if scope["type"] != "http" or scope.get("method") != "POST":
            await self.app(scope, receive, send)
            return

        try:
            session = scope.get("session")
            if not isinstance(session, dict):
                # EC-01: SessionMiddleware did not populate scope["session"].
                await _send_reject(send)
                return

            expected = session.get(_SESSION_KEY)
            if not isinstance(expected, str) or not expected:
                # EC-02: no session token issued yet -- reject.
                await _send_reject(send)
                return

            body = await _read_body(receive)
            submitted = _extract_csrf_token(scope, body)
            if not isinstance(submitted, str) or not submitted:
                # EC-03 / EC-04: missing or empty form field -- reject.
                await _send_reject(send)
                return

            # FR-06: constant-time comparison, coerce to str defensively.
            if not secrets.compare_digest(str(expected), str(submitted)):
                # EC-05: wrong value -- reject.
                await _send_reject(send)
                return
        except Exception:
            # NFR-07: fail-CLOSED on any internal bookkeeping error. The
            # original vulnerability was an unguarded state-changing POST;
            # failing open here would re-open it.
            await _send_reject(send)
            return

        # Re-stream the buffered body so the downstream handler can re-read it.
        await self.app(scope, _replay_receive(body), send)


async def _read_body(receive) -> bytes:
    """Drain the ASGI receive callable into a single bytes buffer.

    ASGI delivers request bodies as one or more `http.request` messages,
    each with a `body` slice and a `more_body` flag. We concatenate every
    chunk until `more_body=False`. After this returns, the original
    `receive` is exhausted -- the downstream handler will need a wrapped
    `receive` (see _replay_receive) to read the same bytes again.
    """
    chunks: list[bytes] = []
    while True:
        message = await receive()
        if message["type"] != "http.request":
            # Disconnect or unexpected message -- stop reading.
            break
        chunks.append(message.get("body", b""))
        if not message.get("more_body", False):
            break
    return b"".join(chunks)


def _extract_csrf_token(scope, body: bytes) -> str | None:
    """Parse `csrf_token` out of headers or a urlencoded form body.

    Returns None for any of: wrong content-type, non-UTF-8 body, missing
    field. Callers treat None as "reject the request".
    """
    # First, try to extract from X-CSRF-Token header (useful for multipart or fetch uploads)
    for name, value in scope.get("headers", []):
        if name == b"x-csrf-token":
            try:
                return value.decode("utf-8")
            except UnicodeDecodeError:
                pass

    content_type = b""
    for name, value in scope.get("headers", []):
        if name == b"content-type":
            content_type = value
            break

    # Only urlencoded form bodies carry the CSRF token in the form parameters.
    # JSON or multipart bodies must pass the token in X-CSRF-Token header.
    if not content_type.startswith(b"application/x-www-form-urlencoded"):
        return None

    try:
        # keep_blank_values=True so an empty `csrf_token=` field is still
        # parsed (it then fails the truthy check downstream and is rejected
        # -- but EXPLICITLY rejected, not silently absent).
        parsed = parse_qs(body.decode("utf-8"), keep_blank_values=True)
    except UnicodeDecodeError:
        return None
    values = parsed.get(_FORM_FIELD)
    if not values:
        return None
    # parse_qs returns lists (a field can appear more than once). We take
    # the first occurrence -- if a client somehow submits two csrf_token
    # fields, the second one is ignored, which is fine.
    return values[0]


def _replay_receive(body: bytes):
    """Build a wrapped ASGI `receive` that re-emits the buffered body.

    Returned callable behavior:
      - First call: emits a single `http.request` with the full body and
        more_body=False (so the downstream parser sees a complete body).
      - Subsequent calls: emit `http.disconnect`, which is the canonical
        "client is gone" signal -- the handler will stop reading.

    This is the standard ASGI primitive for body-touching middleware. It
    is the reason this middleware does NOT inherit from BaseHTTPMiddleware
    (which doesn't expose receive/send and has no clean way to do this).
    """
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return receive
