# Implementation Plan — No Rate Limiting Fix (Per-IP POST Throttling Middleware)

**Version:** 1.0.0
**Last Updated:** June 15, 2026
**Parent Spec:** [no-rate-limiting-fix.md](./no-rate-limiting-fix.md)
**Foundation Spec:** [app-foundation.md](./app-foundation.md)
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md)
**Tracking Issue:** [No Rate Limiting — credential endpoints accept unlimited POSTs per IP](https://github.com/arifpucit/vuln-web-app/issues)

---

## 0. Plan Overview

This plan implements the fix specified in [no-rate-limiting-fix.md](./no-rate-limiting-fix.md). It closes the **No Rate Limiting** vulnerability and **only** that vulnerability, by installing an in-process, per-IP, sliding-window rate-limit middleware scoped to every `POST` request. The middleware is implemented with Python standard library only (`collections.deque`, `asyncio.Lock`, `time.monotonic`) — no new dependency. The work is split into **four phases** so the change is small, individually verifiable, and easy to revert.

The remaining intentional vulnerability (VULN-8, CSRF) MUST remain exploitable after every phase, and the already-closed fixes (bcrypt password hashing, parameterized SQL, removed `/download/db`, env-sourced session secret, escaped dashboard `{{username}}`, escaped `/search` reflection sinks) stay closed. Each phase ends with an explicit "MUST NOT" callout listing things that would silently alter another vulnerability.

### Phase Summary

| # | Phase | Files Touched | Goal |
|---|-------|--------------|------|
| 1 | Author `RateLimitMiddleware` in a new `core/rate_limit.py` | `backend/app/core/rate_limit.py` | Stdlib ASGI middleware: per-IP sliding window, method-first short-circuit, 429 + Retry-After |
| 2 | Wire the middleware into `main.py` | `backend/app/main.py` | Import the class; read `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW_SECONDS` env vars; `add_middleware(...)` after `SessionMiddleware` |
| 3 | Update `CLAUDE.md` (map, rules, post-fix subsection, spec hierarchy) | `CLAUDE.md` | Reflect VULN-7's closed status |
| 4 | End-to-end verification + vulnerability preservation audit | None (read-only) | Walk every Verification Step in spec §10 |

### Files Modified / Created (Authored)

Exactly the three files declared in spec §3:

- **New** — `backend/app/core/rate_limit.py`
- **Modified** — `backend/app/main.py`
- **Modified** — `CLAUDE.md`

No dependency change (`collections`, `asyncio`, `time`, `os` are stdlib; `starlette` is already transitive via FastAPI), so no `pyproject.toml` or `uv.lock` edit (and no `uv sync`).

### Files That MUST NOT Be Modified

- `backend/app/api/routes/auth.py` — handlers stay byte-for-byte. VULN-1/VULN-2/VULN-3/VULN-6 closures all live here and must not regress. The rate-limit decision is transport-layer, not handler-layer.
- `backend/app/services/auth_service.py` — preserves parameterized queries (VULN-1) and the bcrypt verify call (VULN-5).
- `backend/app/core/security.py` — bcrypt stays.
- `backend/app/db/session.py` — schema and connection layer; untouched.
- `frontend/templates/dashboard.html`, `frontend/templates/login.html`, `frontend/templates/signup.html` — no template-side change (no CAPTCHA, no honeypot, no extra field).
- Any CSS under `frontend/static/`.
- `README.md`, `docs/PRD.md`, `docs/TDD.md`, `.claude/specs/app-foundation.md`, and every other prior spec.
- `pyproject.toml` / `backend/pyproject.toml` / `uv.lock` (no dependency change — the middleware is stdlib-only).

### Vulnerability Preservation Checklist (Carry Through Every Phase)

After the edit, re-confirm:

1. **SQL Injection.** Already CLOSED — `auth_service.py` uses parameterized queries (`WHERE username = ?`, `VALUES (?, ?, ?)`) and `/search` uses `LIKE ?`. Not touched by this plan; stays closed.
2. **Stored XSS.** Already CLOSED — `welcome_page` escapes `username` via `html.escape(..., quote=True)`. Not touched; stays closed.
3. **Reflected XSS.** Already CLOSED — `/search` escapes `q`, both row columns, and the exception text. Not touched; stays closed.
4. **Session Hijacking.** Already CLOSED — `main.py` sources `SECRET_KEY` from the environment with a `secrets.token_hex(32)` fallback. Phase 2 adds two more environment reads next to this one but does NOT alter the secret-key line.
5. **Weak Password (bcrypt).** Already CLOSED — `security.py` uses bcrypt at rounds ≥ 12 with the defensive `try/except` in `verify_password`. Not touched; stays closed.
6. **Exposed Database endpoint.** Already CLOSED — `/download/db` route removed. Not touched; stays closed.
7. **No Rate Limiting.** **This is the only vulnerability being closed.** After Phase 2, every `POST` request is gated by the middleware; after the configured window count, further POSTs from that IP return HTTP 429.
8. **CSRF.** No CSRF token field or middleware added — not touched.

---

## Phase 1 — Author `RateLimitMiddleware` in `backend/app/core/rate_limit.py`

### 1.1 Goal

Create a new file `backend/app/core/rate_limit.py` containing a `RateLimitMiddleware` class derived from `starlette.middleware.base.BaseHTTPMiddleware`. The class maintains an in-memory `dict[str, deque[float]]` per-IP map, prunes stale entries with `time.monotonic()`, returns HTTP 429 + `Retry-After` when over the limit, and short-circuits on the very first statement for non-POST requests.

### 1.2 File to Create

- `backend/app/core/rate_limit.py`

### 1.3 File Contents

Write the file with exactly this content:

```python
import asyncio
import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


class RateLimitMiddleware(BaseHTTPMiddleware):
    """In-process, per-IP sliding-window rate limiter scoped to POST requests.

    Stdlib-only (collections.deque + asyncio.Lock + time.monotonic). Counter
    state is intentionally not persisted across restarts -- see the parent
    spec's Operational Note for the trade-off.
    """

    def __init__(self, app, max_requests: int, window_seconds: int):
        super().__init__(app)
        self._max = max_requests
        self._window = window_seconds
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def dispatch(self, request: Request, call_next):
        # FR-01 / FR-07: method check is the first statement. Every non-POST
        # request bypasses the limiter with zero state access.
        if request.method != "POST":
            return await call_next(request)

        # FR-03: client IP, with a defensive fallback so a missing
        # request.client never raises.
        client = request.client
        ip = client.host if client is not None else "unknown"

        try:
            now = time.monotonic()
            cutoff = now - self._window
            async with self._lock:
                bucket = self._buckets[ip]
                # FR-02 step 3: prune stale entries from the left.
                while bucket and bucket[0] < cutoff:
                    bucket.popleft()
                # FR-02 step 4: length check against the configured max.
                if len(bucket) >= self._max:
                    oldest = bucket[0]
                    # FR-04 + EC-11: integer floor of 1 second.
                    retry_after = max(1, int(self._window - (now - oldest)))
                    return JSONResponse(
                        status_code=429,
                        content={"error": "Too many requests", "retry_after": retry_after},
                        headers={"Retry-After": str(retry_after)},
                    )
                # FR-02 step 5: record this request and forward.
                bucket.append(now)
        except Exception:
            # NFR-07: fail-open on any unexpected bookkeeping error.
            return await call_next(request)

        return await call_next(request)
```

### 1.4 Line-by-Line Justification

| Block | Decision | Spec ref |
|---|---|---|
| Imports limited to `asyncio`, `time`, `collections`, `starlette.middleware.base`, `starlette.requests`, `starlette.responses` | Stdlib-only (Starlette is already transitive via FastAPI) — no new third-party dependency | FR-11, NFR-09, AC-02 |
| `BaseHTTPMiddleware` base class | Starlette's standard middleware ABC — works under FastAPI's `app.add_middleware` and exposes `dispatch(request, call_next)` | AC-01, FR-09 |
| `defaultdict(deque)` for `self._buckets` | Lazy bucket creation on first POST per IP; avoids an explicit `if ip not in …` check | FR-02 |
| `asyncio.Lock` | Concurrency safety under uvicorn's single event loop; lock NOT held across `await call_next(request)` (released before the forward) | FR-05, NFR-10 |
| `request.method != "POST"` as the very first statement | Method-first short-circuit — non-POST overhead is one attribute read + one string compare | FR-01, FR-07, AC-03 |
| `client.host if client is not None else "unknown"` | Defensive fallback so a missing `request.client` never raises; all such requests share one bucket | FR-03, EC-01 |
| `time.monotonic()` (not `time.time()`) | Wall-clock-jump immune; the limiter cannot be reset by NTP slew or manual clock change | EC-03 |
| `while bucket and bucket[0] < cutoff: bucket.popleft()` | Sliding-window prune — O(k) in the number of expired entries, bounded by `max_requests` under normal flow | FR-02, EC-04 |
| `if len(bucket) >= self._max` | Length check against the configured max — the `>=` (not `>`) is what makes the 6th POST throttle when max=5 | FR-02, EC-02 |
| `retry_after = max(1, int(self._window - (now - oldest)))` | Integer-seconds Retry-After with a floor of 1 (RFC 9110 wants a positive integer) | FR-04, EC-11 |
| `JSONResponse(status_code=429, content={…}, headers={"Retry-After": str(retry_after)})` | Spec-mandated response shape — no IP/path/UA leakage | FR-04, NFR-06, AC-04–AC-06 |
| `bucket.append(now)` AFTER the length check | Record-then-forward — the count includes the just-admitted request | FR-02 |
| `try/except Exception: return await call_next(request)` around the bookkeeping | Fail-open on any unexpected internal error (a broken limiter must not crash the app) | NFR-07 |
| Lock acquired AROUND prune+check+append, released BEFORE `await call_next` | Prevents a long handler from blocking other IPs while keeping per-IP state torn-read-free | NFR-10, FR-05 |

### 1.5 What NOT to Change in Phase 1

- **DO NOT** read `X-Forwarded-For`, `X-Real-IP`, or any other proxy header. Trusting client-controlled headers without a known reverse-proxy contract creates a *new* bypass vulnerability where the attacker spoofs the source IP (spec §2.4).
- **DO NOT** add a logger. The lab application does not configure structured logging; introducing one adds noise and risks leaking IPs to a log sink (spec §NFR-06).
- **DO NOT** call `await call_next(request)` while still holding `self._lock`. The lock must be released before the forward so a slow bcrypt verify on one IP does not block another IP's prune/check.
- **DO NOT** count requests *after* the handler returns. The append happens before the forward so handler crashes still count against quota (spec §EC-12).
- **DO NOT** inspect the response — no header rewrites, no status changes, no body reads on the non-throttled path (spec §FR-08).
- **DO NOT** introduce a "trusted IP allowlist" or "skip limit for authenticated users" shortcut. The spec mandates one global per-IP cap on every POST.
- **DO NOT** persist `self._buckets` to disk or to Redis. State is in-process by design (spec §NFR-08, §2.4).
- **DO NOT** add a third-party dependency (`slowapi`, `limits`, `redis`, `fastapi-limiter`). The spec mandates stdlib-only (spec §FR-11, §NFR-09).
- **DO NOT** add a periodic GC thread that prunes empty buckets. The spec calls this out as OPTIONAL and explicitly does not require it (spec §NFR-05). For a local lab, unbounded-IP defense is out of scope.
- **DO NOT** use `time.time()`. `monotonic` is the spec-mandated clock source (spec §EC-03).

### 1.6 (Optional, NOT in this fix) Cleanup hook

The spec §NFR-05 notes the implementer MAY add a periodic GC pass that drops empty `bucket` entries after pruning. This plan deliberately does NOT include it — the lab is single-host and short-lived. Adding it later is a one-line `if not bucket: self._buckets.pop(ip, None)` inside the lock, but it is **out of scope for this fix**.

### 1.7 Phase 1 Verification (Pre-Server)

```bash
# File exists and contains the right class
grep -n 'class RateLimitMiddleware' backend/app/core/rate_limit.py

# Stdlib-only imports
grep -nE '^(import|from)' backend/app/core/rate_limit.py
# Expected: only collections, asyncio, time, starlette.middleware.base,
# starlette.requests, starlette.responses

# Method check is the very first statement of dispatch
grep -n 'request.method != "POST"' backend/app/core/rate_limit.py

# No proxy-header trust
grep -ni 'x-forwarded-for\|x-real-ip' backend/app/core/rate_limit.py \
  || echo '(no proxy-header trust — preserved)'

# Module imports cleanly under the runtime Python
cd backend && uv run python -c "from app.core.rate_limit import RateLimitMiddleware; print('import ok')" && cd ..
```

Expected: the first three greps each match; the proxy-header grep prints its fallback; the import smoke test prints `import ok`.

---

## Phase 2 — Wire the Middleware Into `backend/app/main.py`

### 2.1 Goal

Add an import for `RateLimitMiddleware`, read the two new environment variables (`RATE_LIMIT_MAX`, `RATE_LIMIT_WINDOW_SECONDS`) with stdlib `os.environ.get`, and register the middleware via `app.add_middleware(...)` **after** the existing `SessionMiddleware` registration.

### 2.2 File to Modify

- `backend/app/main.py`

### 2.3 Edit A — Add the Middleware Import

**Before** (L13 region):

```python
from app.api.routes.auth import router
from app.db.session import init_db
```

**After**:

```python
from app.api.routes.auth import router
from app.core.rate_limit import RateLimitMiddleware
from app.db.session import init_db
```

The new import is placed alongside the other local-app imports (between `app.api.routes.auth` and `app.db.session`) to match the file's existing local-import grouping.

### 2.4 Edit B — Add Environment-Driven Limits and Register the Middleware

**Before** (L18–23 region):

```python
# FIXED: Session Hijacking closed -- secret loaded from the environment,
# with a strong random fallback so a fresh checkout never ships a known key.
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

app.include_router(router)
```

**After**:

```python
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
```

Four concrete changes:

1. Two new env reads (`RATE_LIMIT_MAX`, `RATE_LIMIT_WINDOW_SECONDS`), each wrapped in `int(...)`. Invalid values raise `ValueError` at import time — fail-loud, per spec §FR-06 / §EC-07.
2. A two-line comment block in the same `# FIXED: …` style as the VULN-4 block immediately above.
3. The `app.add_middleware(RateLimitMiddleware, ...)` call placed **after** `app.add_middleware(SessionMiddleware, ...)` — per spec §FR-09, the last `add_middleware` call wraps the innermost, so `RateLimitMiddleware` runs as the outer layer on the request path (short-circuits with 429 before `SessionMiddleware` decodes the cookie).
4. Nothing else changes. `sys.path.insert`, the `secrets`/`os` imports, the static mounts, the `init_db()` call, and the `__main__` uvicorn block are byte-for-byte unchanged.

### 2.5 Edit Summary

Edits inside `main.py`:

1. **Local-imports block** — add `from app.core.rate_limit import RateLimitMiddleware`.
2. **Middleware-registration region** — add the two env reads, the comment block, and the `app.add_middleware(RateLimitMiddleware, ...)` call directly after the existing `SessionMiddleware` registration.

No other line in the file changes.

### 2.6 Line-by-Line Justification

| Line / Block | Decision | Spec ref |
|---|---|---|
| `from app.core.rate_limit import RateLimitMiddleware` | Local-app import for the new middleware | AC-01, AC-09 |
| `int(os.environ.get("RATE_LIMIT_MAX", "5"))` | Stdlib env read with the spec-mandated default; `int(...)` is fail-loud on garbage values | FR-06, EC-07, AC-10 |
| `int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", "60"))` | Same pattern; default 60 s | FR-06, AC-10 |
| `# FIXED: No Rate Limiting closed -- …` comment block | Mirrors the existing `# FIXED: Session Hijacking closed -- …` block immediately above | (style consistency) |
| `add_middleware(RateLimitMiddleware, ...)` placed AFTER `add_middleware(SessionMiddleware, ...)` | Starlette ordering: last `add_middleware` wraps innermost; `RateLimitMiddleware` becomes the outer layer on the request path | FR-09 |
| `SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))` unchanged | VULN-4 closure stays exactly as it is | AC-13 |
| Static mounts and `init_db()` unchanged | No other behavior changes | NFR-02, NFR-03 |

### 2.7 What NOT to Change in Phase 2

- **DO NOT** reorder the middleware registrations. The `RateLimitMiddleware` registration MUST come **after** `SessionMiddleware`. Reversing the order would make `SessionMiddleware` the outer layer — it would then decode and re-encode the session cookie on every 429 response, wasting CPU and (more importantly) potentially writing a `Set-Cookie` on a throttled call (spec §FR-09).
- **DO NOT** touch the `SECRET_KEY = os.environ.get(...)` line. VULN-4 stays closed (spec §AC-13). Don't replace the `secrets.token_hex(32)` fallback with anything else.
- **DO NOT** swallow the `ValueError` from `int(os.environ.get(...))`. The spec mandates fail-loud on misconfiguration (spec §FR-06, §EC-07). Do not wrap in `try/except`.
- **DO NOT** parse `.env` files. No new dependency. The middleware is configured via raw process environment (spec §FR-11, §NFR-09).
- **DO NOT** add a third-party dependency or modify `pyproject.toml` / `backend/pyproject.toml` / `uv.lock` (spec §NFR-09, §AC-15).
- **DO NOT** change the static-file mounts, the FastAPI title, the uvicorn host/port logic, or the `init_db()` call.
- **DO NOT** add per-route decorators. The middleware applies to all POSTs globally; per-route limits are out of scope (spec §2.4).
- **DO NOT** re-introduce a closed vulnerability:
  - No re-adding `/download/db` (VULN-6 stays closed).
  - No reverting `main.py` to the hardcoded `"super-secret-key-12345"` (VULN-4 stays closed).
  - No reverting `security.py` to MD5 (VULN-5 stays closed).
  - No reverting `auth_service.py` / `auth.py` to string-concatenated SQL (VULN-1 stays closed).
  - No removing the `html.escape` calls in `auth.py` (VULN-2 + VULN-3 stay closed).

### 2.8 Phase 2 Verification (Pre-Server)

```bash
# Import added
grep -n 'from app.core.rate_limit import RateLimitMiddleware' backend/app/main.py

# Env reads present with the spec-mandated defaults
grep -n 'RATE_LIMIT_MAX' backend/app/main.py
grep -n 'RATE_LIMIT_WINDOW_SECONDS' backend/app/main.py

# Middleware registered AFTER SessionMiddleware
awk '/add_middleware\(SessionMiddleware/{s=NR} /add_middleware\(\s*$/||/add_middleware\(RateLimitMiddleware/{r=NR} END{ if (s && r && r > s) print "ordering ok: SessionMiddleware@"s" < RateLimitMiddleware@"r; else print "ORDERING WRONG" }' backend/app/main.py

# VULN-4 closure untouched
grep -n 'os.environ.get("SECRET_KEY"' backend/app/main.py
grep -n 'super-secret-key-12345' backend/app/main.py || echo '(hardcoded secret absent — preserved)'

# No dependency-file edits
git status --porcelain | grep -E '(pyproject\.toml|uv\.lock)' \
  || echo '(no dependency files modified — preserved)'

# Module imports cleanly under the runtime Python
cd backend && uv run python -c "from app.main import app; print('boot ok')" && cd ..
```

Expected: the import grep matches; both env-read greps match; the awk line prints `ordering ok: ...`; the VULN-4 grep matches and the hardcoded-secret grep prints its fallback; the dependency-files grep prints its fallback; the boot smoke test prints `boot ok`.

---

## Phase 3 — Update `CLAUDE.md`

### 3.1 Goal

Reflect VULN-7's closed status across the four `CLAUDE.md` sections that mention rate limiting or vulnerability counts: the opening paragraph, the Vulnerability Map row, the "Important Rules" section, and the Specification Hierarchy list. Also add a new "Rate Limiting After the Fix" subsection mirroring the existing "Session Secret After the Fix" subsection.

### 3.2 File to Modify

- `CLAUDE.md`

### 3.3 Edit A — Opening Paragraph (Count Update)

**Before** (L5):

> It originally shipped with 8 OWASP Top 10 vulnerabilities. Six of them — VULN-5 (Weak Password Storage), VULN-1 (SQL Injection), VULN-6 (Exposed DB), VULN-4 (Session Hijacking), VULN-2 (Stored XSS), and VULN-3 (Reflected XSS) — have since been closed. The other 2 remain intentionally exploitable for students to attack, understand, and remediate.

**After**:

> It originally shipped with 8 OWASP Top 10 vulnerabilities. Seven of them — VULN-5 (Weak Password Storage), VULN-1 (SQL Injection), VULN-6 (Exposed DB), VULN-4 (Session Hijacking), VULN-2 (Stored XSS), VULN-3 (Reflected XSS), and VULN-7 (No Rate Limiting) — have since been closed. The other 1 remains intentionally exploitable for students to attack, understand, and remediate.

**Before** (L7 — the WARNING paragraph):

> **WARNING:** The remaining 2 vulnerabilities are intentional. Do not "fix" them unless explicitly asked. The closed fixes (bcrypt password hashing, parameterized SQL, removed `/download/db` route, the hardened session secret, the escaped dashboard username, and the escaped search output) are permanent — do not revert them.

**After**:

> **WARNING:** The remaining 1 vulnerability is intentional. Do not "fix" it unless explicitly asked. The closed fixes (bcrypt password hashing, parameterized SQL, removed `/download/db` route, the hardened session secret, the escaped dashboard username, the escaped search output, and the per-IP POST rate-limit middleware) are permanent — do not revert them.

### 3.4 Edit B — Vulnerability Map Row

**Before** (L50):

```
| 7 | No Rate Limit | Global | No rate limiting middleware | Open |
```

**After**:

```
| 7 | No Rate Limit | `backend/app/core/rate_limit.py` + `backend/app/main.py` | Stdlib `RateLimitMiddleware` enforces a per-IP sliding window on every POST (default 5 / 60 s); throttled requests get HTTP 429 + `Retry-After` before the handler runs | **Closed** |
```

### 3.5 Edit C — "Important Rules" Section

**Before** (L88):

> - Never add rate limiting middleware (preserves VULN-7)

**After**:

> - Never remove the rate-limit middleware in `backend/app/main.py` / `backend/app/core/rate_limit.py`. VULN-7 is closed by an in-process per-IP sliding-window `RateLimitMiddleware` scoped to every POST (default 5 requests per 60 s, tunable via `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW_SECONDS` env vars). The middleware is permanent and must stay (stdlib-only, no third-party rate-limit dependency).

### 3.6 Edit D — Add "Rate Limiting After the Fix" Subsection

Insert this subsection between the existing "Session Secret After the Fix" subsection and the "Frontend-Backend Integration" subsection:

```markdown
### Rate Limiting After the Fix

`main.py` registers a stdlib-only `RateLimitMiddleware` (defined in `backend/app/core/rate_limit.py`) after `SessionMiddleware`:

```python
RATE_LIMIT_MAX = int(os.environ.get("RATE_LIMIT_MAX", "5"))
RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", "60"))
app.add_middleware(
    RateLimitMiddleware,
    max_requests=RATE_LIMIT_MAX,
    window_seconds=RATE_LIMIT_WINDOW_SECONDS,
)
```

- **Scope:** every `POST` request, identified by `request.client.host`. GET / HEAD / OPTIONS / static-file requests bypass the limiter with a single method-check.
- **State:** in-process `dict[str, collections.deque[float]]` of `time.monotonic()` timestamps, guarded by a single `asyncio.Lock`. Reset on every restart — no Redis, no disk persistence.
- **Throttled response:** HTTP `429` with body `{"error": "Too many requests", "retry_after": <int>}` and a `Retry-After: <int>` header. The downstream handler — including the bcrypt verify on `POST /login` — is never invoked on a throttled call.
- **No proxy-header trust:** `X-Forwarded-For` is intentionally ignored. If you front the app with a reverse proxy in a real deployment, configure the proxy to populate `request.client.host` (e.g., uvicorn's `--proxy-headers` with a trusted-IP allowlist) rather than trusting headers blindly.
- **Local lab use:** run with no env overrides — the defaults are conservative enough to make brute-force impractical without locking out a user who mistypes their password a few times. To experiment, set `RATE_LIMIT_MAX=2 RATE_LIMIT_WINDOW_SECONDS=5` before launch.
```

### 3.7 Edit E — Append to Specification Hierarchy

**Before** (L105 region):

```
9. `.claude/specs/reflected-xss-fix.md` + `.claude/specs/reflected-xss-fix-plan.md` — VULN-3 fix
```

**After** — append item 10:

```
9. `.claude/specs/reflected-xss-fix.md` + `.claude/specs/reflected-xss-fix-plan.md` — VULN-3 fix
10. `.claude/specs/no-rate-limiting-fix.md` + `.claude/specs/no-rate-limiting-fix-plan.md` — VULN-7 fix
```

### 3.8 What NOT to Change in Phase 3

- **DO NOT** touch the count or status of VULN-1, VULN-2, VULN-3, VULN-4, VULN-5, VULN-6, or VULN-8 in the Vulnerability Map. Only the VULN-7 row changes.
- **DO NOT** remove the "Never add CSRF tokens to forms (preserves VULN-8)" rule. VULN-8 stays open (spec §2.3).
- **DO NOT** edit the "Development Commands", "Architecture", "Login Flow After the Bcrypt Fix", "Session Secret After the Fix", or "Frontend-Backend Integration" subsections — except for inserting the new "Rate Limiting After the Fix" subsection (Phase 3.6) between two of them.
- **DO NOT** rename existing rule bullets. Only the rate-limit rule changes; the other rules stay byte-for-byte.

### 3.9 Phase 3 Verification

```bash
# VULN-7 row now reads Closed
grep -n '| 7 | No Rate Limit' CLAUDE.md

# New "Rate Limiting After the Fix" subsection added
grep -n '^### Rate Limiting After the Fix' CLAUDE.md

# Important Rules section's old "Never add rate limiting" line is gone
grep -n 'Never add rate limiting middleware' CLAUDE.md \
  || echo '(old rule retired — preserved)'

# New "Never remove the rate-limit middleware" rule present
grep -n 'Never remove the rate-limit middleware' CLAUDE.md

# Spec hierarchy includes item 10
grep -n 'no-rate-limiting-fix.md' CLAUDE.md

# VULN-8 rule unchanged
grep -n 'Never add CSRF tokens' CLAUDE.md
```

Expected: each grep matches (and the "old rule retired" line prints its fallback).

---

## Phase 4 — End-to-End Verification + Vulnerability Preservation Audit

This phase walks every Verification Step in spec §10 in order. **No edits** are made; if any step fails, return to the relevant earlier phase to repair.

### 4.1 Start the Application (spec §10.4 — AC-16, TC-23)

```bash
rm -f vulnerable_app.db
uv run backend/app/main.py
```

The DB reset is recommended so the test users registered below have predictable bcrypt hashes and a clean `users` table. The server listens on `http://localhost:3001` with no import/boot error.

### 4.2 Confirm Middleware File and Class (spec §10.1 — AC-01, TC-01)

```bash
grep -n 'class RateLimitMiddleware' backend/app/core/rate_limit.py
```

Expected: a single matching line.

### 4.3 Confirm Stdlib-Only Imports (spec §10.2 — AC-02, TC-02)

```bash
grep -nE '^(import|from)' backend/app/core/rate_limit.py
```

Expected: only `collections`, `asyncio`, `time`, `starlette.middleware.base`, `starlette.requests`, `starlette.responses`. No `slowapi`, no `limits`, no `redis`, no `fastapi_limiter`.

### 4.4 Confirm Middleware Registered in `main.py` (spec §10.3 — AC-09, TC-03)

```bash
grep -n 'RateLimitMiddleware' backend/app/main.py
```

Expected: the import line and the `add_middleware(RateLimitMiddleware, ...)` line. Manual inspection confirms the `add_middleware(RateLimitMiddleware, ...)` line appears **after** `add_middleware(SessionMiddleware, ...)`.

### 4.5 Benign POST Passes (spec §10.5 — AC-07, TC-05)

```bash
curl -s -c jar.txt -X POST http://localhost:3001/signup \
     --data-urlencode 'username=alice' \
     --data-urlencode 'email=alice@test.com' \
     --data-urlencode 'password=pass123'

curl -s -i -c jar.txt -b jar.txt -X POST http://localhost:3001/login \
     --data-urlencode 'username=alice' \
     --data-urlencode 'password=pass123' | head -20
```

Expected: HTTP `200`, JSON body `{"success": true, "redirect": "/welcome"}`, `Set-Cookie: session=...` header. No 429.

### 4.6 6th POST Throttled With Default Config (spec §10.6 — AC-04, AC-05, AC-06, TC-06–TC-08)

```bash
for i in {1..6}; do
  curl -s -o body.$i -w 'HTTP=%{http_code}\n' -D headers.$i \
       -X POST http://localhost:3001/login \
       --data-urlencode 'username=ghost' \
       --data-urlencode 'password=wrong'
done
echo '--- final response status:'
cat body.6
echo '--- final response headers:'
grep -i 'retry-after\|^http' headers.6
```

Expected: requests 1–5 print `HTTP=401`; request 6 prints `HTTP=429`; `cat body.6` shows `{"error":"Too many requests","retry_after":<int>}`; `Retry-After: <int>` with `1 ≤ int ≤ 60`.

### 4.7 GET Routes Unaffected (spec §10.7 — AC-08, TC-09)

```bash
for i in {1..50}; do
  curl -s -o /dev/null -w '%{http_code}\n' http://localhost:3001/login
done | sort -u
```

Expected: only `200`.

### 4.8 `POST /signup` Also Throttled (spec §10.8 — TC-10)

```bash
for i in {1..6}; do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:3001/signup \
       --data-urlencode "username=ghost$i" --data-urlencode "email=g$i@x" \
       --data-urlencode 'password=p'
done
```

Expected: a mix of `302` / `400` for the first five and `429` for the sixth.

### 4.9 Window Slides Open (spec §10.9 — AC-11, TC-11)

```bash
sleep 65
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:3001/login \
     --data-urlencode 'username=ghost' --data-urlencode 'password=wrong'
```

Expected: `401`.

### 4.10 Env Override Honored (spec §10.10 — AC-10, TC-13)

Stop the current server, then:

```bash
RATE_LIMIT_MAX=2 RATE_LIMIT_WINDOW_SECONDS=5 uv run backend/app/main.py &
sleep 1
for i in {1..3}; do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:3001/login \
       --data-urlencode 'username=ghost' --data-urlencode 'password=wrong'
done
echo '--- waiting 6 s ---'
sleep 6
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:3001/login \
     --data-urlencode 'username=ghost' --data-urlencode 'password=wrong'
kill %1 2>/dev/null
```

Expected: `401`, `401`, `429`, then after the wait `401`.

### 4.11 Vulnerability Preservation Walkthrough (spec §10.11 — AC-13, TC-15–TC-21)

Restart with default config, then run:

```bash
uv run backend/app/main.py &
sleep 1

# VULN-1 SQL injection stays closed (TC-15)
grep -n 'WHERE username = ?' backend/app/services/auth_service.py
grep -n 'LIKE ?' backend/app/api/routes/auth.py

# VULN-2 Stored XSS stays closed (TC-16)
grep -n 'html.escape(username, quote=True)' backend/app/api/routes/auth.py

# VULN-3 Reflected XSS stays closed (TC-17)
test "$(grep -c 'html.escape(' backend/app/api/routes/auth.py)" = "5" \
  && echo '(5 html.escape calls present — VULN-2 + VULN-3 closures intact)'

# VULN-4 Session secret env-sourced (TC-18)
grep -n 'os.environ.get("SECRET_KEY"' backend/app/main.py
grep -n 'super-secret-key-12345' backend/app/main.py || echo '(hardcoded secret absent — preserved)'

# VULN-5 Bcrypt stays in use (TC-19)
grep -n 'bcrypt' backend/app/core/security.py

# VULN-6 /download/db stays removed (TC-20)
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:3001/download/db
# Expected: 404

# VULN-8 No CSRF tokens (TC-21)
curl -s http://localhost:3001/login  | grep -i csrf || echo '(no csrf field — preserved)'
curl -s http://localhost:3001/signup | grep -i csrf || echo '(no csrf field — preserved)'

kill %1 2>/dev/null
```

Expected: every grep / curl matches the spec's expected output.

### 4.12 No New Dependency (spec §10.12 — AC-15, TC-22)

```bash
git status --porcelain | grep -E '(pyproject\.toml|uv\.lock)' \
  || echo '(no dependency files modified — preserved)'
```

Expected: prints the fallback.

### 4.13 Affected-Files Audit (spec §10.13 — AC-12, AC-14, TC-14, TC-24)

```bash
git status --porcelain
```

Expected output — exactly the three declared files plus the two new spec docs:

```
?? backend/app/core/rate_limit.py
 M backend/app/main.py
 M CLAUDE.md
?? .claude/specs/no-rate-limiting-fix.md
?? .claude/specs/no-rate-limiting-fix-plan.md
```

No other path. In particular, no entry for `auth.py`, `auth_service.py`, `security.py`, `db/session.py`, any template, any CSS file, `README.md`, or any pyproject/lock file.

### 4.14 Spec Acceptance Criteria Roll-Up

Tick every AC from spec §8:

- [ ] AC-01 New Middleware File Exists (Phase 1.3, Phase 4.2)
- [ ] AC-02 Middleware Stdlib-Only (Phase 1.3, Phase 4.3)
- [ ] AC-03 Method Check Comes First (Phase 1.3, Phase 1.7)
- [ ] AC-04 Throttled POST Returns 429 (Phase 4.6)
- [ ] AC-05 429 Response Includes `Retry-After` Header (Phase 4.6)
- [ ] AC-06 429 Response Body Shape (Phase 4.6)
- [ ] AC-07 Non-Throttled POST Untouched (Phase 4.5)
- [ ] AC-08 GET Routes Unaffected by the Limit (Phase 4.7)
- [ ] AC-09 Middleware Registered in `main.py` (Phase 2.4, Phase 4.4)
- [ ] AC-10 Environment Variables Honored (Phase 2.4, Phase 4.10)
- [ ] AC-11 Window Sliding (Phase 4.9)
- [ ] AC-12 Handler Code Untouched (Phase 4.13)
- [ ] AC-13 Other Vulnerabilities Preserved (Phase 4.11)
- [ ] AC-14 CLAUDE.md Updated (Phase 3.3–3.7)
- [ ] AC-15 No New Dependency (Phase 4.12)
- [ ] AC-16 Application Boots (Phase 4.1)

### 4.15 Stop the Server

`Ctrl+C` to stop. Plan complete.

---

## Risk Log & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Middleware ordering reversed (`RateLimitMiddleware` added BEFORE `SessionMiddleware`) → `SessionMiddleware` becomes the outer layer and runs cookie work on every 429 | Medium | Medium | Spec §FR-09 + Phase 2.4 explicitly shows the order; Phase 2.8 awk check asserts the line order; Phase 4.4 manual inspection re-confirms |
| Lock held across `await call_next(request)` → a slow bcrypt verify on one IP blocks every other IP | Medium | High | Phase 1.4 + Phase 1.5 "MUST NOT" call this out explicitly; the code in Phase 1.3 acquires the lock only around prune/check/append and releases before forwarding |
| Counting *after* the handler runs (append placed after `await call_next`) → handler errors don't count and an attacker can avoid the limit by triggering 500s on purpose | Medium | Medium | Spec §EC-12 + Phase 1.3 code shows the append BEFORE the forward; Phase 1.5 MUST-NOT forbids the inverted order |
| Trusting `X-Forwarded-For` "while in here" → introduces a *new* bypass vulnerability (attacker spoofs source IP via header) | Medium | High | Spec §2.4 + Phase 1.5 MUST-NOT explicitly forbid proxy-header trust; Phase 1.7 grep asserts no `x-forwarded-for` reference in the middleware file |
| `time.time()` used instead of `time.monotonic()` → wall-clock jump (NTP slew, manual clock change) can reset counters or freeze the window | Low | Medium | Spec §EC-03 + Phase 1.3 code uses `time.monotonic()` explicitly; Phase 1.4 line-by-line note flags this |
| Forgetting `int(...)` around the env reads → `RATE_LIMIT_MAX` becomes a string, the length comparison `len(deque) >= "5"` raises `TypeError` on first POST | Low | High | Phase 2.4 code shows `int(os.environ.get(...))`; Phase 2.8 boot smoke test catches it (the env reads execute at import time, so the failure surfaces at startup with default values too — `int("5")` is fine, but if a maintainer later drops the `int(...)`, the smoke test exercises the code path) |
| Adding a third-party dependency (`slowapi`, `limits`, `redis`) "for production-readiness" — scope creep + dependency change | Low | Medium | Spec §FR-11, §NFR-09 + Phase 1.5 MUST-NOT forbid new deps; Phase 4.12 grep asserts no pyproject/lock edits |
| `defaultdict(deque)` map grows unboundedly under many distinct attacker IPs → memory leak on a long-running process | Low | Low | Spec §NFR-05 explicitly accepts this trade-off for the lab; the optional cleanup hook (Phase 1.6) is documented as a future enhancement but NOT required for this fix; risk is real but tiny on a single-host educational lab |
| `ValueError` from `int("abc")` on bad env values silently caught somewhere → app starts with a default the operator didn't intend | Very Low | Medium | Spec §FR-06, §EC-07 + Phase 2.7 MUST-NOT forbid wrapping the env read in try/except; the bare `int(...)` is fail-loud by design |
| Accidentally re-opening a previously closed vulnerability while editing `main.py` (e.g. reverting the `SECRET_KEY` line) | Very Low | High | Phase 2.7 MUST-NOT enumerates all closed vulns; Phase 2.8 grep + Phase 4.11 walkthrough catch any regression |
| Modifying a handler file "while in here" (e.g. adding per-route decorators in `auth.py`) → scope creep + diff surface explosion | Low | Medium | Spec §FR-10 + Phase 2.7 MUST-NOT forbid handler edits; Phase 4.13 file audit catches any stray edit |

---

## Rollback Procedure

If a phase fails verification and cannot be repaired quickly:

```bash
git restore backend/app/main.py CLAUDE.md
rm -f backend/app/core/rate_limit.py
```

The two modified files snap back to their pre-fix state and the new middleware file is removed. No dependency, schema, or data migration is involved — the `vulnerable_app.db` file, the `users` table, and the session cookie format are all untouched by the fix in the first place.

---

## Out-of-Band: What This Plan Deliberately Does NOT Do

To make the negative space explicit:

- **No input filtering, no CAPTCHA, no account lockout.** The handler still runs `verify_password` on every non-throttled attempt; on throttled attempts it doesn't run at all. There is no "after 5 failed logins, lock the account for an hour" rule.
- **No distributed state.** Counters live in one Python process. A multi-worker deployment would see each worker enforce its own quota. Production hardening would back the counter with Redis (out of scope).
- **No proxy-header trust.** The middleware uses `request.client.host` directly. `X-Forwarded-For`, `X-Real-IP`, `Forwarded`, and every other client-controlled header are ignored.
- **No per-route limits.** One global per-IP cap on every POST. `/login` and `/signup` are not differentiated.
- **No per-user limits.** The limit is keyed on source IP only. Username-based or session-based counting is out of scope.
- **No third-party dependency.** No `slowapi`, no `limits`, no `redis`, no `fastapi-limiter`. The middleware is stdlib + Starlette (already transitive via FastAPI).
- **No template edits.** `dashboard.html`, `login.html`, `signup.html` are byte-for-byte unchanged. No CAPTCHA field, no honeypot input, no extra hidden field.
- **No change to `auth.py` or `auth_service.py`.** All VULN-1/VULN-2/VULN-3/VULN-6 closures stay exactly as they are. The handlers do not know the limiter exists.
- **No change to bcrypt cost factor.** VULN-5 stays at rounds ≥ 12.
- **No change to session-cookie attributes.** VULN-4's env-sourced secret stays; no change to `name`, `max_age`, `same_site`, `https_only`.
- **No reversal of prior fixes.** VULN-1 (parameterized SQL), VULN-2 (escaped `{{username}}`), VULN-3 (escaped `/search` sinks), VULN-4 (env-sourced session secret), VULN-5 (bcrypt), and VULN-6 (removed `/download/db`) all stay closed.
- **No persistence of counter state.** The `defaultdict(deque)` map is reset on every process start. This is by design (spec §NFR-08).
- **No log line on throttle.** The middleware emits no logs. The 429 response itself is the only signal.
- **No CSRF posture change.** VULN-8 remains. No CSRF tokens are added to forms; no CSRF middleware is registered.
- **No file** created or modified beyond `backend/app/core/rate_limit.py` (new), `backend/app/main.py` (modified), `CLAUDE.md` (modified), and this spec/plan pair.
