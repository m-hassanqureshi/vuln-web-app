# CLAUDE.md

## Project Context

This is an **intentionally vulnerable web application** for security education. It originally shipped with 8 OWASP Top 10 vulnerabilities. All 8 of them — VULN-5 (Weak Password Storage), VULN-1 (SQL Injection), VULN-6 (Exposed DB), VULN-4 (Session Hijacking), VULN-2 (Stored XSS), VULN-3 (Reflected XSS), VULN-7 (No Rate Limiting), and VULN-8 (CSRF) — have since been closed. No vulnerabilities remain intentionally exploitable; the project is now a complete "before / after" reference, with v0.1.0 as the fully vulnerable baseline.

**WARNING:** All eight closed fixes (bcrypt password hashing, parameterized SQL, removed `/download/db` route, the hardened session secret, the escaped dashboard username, the escaped search output, the per-IP POST rate-limit middleware, and the synchronizer-token CSRF middleware) are permanent — do not revert them. To study the original vulnerabilities, students should check out the `v0.1.0` tag rather than weakening the current codebase.

## Development Commands

```bash
# Install backend dependencies
cd backend && uv sync

# Run the application (from project root)
uv run backend/app/main.py

# Access at http://localhost:3001
```

## Architecture

Three-layer architecture: Presentation (HTML/CSS/JS) → Application (FastAPI) → Data (SQLite).

```
backend/app/
├── main.py              # Entry point, middleware, static mounts — VULN-4 closed (env-sourced session secret)
├── core/security.py     # bcrypt password hashing (cost 12) — VULN-5 closed
├── db/session.py        # SQLite connection and init
├── services/auth_service.py  # Auth business logic - VULN-1 closed
└── api/routes/auth.py   # HTTP route handlers

frontend/
├── templates/           # HTML templates (loaded from disk each request)
│                        # Each template carries a pre-render theme init script
│                        # and a theme-toggle button in the shared header
└── static/              # CSS (light/dark via CSS custom properties + data-theme) and images
```

## Vulnerability Map

| # | Vulnerability | File | Mechanism | Status |
|---|---------------|------|-----------|--------|
| 1 | SQL Injection | `backend/app/services/auth_service.py` | String concatenation in SQL queries (both `signup()` INSERT and `login()` SELECT WHERE-username branch) | **Closed** |
| 2 | Stored XSS | `backend/app/api/routes/auth.py` | Was unescaped `{{username}}` in dashboard; now `html.escape(username, quote=True)` before substitution (output encoding; raw value still stored) | **Closed** |
| 3 | Reflected XSS | `backend/app/api/routes/auth.py` | Was unescaped `q` (and result rows / error text) in `/search`; now `html.escape(..., quote=True)` on every sink before splicing (output encoding; raw values still in URL/DB) | **Closed** |
| 4 | Session Hijacking | `backend/app/main.py` | Was hardcoded secret `"super-secret-key-12345"`; now sourced from the `SECRET_KEY` env var with a strong `secrets.token_hex(32)` random fallback | **Closed** |
| 5 | Weak Password | `backend/app/core/security.py` | Was MD5 (no salt); now bcrypt (`BCRYPT_ROUNDS = 12`); `verify_password` wraps `bcrypt.checkpw` in `try/except` so legacy MD5 rows return `False` instead of crashing | **Closed** |
| 6 | Exposed DB | `backend/app/api/routes/auth.py` | Was an unauthenticated `/download/db` route; the route has been removed entirely | **Closed** |
| 7 | No Rate Limit | `backend/app/core/rate_limit.py` + `backend/app/main.py` | Stdlib `RateLimitMiddleware` enforces a per-IP sliding window on every POST (default 5 / 60 s); throttled requests get HTTP 429 + `Retry-After` before the handler runs | **Closed** |
| 8 | CSRF | `backend/app/core/csrf.py` + `backend/app/main.py` + form templates | Synchronizer-token `CSRFMiddleware` rejects every POST whose `csrf_token` form field does not match `request.session["csrf_token"]`; token issued by `get_or_create_csrf_token` on `GET /login` / `GET /signup` and spliced into the rendered HTML | **Closed** |

### Login Flow After the Bcrypt Fix

`auth_service.login()` no longer matches the password hash inside SQL (bcrypt's per-call salt makes equality matching impossible). It now:

1. Builds `SELECT * FROM users WHERE username = ?` and passes `username` as a bound parameter — the query is **parameterized**, so VULN-1 is closed.
2. Calls `verify_password(password, row["password"])` in Python after `fetchone()`.
3. Returns the same JSON 401 for "no row," "bcrypt mismatch," and "legacy MD5 row" cases — no information leakage between them.

If a legacy MD5 hex digest exists in `vulnerable_app.db`, it cannot authenticate. Operators should `rm vulnerable_app.db` and re-register, or have affected users sign up fresh.

### Session Secret After the Fix

`main.py` no longer ships a hardcoded session signing key. It now sets:

```python
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
```

- **Production / shared deployments:** set `SECRET_KEY` in the environment to a strong secret (e.g. `python -c "import secrets; print(secrets.token_hex(32))"`). Supplying the same value on every start keeps existing sessions valid across restarts.
- **Local lab use:** run with no `SECRET_KEY` set. The app generates a fresh random key each start (stdlib `secrets` only — no new dependency, no `.env`). The only visible effect is that sessions do not survive a restart — users simply log in again.

A fresh checkout that is simply run never falls back to a known or guessable key, so the cookie can no longer be forged from a published constant.

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

### CSRF Protection After the Fix

`main.py` registers a stdlib-only **pure-ASGI** `CSRFMiddleware` (defined in `backend/app/core/csrf.py`) as the first `add_middleware` call, with `SessionMiddleware` second and `RateLimitMiddleware` last:

```python
app.add_middleware(CSRFMiddleware)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
app.add_middleware(
    RateLimitMiddleware,
    max_requests=RATE_LIMIT_MAX,
    window_seconds=RATE_LIMIT_WINDOW_SECONDS,
)
```

Starlette's `add_middleware` prepends to its internal middleware list, so the *last* `add_middleware` call is the *outermost* layer on the request path. The resulting flow is `RateLimit (outer) → Session → CSRF (inner) → handler`. Rate-limit still gates floods first; CSRF reads the already-decoded session.

- **Token:** `secrets.token_urlsafe(32)` — 256 bits of entropy, URL-safe Base64 (43 characters, `[A-Za-z0-9_-]`).
- **Storage:** `request.session["csrf_token"]` — lives only inside the signed session cookie (VULN-4's `SECRET_KEY` signs the whole session dict). No database column, no in-process map.
- **Issuance:** `GET /login` and `GET /signup` call `get_or_create_csrf_token(request)`, which lazily writes a token on first read and returns the existing value on subsequent reads (one token per session, not per request).
- **Splice:** the handlers do `page.replace("{{csrf_token}}", html.escape(token, quote=True))` — same pattern as the `{{username}}` splice in `welcome_page`. The hidden input `<input type="hidden" name="csrf_token" value="{{csrf_token}}">` is the first child of each form.
- **Validation:** on every POST, `CSRFMiddleware` drains the ASGI `receive` to buffer the body, parses the urlencoded body with `urllib.parse.parse_qs`, and compares the `csrf_token` value against `scope["session"]["csrf_token"]` with `secrets.compare_digest` (constant-time). Mismatch, missing field, empty field, wrong content-type, or any internal exception → HTTP `403` with body `{"error": "CSRF token missing or invalid"}` (fail-CLOSED). On success the same body bytes are replayed to the downstream handler via a wrapped `receive`. The middleware is pure ASGI rather than `BaseHTTPMiddleware` because the latter consumes the body on its own `Request` wrapper, leaving FastAPI's `Form(...)` dependency to see an empty stream.
- **Scope:** every `POST` request. GET / HEAD / OPTIONS / static-file requests bypass with a single method-check.
- **What it does not do:** no `Origin` / `Referer` header check, no double-submit cookie, no per-request rotation, no `SameSite` cookie-attribute change. The synchronizer token alone is sufficient on this single-origin lab.
- **Local lab use:** no configuration needed. Visit `/login` or `/signup` and the token is issued automatically; subsequent forms in the same session reuse it.

## Frontend-Backend Integration

- **Login**: `fetch()` POST → JSON response → client-side redirect
- **Signup**: Standard form POST → server redirect
- **Dashboard**: Server-side `str.replace('{{username}}', ...)` — no template engine; the value is HTML-escaped with `html.escape(..., quote=True)` before substitution (VULN-2 closed)
- **Theme**: Pure client-side. Each template's `<head>` runs a synchronous IIFE that reads `localStorage["theme"]` (or `prefers-color-scheme` as fallback) and sets `<html data-theme="light|dark">` before first paint. A `#theme-toggle` button in the shared header flips the attribute and persists the new value. No server round-trip, no session field, no backend coupling.
- **Password strength meter** (shipped in v1.0.1): Pure client-side. An inline `<script>` in `signup.html` listens to `input` on `#password`, scores the password against five criteria (length ≥ 8, lowercase, uppercase, digit, special) in JS, and updates a colored bar + live checklist beneath the password field. Advisory UX only — the backend's signup handler still accepts any non-empty password; nothing about the strength is sent to the server, stored in the session, or written to the database. The bar's colors are CSS custom properties shared between `:root` and `[data-theme="dark"]`, so toggling theme recolors the bar without re-running JS.
- **Profile / Change Password** (shipped in v1.0.2): `GET /profile` (session-gated, like `/welcome`) renders `profile.html` with the CSRF token and HTML-escaped `{{username}}`/`{{email}}` spliced in. `POST /profile/password` is a thin handler over `auth_service.change_password()`, which verifies the current password with bcrypt and runs a parameterized `UPDATE`. The form submits via `fetch()` with the body wrapped in `URLSearchParams` (so the CSRF middleware's urlencoded parser accepts it), returning JSON for inline feedback. The **new password is enforced against the same five-criteria strength policy the signup meter advertises** (length ≥ 8 plus lower/upper/digit/special) — checked in JS for inline feedback and re-checked server-side by `auth_service.password_meets_policy()` as the authoritative gate (weak passwords get a 400). Unlike signup, the strength-meter widget is **not** rendered on the profile form; only the rules apply. No schema change; the theme toggle stays frontend-only.

## Important Rules

- Always use parameterized queries in `auth_service.py` and `auth.py`. Never concatenate user-controlled input into SQL statements (VULN-1 is closed and must stay closed).
- Never remove the CSRF middleware in `backend/app/main.py` / `backend/app/core/csrf.py`, the hidden `csrf_token` field in the login/signup templates, or the `get_or_create_csrf_token` calls in the two GET handlers. VULN-8 is closed by a session-bound synchronizer-token pattern: a 256-bit token (`secrets.token_urlsafe(32)`) is stored in `request.session["csrf_token"]`, spliced into every form, and validated on every POST with `secrets.compare_digest`. The middleware, the hidden field, and the splice are permanent and must stay (stdlib-only, no third-party CSRF dependency).
- Never re-introduce a hardcoded session secret in `main.py`. VULN-4 is closed by sourcing `SECRET_KEY` from the environment with a strong `secrets.token_hex(32)` random fallback; the env-sourced secret is permanent and must stay (no constant key, no committed `.env`).
- Never remove the rate-limit middleware in `backend/app/main.py` / `backend/app/core/rate_limit.py`. VULN-7 is closed by an in-process per-IP sliding-window `RateLimitMiddleware` scoped to every POST (default 5 requests per 60 s, tunable via `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW_SECONDS` env vars). The middleware is permanent and must stay (stdlib-only, no third-party rate-limit dependency).
- Never re-introduce MD5 or an "MD5 fallback" in `security.py`. Bcrypt is permanent; legacy MD5 rows must fail closed, not authenticate.
- Never re-introduce unescaped `{{username}}` in the dashboard substitution. VULN-2 is closed by HTML-escaping the username with `html.escape(..., quote=True)` before substitution; the escaping is permanent and must stay (output encoding, not input filtering — the raw value still lives in the session/DB).
- Never re-introduce unescaped reflection in `/search`. VULN-3 is closed by HTML-escaping every attacker-controllable sink (`q`, the result-row `username`/`email`, and the exception text) with `html.escape(..., quote=True)` before splicing; the escaping is permanent and must stay (output encoding, not input filtering — the raw values still live in the URL/DB).
- Never re-add the `/download/db` route. VULN-6 is closed by removing the endpoint entirely; do not reintroduce it (authenticated or otherwise).
- The dark-mode feature is purely frontend (CSS + 4 files: `styles.css`, `login.html`, `signup.html`, `dashboard.html`). Don't push theme state into the backend, the session, or the database.
- The password strength meter on the signup form is purely frontend and advisory (CSS + `signup.html` only). Don't push strength state into the backend, the session, or the database, and don't block form submission on a weak password — the bcrypt-hashing server-side gate (VULN-5 closure) is what authenticates; the meter only informs the user.
- The User Profile Page (`/profile`, `/profile/password`) is session-gated and must stay so. `change_password` in `auth_service.py` must keep its parameterized `SELECT`/`UPDATE` (VULN-1) and bcrypt verify/hash (VULN-5); the change-password form must keep its hidden `csrf_token` field (VULN-8) and submit urlencoded via `URLSearchParams`. The new password must satisfy the five-criteria strength policy (length ≥ 8 plus lower/upper/digit/special), enforced server-side by `password_meets_policy()` and mirrored in the profile form's JS — keep both in sync; the profile form deliberately omits the strength-meter widget. Do not add a `created_at`/theme/profile column — the feature is intentionally schema-free, and dark mode stays frontend-only.

## Specification Hierarchy

1. `docs/PRD.md` — Product requirements
2. `docs/TDD.md` — Technical design
3. `.claude/specs/app-foundation.md` — Foundation implementation specification
4. `.claude/specs/app-foundation-plan.md` — Foundation implementation plan
5. `.claude/specs/dark-mode-toggle.md` + `.claude/specs/dark-mode-toggle-plan.md` — Dark-mode feature
6. `.claude/specs/bcrypt-password-hashing.md` + `.claude/specs/bcrypt-password-hashing-plan.md` — VULN-5 fix
7. `.claude/specs/session-hijacking-fix.md` + `.claude/specs/session-hijacking-fix-plan.md` — VULN-4 fix
8. `.claude/specs/stored-xss-fix.md` + `.claude/specs/stored-xss-fix-plan.md` — VULN-2 fix
9. `.claude/specs/reflected-xss-fix.md` + `.claude/specs/reflected-xss-fix-plan.md` — VULN-3 fix
10. `.claude/specs/no-rate-limiting-fix.md` + `.claude/specs/no-rate-limiting-fix-plan.md` — VULN-7 fix
11. `.claude/specs/csrf-fix.md` + `.claude/specs/csrf-fix-plan.md` — VULN-8 fix
12. `.claude/specs/pwd-str-meter.md` + `.claude/specs/pwd-str-meter-plan.md` — Password strength meter (signup, frontend-only, advisory; shipped in v1.0.1)
13. `.claude/specs/user-profile-page.md` + `.claude/specs/user-profile-page-plan.md` — User Profile Page (v1.0.2 feature)

Prompts that generated each spec/plan/implementation live under `docs/prompts/`.
