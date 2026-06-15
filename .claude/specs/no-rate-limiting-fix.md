# Software Specification Document — No Rate Limiting Fix (Per-IP POST Throttling Middleware)

**Version:** 1.0.0
**Last Updated:** June 15, 2026
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md)
**Tracking Issue:** [No Rate Limiting — credential endpoints accept unlimited POSTs per IP](https://github.com/arifpucit/vuln-web-app/issues)

---

## 1. Overview / Purpose

This document specifies the remediation of the **No Rate Limiting** vulnerability (OWASP **A07:2021 — Identification and Authentication Failures**, sub-control "lack of credential-attack countermeasures"). The application currently accepts unbounded request volume on every endpoint. The most dangerous consequence is on the two credential-bearing routes — `POST /login` and `POST /signup` — where an attacker can:

- **Brute-force passwords** against `POST /login` at the speed of the network (the only cost per attempt is one bcrypt verify, which is intentionally slow, but the server places no cap on attempts per IP). A determined attacker can mount a credential-stuffing campaign against every known username with no friction beyond bandwidth.
- **Enumerate / squat usernames** against `POST /signup` by issuing thousands of signup requests with guessed usernames and observing the `IntegrityError` ("Username already exists") versus 302-redirect distinction.
- **Exhaust resources** by triggering the (intentionally expensive) bcrypt verify on every `POST /login` attempt, effectively turning the brute-force surface into an asymmetric CPU-burning DoS.

The `CLAUDE.md` vulnerability map calls this VULN-7 ("No Rate Limit") and notes it is enforced **globally** — there is no throttling middleware, no per-IP counter, and no `time.sleep` anywhere in the request path.

This fix installs an **in-process, per-IP, sliding-window rate-limit middleware** scoped to **every POST endpoint** (in this codebase: `POST /login`, `POST /signup`, and any future POST route). The middleware is implemented with **Python standard-library only** (`collections.deque`, `asyncio.Lock`, `time.monotonic`) — no new third-party dependency, in line with the project's established stdlib-only pattern (`secrets`, `html`). When an IP exceeds the limit, the middleware returns **HTTP 429 Too Many Requests** with a `Retry-After` header, *before* the handler runs (so the bcrypt verify is never invoked on throttled requests). All other requests — GET routes (`/`, `/login`, `/signup`, `/welcome`, `/search`, `/logout`, every `/static/*` asset) and the request paths of routes that have not exceeded the limit — flow through unchanged.

The fix is **surgical** and closes the **No Rate Limiting** vulnerability **only**. The other intentional vulnerability (VULN-8, CSRF) remains exploitable for educational use, and every previously-closed fix (bcrypt password hashing, parameterized SQL, removed `/download/db` route, env-sourced session secret, escaped dashboard `{{username}}`, escaped `/search` reflection sinks) remains permanently in place.

---

## 2. Scope & Non-Goals

### 2.1 In Scope

- Create one new file, `backend/app/core/rate_limit.py`, containing a small, standard-library-only ASGI middleware class (`RateLimitMiddleware`) that maintains a per-IP sliding window of recent POST request timestamps and returns HTTP 429 when the window count exceeds a configured threshold.
- Wire that middleware into the app via `app.add_middleware(RateLimitMiddleware, ...)` inside `backend/app/main.py` **after** the existing `SessionMiddleware` registration, so it runs as an outer layer for the request and as an inner layer for the response (Starlette middleware ordering — see §FR-09).
- The middleware MUST throttle ONLY requests whose HTTP method is `POST`. Every non-POST request MUST pass through with zero overhead beyond a single method-check branch.
- The limit MUST be configurable via two environment variables with sensible defaults:
  - `RATE_LIMIT_MAX` (integer, default `5`) — maximum POST requests per window per IP.
  - `RATE_LIMIT_WINDOW_SECONDS` (integer, default `60`) — sliding-window length in seconds.
- The middleware MUST identify the client IP from `request.client.host` (the canonical Starlette attribute), with a defensive fallback to `"unknown"` if `request.client` is `None`.
- The middleware MUST be safe to use under uvicorn's default async event loop. Concurrency-safety is provided by a single `asyncio.Lock` guarding the per-IP `deque` map.
- The middleware MUST emit responses with status `429`, a JSON body of the shape `{"error": "Too many requests", "retry_after": <int seconds>}`, and a `Retry-After: <int seconds>` HTTP header.
- Update `CLAUDE.md` to:
  - Move VULN-7 from "Open" to "Closed" in the Vulnerability Map, with a short mechanism description.
  - Update the opening paragraph's count ("Seven of them … closed. The other 1 …").
  - Replace the "Never add rate limiting middleware (preserves VULN-7)" rule with a new "Never remove the rate-limit middleware" rule.
  - Add a "Rate Limiting After the Fix" subsection mirroring the existing "Session Secret After the Fix" subsection.
  - Append the new spec/plan pair to the Specification Hierarchy list.

### 2.2 Out of Scope (Intentionally Unfixed)

This fix addresses only the No Rate Limiting vulnerability. The following intentional vulnerability remains in place after this change and MUST NOT be remediated here:

| Vulnerability | OWASP | Status under this fix |
|---------------|-------|-----------------------|
| SQL Injection (`auth_service.py` queries) | A03:2021 | Already CLOSED (parameterized) — stays closed |
| Stored XSS (`{{username}}` substitution in dashboard) | A03:2021 | Already CLOSED (`html.escape`) — stays closed |
| Reflected XSS (`/search?q=` reflection) | A03:2021 | Already CLOSED (`html.escape`) — stays closed |
| Session Hijacking (hardcoded session secret) | A07:2021 | Already CLOSED (env-sourced secret) — stays closed |
| Weak Password Storage | A02:2021 | Already CLOSED (bcrypt) — stays closed |
| Exposed Database endpoint (`/download/db`) | A01:2021 | Already CLOSED (route removed) — stays closed |
| **No Rate Limiting (unbounded POST per IP)** | **A07:2021** | **CLOSED by this spec** |
| CSRF (no tokens) | A01:2021 | Intentionally unchanged |

### 2.3 Explicit Preservation Note

The remaining intentional vulnerability MUST remain unchanged:

- **VULN-8 (No CSRF):** no CSRF token field is added to any form; no CSRF middleware is registered. The rate-limit middleware does **not** inspect request bodies, validate origins, or check tokens — it only counts requests per (IP, method) pair.

The six already-closed fixes also MUST remain closed:

- **VULN-1 (SQL Injection):** `auth_service.py` and `/search` MUST keep their parameterized `?` queries.
- **VULN-2 (Stored XSS):** `welcome_page` MUST keep escaping the `{{username}}` substitution with `html.escape(..., quote=True)`.
- **VULN-3 (Reflected XSS):** `/search` MUST keep escaping `q`, both row columns, and the exception text.
- **VULN-4 (Session Hijacking):** `main.py` MUST keep sourcing `SECRET_KEY` from the environment with the `secrets.token_hex(32)` fallback.
- **VULN-5 (Weak Password Storage):** `core/security.py` MUST keep its bcrypt implementation (rounds ≥ 12) and the defensive `try/except` in `verify_password`.
- **VULN-6 (Exposed Database):** the `/download/db` route MUST NOT be re-introduced.

### 2.4 Explicit Non-Goals

- This fix does **not** add a distributed limiter (Redis, Memcached, or any external store). State lives in-process. A multi-worker deployment would see each worker enforce its own per-IP counter — acceptable for a local educational lab, called out in §11.
- This fix does **not** add CAPTCHA, account-lockout-after-N-failures, exponential backoff inside the handler, or any other authentication-flow change. The handler is not touched.
- This fix does **not** introduce a new dependency. `collections`, `asyncio`, `time`, and `os` are stdlib.
- This fix does **not** change the response shape of `POST /login` or `POST /signup` for non-throttled requests. A successful login still returns the existing JSON `{"success": True, "redirect": "/welcome"}`; a failed login still returns JSON 401; a successful signup still returns a 302; a duplicate-username signup still returns the existing HTML 400.
- This fix does **not** add per-route limits, per-username limits, or differential limits for `/login` vs. `/signup`. One global limit applies to all POSTs from a given IP — minimum complexity, maximum educational clarity.
- This fix does **not** persist counter state across restarts. The `deque` map is reset on every process start.
- This fix does **not** read `X-Forwarded-For` or any other proxy header. The lab application runs directly on `0.0.0.0:3001`; trusting forwarded headers without a known reverse-proxy contract would create a *new* bypass vulnerability where the attacker spoofs the source IP via a header.

---

## 3. Affected Files

The fix MUST touch only the following files. No other repository file may be created or modified.

| Path | Change Type | Purpose |
|------|-------------|---------|
| `backend/app/core/rate_limit.py` | **New** | `RateLimitMiddleware` class (stdlib only) and its supporting state |
| `backend/app/main.py` | Modified | Import the middleware and register it via `app.add_middleware(...)` |
| `CLAUDE.md` | Modified | Update vulnerability map, count, rules, add post-fix subsection, append to spec hierarchy |

Files that MUST NOT be modified by this change:

- `backend/app/api/routes/auth.py` (handlers stay byte-for-byte — VULN-1/VULN-2/VULN-3/VULN-6 closures and the unchanged login/signup/welcome/search/logout flows).
- `backend/app/services/auth_service.py` (parameterized queries + bcrypt verify — VULN-1 / VULN-5 stay closed).
- `backend/app/core/security.py` (bcrypt — VULN-5 stays closed).
- `backend/app/db/session.py` (schema and connection layer — untouched).
- `frontend/templates/dashboard.html`, `frontend/templates/login.html`, `frontend/templates/signup.html` (no template-side change — no CAPTCHA, no honeypot, no extra field).
- Any CSS under `frontend/static/`.
- `README.md`, `docs/PRD.md`, `docs/TDD.md`, `.claude/specs/app-foundation.md` and every other prior spec.
- `pyproject.toml` / `backend/pyproject.toml` / `uv.lock` (no dependency change — the middleware is stdlib-only).

---

## 4. Functional Requirements

### FR-01: Middleware Throttles Only POST Requests

- The middleware MUST check `scope["method"]` (or, equivalently, `request.method`) at the top of its `dispatch` method.
- If the method is **not** `POST`, the middleware MUST forward the call to `await call_next(request)` immediately, with no lock acquisition, no map lookup, and no time read. GET, OPTIONS, HEAD, PUT, DELETE, PATCH all bypass the limiter.

### FR-02: Per-IP Sliding Window

- The middleware MUST maintain an in-memory mapping `dict[str, deque[float]]` from client IP (string) to a deque of `time.monotonic()` timestamps of recent POST requests from that IP.
- On each POST request, the middleware MUST:
  1. Compute `now = time.monotonic()`.
  2. Compute `cutoff = now - window_seconds`.
  3. Pop timestamps from the **left** of the IP's deque while the leftmost timestamp is `< cutoff` (sliding-window pruning).
  4. Compare the deque length to `max_requests`. If `len(deque) >= max_requests`, the request is throttled (see FR-04).
  5. Otherwise, append `now` to the right of the deque and forward to `await call_next(request)`.

### FR-03: Client IP Extraction

- The middleware MUST identify the client by `request.client.host` (Starlette / Uvicorn populate this from the TCP source address).
- If `request.client is None` (a possibility under custom ASGI scopes or some testing harnesses), the middleware MUST fall back to the literal string `"unknown"` and bucket all such requests together. This MUST NOT raise.

### FR-04: Throttled Response Shape

- When a POST request is throttled, the middleware MUST return a `starlette.responses.JSONResponse` with:
  - `status_code = 429`
  - `content = {"error": "Too many requests", "retry_after": <retry_after_seconds>}`
  - A `Retry-After: <retry_after_seconds>` HTTP header.
- `retry_after_seconds` MUST be computed as `max(1, int(window_seconds - (now - oldest_in_window)))` — i.e., the integer number of seconds until the oldest in-window request falls off the left of the window. The `max(1, …)` floor guarantees the header is at least `1` (per RFC 9110, `Retry-After` SHOULD be a positive integer in seconds-format).
- The downstream handler (`auth_service.login()` / `auth_service.signup()`) MUST NOT be invoked for a throttled request — no bcrypt verify, no DB call, no session write.

### FR-05: Concurrency Safety

- All reads and writes to the per-IP map MUST be guarded by a single `asyncio.Lock` (`self._lock`) held only for the duration of the prune / read-length / append window. The lock MUST NOT be held across `await call_next(request)`.
- Uvicorn's default config runs a single asyncio event loop per worker; a single asyncio.Lock is sufficient to prevent torn reads/writes under interleaving coroutines on that loop.

### FR-06: Configuration via Environment

- The middleware constructor MUST accept two integer keyword arguments: `max_requests` and `window_seconds`.
- `backend/app/main.py` MUST read defaults from the environment with the standard library only:
  ```python
  RATE_LIMIT_MAX = int(os.environ.get("RATE_LIMIT_MAX", "5"))
  RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("RATE_LIMIT_WINDOW_SECONDS", "60"))
  ```
- The defaults — **5 POSTs per 60 seconds per IP** — are conservative enough to make brute-forcing and signup-enumeration impractical, while staying loose enough that a legitimate user who mistypes their password three or four times in a row is not locked out.
- Invalid env values (non-integer strings) MUST cause the app to fail to start with the standard `ValueError` raised by `int(...)` — fail-loud is correct for a misconfigured limiter; silently falling back to a default would hide the misconfiguration.

### FR-07: Method Branch Comes First

- The method check (FR-01) MUST be the very first statement in `dispatch`. No timestamp read, no lock acquisition, no IP read happens for non-POST requests. This guarantees that GET routes (`/`, `/login`, `/signup` HTML page loads, `/welcome`, `/search`, `/logout`, `/static/*`) and HEAD/OPTIONS pre-flights pay **at most one Python attribute access + one string comparison** of overhead.

### FR-08: Middleware Does Not Modify Successful Responses

- For non-throttled requests, the middleware MUST return the exact response object produced by `await call_next(request)` with no header rewrites, status changes, or body inspection. In particular, the `Set-Cookie` headers written by `SessionMiddleware` MUST flow through verbatim.

### FR-09: Middleware Ordering in `main.py`

- The middleware stack in `main.py` MUST be:
  ```python
  app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
  app.add_middleware(RateLimitMiddleware, max_requests=RATE_LIMIT_MAX, window_seconds=RATE_LIMIT_WINDOW_SECONDS)
  ```
- Starlette's middleware ordering is "the **last** `add_middleware` call wraps the innermost." With this ordering, `RateLimitMiddleware` runs **outside** `SessionMiddleware` on the request path (it sees the request first and short-circuits with 429 before any session decoding occurs) and **inside** it on the response path (its 429 JSONResponse is wrapped by `SessionMiddleware`'s cookie-writing pass — which is a no-op for a fresh response with no session writes). This ordering avoids spending CPU on cookie verification for throttled requests.

### FR-10: Handler Code Untouched

- `backend/app/api/routes/auth.py`, `backend/app/services/auth_service.py`, and every other file under `backend/app/` (other than the new `core/rate_limit.py` and the edited `main.py`) MUST remain byte-for-byte unchanged. The rate-limit decision is **transport-layer**, not handler-layer.

### FR-11: Standard-Library Only

- The middleware MUST use only the Python standard library (`collections.deque`, `asyncio.Lock`, `time.monotonic`, `os`) plus the existing transitive `starlette` API (`BaseHTTPMiddleware`, `Request`, `JSONResponse`). No third-party dependency (`slowapi`, `limits`, `fastapi-limiter`, `redis`, etc.) is added.

---

## 5. Non-Functional Requirements

### NFR-01: Effectiveness Against Brute-Force

- After the fix, an attacker scripting `POST /login` from a single IP can produce at most `RATE_LIMIT_MAX` (default `5`) attempts per `RATE_LIMIT_WINDOW_SECONDS` (default `60`). All further attempts within the window return HTTP `429` without invoking `verify_password`.
- At the default settings, an attacker can submit at most **300 login attempts per hour per IP** — versus the pre-fix rate of "as fast as the network allows," which is comfortably four to five orders of magnitude faster.

### NFR-02: Surgical Scope

- Exactly one vulnerability (No Rate Limiting) is closed. The diff MUST NOT touch session secrets, the SQL construction, any XSS escape, the bcrypt verification, the `/download/db` posture, or the CSRF posture.

### NFR-03: API Stability for Non-Throttled Requests

- For any `POST /login` or `POST /signup` that does NOT exceed the limit, the public response is byte-for-byte unchanged: same status, same body, same `Set-Cookie` headers.
- GET routes are entirely unaffected.

### NFR-04: Per-Request Overhead

- For a non-POST request, the middleware adds one method comparison (a sub-microsecond Python operation).
- For a POST request that is not throttled, the middleware adds: one IP read, one dict lookup, a deque-left-pop loop bounded by the window length, one length comparison, one `time.monotonic()` call, and one append — all in O(1) amortized per request under steady traffic, plus the cost of acquiring an uncontested `asyncio.Lock`. At the scale of a single-host educational lab this is negligible.

### NFR-05: Memory Bound

- The per-IP map grows at most by one deque per distinct client IP that has issued a POST request. Each deque holds at most `RATE_LIMIT_MAX` recent timestamps (since the prune step in FR-02 step 3 runs *before* the length check). At default settings, each entry costs ≤ 5 × 8 bytes of float storage + container overhead.
- A long-running process serving many distinct IPs accumulates entries indefinitely. For the educational lab this is acceptable. The implementer MAY (but is not required to) add a periodic cleanup pass that drops entries whose deque is empty after pruning — see Plan §1.6 for the optional cleanup hook. The spec mandates **correctness**, not unbounded-IP defense.

### NFR-06: No Information Leakage

- The throttled response body MUST NOT contain the IP address, the user agent, the request path, or any per-user identifier. The `{"error": "Too many requests", "retry_after": N}` body is identical across all throttled IPs and all paths.
- HTTP status `429`, `Retry-After`, and a generic JSON body are the only signals exposed.

### NFR-07: Fail-Open on Internal Error

- An unexpected exception inside the middleware's own bookkeeping (e.g., a corrupted deque) MUST NOT propagate out and crash the request. If the middleware's `dispatch` raises, the request MUST proceed to `await call_next(request)` (fail-open). Rationale: a broken limiter taking down the application is worse than a missing limiter for a few seconds. The middleware logs nothing to avoid noise (the lab application does not configure structured logging).
- This fail-open semantic applies ONLY to internal middleware errors. A normal "limit exceeded" decision is **fail-closed** (return 429); it is not an internal error.

### NFR-08: Determinism Across Restarts

- Counter state is *intentionally* not persisted. Restarting the process resets all counters to zero. The educational lesson is that in-process limiters are a baseline, not the entire defense — a determined attacker rebooting the box would, in production, also defeat the limiter, which is why production limiters use shared state (Redis, etc.). This trade-off is documented in §11 (Operational Note).

### NFR-09: Standard-Library Only / Zero Dependency Delta

- No entry is added to `pyproject.toml`, `backend/pyproject.toml`, or `uv.lock`. Every imported module is part of CPython's standard library or already transitively present via Starlette/FastAPI.

### NFR-10: Concurrency Correctness

- Under uvicorn's default single-event-loop worker, the `asyncio.Lock` MUST guarantee that no two coroutines simultaneously prune, append to, or read the length of the same per-IP deque. The lock MUST be released before `await call_next(request)` so a long-running handler does not block other IPs.

---

## 6. Success Paths

### SP-01: Legitimate User Under the Limit

1. A user issues `POST /login` with `username=alice`, `password=pass123`.
2. The middleware sees `method == "POST"`, looks up `127.0.0.1`'s deque (empty), prunes (no-op), notes length `0 < 5`, appends `now`, and calls the handler.
3. `auth_service.login()` runs `verify_password` and returns its JSON success or 401 unchanged.
4. The response flows back through `SessionMiddleware` (writing `Set-Cookie` on success) and out. No 429.

### SP-02: Mistyped Password A Few Times

1. The same user mistypes the password 4 times in a row (4 × `POST /login` → 401), then types it correctly.
2. The fifth POST is the 5th in the window — `len(deque) == 4 < 5`, so the handler runs, returns 200 JSON success. **The legitimate user is not locked out.**
3. (Edge case: if the user mistypes a 5th time before any timestamp falls off, the 6th POST would be throttled. The 60-second window means after one minute of silence the counter is empty again — see SP-04.)

### SP-03: Brute-Force Attempt Throttled

1. An attacker scripts `POST /login` from `203.0.113.7` against `username=admin`, sending requests as fast as the network allows.
2. The first 5 requests pass through, each consulting `verify_password` (which returns False each time, with the standard 401 response).
3. The 6th request arrives within the same 60-second window. The middleware prunes (no entries fall off), measures `len(deque) == 5`, computes `retry_after = max(1, int(60 - (now - oldest)))`, and returns HTTP 429 with `Retry-After` header. **The bcrypt verify is never invoked.**
4. Every subsequent request in the window returns 429. After 60 seconds of silence the window empties and the attacker can resume — but at a permanently capped rate.

### SP-04: Window Slides Open Again

1. An attacker hits 5 POSTs at times `t, t+1, t+2, t+3, t+4`. The 6th at `t+5` is throttled with `retry_after` ≈ `55`.
2. The attacker waits 60 seconds. At `t+61`, the leftmost timestamp (`t`) is older than `now - 60` and is pruned; `len(deque) == 4 < 5`; the request passes.

### SP-05: GET Routes Untouched

1. A user loads `GET /login`, `GET /signup`, `GET /welcome`, `GET /search?q=alice`, `GET /static/css/styles.css`, and `GET /logout` in rapid succession (hundreds of requests).
2. The middleware sees `method != "POST"` on every request and returns from `dispatch` immediately. No 429. No counter is ever consulted.

### SP-06: Signup-Enumeration Attempt Throttled

1. An attacker hits `POST /signup` six times with different guessed usernames, hoping to map the `IntegrityError` ("Username already exists") vs 302 distinction.
2. The first 5 are answered by `auth_service.signup()` (some 302, some 400 — both legitimate handler responses).
3. The 6th is throttled at 429. The DB is never touched on the throttled call.

### SP-07: Two IPs Share the Server

1. IPs `198.51.100.10` and `203.0.113.20` each hit `POST /login` simultaneously.
2. Each IP has its own deque. Neither IP's counter affects the other. Both can independently submit up to 5 POSTs per 60-second window before being throttled.

---

## 7. Edge Cases

### EC-01: Missing `request.client`

- Under certain test harnesses (or a misconfigured ASGI wrapper) `request.client` is `None`.
- The middleware MUST fall back to the IP string `"unknown"` and continue. All such requests share one bucket, which is acceptable for the lab.

### EC-02: Burst at Exactly the Boundary

- Five requests arrive at `t = 0.0` (effectively simultaneous). All five succeed because the deque length transitions from 0 → 1 → 2 → 3 → 4 across the 5 successful append operations, and each append happens after a length check that sees a number strictly less than 5.
- The 6th request, even at the same `t = 0.0`, sees `len == 5` and is throttled with `retry_after = max(1, int(60 - 0)) = 60`.

### EC-03: Clock Source

- The middleware MUST use `time.monotonic()`, not `time.time()`. `monotonic` is immune to system clock adjustments (NTP slew, manual `date -s`), so a wall-clock jump cannot artificially clear counters or freeze the window.

### EC-04: Window Pruning Under Burst

- If 100 timestamps were somehow injected into a deque before pruning ran (impossible under normal flow, but defensively), the prune loop `while deque and deque[0] < cutoff: deque.popleft()` will drain stale entries in O(k) where k is the number of stale entries — linear in deque length, bounded by `RATE_LIMIT_MAX` under normal operation.

### EC-05: Misconfigured `RATE_LIMIT_MAX = 0`

- `RATE_LIMIT_MAX = 0` means every POST is throttled. The middleware MUST honor this (no special-case for zero). The educational lab operator who sets this is explicitly disabling all POSTs and the resulting 429-on-everything behavior is correct.
- This is **not** the default. The default is `5`.

### EC-06: Misconfigured `RATE_LIMIT_WINDOW_SECONDS = 0`

- A window of zero seconds means no timestamp is ever in-window: the prune step removes every entry on every request, the length check sees `0 < max`, the append happens, and effectively no rate limiting occurs. This is a configuration error but MUST NOT crash the middleware. The educational lab operator who sets this is opting out, and the only visible effect is "the middleware is a no-op."

### EC-07: Negative or Non-Integer Env Values

- `RATE_LIMIT_MAX="abc"` causes `int(...)` to raise `ValueError` at app import time. The app fails to start. This is the spec-mandated fail-loud behavior for misconfiguration (FR-06).
- A negative integer (e.g., `RATE_LIMIT_MAX=-1`) is accepted by `int(...)`. The length check `len(deque) >= -1` is always true once any append happens, so every POST after the first is throttled. Again, a misconfiguration; correct behavior is "the limit is honored verbatim."

### EC-08: Two Browsers Behind One NAT

- Two users behind the same NAT gateway present the same `request.client.host`. They share one bucket. Five total POSTs across both browsers in 60 seconds trigger 429 for either user. This is an acknowledged trade-off of in-process IP-based limiting and is acceptable for the educational lab.

### EC-09: Throttled Request Followed by GET

- After a `POST /login` returns 429, the same client immediately issues `GET /login` to reload the form. The GET is unaffected by the limiter (FR-01) and returns the standard HTML page. The user can see they were rate-limited (via the 429 fetch response) and try again later.

### EC-10: Successful Login Counts the Same as Failed Login

- The middleware does not inspect the response status — it counts a POST whether the handler returns 200, 302, 400, 401, or 500. Rationale: a flood of *successful* logins from one IP would also be abusive (session-table growth, log noise) and the limit catches that uniformly. The first 5 successful logins go through; the 6th in the window is throttled.

### EC-11: `Retry-After` Floor

- The computed `retry_after_seconds` MUST be at least `1`. If the math `int(window_seconds - (now - oldest))` rounds to `0` (e.g., the window is about to slide open in 200ms), the floor of `1` keeps `Retry-After: 1` valid per RFC 9110.

### EC-12: Handler Raises After Append

- The append happens **before** `await call_next(request)`. If the handler raises a 500, the timestamp stays in the deque — the request "counted" against the IP's quota. This is intentional: an attacker should not be able to evade the limiter by triggering handler errors on purpose.

---

## 8. Acceptance Criteria

### AC-01: New Middleware File Exists

- `backend/app/core/rate_limit.py` exists and contains a class `RateLimitMiddleware` derived from `starlette.middleware.base.BaseHTTPMiddleware`.

### AC-02: Middleware Stdlib-Only

- The only `import` statements in `backend/app/core/rate_limit.py` are from `collections`, `asyncio`, `time`, `starlette.middleware.base`, `starlette.requests`, and `starlette.responses`. No third-party module is imported.

### AC-03: Method Check Comes First

- The first executable statement in `RateLimitMiddleware.dispatch` is a check that returns `await call_next(request)` if `request.method != "POST"`.

### AC-04: Throttled POST Returns 429

- `curl -X POST` issued 6 times against `/login` from the same source within 60 seconds: the 6th response has HTTP status `429`.

### AC-05: 429 Response Includes `Retry-After` Header

- The throttled response includes a `Retry-After` header whose integer value is between `1` and `RATE_LIMIT_WINDOW_SECONDS` inclusive.

### AC-06: 429 Response Body Shape

- The throttled response body is JSON of the form `{"error": "Too many requests", "retry_after": <int>}`. No IP address, user agent, or path is leaked.

### AC-07: Non-Throttled POST Untouched

- A single `POST /login` with valid credentials returns the existing JSON success body byte-for-byte and includes the existing `Set-Cookie: session=...` header. The middleware does not interpose.

### AC-08: GET Routes Unaffected by the Limit

- 50 consecutive `GET /login` requests from one IP all return HTTP `200`. No `429` appears in the output even when far above `RATE_LIMIT_MAX`.

### AC-09: Middleware Registered in `main.py`

- `backend/app/main.py` contains `app.add_middleware(RateLimitMiddleware, max_requests=RATE_LIMIT_MAX, window_seconds=RATE_LIMIT_WINDOW_SECONDS)` after the existing `SessionMiddleware` registration.

### AC-10: Environment Variables Honored

- Setting `RATE_LIMIT_MAX=2 RATE_LIMIT_WINDOW_SECONDS=5` and restarting the app: the 3rd POST within 5 seconds returns 429; after a 6-second wait the next POST returns the normal handler response.

### AC-11: Window Sliding

- After 6 POSTs trigger a 429, sleeping `RATE_LIMIT_WINDOW_SECONDS + 1` seconds and issuing a 7th POST returns the normal handler response.

### AC-12: Handler Code Untouched

- `backend/app/api/routes/auth.py`, `backend/app/services/auth_service.py`, `backend/app/core/security.py`, `backend/app/db/session.py`, every file under `frontend/`, `pyproject.toml`, `backend/pyproject.toml`, and `uv.lock` are byte-for-byte unchanged by this fix.

### AC-13: Other Vulnerabilities Preserved

- VULN-1 (SQL Injection): `auth_service.py` and `/search` still use parameterized queries — closed.
- VULN-2 (Stored XSS): `welcome_page` still calls `html.escape(username, quote=True)` — closed.
- VULN-3 (Reflected XSS): `/search` still escapes `q`, both row columns, and exception text — closed.
- VULN-4 (Session Hijacking): `main.py` still sources `SECRET_KEY` from the environment with the `secrets.token_hex(32)` fallback — closed.
- VULN-5 (Weak Password): `core/security.py` still uses bcrypt with rounds ≥ 12 — closed.
- VULN-6 (Exposed DB): `GET /download/db` still returns HTTP 404 — closed.
- VULN-8 (No CSRF): no CSRF token field was added to the login or signup form; no CSRF middleware was registered.

### AC-14: CLAUDE.md Updated

- The Vulnerability Map row for "No Rate Limit" reads "Closed" with a one-line mechanism description.
- The opening paragraph reads "Seven of them … closed. The other 1 remain intentionally exploitable …".
- The "Important Rules" section replaces "Never add rate limiting middleware (preserves VULN-7)" with "Never remove the rate-limit middleware in `main.py` / `core/rate_limit.py` (VULN-7 stays closed)".
- A new "Rate Limiting After the Fix" subsection appears between "Session Secret After the Fix" and "Frontend-Backend Integration".
- The Specification Hierarchy list appends item 10: `.claude/specs/no-rate-limiting-fix.md` + `.claude/specs/no-rate-limiting-fix-plan.md`.

### AC-15: No New Dependency

- `pyproject.toml`, `backend/pyproject.toml`, and `uv.lock` are unchanged. `git status --porcelain` shows no entry for any of those files.

### AC-16: Application Boots

- The app starts via `uv run backend/app/main.py` with no `ImportError`, `NameError`, or traceback.

---

## 9. Test Cases

| ID | Scenario | Precondition | Expected Result |
|----|----------|--------------|-----------------|
| TC-01 | Middleware file exists with the right class | Repo checkout | `grep -n 'class RateLimitMiddleware' backend/app/core/rate_limit.py` matches |
| TC-02 | Middleware uses stdlib only | Repo checkout | `grep -nE '^(import|from)' backend/app/core/rate_limit.py` shows only `collections`, `asyncio`, `time`, `starlette.middleware.base`, `starlette.requests`, `starlette.responses` |
| TC-03 | Middleware registered in `main.py` | Repo checkout | `grep -n 'RateLimitMiddleware' backend/app/main.py` matches and appears after `SessionMiddleware` |
| TC-04 | Method-first short-circuit | Repo checkout | First non-trivial line of `dispatch` checks `request.method != "POST"` |
| TC-05 | Single benign POST passes | App running, default config | `POST /login` (valid creds) → HTTP 200, normal JSON body, `Set-Cookie` present |
| TC-06 | 6th POST in 60s window throttled | App running, default config | The 6th `POST /login` from the same IP within 60 s returns HTTP 429 |
| TC-07 | Throttled response has `Retry-After` | TC-06 precondition | The 429 response carries a `Retry-After` header with an integer value in `[1, 60]` |
| TC-08 | Throttled response body shape | TC-06 precondition | The 429 body is JSON `{"error": "Too many requests", "retry_after": <int>}` and contains no IP, no path, no user agent |
| TC-09 | GET routes unthrottled | App running | 50 sequential `GET /login` requests from one IP all return HTTP 200 |
| TC-10 | `POST /signup` throttled too | App running | 6 sequential `POST /signup` requests from one IP within 60 s — the 6th returns 429 |
| TC-11 | Window slides open | App running | After 429, sleeping `RATE_LIMIT_WINDOW_SECONDS + 1` seconds, the next POST returns the handler's normal response |
| TC-12 | Per-IP isolation | App running | IP-A's counter does not affect IP-B's quota (use two `--interface` curls or two TCP source ports — see Verification §10.7) |
| TC-13 | Env override honored | App started with `RATE_LIMIT_MAX=2 RATE_LIMIT_WINDOW_SECONDS=5` | 3rd POST within 5 s → 429; after 6 s wait, next POST → handler response |
| TC-14 | Handler code untouched | Repo checkout | `git diff --stat main..HEAD -- backend/app/api/routes/auth.py backend/app/services/auth_service.py backend/app/core/security.py backend/app/db/session.py` reports zero changes |
| TC-15 | SQL injection stays closed (VULN-1) | Repo checkout | `grep -n 'WHERE username = ?' backend/app/services/auth_service.py` matches; `grep -n 'LIKE ?' backend/app/api/routes/auth.py` matches |
| TC-16 | Stored XSS stays closed (VULN-2) | Repo checkout | `grep -n 'html.escape(username, quote=True)' backend/app/api/routes/auth.py` matches |
| TC-17 | Reflected XSS stays closed (VULN-3) | Repo checkout | `grep -cn 'html.escape(' backend/app/api/routes/auth.py` reports `5` |
| TC-18 | Session secret stays env-sourced (VULN-4) | Repo checkout | `grep -n 'os.environ.get("SECRET_KEY"' backend/app/main.py` matches; `grep 'super-secret-key-12345' backend/app/main.py` returns no matches |
| TC-19 | Bcrypt stays in use (VULN-5) | Repo checkout | `grep -n 'bcrypt' backend/app/core/security.py` matches |
| TC-20 | `/download/db` stays removed (VULN-6) | App running | `GET /download/db` → HTTP 404 |
| TC-21 | No CSRF tokens added (VULN-8) | App running | `curl /login` and `curl /signup` HTML contain no `csrf_token` field |
| TC-22 | No new dependency | Repo checkout | `git status --porcelain` shows no entry for `pyproject.toml`, `backend/pyproject.toml`, or `uv.lock` |
| TC-23 | Application boots cleanly | Fresh checkout | `uv run backend/app/main.py` starts with no traceback |
| TC-24 | Affected-files audit | After change | `git status --porcelain` shows only the three declared files plus the two new spec docs |

---

## 10. Verification Steps

Run from the repository root.

### 10.1 Confirm Middleware File and Class (AC-01, TC-01)

```bash
grep -n 'class RateLimitMiddleware' backend/app/core/rate_limit.py
```

Expected: a single matching line.

### 10.2 Confirm Standard-Library-Only Imports (AC-02, TC-02)

```bash
grep -nE '^(import|from)' backend/app/core/rate_limit.py
```

Expected: lines reference only `collections`, `asyncio`, `time`, `starlette.middleware.base`, `starlette.requests`, `starlette.responses`. No `slowapi`, no `limits`, no `redis`, no `fastapi_limiter`.

### 10.3 Confirm Middleware Registered in `main.py` (AC-09, TC-03)

```bash
grep -n 'RateLimitMiddleware' backend/app/main.py
```

Expected: at least one match in the `from app.core.rate_limit import RateLimitMiddleware` line and one in the `app.add_middleware(RateLimitMiddleware, ...)` line. Manual inspection confirms the `add_middleware(RateLimitMiddleware, ...)` line appears **after** the `add_middleware(SessionMiddleware, ...)` line.

### 10.4 Start the Application (AC-16, TC-23)

```bash
uv run backend/app/main.py
```

The server listens on `http://localhost:3001` with no import/boot error.

### 10.5 Benign POST Passes (AC-07, TC-05)

```bash
curl -s -c jar.txt -X POST http://localhost:3001/signup \
     --data-urlencode 'username=alice' \
     --data-urlencode 'email=alice@test.com' \
     --data-urlencode 'password=pass123'

curl -s -i -c jar.txt -b jar.txt -X POST http://localhost:3001/login \
     --data-urlencode 'username=alice' \
     --data-urlencode 'password=pass123' | head -20
```

Expected: the login response carries HTTP `200`, a JSON body `{"success": true, "redirect": "/welcome"}`, and a `Set-Cookie: session=...` header. No 429.

### 10.6 6th POST Throttled With Default Config (AC-04, AC-05, AC-06, TC-06–TC-08)

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

Expected: requests 1–5 print `HTTP=401`. Request 6 prints `HTTP=429`. `cat body.6` shows `{"error":"Too many requests","retry_after":<int>}`. `grep retry-after` finds `Retry-After: <int>` with `1 ≤ int ≤ 60`.

### 10.7 GET Routes Unaffected (AC-08, TC-09)

```bash
for i in {1..50}; do
  curl -s -o /dev/null -w '%{http_code}\n' http://localhost:3001/login
done | sort -u
```

Expected: only `200` in the deduplicated output. No `429`.

### 10.8 `POST /signup` Also Throttled (TC-10)

```bash
for i in {1..6}; do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:3001/signup \
       --data-urlencode "username=ghost$i" --data-urlencode "email=g$i@x" \
       --data-urlencode 'password=p'
done
```

Expected: a mix of `302` / `400` for the first five (depending on whether the username collides) and `429` for the sixth.

### 10.9 Window Slides Open (AC-11, TC-11)

```bash
# After §10.6 fires a 429, wait for the window to fully roll off
sleep 65
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:3001/login \
     --data-urlencode 'username=ghost' --data-urlencode 'password=wrong'
```

Expected: `401` (the handler ran again — the limiter let it through).

### 10.10 Env Override Honored (AC-10, TC-13)

```bash
# Stop the previous instance, then:
RATE_LIMIT_MAX=2 RATE_LIMIT_WINDOW_SECONDS=5 uv run backend/app/main.py &
sleep 1
for i in {1..3}; do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:3001/login \
       --data-urlencode 'username=ghost' --data-urlencode 'password=wrong'
done
echo '--- waiting 6 s for window roll-off ---'
sleep 6
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:3001/login \
     --data-urlencode 'username=ghost' --data-urlencode 'password=wrong'
kill %1 2>/dev/null
```

Expected: the first two POSTs print `401`, the 3rd prints `429`, and after the 6-second wait the 4th prints `401` again.

### 10.11 Vulnerability Preservation Walkthrough (AC-13, TC-15–TC-21)

```bash
# Restart with default config for the rest of these checks
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
# Expected: 404.

# VULN-8 No CSRF tokens (TC-21)
curl -s http://localhost:3001/login  | grep -i csrf || echo '(no csrf field — preserved)'
curl -s http://localhost:3001/signup | grep -i csrf || echo '(no csrf field — preserved)'

kill %1 2>/dev/null
```

### 10.12 No New Dependency (AC-15, TC-22)

```bash
git status --porcelain | grep -E '(pyproject\.toml|uv\.lock)' \
  || echo '(no dependency files modified — preserved)'
```

Expected: prints the fallback.

### 10.13 Affected-Files Audit (TC-24)

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

---

## 11. Operational Note

This fix requires **no database migration and no data changes**.

- Existing user accounts continue to work without modification — they can still log in, sign up, search, and visit the dashboard.
- The `vulnerable_app.db` file is not modified, moved, or deleted.
- The `users` table schema is unchanged.
- The session cookie format is unchanged.

After deploying this change:

- Every POST endpoint enforces a **per-IP sliding-window limit** (default: **5 POSTs per 60-second window**). Throttled requests receive HTTP `429` with a `Retry-After` header and never reach the application handler — so the (intentionally slow) bcrypt verify and the SQLite write are never executed on a throttled call.
- GET routes (page loads, search, static assets) are entirely unaffected.
- Operators can tune the limit by setting `RATE_LIMIT_MAX` and/or `RATE_LIMIT_WINDOW_SECONDS` in the environment before launch. Invalid env values are fail-loud: the app refuses to start.

**Trade-offs intentionally accepted for the lab:**

- **In-process state.** Counters live in a single Python process and are reset on every restart. A multi-worker deployment would see each worker enforce an independent quota. For the educational lab — which runs one uvicorn worker on `localhost` — this is sufficient. Production hardening would back the counter with Redis (out of scope).
- **IP-only identity.** Two users behind one NAT share one bucket. CAPTCHA, device fingerprinting, and per-user back-off are deliberately not added.
- **No proxy-header trust.** The middleware uses `request.client.host` directly, never `X-Forwarded-For`. If you front the app with a reverse proxy in a real deployment, configure that proxy to populate `request.client.host` correctly (e.g., uvicorn's `--proxy-headers` flag with `--forwarded-allow-ips=<trusted-proxy-IP>`) rather than trusting headers blindly — header trust without a known-trusted-proxy contract is its own bypass vulnerability.
- **Combined with the prior fixes**, the realistic credential-attack surface is now sharply reduced: bcrypt (VULN-5) makes per-attempt verification expensive; parameterized SQL (VULN-1) blocks injection; env-sourced session secrets (VULN-4) prevent forgery; output encoding (VULN-2/VULN-3) blocks reflection-based exfiltration; and this fix (VULN-7) caps the volume of attempts per IP. The only remaining intentional vulnerability (VULN-8, CSRF) is left exploitable for further exercises.
