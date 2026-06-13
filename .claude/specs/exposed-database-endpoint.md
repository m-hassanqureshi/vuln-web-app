# Software Specification Document — Exposed Database Endpoint Removal

**Version:** 1.0.0
**Last Updated:** June 12, 2026
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md)
**Tracking Issue:** [#7 — Exposed Database endpoint](https://github.com/arifpucit/vuln-web-app/issues/7)

---

## 1. Overview / Purpose

This document specifies the remediation of the **Exposed Database endpoint** vulnerability (GitHub issue **#7**, OWASP **A01:2021 — Broken Access Control**). The route `GET /download/db` in `backend/app/api/routes/auth.py` serves the entire SQLite database file (`vulnerable_app.db`) over HTTP with **no authentication, authorization, or rate limit of any kind**. Any anonymous visitor can download the full `users` table — every username, email, and password hash — in a single unauthenticated request.

The README documents two acceptable remediations: *"removing the route or restricting it behind admin auth."* Gating the endpoint behind a regular session was rejected because **any** registered account would still be able to exfiltrate the whole database — only marginally better than no auth. A public application should not expose a "download the entire database" endpoint at all, so this fix **removes the route entirely**, eliminating the attack surface. After this change `GET /download/db` returns HTTP 404.

This fix is **surgical** and closes **issue #7 only**. The other intentional vulnerabilities remain exploitable for educational use, and the bcrypt password-hashing fix remains permanently in place.

---

## 2. Scope & Non-Goals

### 2.1 In Scope

- Delete the `download_db` route handler (the `@router.get("/download/db")` block) from `backend/app/api/routes/auth.py`.
- Remove the now-unused `FileResponse` symbol from the `fastapi.responses` import line in the same file.
- Remove the now-unused module-level `DB_PATH` constant in the same file.
- Leave every other route handler in `auth.py` byte-for-byte unchanged.

### 2.2 Out of Scope (Intentionally Unfixed)

This fix addresses only the Exposed Database endpoint. The following intentional vulnerabilities remain in place after this change and MUST NOT be remediated here:

| Vulnerability | OWASP | Status under this fix |
|---------------|-------|-----------------------|
| SQL Injection (`auth_service.py` string-concatenated queries) | A03:2021 | Intentionally unchanged |
| Stored XSS (`{{username}}` substitution in dashboard) | A03:2021 | Intentionally unchanged |
| Reflected XSS (`/search?q=` reflection) | A03:2021 | Intentionally unchanged |
| Session Hijacking (hardcoded `"super-secret-key-12345"`) | A07:2021 | Intentionally unchanged |
| Weak Password Storage | A02:2021 | Already CLOSED (bcrypt) — stays closed |
| **Exposed Database endpoint (`/download/db`)** | **A01:2021** | **CLOSED by this spec** |
| No Rate Limiting | A07:2021 | Intentionally unchanged |
| CSRF (no tokens) | A01:2021 | Intentionally unchanged |

### 2.3 Explicit Non-Goals

- This fix does **not** add authentication, an admin role, an `is_admin` column, rate limiting, or CSRF protection. It removes the endpoint; it does not gate it.
- This fix does **not** change the database schema, the on-disk database file, or any other route's behavior.
- This fix does **not** delete or relocate the `vulnerable_app.db` file. The file remains on disk for local inspection (`sqlite3 vulnerable_app.db`); it is simply no longer reachable over HTTP.

---

## 3. Affected Files

The fix MUST touch only the following file (plus the two specification documents). No other repository file may be created or modified.

| Path | Change Type | Purpose |
|------|-------------|---------|
| `backend/app/api/routes/auth.py` | Modified | Delete `download_db` handler; remove dead `FileResponse` import and `DB_PATH` constant |

Files that MUST NOT be modified by this change:

- `backend/app/main.py` (session middleware secret — preserves Session Hijacking).
- `backend/app/services/auth_service.py` (string-concatenated SQL — preserves SQL Injection).
- `backend/app/core/security.py` (bcrypt — stays closed).
- `backend/app/db/session.py` (schema and connection layer; its own separate `DB_PATH` is unrelated and untouched).
- Any HTML template under `frontend/templates/` or CSS under `frontend/static/` (preserves Stored XSS via `{{username}}`).
- The `/search` handler in `auth.py` (preserves Reflected XSS).
- `CLAUDE.md`, `docs/PRD.md`, `docs/TDD.md`, `.claude/specs/app-foundation.md`.
- `pyproject.toml` / `backend/pyproject.toml` / `uv.lock` (no dependency change).

---

## 4. Functional Requirements

### FR-01: Route Handler Removed

- The `download_db` function and its `@router.get("/download/db")` decorator MUST be removed from `auth.py`.
- After removal, the `/download/db` path MUST NOT be registered on the FastAPI router.

### FR-02: 404 Response

- A `GET` request to `/download/db` MUST return HTTP **404 Not Found** (FastAPI's default for an unregistered path).
- This applies to **every** caller — anonymous and authenticated alike. There is no privileged bypass, because the route no longer exists.

### FR-03: Dead Import Removed

- The `FileResponse` name MUST be removed from the `from fastapi.responses import ...` line, because the deleted handler was its only consumer.
- The remaining imports on that line (`HTMLResponse`, `RedirectResponse`) MUST be preserved.

### FR-04: Dead Constant Removed

- The module-level `DB_PATH = os.path.join(BASE_DIR, "vulnerable_app.db")` line in `auth.py` MUST be removed, because the deleted handler was its only consumer.
- `BASE_DIR` and `TEMPLATE_DIR` MUST be preserved — `TEMPLATE_DIR` is still used by `signup_page`, `login_page`, and `welcome_page`.

### FR-05: Other Routes Unchanged

- The handlers for `/`, `/signup` (GET + POST), `/login` (GET + POST), `/search`, `/welcome`, and `/logout` MUST remain byte-for-byte identical. Their behavior, response shapes, and status codes are unchanged.

---

## 5. Non-Functional Requirements

### NFR-01: Surgical Scope

- Exactly one vulnerability (issue #7) is closed. The diff MUST NOT touch session secrets, the SQL-injection construction, XSS escape logic, rate limiting, or CSRF posture.

### NFR-02: No Dead Code

- After the change, `auth.py` MUST contain no reference to `download_db`, `/download/db`, `FileResponse`, or `DB_PATH`. Removing the route cleanly (rather than leaving an unused import or constant) follows the precedent set by the bcrypt fix, which removed the now-dead `hashlib` import rather than leaving a misleading footprint.

### NFR-03: No Behavioral Regression

- Removing the import and constant MUST NOT affect any surviving route. The application MUST still import and boot without error.

### NFR-04: Data-at-Rest Untouched

- The `vulnerable_app.db` file on disk is not modified, moved, or deleted by this change. Only its HTTP exposure is removed.

---

## 6. Success Paths

### SP-01: Endpoint No Longer Exists

1. The application is running.
2. A client issues `GET /download/db`.
3. The server responds with HTTP 404 — the route is not registered.

### SP-02: Normal App Flow Still Works

1. A user registers via `/signup`, logs in via `/login`, and reaches `/welcome`.
2. All three flows behave exactly as before the change.
3. `/search`, `/logout`, and `/` (redirect to `/signup`) also behave as before.

---

## 7. Edge Cases

### EC-01: Authenticated User Also Gets 404

- A logged-in user (valid session) requests `/download/db`.
- They also receive HTTP 404 — the route was removed for everyone, not gated. There is no authenticated path to the database file over HTTP.

### EC-02: Database File Still On Disk

- `vulnerable_app.db` continues to exist in the project root and is still read/written by the app's normal queries.
- It is simply unreachable via any HTTP route. Local inspection via `sqlite3 vulnerable_app.db` is unaffected.

### EC-03: No Import-Time Regression

- Because `FileResponse` and `DB_PATH` were used **only** by the deleted handler, removing them leaves no dangling reference. The module imports cleanly and the server starts normally (NFR-03).

---

## 8. Acceptance Criteria

### AC-01: Route Returns 404

- `GET /download/db` returns HTTP 404 (it previously returned 200 with the SQLite file body).

### AC-02: No Residual References

- `auth.py` contains no occurrence of `download_db`, `download/db`, `FileResponse`, or `DB_PATH`.

### AC-03: Application Boots

- The app starts via `uv run backend/app/main.py` with no `ImportError`, `NameError`, or traceback.

### AC-04: Surviving Routes Work

- `GET /signup` and `GET /login` return HTTP 200; the signup → login → `/welcome` session flow still works; `/welcome` still redirects anonymous users to `/login`.

### AC-05: Other Vulnerabilities Preserved

- Reflected XSS: `/search?q=<script>alert(1)</script>` still reflects the payload unescaped.
- Stored XSS: a user registered with `<script>` in the username still triggers script execution on `/welcome`.
- Session Hijacking: the literal `"super-secret-key-12345"` is still present in `backend/app/main.py`.
- SQL Injection: `auth_service.py` still builds `WHERE username = '<...>'` by string concatenation.
- No Rate Limiting: no throttling middleware was added.
- CSRF: no CSRF token field was added to the login or signup form.

### AC-06: Only `auth.py` Modified

- `git status --porcelain` shows `backend/app/api/routes/auth.py` as the only modified source file (plus the two new spec documents under `.claude/specs/`).

---

## 9. Test Cases

| ID | Scenario | Precondition | Expected Result |
|----|----------|--------------|-----------------|
| TC-01 | Endpoint removed | App running | `GET /download/db` → HTTP 404 |
| TC-02 | Authenticated caller also blocked | Valid session cookie | `GET /download/db` → HTTP 404 |
| TC-03 | App boots cleanly | Fresh checkout | `uv run backend/app/main.py` starts with no traceback |
| TC-04 | Signup page works | App running | `GET /signup` → HTTP 200 |
| TC-05 | Login page works | App running | `GET /login` → HTTP 200 |
| TC-06 | Full auth flow works | Empty DB | signup → login returns success JSON; `/welcome` shows dashboard |
| TC-07 | No residual references | Repo checkout | `grep -n 'download/db\|download_db\|FileResponse\|DB_PATH' backend/app/api/routes/auth.py` returns no matches |
| TC-08 | Reflected XSS preserved | App running | `GET /search?q=<script>alert(1)</script>` reflects payload unescaped |
| TC-09 | Session secret preserved | Repo checkout | `grep 'super-secret-key-12345' backend/app/main.py` matches |
| TC-10 | SQL injection construction preserved | Repo checkout | `grep "WHERE username = '" backend/app/services/auth_service.py` matches |
| TC-11 | No CSRF tokens added | App running | `curl /login` and `curl /signup` HTML contain no `csrf_token` field |
| TC-12 | Affected-files audit | After change | `git status --porcelain` shows only `auth.py` modified plus the two new spec docs |

---

## 10. Verification Steps

Run from the repository root.

### 10.1 Start the Application

```bash
uv run backend/app/main.py
```

The server listens on `http://localhost:3001` with no import/boot error (AC-03, TC-03).

### 10.2 Confirm the Route Is Gone (AC-01, TC-01)

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:3001/download/db
```

Expected: `404`.

### 10.3 Confirm Surviving Routes (AC-04, TC-04/TC-05)

```bash
curl -s -o /dev/null -w 'signup=%{http_code}\n' http://localhost:3001/signup
curl -s -o /dev/null -w 'login=%{http_code}\n'  http://localhost:3001/login
```

Expected: `signup=200`, `login=200`.

### 10.4 Confirm Full Auth Flow (TC-06)

```bash
curl -s -c jar.txt -X POST http://localhost:3001/signup \
     --data-urlencode 'username=alice' --data-urlencode 'email=alice@test.com' --data-urlencode 'password=pass123'
curl -s -c jar.txt -b jar.txt -X POST http://localhost:3001/login \
     --data-urlencode 'username=alice' --data-urlencode 'password=pass123'
curl -s -b jar.txt -o /dev/null -w 'welcome=%{http_code}\n' http://localhost:3001/welcome
```

Expected: login returns `{"success": true, "redirect": "/welcome"}`; `welcome=200`.

### 10.5 Confirm No Residual References (AC-02, TC-07)

```bash
grep -n 'download/db\|download_db\|FileResponse\|DB_PATH' backend/app/api/routes/auth.py \
  || echo '(all references removed)'
```

Expected: `(all references removed)`.

### 10.6 Vulnerability Preservation Walkthrough (AC-05, TC-08–TC-11)

```bash
# Reflected XSS still fires (TC-08)
curl -s 'http://localhost:3001/search?q=<script>alert(1)</script>' | grep -o '<script>alert(1)</script>'

# Session secret unchanged (TC-09)
grep -n 'super-secret-key-12345' backend/app/main.py

# SQL injection construction unchanged (TC-10)
grep -n "WHERE username = '" backend/app/services/auth_service.py

# No CSRF tokens (TC-11)
curl -s http://localhost:3001/login  | grep -i csrf || echo '(no csrf field — preserved)'
curl -s http://localhost:3001/signup | grep -i csrf || echo '(no csrf field — preserved)'
```

### 10.7 Affected-Files Audit (AC-06, TC-12)

```bash
git status --porcelain
```

Expected: `backend/app/api/routes/auth.py` modified, plus the two new files
`.claude/specs/exposed-database-endpoint.md` and `.claude/specs/exposed-database-endpoint-plan.md`. No other path.

---

## 11. Operational Note

After this change, the database is no longer downloadable through the application. This is intentional and requires **no migration** — the schema and the on-disk file are untouched. Operators and students who need to inspect the database can still do so locally:

```bash
sqlite3 vulnerable_app.db "SELECT * FROM users;"
```

There is nothing to reset and no data to migrate; only the HTTP exposure has been removed.
