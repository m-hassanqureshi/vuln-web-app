# Implementation Plan — Exposed Database Endpoint Removal

**Version:** 1.0.0
**Last Updated:** June 12, 2026
**Parent Spec:** [exposed-database-endpoint.md](./exposed-database-endpoint.md)
**Foundation Spec:** [app-foundation.md](./app-foundation.md)
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md)
**Tracking Issue:** [#7 — Exposed Database endpoint](https://github.com/arifpucit/vuln-web-app/issues/7)

---

## 0. Plan Overview

This plan implements the fix specified in [exposed-database-endpoint.md](./exposed-database-endpoint.md). It closes **issue #7 (Exposed Database endpoint)** and **only** that vulnerability, by **removing** the unauthenticated `GET /download/db` route from `backend/app/api/routes/auth.py`. The work is split into **three phases** so the change is small, individually verifiable, and easy to revert.

The other intentional vulnerabilities (SQL Injection, Stored XSS, Reflected XSS, Session Hijacking, No Rate Limiting, CSRF) MUST remain exploitable after every phase, and the bcrypt password fix stays closed. Each phase ends with an explicit "MUST NOT" callout listing things that would silently alter another vulnerability.

### Phase Summary

| # | Phase | Files Touched | Goal |
|---|-------|--------------|------|
| 1 | Remove the route + dead symbols from `auth.py` | `backend/app/api/routes/auth.py` | `/download/db` no longer registered; no dead `FileResponse`/`DB_PATH` left |
| 2 | End-to-end verification | None (read-only) | Walk every Verification Step in spec §10 |
| 3 | Vulnerability preservation audit | None (read-only) | Confirm the other vulnerabilities still fire |

### Files Modified (Authored)

Exactly the one source file declared in spec §3:

- `backend/app/api/routes/auth.py`

No dependency change, so no `pyproject.toml` or `uv.lock` edit (and no `uv sync`).

### Files That MUST NOT Be Modified

- `backend/app/main.py` — touching it risks changing the hardcoded session secret (Session Hijacking).
- `backend/app/services/auth_service.py` — preserves the string-concatenated SQL (SQL Injection).
- `backend/app/core/security.py` — bcrypt stays; do not revert.
- `backend/app/db/session.py` — schema and its own separate `DB_PATH` are unrelated and untouched.
- Any HTML template or CSS — preserves the `{{username}}` Stored XSS path.
- The `/search` handler inside `auth.py` — preserves Reflected XSS.
- `CLAUDE.md`, `docs/PRD.md`, `docs/TDD.md`, `.claude/specs/app-foundation.md`, and this spec/plan pair.

### Vulnerability Preservation Checklist (Carry Through Every Phase)

After the edit, re-confirm:

1. **SQL Injection.** `auth_service.signup()` and `login()` still use string-concatenated queries (`"... WHERE username = '" + username + "'"`). Not touched by this plan.
2. **Stored XSS.** `auth.py:welcome_page()` still does `html.replace('{{username}}', username)` — not touched.
3. **Reflected XSS.** `/search` still interpolates `q` into HTML unescaped — not touched.
4. **Session Hijacking.** `main.py` still contains the literal `"super-secret-key-12345"` — not touched.
5. **Weak Password (bcrypt).** `security.py` still uses bcrypt; no MD5 re-introduced — not touched.
6. **Exposed Database endpoint.** **This is the only vulnerability being closed.** After Phase 1, `/download/db` is gone.
7. **No Rate Limiting.** No throttling middleware added — not touched.
8. **CSRF.** No CSRF token field or middleware added — not touched.

---

## Phase 1 — Remove the `/download/db` Route and Dead Symbols

### 1.1 Goal

Delete the `download_db` handler from `auth.py` so the route is no longer registered, and remove the two symbols that become dead as a result (`FileResponse` import, `DB_PATH` constant). All edits are confined to `auth.py`.

### 1.2 File to Modify

- `backend/app/api/routes/auth.py`

### 1.3 Edit A — Drop `FileResponse` from the imports

**Before** (L4):

```python
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
```

**After**:

```python
from fastapi.responses import HTMLResponse, RedirectResponse
```

`HTMLResponse` (signup/login/search/welcome) and `RedirectResponse` (index/welcome/logout) are still used; `FileResponse` was used only by the deleted handler.

### 1.4 Edit B — Remove the dead `DB_PATH` constant

**Before** (L11–13):

```python
BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
TEMPLATE_DIR = os.path.join(BASE_DIR, "frontend", "templates")
DB_PATH = os.path.join(BASE_DIR, "vulnerable_app.db")
```

**After**:

```python
BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")
TEMPLATE_DIR = os.path.join(BASE_DIR, "frontend", "templates")
```

`BASE_DIR` and `TEMPLATE_DIR` stay — `TEMPLATE_DIR` is read by `signup_page`, `login_page`, and `welcome_page`. Only the `DB_PATH` line is removed (it was used only by the deleted handler).

### 1.5 Edit C — Delete the route handler

**Before** (L53–56):

```python
@router.get("/download/db")
async def download_db():
    # VULNERABILITY #6: Exposed Database -- no authentication check
    return FileResponse(path=DB_PATH, filename="vulnerable_app.db")
```

**After**: the entire block is removed (handler, decorator, and comment). The surrounding routes (`/login` POST above it, `/search` below it) are left untouched, separated by the usual two blank lines.

### 1.6 Edit Summary

Three deletions inside `auth.py`:

1. Remove `FileResponse` from the `fastapi.responses` import.
2. Remove the `DB_PATH = ...` module-level line.
3. Remove the whole `@router.get("/download/db")` handler block.

No other line in the file changes.

### 1.7 What NOT to Change in Phase 1

- **DO NOT** replace the route with an auth-gated version. The decision (spec §1, §2.3) is to **remove**, not gate — any-logged-in-user access would still expose the whole DB.
- **DO NOT** add an admin role, an `is_admin` column, or any session check anywhere. That would change other files and re-introduce a download path.
- **DO NOT** delete, move, or rename the `vulnerable_app.db` file (NFR-04). Only the HTTP route is removed.
- **DO NOT** remove `BASE_DIR` or `TEMPLATE_DIR` — they are still in use.
- **DO NOT** touch any other handler, import, or the `/search` SQL/HTML construction.
- **DO NOT** edit `main.py`, `auth_service.py`, `security.py`, `session.py`, templates, CSS, or any pyproject/lock file.

### 1.8 Phase 1 Verification (Pre-Server)

```bash
cd backend && uv run python -c "from app.api.routes.auth import router; print('import ok')" && cd ..
grep -n 'download/db\|download_db\|FileResponse\|DB_PATH' backend/app/api/routes/auth.py || echo '(all references removed)'
```

Expected: prints `import ok`; the grep prints `(all references removed)`.

---

## Phase 2 — End-to-End Verification

This phase walks every Verification Step in spec §10 in order. **No edits** are made; if a step fails, return to Phase 1 to repair.

### 2.1 Start the App (spec §10.1)

```bash
uv run backend/app/main.py
```

Confirm the server boots with no traceback and `http://localhost:3001/login` responds 200.

### 2.2 Route Gone (spec §10.2 — AC-01, TC-01)

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:3001/download/db
```

Expected: `404`.

### 2.3 Surviving Routes (spec §10.3 — AC-04, TC-04/TC-05)

```bash
curl -s -o /dev/null -w 'signup=%{http_code}\n' http://localhost:3001/signup
curl -s -o /dev/null -w 'login=%{http_code}\n'  http://localhost:3001/login
```

Expected: `signup=200`, `login=200`.

### 2.4 Full Auth Flow (spec §10.4 — TC-06)

```bash
curl -s -c jar.txt -X POST http://localhost:3001/signup \
     --data-urlencode 'username=alice' --data-urlencode 'email=alice@test.com' --data-urlencode 'password=pass123'
curl -s -c jar.txt -b jar.txt -X POST http://localhost:3001/login \
     --data-urlencode 'username=alice' --data-urlencode 'password=pass123'
curl -s -b jar.txt -o /dev/null -w 'welcome=%{http_code}\n' http://localhost:3001/welcome
```

Expected: login returns success JSON; `welcome=200`.

### 2.5 Authenticated Caller Also Blocked (TC-02, EC-01)

```bash
curl -s -b jar.txt -o /dev/null -w '%{http_code}\n' http://localhost:3001/download/db
```

Expected: `404` — even with a valid session (route removed for everyone).

### 2.6 No Residual References (spec §10.5 — AC-02, TC-07)

```bash
grep -n 'download/db\|download_db\|FileResponse\|DB_PATH' backend/app/api/routes/auth.py \
  || echo '(all references removed)'
```

Expected: `(all references removed)`.

### 2.7 Affected-Files Audit (spec §10.7 — AC-06, TC-12)

```bash
git status --porcelain
```

Expected: `backend/app/api/routes/auth.py` modified, plus the two new spec docs. No other path.

---

## Phase 3 — Vulnerability Preservation Audit

Read-only confirmation that the other intentional vulnerabilities still fire.

### 3.1 Reflected XSS (AC-05, TC-08)

```bash
curl -s 'http://localhost:3001/search?q=<script>alert(1)</script>' | grep -o '<script>alert(1)</script>'
```

Expected: the literal payload is printed back (reflected unescaped).

### 3.2 Stored XSS (AC-05)

```bash
curl -s -X POST http://localhost:3001/signup \
     --data-urlencode 'username=<img src=x onerror=alert(1)>' \
     --data-urlencode 'email=xss@x' --data-urlencode 'password=p'
```

Then log in as that user and visit `/welcome` in a browser — the unescaped markup renders.

### 3.3 Session Secret (AC-05, TC-09)

```bash
grep -n 'super-secret-key-12345' backend/app/main.py
```

Expected: the secret is still present on its original line.

### 3.4 SQL Injection Construction (AC-05, TC-10)

```bash
grep -n "WHERE username = '" backend/app/services/auth_service.py
```

Expected: the string-concatenated query is still present.

### 3.5 No Rate Limiting (AC-05)

```bash
for i in 1 2 3 4 5; do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:3001/login \
       --data-urlencode 'username=ghost' --data-urlencode "password=$i"
done | sort -u
```

Expected: only `401` appears — no `429`, no throttling.

### 3.6 No CSRF (AC-05, TC-11)

```bash
curl -s http://localhost:3001/login  | grep -i csrf || echo '(no csrf field — preserved)'
curl -s http://localhost:3001/signup | grep -i csrf || echo '(no csrf field — preserved)'
```

Expected: each prints `(no csrf field — preserved)`.

### 3.7 Spec Acceptance Criteria Roll-Up

- [ ] AC-01 Route Returns 404 (Phase 2.2)
- [ ] AC-02 No Residual References (Phase 1.8, Phase 2.6)
- [ ] AC-03 Application Boots (Phase 2.1)
- [ ] AC-04 Surviving Routes Work (Phase 2.3, 2.4)
- [ ] AC-05 Other Vulnerabilities Preserved (Phase 3.1–3.6)
- [ ] AC-06 Only `auth.py` Modified (Phase 2.7)

### 3.8 Stop the Server

`Ctrl+C` to stop. Plan complete.

---

## Risk Log & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Gating the route behind a session instead of removing it — leaves the whole-DB exposure to any registered user | Medium | High | Spec §2.3 + Phase 1.7 "MUST NOT"; the decision is remove, not gate |
| Removing `FileResponse` but leaving the handler (or vice versa) — `NameError`/dead code | Low | Medium | Phase 1.6 lists all three deletions; Phase 1.8 import smoke test catches a dangling reference |
| Accidentally deleting `BASE_DIR`/`TEMPLATE_DIR` — breaks signup/login/welcome page loads | Low | High | Phase 1.4 keeps both; Phase 2.3/2.4 verify the pages still load |
| Touching `main.py` to "centralize secrets" — rotates the session secret | Low | High | MUST-NOT list; Phase 3.3 grep catches it |
| Deleting the `vulnerable_app.db` file as part of "removing the DB" | Low | Medium | NFR-04 + Phase 1.7 explicit; the file stays, only the route goes |

---

## Rollback Procedure

If verification fails and cannot be repaired quickly:

```bash
git restore backend/app/api/routes/auth.py
```

The single authored file snaps back to its pre-fix state. No dependency, schema, or data migration is involved.

---

## Out-of-Band: What This Plan Deliberately Does NOT Do

- **No auth gating.** The route is removed, not protected. Any-logged-in-user access would still expose the full database.
- **No admin role / schema change.** No `is_admin` column, no admin username, no `session.py` edit.
- **No file deletion.** `vulnerable_app.db` stays on disk; only its HTTP route is removed.
- **No change to other vulnerabilities.** SQL Injection, Stored XSS, Reflected XSS, Session Hijacking, No Rate Limiting, and CSRF all remain. bcrypt stays closed.
- **No dependency change.** No `pyproject.toml`/`uv.lock` edit, no `uv sync`.
- **No new file** beyond this spec/plan pair.
