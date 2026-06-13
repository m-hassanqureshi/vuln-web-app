# Implementation Plan — SQL Injection Fix (Complete)

**Version:** 1.0.0
**Last Updated:** June 12, 2026
**Parent Spec:** [sql-injection-fix.md](./sql-injection-fix.md)
**Foundation Spec:** [app-foundation.md](./app-foundation.md)
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md)

---

## 0. Plan Overview

This plan implements the SQL injection fix specified in [sql-injection-fix.md](./sql-injection-fix.md). It closes **SQL Injection vulnerabilities in all three locations** (signup, login, and search) and **only** those vulnerabilities. The work is split into **five phases** so each step is small, individually verifiable, and easy to revert.

The six remaining intentional vulnerabilities (VULN-2 Stored XSS, VULN-3 Reflected XSS, VULN-4 Session Hijacking, VULN-6 Exposed DB, VULN-7 No Rate Limiting, VULN-8 No CSRF) MUST remain exploitable after every phase. Each phase ends with an explicit "MUST NOT" callout listing things that would silently close another vulnerability.

### Phase Summary

| # | Phase | Files Touched | Goal |
|---|-------|--------------|------|
| 1 | Parameterize `signup()` query | `backend/app/services/auth_service.py` | Replace string concatenation in INSERT with `?` placeholders |
| 2 | Parameterize `login()` query | `backend/app/services/auth_service.py` | Replace string concatenation in SELECT with `?` placeholder |
| 3 | Parameterize `search_user()` query | `backend/app/api/routes/auth.py` | Replace string concatenation in SELECT with `?` placeholders for LIKE |
| 4 | End-to-end verification | None (read-only) | Walk every Verification Step in spec §10 |
| 5 | Vulnerability preservation audit | None (read-only) | Confirm the other 6 vulnerabilities still fire |

### Files Modified (Authored)

Exactly the two source files declared in spec §3:

- `backend/app/services/auth_service.py`
- `backend/app/api/routes/auth.py`

### Files That MUST NOT Be Modified

- `backend/app/core/security.py` — bcrypt password hashing unchanged (VULN-5 already closed).
- `backend/app/main.py` — preserves hardcoded session secret (VULN-4).
- `backend/app/db/session.py` — schema and connection layer unchanged.
- `backend/pyproject.toml`, `pyproject.toml` — no new dependencies required.
- Any HTML template under `frontend/templates/` or CSS under `frontend/static/`.
- `CLAUDE.md`, `docs/PRD.md`, `docs/TDD.md`, `.claude/specs/app-foundation.md`, `.claude/specs/sql-injection-fix.md`.

### Vulnerability Preservation Checklist (Carry Through Every Phase)

After each edit, re-confirm:

1. ✅ **VULN-2 Stored XSS.** `auth.py:welcome_page()` still does `html.replace('{{username}}', username)` — not touched.
2. ✅ **VULN-3 Reflected XSS.** `/search` still interpolates `q` into HTML unescaped — not touched (SQLi fixed, XSS preserved).
3. ✅ **VULN-4 Session Hijacking.** `main.py` still contains the literal `"super-secret-key-12345"` — not touched.
4. ✅ **VULN-5 Weak Password.** Bcrypt hashing (already closed) remains untouched.
5. ✅ **VULN-6 Exposed DB.** `/download/db` remains unauthenticated — not touched.
6. ✅ **VULN-7 No Rate Limiting.** No throttling middleware is added to `main.py`. No `slowapi`, no per-IP counter, no `time.sleep`.
7. ✅ **VULN-8 No CSRF.** No CSRF token field is added to any form, no CSRF middleware is registered.

---

## Phase 1 — Parameterize `signup()` Query

### 1.1 Goal

Replace the string-concatenated `INSERT` query in `signup()` with a parameterized query using sqlite3's `?` placeholder syntax. This closes the SQL injection vector in the signup flow while preserving all existing behavior.

### 1.2 File to Modify

- `backend/app/services/auth_service.py`

### 1.3 Current `signup()` Implementation (L10–38)

```python
def signup(username: str, email: str, password: str):
    if not username or not email or not password:
        return HTMLResponse(
            content="<h3>All fields are required</h3><a href='/signup'>Go back</a>",
            status_code=400,
        )

    hashed = hash_password(password)

    # VULNERABILITY #1: SQL Injection via string concatenation
    query = "INSERT INTO users (username, email, password) VALUES ('" + username + "', '" + email + "', '" + hashed + "')"

    conn = get_db()
    try:
        conn.execute(query)
        conn.commit()
        return RedirectResponse(url="/login", status_code=302)
    except sqlite3.IntegrityError:
        return HTMLResponse(
            content="<h3>Username already exists</h3><a href='/signup'>Go back</a>",
            status_code=400,
        )
    except Exception as e:
        return HTMLResponse(
            content=f"<h3>Error: {str(e)}</h3><a href='/signup'>Go back</a>",
            status_code=400,
        )
    finally:
        conn.close()
```

### 1.4 New `signup()` Implementation

Replace the function body with:

```python
def signup(username: str, email: str, password: str):
    if not username or not email or not password:
        return HTMLResponse(
            content="<h3>All fields are required</h3><a href='/signup'>Go back</a>",
            status_code=400,
        )

    hashed = hash_password(password)

    # FIXED: SQL Injection closed by using parameterized query
    query = "INSERT INTO users (username, email, password) VALUES (?, ?, ?)"

    conn = get_db()
    try:
        conn.execute(query, [username, email, hashed])
        conn.commit()
        return RedirectResponse(url="/login", status_code=302)
    except sqlite3.IntegrityError:
        return HTMLResponse(
            content="<h3>Username already exists</h3><a href='/signup'>Go back</a>",
            status_code=400,
        )
    except Exception as e:
        return HTMLResponse(
            content=f"<h3>Error: {str(e)}</h3><a href='/signup'>Go back</a>",
            status_code=400,
        )
    finally:
        conn.close()
```

### 1.5 Line-by-Line Justification

| Line | Decision | Spec ref |
|------|----------|----------|
| Query template with `?, ?, ?` | Parameterized placeholders separate SQL from data | FR-01, NFR-01 |
| `conn.execute(query, [username, email, hashed])` | Values passed as list, not concatenated | FR-01, AC-01 |
| Comment updated from "VULNERABILITY #1" to "FIXED" | Documents the closure for educational purposes | NFR-03 |
| All error handling unchanged | Preserves existing error behaviors | FR-04, NFR-06 |
| Return types and responses unchanged | API stability maintained | NFR-02 |

### 1.6 What NOT to Change in Phase 1

- **DO NOT** touch `login()` or `search_user()`. Their SQL injection fixes happen in Phase 2 and Phase 3.
- **DO NOT** change the function signature, return types, or error messages.
- **DO NOT** add any new dependencies (sqlite3 parameterization is built-in).
- **DO NOT** add input validation or sanitization — that's not the fix for SQLi.
- **DO NOT** escape values manually (e.g., `username.replace("'", "''")`) — parameterization is the correct fix.
- **DO NOT** modify any other file in the repository.

### 1.7 Phase 1 Verification

```bash
cd backend && uv run python -c "from app.services.auth_service import signup; print('imports ok')" && cd ..
```

Expected: prints `imports ok` (no `ImportError` or syntax error).

---

## Phase 2 — Parameterize `login()` Query

### 2.1 Goal

Replace the string-concatenated `SELECT` query in `login()` with a parameterized query. This closes the SQL injection vector in the login flow. Note: the password comparison already happens in Python via `verify_password()` (VULN-5 was previously closed with bcrypt), so only the username branch needs parameterization.

### 2.2 File to Modify

- `backend/app/services/auth_service.py`

### 2.3 Current `login()` Implementation (L41–76)

```python
def login(request: Request, username: str, password: str):
    if not username or not password:
        return JSONResponse(
            content={"error": "Username and password are required"},
            status_code=401,
        )

    # VULNERABILITY #1: SQL Injection via string concatenation
    # (Password comparison is performed in Python — see verify_password below —
    # because bcrypt hashes cannot be matched with an SQL equality check.
    # The username branch is intentionally still concatenated to preserve VULN-1.)
    query = "SELECT * FROM users WHERE username = '" + username + "'"

    conn = get_db()
    try:
        cursor = conn.execute(query)
        user = cursor.fetchone()
    except Exception:
        return JSONResponse(
            content={"error": "Invalid username or password"},
            status_code=401,
        )
    finally:
        conn.close()

    if user and verify_password(password, user["password"]):
        request.session["user_id"] = user["id"]
        request.session["username"] = user["username"]
        request.session["email"] = user["email"]
        return JSONResponse(content={"success": True, "redirect": "/welcome"})
    else:
        return JSONResponse(
            content={"error": "Invalid username or password"},
            status_code=401,
        )
```

### 2.4 New `login()` Implementation

Replace the function body with:

```python
def login(request: Request, username: str, password: str):
    if not username or not password:
        return JSONResponse(
            content={"error": "Username and password are required"},
            status_code=401,
        )

    # FIXED: SQL Injection closed by using parameterized query
    # (Password comparison is performed in Python via verify_password
    # because bcrypt hashes cannot be matched with an SQL equality check.)
    query = "SELECT * FROM users WHERE username = ?"

    conn = get_db()
    try:
        cursor = conn.execute(query, [username])
        user = cursor.fetchone()
    except Exception:
        return JSONResponse(
            content={"error": "Invalid username or password"},
            status_code=401,
        )
    finally:
        conn.close()

    if user and verify_password(password, user["password"]):
        request.session["user_id"] = user["id"]
        request.session["username"] = user["username"]
        request.session["email"] = user["email"]
        return JSONResponse(content={"success": True, "redirect": "/welcome"})
    else:
        return JSONResponse(
            content={"error": "Invalid username or password"},
            status_code=401,
        )
```

### 2.5 Line-by-Line Justification

| Line | Decision | Spec ref |
|------|----------|----------|
| Query template with `?` placeholder | Parameterized placeholder separates SQL from data | FR-02, NFR-01 |
| `conn.execute(query, [username])` | Username passed as list element, not concatenated | FR-02, AC-02 |
| Comment updated from "VULNERABILITY #1... to preserve VULN-1" to "FIXED" | Documents the closure; removes outdated preservation note | NFR-03 |
| Password comparison unchanged | Bcrypt verification (VULN-5 already closed) preserved | FR-06, NFR-04 |
| Session writes unchanged | API stability maintained | FR-05, NFR-02 |
| Error handling unchanged | No information leakage introduced | FR-04, NFR-06 |

### 2.6 What NOT to Change in Phase 2

- **DO NOT** change the `verify_password` call or add any inline bcrypt logic.
- **DO NOT** modify the session writes (`request.session[...]`) or the success/failure JSON payloads.
- **DO NOT** add `LIMIT 1` or other "hardenings" that change query behavior.
- **DO NOT** add timing-attack mitigation (constant-time username lookup).
- **DO NOT** change HTTP status codes or error messages.
- **DO NOT** modify any other function in the file.

### 2.7 Phase 2 Verification

```bash
cd backend && uv run python -c "from app.services.auth_service import login, signup; print('imports ok')" && cd ..
```

Expected: prints `imports ok` (no `ImportError` or syntax error).

---

## Phase 3 — Parameterize `search_user()` Query

### 3.1 Goal

Replace the string-concatenated `SELECT` query with LIKE pattern in `search_user()` with a parameterized query. This closes the SQL injection vector in the search flow while preserving the LIKE partial matching functionality. Critically: the HTML output must still reflect the `q` parameter unescaped to preserve VULN-3 (Reflected XSS).

### 3.2 File to Modify

- `backend/app/api/routes/auth.py`

### 3.3 Current `search_user()` Implementation (L59–82)

```python
@router.get("/search")
async def search_user(q: str = ""):
    if not q:
        return HTMLResponse(content="<h3>No search query provided</h3>")

    # VULNERABILITY #3: Reflected XSS -- query interpolated into HTML without escaping
    # SQL also uses string concatenation
    query = "SELECT username, email FROM users WHERE username LIKE '%" + q + "%' OR email LIKE '%" + q + "%'"

    conn = get_db()
    try:
        cursor = conn.execute(query)
        rows = cursor.fetchall()

        results = ""
        for row in rows:
            results += f"<li>{row[0]} ({row[1]})</li>"

        html = f"<h3>Search results for: {q}</h3><ul>{results}</ul>"
        return HTMLResponse(content=html)
    except Exception as e:
        return HTMLResponse(content=f"<h3>Error: {str(e)}</h3>")
    finally:
        conn.close()
```

### 3.4 New `search_user()` Implementation

Replace the function body with:

```python
@router.get("/search")
async def search_user(q: str = ""):
    if not q:
        return HTMLResponse(content="<h3>No search query provided</h3>")

    # FIXED: SQL Injection closed by using parameterized query
    # VULNERABILITY #3: Reflected XSS still preserved -- query interpolated into HTML without escaping
    query = "SELECT username, email FROM users WHERE username LIKE ? OR email LIKE ?"

    conn = get_db()
    try:
        cursor = conn.execute(query, [f"%{q}%", f"%{q}%"])
        rows = cursor.fetchall()

        results = ""
        for row in rows:
            results += f"<li>{row[0]} ({row[1]})</li>"

        html = f"<h3>Search results for: {q}</h3><ul>{results}</ul>"
        return HTMLResponse(content=html)
    except Exception as e:
        return HTMLResponse(content=f"<h3>Error: {str(e)}</h3>")
    finally:
        conn.close()
```

### 3.5 Line-by-Line Justification

| Line | Decision | Spec ref |
|------|----------|----------|
| Query template with `?` placeholders | Parameterized placeholders separate SQL from data | FR-03, NFR-01 |
| `conn.execute(query, [f"%{q}%", f"%{q}%"])` | Values passed as list with wildcards in parameters, not query | FR-03, FR-07, AC-03, AC-04 |
| Comment updated to indicate SQLi fixed but XSS preserved | Documents selective vulnerability closure | NFR-03 |
| HTML response still uses `{q}` unescaped | Preserves VULN-3 Reflected XSS | FR-08, NFR-03 |
| LIKE pattern matching unchanged via `%` wildcards | Preserves partial matching behavior | FR-07, NFR-04 |
| Error handling unchanged | No information leakage introduced | FR-04, NFR-06 |

### 3.6 What NOT to Change in Phase 3

- **DO NOT** escape the `q` parameter in the HTML output (e.g., with `html.escape(q)`). That would close VULN-3.
- **DO NOT** change the LIKE pattern matching behavior.
- **DO NOT** change the HTML response format.
- **DO NOT** add validation or sanitization to the `q` parameter.
- **DO NOT** modify any other function in the file.
- **DO NOT** touch the dashboard `{{username}}` substitution (that's VULN-2).

### 3.7 Phase 3 Verification

```bash
cd backend && uv run python -c "from app.api.routes.auth import router; print('imports ok')" && cd ..
```

Expected: prints `imports ok` (no `ImportError` or syntax error).

---

## Phase 4 — End-to-End Verification

This phase walks every Verification Step in spec §10 in order. **No edits** are made during this phase; if any step fails, document the failure and return to the offending phase to repair.

### 4.1 Start the Application (spec §10.1)

```bash
rm -f vulnerable_app.db
uv run backend/app/main.py
```

The server listens on `http://localhost:3001`. Confirm it starts without errors.

### 4.2 Functional Walkthrough (spec §10.2)

| Step | Action | Expected | Spec ref |
|------|--------|----------|----------|
| 4.2.1 | Register `alice` / `alice@test.com` / `pass123` via `/signup` | 302 → `/login` | SP-01, TC-01 |
| 4.2.2 | `sqlite3 vulnerable_app.db "SELECT username FROM users WHERE username='alice';"` | Returns `alice` | TC-02 |
| 4.2.3 | `POST /login` as `alice` / `pass123` | JSON `{"success": true, "redirect": "/welcome"}` | SP-02, TC-02 |
| 4.2.4 | `GET /search?q=alice` | HTML with alice's info | SP-03, TC-14 |

### 4.3 SQL Injection Payload Tests (spec §10.3)

1. **Classic OR injection in login** (TC-03)
   ```bash
   curl -s -i -X POST http://localhost:3001/login \
        --data-urlencode "username=admin' OR '1'='1' --" \
        --data-urlencode 'password=anything'
   ```
   Expected: HTTP 401, `{"error":"Invalid username or password"}`. No authentication bypass.

2. **Tautology injection in login** (TC-03)
   ```bash
   curl -s -i -X POST http://localhost:3001/login \
        --data-urlencode "username=' OR '1'='1' --" \
        --data-urlencode 'password=x'
   ```
   Expected: HTTP 401. No authentication bypass.

3. **Comment-based injection in login** (TC-03)
   ```bash
   curl -s -i -X POST http://localhost:3001/login \
        --data-urlencode "username=alice' --" \
        --data-urlencode 'password=wrongpass'
   ```
   Expected: HTTP 401. The literal username `alice' --` does not match any user.

4. **SQLi in signup** (TC-04)
   ```bash
   curl -s -i -X POST http://localhost:3001/signup \
        --data-urlencode "username=test', 'x@x', 'hash') --" \
        --data-urlencode 'email=sql@x' \
        --data-urlencode 'password=x'
   ```
   Expected: Either successful signup with literal username or validation error. **No injection.**

5. **SQLi in search** (TC-05)
   ```bash
   curl -s 'http://localhost:3001/search?q=test'\'' OR '\''1'\''='\''1'\'' --'
   ```
   Expected: No results (or results for literal string only). No SQL injection.

### 4.4 Edge Case Tests (spec §10.4)

1. **Single quote in username** (TC-06)
   ```bash
   # Register
   curl -s -i -X POST http://localhost:3001/signup \
        --data-urlencode "username=o'neill" \
        --data-urlencode 'email=oneill@test.com' \
        --data-urlencode 'password=pass123'
   # Login
   curl -s -i -X POST http://localhost:3001/login \
        --data-urlencode "username=o'neill" \
        --data-urlencode 'password=pass123'
   # Search
   curl -s "http://localhost:3001/search?q=o'neill"
   ```
   Expected: Registration succeeds (302 to `/login`), login succeeds (200), search succeeds (returns result).

2. **SQL keywords in username** (TC-07)
   ```bash
   curl -s -i -X POST http://localhost:3001/signup \
        --data-urlencode "username=admin; DROP TABLE users; --" \
        --data-urlencode 'email=drop@x' \
        --data-urlencode 'password=x'
   ```
   Expected: Either successful signup with literal username or validation error; **no table dropped**.

3. **Empty username** (TC-08)
   ```bash
   curl -s -i -X POST http://localhost:3001/login \
        --data-urlencode 'username=' \
        --data-urlencode 'password=pass123'
   ```
   Expected: HTTP 401.

4. **Unicode input** (TC-12)
   ```bash
   curl -s -i -X POST http://localhost:3001/signup \
        --data-urlencode 'username=日本語' \
        --data-urlencode 'email=test@example.com' \
        --data-urlencode 'password=パスワード'
   ```
   Expected: Registration succeeds (302 to `/login`), login succeeds, search succeeds.

5. **Partial matching in search** (TC-15)
   ```bash
   curl -s 'http://localhost:3001/search?q=ali'
   ```
   Expected: Returns alice's result (partial match).

6. **Empty search query** (TC-16)
   ```bash
   curl -s 'http://localhost:3001/search'
   ```
   Expected: Returns "No search query provided" message.

7. **Special characters in search** (TC-17)
   ```bash
   curl -s 'http://localhost:3001/search?q=%'
   ```
   Expected: Returns results for literal `%` character (if any).

### 4.5 Code Inspection (spec §10.6)

```bash
# Verify no string concatenation in queries
grep -n "VALUES.*'" backend/app/services/auth_service.py || echo 'No concatenation in signup'
grep -n "WHERE.*'" backend/app/services/auth_service.py || echo 'No concatenation in login'
grep -n "LIKE.*'" backend/app/api/routes/auth.py || echo 'No concatenation in search'

# Verify parameterized query syntax
grep -n "VALUES (?, ?, ?)" backend/app/services/auth_service.py
grep -n "WHERE username = ?" backend/app/services/auth_service.py
grep -n "LIKE ?" backend/app/api/routes/auth.py

# Verify execute() is called with parameters
grep -n "execute.*\[" backend/app/services/auth_service.py
grep -n "execute.*\[" backend/app/api/routes/auth.py

# Verify % wildcards are in parameters, not query (for search)
grep -n "f\"%.*%\"" backend/app/api/routes/auth.py
```

Expected:
- No string concatenation in query construction in any file.
- All three parameterized query patterns found.
- All `execute()` calls use list syntax `conn.execute(query, [...])`.
- Search query uses `f"%{q}%"` in parameters, not in query template.

### 4.6 Affected-Files Audit (spec §10.7)

```bash
git status --porcelain
```

Expected output — exactly two modified files:

```
 M backend/app/services/auth_service.py
 M backend/app/api/routes/auth.py
```

---

## Phase 5 — Vulnerability Preservation Audit

This phase confirms the **other six** intentional vulnerabilities still fire. It's read-only — no edits.

### 5.1 VULN-2 Stored XSS Still Fires (AC-11, TC-18)

```bash
curl -s -i -X POST http://localhost:3001/signup \
     --data-urlencode 'username=<img src=x onerror=alert(1)>' \
     --data-urlencode 'email=xss@x' \
     --data-urlencode 'password=p'
curl -s -c /tmp/x.txt -X POST http://localhost:3001/login \
     --data-urlencode 'username=<img src=x onerror=alert(1)>' \
     --data-urlencode 'password=p'
curl -s -b /tmp/x.txt http://localhost:3001/welcome | grep -o "Logged in as.*</span>"
```

Expected: the dashboard HTML contains `Logged in as <strong><img src=x onerror=alert(1)></strong>` — raw, unescaped.

### 5.2 VULN-3 Reflected XSS Still Fires (AC-11, TC-19)

```bash
curl -s 'http://localhost:3001/search?q=<script>alert(1)</script>' | grep -o '<script>alert(1)</script>'
```

Expected: the literal payload is printed back (reflected unescaped). XSS preserved, only SQLi fixed.

### 5.3 VULN-4 Session Secret Unchanged (AC-11, TC-20)

```bash
grep -n 'super-secret-key-12345' backend/app/main.py
```

Expected: the secret is still present on its original line.

### 5.4 VULN-6 Exposed DB Still Open (AC-11, TC-21)

```bash
curl -s -o /tmp/dl.db -w 'status=%{http_code}\n' http://localhost:3001/download/db
file /tmp/dl.db
```

Expected: `status=200`, non-zero byte count, `file` identifies it as a SQLite 3.x database.

### 5.5 VULN-7 No Rate Limiting (AC-11, TC-23)

```bash
for i in {1..50}; do
  curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:3001/login \
       --data-urlencode 'username=ghost' --data-urlencode "password=$i"
done | sort -u
```

Expected: only `401` appears in the deduplicated output. No `429`, no connection refusals.

### 5.6 VULN-8 No CSRF Tokens (AC-11, TC-22)

```bash
curl -s http://localhost:3001/login | grep -i csrf || echo '(no csrf field — preserved)'
curl -s http://localhost:3001/signup | grep -i csrf || echo '(no csrf field — preserved)'
```

Expected: each command prints the `(no csrf field — preserved)` fallback.

### 5.7 Spec Acceptance Criteria Roll-Up

Tick every AC from spec §8:

- [ ] AC-01 signup() Uses Parameterized Query (Phase 1, Phase 4.5)
- [ ] AC-02 login() Uses Parameterized Query (Phase 2, Phase 4.5)
- [ ] AC-03 search_user() Uses Parameterized Query (Phase 3, Phase 4.5)
- [ ] AC-04 LIKE Pattern Preserved (Phase 3, Phase 4.5)
- [ ] AC-05 No String Concatenation in Any Query (Phase 4.5)
- [ ] AC-06 SQL Injection Payload Fails in All Locations (Phase 4.3)
- [ ] AC-07 Normal Signup Still Works (Phase 4.2.1)
- [ ] AC-08 Normal Login Still Works (Phase 4.2.3)
- [ ] AC-09 Normal Search Still Works (Phase 4.2.4)
- [ ] AC-10 Error Messages Preserved (verified throughout)
- [ ] AC-11 Other Vulnerabilities Preserved (Phase 5.1–5.6)
- [ ] AC-12 Affected Files Limited (Phase 4.6)

### 5.8 Stop the Server

`Ctrl+C` to stop. Plan complete.

---

## Risk Log & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Forgetting to parameterize one of the three functions | Low | High | Three-phase approach ensures each function is addressed separately; Phase 4.3 verifies all are fixed |
| Manually escaping values instead of using parameters | Low | High | Phase 1.6, 2.6, and 3.6 explicitly forbid escaping; Phase 4.5 grep checks confirm no concatenation |
| Changing error messages or status codes | Low | Medium | Phases 1.5, 2.5, and 3.5 emphasize unchanged error handling; Phase 4.3 tests verify same responses |
| Touching other files "for consistency" | Low | Medium | "Files That MUST NOT Be Modified" list; Phase 4.6 git status catches it |
| Breaking existing bcrypt integration | Low | Medium | Phase 2.5 explicitly forbids touching `verify_password`; Phase 4.2.3 tests login succeeds |
| Accidentally adding CSRF tokens or rate limiting | Very Low | High | Vulnerability Preservation Checklist carried through each phase; Phase 5 audit catches it |
| Accidentally escaping XSS in search or dashboard | Very Low | High | Phase 3.6 explicitly forbids escaping `q` in HTML; Phase 5.2 verifies XSS still fires |
| Database schema change perceived as needed | Very Low | Medium | spec §11 explicitly states no migration needed; Phase 4.6 git status catches any new files |
| Breaking LIKE pattern matching in search | Low | Medium | Phase 3.5 emphasizes preserving LIKE with `%` wildcards in parameters; Phase 4.4 tests verify partial matching works |

---

## Rollback Procedure

If a phase fails verification and cannot be repaired quickly:

```bash
git restore backend/app/services/auth_service.py
git restore backend/app/api/routes/auth.py
```

The two authored files snap back to their pre-fix state. No data migration is involved because no schema changes were made.

---

## Out-of-Band: What This Plan Deliberately Does NOT Do

To make the negative space explicit:

- **No input validation or sanitization.** Parameterization is the correct fix for SQLi, not manual escaping or validation. Malicious payloads like `' OR '1'='1' --` are still accepted as usernames or search terms — they just no longer execute SQL.
- **No schema changes.** The `users` table structure is unchanged. No `ALTER TABLE`, no new columns.
- **No database migration script.** Existing rows continue to work without modification.
- **No new dependencies.** SQLite's parameterized query syntax is built-in; no ORM or query library added.
- **No session secret rotation.** `"super-secret-key-12345"` remains in `main.py` (VULN-4).
- **No CSRF tokens.** Forms remain token-less (VULN-8).
- **No XSS escaping.** Dashboard `{{username}}` and search `q` remain unescaped (VULN-2, VULN-3).
- **No rate limiting middleware.** Login and search attempts remain unthrottled (VULN-7).
- **No /download/db protection.** The endpoint remains open (VULN-6).
- **No password policy changes.** Any non-empty password is still accepted.