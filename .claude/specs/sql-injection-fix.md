# Software Specification Document — SQL Injection Fix (Complete)

**Version:** 1.0.0
**Last Updated:** June 12, 2026
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md), [bcrypt-password-hashing.md](./bcrypt-password-hashing.md)

---

## 1. Overview / Purpose

This document specifies the remediation of **All SQL Injection Vulnerabilities** in the Vulnerable Web Application. The current implementation constructs SQL queries using **string concatenation** of untrusted user input in three locations:
1. `backend/app/services/auth_service.py:signup()` — INSERT query with username, email, password
2. `backend/app/services/auth_service.py:login()` — SELECT query with username
3. `backend/app/api/routes/auth.py:search_user()` — SELECT query with search term (q parameter)

This fix replaces all string concatenation with **parameterized queries** (prepared statements) using sqlite3's `?` placeholder syntax, which separates SQL logic from data and guarantees that user input is treated as literal values rather than executable SQL. The fix closes **SQL injection vulnerabilities in all locations**; the other intentional vulnerabilities remain in place for educational use.

---

## 2. Scope & Non-Goals

### 2.1 In Scope

- Replace string concatenation in `auth_service.signup()` with parameterized queries.
- Replace string concatenation in `auth_service.login()` with parameterized queries.
- Replace string concatenation in `auth.py:search_user()` with parameterized queries.
- Preserve all existing function signatures, return types, and error behaviors.
- Maintain compatibility with the existing SQLite schema and connection layer.
- Ensure the fix works with the existing bcrypt-based password hashing (VULN-5 already closed).
- Ensure the fix works with the existing LIKE pattern matching in search.

### 2.2 Out of Scope (Intentionally Unfixed)

This fix is **surgical** and addresses only SQL injection vulnerabilities. The following intentional vulnerabilities remain in place after this fix and MUST NOT be remediated in the same change:

| # | Vulnerability | Status under this fix |
|---|---------------|-----------------------|
| **1** | **SQL Injection (all locations)** | **CLOSED by this spec** |
| 2 | Stored XSS (`{{username}}` substitution in dashboard) | Intentionally unchanged |
| 3 | Reflected XSS (`/search?q=` reflection) | Intentionally unchanged |
| 4 | Session Hijacking (hardcoded `"super-secret-key-12345"`) | Intentionally unchanged |
| 5 | Weak Password Storage | Already closed (bcrypt) — preserved |
| 6 | Exposed Database (`/download/db` open endpoint) | Intentionally unchanged |
| 7 | No Rate Limiting | Intentionally unchanged |
| 8 | CSRF (no tokens) | Intentionally unchanged |

### 2.3 Explicit Preservation Note

All other intentional vulnerabilities MUST remain unchanged:
- VULN-2: No escaping of `{{username}}` in dashboard
- VULN-3: No escaping of `q` query parameter in `/search` (XSS remains, only SQLi is fixed)
- VULN-4: Session secret remains `"super-secret-key-12345"`
- VULN-6: `/download/db` remains unauthenticated
- VULN-7: No rate limiting middleware added
- VULN-8: No CSRF tokens added to forms

---

## 3. Affected Files

The fix MUST touch only the following two files. No other repository file may be created or modified.

| Path | Change Type | Purpose |
|------|-------------|---------|
| `backend/app/services/auth_service.py` | Modified | Replace string concatenation with parameterized queries in `signup()` and `login()` |
| `backend/app/api/routes/auth.py` | Modified | Replace string concatenation with parameterized query in `search_user()` |

Files that MUST NOT be modified by this change:

- `backend/app/core/security.py` (bcrypt implementation — VULN-5 already closed, must remain)
- `backend/app/main.py` (session middleware secret — preserves VULN-4).
- `backend/app/db/session.py` (schema and connection layer — no changes needed).
- `backend/pyproject.toml`, `pyproject.toml` (no new dependencies).
- Any HTML template under `frontend/templates/` or CSS under `frontend/static/`.
- `CLAUDE.md`, `docs/PRD.md`, `docs/TDD.md`.

---

## 4. Functional Requirements

### FR-01: Parameterized Query in signup()

- `signup()` MUST construct the `INSERT` query using parameterized syntax:
  - Query template: `INSERT INTO users (username, email, password) VALUES (?, ?, ?)`
  - Values passed via `conn.execute(query, [username, email, hashed])` (or equivalent tuple/list)
- No string concatenation MAY appear in the query construction.
- The function's return values, error handling, and control flow MUST remain identical to the current implementation.

### FR-02: Parameterized Query in login()

- `login()` MUST construct the `SELECT` query using parameterized syntax:
  - Query template: `SELECT * FROM users WHERE username = ?`
  - Values passed via `conn.execute(query, [username])` (or equivalent)
- No string concatenation MAY appear in the query construction.
- The function's return values, error handling, and control flow MUST remain identical to the current implementation.

### FR-03: Parameterized Query in search_user()

- `search_user()` MUST construct the `SELECT` query using parameterized syntax:
  - Query template: `SELECT username, email FROM users WHERE username LIKE ? OR email LIKE ?`
  - Values passed via `conn.execute(query, [f"%{q}%", f"%{q}%"])` (or equivalent)
- The `%` wildcard characters for LIKE matching MUST be added to the parameter values, not the query template.
- No string concatenation MAY appear in the query construction.
- The function's return values, error handling, and control flow MUST remain identical to the current implementation.

### FR-04: Error Behavior Preservation

- `signup()` MUST continue to return `HTMLResponse` with HTTP 400 for:
  - Missing fields
  - `sqlite3.IntegrityError` (username already exists)
  - Any other exception
- `login()` MUST continue to return `JSONResponse` with HTTP 401 for:
  - Missing fields
  - Database errors
  - Invalid credentials (no user found or password mismatch)
- `search_user()` MUST continue to return `HTMLResponse` with:
  - HTTP 200 and results HTML when query succeeds
  - HTTP 200 with "No search query provided" message when `q` is empty
  - HTTP 200 with error message when database exception occurs

### FR-05: Session Behavior

- `login()` MUST continue to set the same three session keys on successful authentication:
  - `request.session["user_id"] = user["id"]`
  - `request.session["username"] = user["username"]`
  - `request.session["email"] = user["email"]`
- The redirect URL `/welcome` and success JSON structure MUST remain unchanged.

### FR-06: Password Verification

- `login()` MUST continue to call `verify_password(password, user["password"])` for password comparison.
- The bcrypt-based verification (VULN-5 already closed) MUST remain untouched.

### FR-07: LIKE Pattern Preservation

- The search functionality MUST continue to perform partial matching using the `LIKE` operator.
- The `%` wildcard MUST be added to both sides of the search term (e.g., `%term%`).
- Search results MUST be identical to the pre-fix implementation for valid inputs.

### FR-08: Response Format Preservation

- The search HTML response format MUST remain unchanged:
  - `<h3>Search results for: {q}</h3><ul>{results}</ul>`
  - Each result as `<li>{username} ({email})</li>`
- The query parameter `q` MUST still be reflected in the response (preserves VULN-3 Reflected XSS).

---

## 5. Non-Functional Requirements

### NFR-01: SQL Injection Immunity

- All user input MUST be treated as literal values by the database engine in all three locations.
- No SQL keywords or operators injected via user input can alter any query structure.
- A payload like `admin' OR '1'='1' --` MUST result in a literal lookup in signup, login, or search.
- No SQL injection can occur in any location after the fix.

### NFR-02: API Stability

- The public signatures of `signup()`, `login()`, and `search_user()` MUST remain byte-identical.
- All callers continue to work without modification.

### NFR-03: Surgical Scope

- Exactly SQL injection vulnerabilities are closed by this change.
- The diff MUST NOT touch session secrets, CSRF posture, XSS escape logic, rate limiting, or the `/download/db` route.

### NFR-04: Backward Compatibility

- Existing user accounts in `vulnerable_app.db` continue to work without migration.
- The bcrypt password hashes already in the database continue to verify correctly.
- Search functionality continues to work identically for valid inputs.

### NFR-05: Performance

- Parameterized queries incur no measurable performance penalty; the fix is a drop-in replacement for string concatenation.

### NFR-06: Error Information Leakage

- The error messages and HTTP status codes MUST remain exactly the same as before.
- No new information is leaked about the internal query structure or validation failures.

---

## 6. Success Paths

### SP-01: Successful Signup

1. User submits signup form with `username=alice`, `email=alice@test.com`, `password=pass123`.
2. `auth_service.signup()` executes parameterized `INSERT` query.
3. Row is inserted into `users` table.
4. Server returns `RedirectResponse` to `/login` (HTTP 302).

### SP-02: Successful Login

1. User submits login form with `username=alice`, `password=pass123`.
2. `auth_service.login()` executes parameterized `SELECT WHERE username = ?` query.
3. Row is fetched and `verify_password()` returns `True`.
4. Session is populated with user data.
5. Server returns JSON `{"success": true, "redirect": "/welcome"}` (HTTP 200).

### SP-03: Successful Search

1. User requests `GET /search?q=alice`.
2. `search_user()` executes parameterized `SELECT WHERE username LIKE ? OR email LIKE ?` query.
3. Rows matching the pattern are fetched.
4. Server returns HTML with results list.

### SP-04: Login with SQL Injection Payload

1. Attacker submits login with `username=admin' OR '1'='1' --`, `password=anything`.
2. The parameterized query treats the entire payload as a literal username string.
3. No user with that literal username exists in the database.
4. Server returns JSON 401 with `{"error": "Invalid username or password"}`.
5. **No authentication bypass occurs.**

### SP-05: Signup with SQL Injection Payload

1. Attacker submits signup with `username=test', 'test@test.com', 'hash') --`, etc.
2. The parameterized query treats the entire payload as a literal username.
3. Either the `INSERT` succeeds with that literal username (malformed but harmless) or fails validation.
4. **No SQL injection occurs; no data exfiltration or corruption.**

### SP-06: Search with SQL Injection Payload

1. Attacker requests `GET /search?q=test' OR '1'='1' --`.
2. The parameterized query treats the entire payload as a literal search term.
3. The query searches for users matching the literal string `test' OR '1'='1' --`.
4. No results are returned (no user has that literal string in username or email).
5. **No SQL injection occurs; no data exfiltration.**

### SP-07: Empty Query

1. User requests `GET /search` (no `q` parameter).
2. `search_user()` returns HTML with "No search query provided" message.
3. Behavior is identical to pre-fix implementation.

---

## 7. Edge Cases

### EC-01: Single Quote in Username

- A user registers with username `o'neill` (contains a literal apostrophe).
- The parameterized query in signup handles the quote correctly without escaping.
- Signup succeeds and login with `username=o'neill` succeeds.
- Search for `q=o'neill` returns matching results.

### EC-02: SQL Keywords in Input

- A user attempts to register with username `admin; DROP TABLE users; --`.
- The parameterized query treats it as a literal string.
- Either signup succeeds with that literal username (allowed by schema) or fails validation.
- **No table is dropped.**

### EC-03: NULL Character in Input

- Input containing a null byte (`\x00`) is passed to any of the parameterized queries.
- SQLite's parameterized binding handles null bytes as literal characters.
- No injection or buffer overflow occurs in any location.

### EC-04: Empty String Parameters

- `username=""` with valid password results in the parameterized query looking for an empty string.
- No user matches, resulting in HTTP 401.
- Behavior is identical to pre-fix implementation.

### EC-05: Very Long Input

- Input exceeding typical field lengths (e.g., 10,000-character username) is passed to any parameterized query.
- SQLite's `TEXT` column type accommodates the input.
- No injection vector exists regardless of length in any location.

### EC-06: Unicode Input

- User registers with `username=日本語`, `email=test@example.com`, `password=パスワード`.
- All parameterized queries handle UTF-8 encoding correctly.
- Signup, login, and search all succeed.

### EC-07: Special Characters in Search Query

- User searches for `q=%` (literal percent sign).
- The parameterized query treats it as a literal character, not a wildcard.
- Search succeeds and returns matching results.

---

## 8. Acceptance Criteria

### AC-01: signup() Uses Parameterized Query

- The `signup()` function contains a query string with `?` placeholders.
- The query is executed with a list/tuple of values, not via concatenation.

### AC-02: login() Uses Parameterized Query

- The `login()` function contains a query string with `?` placeholders.
- The query is executed with a list/tuple of values, not via concatenation.

### AC-03: search_user() Uses Parameterized Query

- The `search_user()` function contains a query string with `?` placeholders.
- The query is executed with a list/tuple of values, not via concatenation.

### AC-04: LIKE Pattern Preserved

- The search query uses `LIKE` operator with `?` placeholders.
- The `%` wildcards are added to the parameter values, not the query template.

### AC-05: No String Concatenation in Any Query

- `grep` for query construction shows no `+` or `f"` string concatenation with user input in any file.

### AC-06: SQL Injection Payload Fails in All Locations

- Attempting to log in with `username=admin' OR '1'='1' --` returns HTTP 401.
- Attempting to signup with SQL injection payload creates harmless user or fails validation.
- Attempting to search with SQL injection payload returns no results.
- No SQL injection can occur in any location.

### AC-07: Normal Signup Still Works

- A new user can successfully register via `/signup`.
- The user can then log in and access `/welcome`.

### AC-08: Normal Login Still Works

- Existing user accounts can log in successfully.
- Session data is set correctly.

### AC-09: Normal Search Still Works

- A search for an existing user returns matching results.
- The HTML response format is unchanged.

### AC-10: Error Messages Preserved

- All error responses have identical text and HTTP status codes as before.
- No new information is leaked.

### AC-11: Other Vulnerabilities Preserved

- VULN-2 (Stored XSS): Registering `<script>alert(1)</script>` still triggers script execution.
- VULN-3 (Reflected XSS): `/search?q=<script>alert(1)</script>` still reflects unescaped (XSS preserved, only SQLi fixed).
- VULN-4 (Session secret): `"super-secret-key-12345"` still present in `main.py`.
- VULN-6 (Exposed DB): `/download/db` still serves SQLite file unauthenticated.
- VULN-7 (No rate limit): No throttling middleware added.
- VULN-8 (No CSRF): No CSRF tokens added to forms.

### AC-12: Affected Files Limited

- Only `backend/app/services/auth_service.py` and `backend/app/api/routes/auth.py` are modified.
- No other files appear in `git status`.

---

## 9. Test Cases

| ID | Scenario | Precondition | Expected Result |
|----|----------|--------------|-----------------|
| TC-01 | Normal signup succeeds | Empty DB | User created, redirect to `/login` |
| TC-02 | Normal login succeeds | User `alice` exists with known password | HTTP 200, success JSON, session set |
| TC-03 | SQLi payload in login fails | User `alice` exists | `username=alice' OR '1'='1' --` returns HTTP 401 |
| TC-04 | SQLi payload in signup fails | Empty DB | `username=test', 'x@x', 'hash') --` creates harmless user or fails validation; no injection |
| TC-05 | SQLi payload in search fails | Any DB state | `q=test' OR '1'='1' --` returns no results; no injection |
| TC-06 | Single quote in username works | Empty DB | `username=o'neill` registers, logs in, and searches successfully |
| TC-07 | SQL keywords in input handled | Empty DB | `username=admin; DROP TABLE users; --` either creates user with literal name or fails; no table dropped |
| TC-08 | Empty username returns 401 | Any DB state | `username=""`, valid password returns HTTP 401 |
| TC-09 | Wrong password returns 401 | User exists | HTTP 401 with standard error JSON |
| TC-10 | Unknown username returns 401 | Any DB state | HTTP 401 with standard error JSON |
| TC-11 | Duplicate username returns 400 | User exists | HTTP 400 with "Username already exists" HTML |
| TC-12 | Unicode input works | Empty DB | `username=日本語`, UTF-8 password registers, logs in, and searches successfully |
| TC-13 | Very long input handled | Empty DB | 10,000-char username either succeeds or fails validation; no injection in any location |
| TC-14 | Normal search succeeds | User `alice` exists | `GET /search?q=alice` returns HTML with alice's info |
| TC-15 | Partial matching works | User `alice@example.com` exists | `q=alice` returns alice's result (LIKE %alice%) |
| TC-16 | Empty search query returns message | Any DB state | `GET /search` (no q) returns "No search query provided" |
| TC-17 | Special characters in search work | User with special chars exists | `q=%` returns matching results (literal %) |
| TC-18 | Stored XSS still fires (VULN-2 preserved) | App running | Register `<img src=x onerror=alert(1)>`, log in, visit `/welcome` → alert fires |
| TC-19 | Reflected XSS still fires (VULN-3 preserved) | App running | `/search?q=<script>alert(1)</script>` reflects payload |
| TC-20 | Session secret unchanged (VULN-4 preserved) | App running | `grep 'super-secret-key-12345' backend/app/main.py` matches |
| TC-21 | `/download/db` still open (VULN-6 preserved) | App running | Unauthenticated GET returns HTTP 200 with SQLite file |
| TC-22 | No CSRF tokens (VULN-8 preserved) | App running | HTML forms lack `csrf_token` input |
| TC-23 | No rate limiting (VULN-7 preserved) | App running | Repeated requests not throttled |

---

## 10. Verification Steps

Run from the repository root.

### 10.1 Start the Application

```bash
uv run backend/app/main.py
```

The server listens on `http://localhost:3001`.

### 10.2 Functional Walkthrough

1. **Register a user** — `http://localhost:3001/signup`
   - Submit `username=alice`, `email=alice@test.com`, `password=pass123`.
   - Expect a redirect to `/login`.

2. **Verify user created**
   ```bash
   sqlite3 vulnerable_app.db "SELECT username FROM users WHERE username='alice';"
   ```
   Expected: returns `alice`.

3. **Successful login** (TC-02)
   ```bash
   curl -s -i -X POST http://localhost:3001/login \
        --data-urlencode 'username=alice' \
        --data-urlencode 'password=pass123'
   ```
   Expected: HTTP 200, body `{"success": true, "redirect": "/welcome"}`.

4. **Successful search** (TC-14)
   ```bash
   curl -s 'http://localhost:3001/search?q=alice'
   ```
   Expected: HTML with alice's username and email.

### 10.3 SQL Injection Payload Tests

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

### 10.4 Edge Case Tests

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

### 10.5 Vulnerability Preservation Walkthrough

```bash
# VULN-2: Stored XSS still fires (TC-18)
curl -s -i -X POST http://localhost:3001/signup \
     --data-urlencode 'username=<img src=x onerror=alert(1)>' \
     --data-urlencode 'email=xss@x' \
     --data-urlencode 'password=p'
# Then log in and visit /welcome in a browser — alert should fire.

# VULN-3: Reflected XSS (TC-19) — XSS preserved, only SQLi fixed
curl -s 'http://localhost:3001/search?q=<script>alert(1)</script>' | grep -o '<script>alert(1)</script>'
# Expected: payload found in response (XSS still works).

# VULN-4: Session secret unchanged (TC-20)
grep -n 'super-secret-key-12345' backend/app/main.py
# Expected: matches a line.

# VULN-6: /download/db still open (TC-21)
curl -s -o /tmp/dl.db -w 'status=%{http_code}\n' http://localhost:3001/download/db
file /tmp/dl.db
# Expected: status=200, file is SQLite database.

# VULN-8: No CSRF tokens (TC-22)
curl -s http://localhost:3001/login | grep -i csrf || echo 'No CSRF token (preserved)'
curl -s http://localhost:3001/signup | grep -i csrf || echo 'No CSRF token (preserved)'
# Expected: no CSRF token fields.
```

### 10.6 Code Inspection

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

### 10.7 Affected-Files Audit

```bash
git status --porcelain
```

Expected output — exactly two modified files:

```
 M backend/app/services/auth_service.py
 M backend/app/api/routes/auth.py
```

---

## 11. Migration & Operational Note

This fix requires **no database migration or data changes**. Existing user accounts continue to work without modification because:

1. The SQLite schema is unchanged.
2. The bcrypt password hashes already in the database are unchanged.
3. The password verification logic (`verify_password()`) is unchanged.
4. The LIKE pattern matching behavior in search is preserved.

The only change is how queries are constructed at runtime in all three locations. After deploying this change:

- No user action is required.
- Existing users can log in with their existing credentials.
- New users can sign up and log in normally.
- Search functionality works identically for valid inputs.
- SQL injection attacks are neutralized in all locations.
- Reflected XSS vulnerability (VULN-3) remains intact for educational purposes.