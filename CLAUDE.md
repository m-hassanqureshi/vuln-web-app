# CLAUDE.md

## Project Context

This is an **intentionally vulnerable web application** for security education. It originally shipped with 8 OWASP Top 10 vulnerabilities. One of them — VULN-5 (Weak Password Storage) — has since been closed by the `fix/bcrypt-password-hashing` branch. The other 7 remain intentionally exploitable for students to attack, understand, and remediate.

**WARNING:** The remaining 7 vulnerabilities are intentional. Do not "fix" them unless explicitly asked. The bcrypt password fix (VULN-5) is permanent — do not revert it.

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
├── main.py              # Entry point, middleware, static mounts
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
| 2 | Stored XSS | `backend/app/api/routes/auth.py` | Unescaped `{{username}}` in dashboard | Open |
| 3 | Reflected XSS | `backend/app/api/routes/auth.py` | Unescaped query param in search | Open |
| 4 | Session Hijacking | `backend/app/main.py` | Hardcoded secret `"super-secret-key-12345"` | Open |
| 5 | Weak Password | `backend/app/core/security.py` | Was MD5 (no salt); now bcrypt (`BCRYPT_ROUNDS = 12`); `verify_password` wraps `bcrypt.checkpw` in `try/except` so legacy MD5 rows return `False` instead of crashing | **Closed** |
| 6 | Exposed DB | `backend/app/api/routes/auth.py` | No auth on `/download/db` | Open |
| 7 | No Rate Limit | Global | No rate limiting middleware | Open |
| 8 | CSRF | Global | No CSRF tokens | Open |

### Login Flow After the Bcrypt Fix

`auth_service.login()` no longer matches the password hash inside SQL (bcrypt's per-call salt makes equality matching impossible). It now:

1. Builds `SELECT * FROM users WHERE username = '" + username + "'` — username branch is **still string-concatenated**, preventing SQL injection.
2. Calls `verify_password(password, row["password"])` in Python after `fetchone()`.
3. Returns the same JSON 401 for "no row," "bcrypt mismatch," and "legacy MD5 row" cases — no information leakage between them.

If a legacy MD5 hex digest exists in `vulnerable_app.db`, it cannot authenticate. Operators should `rm vulnerable_app.db` and re-register, or have affected users sign up fresh.

## Frontend-Backend Integration

- **Login**: `fetch()` POST → JSON response → client-side redirect
- **Signup**: Standard form POST → server redirect
- **Dashboard**: Server-side `str.replace('{{username}}', ...)` — no template engine
- **Theme**: Pure client-side. Each template's `<head>` runs a synchronous IIFE that reads `localStorage["theme"]` (or `prefers-color-scheme` as fallback) and sets `<html data-theme="light|dark">` before first paint. A `#theme-toggle` button in the shared header flips the attribute and persists the new value. No server round-trip, no session field, no backend coupling.

## Important Rules

- Always use parameterized queries in `auth_service.py` and `auth.py`. Never concatenate user-controlled input into SQL statements.` MUST stay even though the password match moved to Python.
- Never add CSRF tokens to forms (preserves VULN-8)
- Never change the session secret key (preserves VULN-4)
- Never add rate limiting middleware (preserves VULN-7)
- Never re-introduce MD5 or an "MD5 fallback" in `security.py`. Bcrypt is permanent; legacy MD5 rows must fail closed, not authenticate.
- Never escape `{{username}}` in the dashboard substitution or `q` in `/search` (preserves VULN-2, VULN-3)
- Never add auth to `/download/db` (preserves VULN-6)
- The dark-mode feature is purely frontend (CSS + 4 files: `styles.css`, `login.html`, `signup.html`, `dashboard.html`). Don't push theme state into the backend, the session, or the database.

## Specification Hierarchy

1. `docs/PRD.md` — Product requirements
2. `docs/TDD.md` — Technical design
3. `.claude/specs/app-foundation.md` — Foundation implementation specification
4. `.claude/specs/app-foundation-plan.md` — Foundation implementation plan
5. `.claude/specs/dark-mode-toggle.md` + `.claude/specs/dark-mode-toggle-plan.md` — Dark-mode feature
6. `.claude/specs/bcrypt-password-hashing.md` + `.claude/specs/bcrypt-password-hashing-plan.md` — VULN-5 fix

Prompts that generated each spec/plan/implementation live under `docs/prompts/`.
