# Software Specification Document — Database-Backed Session Store & Active Sessions List

**Version:** 1.0.0
**Last Updated:** 2026-07-06
**Target Release Tag:** v2.1.0
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md)

---

## 1. Overview / Purpose

This document specifies the **Database-Backed Session Store & Active Sessions List** enhancement. It is the post-v2.0.0 addition to prevent session-hijacking (VULN-4) permanently by enabling server-side session invalidation, device tracking, and user-driven session revocation.

Before this change, the application relied solely on signed client-side cookies via Starlette's `SessionMiddleware`. Once issued, a session cookie remained valid until it expired naturally, with no way for a user to log out of other devices, audit active logins, or for the server to revoke access immediately.

This enhancement introduces a database-backed session tracker that:
1. **Tracks Active Logins**: Records every authenticated session in the database alongside user-agent details, client IP, and timestamps.
2. **Validates Every Request**: Intercepts requests using an ASGI middleware layer that verifies the cookie's `session_id` against the database. If revoked or deleted, it instantly clears the cookie and redirects to `/login`.
3. **Active Sessions UI**: Renders a list on the Profile page (`/profile`) showing friendly device descriptions (e.g., "Chrome on Windows"), client IP, and last activity timestamps.
4. **Revocation Controls**: Provides single-session revocation and a global "Revoke All Other Sessions" action.

---

## 2. Scope & Non-Goals

### 2.1 In Scope

- **Database Schema**: Add the `sessions` table in `backend/app/db/session.py` mapping:
  - `session_id TEXT PRIMARY KEY` (a high-entropy 32-character hex token).
  - `user_id INTEGER NOT NULL`.
  - `user_agent TEXT`.
  - `ip_address TEXT`.
  - `created_at REAL NOT NULL`.
  - `last_activity REAL NOT NULL`.
- **Session Service Layer**: Create `backend/app/services/session_service.py` to handle:
  - `create_session(user_id, user_agent, ip_address)`: Inserts a session record and returns the ID.
  - `verify_session(session_id)`: Checks active state and updates `last_activity` timestamps (sliding window).
  - `get_active_sessions(user_id)`: Retrieves active user sessions, parsing `User-Agent` strings into friendly names.
  - `revoke_session(session_id, user_id)`: Deletes a specific session.
  - `revoke_all_other_sessions(current_session_id, user_id)`: Deletes all user sessions except the current one.
  - `establish_session(request, user_id, username, email)`: Central helper to set both DB record and cookie keys.
- **ASGI Middleware Integration**: Register `verify_db_session_middleware` in `backend/app/main.py`:
  - Runs on all private endpoints, checking `session_id` validity in the database.
  - Bypasses public pages (`/login`, `/signup`, `/forgot-password`, `/reset-password`, `/auth/google`) to prevent redirect loops.
  - Clears cookies and redirects to `/login` when verification fails.
- **Endpoints & UI**:
  - Update authentication endpoints in `backend/app/api/routes/auth.py` (password login, registration verification, OTP/TOTP 2FA steps, Google OAuth callback, QR code status check) to use `establish_session`.
  - Add `/profile/sessions/revoke` and `/profile/sessions/revoke-all` POST routes.
  - Fetch active sessions and pass them serialized as a safe JSON block to `/profile`.
  - Render an "Active Sessions" HTML card on `profile.html` with friendly device descriptions, relative activity times (e.g. "Active 5m ago"), and revocation event handling.

### 2.2 Out of Scope
- **No persistent/remember-me checkbox**: Sessions maintain standard default expiration.
- **No geolocation tracking**: IP address is listed raw without looking up geographic data.
- **No background task for expired sessions cleanup**: Old database rows are cleaned up on new session creation or manual revocation.

---

## 3. Technical Requirements & Security Rules

### 3.1 Session Entropy & Signature
- The `session_id` must use `secrets.token_hex(16)` (256-bit cryptographically secure token).
- The `SessionMiddleware` remains active as the signature layer; the cookie itself is signed and secure.

### 3.2 Output Encoding & Injection Prevention
- The User-Agent parser output (`device_info`) must be handled as untrusted data. When rendering in `profile.html`, it must be set via `textContent` in DOM elements to prevent Stored XSS.
- All database operations in `session_service.py` must use parameterized SQLite placeholders (`?`) to prevent SQL Injection.

### 3.3 CSRF & Rate Limiting
- The `/profile/sessions/revoke` and `/profile/sessions/revoke-all` POST endpoints must require the `X-CSRF-Token` header, aligned with the synchronizer-token CSRF architecture (VULN-8).
- Revocation forms must be routed through the rate limiter (VULN-7).
