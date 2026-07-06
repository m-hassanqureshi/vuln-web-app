# Software Specification Document — Password Reset Flow ("Forgot Password")

**Version:** 1.0.0
**Last Updated:** 2026-07-06
**Target Release Tag:** v2.0.1
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md)

---

## 1. Overview / Purpose

This document specifies the **Password Reset Flow ("Forgot Password")** enhancement. It is the post-v2.0.0 addition to enable users to recover their accounts securely if they forget their password.

To ensure high-grade security, the design mitigates several classic password-reset vulnerabilities:
1. **Predictive Reset Tokens**: Replaces simple/sequential tokens with high-entropy cryptographic tokens.
2. **Host Header Injection**: Mitigates link hijacking by generating reset links using the server's configured `APP_BASE_URL` rather than the request's `Host` header.
3. **Token Reuse / Multi-use**: Enforces single-use tokens by clearing the reset token from the database immediately upon successful validation or validation attempt.
4. **Token Leakage via Referrer**: Restricts referrer leakage using appropriate metadata headers.

---

## 2. Scope & Technical Requirements

### 2.1 Schema Definition
The `users` table gains two new columns:
- `reset_token TEXT` (nullable; stores the active reset capability token).
- `reset_token_expires REAL` (nullable; epoch timestamp after which the token is invalid).

### 2.2 Password Reset Service (`password_reset_service.py`)
- `request_reset(username_or_email, request)`:
  - Looks up the user by username or email using a **parameterized** query.
  - Generates a cryptographically secure token using `secrets.token_urlsafe(32)`.
  - Sets token TTL to **1 hour** (`3600 seconds`) and commits to the database.
  - Generates the reset link: `{APP_BASE_URL}/reset-password?token={token}`.
  - Emails the link to the user via SendGrid mailer.
  - Returns a generic message to prevent username enumeration: `"If that account exists, a reset link has been sent."`
- `verify_reset_token(token)`:
  - Queries the database for the active token.
  - Compares expiration time against `time.time()`.
- `reset_password(token, new_password, request)`:
  - Validates token active status.
  - Enforces password complexity rules (length ≥ 8, uppercase, lowercase, digit, special character).
  - Updates password hash (bcrypt) and **clears the reset token columns** (setting them to `NULL`).
  - Resets the account lockout counter (`failed_login_attempts = 0` and `locked_until = NULL`) so users can log back in immediately.

### 2.3 Endpoints & Views
- `GET /forgot-password` and `POST /forgot-password`.
- `GET /reset-password` and `POST /reset-password`.
- Forms are CSRF-protected and rate-limited.
