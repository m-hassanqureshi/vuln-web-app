# Implementation Plan — Sanitized Security Audit Logging

This document details the step-by-step plan for implementing the security audit logger.

---

## 1. Centralized Logger Creation

Create `backend/app/core/audit_logger.py` defining:
- `RotatingFileHandler` writing to `security_audit.log`.
- `sanitize_log_input(value: str) -> str` escaping `\r` and `\n` to `\\r` and `\\n`.
- `log_auth_event()`, `log_security_event()`, and `log_file_event()` wrapping sanitizers.

---

## 2. proposed Changes

### Integration Points:
- **Signup / Email Verification resend**: Log signup start, verification token issuance, email delivery results.
- **Login (Standard, OTP, TOTP, Google OAuth, QR)**: Log login attempts, successes, 2FA prompt challenges, failures, lockouts.
- **Password Reset**: Log reset requests, email delivery, and successful resets.
- **Avatar Upload**: Log filenames, size checks, and outcome status.
- **Admin Control Panel**: Log role modifications, session revocations, and user deletions.
- **Logout**: Log session destruction events.

---

## 3. Verification Plan
- Attempt to sign up or log in with carriage return characters inside the username field.
- Verify that the resulting log line in `security_audit.log` displays the escaped `\r` and `\n` characters on a single line instead of creating a new log line.
