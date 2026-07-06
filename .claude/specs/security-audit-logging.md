# Software Specification Document — Sanitized Security Audit Logging

**Version:** 1.0.0
**Last Updated:** 2026-07-06
**Target Release Tag:** v2.3.0
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md)

---

## 1. Overview / Purpose

This document specifies the **Sanitized Security Audit Logging** enhancement. It is the post-v2.2.0 addition to enable standardized audit trails for security-sensitive operations while mitigating CRLF log injection / log forgery vulnerabilities.

Security logging is vital for incident response and threat monitoring. However, writing unvalidated parameters directly to logs opens up a Log Injection vulnerability, where an attacker crafts carriage returns (`\r`) and line feeds (`\n`) in input parameters (such as usernames) to append fake log lines, forging events.

This enhancement introduces a centralized audit logging utility that:
1. **Sanitizes Inputs**: Automatically escapes carriage returns and line feeds into safe representation (`\r` -> `\\r`, `\n` -> `\\n`).
2. **Tracks Sensitive Events**: Hooks into all authentication states, privilege promotions, password resets, 2FA setups, and avatar uploads.
3. **Writes to Dedicated Security Log**: Output is written to a distinct `security_audit.log` file in the workspace root, separated from application debugger logs.

---

## 2. Technical Requirements

### 2.1 Logger Architecture
- Log output goes to `security_audit.log`.
- Log handler is a standard Python rotating file handler (`RotatingFileHandler`), restricted to 10MB file size and up to 5 backups.
- Formatting uses `%Y-%m-%d %H:%M:%S - LEVEL - message`.

### 2.2 CRLF Injection Mitigation
- The function `sanitize_log_input(value)` converts values to string and replaces any occurrences of `\r` and `\n` with escaped representations (`\\r` and `\\n`).
- Logging interfaces must wrap all untrusted values (usernames, filenames, IPs, details) in this sanitizer prior to logging.

### 2.3 Covered Events
- **Authentication**: Signups, logins, logouts, OTP challenges, TOTP verifications, and lockout thresholds.
- **Security & Authorization**: Password changes, password resets, role changes (promotions/demotions), session revocations.
- **Files**: Avatar uploads (recording username, file name, and status).
