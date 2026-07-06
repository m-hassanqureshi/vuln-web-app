# Implementation Plan — Password Reset Flow ("Forgot Password")

This document details the step-by-step plan for implementing the password reset flow.

---

## 1. Schema Definition

In `backend/app/db/session.py`, update `init_db()` to support password reset fields:

```sql
ALTER TABLE users ADD COLUMN reset_token TEXT;
ALTER TABLE users ADD COLUMN reset_token_expires REAL;
```

---

## 2. Proposed Changes

### `backend/app/services/password_reset_service.py` [NEW]
- Centralized validation rules for token issuance, email dispatch, and database clearance.
- Enforce the 5-point password strength policy on reset.

### `backend/app/api/routes/auth.py` [MODIFY]
- Register forgot and reset password routes.
- Forward requests to the `password_reset_service`.

### `frontend/templates/forgot_password.html` [NEW]
- Template containing the reset-request email input form.

### `frontend/templates/reset_password.html` [NEW]
- Password input forms with client-side password strength checker matching signup policies.

---

## 3. Verification Plan
- Request a password reset for a test account.
- Extract the token from the console/logs or database.
- Attempt to use the same token twice (verify it fails on the second attempt).
- Verify password strength checking works on reset.
