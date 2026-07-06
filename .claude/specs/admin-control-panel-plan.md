# Implementation Plan — Admin Control Panel (RBAC)

This document details the step-by-step plan for implementing the Admin Control Panel.

---

## 1. Schema Definition

In `backend/app/db/session.py`, update `init_db()` to support the `role` column:

```sql
ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user';
```

---

## 2. Proposed Changes

### `backend/app/api/routes/auth.py` [MODIFY]
- Create `GET /admin` rendering `admin.html`. Perform database-level role check.
- Create `POST /admin/user/promote` to toggle user roles. Prevent self-demotion.
- Create `POST /admin/user/delete` to delete users. Prevent self-deletion.
- Create `POST /admin/user/revoke-sessions` to bulk delete target sessions.
- Expose "Admin Panel" navigation link on welcome dashboard and profile page for admin accounts.

### `frontend/templates/admin.html` [NEW]
- Main control layout featuring summary panels (user/session counts) and a table of registered users.
- Connect forms to revocation, deletion, and role toggle endpoints.

---

## 3. Verification Plan
- Sign in as standard user and verify `/admin` returns `403 Forbidden`.
- Sign in as admin user and verify access.
- Confirm session revocation, promotion, and deletion actions execute correctly.
