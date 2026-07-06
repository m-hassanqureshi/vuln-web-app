# Software Specification Document — Admin Control Panel (RBAC)

**Version:** 1.0.0
**Last Updated:** 2026-07-06
**Target Release Tag:** v2.2.0
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md), [database-backed-sessions.md](./database-backed-sessions.md)

---

## 1. Overview / Purpose

This document specifies the **Admin Control Panel (RBAC)** enhancement. It is the post-v2.1.0 feature adding role-based access control (RBAC) to segment administrative actions from standard user paths.

Previously, all authenticated accounts had identical access scopes. The Admin Control Panel provides an administrative dashboard (`/admin`) to monitor and manage user accounts and security configurations.

---

## 2. Scope & Technical Requirements

### 2.1 Role-Based Access Control (RBAC)
- A `role` column on the `users` table distinguishes `'admin'` from `'user'`.
- Access to `/admin` and related actions is strictly verified in the database on every request. Client-side claims are never trusted.
- Unauthorized attempts return an HTTP `403 Forbidden` response.

### 2.2 Control Actions
- **User List**: Displays registered user accounts, roles, verification states, 2FA status, and count of active sessions.
- **Toggle Role**: Promotes standard users to admins or demotes admins. Self-demotion is strictly blocked to prevent locking out the last administrator.
- **Revoke Sessions**: Deletes all active sessions for a target user from the `sessions` table, triggering an immediate logout on their devices.
- **Delete User**: Permanently deletes a user record and cascaded relations (e.g. sessions) from the database. Self-deletion is blocked.

### 2.3 Integration & Security
- Forms carry the per-session `csrf_token` input validated by `CSRFMiddleware`.
- Administrative changes are logged immediately via the security audit logger.
