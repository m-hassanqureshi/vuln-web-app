# Implementation Plan — Database-Backed Session Store & Active Sessions List

This document details the step-by-step plan for implementing database-backed sessions.

---

## 1. Schema Definition

In `backend/app/db/session.py`, add:

```sql
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    user_agent TEXT,
    ip_address TEXT,
    created_at REAL NOT NULL,
    last_activity REAL NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
```

---

## 2. Proposed Changes

### `backend/app/services/session_service.py` [NEW]
- Helper functions to execute parameterized SQL for sessions.
- User-Agent parser via simple regular expressions.
- Central `establish_session(request, user_id, username, email)` helper.

### `backend/app/main.py` [MODIFY]
- Create and register `verify_db_session_middleware` inside `app`.
- Bypasses check on public static assets and auth paths.

### `backend/app/api/routes/auth.py` [MODIFY]
- Update `/logout` to delete session from DB first.
- Update `/profile` GET route to query active sessions and serialize them.
- Add `/profile/sessions/revoke` and `/profile/sessions/revoke-all` POST handlers.

### `frontend/templates/profile.html` [MODIFY]
- Render "Active Sessions" card listing clean device/browser and activity times.
- Handle click handlers for revoke buttons.

---

## 3. Verification Plan

### Unit Tests
- Add a scratch test script `test_sessions.py` validating DB methods.

### Integration Tests
- Add a scratch integration script `test_session_endpoints.py` simulating middleware intercepts.
