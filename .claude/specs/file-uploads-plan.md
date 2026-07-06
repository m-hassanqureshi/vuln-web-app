# Implementation Plan — Secure File Uploads (Profile Pictures/Avatars)

This document details the step-by-step plan for implementing profile picture uploads.

---

## 1. Schema Definition

In `backend/app/db/session.py`, update `init_db()` to support the avatar picture field:

```sql
ALTER TABLE users ADD COLUMN picture TEXT;
```

---

## 2. Proposed Changes

### `backend/app/services/avatar_service.py` [NEW]
- Validations for file sizes, extensions, and magic byte headers.
- Safe file naming, disk storage, and database tracking.

### `backend/app/main.py` [MODIFY]
- Automatically create the static uploads directory and mount it to serve images:
  ```python
  app.mount("/static/uploads", StaticFiles(directory=UPLOADS_DIR), name="uploads")
  ```

### `backend/app/api/routes/auth.py` [MODIFY]
- Create `POST /profile/avatar` route verifying session and CSRF.
- Splicing the picture path into templates.

---

## 3. Verification Plan
- Attempt to upload a non-image file (e.g. `test.txt`) renamed to `test.png` and verify it is rejected via magic byte checks.
- Verify file sizes exceeding 2MB are rejected.
- Verify path traversal payloads (e.g. `../../test.png`) are sanitized and stripped.
