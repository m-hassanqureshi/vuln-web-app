# Software Specification Document — Secure File Uploads (Profile Pictures/Avatars)

**Version:** 1.0.0
**Last Updated:** 2026-07-06
**Target Release Tag:** v2.0.2
**Parent Documents:** [PRD.md](../../docs/PRD.md), [TDD.md](../../docs/TDD.md), [app-foundation.md](./app-foundation.md), [user-profile-page.md](./user-profile-page.md)

---

## 1. Overview / Purpose

This document specifies the **Secure File Uploads (Profile Pictures/Avatars)** enhancement. It is the post-v2.0.1 addition to support custom profile images while mitigating unrestricted file upload vulnerabilities.

Unrestricted uploads present significant risks, including:
1. **Remote Code Execution (RCE)**: Attackers upload executable code (e.g. PHP/ASP) if files are saved in executable directories.
2. **Stored Cross-Site Scripting (XSS)**: Attackers upload SVGs containing malicious HTML/JS or files served with unsafe MIME-types.
3. **Path Traversal / Arbitrary File Overwrite**: Attackers manipulate the filename (e.g. `../../main.py`) to overwrite system or source code files.
4. **Denial of Service**: Uploading extremely large files to exhaust server storage.

---

## 2. Scope & Technical Requirements

### 2.1 Schema Definition
The `users` table gains a new column:
- `picture TEXT` (nullable; stores the filename or URL of the avatar image).

### 2.2 Upload Validation Service (`avatar_service.py`)
- **File Size**: Rejects uploads larger than **2MB** (`2 * 1024 * 1024 bytes`).
- **Filename Sanitization**: Ignores user-provided filenames to prevent Path Traversal. Files are saved as `avatar_{user_id}_{random_hex}.{ext}` where `{ext}` is strictly validated.
- **MIME-Type Check**: Restricts inputs to `image/png`, `image/jpeg`, `image/jpg`, or `image/gif`.
- **Magic Bytes Validation**: Verifies the file's binary header matches PNG (`\x89PNG\r\n\x1a\n`), JPEG (`\xff\xd8\xff`), or GIF (`GIF87a`/`GIF89a`) signatures to prevent file extension spoofing.
- **Disk Management**: Deletes the user's previously uploaded avatar file from the disk upon a successful new upload to prevent storage bloat.

### 2.3 Endpoints & UI
- `POST /profile/avatar` handles the file stream (authenticated and CSRF-protected via header check).
- The profile dashboard renders the user's current avatar image dynamically or falls back to a silhouette SVG placeholder.
- Image URLs are strictly served from the `static/uploads/` directory, mounted in `main.py` with static assets.
