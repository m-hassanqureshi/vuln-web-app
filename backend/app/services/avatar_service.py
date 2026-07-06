"""Profile picture upload service (avatar validation and storage).

This service implements strict security checks to prevent file upload vulnerabilities
(e.g., Remote Code Execution, path traversal, arbitrary file writes, XSS in images).
"""

import os
import secrets
import logging
from app.db.session import get_db

logger = logging.getLogger(__name__)

# Absolute path to frontend/static/uploads
BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..")
UPLOADS_DIR = os.path.join(BASE_DIR, "frontend", "static", "uploads")

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB

ALLOWED_MIMES = {
    "image/png": "png",
    "image/jpeg": "jpg",
    "image/gif": "gif"
}

# Image signatures (magic bytes)
SIGNATURES = {
    "png": [b"\x89PNG\r\n\x1a\n"],
    "jpg": [b"\xff\xd8\xff"],
    "gif": [b"GIF87a", b"GIF89a"]
}


def save_avatar(user_id: int, file_data: bytes, client_filename: str, content_type: str, request = None) -> dict:
    """Validate and store a user avatar upload.

    Security Mitigations:
    1. Limit file size to 2MB.
    2. Enforce strict MIME-type allowlist (PNG, JPEG, GIF).
    3. Verify file signature (magic bytes) to ensure renamed scripts are rejected.
    4. Generate a fresh, unique, server-determined filename (ignores client input completely).
    5. Clean up old avatar files to prevent disk bloating.
    """
    from app.core import audit_logger
    ip = request.client.host if request and request.client else ""

    # Fetch user info (username and current picture for cleanup)
    conn = get_db()
    username = f"user_{user_id}"
    old_filename = None
    try:
        row = conn.execute("SELECT username, picture FROM users WHERE id = ?", [user_id]).fetchone()
        if row:
            username = row["username"]
            old_filename = row["picture"]
    except Exception:
        logger.exception("Failed to query user info for user_id=%s", user_id)
    finally:
        conn.close()

    # 1. Size Check
    if len(file_data) > MAX_FILE_SIZE:
        audit_logger.log_file_event("avatar_upload", username, client_filename, ip, "failure", "File size exceeds 2MB")
        return {"status": "error", "error": "File size exceeds the 2MB limit."}
    if len(file_data) == 0:
        audit_logger.log_file_event("avatar_upload", username, client_filename, ip, "failure", "File is empty")
        return {"status": "error", "error": "File is empty."}

    # 2. MIME-type validation
    if content_type not in ALLOWED_MIMES:
        audit_logger.log_file_event("avatar_upload", username, client_filename, ip, "failure", f"Invalid content type: {content_type}")
        return {"status": "error", "error": "Invalid file type. Only PNG, JPEG, and GIF images are allowed."}
    
    ext = ALLOWED_MIMES[content_type]

    # 3. Magic bytes validation
    signature_matched = False
    for sig in SIGNATURES[ext]:
        if file_data.startswith(sig):
            signature_matched = True
            break
            
    if not signature_matched:
        audit_logger.log_file_event("avatar_upload", username, client_filename, ip, "failure", "Magic bytes mismatch")
        return {"status": "error", "error": "Invalid image data. File header does not match expected image type."}

    # 4. Generate unique filename: avatar_{user_id}_{token}.{ext}
    # This prevents path traversal and files overwriting other critical resources.
    token = secrets.token_hex(8)
    filename = f"avatar_{user_id}_{token}.{ext}"
    filepath = os.path.join(UPLOADS_DIR, filename)

    # 6. Save the new file to disk
    try:
        # Ensure uploads directory exists
        os.makedirs(UPLOADS_DIR, exist_ok=True)
        with open(filepath, "wb") as f:
            f.write(file_data)
    except Exception:
        logger.exception("Failed to write avatar file to disk: %s", filepath)
        audit_logger.log_file_event("avatar_upload", username, client_filename, ip, "failure", "Failed to write to disk")
        return {"status": "error", "error": "Failed to save file to disk."}

    # 7. Update database record
    conn = get_db()
    try:
        conn.execute("UPDATE users SET picture = ? WHERE id = ?", [filename, user_id])
        conn.commit()
    except Exception:
        logger.exception("Failed to update user picture in DB for user_id=%s", user_id)
        # Delete file if DB write failed to avoid orphaned files
        try:
            os.remove(filepath)
        except OSError:
            pass
        audit_logger.log_file_event("avatar_upload", username, client_filename, ip, "failure", "Database update failed")
        return {"status": "error", "error": "Database error while updating avatar."}
    finally:
        conn.close()

    # 8. Clean up old avatar file from disk if it exists
    if old_filename:
        old_filepath = os.path.join(UPLOADS_DIR, old_filename)
        if os.path.exists(old_filepath):
            try:
                os.remove(old_filepath)
            except OSError:
                logger.warning("Failed to clean up old avatar file: %s", old_filepath)

    audit_logger.log_file_event("avatar_upload", username, client_filename, ip, "success", f"Saved as {filename}")
    return {"status": "success", "filename": filename}
