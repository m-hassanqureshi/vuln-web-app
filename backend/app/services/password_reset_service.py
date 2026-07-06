"""Password-reset business logic (token issue / verify / reset).

This module handles the database mutations and business rules for the Password Reset Flow.
"""

import logging
import secrets
import threading
import time

from starlette.requests import Request
from app.db.session import get_db
from app.core import config, mailer, audit_logger
from app.services.auth_service import password_meets_policy
from app.core.security import hash_password
from app.services import lockout_service

logger = logging.getLogger(__name__)


def request_reset(username_or_email: str, request: Request = None) -> dict:
    """Issue a fresh reset token for the given username or email and dispatch the link.

    Always returns a generic success status to prevent user enumeration attacks.
    If the account exists and uses local authentication, a token is issued and emailed.
    """
    if not username_or_email:
        ip = request.client.host if request and request.client else ""
        audit_logger.log_security_event("password_reset_request", "empty", ip, "failure: Empty username_or_email")
        return {"status": "ok", "message": "If the account exists, a password reset link has been sent."}

    # If email delivery is not configured, we let the route layer handle the gate page.
    if not config.is_email_configured():
        return {"status": "email_not_configured"}

    conn = get_db()
    row = None
    try:
        row = conn.execute(
            "SELECT id, username, email, auth_provider FROM users WHERE username = ? OR email = ?",
            [username_or_email, username_or_email]
        ).fetchone()
    except Exception:
        logger.exception("Failed to query user for password reset")
    finally:
        conn.close()

    # Issue token only if user exists and is a local auth user (Google users don't have passwords).
    if row and row["auth_provider"] == "local" and row["email"]:
        user_id = row["id"]
        username = row["username"]
        email = row["email"]
        token = secrets.token_urlsafe(32)
        expires = time.time() + config.PASSWORD_RESET_TTL_SECONDS

        conn = get_db()
        try:
            conn.execute(
                "UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?",
                [token, expires, user_id]
            )
            conn.commit()
        except Exception:
            logger.exception("Failed to update reset token for user_id=%s", user_id)
            ip = request.client.host if request and request.client else ""
            audit_logger.log_security_event("password_reset_request", username, ip, "failure: DB update failed")
            return {"status": "ok", "message": "If the account exists, a password reset link has been sent."}
        finally:
            conn.close()

        reset_url = f"{config.APP_BASE_URL}/reset-password?token={token}"

        # Send the email in a background thread to prevent blocking the HTTP response
        threading.Thread(
            target=mailer.send_password_reset_email,
            args=(email, username, reset_url),
            daemon=True
        ).start()

        ip = request.client.host if request and request.client else ""
        audit_logger.log_security_event("password_reset_request", username, ip, "success")
    else:
        ip = request.client.host if request and request.client else ""
        audit_logger.log_security_event("password_reset_request", username_or_email, ip, "ignored (user not found or oauth)")

    return {"status": "ok", "message": "If the account exists, a password reset link has been sent."}


def verify_reset_token(token: str) -> dict:
    """Validate a password reset token.

    Returns a dict containing the status and username/user_id on success.
    """
    if not token:
        return {"status": "invalid"}

    conn = get_db()
    row = None
    try:
        row = conn.execute(
            "SELECT id, username, reset_token_expires FROM users WHERE reset_token = ?",
            [token]
        ).fetchone()
    except Exception:
        logger.exception("Failed to query reset token")
        return {"status": "invalid"}
    finally:
        conn.close()

    if not row:
        return {"status": "invalid"}

    if row["reset_token_expires"] < time.time():
        return {"status": "expired"}

    return {"status": "ok", "username": row["username"], "user_id": row["id"]}


def reset_password(token: str, new_password: str, request: Request = None) -> dict:
    """Validate the token, verify password strength policy, hash, and update password."""
    verify_res = verify_reset_token(token)
    if verify_res["status"] != "ok":
        ip = request.client.host if request and request.client else ""
        audit_logger.log_security_event("password_reset_success", "unknown", ip, f"failure: token status: {verify_res['status']}")
        return verify_res

    username = verify_res["username"]
    if not new_password:
        ip = request.client.host if request and request.client else ""
        audit_logger.log_security_event("password_reset_success", username, ip, "failure: empty new password")
        return {"status": "policy_failed", "error": "Password cannot be empty."}

    if not password_meets_policy(new_password):
        ip = request.client.host if request and request.client else ""
        audit_logger.log_security_event("password_reset_success", username, ip, "failure: password policy failed")
        return {
            "status": "policy_failed",
            "error": "Password must be at least 8 characters long and contain at least one lowercase letter, one uppercase letter, one digit, and one special character."
        }

    user_id = verify_res["user_id"]
    hashed = hash_password(new_password)

    conn = get_db()
    try:
        # Update password and clear reset token columns
        conn.execute(
            "UPDATE users SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?",
            [hashed, user_id]
        )
        conn.commit()
    except Exception:
        logger.exception("Failed to update password for user_id=%s", user_id)
        ip = request.client.host if request and request.client else ""
        audit_logger.log_security_event("password_reset_success", username, ip, "failure: DB update failed")
        return {"status": "error", "error": "Database error while resetting password."}
    finally:
        conn.close()

    # Clear account lockouts so they can log in immediately
    lockout_service.reset(user_id)

    ip = request.client.host if request and request.client else ""
    audit_logger.log_security_event("password_reset_success", username, ip, "success")

    return {"status": "success", "message": "Password successfully reset. You can now log in."}
