"""Database-backed session service.

Handles active session management, creation, verification, and revocation.
"""

import time
import secrets
import logging
from app.db.session import get_db

logger = logging.getLogger(__name__)


def parse_user_agent(ua_string: str) -> str:
    """Parse User-Agent string to user-friendly Browser and OS name."""
    if not ua_string:
        return "Unknown Device"
    
    # Detect Operating System
    os_name = "Unknown OS"
    if "Windows" in ua_string:
        os_name = "Windows"
    elif "Macintosh" in ua_string or "Mac OS X" in ua_string:
        os_name = "macOS"
    elif "iPhone" in ua_string:
        os_name = "iOS"
    elif "iPad" in ua_string:
        os_name = "iPadOS"
    elif "Android" in ua_string:
        os_name = "Android"
    elif "Linux" in ua_string:
        os_name = "Linux"
        
    # Detect Browser
    browser_name = "Unknown Browser"
    if "Edg" in ua_string or "Edge" in ua_string:
        browser_name = "Edge"
    elif "Chrome" in ua_string and "Safari" in ua_string:
        browser_name = "Chrome"
    elif "Safari" in ua_string and "Chrome" not in ua_string:
        browser_name = "Safari"
    elif "Firefox" in ua_string:
        browser_name = "Firefox"
    elif "MSIE" in ua_string or "Trident" in ua_string:
        browser_name = "Internet Explorer"
        
    if browser_name == "Unknown Browser" and os_name == "Unknown OS":
        return ua_string[:40] + "..." if len(ua_string) > 40 else ua_string
        
    return f"{browser_name} on {os_name}"


def create_session(user_id: int, user_agent: str, ip_address: str) -> str:
    """Generate a fresh session_id and save to the database."""
    session_id = secrets.token_hex(16)
    now = time.time()
    
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO sessions (session_id, user_id, user_agent, ip_address, created_at, last_activity) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            [session_id, user_id, user_agent or "", ip_address or "", now, now]
        )
        conn.commit()
    except Exception:
        logger.exception("Failed to insert session into database for user_id=%s", user_id)
        raise RuntimeError("Database error while creating session.")
    finally:
        conn.close()
        
    return session_id


def verify_session(session_id: str) -> bool:
    """Check if the session_id exists and is active in the database.

    If valid, updates the last_activity timestamp.
    """
    if not session_id:
        return False
        
    conn = get_db()
    row = None
    try:
        row = conn.execute(
            "SELECT session_id FROM sessions WHERE session_id = ?",
            [session_id]
        ).fetchone()
        
        if row:
            # Update last activity
            conn.execute(
                "UPDATE sessions SET last_activity = ? WHERE session_id = ?",
                [time.time(), session_id]
            )
            conn.commit()
    except Exception:
        logger.exception("Failed to verify session_id=%s", session_id)
        return False
    finally:
        conn.close()
        
    return row is not None


def get_active_sessions(user_id: int) -> list[dict]:
    """Retrieve all active session records for a user."""
    conn = get_db()
    sessions = []
    try:
        rows = conn.execute(
            "SELECT session_id, user_agent, ip_address, created_at, last_activity "
            "FROM sessions WHERE user_id = ? ORDER BY last_activity DESC",
            [user_id]
        ).fetchall()
        
        for row in rows:
            sessions.append({
                "session_id": row["session_id"],
                "device_info": parse_user_agent(row["user_agent"]),
                "ip_address": row["ip_address"] or "Unknown IP",
                "created_at": row["created_at"],
                "last_activity": row["last_activity"]
            })
    except Exception:
        logger.exception("Failed to query active sessions for user_id=%s", user_id)
    finally:
        conn.close()
        
    return sessions


def revoke_session(session_id: str, user_id: int) -> bool:
    """Revoke a specific session for a user by deleting it from the database."""
    if not session_id:
        return False
        
    conn = get_db()
    try:
        cursor = conn.execute(
            "DELETE FROM sessions WHERE session_id = ? AND user_id = ?",
            [session_id, user_id]
        )
        conn.commit()
        return cursor.rowcount > 0
    except Exception:
        logger.exception("Failed to delete session_id=%s for user_id=%s", session_id, user_id)
        return False
    finally:
        conn.close()


def revoke_all_other_sessions(current_session_id: str, user_id: int) -> bool:
    """Revoke all sessions for a user EXCEPT the current session."""
    conn = get_db()
    try:
        conn.execute(
            "DELETE FROM sessions WHERE user_id = ? AND session_id != ?",
            [user_id, current_session_id]
        )
        conn.commit()
        return True
    except Exception:
        logger.exception("Failed to delete other sessions for user_id=%s", user_id)
        return False
    finally:
        conn.close()


def establish_session(request, user_id: int, username: str, email: str) -> None:
    """Centralized helper to create a database session and populate the Starlette session dict."""
    user_agent = request.headers.get("user-agent", "")
    ip_address = request.client.host if request.client else ""
    
    session_id = create_session(user_id, user_agent, ip_address)
    
    request.session["user_id"] = user_id
    request.session["username"] = username
    request.session["email"] = email
    request.session["session_id"] = session_id

