"""Audit logging service.

This module implements standardized, secure audit logging for security-sensitive
events (e.g. authentication, role changes, password resets, uploads).
It includes strict CRLF injection mitigation to prevent log forging.
"""

import os
import logging
from logging.handlers import RotatingFileHandler

# Set up path to security_audit.log in the workspace root
BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..")
LOG_FILE = os.path.abspath(os.path.join(BASE_DIR, "security_audit.log"))

# Create audit logger
audit_logger = logging.getLogger("security_audit")
audit_logger.setLevel(logging.INFO)
audit_logger.propagate = False # Do not propagate to main application logs

# File handler with rotation (max 10MB, keep 5 backups)
handler = RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=5, encoding="utf-8")
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
audit_logger.addHandler(handler)


def sanitize_log_input(value: str) -> str:
    """Sanitize all inputs to prevent CRLF log injection.

    Replaces Carriage Return (\r) and Line Feed (\n) characters with escaped
    variants (\\r and \\n) so they cannot break the log format or forge entries.
    """
    if value is None:
        return ""
    # Ensure it's a string
    val_str = str(value)
    return val_str.replace("\r", "\\r").replace("\n", "\\n")


def log_auth_event(event_type: str, username: str, ip_address: str, status: str, details: str = "") -> None:
    """Log an authentication event (signup, login, logout, lockout)."""
    clean_event = sanitize_log_input(event_type)
    clean_user = sanitize_log_input(username)
    clean_ip = sanitize_log_input(ip_address)
    clean_status = sanitize_log_input(status)
    clean_details = sanitize_log_input(details)
    
    msg = f"AUTH - Event: {clean_event} | User: {clean_user} | IP: {clean_ip} | Status: {clean_status}"
    if clean_details:
        msg += f" | Details: {clean_details}"
        
    audit_logger.info(msg)


def log_security_event(event_type: str, username: str, ip_address: str, details: str = "") -> None:
    """Log a security configuration or database modification event (reset request, reset success, 2fa, TOTP, RBAC, session revocation)."""
    clean_event = sanitize_log_input(event_type)
    clean_user = sanitize_log_input(username)
    clean_ip = sanitize_log_input(ip_address)
    clean_details = sanitize_log_input(details)
    
    msg = f"SECURITY - Event: {clean_event} | User: {clean_user} | IP: {clean_ip}"
    if clean_details:
        msg += f" | Details: {clean_details}"
        
    audit_logger.info(msg)


def log_file_event(event_type: str, username: str, filename: str, ip_address: str, status: str, details: str = "") -> None:
    """Log file upload events (avatar uploads)."""
    clean_event = sanitize_log_input(event_type)
    clean_user = sanitize_log_input(username)
    clean_file = sanitize_log_input(filename)
    clean_ip = sanitize_log_input(ip_address)
    clean_status = sanitize_log_input(status)
    clean_details = sanitize_log_input(details)
    
    msg = f"FILE - Event: {clean_event} | User: {clean_user} | File: {clean_file} | IP: {clean_ip} | Status: {clean_status}"
    if clean_details:
        msg += f" | Details: {clean_details}"
        
    audit_logger.info(msg)
