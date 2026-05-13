"""Security utilities - CSRF, auth, path validation, URL sanitization."""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import logging
import os
import re
import secrets
import time
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

_CSRF_SECRET: bytes = secrets.token_bytes(32)

SAFE_FILENAME_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}-[a-zA-Z0-9\u4e00-\u9fa5-]+\.html$")

SAFE_URL_PROTOCOLS: set[str] = {
    "http", "https", "ftp", "ftps", "mailto", "tel", "sip", "sips",
    "news", "nntp", "telnet", "irc", "ircs", "gopher", "wais",
}
DANGEROUS_PROTOCOLS: set[str] = {
    "javascript", "data", "vbscript", "file", "about", "chrome",
    "chrome-extension", "ms-help", "ms-windows-store", "ms-settings",
    "jar", "rmi", "jndi", "ldap", "dns",
}


def escape_html(text: str) -> str:
    return html.escape(text, quote=True)


def escape_attr(text: str) -> str:
    return html.escape(text, quote=True).replace('"', '&quot;')


def generate_csrf_token() -> str:
    """Generate a secure CSRF token with HMAC signature."""
    random_bytes = secrets.token_bytes(16)
    timestamp = int(time.time()).to_bytes(4, "big")
    token_data = random_bytes + timestamp
    signature = hmac.new(_CSRF_SECRET, token_data, hashlib.sha256).digest()
    signed_token = token_data + signature
    return base64.urlsafe_b64encode(signed_token).decode("ascii")


def validate_csrf_token(environ: dict, token: str, admin_port: int = 8081, bind_domain: str = "") -> bool:
    """Validate CSRF token with double-submit cookie pattern."""
    client_ip = get_real_ip(environ)

    if not token or len(token) < 32:
        logger.warning(f"[CSRF-FAIL] Invalid token format from {client_ip}")
        return False

    try:
        signed_token = base64.urlsafe_b64decode(token.encode("ascii"))
        if len(signed_token) != 52:
            logger.warning(f"[CSRF-FAIL] Invalid token length from {client_ip}")
            return False

        token_data = signed_token[:20]
        signature = signed_token[20:]
        expected_sig = hmac.new(_CSRF_SECRET, token_data, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected_sig):
            logger.warning(f"[CSRF-FAIL] Invalid signature from {client_ip}")
            return False

        # Check timestamp (1 hour expiry)
        timestamp = int.from_bytes(token_data[16:20], "big")
        now = time.time()
        if now - timestamp > 3600 or timestamp > now + 60:
            logger.warning(f"[CSRF-FAIL] Token expired or future timestamp from {client_ip}")
            return False

        # Double-submit cookie check
        cookie_header = environ.get("HTTP_COOKIE", "")
        cookie_token = ""
        for cookie in cookie_header.split(";"):
            cookie = cookie.strip()
            if cookie.startswith("csrf_token="):
                cookie_token = cookie[11:]
                break

        if not cookie_token or not hmac.compare_digest(token, cookie_token):
            logger.warning(f"[CSRF-FAIL] Cookie mismatch from {client_ip}")
            return False

        # Origin/Referer check
        origin = environ.get("HTTP_ORIGIN", "")
        referer = environ.get("HTTP_REFERER", "")
        expected_hosts = [f"http://127.0.0.1:{admin_port}", f"http://localhost:{admin_port}"]
        if bind_domain:
            expected_hosts.extend([f"http://{bind_domain}", f"https://{bind_domain}"])

        if origin and origin.lower() != "null":
            if not any(origin.startswith(h) for h in expected_hosts):
                logger.warning(f"[CSRF-FAIL] Invalid Origin: {origin} from {client_ip}")
                return False
        if referer:
            if not any(referer.startswith(h) for h in expected_hosts):
                logger.warning(f"[CSRF-FAIL] Invalid Referer: {referer} from {client_ip}")
                return False

        return True
    except Exception as e:
        logger.error(f"[CSRF-ERROR] Validation failed from {client_ip}: {e}")
        return False


def get_csrf_cookie_header(token: Optional[str] = None) -> Tuple[str, str]:
    if token is None:
        token = generate_csrf_token()
    return ("Set-Cookie", f"csrf_token={token}; Path=/; HttpOnly; SameSite=Strict")


def get_real_ip(environ: dict) -> str:
    x_forwarded_for = environ.get("HTTP_X_FORWARDED_FOR", "")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    x_real_ip = environ.get("HTTP_X_REAL_IP", "")
    if x_real_ip:
        return x_real_ip.strip()
    return environ.get("REMOTE_ADDR", "unknown")


def validate_filename(filename: str) -> bool:
    if not SAFE_FILENAME_PATTERN.match(filename):
        return False
    try:
        parts = filename.split("-")
        if len(parts) < 4:
            return False
        year, month, day = int(parts[0]), int(parts[1]), int(parts[2])
        if not (2000 <= year <= 2100 and 1 <= month <= 12 and 1 <= day <= 31):
            return False
    except (ValueError, IndexError):
        return False
    return True


def validate_date_format(date_str: str) -> bool:
    if not re.match(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$", date_str):
        return False
    try:
        from datetime import datetime
        dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M")
        if not (2000 <= dt.year <= 2100):
            return False
    except ValueError:
        return False
    return True


def validate_content(content: str, max_length: int = 50000) -> bool:
    if not isinstance(content, str):
        return False
    if len(content) > max_length:
        return False
    if len(content.encode("utf-8")) > max_length * 4:
        return False
    control_chars = sum(1 for c in content if ord(c) < 32 and c not in "\t\n\r")
    if control_chars > len(content) * 0.1:
        return False
    return True


def safe_path_check(path_str: str, base_dir: Path) -> Tuple[bool, Optional[Path]]:
    """Resolve path and ensure it stays within base_dir."""
    try:
        base = base_dir.resolve()
        # Strip leading slash
        if path_str.startswith("/"):
            path_str = path_str[1:]
        target = (base / path_str).resolve()
        if not str(target).startswith(str(base)):
            logger.warning(f"[BLOCK] Path traversal: {path_str} -> {target}")
            return False, None
        safe_exts = {".html", ".xml", ".json", ".txt", ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff2"}
        if target.suffix.lower() not in safe_exts and target.is_file():
            logger.warning(f"[BLOCK] Unsafe file access: {path_str}")
            return False, None
        return True, target
    except Exception as e:
        logger.error(f"[ERROR] Path check failed: {e}")
        return False, None


def validate_url_protocol(url: str) -> bool:
    if not url or not isinstance(url, str):
        return False
    url_lower = url.lower().strip()
    if not url_lower:
        return False
    if url_lower.startswith("//"):
        return True
    colon_pos = url_lower.find(":")
    if colon_pos == -1:
        return True
    protocol = url_lower[:colon_pos].strip()
    if protocol in DANGEROUS_PROTOCOLS:
        logger.warning(f"[XSS-BLOCK] Dangerous protocol: {url}")
        return False
    if protocol in SAFE_URL_PROTOCOLS:
        return True
    logger.warning(f"[XSS-BLOCK] Unknown protocol: {url}")
    return False


def check_basic_auth(environ: dict, expected_user: str, expected_pass: str) -> bool:
    """Validate Basic Auth header using constant-time comparison."""
    auth_header = environ.get("HTTP_AUTHORIZATION", "")
    if not auth_header.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(auth_header[6:], validate=True).decode("utf-8", errors="strict")
    except Exception:
        return False
    if ":" not in decoded:
        return False
    username, password = decoded.split(":", 1)
    user_valid = secrets.compare_digest(username, expected_user)
    pass_valid = secrets.compare_digest(password, expected_pass)
    return user_valid and pass_valid


def get_security_headers() -> list[Tuple[str, str]]:
    """Modern security headers."""
    return [
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        ("Cross-Origin-Opener-Policy", "same-origin"),
        ("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"),
    ]


def get_csp_header() -> Tuple[str, str]:
    """Content Security Policy header."""
    policy = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self';"
    )
    return ("Content-Security-Policy", policy)
