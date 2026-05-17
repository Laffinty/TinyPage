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
import threading
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


def get_csrf_cookie_header(
    token: Optional[str] = None,
    secure: bool = False,
) -> Tuple[str, str]:
    """Generate Set-Cookie header for CSRF token.

    Args:
        token: CSRF token string. Generated if not provided.
        secure: Add Secure flag. Should be True when served over HTTPS.
    """
    if token is None:
        token = generate_csrf_token()
    cookie = f"csrf_token={token}; Path=/; HttpOnly; SameSite=Strict"
    if secure:
        cookie += "; Secure"
    return ("Set-Cookie", cookie)


def generate_session_token() -> str:
    """Generate a secure opaque session token."""
    return secrets.token_urlsafe(32)


def get_session_cookie_header(
    token: Optional[str] = None,
    secure: bool = False,
    max_age: int = 86400,
) -> Tuple[str, str]:
    """Generate Set-Cookie header for session token.

    Args:
        token: Session token string. Generated if not provided.
        secure: Add Secure flag. Should be True when served over HTTPS.
        max_age: Max-Age in seconds (default 24h).
    """
    if token is None:
        token = generate_session_token()
    cookie = f"session_id={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}"
    if secure:
        cookie += "; Secure"
    return ("Set-Cookie", cookie)


def get_session_clear_cookie_header(secure: bool = False) -> Tuple[str, str]:
    """Generate Set-Cookie header to clear session."""
    cookie = "session_id=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
    if secure:
        cookie += "; Secure"
    return ("Set-Cookie", cookie)


def is_valid_csrf_format(token: str, max_age: int = 3600) -> bool:
    """Check if a CSRF token has valid format and signature (no origin check).

    Use this for reusing existing tokens in cookies without requiring
    a full request context. Does NOT replace validate_csrf_token() for
    POST request validation.

    Args:
        token: CSRF token string.
        max_age: Maximum token age in seconds.

    Returns:
        True if token format and HMAC signature are valid.
    """
    if not token or len(token) < 32:
        return False
    try:
        signed_token = base64.urlsafe_b64decode(token.encode("ascii"))
        if len(signed_token) != 52:
            return False
        token_data = signed_token[:20]
        signature = signed_token[20:]
        expected_sig = hmac.new(_CSRF_SECRET, token_data, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected_sig):
            return False
        timestamp = int.from_bytes(token_data[16:20], "big")
        now = time.time()
        if now - timestamp > max_age or timestamp > now + 60:
            return False
        return True
    except Exception:
        return False


_TRUSTED_PROXIES: set[str] = set()  # Configured at startup


def configure_trusted_proxies(proxies: set[str]) -> None:
    """Set trusted reverse proxy IPs. Only these proxies' headers are trusted."""
    global _TRUSTED_PROXIES
    _TRUSTED_PROXIES = proxies


def get_real_ip(environ: dict) -> str:
    """Get client IP, trusting proxy headers only from trusted proxies."""
    remote_addr = environ.get("REMOTE_ADDR", "unknown")

    # Only trust proxy headers when request comes from a trusted proxy
    if remote_addr in _TRUSTED_PROXIES:
        x_forwarded_for = environ.get("HTTP_X_FORWARDED_FOR", "")
        if x_forwarded_for:
            # X-Forwarded-For: client, proxy1, proxy2
            ips = [ip.strip() for ip in x_forwarded_for.split(",")]
            return ips[0]
        x_real_ip = environ.get("HTTP_X_REAL_IP", "")
        if x_real_ip:
            return x_real_ip.strip()

    return remote_addr


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


def slugify(text: str, max_length: int = 80, fallback: str = "") -> str:
    """Convert text to URL-safe slug, preserving CJK characters.

    Args:
        text: Input text to slugify.
        max_length: Maximum slug length.
        fallback: Fallback value if result is empty.

    Returns:
        URL-safe slug string.
    """
    slug = re.sub(r"[^\w\u4e00-\u9fa5-]", "-", text.lower()).strip("-")
    slug = re.sub(r"-{2,}", "-", slug)
    if max_length:
        slug = slug[:max_length].rstrip("-")
    return slug or fallback or f"untitled-{int(time.time())}"


class SessionManager:
    """In-memory session manager with automatic expiration and cleanup."""

    SESSION_MAX_AGE = 86400  # 24 hours
    MAX_TRACKED_SESSIONS = 5000
    CLEANUP_INTERVAL = 300  # 5 minutes

    def __init__(self):
        self._sessions: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._last_cleanup = time.time()

    def _cleanup(self, now: float) -> None:
        if now - self._last_cleanup < self.CLEANUP_INTERVAL:
            return
        self._last_cleanup = now
        cutoff = now - self.SESSION_MAX_AGE
        expired = [sid for sid, data in self._sessions.items() if data["created_at"] < cutoff]
        for sid in expired:
            del self._sessions[sid]

    def create_session(self, client_ip: str) -> str:
        now = time.time()
        with self._lock:
            self._cleanup(now)
            if len(self._sessions) >= self.MAX_TRACKED_SESSIONS:
                # Remove oldest session to prevent memory growth
                oldest = min(self._sessions, key=lambda k: self._sessions[k]["created_at"])
                del self._sessions[oldest]
            token = secrets.token_urlsafe(32)
            self._sessions[token] = {"created_at": now, "client_ip": client_ip}
            return token

    def validate_session(self, token: str, client_ip: str) -> bool:
        now = time.time()
        with self._lock:
            self._cleanup(now)
            data = self._sessions.get(token)
            if not data:
                return False
            if now - data["created_at"] > self.SESSION_MAX_AGE:
                del self._sessions[token]
                return False
            # Optional strict IP binding: uncomment to enforce
            # if data["client_ip"] != client_ip:
            #     return False
            return True

    def destroy_session(self, token: str) -> None:
        with self._lock:
            self._sessions.pop(token, None)

    def get_session_from_environ(self, environ: dict) -> Optional[str]:
        cookie_header = environ.get("HTTP_COOKIE", "")
        for cookie in cookie_header.split(";"):
            cookie = cookie.strip()
            if cookie.startswith("session_id="):
                return cookie[11:]
        return None


class RateLimiter:
    """In-memory rate limiter using sliding window with automatic cleanup."""

    MAX_TRACKED_IPS = 10000  # Prevent dictionary from growing indefinitely

    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = {}
        self._lock = threading.Lock()
        self._last_cleanup = time.time()
        self._cleanup_interval = 60  # Clean up every 60 seconds

    def _cleanup(self, now: float) -> None:
        """Remove expired IP entries to prevent memory leak."""
        if now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now
        cutoff = now - self.window_seconds
        expired = [
            ip
            for ip, times in self._requests.items()
            if not times or times[-1] < cutoff
        ]
        for ip in expired:
            del self._requests[ip]

    def is_allowed(self, client_ip: str) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            self._cleanup(now)
            if client_ip not in self._requests:
                # If IP count has reached limit, reject new IPs (preserve existing)
                if len(self._requests) >= self.MAX_TRACKED_IPS:
                    return False
                self._requests[client_ip] = []
            self._requests[client_ip] = [
                t for t in self._requests[client_ip] if t > cutoff
            ]
            if len(self._requests[client_ip]) >= self.max_requests:
                return False
            self._requests[client_ip].append(now)
            return True

    def get_retry_after(self, client_ip: str) -> int:
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            if client_ip not in self._requests:
                return 0
            valid_times = [t for t in self._requests[client_ip] if t > cutoff]
            if not valid_times:
                return 0
            oldest = min(valid_times)
            return int(self.window_seconds - (now - oldest)) + 1


class AuthFailureTracker:
    """Track authentication failures and implement progressive lockout."""

    def __init__(
        self,
        max_failures: int = 5,
        lockout_seconds: int = 300,
        cleanup_interval: int = 60,
    ):
        self.max_failures = max_failures
        self.lockout_seconds = lockout_seconds
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()
        self._last_cleanup = time.time()
        self._cleanup_interval = cleanup_interval

    def record_failure(self, client_ip: str) -> None:
        """Record an authentication failure."""
        now = time.time()
        with self._lock:
            if client_ip not in self._failures:
                self._failures[client_ip] = []
            cutoff = now - self.lockout_seconds
            self._failures[client_ip] = [
                t for t in self._failures[client_ip] if t > cutoff
            ]
            self._failures[client_ip].append(now)
            self._maybe_cleanup(now)

    def is_locked_out(self, client_ip: str) -> bool:
        """Check if an IP is currently locked out."""
        now = time.time()
        with self._lock:
            cutoff = now - self.lockout_seconds
            recent = [t for t in self._failures.get(client_ip, []) if t > cutoff]
            return len(recent) >= self.max_failures

    def get_lockout_remaining(self, client_ip: str) -> int:
        """Get seconds remaining in lockout."""
        now = time.time()
        with self._lock:
            cutoff = now - self.lockout_seconds
            recent = [t for t in self._failures.get(client_ip, []) if t > cutoff]
            if len(recent) < self.max_failures:
                return 0
            oldest = min(recent)
            return int(self.lockout_seconds - (now - oldest)) + 1

    def _maybe_cleanup(self, now: float) -> None:
        """Periodically clean up expired IP entries."""
        if now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now
        cutoff = now - self.lockout_seconds
        expired = [
            ip
            for ip, times in self._failures.items()
            if not times or times[-1] < cutoff
        ]
        for ip in expired:
            del self._failures[ip]
