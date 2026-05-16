"""Frontend static file WSGI application with PWA asset injection."""

from __future__ import annotations

import logging
import mimetypes
from pathlib import Path
from typing import Any, Optional
from wsgiref.types import StartResponse

from .config import Config
from .security import get_security_headers, safe_path_check

logger = logging.getLogger(__name__)

# Map virtual paths to injected static assets (lazy loaded)
_INJECTED_ASSETS: dict[str, tuple[str, bytes]] | None = None


def _get_injected_assets() -> dict[str, tuple[str, bytes]]:
    """Lazy-load injected assets on first access."""
    global _INJECTED_ASSETS
    if _INJECTED_ASSETS is None:
        _INJECTED_ASSETS = {}
        base = Path("static_inject")
        if base.exists():
            for f in base.iterdir():
                if f.is_file():
                    data = f.read_bytes()
                    ct = mimetypes.guess_type(f.name)[0] or "application/octet-stream"
                    _INJECTED_ASSETS[f"/" + f.name] = (ct, data)
    return _INJECTED_ASSETS


class StaticApp:
    """WSGI application serving static files with security headers and asset injection."""

    def __init__(self, config: Config):
        self.cfg = config
        self.doc_root = config.root_dir

    def __call__(self, environ: dict[str, Any], start_response: StartResponse) -> list[bytes]:
        path = environ.get("PATH_INFO", "/")
        # Fix potential mojibake from WSGI servers that decode UTF-8 as latin1
        try:
            path = path.encode("latin1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass
        if path == "/" or path.endswith("/"):
            path += "index.html"

        # Check injected assets first
        injected = _get_injected_assets()
        if path in injected:
            ct, data = injected[path]
            headers = [
                ("Content-Type", ct),
                ("Content-Length", str(len(data))),
                ("Cache-Control", "max-age=3600"),
            ] + get_security_headers()
            start_response("200 OK", headers)
            return [data]

        # Regular file serving
        is_safe, full_path = safe_path_check(path, self.doc_root)
        if not is_safe or full_path is None:
            return self._error(start_response, "403 Forbidden", "Invalid path")

        if not full_path.is_file():
            return self._error(start_response, "404 Not Found", "Not found")

        try:
            data = full_path.read_bytes()
            ct = mimetypes.guess_type(str(full_path))[0] or "text/html"
            headers = [
                ("Content-Type", f"{ct}; charset=utf-8" if ct.startswith("text/") else ct),
                ("Content-Length", str(len(data))),
                ("Cache-Control", "max-age=300, must-revalidate"),
            ] + get_security_headers()
            start_response("200 OK", headers)
            return [data]
        except Exception as e:
            logger.error(f"[STATIC-ERROR] {e}")
            return self._error(start_response, "500 Internal Server Error", "Server error")

    def _error(self, start_response, status: str, message: str):
        body = message.encode("utf-8")
        headers = get_security_headers() + [("Content-Type", "text/plain")]
        start_response(status, headers)
        return [body]
