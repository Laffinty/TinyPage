"""Admin backend WSGI application — lightweight router core."""

from __future__ import annotations

import io
import inspect
import json
import logging
from typing import Any
from urllib.parse import parse_qs
from wsgiref.types import StartResponse

from ..config import Config
from ..frontend import _get_injected_assets
from ..security import (
    generate_csrf_token,
    get_csrf_cookie_header,
    get_csp_header,
    get_real_ip,
    get_security_headers,
    validate_csrf_token,
    is_valid_csrf_format,
    SessionManager,
    RateLimiter,
    AuthFailureTracker,
)
from .responses import html_response, redirect_response, error_response
from . import views
from . import actions

logger = logging.getLogger(__name__)


def _verify_handler_arities() -> None:
    """Fail loudly at import time if a handler's signature drifts.

    The regression this guards against is concrete: ``actions.*`` were called
    with ``(environ, start_response, cfg, post_data)`` while every handler was
    defined with three parameters, so all 12 write actions returned 500. A
    request-time ``TypeError`` is easy to miss; an import-time failure is not.
    """
    problems: list[str] = []
    for route, handler in AdminApp._POST_HANDLERS.items():
        count = len(inspect.signature(handler).parameters)
        if count != 4:
            problems.append(f"{route} -> {handler.__name__}: {count} params, dispatch passes 4")
    for route, handler in AdminApp._POST_HANDLERS_NO_BODY.items():
        count = len(inspect.signature(handler).parameters)
        if count != 3:
            problems.append(f"{route} -> {handler.__name__}: {count} params, dispatch passes 3")
    if problems:
        raise TypeError("AdminApp route/handler contract broken:\n  - " + "\n  - ".join(problems))


class AdminApp:
    """WSGI admin application — routes to views/actions modules."""

    MAX_POST_SIZE = 10 * 1024 * 1024  # 10MB

    _GET_ROUTES: dict[str, str] = {
        "/": "dashboard",
        "/dashboard": "dashboard",
        "/pages": "pages_dashboard",
        "/new": "new_article",
        "/new-page": "new_page",
        "/edit": "edit_article",
        "/edit-page": "edit_page",
        "/theme": "theme",
        "/login": "login",
    }

    _POST_ROUTES: dict[str, str] = {
        "/upload": "upload_image",
        "/create": "create_article",
        "/create-page": "create_page",
        "/save": "save_article",
        "/save-page": "save_page",
        "/delete": "delete_article",
        "/delete-page": "delete_page",
        "/regen": "regenerate",
        "/preview": "live_preview",
        "/set-theme": "set_theme",
        "/ai-assist": "ai_assist",
        "/translate": "translate_article",
        "/login": "login_handler",
        "/logout": "logout_handler",
    }

    _CSRF_EXEMPT_POST: set[str] = {"/upload"}

    # Table-driven dispatch. This used to be a 24-line if/elif chain that called
    # every handler with a hard-coded argument list; when the handlers' signatures
    # drifted (start_response was never a parameter, so all 12 write actions
    # raised TypeError) nothing caught it. The arity guard below now fails at
    # import time instead of at request time.
    #
    # Handlers that read POST form fields.
    _POST_HANDLERS: dict[str, Any] = {
        "upload_image": actions.upload_image,
        "create_article": actions.create_article,
        "save_article": actions.save_article,
        "delete_article": actions.delete_article_action,
        "create_page": actions.create_page,
        "save_page": actions.save_page,
        "delete_page": actions.delete_page_action,
        "live_preview": actions.live_preview,
        "set_theme": actions.set_theme,
        "ai_assist": actions.ai_assist,
        "translate_article": actions.translate_article_action,
    }

    # Handlers that ignore the POST body.
    _POST_HANDLERS_NO_BODY: dict[str, Any] = {
        "regenerate": actions.regenerate,
    }

    def __init__(self, config: Config):
        self.cfg = config
        self.user = config.admin_user
        self.password = config.admin_pass
        self.rate_limiter = RateLimiter(max_requests=60, window_seconds=60)
        self.auth_tracker = AuthFailureTracker(max_failures=5, lockout_seconds=300)
        self.session_manager = SessionManager()

    def __call__(
        self, environ: dict[str, Any], start_response: StartResponse
    ) -> list[bytes]:
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "/")
        client_ip = get_real_ip(environ)

        if not self.rate_limiter.is_allowed(client_ip):
            retry_after = self.rate_limiter.get_retry_after(client_ip)
            logger.warning(f"[RATE-LIMIT] Blocked {client_ip}, retry after {retry_after}s")
            headers = [
                ("Content-Type", "text/plain"),
                ("Retry-After", str(retry_after)),
            ] + get_security_headers()
            start_response("429 Too Many Requests", headers)
            return [b"Rate limit exceeded. Please try again later."]

        # Serve injected static assets (CSS/JS) without session
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

        # Allow login/logout without session
        if path in ("/login", "/logout"):
            try:
                if method == "GET" and path == "/login":
                    return self._route_login_get(environ, start_response)
                if method == "POST" and path == "/login":
                    return self._route_login_post(environ, start_response)
                if method == "POST" and path == "/logout":
                    return self._route_logout_post(environ, start_response)
                return error_response(start_response, "405 Method Not Allowed", "Method not allowed")
            except Exception as e:
                logger.error(f"[ADMIN-ERROR] {e}")
                return error_response(start_response, "500 Internal Server Error", "Server error")

        # Check session for all other routes
        session_token = self.session_manager.get_session_from_environ(environ)
        if not session_token or not self.session_manager.validate_session(session_token, client_ip):
            return redirect_response(start_response, "/login")

        try:
            if method == "GET":
                return self._handle_get(environ, start_response, path)
            if method == "POST":
                return self._handle_post(environ, start_response, path)
            return error_response(start_response, "405 Method Not Allowed", "Method not allowed")
        except Exception as e:
            logger.error(f"[ADMIN-ERROR] {e}")
            return error_response(start_response, "500 Internal Server Error", "Server error")

    # ---------- GET routing ----------

    def _handle_get(self, environ: dict, start_response: StartResponse, path: str) -> list[bytes]:
        route = self._GET_ROUTES.get(path)
        if not route:
            return self._send_404(start_response)

        csrf_token = self._get_existing_csrf(environ)
        body = ""
        htmx = False

        if route == "dashboard":
            body = views.dashboard_view(environ, self.cfg, csrf_token)
        elif route == "pages_dashboard":
            body = views.pages_dashboard_view(environ, self.cfg, csrf_token)
            htmx = True
        elif route == "new_article":
            body = views.article_form_view(environ, self.cfg, csrf_token, is_edit=False)
            htmx = True
        elif route == "edit_article":
            body = views.article_form_view(environ, self.cfg, csrf_token, is_edit=True)
            htmx = True
        elif route == "new_page":
            body = views.page_form_view(environ, self.cfg, csrf_token, is_edit=False)
            htmx = True
        elif route == "edit_page":
            body = views.page_form_view(environ, self.cfg, csrf_token, is_edit=True)
            htmx = True
        elif route == "theme":
            body = views.theme_selector_view(environ, self.cfg, csrf_token)
        else:
            return self._send_404(start_response)

        from .responses import render_admin_page
        return render_admin_page(
            start_response,
            self._page_title(route),
            body,
            csrf_token,
            current_path=path,
            htmx=htmx,
        )

    def _route_login_get(self, environ: dict, start_response: StartResponse) -> list[bytes]:
        csrf_token = self._get_existing_csrf(environ)
        html = views.login_view(environ, csrf_token)
        is_secure = bool(self.cfg.bind_domain)
        csrf_cookie = get_csrf_cookie_header(csrf_token, secure=is_secure)
        headers = [
            ("Content-Type", "text/html; charset=utf-8"),
            csrf_cookie,
            get_csp_header(),
        ] + get_security_headers()
        start_response("200 OK", headers)
        return [html.encode("utf-8")]

    # ---------- POST routing ----------

    def _handle_post(self, environ: dict, start_response: StartResponse, path: str) -> list[bytes]:
        route = self._POST_ROUTES.get(path)
        if not route:
            return self._send_404(start_response)

        post_data = self._get_post_data(environ)
        csrf_token = post_data.get("csrf_token", [""])[0]

        is_valid_csrf = validate_csrf_token(
            environ, csrf_token, self.cfg.admin_port, self.cfg.bind_domain
        )

        if path in self._CSRF_EXEMPT_POST:
            if not is_valid_csrf:
                headers = [("Content-Type", "application/json")] + get_security_headers()
                start_response("403 Forbidden", headers)
                return [json.dumps({"success": False, "error": "CSRF validation failed"}).encode("utf-8")]
        else:
            if not is_valid_csrf:
                return error_response(start_response, "403 Forbidden", "CSRF validation failed")

        # Dispatch to action handlers (table-driven; see _POST_HANDLERS)
        handler = self._POST_HANDLERS.get(route)
        if handler is not None:
            return handler(environ, start_response, self.cfg, post_data)

        handler = self._POST_HANDLERS_NO_BODY.get(route)
        if handler is not None:
            return handler(environ, start_response, self.cfg)

        return self._send_404(start_response)

    def _route_login_post(self, environ: dict, start_response: StartResponse) -> list[bytes]:
        post_data = self._get_post_data(environ)
        return actions.login_handler(
            environ, start_response, self.cfg, post_data,
            self.session_manager, self.auth_tracker
        )

    def _route_logout_post(self, environ: dict, start_response: StartResponse) -> list[bytes]:
        post_data = self._get_post_data(environ)
        return actions.logout_handler(
            environ, start_response, self.cfg, post_data, self.session_manager
        )

    # ---------- Helpers ----------

    def _page_title(self, route: str) -> str:
        titles = {
            "dashboard": "仪表盘",
            "pages_dashboard": "独立页面",
            "new_article": "新建文章",
            "edit_article": "编辑文章",
            "new_page": "新建页面",
            "edit_page": "编辑页面",
            "theme": "主题管理",
        }
        return titles.get(route, "管理后台")

    def _is_htmx(self, environ: dict) -> bool:
        return environ.get("HTTP_HX_REQUEST", "") == "true"

    def _get_existing_csrf(self, environ: dict) -> str:
        cookie_header = environ.get("HTTP_COOKIE", "")
        for cookie in cookie_header.split(";"):
            cookie = cookie.strip()
            if cookie.startswith("csrf_token="):
                token = cookie[11:]
                if is_valid_csrf_format(token):
                    return token
                break
        return generate_csrf_token()

    def _send_404(self, start_response: StartResponse) -> list[bytes]:
        return error_response(start_response, "404 Not Found", "Not Found")

    def _get_post_data(self, environ: dict) -> dict:
        try:
            cl = int(environ.get("CONTENT_LENGTH", 0))
        except (ValueError, TypeError):
            cl = 0
        if cl <= 0:
            return {}
        if cl > self.MAX_POST_SIZE:
            logger.warning(f"[BLOCK] POST body too large: {cl} bytes")
            return {}
        data = environ["wsgi.input"].read(cl)
        environ["wsgi.input"] = io.BytesIO(data)
        return parse_qs(data.decode("utf-8", errors="replace"))


# Runs after the class body exists. A mismatch is a programming error, not a
# runtime condition, so fail at import rather than on the first request.
_verify_handler_arities()
