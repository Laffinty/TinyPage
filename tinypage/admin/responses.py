"""WSGI response helpers for admin dashboard."""

from __future__ import annotations

import json
from typing import Any
from wsgiref.types import StartResponse

from ..security import (
    escape_html,
    get_security_headers,
    get_csp_header,
    get_csrf_cookie_header,
)


def redirect_response(start_response: StartResponse, location: str) -> list[bytes]:
    headers = [("Location", location)] + get_security_headers()
    start_response("302 Found", headers)
    return [b""]


def error_response(
    start_response: StartResponse, status: str, message: str
) -> list[bytes]:
    headers = [("Content-Type", "text/plain")] + get_security_headers()
    start_response(status, headers)
    return [message.encode("utf-8")]


def json_error_response(
    start_response: StartResponse, status: str, message: str
) -> list[bytes]:
    headers = [("Content-Type", "application/json")] + get_security_headers()
    start_response(status, headers)
    return [json.dumps({"success": False, "error": message}).encode("utf-8")]


def html_response(
    start_response: StartResponse,
    html: str,
    csrf_token: str = "",
    status: str = "200 OK",
    extra_headers: list[tuple[str, str]] | None = None,
) -> list[bytes]:
    headers = [
        ("Content-Type", "text/html; charset=utf-8"),
    ] + get_security_headers()
    if csrf_token:
        headers.append(get_csrf_cookie_header(csrf_token, secure=False))
    headers.append(get_csp_header())
    if extra_headers:
        headers.extend(extra_headers)
    start_response(status, headers)
    return [html.encode("utf-8")]


def render_admin_page(
    start_response: StartResponse,
    title: str,
    body: str,
    csrf_token: str,
    current_path: str = "/",
    htmx: bool = False,
) -> list[bytes]:
    """Render a full admin page using the base template."""
    from .templates import render_template, build_nav_html

    nav_items = [
        ("/", "仪表盘", "dashboard"),
        ("/new", "新建文章", "article"),
        ("/new-page", "新建页面", "page"),
        ("/pages", "管理页面", "pages"),
        ("/theme", "主题", "theme"),
    ]

    nav_html = build_nav_html(nav_items, current_path)

    html = render_template(
        "base.html",
        title=escape_html(title),
        body=body,
        csrf_token=csrf_token,
        current_path=current_path,
        nav_html=nav_html,
        htmx_script='<script src="/htmx.min.js"></script>' if htmx else "",
    )
    return html_response(start_response, html, csrf_token=csrf_token)
