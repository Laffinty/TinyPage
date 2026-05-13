"""Admin backend WSGI application with HTMX-enhanced modern UI."""

from __future__ import annotations

import io
import json
import logging
import re
import secrets
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs

from .config import Config
from .content import list_articles, write_article, delete_article, text_to_html
from .generator import generate_static_pages
from .models import ArticleMeta
from .security import (
    check_basic_auth,
    escape_html,
    escape_attr,
    generate_csrf_token,
    get_csrf_cookie_header,
    get_real_ip,
    get_security_headers,
    get_csp_header,
    validate_csrf_token,
    validate_filename,
)

logger = logging.getLogger(__name__)

HTMX_CDN = "https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js"


class AdminApp:
    """WSGI admin application with HTMX interactivity."""

    def __init__(self, config: Config):
        self.cfg = config
        self.user = config.admin_user
        self.password = config.admin_pass

    def __call__(self, environ: dict, start_response):
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "/")
        client_ip = get_real_ip(environ)

        if not check_basic_auth(environ, self.user, self.password):
            logger.warning(f"[AUTH-FAIL] Admin access from {client_ip}")
            return self._auth_required(start_response)

        try:
            if method == "GET":
                if path in ("/", "/dashboard"):
                    return self._dashboard(environ, start_response)
                if path == "/new":
                    return self._new_form(environ, start_response)
                if path == "/edit":
                    return self._edit_form(environ, start_response)
                if path == "/preview":
                    return self._live_preview(environ, start_response)
                return self._send_404(start_response)

            if method == "POST":
                post_data = self._get_post_data(environ)
                csrf_token = post_data.get("csrf_token", [""])[0]
                if not validate_csrf_token(environ, csrf_token, self.cfg.admin_port, self.cfg.bind_domain):
                    return self._error(start_response, "403 Forbidden", "CSRF validation failed")

                if path == "/create":
                    return self._create(environ, start_response, post_data)
                if path == "/save":
                    return self._save(environ, start_response, post_data)
                if path == "/delete":
                    return self._delete(environ, start_response, post_data)
                if path == "/regen":
                    return self._regen(environ, start_response)
                if path == "/preview":
                    return self._live_preview(environ, start_response, post_data)
                return self._send_404(start_response)

            return self._error(start_response, "405 Method Not Allowed", "Method not allowed")
        except Exception as e:
            logger.error(f"[ADMIN-ERROR] {e}")
            return self._error(start_response, "500 Internal Server Error", "Server error")

    # ---------- HTMX helpers ----------

    def _is_htmx(self, environ: dict) -> bool:
        return environ.get("HTTP_HX_REQUEST", "") == "true"

    def _get_existing_csrf(self, environ: dict) -> str:
        """Reuse existing CSRF cookie if present to avoid invalidating forms."""
        cookie_header = environ.get("HTTP_COOKIE", "")
        for cookie in cookie_header.split(";"):
            cookie = cookie.strip()
            if cookie.startswith("csrf_token="):
                return cookie[11:]
        return generate_csrf_token()

    # ---------- Page handlers ----------

    def _dashboard(self, environ: dict, start_response):
        qs = parse_qs(environ.get("QUERY_STRING", ""))
        try:
            page = max(1, int(qs.get("page", ["1"])[0]))
        except (ValueError, TypeError):
            page = 1

        arts = list_articles(self.cfg.article_dir, self.cfg.max_file_size)
        total = len(arts)
        pages = max(1, (total + self.cfg.page_size - 1) // self.cfg.page_size)
        start_idx = (page - 1) * self.cfg.page_size
        page_arts = arts[start_idx:start_idx + self.cfg.page_size]

        csrf_token = self._get_existing_csrf(environ)
        rows = []
        for art in page_arts:
            safe_title = escape_html(art.title[:80])
            tags_display = f"<span class='tag'>{escape_html(', '.join(art.tag_list))}</span>" if art.tag_list else ""
            rows.append(f"""
<tr>
  <td><a href="/edit?file={art.file}">{safe_title}</a> {tags_display}</td>
  <td>{escape_html(art.date)}</td>
  <td>
    <form method="post" action="/delete" hx-post="/delete" hx-target="closest tr" hx-swap="outerHTML swap:0.3s" hx-confirm="删除不可恢复，确定？" style="display:inline;">
      <input type="hidden" name="csrf_token" value="{csrf_token}">
      <input type="hidden" name="file" value="{art.file}">
      <button type="submit" class="btn-danger btn-sm">删除</button>
    </form>
  </td>
</tr>""")

        # Pagination
        nav = []
        if page > 1:
            nav.append(f'<a href="/?page={page-1}">← 上一页</a>')
        if page < pages:
            nav.append(f'<a href="/?page={page+1}">下一页 →</a>')
        nav_html = f'<div class="nav-links">{" ".join(nav)}</div>' if nav else ""

        body = f"""<div class="admin-wrapper">
<h1>管理后台</h1>
<div class="security-notice">
  <strong>安全提醒：</strong>所有操作已记录审计日志 | CSRF保护已启用
</div>
<div class="actions">
  <a href="/new" class="btn-primary">+ 新建文章</a>
  <form method="post" action="/regen" hx-post="/regen" hx-target="#regen-status" style="display:inline;">
    <input type="hidden" name="csrf_token" value="{csrf_token}">
    <button type="submit" class="btn-secondary">重新生成静态页</button>
  </form>
  <span id="regen-status"></span>
</div>
<table class="admin-table">
<thead><tr><th style="width:55%">标题</th><th style="width:25%">发布时间</th><th style="width:20%">操作</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>
{nav_html}
<p style="margin-top:1rem;color:#666;font-size:0.9rem;">共 {total} 篇文章，第 {page}/{pages} 页</p>
</div>"""

        return self._render_page(start_response, "管理后台", body, csrf_token)

    def _new_form(self, environ: dict, start_response):
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        csrf_token = self._get_existing_csrf(environ)
        body = f"""<div class="admin-wrapper">
<h1>新建文章</h1>
<div class="editor-grid">
  <div class="editor-form">
    <form method="post" action="/create" id="article-form">
      <input type="hidden" name="csrf_token" value="{csrf_token}">
      <p><input name="title" placeholder="文章标题" required maxlength="{self.cfg.max_title_length}"></p>
      <p><input name="date" value="{now}" required pattern="\\d{{4}}-\\d{{2}}-\\d{{2}} \\d{{2}}:\\d{{2}}"></p>
      <p><input name="tags" placeholder="标签，用逗号分隔"></p>
      <p><textarea name="content" placeholder="支持 **粗体**、*斜体*、`代码`、[链接](url)" required maxlength="{self.cfg.max_content_length}" hx-trigger="keyup changed delay:500ms" hx-post="/preview" hx-target="#live-preview" hx-include="#article-form"></textarea></p>
      <p>
        <button type="submit" class="btn-primary">发布</button>
        <a href="/" class="btn-secondary">返回</a>
      </p>
    </form>
  </div>
  <div class="editor-preview">
    <h3>实时预览</h3>
    <div id="live-preview" class="preview-box">
      <p class="preview-placeholder">在左侧输入内容，预览将显示在这里...</p>
    </div>
  </div>
</div>
</div>"""
        return self._render_page(start_response, "新建文章", body, csrf_token, extra_script=True)

    def _edit_form(self, environ: dict, start_response):
        qs = parse_qs(environ.get("QUERY_STRING", ""))
        fname = qs.get("file", [""])[0]
        if not validate_filename(fname):
            return self._error(start_response, "400 Bad Request", "Invalid filename")

        path = self.cfg.article_dir / fname
        if not path.is_file():
            return self._error(start_response, "404 Not Found", "Article not found")

        meta = list_articles(self.cfg.article_dir, self.cfg.max_file_size)
        article = next((a for a in meta if a.file == fname), None)
        if not article:
            return self._error(start_response, "500 Internal Server Error", "Parse failed")

        # Extract raw text content
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for _ in range(5):
                next(f, None)
            html_content = f.read()
        match = re.search(r'<div class="post-content">(.*?)</div>', html_content, re.DOTALL)
        text = re.sub(r"<[^>]+>", "", match.group(1) if match else html_content).strip()

        csrf_token = self._get_existing_csrf(environ)
        body = f"""<div class="admin-wrapper">
<h1>编辑文章</h1>
<div class="editor-grid">
  <div class="editor-form">
    <form method="post" action="/save" id="article-form">
      <input type="hidden" name="csrf_token" value="{csrf_token}">
      <input type="hidden" name="file" value="{fname}">
      <p><input name="title" value="{escape_attr(article.title)}" required maxlength="{self.cfg.max_title_length}"></p>
      <p><input name="date" value="{escape_html(article.date)}" required></p>
      <p><input name="tags" value="{escape_attr(article.tags)}" placeholder="标签，用逗号分隔"></p>
      <p><textarea name="content" required maxlength="{self.cfg.max_content_length}" hx-trigger="keyup changed delay:500ms" hx-post="/preview" hx-target="#live-preview" hx-include="#article-form">{escape_html(text)}</textarea></p>
      <p>
        <button type="submit" class="btn-primary">保存更改</button>
        <a href="/" class="btn-secondary">返回</a>
      </p>
    </form>
  </div>
  <div class="editor-preview">
    <h3>实时预览</h3>
    <div id="live-preview" class="preview-box">
      <p class="preview-placeholder">在左侧输入内容，预览将显示在这里...</p>
    </div>
  </div>
</div>
</div>"""
        return self._render_page(start_response, f"编辑: {article.title}", body, csrf_token, extra_script=True)

    def _live_preview(self, environ: dict, start_response, post_data=None):
        """HTMX endpoint for live preview."""
        if post_data is None:
            post_data = self._get_post_data(environ)
        content = post_data.get("content", [""])[0]
        html = text_to_html(content) if content else '<p class="preview-placeholder">（无内容）</p>'
        headers = [("Content-Type", "text/html; charset=utf-8")] + get_security_headers()
        start_response("200 OK", headers)
        return [html.encode("utf-8")]

    def _create(self, environ: dict, start_response, post_data):
        title = post_data.get("title", [""])[0]
        date = post_data.get("date", [""])[0]
        content = post_data.get("content", [""])[0]
        tags = post_data.get("tags", [""])[0]
        client_ip = get_real_ip(environ)

        if not all([title, date, content]):
            return self._error(start_response, "400 Bad Request", "Missing fields")

        from .content import slugify_title
        slug = slugify_title(title)
        fname = f"{date[:10]}-{slug}.html"
        if (self.cfg.article_dir / fname).exists():
            fname = f"{date[:10]}-{slug}-{secrets.token_urlsafe(4)}.html"

        write_article(self.cfg.article_dir, fname, title, date, slug, content, tags)
        arts = list_articles(self.cfg.article_dir, self.cfg.max_file_size)
        generate_static_pages(arts, self.cfg)
        logger.info(f"[CREATE] {fname} from {client_ip}")
        return self._redirect(start_response, "/")

    def _save(self, environ: dict, start_response, post_data):
        fname = post_data.get("file", [""])[0]
        title = post_data.get("title", [""])[0]
        date = post_data.get("date", [""])[0]
        content = post_data.get("content", [""])[0]
        tags = post_data.get("tags", [""])[0]
        client_ip = get_real_ip(environ)

        if not all([fname, title, date, content]):
            return self._error(start_response, "400 Bad Request", "Missing fields")
        if not validate_filename(fname):
            return self._error(start_response, "400 Bad Request", "Invalid filename")

        from .content import slugify_title
        slug = slugify_title(title)
        write_article(self.cfg.article_dir, fname, title, date, slug, content, tags)
        arts = list_articles(self.cfg.article_dir, self.cfg.max_file_size)
        generate_static_pages(arts, self.cfg)
        logger.info(f"[SAVE] {fname} from {client_ip}")
        return self._redirect(start_response, "/")

    def _delete(self, environ: dict, start_response, post_data):
        fname = post_data.get("file", [""])[0]
        client_ip = get_real_ip(environ)
        if not validate_filename(fname):
            return self._error(start_response, "400 Bad Request", "Invalid filename")
        path = self.cfg.article_dir / fname
        if path.is_file():
            delete_article(path)
            arts = list_articles(self.cfg.article_dir, self.cfg.max_file_size)
            generate_static_pages(arts, self.cfg)
            logger.info(f"[DELETE] {fname} from {client_ip}")
        # Return empty for HTMX swap removal
        headers = get_security_headers()
        start_response("200 OK", headers)
        return [b""]

    def _regen(self, environ: dict, start_response):
        client_ip = get_real_ip(environ)
        arts = list_articles(self.cfg.article_dir, self.cfg.max_file_size)
        generate_static_pages(arts, self.cfg)
        logger.info(f"[REGEN] from {client_ip}")
        if self._is_htmx(environ):
            headers = [("Content-Type", "text/html; charset=utf-8")] + get_security_headers()
            start_response("200 OK", headers)
            return ['<span style="color:green;font-size:0.9rem;">✓ 已重新生成</span>'.encode('utf-8')]
        return self._redirect(start_response, "/")

    # ---------- Response helpers ----------

    def _render_page(self, start_response, title: str, body: str, csrf_token: str, extra_script: bool = False):
        htmx_script = f'<script src="{HTMX_CDN}" integrity="sha384-oeUn82QN6taHto+oP9ST7C3QZzHDXz8rNThDFeQVVI+1cL4laBIAxWU0JyPQY1Q" crossorigin="anonymous"></script>' if extra_script else ""
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{escape_html(title)} - 管理后台</title>
<style>
:root {{ --primary: #2c3e50; --accent: #e74c3c; --bg: #fff; --surface: #f8f9fa; --text: #333; --border: #e0e0e0; }}
html.dark {{ --bg: #1a1a2e; --surface: #16213e; --text: #eaeaea; --border: #0f3460; }}
body {{ max-width: 1100px; margin: 2rem auto; padding: 0 1.5rem; font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; transition: background 0.2s, color 0.2s; }}
h1 {{ color: var(--primary); margin-bottom: 1rem; font-size: 1.6rem; }}
.security-notice {{ background: #d4edda; border-left: 4px solid #28a745; padding: 0.6rem 1rem; margin-bottom: 1.5rem; border-radius: 4px; font-size: 0.9rem; }}
.actions {{ margin: 1.5rem 0; display: flex; gap: 0.75rem; align-items: center; flex-wrap: wrap; }}
.btn-primary, .btn-secondary, .btn-danger {{ border: none; padding: 0.5rem 1rem; cursor: pointer; border-radius: 6px; font-size: 0.9rem; text-decoration: none; display: inline-block; transition: opacity 0.15s; }}
.btn-primary {{ background: var(--accent); color: white; }}
.btn-secondary {{ background: var(--surface); color: var(--text); border: 1px solid var(--border); }}
.btn-danger {{ background: #c0392b; color: white; }}
.btn-sm {{ padding: 0.25rem 0.6rem; font-size: 0.8rem; }}
button:hover, .btn-primary:hover, .btn-secondary:hover, .btn-danger:hover {{ opacity: 0.85; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
th, td {{ text-align: left; padding: 0.75rem; border-bottom: 1px solid var(--border); }}
th {{ background: var(--surface); font-weight: 600; font-size: 0.85rem; color: var(--primary); }}
tr {{ transition: background 0.2s; }}
tr:hover {{ background: var(--surface); }}
a {{ color: var(--accent); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
input, textarea {{ width: 100%; font-family: inherit; font-size: 1rem; padding: 0.6rem; margin-bottom: 0.75rem; border: 1px solid var(--border); border-radius: 6px; background: var(--surface); color: var(--text); }}
textarea {{ height: 300px; resize: vertical; line-height: 1.6; }}
input:focus, textarea:focus {{ outline: none; border-color: var(--accent); }}
.editor-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; }}
.editor-preview {{ position: sticky; top: 2rem; height: fit-content; }}
.preview-box {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; min-height: 200px; overflow: auto; }}
.preview-placeholder {{ color: #888; font-style: italic; }}
.tag {{ display: inline-block; padding: 0.15rem 0.5rem; background: var(--surface); border: 1px solid var(--border); border-radius: 999px; font-size: 0.75rem; margin-left: 0.5rem; color: var(--text); }}
.nav-links {{ margin-top: 1.5rem; display: flex; gap: 1rem; }}
.nav-links a {{ color: var(--accent); }}
@media (max-width: 800px) {{ .editor-grid {{ grid-template-columns: 1fr; }} .editor-preview {{ position: static; }} }}
</style>
</head>
<body>
{body}
{htmx_script}
</body>
</html>"""
        csrf_cookie = get_csrf_cookie_header(csrf_token)
        headers = [
            ("Content-Type", "text/html; charset=utf-8"),
            csrf_cookie,
            get_csp_header(),
        ] + get_security_headers()
        start_response("200 OK", headers)
        return [html.encode("utf-8")]

    def _auth_required(self, start_response):
        headers = [
            ("WWW-Authenticate", 'Basic realm="Secure Admin"'),
            ("Content-Type", "text/plain"),
        ] + get_security_headers()
        start_response("401 Unauthorized", headers)
        return [b"401 Unauthorized"]

    def _redirect(self, start_response, location: str):
        headers = [("Location", location)] + get_security_headers()
        start_response("302 Found", headers)
        return [b""]

    def _error(self, start_response, status: str, message: str):
        headers = [("Content-Type", "text/plain")] + get_security_headers()
        start_response(status, headers)
        return [message.encode("utf-8")]

    def _send_404(self, start_response):
        return self._error(start_response, "404 Not Found", "Not Found")

    def _get_post_data(self, environ: dict) -> dict:
        try:
            cl = int(environ.get("CONTENT_LENGTH", 0))
            if cl > 0:
                data = environ["wsgi.input"].read(cl)
                environ["wsgi.input"] = io.BytesIO(data)
                return parse_qs(data.decode("utf-8"))
        except (ValueError, KeyError):
            pass
        return {}
