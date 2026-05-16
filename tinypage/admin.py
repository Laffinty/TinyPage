"""Admin backend WSGI application with HTMX-enhanced modern UI."""

from __future__ import annotations

import io
import json
import logging
import re
import secrets
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs
from wsgiref.types import StartResponse

from .config import Config
from .content import (
    list_articles,
    write_article,
    delete_article,
    list_standalones,
    write_standalone,
    delete_standalone,
    get_raw_content,
)
from .parsers import render_markdown
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
    is_valid_csrf_format,
)

logger = logging.getLogger(__name__)

HTMX_CDN = "/htmx.min.js"


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


class AdminApp:
    """WSGI admin application with HTMX interactivity."""

    MAX_POST_SIZE = 10 * 1024 * 1024  # 10MB max POST body

    def __init__(self, config: Config):
        self.cfg = config
        self.user = config.admin_user
        self.password = config.admin_pass
        self.rate_limiter = RateLimiter(max_requests=60, window_seconds=60)
        self.auth_tracker = AuthFailureTracker(
            max_failures=5,
            lockout_seconds=300,
        )

    def __call__(
        self, environ: dict[str, Any], start_response: StartResponse
    ) -> list[bytes]:
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "/")
        client_ip = get_real_ip(environ)

        if not self.rate_limiter.is_allowed(client_ip):
            retry_after = self.rate_limiter.get_retry_after(client_ip)
            logger.warning(
                f"[RATE-LIMIT] Blocked {client_ip}, retry after {retry_after}s"
            )
            headers = [
                ("Content-Type", "text/plain"),
                ("Retry-After", str(retry_after)),
            ] + get_security_headers()
            start_response("429 Too Many Requests", headers)
            return [b"Rate limit exceeded. Please try again later."]

        # Check auth lockout first
        if self.auth_tracker.is_locked_out(client_ip):
            remaining = self.auth_tracker.get_lockout_remaining(client_ip)
            logger.warning(f"[AUTH-LOCKOUT] {client_ip} locked out for {remaining}s")
            headers = [
                ("Content-Type", "text/plain"),
                ("Retry-After", str(remaining)),
            ] + get_security_headers()
            start_response("429 Too Many Requests", headers)
            return [b"Account temporarily locked. Try again later."]

        if not check_basic_auth(environ, self.user, self.password):
            self.auth_tracker.record_failure(client_ip)
            failures = len(self.auth_tracker._failures.get(client_ip, []))
            logger.warning(
                f"[AUTH-FAIL] Admin access from {client_ip} "
                f"(attempt {failures}/{self.auth_tracker.max_failures})"
            )
            return self._auth_required(start_response)

        try:
            if method == "GET":
                from .frontend import _get_injected_assets

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
                if path in ("/", "/dashboard"):
                    return self._dashboard(environ, start_response)
                if path == "/pages":
                    return self._pages_dashboard(environ, start_response)
                if path == "/new":
                    return self._new_form(environ, start_response)
                if path == "/new-page":
                    return self._new_page_form(environ, start_response)
                if path == "/edit":
                    return self._edit_form(environ, start_response)
                if path == "/edit-page":
                    return self._edit_page_form(environ, start_response)
                if path == "/theme":
                    return self._theme_page(environ, start_response)
                return self._send_404(start_response)

            if method == "POST":
                post_data = self._get_post_data(environ)
                csrf_token = post_data.get("csrf_token", [""])[0]

                if path == "/upload":
                    if not validate_csrf_token(
                        environ, csrf_token, self.cfg.admin_port, self.cfg.bind_domain
                    ):
                        headers = [
                            ("Content-Type", "application/json")
                        ] + get_security_headers()
                        start_response("403 Forbidden", headers)
                        return [
                            json.dumps(
                                {"success": False, "error": "CSRF validation failed"}
                            ).encode("utf-8")
                        ]
                    return self._upload(environ, start_response, post_data)

                if not validate_csrf_token(
                    environ, csrf_token, self.cfg.admin_port, self.cfg.bind_domain
                ):
                    return self._error(
                        start_response, "403 Forbidden", "CSRF validation failed"
                    )

                if path == "/create":
                    return self._create(environ, start_response, post_data)
                if path == "/create-page":
                    return self._create_page(environ, start_response, post_data)
                if path == "/save":
                    return self._save(environ, start_response, post_data)
                if path == "/save-page":
                    return self._save_page(environ, start_response, post_data)
                if path == "/delete":
                    return self._delete(environ, start_response, post_data)
                if path == "/delete-page":
                    return self._delete_page(environ, start_response, post_data)
                if path == "/regen":
                    return self._regen(environ, start_response)
                if path == "/preview":
                    return self._live_preview(environ, start_response, post_data)
                if path == "/set-theme":
                    return self._set_theme(environ, start_response, post_data)
                if path == "/ai-assist":
                    return self._ai_assist(environ, start_response, post_data)
                if path == "/translate":
                    return self._translate(environ, start_response, post_data)
                return self._send_404(start_response)

            return self._error(
                start_response, "405 Method Not Allowed", "Method not allowed"
            )
        except Exception as e:
            logger.error(f"[ADMIN-ERROR] {e}")
            return self._error(
                start_response, "500 Internal Server Error", "Server error"
            )

    # ---------- HTMX helpers ----------

    def _is_htmx(self, environ: dict) -> bool:
        return environ.get("HTTP_HX_REQUEST", "") == "true"

    def _get_existing_csrf(self, environ: dict) -> str:
        """Reuse existing CSRF cookie if present and valid, otherwise generate new."""
        cookie_header = environ.get("HTTP_COOKIE", "")
        for cookie in cookie_header.split(";"):
            cookie = cookie.strip()
            if cookie.startswith("csrf_token="):
                token = cookie[11:]
                if is_valid_csrf_format(token):
                    return token
                break
        return generate_csrf_token()

    # ---------- Page handlers ----------

    def _dashboard(self, environ: dict, start_response):
        qs = parse_qs(environ.get("QUERY_STRING", ""))
        try:
            page = max(1, int(qs.get("page", ["1"])[0]))
        except (ValueError, TypeError):
            page = 1

        arts = list_articles(
            self.cfg.article_dir, self.cfg.max_file_size, include_drafts=True
        )
        total = len(arts)
        pages = max(1, (total + self.cfg.page_size - 1) // self.cfg.page_size)
        start_idx = (page - 1) * self.cfg.page_size
        page_arts = arts[start_idx : start_idx + self.cfg.page_size]

        csrf_token = self._get_existing_csrf(environ)
        rows = []
        for art in page_arts:
            safe_title = escape_html(art.title[:80])
            tags_display = (
                f"<span class='tag'>{escape_html(', '.join(art.tag_list))}</span>"
                if art.tag_list
                else ""
            )
            draft_label = (
                '<span style="background:#f39c12;color:#fff;padding:0.1rem 0.4rem;border-radius:4px;font-size:0.75rem;margin-left:0.5rem;">草稿</span>'
                if art.is_draft
                else ""
            )
            cat_display = (
                f'<span style="color:#888;font-size:0.8rem;margin-left:0.5rem;">[{escape_html(art.category)}]</span>'
                if art.category
                else ""
            )
            translate_html = (
                f"""
    <form method="post" action="/translate" style="display:inline;">
      <input type="hidden" name="csrf_token" value="{escape_attr(csrf_token)}">
      <input type="hidden" name="file" value="{escape_attr(art.file)}">
      <select name="lang" onchange="if(this.value)this.form.submit()" 
              style="padding:0.2rem 0.4rem;font-size:0.8rem;border-radius:4px;
                     background:var(--surface);color:var(--text);border:1px solid var(--border);">
        <option value="">翻译▼</option>
        <option value="en">English</option>
        <option value="ja">日本語</option>
      </select>
    </form>"""
                if self.cfg.ai_enabled and self.cfg.ai_api_key
                else ""
            )
            rows.append(f"""
<tr style="{"background:#fff9e6;" if art.is_draft else ""}">
  <td><a href="/edit?file={escape_attr(art.file)}">{safe_title}</a>{cat_display}{draft_label} {tags_display}</td>
  <td>{escape_html(art.date)}</td>
  <td>
    <form method="post" action="/delete" hx-post="/delete" hx-target="closest tr" hx-swap="outerHTML swap:0.3s" hx-confirm="删除不可恢复，确定？" style="display:inline;">
      <input type="hidden" name="csrf_token" value="{escape_attr(csrf_token)}">
      <input type="hidden" name="file" value="{escape_attr(art.file)}">
      <button type="submit" class="btn-danger btn-sm" onclick="return confirm('删除不可恢复，确定？')">删除</button>
    </form>
    {translate_html}
  </td>
</tr>""")

        # Pagination
        nav = []
        if page > 1:
            nav.append(f'<a href="/?page={page - 1}">← 上一页</a>')
        if page < pages:
            nav.append(f'<a href="/?page={page + 1}">下一页 →</a>')
        nav_html = f'<div class="nav-links">{" ".join(nav)}</div>' if nav else ""

        body = f"""<div class="admin-wrapper">
<h1>管理后台</h1>
<div class="security-notice">
  <strong>安全提醒：</strong>所有操作已记录审计日志 | CSRF保护已启用
</div>
<div class="actions">
  <a href="/new" class="btn-primary">+ 新建文章</a>
  <a href="/new-page" class="btn-primary">+ 新建页面</a>
  <a href="/pages" class="btn-secondary">📄 管理页面</a>
  <form method="post" action="/regen" hx-post="/regen" hx-target="#regen-status" style="display:inline;">
    <input type="hidden" name="csrf_token" value="{escape_attr(csrf_token)}">
    <button type="submit" class="btn-secondary">重新生成静态页</button>
  </form>
  <span id="regen-status" style="margin-left:0.5rem;font-size:0.9rem;"></span>
  <a href="/theme" class="btn-secondary">主题</a>
  <input type="search" id="article-search" placeholder="搜索文章标题..." 
         style="max-width:200px;margin-left:auto;padding:0.4rem 0.6rem;border:1px solid var(--border);border-radius:6px;background:var(--surface);color:var(--text);font-size:0.9rem;" 
         oninput="filterArticles(this.value)">
</div>
<script>
function filterArticles(q) {{
  var rows = document.querySelectorAll('table.admin-table tbody tr');
  q = q.toLowerCase();
  rows.forEach(function(row) {{
    var text = row.textContent.toLowerCase();
    row.style.display = text.includes(q) ? '' : 'none';
  }});
}}
</script>
<table class="admin-table">
<thead><tr><th style="width:55%">标题</th><th style="width:25%">发布时间</th><th style="width:20%">操作</th></tr></thead>
<tbody>{"".join(rows)}</tbody>
</table>
{nav_html}
<p style="margin-top:1rem;color:#666;font-size:0.9rem;">共 {total} 篇文章，第 {page}/{pages} 页</p>
</div>"""

        return self._render_page(
            start_response, "管理后台", body, csrf_token, extra_script=True
        )

    def _new_form(self, environ: dict, start_response):
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        csrf_token = self._get_existing_csrf(environ)
        # Build category datalist from existing articles
        all_arts = list_articles(
            self.cfg.article_dir, self.cfg.max_file_size, include_drafts=True
        )
        categories = sorted({a.category for a in all_arts if a.category})
        datalist = ""
        if categories:
            options = "\n".join(
                f'<option value="{escape_attr(c)}">' for c in categories
            )
            datalist = f'<datalist id="category-list">{options}</datalist>'

        if self.cfg.ai_enabled and self.cfg.ai_api_key:
            ai_panel_html = f"""<div id="ai-panel" class="ai-panel" style="display:none;margin:0.75rem 0;padding:0.75rem;background:var(--surface);border:1px solid var(--border);border-radius:6px;">
        <div style="display:flex;gap:0.5rem;flex-wrap:wrap;align-items:center;">
          <span style="font-size:0.85rem;color:#666;">AI 助手:</span>
          <button type="button" class="ai-btn" onclick="aiComplete()">续写</button>
          <button type="button" class="ai-btn" onclick="aiPolish()">润色</button>
          <button type="button" class="ai-btn" onclick="aiTranslate('en')">译英</button>
          <button type="button" class="ai-btn" onclick="aiTranslate('ja')">译日</button>
          <button type="button" class="ai-btn" onclick="aiSuggestTags()">推荐标签</button>
          <span id="ai-status" style="font-size:0.8rem;color:#888;margin-left:auto;"></span>
        </div>
      </div>"""
        else:
            ai_panel_html = ""

        body = f"""<div class="admin-wrapper">
<h1>新建文章</h1>
<div class="editor-grid">
  <div class="editor-form">
    <form method="post" action="/create" id="article-form">
      <input type="hidden" name="csrf_token" value="{escape_attr(csrf_token)}">
      <p><input name="title" placeholder="文章标题" required maxlength="{self.cfg.max_title_length}"></p>
      <p><input name="date" value="{now}" required pattern="\\d{{4}}-\\d{{2}}-\\d{{2}} \\d{{2}}:\\d{{2}}"></p>
      <p><input name="category" list="category-list" placeholder="分类"></p>
      {datalist}
      <p><input name="tags" placeholder="标签，用逗号分隔"></p>
      <p>
        <select name="status">
          <option value="published">发布</option>
          <option value="draft">草稿</option>
        </select>
      </p>
      {ai_panel_html}
      <div id="drop-zone" style="margin-bottom:0.75rem;padding:1rem;border:2px dashed #ccc;border-radius:6px;text-align:center;color:#888;cursor:pointer;" onclick="document.getElementById('file-input').click()" ondragover="event.preventDefault();this.style.borderColor='#e74c3c';this.style.color='#e74c3c'" ondragleave="this.style.borderColor='#ccc';this.style.color='#888'" ondrop="handleDrop(event)">拖拽图片到此处上传，或点击选择文件<input type="file" id="file-input" accept="image/*" style="display:none" onchange="handleFileSelect(event)"></div>
      <p><textarea name="content" placeholder="支持 Markdown：# 标题、**粗体**、*斜体*、`代码`、[链接](url)、```代码块```" required maxlength="{self.cfg.max_content_length}" hx-trigger="keyup changed delay:500ms" hx-post="/preview" hx-target="#live-preview" hx-include="#article-form"></textarea></p>
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
        return self._render_page(
            start_response, "新建文章", body, csrf_token, extra_script=True
        )

    def _edit_form(self, environ: dict, start_response):
        qs = parse_qs(environ.get("QUERY_STRING", ""))
        fname = qs.get("file", [""])[0]
        if not validate_filename(fname):
            return self._error(start_response, "400 Bad Request", "Invalid filename")

        path = self.cfg.article_dir / fname
        if not path.is_file():
            return self._error(start_response, "404 Not Found", "Article not found")

        meta = list_articles(
            self.cfg.article_dir, self.cfg.max_file_size, include_drafts=True
        )
        article = next((a for a in meta if a.file == fname), None)
        if not article:
            return self._error(
                start_response, "500 Internal Server Error", "Parse failed"
            )

        # Extract raw markdown content from article file
        text = get_raw_content(path)

        # Build AI panel (conditionally rendered)
        if self.cfg.ai_enabled and self.cfg.ai_api_key:
            ai_panel_html = f"""<div id="ai-panel" class="ai-panel" style="display:none;margin:0.75rem 0;padding:0.75rem;background:var(--surface);border:1px solid var(--border);border-radius:6px;">
        <div style="display:flex;gap:0.5rem;flex-wrap:wrap;align-items:center;">
          <span style="font-size:0.85rem;color:#666;">AI 助手:</span>
          <button type="button" class="ai-btn" onclick="aiComplete()">续写</button>
          <button type="button" class="ai-btn" onclick="aiPolish()">润色</button>
          <button type="button" class="ai-btn" onclick="aiTranslate('en')">译英</button>
          <button type="button" class="ai-btn" onclick="aiTranslate('ja')">译日</button>
          <button type="button" class="ai-btn" onclick="aiSuggestTags()">推荐标签</button>
          <span id="ai-status" style="font-size:0.8rem;color:#888;margin-left:auto;"></span>
        </div>
      </div>"""
        else:
            ai_panel_html = ""

        # Build category datalist
        categories = sorted({a.category for a in meta if a.category})
        datalist = ""
        if categories:
            options = "\n".join(
                f'<option value="{escape_attr(c)}">' for c in categories
            )
            datalist = f'<datalist id="category-list">{options}</datalist>'

        draft_selected = " selected" if article.is_draft else ""
        pub_selected = " selected" if article.is_published else ""

        csrf_token = self._get_existing_csrf(environ)
        body = f"""<div class="admin-wrapper">
<h1>编辑文章</h1>
<div class="editor-grid">
  <div class="editor-form">
    <form method="post" action="/save" id="article-form">
      <input type="hidden" name="csrf_token" value="{escape_attr(csrf_token)}">
      <input type="hidden" name="file" value="{escape_attr(fname)}">
      <p><input name="title" value="{escape_attr(article.title)}" required maxlength="{self.cfg.max_title_length}"></p>
      <p><input name="date" value="{escape_html(article.date)}" required></p>
      <p><input name="category" list="category-list" value="{escape_attr(article.category)}" placeholder="分类"></p>
      {datalist}
      <p><input name="tags" value="{escape_attr(article.tags)}" placeholder="标签，用逗号分隔"></p>
      <p>
        <select name="status">
          <option value="published"{pub_selected}>发布</option>
          <option value="draft"{draft_selected}>草稿</option>
        </select>
      </p>
      {ai_panel_html}
      <div id="drop-zone" style="margin-bottom:0.75rem;padding:1rem;border:2px dashed #ccc;border-radius:6px;text-align:center;color:#888;cursor:pointer;" onclick="document.getElementById('file-input').click()" ondragover="event.preventDefault();this.style.borderColor='#e74c3c';this.style.color='#e74c3c'" ondragleave="this.style.borderColor='#ccc';this.style.color='#888'" ondrop="handleDrop(event)">拖拽图片到此处上传，或点击选择文件<input type="file" id="file-input" accept="image/*" style="display:none" onchange="handleFileSelect(event)"></div>
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
        return self._render_page(
            start_response,
            f"编辑: {article.title}",
            body,
            csrf_token,
            extra_script=True,
        )

    def _live_preview(self, environ: dict, start_response, post_data=None):
        """HTMX endpoint for live preview."""
        if post_data is None:
            post_data = self._get_post_data(environ)
            csrf_token = post_data.get("csrf_token", [""])[0]
            if not validate_csrf_token(
                environ, csrf_token, self.cfg.admin_port, self.cfg.bind_domain
            ):
                return self._error(
                    start_response, "403 Forbidden", "CSRF validation failed"
                )
        content = post_data.get("content", [""])[0]
        html = (
            render_markdown(content)
            if content
            else '<p class="preview-placeholder">（无内容）</p>'
        )
        headers = [
            ("Content-Type", "text/html; charset=utf-8")
        ] + get_security_headers()
        start_response("200 OK", headers)
        return [html.encode("utf-8")]

    def _create(self, environ: dict, start_response, post_data):
        title = post_data.get("title", [""])[0]
        date = post_data.get("date", [""])[0]
        content = post_data.get("content", [""])[0]
        tags = post_data.get("tags", [""])[0]
        category = post_data.get("category", [""])[0]
        status = post_data.get("status", ["published"])[0]
        if status not in ("published", "draft"):
            status = "published"
        client_ip = get_real_ip(environ)

        if not all([title, date, content]):
            return self._error(start_response, "400 Bad Request", "Missing fields")

        from .security import slugify

        slug = slugify(title)
        fname = f"{date[:10]}-{slug}.html"
        if (self.cfg.article_dir / fname).exists():
            fname = f"{date[:10]}-{slug}-{secrets.token_urlsafe(4)}.html"

        write_article(
            self.cfg.article_dir,
            fname,
            title,
            date,
            slug,
            content,
            tags,
            "",
            category,
            status,
            skip_html_generation=True,
        )
        arts = list_articles(self.cfg.article_dir, self.cfg.max_file_size)
        standalones = list_standalones(self.cfg.standalone_dir, self.cfg.max_file_size)
        generate_static_pages(arts, self.cfg, standalones)
        logger.info(f"[CREATE] {fname} from {client_ip}")
        return self._redirect(start_response, "/")

    def _save(self, environ: dict, start_response, post_data):
        fname = post_data.get("file", [""])[0]
        title = post_data.get("title", [""])[0]
        date = post_data.get("date", [""])[0]
        content = post_data.get("content", [""])[0]
        tags = post_data.get("tags", [""])[0]
        category = post_data.get("category", [""])[0]
        status = post_data.get("status", ["published"])[0]
        if status not in ("published", "draft"):
            status = "published"
        client_ip = get_real_ip(environ)

        if not all([fname, title, date, content]):
            return self._error(start_response, "400 Bad Request", "Missing fields")
        if not validate_filename(fname):
            return self._error(start_response, "400 Bad Request", "Invalid filename")

        from .security import slugify

        slug = slugify(title)
        write_article(
            self.cfg.article_dir,
            fname,
            title,
            date,
            slug,
            content,
            tags,
            "",
            category,
            status,
            skip_html_generation=True,
        )
        arts = list_articles(self.cfg.article_dir, self.cfg.max_file_size)
        standalones = list_standalones(self.cfg.standalone_dir, self.cfg.max_file_size)
        generate_static_pages(arts, self.cfg, standalones)
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
            standalones = list_standalones(
                self.cfg.standalone_dir, self.cfg.max_file_size
            )
            generate_static_pages(arts, self.cfg, standalones)
            logger.info(f"[DELETE] {fname} from {client_ip}")
        if self._is_htmx(environ):
            headers = get_security_headers()
            start_response("200 OK", headers)
            return [b""]
        else:
            return self._redirect(start_response, "/")

    def _regen(self, environ: dict, start_response):
        client_ip = get_real_ip(environ)
        arts = list_articles(self.cfg.article_dir, self.cfg.max_file_size)
        standalones = list_standalones(self.cfg.standalone_dir, self.cfg.max_file_size)
        generate_static_pages(arts, self.cfg, standalones)
        logger.info(f"[REGEN] from {client_ip}")
        if self._is_htmx(environ):
            headers = [
                ("Content-Type", "text/html; charset=utf-8")
            ] + get_security_headers()
            start_response("200 OK", headers)
            return [
                '<span style="color:green;font-size:0.9rem;">✓ 已重新生成</span>'.encode(
                    "utf-8"
                )
            ]
        return self._redirect(start_response, "/")

    # ---------- Theme Management ----------

    def _theme_page(self, environ: dict, start_response):
        """Show theme selection page."""
        from pathlib import Path
        from .core.template import list_themes

        themes_dir = Path("themes")
        themes = list_themes(themes_dir)
        current_theme = self.cfg.theme_name
        csrf_token = self._get_existing_csrf(environ)

        theme_rows = []
        for theme in themes:
            selected = (
                " border: 2px solid #e74c3c;"
                if theme["name"] == current_theme
                else " border: 2px solid transparent;"
            )
            default_badge = (
                ' <span style="background:#27ae60;color:#fff;padding:0.1rem 0.4rem;border-radius:4px;font-size:0.7rem;margin-left:0.5rem;">当前</span>'
                if theme["name"] == current_theme
                else ""
            )
            layouts = (
                ", ".join(theme.get("layouts", ["blog"]))
                if theme.get("layouts")
                else "blog"
            )
            desc = escape_html(theme.get("description", ""))
            theme_rows.append(f"""
<div style="display:inline-block;width:200px;margin:0.5rem;padding:1rem;border-radius:8px;background:var(--surface);{selected}">
  <h3 style="margin:0 0 0.5rem 0;font-size:1rem;">{escape_html(theme.get("display_name", theme["name"]))}{default_badge}</h3>
  <p style="color:#888;font-size:0.8rem;margin:0 0 0.5rem 0;">{desc}</p>
  <p style="color:#666;font-size:0.75rem;margin:0 0 0.75rem 0;">布局: {layouts}</p>
  <form method="post" action="/set-theme" style="margin:0;">
    <input type="hidden" name="csrf_token" value="{escape_attr(csrf_token)}">
    <input type="hidden" name="theme" value="{escape_attr(theme["name"])}">
    <button type="submit" class="btn-primary btn-sm" {'disabled style="opacity:0.5;"' if theme["name"] == current_theme else ""}>选择</button>
  </form>
</div>""")

        body = f"""<div class="admin-wrapper">
<h1>主题管理</h1>
<div class="actions">
  <a href="/" class="btn-secondary">返回后台</a>
</div>
<p style="margin-bottom:1rem;color:#666;">当前主题：<strong>{escape_html(current_theme)}</strong></p>
<div style="display:flex;flex-wrap:wrap;gap:0.5rem;">
  {"".join(theme_rows)}
</div>
</div>"""
        return self._render_page(start_response, "主题管理", body, csrf_token)

    def _set_theme(self, environ: dict, start_response, post_data):
        """Handle theme switching."""
        theme_name = post_data.get("theme", [""])[0]
        if not theme_name:
            return self._error(start_response, "400 Bad Request", "Missing theme name")

        manifest_path = Path("themes") / theme_name / "manifest.json"
        if not manifest_path.is_file():
            return self._error(start_response, "400 Bad Request", "Theme not found")

        self.cfg = self.cfg.merge(theme_name=theme_name)
        self._save_theme_config(theme_name)

        arts = list_articles(self.cfg.article_dir, self.cfg.max_file_size)
        standalones = list_standalones(self.cfg.standalone_dir, self.cfg.max_file_size)
        generate_static_pages(arts, self.cfg, standalones)

        logger.info(f"[THEME] Switched to: {theme_name}")

        return self._redirect(start_response, "/theme")

    def _save_theme_config(self, theme_name: str) -> None:
        """Persist theme configuration to config file."""
        config_dir = Path(".") / ".tinypage"
        config_dir.mkdir(parents=True, exist_ok=True)
        config_file = config_dir / "config.json"

        try:
            if config_file.exists():
                config_data = json.loads(config_file.read_text(encoding="utf-8"))
            else:
                config_data = {}

            config_data["theme_name"] = theme_name
            config_file.write_text(
                json.dumps(config_data, ensure_ascii=False, indent=2), encoding="utf-8"
            )
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"[THEME] Failed to persist config: {e}")

    def _ai_assist(self, environ: dict, start_response, post_data):
        """Handle AI assistance requests."""
        from .core.ai_assistance import build_ai_assistance, AIAssistanceError

        action = post_data.get("action", [""])[0]
        text = post_data.get("text", [""])[0]

        ai = build_ai_assistance(self.cfg)
        if not ai:
            result = {"error": "AI 未启用或未配置 API Key"}
        else:
            try:
                if action == "complete":
                    result = {"result": ai.complete_text(text)}
                elif action == "polish":
                    result = {"result": ai.polish_text(text)}
                elif action == "translate":
                    lang = post_data.get("lang", ["English"])[0]
                    lang_map = {"en": "English", "ja": "Japanese"}
                    target = lang_map.get(lang, "English")
                    result = {"result": ai.translate_text(text, target)}
                elif action == "suggest_tags":
                    result = {"result": ai.suggest_tags(text)}
                elif action == "summarize":
                    result = {"result": ai.summarize(text)}
                else:
                    result = {"error": f"未知操作: {action}"}
            except AIAssistanceError as e:
                result = {"error": str(e)}

        import json as json_mod

        headers = [
            ("Content-Type", "application/json"),
        ] + get_security_headers()
        start_response("200 OK", headers)
        return [json_mod.dumps(result).encode("utf-8")]

    def _translate(self, environ: dict, start_response, post_data):
        """Handle article translation requests."""
        from .content import translate_article

        fname = post_data.get("file", [""])[0]
        target_lang = post_data.get("lang", ["en"])[0]
        client_ip = get_real_ip(environ)

        if not validate_filename(fname):
            return self._error(start_response, "400 Bad Request", "Invalid filename")

        result = translate_article(
            self.cfg.article_dir,
            fname,
            target_lang,
            self.cfg,
        )

        if result.get("success"):
            logger.info(f"[TRANSLATE] {fname} -> {target_lang} from {client_ip}")
            return self._redirect(start_response, "/")
        else:
            return self._error(
                start_response, "400 Bad Request", result.get("error", "翻译失败")
            )

    # ---------- Standalone Pages ----------

    def _pages_dashboard(self, environ: dict, start_response):
        pages = list_standalones(self.cfg.standalone_dir, self.cfg.max_file_size)
        csrf_token = self._get_existing_csrf(environ)
        rows = []
        for page in pages:
            safe_title = escape_html(page.title[:80] or page.file)
            rows.append(f"""
<tr>
  <td><a href="/edit-page?file={escape_attr(page.file)}">{safe_title}</a></td>
  <td>/standalone/{escape_attr(page.file)}</td>
  <td>
    <form method="post" action="/delete-page" hx-post="/delete-page" hx-target="closest tr" hx-swap="outerHTML swap:0.3s" hx-confirm="删除不可恢复，确定？" style="display:inline;">
      <input type="hidden" name="csrf_token" value="{escape_attr(csrf_token)}">
      <input type="hidden" name="file" value="{escape_attr(page.file)}">
      <button type="submit" class="btn-danger btn-sm" onclick="return confirm('删除不可恢复，确定？')">删除</button>
    </form>
  </td>
</tr>""")

        body = f"""<div class="admin-wrapper">
<h1>独立页面管理</h1>
<div class="actions">
  <a href="/new-page" class="btn-primary">+ 新建页面</a>
  <a href="/" class="btn-secondary">返回文章</a>
</div>
<table class="admin-table">
<thead><tr><th style="width:45%">标题</th><th style="width:35%">路径</th><th style="width:20%">操作</th></tr></thead>
<tbody>{"".join(rows)}</tbody>
</table>
<p style="margin-top:1rem;color:#666;font-size:0.9rem;">共 {len(pages)} 个页面</p>
</div>"""
        return self._render_page(
            start_response, "独立页面", body, csrf_token, extra_script=True
        )

    def _new_page_form(self, environ: dict, start_response):
        csrf_token = self._get_existing_csrf(environ)
        body = f"""<div class="admin-wrapper">
<h1>新建独立页面</h1>
<div class="editor-grid">
  <div class="editor-form">
    <form method="post" action="/create-page" id="page-form">
      <input type="hidden" name="csrf_token" value="{escape_attr(csrf_token)}">
      <p><input name="title" placeholder="页面标题" required maxlength="{self.cfg.max_title_length}"></p>
      <p><input name="slug" placeholder="URL 标识（如 about）" required pattern="[a-zA-Z0-9\\u4e00-\\u9fa5_-]+" title="字母、数字、中文、下划线、连字符"></p>
      <p><textarea name="content" placeholder="支持 Markdown" required maxlength="{self.cfg.max_content_length}" hx-trigger="keyup changed delay:500ms" hx-post="/preview" hx-target="#live-preview" hx-include="#page-form"></textarea></p>
      <p>
        <button type="submit" class="btn-primary">创建</button>
        <a href="/pages" class="btn-secondary">返回</a>
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
        return self._render_page(
            start_response, "新建页面", body, csrf_token, extra_script=True
        )

    def _edit_page_form(self, environ: dict, start_response):
        from .content import validate_page_filename

        qs = parse_qs(environ.get("QUERY_STRING", ""))
        fname = qs.get("file", [""])[0]
        if not validate_page_filename(fname):
            return self._error(start_response, "400 Bad Request", "Invalid filename")

        path = self.cfg.standalone_dir / fname
        if not path.is_file():
            return self._error(start_response, "404 Not Found", "Page not found")

        pages = list_standalones(self.cfg.standalone_dir, self.cfg.max_file_size)
        page = next((p for p in pages if p.file == fname), None)
        if not page:
            return self._error(
                start_response, "500 Internal Server Error", "Parse failed"
            )

        text = get_raw_content(path)

        csrf_token = self._get_existing_csrf(environ)

        if self.cfg.ai_enabled and self.cfg.ai_api_key:
            ai_panel_html = f"""<div id="ai-panel" class="ai-panel" style="display:none;margin:0.75rem 0;padding:0.75rem;background:var(--surface);border:1px solid var(--border);border-radius:6px;">
        <div style="display:flex;gap:0.5rem;flex-wrap:wrap;align-items:center;">
          <span style="font-size:0.85rem;color:#666;">AI 助手:</span>
          <button type="button" class="ai-btn" onclick="aiComplete()">续写</button>
          <button type="button" class="ai-btn" onclick="aiPolish()">润色</button>
          <button type="button" class="ai-btn" onclick="aiTranslate('en')">译英</button>
          <button type="button" class="ai-btn" onclick="aiTranslate('ja')">译日</button>
          <span id="ai-status" style="font-size:0.8rem;color:#888;margin-left:auto;"></span>
        </div>
      </div>"""
        else:
            ai_panel_html = ""

        body = f"""<div class="admin-wrapper">
<h1>编辑页面</h1>
<div class="editor-grid">
  <div class="editor-form">
    <form method="post" action="/save-page" id="page-form">
      <input type="hidden" name="csrf_token" value="{escape_attr(csrf_token)}">
      <input type="hidden" name="file" value="{escape_attr(fname)}">
      <p><input name="title" value="{escape_attr(page.title)}" required maxlength="{self.cfg.max_title_length}"></p>
      <p><input name="slug" value="{escape_attr(page.slug)}" placeholder="URL 标识" required pattern="[a-zA-Z0-9\\u4e00-\\u9fa5_-]+"></p>
      {ai_panel_html}
      <div id="drop-zone" style="margin-bottom:0.75rem;padding:1rem;border:2px dashed #ccc;border-radius:6px;text-align:center;color:#888;cursor:pointer;" onclick="document.getElementById('file-input').click()" ondragover="event.preventDefault();this.style.borderColor='#e74c3c';this.style.color='#e74c3c'" ondragleave="this.style.borderColor='#ccc';this.style.color='#888'" ondrop="handleDrop(event)">拖拽图片到此处上传，或点击选择文件<input type="file" id="file-input" accept="image/*" style="display:none" onchange="handleFileSelect(event)"></div>
      <p><textarea name="content" required maxlength="{self.cfg.max_content_length}" hx-trigger="keyup changed delay:500ms" hx-post="/preview" hx-target="#live-preview" hx-include="#page-form">{escape_html(text)}</textarea></p>
      <p>
        <button type="submit" class="btn-primary">保存更改</button>
        <a href="/pages" class="btn-secondary">返回</a>
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
        return self._render_page(
            start_response, f"编辑: {page.title}", body, csrf_token, extra_script=True
        )

    def _create_page(self, environ: dict, start_response, post_data):
        from .content import validate_page_filename

        title = post_data.get("title", [""])[0]
        slug = post_data.get("slug", [""])[0]
        content = post_data.get("content", [""])[0]
        client_ip = get_real_ip(environ)

        if not all([title, slug, content]):
            return self._error(start_response, "400 Bad Request", "Missing fields")

        fname = f"{slug}.html"
        if not validate_page_filename(fname):
            return self._error(start_response, "400 Bad Request", "Invalid slug")
        if (self.cfg.standalone_dir / fname).exists():
            return self._error(start_response, "409 Conflict", "Page already exists")

        self.cfg.standalone_dir.mkdir(parents=True, exist_ok=True)
        write_standalone(self.cfg.standalone_dir, fname, title, content)
        arts = list_articles(self.cfg.article_dir, self.cfg.max_file_size)
        standalones = list_standalones(self.cfg.standalone_dir, self.cfg.max_file_size)
        generate_static_pages(arts, self.cfg, standalones)
        logger.info(f"[CREATE-PAGE] {fname} from {client_ip}")
        return self._redirect(start_response, "/pages")

    def _save_page(self, environ: dict, start_response, post_data):
        from .content import validate_page_filename

        fname = post_data.get("file", [""])[0]
        title = post_data.get("title", [""])[0]
        slug = post_data.get("slug", [""])[0]
        content = post_data.get("content", [""])[0]
        client_ip = get_real_ip(environ)

        if not all([fname, title, slug, content]):
            return self._error(start_response, "400 Bad Request", "Missing fields")
        if not validate_page_filename(fname):
            return self._error(start_response, "400 Bad Request", "Invalid filename")

        new_fname = f"{slug}.html"
        # If slug changed, delete old file
        if new_fname != fname:
            old_path = self.cfg.standalone_dir / fname
            if old_path.is_file():
                delete_standalone(old_path)

        write_standalone(self.cfg.standalone_dir, new_fname, title, content)
        arts = list_articles(self.cfg.article_dir, self.cfg.max_file_size)
        standalones = list_standalones(self.cfg.standalone_dir, self.cfg.max_file_size)
        generate_static_pages(arts, self.cfg, standalones)
        logger.info(f"[SAVE-PAGE] {new_fname} from {client_ip}")
        return self._redirect(start_response, "/pages")

    def _delete_page(self, environ: dict, start_response, post_data):
        from .content import validate_page_filename

        fname = post_data.get("file", [""])[0]
        client_ip = get_real_ip(environ)
        if not validate_page_filename(fname):
            return self._error(start_response, "400 Bad Request", "Invalid filename")
        path = self.cfg.standalone_dir / fname
        if path.is_file():
            delete_standalone(path)
            arts = list_articles(self.cfg.article_dir, self.cfg.max_file_size)
            standalones = list_standalones(
                self.cfg.standalone_dir, self.cfg.max_file_size
            )
            generate_static_pages(arts, self.cfg, standalones)
            logger.info(f"[DELETE-PAGE] {fname} from {client_ip}")
        if self._is_htmx(environ):
            headers = get_security_headers()
            start_response("200 OK", headers)
            return [b""]
        else:
            return self._redirect(start_response, "/pages")

    def _upload(self, environ: dict, start_response, post_data):
        """Handle base64-encoded image uploads."""
        import base64

        client_ip = get_real_ip(environ)
        logger.info(f"[UPLOAD-DEBUG] 收到上传请求 from {client_ip}")
        logger.info(f"[UPLOAD-DEBUG] POST数据键: {list(post_data.keys())}")

        filename = post_data.get("filename", [""])[0]
        data_b64 = post_data.get("data", [""])[0]
        csrf_token = post_data.get("csrf_token", [""])[0]

        logger.info(f"[UPLOAD-DEBUG] 文件名: '{filename}'")
        logger.info(
            f"[UPLOAD-DEBUG] Base64数据长度: {len(data_b64) if data_b64 else 0}"
        )
        logger.info(f"[UPLOAD-DEBUG] CSRF token存在: {bool(csrf_token)}")

        if not filename or not data_b64:
            logger.error(f"[UPLOAD-DEBUG] 缺少文件名或数据")
            return self._json_error(
                start_response, "400 Bad Request", "Missing filename or data"
            )

        # Sanitize filename
        filename = re.sub(r"[^a-zA-Z0-9._-]", "_", filename)
        logger.info(f"[UPLOAD-DEBUG] 清理后文件名: '{filename}'")

        if not filename or ".." in filename:
            logger.error(f"[UPLOAD-DEBUG] 无效文件名: '{filename}'")
            return self._json_error(
                start_response, "400 Bad Request", "Invalid filename"
            )

        # Validate file extension against whitelist
        ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp"}
        ext = Path(filename).suffix.lower()
        logger.info(f"[UPLOAD-DEBUG] 文件扩展名: '{ext}'")

        if ext not in ALLOWED_EXTENSIONS:
            logger.error(f"[UPLOAD-DEBUG] 文件类型不允许: {ext}")
            return self._json_error(
                start_response, "400 Bad Request", f"File type not allowed: {ext}"
            )

        # Determine subdir by month
        now = datetime.now()
        subdir = self.cfg.static_dir / "images" / f"{now.year:04d}-{now.month:02d}"
        logger.info(f"[UPLOAD-DEBUG] 目标目录: {subdir}")

        subdir.mkdir(parents=True, exist_ok=True)

        # Decode base64 (data URI prefix is stripped if present)
        if "," in data_b64:
            data_b64 = data_b64.split(",", 1)[1]
            logger.info(f"[UPLOAD-DEBUG] 已去除Data URI前缀")

        try:
            raw_data = base64.b64decode(data_b64)
            logger.info(
                f"[UPLOAD-DEBUG] Base64解码成功，原始数据大小: {len(raw_data)} bytes"
            )
        except Exception as e:
            logger.error(f"[UPLOAD-DEBUG] Base64解码失败: {e}")
            return self._json_error(
                start_response, "400 Bad Request", "Invalid base64 data"
            )

        if len(raw_data) > 10 * 1024 * 1024:
            logger.error(f"[UPLOAD-DEBUG] 文件过大: {len(raw_data)} bytes")
            return self._json_error(
                start_response, "400 Bad Request", "File too large (max 10MB)"
            )

        # Validate magic bytes (file header) to ensure it's a real image
        MAGIC_BYTES = {
            b"\x89PNG\r\n\x1a\n": ".png",
            b"\xff\xd8\xff": ".jpg",
            b"GIF87a": ".gif",
            b"GIF89a": ".gif",
            b"RIFF": ".webp",  # WebP starts with RIFF....WEBP
        }
        is_valid = False
        header_hex = raw_data[:16].hex() if len(raw_data) >= 16 else raw_data.hex()
        logger.info(f"[UPLOAD-DEBUG] 文件头部(hex): {header_hex}")

        for magic, expected_ext in MAGIC_BYTES.items():
            if raw_data[: len(magic)] == magic:
                logger.info(f"[UPLOAD-DEBUG] 匹配文件格式: {expected_ext}")
                if ext == expected_ext:
                    is_valid = True
                    break
                # Special check for WebP (RIFF header needs full validation)
                if expected_ext == ".webp" and ext == ".webp" and len(raw_data) >= 12:
                    if raw_data[8:12] == b"WEBP":
                        is_valid = True
                        break

        if not is_valid:
            logger.error(f"[UPLOAD-DEBUG] 无效图片格式，扩展名: {ext}")
            return self._json_error(
                start_response, "400 Bad Request", "Invalid image format"
            )

        target = subdir / filename
        # Avoid overwrite by appending number
        if target.exists():
            stem = target.stem
            suffix = target.suffix
            counter = 1
            while target.exists():
                target = subdir / f"{stem}-{counter}{suffix}"
                counter += 1
            logger.info(f"[UPLOAD-DEBUG] 文件已存在，使用新名称: {target.name}")

        target.write_bytes(raw_data)
        rel_path = f"/static/images/{now.year:04d}-{now.month:02d}/{target.name}"
        logger.info(f"[UPLOAD] {rel_path} from {client_ip}")
        logger.info(f"[UPLOAD-DEBUG] 上传成功，目标路径: {target}")

        headers = [("Content-Type", "application/json")] + get_security_headers()
        start_response("200 OK", headers)
        return [json.dumps({"success": True, "url": rel_path}).encode("utf-8")]

    # ---------- Response helpers ----------

    def _render_page(
        self,
        start_response,
        title: str,
        body: str,
        csrf_token: str,
        extra_script: bool = False,
    ):
        htmx_script = f'<script src="{HTMX_CDN}"></script>' if extra_script else ""
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{escape_html(title)} - 管理后台</title>
{htmx_script}
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
#drop-zone.dragover {{ border-color: #e74c3c; color: #e74c3c; background: #fdf2f2; }}
.ai-panel {{ transition: all 0.2s; }}
.ai-btn {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; padding: 0.4rem 0.8rem; border-radius: 4px; cursor: pointer; font-size: 0.8rem; transition: opacity 0.2s; }}
.ai-btn:hover {{ opacity: 0.85; }}
.ai-btn:disabled {{ opacity: 0.5; cursor: not-allowed; }}
#ai-status:empty {{ display: none; }}
</style>
<script>
function handleDrop(e) {{
  e.preventDefault();
  var zone = document.getElementById('drop-zone');
  zone.style.borderColor = '#ccc'; zone.style.color = '#888'; zone.style.background = 'transparent';
  var file = e.dataTransfer.files[0];
  if (file && file.type.startsWith('image/')) {{ uploadFile(file); }}
}}
function handleFileSelect(e) {{
  var file = e.target.files[0];
  if (file) {{ uploadFile(file); }}
}}
function uploadFile(file) {{
  var csrfInput = document.querySelector('input[name=csrf_token]');
  if (!csrfInput || !csrfInput.value) {{
    alert('CSRF token missing');
    return;
  }}
  var reader = new FileReader();
  reader.onload = function(ev) {{
    var b64 = ev.target.result;
    var b64Data = b64.split(',')[1];
    var body = 'csrf_token=' + encodeURIComponent(csrfInput.value) +
               '&filename=' + encodeURIComponent(file.name) + '&data=' + encodeURIComponent(b64Data);
    fetch('/upload', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
      body: body
    }}).then(function(r) {{ return r.json(); }}).then(function(data) {{
      if (data.success) {{
        var ta = document.querySelector('textarea[name=content]');
        ta.value += '\\n![](' + data.url + ')\\n';
        ta.dispatchEvent(new Event('input', {{ bubbles: true }}));
      }} else {{
        alert('Upload failed: ' + (data.error || 'Unknown error'));
      }}
    }}).catch(function(err) {{
      alert('Upload failed: Network error');
    }});
  }};
  reader.onerror = function() {{ alert('File read error'); }};
  reader.readAsDataURL(file);
}}
function showAIPanel() {{
  var panel = document.getElementById('ai-panel');
  if (panel) panel.style.display = 'block';
}}
function setAIStatus(msg, isError) {{
  var el = document.getElementById('ai-status');
  if (el) {{ el.textContent = msg; el.style.color = isError ? "#e74c3c" : "#27ae60"; }}
}}
function setAIBusy(busy) {{
  document.querySelectorAll('.ai-btn').forEach(function(b) {{ b.disabled = busy; }});
}}
function aiCall(action, data, callback) {{
  setAIBusy(true);
  setAIStatus('AI 处理中...', false);
  var csrf = document.querySelector('[name=csrf_token]').value;
  var body = 'csrf_token=' + encodeURIComponent(csrf) + '&action=' + action;
  for (var k in data) {{ body += '&' + encodeURIComponent(k) + '=' + encodeURIComponent(data[k]); }}
  fetch('/ai-assist', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
    body: body
  }}).then(function(r) {{ return r.json(); }}).then(function(result) {{
    setAIBusy(false);
    if (result.error) {{ setAIStatus('错误: ' + result.error, true); }}
    else {{ setAIStatus('\u2713', false); callback(result); }}
  }}).catch(function(e) {{ setAIBusy(false); setAIStatus('网络错误', true); }});
}}
function aiComplete() {{
  var ta = document.querySelector('textarea[name=content]');
  if (!ta.value) {{ setAIStatus('请先输入内容', true); return; }}
  aiCall('complete', {{ text: ta.value }}, function(r) {{ ta.value += '\\n\\n' + r.result; ta.dispatchEvent(new Event('input', {{ bubbles: true }})); }});
}}
function aiPolish() {{
  var ta = document.querySelector('textarea[name=content]');
  if (!ta.value) {{ setAIStatus('请先输入内容', true); return; }}
  aiCall('polish', {{ text: ta.value }}, function(r) {{ ta.value = r.result; ta.dispatchEvent(new Event('input', {{ bubbles: true }})); }});
}}
function aiTranslate(lang) {{
  var ta = document.querySelector('textarea[name=content]');
  if (!ta.value) {{ setAIStatus('请先输入内容', true); return; }}
  aiCall('translate', {{ text: ta.value, lang: lang }}, function(r) {{ ta.value = r.result; ta.dispatchEvent(new Event('input', {{ bubbles: true }})); }});
}}
function aiSuggestTags() {{
  var ta = document.querySelector('textarea[name=content]');
  var tagsInput = document.querySelector('input[name=tags]');
  if (!ta.value) {{ setAIStatus('请先输入内容', true); return; }}
  aiCall('suggest_tags', {{ text: ta.value }}, function(r) {{
    if (r.result && r.result.length > 0) {{
      var current = tagsInput.value || '';
      var newTags = current ? current.split(',').map(function(t) {{ return t.trim(); }}) : [];
      r.result.forEach(function(t) {{ if (newTags.indexOf(t) < 0) newTags.push(t); }});
      tagsInput.value = newTags.join(', ');
      setAIStatus('已推荐 ' + r.result.length + ' 个标签', false);
    }} else {{ setAIStatus('未找到标签', true); }}
  }});
}}
setTimeout(showAIPanel, 100);
</script>
</head>
<body>
{body}
</body>
</html>"""
        is_secure = bool(self.cfg.bind_domain)
        csrf_cookie = get_csrf_cookie_header(csrf_token, secure=is_secure)
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

    def _json_error(self, start_response, status: str, message: str):
        headers = [("Content-Type", "application/json")] + get_security_headers()
        start_response(status, headers)
        return [json.dumps({"success": False, "error": message}).encode("utf-8")]

    def _send_404(self, start_response):
        return self._error(start_response, "404 Not Found", "Not Found")

    def _get_post_data(self, environ: dict) -> dict:
        try:
            cl = int(environ.get("CONTENT_LENGTH", 0))
        except (ValueError, TypeError):
            cl = 0
        if cl <= 0:
            return {}
        if cl > self.MAX_POST_SIZE:
            logger.warning(
                f"[BLOCK] POST body too large: {cl} bytes (max {self.MAX_POST_SIZE})"
            )
            return {}
        data = environ["wsgi.input"].read(cl)
        environ["wsgi.input"] = io.BytesIO(data)
        return parse_qs(data.decode("utf-8", errors="replace"))
