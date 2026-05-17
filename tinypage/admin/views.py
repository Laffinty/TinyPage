"""Admin GET view handlers — render dashboard and form pages."""

from __future__ import annotations

from datetime import datetime
from urllib.parse import parse_qs

from ..config import Config
from ..content import list_articles, list_standalones, get_raw_content
from ..security import escape_html, escape_attr, validate_filename
from .templates import render_template, build_nav_html


def dashboard_view(environ: dict, cfg: Config, csrf_token: str) -> str:
    """Render article dashboard HTML body."""
    qs = parse_qs(environ.get("QUERY_STRING", ""))
    try:
        page = max(1, int(qs.get("page", ["1"])[0]))
    except (ValueError, TypeError):
        page = 1

    arts = list_articles(cfg.article_dir, cfg.max_file_size, include_drafts=True)
    total = len(arts)
    pages = max(1, (total + cfg.page_size - 1) // cfg.page_size)
    start_idx = (page - 1) * cfg.page_size
    page_arts = arts[start_idx : start_idx + cfg.page_size]

    draft_count = sum(1 for a in arts if a.is_draft)
    page_count = len(list_standalones(cfg.standalone_dir, cfg.max_file_size))

    rows = []
    for art in page_arts:
        safe_title = escape_html(art.title[:80])
        tags_display = (
            f"<span class='tag'>{escape_html(', '.join(art.tag_list))}</span>"
            if art.tag_list else ""
        )
        draft_label = '<span class="draft-badge">草稿</span>' if art.is_draft else ""
        cat_display = (
            f'<span style="color:var(--a-text-dim);font-size:0.8rem;margin-left:0.5rem;">[{escape_html(art.category)}]</span>'
            if art.category else ""
        )
        translate_html = (
            f'''<form method="post" action="/translate" style="display:inline;">
      <input type="hidden" name="csrf_token" value="{escape_attr(csrf_token)}">
      <input type="hidden" name="file" value="{escape_attr(art.file)}">
      <select name="lang" onchange="if(this.value)this.form.submit()"
              style="padding:0.25rem 0.5rem;font-size:0.8rem;border-radius:var(--a-radius-sm);
                     background:var(--a-surface);color:var(--a-text);border:1px solid var(--a-border);">
        <option value="">翻译▼</option>
        <option value="en">English</option>
        <option value="ja">日本語</option>
      </select>
    </form>'''
            if cfg.ai_enabled and cfg.ai_api_key else ""
        )
        rows.append(f"""<tr{" style='background:var(--a-surface-elevated);'" if art.is_draft else ""}>
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

    nav = []
    if page > 1:
        nav.append(f'<a href="/?page={page - 1}">← 上一页</a>')
    if page < pages:
        nav.append(f'<a href="/?page={page + 1}">下一页 →</a>')
    nav_html = f'<div class="nav-links">{" ".join(nav)}</div>' if nav else ""

    return render_template(
        "dashboard.html",
        total=total,
        draft_count=draft_count,
        page_count=page_count,
        csrf_token=csrf_token,
        rows="".join(rows),
        nav_html=nav_html,
        page=page,
        pages=pages,
    )


def article_form_view(environ: dict, cfg: Config, csrf_token: str, is_edit: bool = False) -> str:
    """Render new or edit article form HTML body."""
    from ..security import slugify

    if is_edit:
        qs = parse_qs(environ.get("QUERY_STRING", ""))
        fname = qs.get("file", [""])[0]
        if not validate_filename(fname):
            return "<p>Invalid filename</p>"
        path = cfg.article_dir / fname
        if not path.is_file():
            return "<p>Article not found</p>"
        meta = list_articles(cfg.article_dir, cfg.max_file_size, include_drafts=True)
        article = next((a for a in meta if a.file == fname), None)
        if not article:
            return "<p>Parse failed</p>"
        text = get_raw_content(path)
        heading = f"编辑: {escape_html(article.title)}"
        form_action = "/save"
        file_input = f'<input type="hidden" name="file" value="{escape_attr(fname)}">'
        title_val = escape_attr(article.title)
        date_val = escape_html(article.date)
        cat_val = escape_attr(article.category)
        tags_val = escape_attr(article.tags)
        pub_selected = " selected" if article.is_published else ""
        draft_selected = " selected" if article.is_draft else ""
        content_val = escape_html(text)
        submit_label = "保存更改"
    else:
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        heading = "新建文章"
        form_action = "/create"
        file_input = ""
        title_val = ""
        date_val = now
        cat_val = ""
        tags_val = ""
        pub_selected = " selected"
        draft_selected = ""
        content_val = ""
        submit_label = "发布"

    all_arts = list_articles(cfg.article_dir, cfg.max_file_size, include_drafts=True)
    categories = sorted({a.category for a in all_arts if a.category})
    datalist = ""
    if categories:
        options = "\n".join(f'<option value="{escape_attr(c)}">' for c in categories)
        datalist = f'<datalist id="category-list">{options}</datalist>'

    ai_panel = _build_ai_panel(cfg, csrf_token, suggest_tags=True)

    return render_template(
        "article_form.html",
        heading=heading,
        form_action=form_action,
        csrf_token=csrf_token,
        file_input=file_input,
        title=title_val,
        date=date_val,
        category=cat_val,
        tags=tags_val,
        datalist=datalist,
        pub_selected=pub_selected,
        draft_selected=draft_selected,
        ai_panel=ai_panel,
        max_title_length=cfg.max_title_length,
        max_content_length=cfg.max_content_length,
        content=content_val,
        submit_label=submit_label,
    )


def page_form_view(environ: dict, cfg: Config, csrf_token: str, is_edit: bool = False) -> str:
    """Render new or edit standalone page form HTML body."""
    from ..content import validate_page_filename

    if is_edit:
        qs = parse_qs(environ.get("QUERY_STRING", ""))
        fname = qs.get("file", [""])[0]
        if not validate_page_filename(fname):
            return "<p>Invalid filename</p>"
        path = cfg.standalone_dir / fname
        if not path.is_file():
            return "<p>Page not found</p>"
        pages = list_standalones(cfg.standalone_dir, cfg.max_file_size)
        page = next((p for p in pages if p.file == fname), None)
        if not page:
            return "<p>Parse failed</p>"
        text = get_raw_content(path)
        heading = f"编辑: {escape_html(page.title)}"
        form_action = "/save-page"
        file_input = f'<input type="hidden" name="file" value="{escape_attr(fname)}">'
        title_val = escape_attr(page.title)
        slug_val = escape_attr(page.slug)
        content_val = escape_html(text)
        submit_label = "保存更改"
    else:
        heading = "新建独立页面"
        form_action = "/create-page"
        file_input = ""
        title_val = ""
        slug_val = ""
        content_val = ""
        submit_label = "创建"

    ai_panel = _build_ai_panel(cfg, csrf_token, suggest_tags=False)

    return render_template(
        "page_form.html",
        heading=heading,
        form_action=form_action,
        csrf_token=csrf_token,
        file_input=file_input,
        title=title_val,
        slug=slug_val,
        ai_panel=ai_panel,
        max_title_length=cfg.max_title_length,
        max_content_length=cfg.max_content_length,
        content=content_val,
        submit_label=submit_label,
    )


def pages_dashboard_view(environ: dict, cfg: Config, csrf_token: str) -> str:
    """Render standalone pages dashboard HTML body."""
    pages = list_standalones(cfg.standalone_dir, cfg.max_file_size)
    rows = []
    for page in pages:
        safe_title = escape_html(page.title[:80] or page.file)
        rows.append(f"""<tr>
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

    return render_template(
        "pages_dashboard.html",
        csrf_token=csrf_token,
        rows="".join(rows),
        total=len(pages),
    )


def theme_selector_view(environ: dict, cfg: Config, csrf_token: str) -> str:
    """Render theme selector page HTML body."""
    from pathlib import Path
    from ..core.template import list_themes

    themes_dir = Path("themes")
    themes = list_themes(themes_dir)
    current_theme = cfg.theme_name

    cards = []
    for theme in themes:
        is_active = theme["name"] == current_theme
        active_cls = " active" if is_active else ""
        default_badge = ' <span class="draft-badge">当前</span>' if is_active else ""
        layouts = ", ".join(theme.get("layouts", ["blog"])) if theme.get("layouts") else "blog"
        desc = escape_html(theme.get("description", ""))
        disabled = 'disabled style="opacity:0.5;"' if is_active else ""
        cards.append(f"""<div class="theme-card{active_cls}">
  <h3>{escape_html(theme.get("display_name", theme["name"]))}{default_badge}</h3>
  <p>{desc}</p>
  <p class="theme-meta">布局: {layouts}</p>
  <form method="post" action="/set-theme" style="margin:0;">
    <input type="hidden" name="csrf_token" value="{escape_attr(csrf_token)}">
    <input type="hidden" name="theme" value="{escape_attr(theme['name'])}">
    <button type="submit" class="btn-primary btn-sm" {disabled}>选择</button>
  </form>
</div>""")

    return render_template(
        "theme_selector.html",
        csrf_token=csrf_token,
        current_theme=escape_html(current_theme),
        theme_cards="".join(cards),
    )


def login_view(environ: dict, csrf_token: str) -> str:
    """Render standalone login page full HTML."""
    error_msg = ""
    qs = parse_qs(environ.get("QUERY_STRING", ""))
    if qs.get("error", [""])[0] == "1":
        error_msg = '<div class="login-error">用户名或密码错误</div>'
    if qs.get("locked", [""])[0] == "1":
        error_msg = '<div class="login-error">登录尝试过多，请稍后再试</div>'

    return render_template(
        "login.html",
        csrf_token=csrf_token,
        error_msg=error_msg,
    )


def _build_ai_panel(cfg: Config, csrf_token: str, suggest_tags: bool = True) -> str:
    """Build AI assistant panel HTML if enabled."""
    if not (cfg.ai_enabled and cfg.ai_api_key):
        return ""
    tags_btn = '<button type="button" class="ai-btn" onclick="aiSuggestTags()">推荐标签</button>' if suggest_tags else ""
    return f"""<div id="ai-panel" class="ai-panel">
  <div class="ai-panel-header">
    <span class="ai-label">AI 助手</span>
    <button type="button" class="ai-btn" onclick="aiComplete()">续写</button>
    <button type="button" class="ai-btn" onclick="aiPolish()">润色</button>
    <button type="button" class="ai-btn" onclick="aiTranslate('en')">译英</button>
    <button type="button" class="ai-btn" onclick="aiTranslate('ja')">译日</button>
    {tags_btn}
    <span id="ai-status"></span>
  </div>
</div>"""
