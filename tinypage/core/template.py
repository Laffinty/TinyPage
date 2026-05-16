"""Page skeleton template using Python standard library string.Template."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from ..security import escape_html, escape_attr

# Page skeleton template - one template for all page types
_PAGE_SKELETON = """<!DOCTYPE html>
<html lang="$lang">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
$dark_mode_meta
$pwa_meta
$vt_meta
<meta name="description" content="$description">
$og_html
$json_ld_html
$pwa_manifest
<title>$page_title - $site_title</title>
<style>
$theme_css
</style>
$dark_css_block
$dark_mode_script
</head>
<body>
<div class="container">
  <header class="site-header">
    <a href="/" class="site-title">$site_title</a>
    <nav class="site-nav" aria-label="站点导航">
      $nav_links
      $theme_toggle
    </nav>
  </header>
  <main>
$body_content
  </main>
  <footer class="site-footer">
    <p>$footer_text</p>
  </footer>
</div>
$search_script
$mermaid_script
</body>
</html>"""


def render_skeleton(
    page_type: str,
    *,
    site_title: str,
    page_title: str,
    description: str,
    body_content: str,
    theme_css: str,
    dark_css: str = "",
    has_dark: bool = False,
    nav_links: str = "",
    footer_text: str = "",
    lang: str = "zh-CN",
    dark_mode_meta: str = "",
    pwa_meta: str = "",
    vt_meta: str = "",
    og_html: str = "",
    pwa_manifest: str = "",
    dark_mode_script: str = "",
    search_script: str = "",
    mermaid_script: str = "",
    json_ld_html: str = "",
    theme_toggle: str = "",
) -> str:
    """Render a complete page HTML from the skeleton template.

    Args:
        page_type: Page type identifier (article/list/search/standalone/category)
        site_title: Site name
        page_title: Page title
        description: Meta description
        body_content: Main content HTML
        theme_css: Base theme CSS
        dark_css: Dark mode CSS (empty if no dark mode)
        has_dark: Whether dark mode is available
        nav_links: Navigation links HTML
        footer_text: Footer text
        lang: HTML lang attribute
        dark_mode_meta: Dark mode meta tag
        pwa_meta: PWA theme-color meta tags
        vt_meta: View transition meta tag
        og_html: Open Graph meta tags
        pwa_manifest: PWA manifest link tag
        dark_mode_script: Inline dark mode JS
        search_script: Search JS script tag
        mermaid_script: Mermaid initialization script tag
        json_ld_html: JSON-LD structured data script tag
        theme_toggle: Theme toggle button HTML
    """
    from string import Template
    t = Template(_PAGE_SKELETON)

    dark_css_block = (
        f"<style media=\"(prefers-color-scheme: dark)\">{dark_css}</style>"
        if dark_css else ""
    )

    return t.substitute(
        page_type=page_type,
        lang=escape_html(lang),
        site_title=escape_html(site_title),
        page_title=escape_html(page_title),
        description=escape_html(description),
        dark_mode_meta=dark_mode_meta,
        pwa_meta=pwa_meta,
        vt_meta=vt_meta,
        og_html=og_html,
        json_ld_html=json_ld_html,
        pwa_manifest=pwa_manifest,
        theme_css=theme_css,
        dark_css_block=dark_css_block,
        dark_mode_script=dark_mode_script,
        nav_links=nav_links,
        theme_toggle=theme_toggle,
        footer_text=escape_html(footer_text) if footer_text else "",
        body_content=body_content,
        search_script=search_script,
        mermaid_script=mermaid_script,
    )


def load_theme_manifest(theme_name: str, themes_dir: Path) -> Optional[dict]:
    """Load theme manifest.json if it exists."""
    manifest_path = themes_dir / theme_name / "manifest.json"
    if not manifest_path.is_file():
        return None
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def list_themes(themes_dir: Path) -> list[dict]:
    """List all themes with their manifests."""
    themes = []
    if not themes_dir.is_dir():
        return themes
    for entry in themes_dir.iterdir():
        if entry.is_dir():
            manifest = load_theme_manifest(entry.name, themes_dir)
            themes.append({
                "name": entry.name,
                "display_name": (manifest.get("name", entry.name) if manifest else entry.name),
                "description": (manifest.get("description", "") if manifest else ""),
                "layouts": (manifest.get("layouts", ["blog"]) if manifest else ["blog"]),
                "default_layout": (manifest.get("default_layout", "blog") if manifest else "blog"),
            })
    return themes


def build_article_context(
    title: str,
    date: str,
    slug: str,
    content: str,
    tags: str = "",
    summary: str = "",
    category: str = "",
    status: str = "published",
    config=None,
    theme_css: str = "",
    dark_css: str = "",
    has_dark: bool = False,
    standalones: Optional[list] = None,
) -> dict:
    """Build template context for an article page."""
    from ..config import Config
    from ..models import ArticleMeta

    cfg = config or Config()
    site_title = escape_html(cfg.site_title)
    page_title = escape_html(title)
    safe_date = escape_html(date)
    safe_summary = escape_html(summary)

    # Tags HTML
    tags_html = ""
    if tags:
        tag_items = [f'<span class="tag">{escape_html(t.strip())}</span>' for t in tags.split(",") if t.strip()]
        if tag_items:
            tags_html = f'<div class="post-tags">{" ".join(tag_items)}</div>'

    # Category HTML
    category_html = ""
    if category:
        category_html = f'<span class="post-category"><a href="/category/{escape_attr(category)}.html">{escape_html(category)}</a></span>'

    # Draft badge
    draft_badge = ""
    if status.lower() == "draft":
        draft_badge = '<span class="draft-badge">草稿</span>'

    # Dark mode
    dark_mode_meta = '<meta name="color-scheme" content="light dark">' if has_dark else ""
    dark_mode_script = (
        """<script>(function(){try{var m=localStorage.getItem('theme');if(m==='dark'||(!m&&window.matchMedia('(prefers-color-scheme: dark)').matches)){document.documentElement.classList.add('dark')}}catch(e){}})();</script>"""
        if has_dark else ""
    )

    # PWA
    pwa_meta = ""
    pwa_manifest = ""
    if cfg.enable_pwa:
        pwa_meta = f"""<meta name="theme-color" content="{cfg.pwa_theme_color}" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="{cfg.pwa_bg_color}" media="(prefers-color-scheme: dark)">"""
        pwa_manifest = '<link rel="manifest" href="/manifest.json">'

    # View transitions
    vt_meta = '<meta name="view-transition" content="same-origin">' if cfg.enable_view_transitions else ""

    # Open Graph
    og_html = ""
    if cfg.site_url:
        og_html = f"""<meta property="og:title" content="{page_title}">
<meta property="og:description" content="{safe_summary}">
<meta property="og:type" content="article">
<meta property="og:url" content="{escape_attr(cfg.site_url)}/article/{slug}.html">
<meta name="twitter:card" content="summary">"""

    # Navigation
    from ..generator import _nav_links
    nav = _nav_links(cfg, standalones, f"/article/{slug}.html")
    theme_toggle = '<button class="theme-toggle" aria-label="切换主题" onclick="document.documentElement.classList.toggle(\'dark\');try{localStorage.setItem(\'theme\',document.documentElement.classList.contains(\'dark\')?\'dark\':\'light\')}catch(e){}">🌓</button>' if has_dark else ''

    # Share button
    share_html = ""
    if cfg.site_url:
        share_html = f"""<button class="share-btn" onclick="navigator.share?.({{title:'{page_title}',text:'{safe_summary}',url:'{escape_attr(cfg.site_url)}/article/{slug}.html'}}).catch(()=>{{}})" hidden>分享</button>"""

    # Body content for article
    body_content = f"""<article class="post">
      <header class="post-header">
        <h1 class="post-title">{page_title}</h1>
        <div class="post-meta">
          {category_html}
          <time datetime="{safe_date}">{safe_date}</time>
          {draft_badge}
          {share_html}
        </div>
      </header>
      <div class="post-content">
{content}
      </div>
      {tags_html}
    </article>"""

    search_script = '<script src="/search.js" defer></script>' if cfg.enable_search else ""
    mermaid_script = '<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script><script>mermaid.initialize({startOnLoad:true,theme:document.documentElement.classList.contains(\'dark\')?\'dark\':\'default\',securityLevel:\'strict\'});</script>'

    return {
        "page_type": "article",
        "site_title": site_title,
        "page_title": page_title,
        "description": safe_summary,
        "body_content": body_content,
        "theme_css": theme_css,
        "dark_css": dark_css,
        "has_dark": has_dark,
        "nav_links": nav,
        "theme_toggle": theme_toggle,
        "footer_text": cfg.footer_text or "",
        "lang": cfg.lang,
        "dark_mode_meta": dark_mode_meta,
        "pwa_meta": pwa_meta,
        "vt_meta": vt_meta,
        "og_html": og_html,
        "pwa_manifest": pwa_manifest,
        "dark_mode_script": dark_mode_script,
        "search_script": search_script,
        "mermaid_script": mermaid_script,
    }


def build_list_context(
    items_html: str,
    page_info,
    config=None,
    theme_css: str = "",
    dark_css: str = "",
    has_dark: bool = False,
    standalones: Optional[list] = None,
    page_title: str = "首页",
) -> dict:
    """Build template context for list/index page."""
    from ..config import Config

    cfg = config or Config()
    site_title = escape_html(cfg.site_title)

    # Pagination
    nav_links_list = []
    if page_info.has_prev:
        nav_links_list.append(f'<a href="{page_info.prev_url}" class="prev">← 上一页</a>')
    if page_info.has_next:
        nav_links_list.append(f'<a href="{page_info.next_url}" class="next">下一页 →</a>')
    page_numbers = []
    for p in range(1, page_info.total + 1):
        if p == page_info.current:
            page_numbers.append(f'<span class="current" aria-current="page">{p}</span>')
        elif p == 1:
            page_numbers.append('<a href="/">1</a>')
        else:
            page_numbers.append(f'<a href="/list/{p}.html">{p}</a>')

    nav_html = ""
    if page_info.total > 1:
        nav_html = f"""
<nav class="pagination" aria-label="分页导航">
  <div class="nav-links">{''.join(nav_links_list)}</div>
  <div class="page-numbers">{''.join(page_numbers)}</div>
</nav>"""

    dark_mode_meta = '<meta name="color-scheme" content="light dark">' if has_dark else ""
    dark_mode_script = (
        """<script>(function(){try{var m=localStorage.getItem('theme');if(m==='dark'||(!m&&window.matchMedia('(prefers-color-scheme: dark)').matches)){document.documentElement.classList.add('dark')}}catch(e){}})();</script>"""
        if has_dark else ""
    )

    pwa_meta = ""
    pwa_manifest = ""
    if cfg.enable_pwa:
        pwa_meta = f"""<meta name="theme-color" content="{cfg.pwa_theme_color}" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="{cfg.pwa_bg_color}" media="(prefers-color-scheme: dark)">"""
        pwa_manifest = '<link rel="manifest" href="/manifest.json">'

    vt_meta = '<meta name="view-transition" content="same-origin">' if cfg.enable_view_transitions else ""
    search_script = '<script src="/search.js" defer></script>' if cfg.enable_search else ""

    from ..generator import _nav_links
    nav = _nav_links(cfg, standalones, "/" if page_info.current == 1 else f"/list/{page_info.current}.html")
    theme_toggle = '<button class="theme-toggle" aria-label="切换主题" onclick="document.documentElement.classList.toggle(\'dark\');try{localStorage.setItem(\'theme\',document.documentElement.classList.contains(\'dark\')?\'dark\':\'light\')}catch(e){}">🌓</button>' if has_dark else ''

    body_content = f"""<h1 class="page-title" style="position:absolute;left:-9999px;">{page_title}</h1>
    <div class="posts">
      {items_html}
    </div>
    {nav_html}"""

    return {
        "page_type": "list",
        "site_title": site_title,
        "page_title": f"第{page_info.current}页" if page_info.current > 1 else page_title,
        "description": escape_html(cfg.site_description),
        "body_content": body_content,
        "theme_css": theme_css,
        "dark_css": dark_css,
        "has_dark": has_dark,
        "nav_links": nav,
        "theme_toggle": theme_toggle,
        "footer_text": cfg.footer_text or "",
        "lang": cfg.lang,
        "dark_mode_meta": dark_mode_meta,
        "pwa_meta": pwa_meta,
        "vt_meta": vt_meta,
        "og_html": "",
        "pwa_manifest": pwa_manifest,
        "dark_mode_script": dark_mode_script,
        "search_script": search_script,
        "mermaid_script": "",
    }


def build_search_context(
    config=None,
    theme_css: str = "",
    dark_css: str = "",
    has_dark: bool = False,
    standalones: Optional[list] = None,
) -> dict:
    """Build template context for search page."""
    from ..config import Config

    cfg = config or Config()
    site_title = escape_html(cfg.site_title)

    dark_mode_meta = '<meta name="color-scheme" content="light dark">' if has_dark else ""
    dark_mode_script = (
        """<script>(function(){try{var m=localStorage.getItem('theme');if(m==='dark'||(!m&&window.matchMedia('(prefers-color-scheme: dark)').matches)){document.documentElement.classList.add('dark')}}catch(e){}})();</script>"""
        if has_dark else ""
    )

    pwa_meta = ""
    pwa_manifest = ""
    if cfg.enable_pwa:
        pwa_meta = f"""<meta name="theme-color" content="{cfg.pwa_theme_color}">"""
        pwa_manifest = '<link rel="manifest" href="/manifest.json">'

    from ..generator import _nav_links
    nav = _nav_links(cfg, standalones, "/search.html")
    theme_toggle = '<button class="theme-toggle" aria-label="切换主题" onclick="document.documentElement.classList.toggle(\'dark\');try{localStorage.setItem(\'theme\',document.documentElement.classList.contains(\'dark\')?\'dark\':\'light\')}catch(e){}">🌓</button>' if has_dark else ''

    body_content = """<h1 class="page-title">搜索文章</h1>
    <div class="search-box">
      <input type="search" id="search-input" placeholder="输入关键词..." autocomplete="off" aria-label="搜索关键词">
      <div id="search-results" class="search-results"></div>
    </div>"""

    return {
        "page_type": "search",
        "site_title": site_title,
        "page_title": "搜索",
        "description": "搜索站内文章",
        "body_content": body_content,
        "theme_css": theme_css,
        "dark_css": dark_css,
        "has_dark": has_dark,
        "nav_links": nav,
        "theme_toggle": theme_toggle,
        "footer_text": cfg.footer_text or "",
        "lang": cfg.lang,
        "dark_mode_meta": dark_mode_meta,
        "pwa_meta": pwa_meta,
        "vt_meta": "",
        "og_html": "",
        "pwa_manifest": pwa_manifest,
        "dark_mode_script": dark_mode_script,
        "search_script": '<script src="/search.js" defer></script>',
        "mermaid_script": "",
    }


def build_standalone_context(
    title: str,
    content: str,
    summary: str = "",
    config=None,
    theme_css: str = "",
    dark_css: str = "",
    has_dark: bool = False,
    standalones: Optional[list] = None,
    current_path: str = "/",
) -> dict:
    """Build template context for a standalone page."""
    from ..config import Config

    cfg = config or Config()
    site_title = escape_html(cfg.site_title)
    page_title = escape_html(title)
    safe_summary = escape_html(summary)

    dark_mode_meta = '<meta name="color-scheme" content="light dark">' if has_dark else ""
    dark_mode_script = (
        """<script>(function(){try{var m=localStorage.getItem('theme');if(m==='dark'||(!m&&window.matchMedia('(prefers-color-scheme: dark)').matches)){document.documentElement.classList.add('dark')}}catch(e){}})();</script>"""
        if has_dark else ""
    )

    pwa_meta = ""
    pwa_manifest = ""
    if cfg.enable_pwa:
        pwa_meta = f"""<meta name="theme-color" content="{cfg.pwa_theme_color}" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="{cfg.pwa_bg_color}" media="(prefers-color-scheme: dark)">"""
        pwa_manifest = '<link rel="manifest" href="/manifest.json">'

    vt_meta = '<meta name="view-transition" content="same-origin">' if cfg.enable_view_transitions else ""
    search_script = '<script src="/search.js" defer></script>' if cfg.enable_search else ""

    og_html = ""
    if cfg.site_url:
        og_html = f"""<meta property="og:title" content="{page_title}">
<meta property="og:description" content="{safe_summary}">
<meta property="og:type" content="website">
<meta name="twitter:card" content="summary">"""

    from ..generator import _nav_links
    nav = _nav_links(cfg, standalones, current_path)
    theme_toggle = '<button class="theme-toggle" aria-label="切换主题" onclick="document.documentElement.classList.toggle(\'dark\');try{localStorage.setItem(\'theme\',document.documentElement.classList.contains(\'dark\')?\'dark\':\'light\')}catch(e){}">🌓</button>' if has_dark else ''

    body_content = f"""<article class="post standalone">
      <header class="post-header">
        <h1 class="post-title">{page_title}</h1>
      </header>
      <div class="post-content">
{content}
      </div>
    </article>"""

    return {
        "page_type": "standalone",
        "site_title": site_title,
        "page_title": page_title,
        "description": safe_summary,
        "body_content": body_content,
        "theme_css": theme_css,
        "dark_css": dark_css,
        "has_dark": has_dark,
        "nav_links": nav,
        "theme_toggle": theme_toggle,
        "footer_text": cfg.footer_text or "",
        "lang": cfg.lang,
        "dark_mode_meta": dark_mode_meta,
        "pwa_meta": pwa_meta,
        "vt_meta": vt_meta,
        "og_html": og_html,
        "pwa_manifest": pwa_manifest,
        "dark_mode_script": dark_mode_script,
        "search_script": search_script,
        "mermaid_script": "",
    }


def build_category_context(
    category: str,
    items_html: str,
    article_count: int,
    config=None,
    theme_css: str = "",
    dark_css: str = "",
    has_dark: bool = False,
    standalones: Optional[list] = None,
) -> dict:
    """Build template context for category index page."""
    from ..config import Config

    cfg = config or Config()
    site_title = escape_html(cfg.site_title)
    safe_category = escape_html(category)

    dark_mode_meta = '<meta name="color-scheme" content="light dark">' if has_dark else ""
    dark_mode_script = (
        """<script>(function(){try{var m=localStorage.getItem('theme');if(m==='dark'||(!m&&window.matchMedia('(prefers-color-scheme: dark)').matches)){document.documentElement.classList.add('dark')}}catch(e){}})();</script>"""
        if has_dark else ""
    )

    pwa_meta = ""
    pwa_manifest = ""
    if cfg.enable_pwa:
        pwa_meta = f"""<meta name="theme-color" content="{cfg.pwa_theme_color}" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="{cfg.pwa_bg_color}" media="(prefers-color-scheme: dark)">"""
        pwa_manifest = '<link rel="manifest" href="/manifest.json">'

    vt_meta = '<meta name="view-transition" content="same-origin">' if cfg.enable_view_transitions else ""
    search_script = '<script src="/search.js" defer></script>' if cfg.enable_search else ""

    from ..generator import _nav_links
    nav = _nav_links(cfg, standalones, f"/category/{category}.html")
    theme_toggle = '<button class="theme-toggle" aria-label="切换主题" onclick="document.documentElement.classList.toggle(\'dark\');try{localStorage.setItem(\'theme\',document.documentElement.classList.contains(\'dark\')?\'dark\':\'light\')}catch(e){}">🌓</button>' if has_dark else ''

    body_content = f"""<h1 class="page-title">分类：{safe_category}</h1>
    <p style="color:#666;margin-bottom:1.5rem;">共 {article_count} 篇文章</p>
    <div class="posts">
      {items_html}
    </div>"""

    return {
        "page_type": "category",
        "site_title": site_title,
        "page_title": safe_category,
        "description": f"{safe_category} 分类下的文章",
        "body_content": body_content,
        "theme_css": theme_css,
        "dark_css": dark_css,
        "has_dark": has_dark,
        "nav_links": nav,
        "theme_toggle": theme_toggle,
        "footer_text": cfg.footer_text or "",
        "lang": cfg.lang,
        "dark_mode_meta": dark_mode_meta,
        "pwa_meta": pwa_meta,
        "vt_meta": vt_meta,
        "og_html": "",
        "pwa_manifest": pwa_manifest,
        "dark_mode_script": dark_mode_script,
        "search_script": search_script,
        "mermaid_script": "",
    }