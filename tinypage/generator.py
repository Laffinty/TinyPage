"""Static page generator with cutting-edge CSS/HTML/JS output."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from .config import Config
from .models import ArticleMeta, PageInfo
from .security import escape_html, escape_attr

logger = logging.getLogger(__name__)


def load_theme_css(theme_dir: Path) -> tuple[str, str, bool]:
    """Load base and optional dark theme CSS."""
    base_file = theme_dir / "theme.css"
    dark_file = theme_dir / "theme.dark.css"
    base_css = base_file.read_text(encoding="utf-8") if base_file.exists() else ""
    dark_css = dark_file.read_text(encoding="utf-8") if dark_file.exists() else ""
    return base_css, dark_css, bool(dark_css)


def generate_article_html(
    title: str,
    date: str,
    slug: str,
    content: str,
    tags: str = "",
    summary: str = "",
    config: Optional[Config] = None,
    theme_css: str = "",
    dark_css: str = "",
    has_dark: bool = False,
) -> str:
    """Generate a single article page with modern WEB standards."""
    cfg = config or Config()
    if not theme_css:
        theme_css, dark_css, has_dark = load_theme_css(cfg.theme_dir)
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

    # Dark mode support
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

    # Search script injection
    search_script = '<script src="/search.js" defer></script>' if cfg.enable_search else ""

    # Share button
    share_html = ""
    if cfg.site_url:
        share_html = f"""<button class="share-btn" onclick="navigator.share?.({{title:'{page_title}',text:'{safe_summary}',url:'{escape_attr(cfg.site_url)}/article/{slug}.html'}}).catch(()=>{{}})" hidden>分享</button>"""

    return f"""<!DOCTYPE html>
<html lang="{cfg.lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
{dark_mode_meta}
{pwa_meta}
{vt_meta}
<meta name="description" content="{safe_summary}">
{og_html}
{pwa_manifest}
<title>{page_title} - {site_title}</title>
<style>
{theme_css}
</style>
{('<style media="(prefers-color-scheme: dark)">' + dark_css + '</style>') if dark_css else ''}
{dark_mode_script}
</head>
<body>
<div class="container">
  <header class="site-header">
    <a href="/" class="site-title">{site_title}</a>
    <nav class="site-nav" aria-label="站点导航">
      <a href="/">首页</a>
      {'<a href="/search.html">搜索</a>' if cfg.enable_search else ''}
      {'<button class="theme-toggle" aria-label="切换主题" onclick="document.documentElement.classList.toggle(\'dark\');try{{localStorage.setItem(\'theme\',document.documentElement.classList.contains(\'dark\')?\'dark\':\'light\')}}catch(e){{}}">🌓</button>' if has_dark else ''}
    </nav>
  </header>
  <main>
    <article class="post">
      <header class="post-header">
        <h1 class="post-title">{page_title}</h1>
        <div class="post-meta">
          <time datetime="{safe_date}">{safe_date}</time>
          {share_html}
        </div>
      </header>
      <div class="post-content">
{content}
      </div>
      {tags_html}
    </article>
  </main>
  <footer class="site-footer">
    <p>{escape_html(cfg.footer_text) if cfg.footer_text else ''}</p>
  </footer>
</div>
{search_script}
</body>
</html>"""


def generate_list_page(
    articles: list[ArticleMeta],
    page_info: PageInfo,
    config: Optional[Config] = None,
    theme_css: str = "",
    dark_css: str = "",
    has_dark: bool = False,
) -> str:
    """Generate list/index page with article previews."""
    cfg = config or Config()
    if not theme_css:
        theme_css, dark_css, has_dark = load_theme_css(cfg.theme_dir)
    site_title = escape_html(cfg.site_title)
    page_title = f"第{page_info.current}页" if page_info.current > 1 else "首页"

    items_html: list[str] = []
    for art in articles:
        safe_title = escape_html(art.title[:80])
        safe_summary = escape_html(art.summary).replace("<p>", "").replace("</p>", "")
        tag_html = ""
        if art.tags:
            tags = [f'<span class="tag">{escape_html(t)}</span>' for t in art.tag_list]
            tag_html = f'<div class="post-tags">{" ".join(tags)}</div>'
        items_html.append(f"""
<article class="post-preview">
  <header>
    <h2 class="post-title"><a href="{art.url}">{safe_title}</a></h2>
    <time class="post-date" datetime="{escape_attr(art.date)}">{escape_html(art.date)}</time>
  </header>
  <p class="post-summary">{safe_summary}</p>
  {tag_html}
  <a href="{art.url}" class="read-more">阅读全文 →</a>
</article>
""")

    # Pagination
    nav_links: list[str] = []
    if page_info.has_prev:
        nav_links.append(f'<a href="{page_info.prev_url}" class="prev">← 上一页</a>')
    if page_info.has_next:
        nav_links.append(f'<a href="{page_info.next_url}" class="next">下一页 →</a>')

    page_numbers: list[str] = []
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
  <div class="nav-links">{''.join(nav_links)}</div>
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

    return f"""<!DOCTYPE html>
<html lang="{cfg.lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
{dark_mode_meta}
{pwa_meta}
{vt_meta}
<meta name="description" content="{escape_html(cfg.site_description)}">
{pwa_manifest}
<title>{page_title} - {site_title}</title>
<style>
{theme_css}
</style>
{('<style media="(prefers-color-scheme: dark)">' + dark_css + '</style>') if dark_css else ''}
{dark_mode_script}
</head>
<body>
<div class="container">
  <header class="site-header">
    <a href="/" class="site-title">{site_title}</a>
    <nav class="site-nav" aria-label="站点导航">
      <a href="/">首页</a>
      {'<a href="/search.html">搜索</a>' if cfg.enable_search else ''}
      {'<button class="theme-toggle" aria-label="切换主题" onclick="document.documentElement.classList.toggle(\'dark\');try{{localStorage.setItem(\'theme\',document.documentElement.classList.contains(\'dark\')?\'dark\':\'light\')}}catch(e){{}}">🌓</button>' if has_dark else ''}
    </nav>
  </header>
  <main>
    <h1 class="page-title" style="position:absolute;left:-9999px;">文章列表</h1>
    <div class="posts">
      {''.join(items_html)}
    </div>
    {nav_html}
  </main>
  <footer class="site-footer">
    <p>{escape_html(cfg.footer_text) if cfg.footer_text else ''}</p>
  </footer>
</div>
{search_script}
</body>
</html>"""


def generate_search_page(
    config: Optional[Config] = None,
    theme_css: str = "",
    dark_css: str = "",
    has_dark: bool = False,
) -> str:
    """Generate search page."""
    cfg = config or Config()
    if not theme_css:
        theme_css, dark_css, has_dark = load_theme_css(cfg.theme_dir)
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

    return f"""<!DOCTYPE html>
<html lang="{cfg.lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
{dark_mode_meta}
{pwa_meta}
{pwa_manifest}
<title>搜索 - {site_title}</title>
<style>
{theme_css}
</style>
{('<style media="(prefers-color-scheme: dark)">' + dark_css + '</style>') if dark_css else ''}
{dark_mode_script}
</head>
<body>
<div class="container">
  <header class="site-header">
    <a href="/" class="site-title">{site_title}</a>
    <nav class="site-nav" aria-label="站点导航">
      <a href="/">首页</a>
      <a href="/search.html" aria-current="page">搜索</a>
      {'<button class="theme-toggle" aria-label="切换主题" onclick="document.documentElement.classList.toggle(\'dark\');try{{localStorage.setItem(\'theme\',document.documentElement.classList.contains(\'dark\')?\'dark\':\'light\')}}catch(e){{}}">🌓</button>' if has_dark else ''}
    </nav>
  </header>
  <main>
    <h1 class="page-title">搜索文章</h1>
    <div class="search-box">
      <input type="search" id="search-input" placeholder="输入关键词..." autocomplete="off" aria-label="搜索关键词">
      <div id="search-results" class="search-results"></div>
    </div>
  </main>
  <footer class="site-footer">
    <p>{escape_html(cfg.footer_text) if cfg.footer_text else ''}</p>
  </footer>
</div>
<script src="/search.js" defer></script>
</body>
</html>"""


def generate_rss(articles: list[ArticleMeta], config: Config) -> str:
    """Generate RSS 2.0 feed."""
    cfg = config
    site_url = cfg.site_url or "http://localhost:8080"
    items = ""
    for art in articles[:20]:
        link = f"{site_url.rstrip('/')}/article/{art.file}"
        desc = escape_html(art.summary)
        items += f"""
    <item>
      <title>{escape_html(art.title)}</title>
      <link>{link}</link>
      <guid>{link}</guid>
      <pubDate>{art.iso_date}</pubDate>
      <description>{desc}</description>
    </item>"""

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>{escape_html(cfg.site_title)}</title>
    <link>{site_url}</link>
    <description>{escape_html(cfg.site_description)}</description>
    <language>{cfg.lang}</language>
    {items}
  </channel>
</rss>"""


def generate_sitemap(articles: list[ArticleMeta], config: Config) -> str:
    """Generate XML sitemap."""
    cfg = config
    site_url = cfg.site_url or "http://localhost:8080"
    urls = [f"{site_url.rstrip('/')}/"]
    for art in articles:
        urls.append(f"{site_url.rstrip('/')}/article/{art.file}")

    url_entries = "\n".join(
        f"  <url>\n    <loc>{u}</loc>\n  </url>" for u in urls
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
{url_entries}
</urlset>"""


def generate_search_index(articles: list[ArticleMeta]) -> str:
    """Generate JSON search index."""
    data = [
        {
            "title": art.title,
            "summary": art.summary,
            "url": f"/article/{art.file}",
            "date": art.date,
            "tags": art.tag_list,
        }
        for art in articles
    ]
    return json.dumps(data, ensure_ascii=False)


def generate_static_pages(articles: list[ArticleMeta], config: Config) -> None:
    """Regenerate all static pages."""
    cfg = config
    total = len(articles)
    pages = max(1, (total + cfg.page_size - 1) // cfg.page_size)

    theme_css, dark_css, has_dark = load_theme_css(cfg.theme_dir)

    logger.info(f"[GENERATE] {total} articles, {pages} pages")

    # Generate index + list pages
    cfg.root_dir.mkdir(parents=True, exist_ok=True)
    cfg.list_dir.mkdir(parents=True, exist_ok=True)

    for p in range(1, pages + 1):
        start = (p - 1) * cfg.page_size
        items = articles[start:start + cfg.page_size]
        page_info = PageInfo(
            current=p,
            total=pages,
            has_prev=p > 1,
            has_next=p < pages,
            prev_url="/" if p == 2 else f"/list/{p - 1}.html",
            next_url=f"/list/{p + 1}.html" if p < pages else "",
        )
        html = generate_list_page(items, page_info, cfg, theme_css, dark_css, has_dark)
        if p == 1:
            (cfg.root_dir / "index.html").write_text(html, encoding="utf-8")
        else:
            (cfg.list_dir / f"{p}.html").write_text(html, encoding="utf-8")

    # Search page
    if cfg.enable_search:
        (cfg.root_dir / "search.html").write_text(
            generate_search_page(cfg, theme_css, dark_css, has_dark), encoding="utf-8"
        )
        # Search index JSON
        (cfg.root_dir / "search-index.json").write_text(
            generate_search_index(articles), encoding="utf-8"
        )

    # RSS
    if cfg.enable_rss:
        (cfg.root_dir / "rss.xml").write_text(generate_rss(articles, cfg), encoding="utf-8")

    # Sitemap
    if cfg.enable_sitemap:
        (cfg.root_dir / "sitemap.xml").write_text(generate_sitemap(articles, cfg), encoding="utf-8")

    # robots.txt
    robots = f"""User-agent: *
Allow: /
Sitemap: {cfg.site_url or ''}/sitemap.xml
"""
    (cfg.root_dir / "robots.txt").write_text(robots, encoding="utf-8")

    logger.info("[GENERATE-COMPLETE] All static pages generated")
