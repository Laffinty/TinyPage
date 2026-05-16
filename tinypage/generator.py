"""Static page generator with cutting-edge CSS/HTML/JS output."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from .config import Config
from .models import ArticleMeta, PageInfo
from .security import escape_html, escape_attr
from .core.template import render_skeleton

# Lazy imports to avoid circular dependency with content module
_render_markdown = None
_extract_body = None


def _get_render_markdown():
    global _render_markdown
    if _render_markdown is None:
        from .parsers import render_markdown as _rm
        _render_markdown = _rm
    return _render_markdown


def _get_extract_body():
    global _extract_body
    if _extract_body is None:
        from .content import _extract_body_from_html as _eb
        _extract_body = _eb
    return _extract_body

logger = logging.getLogger(__name__)


def build_json_ld(
    title: str,
    description: str,
    date: str,
    slug: str,
    tags: list[str],
    site_url: str,
    author: str = "",
) -> str:
    """Build JSON-LD structured data for article pages.

    Args:
        title: Article title
        description: Article summary/description
        date: Publication date (ISO format)
        slug: Article slug
        tags: List of tag names
        site_url: Site base URL
        author: Author name

    Returns:
        JSON-LD script tag HTML
    """
    article_url = f"{site_url.rstrip('/')}/article/{slug}.html"

    schema = {
        "@context": "https://schema.org",
        "@type": "Article",
        "headline": title,
        "description": description,
        "url": article_url,
        "datePublished": date,
        "author": {
            "@type": "Person",
            "name": author or "Anonymous",
        },
        "publisher": {
            "@type": "Organization",
            "name": site_url,
        },
    }

    if tags:
        schema["keywords"] = ", ".join(tags)

    return f'<script type="application/ld+json">{json.dumps(schema, ensure_ascii=False)}</script>'


def _nav_links(cfg: Config, standalones: list[ArticleMeta] | None = None, current_path: str = "") -> str:
    """Generate site navigation links."""
    links = ['<a href="/">首页</a>']
    if standalones:
        for page in standalones:
            active = ' aria-current="page"' if current_path == f"/standalone/{page.file}" else ""
            links.append(f'<a href="/standalone/{page.file}"{active}>{escape_html(page.title[:20] or page.file)}</a>')
    if cfg.enable_search:
        active = ' aria-current="page"' if current_path == "/search.html" else ""
        links.append(f'<a href="/search.html"{active}>搜索</a>')
    return "\n      ".join(links)


def load_theme_css(theme_dir: Path) -> tuple[str, str, bool]:
    """Load base and optional dark theme CSS, appending Pygments syntax highlighting if available."""
    base_file = theme_dir / "theme.css"
    dark_file = theme_dir / "theme.dark.css"
    base_css = base_file.read_text(encoding="utf-8") if base_file.exists() else ""
    dark_css = dark_file.read_text(encoding="utf-8") if dark_file.exists() else ""

    # Inject Pygments CSS for syntax highlighting (Phase 1 task 1.5 enhancement)
    try:
        from .parsers.syntax import get_pygments_css, has_syntax_highlighting
        if has_syntax_highlighting():
            pygments_css = get_pygments_css()
            if pygments_css:
                base_css = base_css + "\n/* Pygments syntax highlighting */\n" + pygments_css
    except Exception:
        pass  # Pygments is optional

    return base_css, dark_css, bool(dark_css)


def generate_article_html(
    title: str,
    date: str,
    slug: str,
    content: str,
    tags: str = "",
    summary: str = "",
    category: str = "",
    status: str = "published",
    config: Optional[Config] = None,
    theme_css: str = "",
    dark_css: str = "",
    has_dark: bool = False,
    standalones: list[ArticleMeta] | None = None,
    toc_html: str = "",
    footnotes_html: str = "",
    backlinks_html: str = "",
    related_articles: list[ArticleMeta] | None = None,
) -> str:
    """Generate a single article page with modern WEB standards.
    
    Phase 3 features:
        toc_html: Table of contents HTML
        footnotes_html: Footnotes section HTML
        backlinks_html: Backlinks section HTML
        related_articles: List of ArticleMeta for related articles section
    """
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

    # Category HTML
    category_html = ""
    if category:
        category_html = f'<span class="post-category"><a href="/category/{escape_attr(category)}.html">{escape_html(category)}</a></span>'

    # Draft badge
    draft_badge = ""
    if status.lower() == "draft":
        draft_badge = '<span class="draft-badge">草稿</span>'

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

    # Open Graph & Twitter Cards
    og_html = ""
    json_ld_html = ""
    if cfg.site_url:
        article_url = f"{cfg.site_url.rstrip('/')}/article/{slug}.html"
        og_html = f"""<meta property="og:title" content="{page_title}">
<meta property="og:description" content="{safe_summary}">
<meta property="og:type" content="article">
<meta property="og:url" content="{escape_attr(article_url)}">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="{page_title}">
<meta name="twitter:description" content="{safe_summary}">"""
        tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
        json_ld_html = build_json_ld(
            title=title,
            description=summary,
            date=date,
            slug=slug,
            tags=tag_list,
            site_url=cfg.site_url,
            author=cfg.site_author,
        )

    # Search script injection
    search_script = '<script src="/search.js" defer></script>' if cfg.enable_search else ""

    # Mermaid script for diagrams
    mermaid_script = '<script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script><script>mermaid.initialize({startOnLoad:true,theme:document.documentElement.classList.contains(\'dark\')?\'dark\':\'default\',securityLevel:\'strict\'});</script>'

    # Share button
    share_html = ""
    if cfg.site_url:
        share_html = f"""<button class="share-btn" onclick="navigator.share?.({{title:'{page_title}',text:'{safe_summary}',url:'{escape_attr(cfg.site_url)}/article/{slug}.html'}}).catch(()=>{{}})" hidden>分享</button>"""

    nav = _nav_links(cfg, standalones, f"/article/{slug}.html")
    theme_toggle = '<button class="theme-toggle" aria-label="切换主题" onclick="document.documentElement.classList.toggle(\'dark\');try{localStorage.setItem(\'theme\',document.documentElement.classList.contains(\'dark\')?\'dark\':\'light\')}catch(e){}">🌓</button>' if has_dark else ''

    # Related articles HTML
    related_html = ""
    if related_articles:
        items = []
        for art in related_articles:
            items.append(f"""
      <div class="related-item">
        <a href="{art.url}">{escape_html(art.title)}</a>
        <span class="related-date">{escape_html(art.date)}</span>
      </div>""")
        related_html = f"""
    <section class="related-articles">
      <h2>相关文章</h2>
      <div class="related-list">
        {"".join(items)}
      </div>
    </section>"""

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
      {toc_html}
      <div class="post-content">
{content}
      </div>
      {tags_html}
      {footnotes_html}
      {backlinks_html}
    </article>
    {related_html}"""

    return render_skeleton(
        "article",
        site_title=site_title,
        page_title=page_title,
        description=safe_summary,
        body_content=body_content,
        theme_css=theme_css,
        dark_css=dark_css,
        has_dark=has_dark,
        nav_links=nav,
        theme_toggle=theme_toggle,
        footer_text=cfg.footer_text or "",
        lang=cfg.lang,
        dark_mode_meta=dark_mode_meta,
        pwa_meta=pwa_meta,
        vt_meta=vt_meta,
        og_html=og_html,
        json_ld_html=json_ld_html,
        pwa_manifest=pwa_manifest,
        dark_mode_script=dark_mode_script,
        search_script=search_script,
        mermaid_script=mermaid_script,
    )


def generate_list_page(
    articles: list[ArticleMeta],
    page_info: PageInfo,
    config: Optional[Config] = None,
    theme_css: str = "",
    dark_css: str = "",
    has_dark: bool = False,
    standalones: list[ArticleMeta] | None = None,
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
        category_badge = ""
        if art.category:
            category_badge = f'<span class="category-badge">{escape_html(art.category)}</span>'
        items_html.append(f"""
<article class="post-preview">
  <header>
    <h2 class="post-title"><a href="{art.url}">{safe_title}</a></h2>
    <time class="post-date" datetime="{escape_attr(art.date)}">{escape_html(art.date)}</time>
    {category_badge}
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

    nav = _nav_links(cfg, standalones, "/")
    theme_toggle = '<button class="theme-toggle" aria-label="切换主题" onclick="document.documentElement.classList.toggle(\'dark\');try{localStorage.setItem(\'theme\',document.documentElement.classList.contains(\'dark\')?\'dark\':\'light\')}catch(e){}">🌓</button>' if has_dark else ''

    body_content = f"""<h1 class="page-title" style="position:absolute;left:-9999px;">文章列表</h1>
    <div class="posts">
      {''.join(items_html)}
    </div>
    {nav_html}"""

    return render_skeleton(
        "list",
        site_title=site_title,
        page_title=page_title,
        description=escape_html(cfg.site_description),
        body_content=body_content,
        theme_css=theme_css,
        dark_css=dark_css,
        has_dark=has_dark,
        nav_links=nav,
        theme_toggle=theme_toggle,
        footer_text=cfg.footer_text or "",
        lang=cfg.lang,
        dark_mode_meta=dark_mode_meta,
        pwa_meta=pwa_meta,
        vt_meta=vt_meta,
        og_html="",
        pwa_manifest=pwa_manifest,
        dark_mode_script=dark_mode_script,
        search_script=search_script,
    )


def generate_search_page(
    config: Optional[Config] = None,
    theme_css: str = "",
    dark_css: str = "",
    has_dark: bool = False,
    standalones: list[ArticleMeta] | None = None,
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

    nav = _nav_links(cfg, standalones, "/search.html")
    theme_toggle = '<button class="theme-toggle" aria-label="切换主题" onclick="document.documentElement.classList.toggle(\'dark\');try{localStorage.setItem(\'theme\',document.documentElement.classList.contains(\'dark\')?\'dark\':\'light\')}catch(e){}">🌓</button>' if has_dark else ''

    body_content = """<h1 class="page-title">搜索文章</h1>
    <div class="search-box">
      <input type="search" id="search-input" placeholder="输入关键词..." autocomplete="off" aria-label="搜索关键词">
      <div id="search-results" class="search-results"></div>
    </div>"""

    return render_skeleton(
        "search",
        site_title=site_title,
        page_title="搜索",
        description="搜索站内文章",
        body_content=body_content,
        theme_css=theme_css,
        dark_css=dark_css,
        has_dark=has_dark,
        nav_links=nav,
        theme_toggle=theme_toggle,
        footer_text=cfg.footer_text or "",
        lang=cfg.lang,
        dark_mode_meta=dark_mode_meta,
        pwa_meta=pwa_meta,
        vt_meta="",
        og_html="",
        pwa_manifest=pwa_manifest,
        dark_mode_script=dark_mode_script,
        search_script='<script src="/search.js" defer></script>',
    )


def generate_standalone_html(
    title: str,
    content: str,
    summary: str = "",
    config: Optional[Config] = None,
    theme_css: str = "",
    dark_css: str = "",
    has_dark: bool = False,
    standalones: list[ArticleMeta] | None = None,
) -> str:
    """Generate a standalone page (e.g. About, Projects)."""
    cfg = config or Config()
    if not theme_css:
        theme_css, dark_css, has_dark = load_theme_css(cfg.theme_dir)
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

    nav = _nav_links(cfg, standalones, "/")
    theme_toggle = '<button class="theme-toggle" aria-label="切换主题" onclick="document.documentElement.classList.toggle(\'dark\');try{localStorage.setItem(\'theme\',document.documentElement.classList.contains(\'dark\')?\'dark\':\'light\')}catch(e){}">🌓</button>' if has_dark else ''

    body_content = f"""<article class="post standalone">
      <header class="post-header">
        <h1 class="post-title">{page_title}</h1>
      </header>
      <div class="post-content">
{content}
      </div>
    </article>"""

    return render_skeleton(
        "standalone",
        site_title=site_title,
        page_title=page_title,
        description=safe_summary,
        body_content=body_content,
        theme_css=theme_css,
        dark_css=dark_css,
        has_dark=has_dark,
        nav_links=nav,
        theme_toggle=theme_toggle,
        footer_text=cfg.footer_text or "",
        lang=cfg.lang,
        dark_mode_meta=dark_mode_meta,
        pwa_meta=pwa_meta,
        vt_meta=vt_meta,
        og_html=og_html,
        pwa_manifest=pwa_manifest,
        dark_mode_script=dark_mode_script,
        search_script=search_script,
    )


def generate_category_page(
    category: str,
    articles: list[ArticleMeta],
    config: Optional[Config] = None,
    theme_css: str = "",
    dark_css: str = "",
    has_dark: bool = False,
    standalones: list[ArticleMeta] | None = None,
) -> str:
    """Generate a category index page."""
    cfg = config or Config()
    if not theme_css:
        theme_css, dark_css, has_dark = load_theme_css(cfg.theme_dir)
    site_title = escape_html(cfg.site_title)
    safe_category = escape_html(category)

    items_html: list[str] = []
    for art in articles:
        safe_title = escape_html(art.title[:80])
        safe_summary = escape_html(art.summary).replace("<p>", "").replace("</p>", "")
        items_html.append(f"""
<article class="post-preview">
  <header>
    <h2 class="post-title"><a href="{art.url}">{safe_title}</a></h2>
    <time class="post-date" datetime="{escape_attr(art.date)}">{escape_html(art.date)}</time>
  </header>
  <p class="post-summary">{safe_summary}</p>
  <a href="{art.url}" class="read-more">阅读全文 →</a>
</article>
""")

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

    nav = _nav_links(cfg, standalones, f"/category/{category}.html")
    theme_toggle = '<button class="theme-toggle" aria-label="切换主题" onclick="document.documentElement.classList.toggle(\'dark\');try{localStorage.setItem(\'theme\',document.documentElement.classList.contains(\'dark\')?\'dark\':\'light\')}catch(e){}">🌓</button>' if has_dark else ''

    body_content = f"""<h1 class="page-title">分类：{safe_category}</h1>
    <p style="color:#666;margin-bottom:1.5rem;">共 {len(articles)} 篇文章</p>
    <div class="posts">
      {''.join(items_html)}
    </div>"""

    return render_skeleton(
        "category",
        site_title=site_title,
        page_title=f"分类：{safe_category}",
        description=f"{safe_category} 分类下的文章 - {site_title}",
        body_content=body_content,
        theme_css=theme_css,
        dark_css=dark_css,
        has_dark=has_dark,
        nav_links=nav,
        theme_toggle=theme_toggle,
        footer_text=cfg.footer_text or "",
        lang=cfg.lang,
        dark_mode_meta=dark_mode_meta,
        pwa_meta=pwa_meta,
        vt_meta=vt_meta,
        og_html="",
        pwa_manifest=pwa_manifest,
        dark_mode_script=dark_mode_script,
        search_script=search_script,
    )


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


def generate_sitemap(
    articles: list[ArticleMeta],
    config: Config,
    standalones: list[ArticleMeta] | None = None,
    categories: list[str] | None = None,
) -> str:
    """Generate XML sitemap."""
    cfg = config
    site_url = cfg.site_url or "http://localhost:8080"
    urls = [f"{site_url.rstrip('/')}/"]
    for art in articles:
        urls.append(f"{site_url.rstrip('/')}/article/{art.file}")
    if standalones:
        for page in standalones:
            urls.append(f"{site_url.rstrip('/')}/standalone/{page.file}")
    if categories:
        for cat in categories:
            urls.append(f"{site_url.rstrip('/')}/category/{cat}.html")

    url_entries = "\n".join(
        f"  <url>\n    <loc>{u}</loc>\n  </url>" for u in urls
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
{url_entries}
</urlset>"""


def generate_search_index(
    articles: list[ArticleMeta],
    standalones: list[ArticleMeta] | None = None,
) -> str:
    """Generate JSON search index."""
    data = [
        {
            "title": art.title,
            "summary": art.summary,
            "url": f"/article/{art.file}",
            "date": art.date,
            "tags": art.tag_list,
            "category": art.category,
        }
        for art in articles
    ]
    if standalones:
        for page in standalones:
            data.append({
                "title": page.title,
                "summary": page.summary,
                "url": f"/standalone/{page.file}",
                "date": "",
                "tags": [],
                "category": "",
            })
    return json.dumps(data, ensure_ascii=False)


def generate_static_pages(
    articles: list[ArticleMeta],
    config: Config,
    standalones: list[ArticleMeta] | None = None,
) -> None:
    """Regenerate all static pages."""
    cfg = config
    total = len(articles)
    pages = max(1, (total + cfg.page_size - 1) // cfg.page_size)

    theme_css, dark_css, has_dark = load_theme_css(cfg.theme_dir)

    logger.info(f"[GENERATE] {total} articles, {pages} pages")

    # Phase 3: Regenerate articles with digital garden features
    from .content import regenerate_all_articles
    regenerate_all_articles(
        articles,
        cfg.article_dir,
        cfg,
        theme_css,
        dark_css,
        has_dark,
        standalones,
    )

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
        html = generate_list_page(items, page_info, cfg, theme_css, dark_css, has_dark, standalones)
        if p == 1:
            (cfg.root_dir / "index.html").write_text(html, encoding="utf-8")
        else:
            (cfg.list_dir / f"{p}.html").write_text(html, encoding="utf-8")

    # Category pages
    categories: list[str] = []
    category_articles: dict[str, list[ArticleMeta]] = {}
    for art in articles:
        if art.category:
            cat = art.category.strip()
            if cat:
                categories.append(cat)
                category_articles.setdefault(cat, []).append(art)
    categories = sorted(set(categories))
    if categories:
        cat_dir = cfg.root_dir / "category"
        cat_dir.mkdir(parents=True, exist_ok=True)
        for cat in categories:
            html = generate_category_page(
                cat, category_articles[cat], cfg, theme_css, dark_css, has_dark, standalones
            )
            (cat_dir / f"{cat}.html").write_text(html, encoding="utf-8")

    # Standalone pages
    if standalones:
        st_dir = cfg.root_dir / "standalone"
        st_dir.mkdir(parents=True, exist_ok=True)
        for page in standalones:
            path = cfg.standalone_dir / page.file
            if path.is_file():
                content = path.read_text(encoding="utf-8")
                body = _get_extract_body()(content)
                html = generate_standalone_html(
                    title=page.title or page.file,
                    content=_get_render_markdown()(body) if body else "",
                    summary=page.summary,
                    config=cfg,
                    theme_css=theme_css,
                    dark_css=dark_css,
                    has_dark=has_dark,
                    standalones=standalones,
                )
                (st_dir / page.file).write_text(html, encoding="utf-8")

    # Search page
    if cfg.enable_search:
        (cfg.root_dir / "search.html").write_text(
            generate_search_page(cfg, theme_css, dark_css, has_dark, standalones), encoding="utf-8"
        )
        # Search index JSON
        (cfg.root_dir / "search-index.json").write_text(
            generate_search_index(articles, standalones), encoding="utf-8"
        )

    # RSS (exclude standalones and drafts)
    if cfg.enable_rss:
        published = [a for a in articles if a.is_published]
        (cfg.root_dir / "rss.xml").write_text(generate_rss(published, cfg), encoding="utf-8")

    # Sitemap
    if cfg.enable_sitemap:
        (cfg.root_dir / "sitemap.xml").write_text(
            generate_sitemap(articles, cfg, standalones, categories), encoding="utf-8"
        )

    # robots.txt
    robots = f"""User-agent: *
Allow: /
Sitemap: {cfg.site_url or ''}/sitemap.xml
"""
    (cfg.root_dir / "robots.txt").write_text(robots, encoding="utf-8")

    logger.info("[GENERATE-COMPLETE] All static pages generated")
