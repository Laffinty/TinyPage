"""Page skeleton template using Python standard library string.Template."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from ..security import escape_html, escape_attr

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
