"""Bidirectional links parser for wiki-style [[Page Title]] syntax."""

from __future__ import annotations

import re
from typing import Optional

from ..security import escape_html, slugify


BIDIRECTIONAL_LINK_PATTERN = re.compile(r"\[\[([^\]|]+)(?:\|([^\]]+))?\]\]")
BACKLINKS_HTML_TEMPLATE = """
<section class="backlinks">
  <h2>反向链接</h2>
  <ul>
    {links}
  </ul>
</section>
"""
BACKLINK_ITEM_TEMPLATE = '<li><a href="{url}">{title}</a></li>'


def slugify_for_link(title: str) -> str:
    """Convert a title to a URL-safe slug for linking."""
    return slugify(title, max_length=0, fallback="untitled")


def parse_bidirectional_links(
    text: str,
    article_map: dict[str, tuple[str, str]] | None = None,
) -> tuple[str, list[tuple[str, str, str]]]:
    """Parse bidirectional links in text and resolve to URLs.

    Args:
        text: Markdown text with [[Page Title]] or [[Page Title|Display Text]] links
        article_map: Dict mapping lowercase title -> (slug, url) tuples

    Returns:
        Tuple of (processed_text with links replaced, list of found links as (title, display, url))
    """
    if article_map is None:
        article_map = {}

    found_links: list[tuple[str, str, str]] = []

    def replace_link(m: re.Match) -> str:
        title = m.group(1).strip()
        display = m.group(2).strip() if m.group(2) else title
        slug = slugify_for_link(title)

        title_lower = title.lower()
        url = None

        if title_lower in article_map:
            _, resolved_url = article_map[title_lower]
            url = resolved_url
        else:
            url = f"/article/{slug}.html"

        found_links.append((title, display, url))
        return f"[{display}]({url})"

    processed_text = BIDIRECTIONAL_LINK_PATTERN.sub(replace_link, text)
    return processed_text, found_links


def build_backlinks_html(backlinks: list[tuple[str, str]]) -> str:
    """Build HTML for backlinks section.

    Args:
        backlinks: List of (title, display, url) tuples from other articles

    Returns:
        HTML string for backlinks section, empty string if no backlinks
    """
    if not backlinks:
        return ""

    links_html = "\n    ".join(
        BACKLINK_ITEM_TEMPLATE.format(url=url, title=escape_html(display))
        for _, display, url in backlinks
    )

    return BACKLINKS_HTML_TEMPLATE.format(links=links_html)


def extract_bidirectional_links(text: str) -> list[str]:
    """Extract all bidirectional link titles from text without replacement.

    Args:
        text: Markdown text with [[Page Title]] links

    Returns:
        List of page titles found in bidirectional links
    """
    titles: list[str] = []
    for match in BIDIRECTIONAL_LINK_PATTERN.finditer(text):
        title = match.group(1).strip()
        if title:
            titles.append(title)
    return titles


def build_article_title_map(
    articles: list,
    article_dir_name: str = "article",
) -> dict[str, tuple[str, str]]:
    """Build a map from article titles to their slugs/URLs.

    Args:
        articles: List of ArticleMeta objects
        article_dir_name: Directory name for article URLs

    Returns:
        Dict mapping lowercase title -> (slug, url) tuples
    """
    title_map: dict[str, tuple[str, str]] = {}
    for article in articles:
        if article.title:
            slug = article.slug or slugify_for_link(article.title)
            url = f"/{article_dir_name}/{article.file}"
            title_map[article.title.lower()] = (slug, url)
    return title_map
