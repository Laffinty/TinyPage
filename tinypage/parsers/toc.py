"""Table of Contents (ToC) generator from Markdown headings."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from ..security import escape_html


HEADING_PATTERN = re.compile(r"^(#{1,6})\s+(.+)$", re.MULTILINE)


@dataclass
class Heading:
    """Represents a heading extracted from Markdown."""
    level: int
    text: str
    id: str


def slugify_heading(text: str) -> str:
    """Convert heading text to URL-safe anchor id."""
    s = re.sub(r"[^a-zA-Z0-9\u4e00-\u9fa5\s]", "", text)
    s = re.sub(r"\s+", "-", s.lower())
    s = re.sub(r"-+", "-", s).strip("-")
    return s or "heading"


def extract_headings(markdown_text: str) -> list[Heading]:
    """Extract all headings from Markdown text.

    Args:
        markdown_text: Raw Markdown content

    Returns:
        List of Heading objects with level, text, and generated id
    """
    headings: list[Heading] = []
    slug_counts: dict[str, int] = {}

    for line in markdown_text.split("\n"):
        match = HEADING_PATTERN.match(line.strip())
        if match:
            hashes = match.group(1)
            text = match.group(2).strip()
            level = len(hashes)
            base_slug = slugify_heading(text)
            slug_counts[base_slug] = slug_counts.get(base_slug, 0) + 1
            if slug_counts[base_slug] > 1:
                heading_id = f"{base_slug}-{slug_counts[base_slug]}"
            else:
                heading_id = base_slug
            headings.append(Heading(level=level, text=text, id=heading_id))

    return headings


def build_toc_html(
    headings: list[Heading],
    min_level: int = 2,
    max_level: int = 3,
) -> str:
    """Build HTML for Table of Contents.

    Args:
        headings: List of Heading objects
        min_level: Minimum heading level to include (default 2 = h2)
        max_level: Maximum heading level to include (default 3 = h3)

    Returns:
        HTML string for ToC, empty string if no valid headings
    """
    filtered = [h for h in headings if min_level <= h.level <= max_level]

    if not filtered:
        return ""

    items: list[str] = []
    current_level = min_level

    for heading in filtered:
        indent = "  " * (heading.level - min_level)
        item = f'{indent}<li><a href="#{heading.id}">{escape_html(heading.text)}</a></li>'
        items.append(item)

    return f"""
<nav class="toc" aria-label="文章目录">
  <details open>
    <summary>目录</summary>
    <ul>
      {"".join(items)}
    </ul>
  </details>
</nav>"""


def add_heading_ids(html_content: str, headings: list[Heading]) -> str:
    """Add id attributes to headings in rendered HTML.

    Args:
        html_content: Rendered HTML content
        headings: List of Heading objects with text and ids

    Returns:
        HTML content with heading ids added
    """
    heading_map = {h.text: h.id for h in headings}

    def replace_heading(m: re.Match) -> str:
        tag = m.group(1)
        content = m.group(2)
        for text, heading_id in heading_map.items():
            if text in content:
                return f"<{tag} id=\"{heading_id}\">{content}</{tag}>"
        return m.group(0)

    html_content = re.sub(
        r"<(h[1-6])([^>]*)>(.+?)</\1>",
        lambda m: _add_id_to_heading(m, heading_map),
        html_content,
        flags=re.DOTALL,
    )

    return html_content


def _add_id_to_heading(match: re.Match, heading_map: dict[str, str]) -> str:
    """Helper to add id attribute to a heading match."""
    tag = match.group(1)
    attrs = match.group(2)
    content = match.group(3)

    if "id=" in attrs:
        return match.group(0)

    for text, heading_id in heading_map.items():
        if text in content:
            return f"<{tag} id=\"{heading_id}\"{attrs}>{content}</{tag}>"

    return match.group(0)
