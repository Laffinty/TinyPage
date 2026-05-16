"""Markdown parser with optional mistune dependency."""

from __future__ import annotations

import logging
import re

from ..security import escape_html, escape_attr, validate_url_protocol

logger = logging.getLogger(__name__)

try:
    import mistune
    _HAS_MISTUNE = True
except ImportError:
    mistune = None  # type: ignore
    _HAS_MISTUNE = False


def _fallback_text_to_html(content: str) -> str:
    """Original lightweight markup converter (fallback when mistune unavailable)."""
    content = escape_html(content)
    paragraphs = re.split(r"\n\s*\n", content.strip())
    html_paragraphs: list[str] = []

    for para in paragraphs:
        if not para.strip():
            continue
        # Inline formatting
        para = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", para)
        para = re.sub(r"\*(.+?)\*", r"<em>\1</em>", para)
        para = re.sub(r"`(.+?)`", r"<code>\1</code>", para)

        # Links with protocol validation
        def replace_link(m: re.Match) -> str:
            text = m.group(1)
            url = m.group(2)
            if validate_url_protocol(url):
                return f'<a href="{escape_attr(url)}" rel="noopener noreferrer">{text}</a>'
            return f"[{text}]({url})"

        para = re.sub(r"\[([^\]]+)\]\(([^\)]+)\)", replace_link, para)

        lines = para.strip().split("\n")
        html_lines = "<br>\n".join(lines)
        html_paragraphs.append(f"<p>{html_lines}</p>")

    return "\n".join(html_paragraphs)


def render_markdown(text: str) -> str:
    """Render Markdown text to HTML.
    
    Uses mistune if available (install with ``pip install tinypage[markdown]``),
    otherwise falls back to the original lightweight markup converter.
    """
    if _HAS_MISTUNE and mistune is not None:
        try:
            return mistune.html(text)
        except Exception as e:
            logger.warning(f"[MARKDOWN] mistune render failed, falling back: {e}")
            return _fallback_text_to_html(text)
    return _fallback_text_to_html(text)


def has_markdown_support() -> bool:
    """Return True if full Markdown support is available."""
    return _HAS_MISTUNE
