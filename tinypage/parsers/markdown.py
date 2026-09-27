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

# Built once: create_markdown() constructs a parser, and render_markdown() is
# called for every article on every build.
#
# escape=True is required, not optional. mistune passes raw HTML in the source
# through by default, and article content reaches this function straight from
# the admin editor and from AI/translation responses. The rendered result is
# additionally injected into the admin origin by the live-preview endpoint, so
# unescaped output was a stored-XSS path.
#
# Plugins are deliberately left off: mistune's own `footnotes` plugin would
# collide with this project's custom implementation in parsers/footnotes.py.
_markdown: object | None = None


def _get_markdown():
    """Return the cached mistune Markdown instance, or None if unavailable."""
    global _markdown
    if _markdown is None:
        try:
            _markdown = mistune.create_markdown(escape=True)
        except Exception as e:  # pragma: no cover - depends on mistune version
            logger.warning(f"[MARKDOWN] cannot build mistune parser: {e}")
            _markdown = False
    return _markdown or None


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

    Raw HTML in the source is always escaped -- see ``_get_markdown``. Code
    blocks are unaffected: they are escaped either way, and
    ``highlight_code_blocks`` unescapes them before lexing.
    """
    if _HAS_MISTUNE:
        md = _get_markdown()
        if md is not None:
            try:
                return md(text)
            except Exception as e:
                logger.warning(f"[MARKDOWN] mistune render failed, falling back: {e}")
    return _fallback_text_to_html(text)


def has_markdown_support() -> bool:
    """Return True if full Markdown support is available."""
    return _HAS_MISTUNE
