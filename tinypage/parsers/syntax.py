"""Syntax highlighting with optional Pygments dependency."""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

try:
    from pygments import highlight as _pygments_highlight
    from pygments.lexers import get_lexer_by_name, guess_lexer
    from pygments.formatters import HtmlFormatter
    from pygments.util import ClassNotFound

    _HAS_PYGMENTS = True
except ImportError:
    _HAS_PYGMENTS = False
    _pygments_highlight = None
    get_lexer_by_name = None
    guess_lexer = None
    HtmlFormatter = None
    ClassNotFound = Exception


def highlight_code_blocks(html: str) -> str:
    """Find <pre><code class="language-xxx"> blocks and apply Pygments highlighting.
    
    If Pygments is not installed, returns HTML unchanged.
    """
    if not _HAS_PYGMENTS or _pygments_highlight is None:
        return html

    def _replace_code_block(m: re.Match) -> str:
        lang = m.group(1).strip() if m.group(1) else ""
        code = _unescape_html_entities(m.group(2))
        # Remove leading newline commonly added by markdown parsers
        code = code.lstrip("\n")
        try:
            if lang:
                lexer = get_lexer_by_name(lang)
            else:
                lexer = guess_lexer(code)
        except ClassNotFound:
            lexer = get_lexer_by_name("text")
        except Exception as e:
            logger.debug(f"[SYNTAX] Lexer error: {e}")
            return m.group(0)

        formatter = HtmlFormatter(nowrap=True)
        highlighted = _pygments_highlight(code, lexer, formatter)
        return f'<pre><code class="language-{lang or "text"}">{highlighted}</code></pre>'

    # Match <pre><code class="language-xxx">...</code></pre>
    pattern = re.compile(
        r'<pre><code(?:\s+class="language-([^"]*)")?>(.*?)</code></pre>',
        re.DOTALL,
    )
    return pattern.sub(_replace_code_block, html)


def get_pygments_css(style: str = "default") -> str:
    """Return Pygments CSS for the given style. Empty string if Pygments unavailable."""
    if not _HAS_PYGMENTS or HtmlFormatter is None:
        return ""
    try:
        return HtmlFormatter(style=style).get_style_defs(".highlight")
    except Exception as e:
        logger.warning(f"[SYNTAX] Failed to generate Pygments CSS: {e}")
        return ""


def has_syntax_highlighting() -> bool:
    """Return True if syntax highlighting is available."""
    return _HAS_PYGMENTS


def _unescape_html_entities(text: str) -> str:
    """Minimal unescape for code blocks that may have been HTML-escaped."""
    return (
        text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
        .replace("&quot;", '"')
    )
