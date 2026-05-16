"""Footnotes parser for Markdown [^n] or [^note] syntax."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from ..security import escape_html


FOOTNOTE_DEF_PATTERN = re.compile(r"\[\^([^\]]+)\]:\s*(.+)$", re.MULTILINE)
FOOTNOTE_REF_PATTERN = re.compile(r"\[\^([^\]]+)\](?![:])")
SUPERSCRIPT_PATTERN = re.compile(r"<sup>\[\^([^\]]+)\]</sup>")


@dataclass
class Footnote:
    """Represents a footnote definition."""
    key: str
    text: str


def parse_footnotes(markdown_text: str) -> tuple[str, list[Footnote]]:
    """Extract footnote definitions from Markdown.

    Args:
        markdown_text: Raw Markdown content with footnote definitions

    Returns:
        Tuple of (text with definitions removed, list of Footnote objects)
    """
    footnotes: list[Footnote] = []
    footnote_keys: set[str] = set()

    definitions: dict[str, str] = {}
    for match in FOOTNOTE_DEF_PATTERN.finditer(markdown_text):
        key = match.group(1)
        text = match.group(2).strip()
        if key not in definitions:
            definitions[key] = text
            footnote_keys.add(key)

    cleaned_text = FOOTNOTE_DEF_PATTERN.sub("", markdown_text)

    for key in footnote_keys:
        footnotes.append(Footnote(key=key, text=definitions[key]))

    return cleaned_text, footnotes


def render_footnote_refs(text: str) -> str:
    """Convert footnote references [^n] to superscript links.

    Args:
        text: Text with [^n] footnote references

    Returns:
        Text with footnote refs converted to <sup> tags
    """
    def replace_ref(m: re.Match) -> str:
        key = m.group(1)
        return f'<sup><a href="#fn-{key}" id="fnref-{key}">[{key}]</a></sup>'

    return FOOTNOTE_REF_PATTERN.sub(replace_ref, text)


def build_footnotes_html(footnotes: list[Footnote]) -> str:
    """Build HTML for footnotes section.

    Args:
        footnotes: List of Footnote objects

    Returns:
        HTML string for footnotes section, empty string if no footnotes
    """
    if not footnotes:
        return ""

    items: list[str] = []
    for fn in footnotes:
        items.append(
            f'<li id="fn-{fn.key}">{escape_html(fn.text)} '
            f'<a href="#fnref-{fn.key}">↩</a></li>'
        )

    return f"""
<section class="footnotes">
  <hr>
  <ol>
    {"".join(items)}
  </ol>
</section>"""


def process_footnotes(markdown_text: str) -> tuple[str, str]:
    """Process footnotes in Markdown text.

    Args:
        markdown_text: Raw Markdown content

    Returns:
        Tuple of (processed_text with refs rendered, footnotes_html)
    """
    cleaned, footnotes = parse_footnotes(markdown_text)
    rendered = render_footnote_refs(cleaned)
    footnotes_html = build_footnotes_html(footnotes)
    return rendered, footnotes_html
