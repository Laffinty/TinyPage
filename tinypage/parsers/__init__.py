"""Content parsers for TinyPage."""

from .markdown import render_markdown, has_markdown_support
from .syntax import highlight_code_blocks, has_syntax_highlighting
from .bidirectional_links import parse_bidirectional_links, build_backlinks_html, build_article_title_map
from .toc import extract_headings, build_toc_html, add_heading_ids
from .footnotes import process_footnotes
from .tag_graph import get_tag_graph_html

__all__ = [
    "render_markdown",
    "highlight_code_blocks",
    "has_markdown_support",
    "has_syntax_highlighting",
    "parse_bidirectional_links",
    "build_backlinks_html",
    "build_article_title_map",
    "extract_headings",
    "build_toc_html",
    "add_heading_ids",
    "process_footnotes",
    "get_tag_graph_html",
]
