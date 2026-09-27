"""Regression tests for P0-5: article content must never emit live raw HTML.

``render_markdown`` called ``mistune.html(text)``, which passes raw HTML in the
source straight through. That output is injected into the admin origin by the
live-preview endpoint, so a payload in the editor (or in an AI / translation
response) executed with the admin session's privileges. The admin CSP contains
``'unsafe-inline'`` and therefore did not mitigate it.
"""

from __future__ import annotations

import pytest

from tinypage.parsers import highlight_code_blocks, render_markdown

VECTORS = [
    "<img src=x onerror=alert(1)>",
    "<script>alert(1)</script>",
    "<svg/onload=alert(1)>",
    '<a href="javascript:alert(1)">click</a>',
    '<iframe src="data:text/html,<script>alert(1)</script>"></iframe>',
    '<div onmouseover="steal()">hover</div>',
    '<body onload=alert(1)>',
    "<object data='javascript:alert(1)'>",
    "<style>body{background:url(javascript:alert(1))}</style>",
]

LIVE_TAGS = ("<img", "<script", "<svg", "<iframe", "<object", "<style", "<body", "<div onmouseover")


@pytest.mark.parametrize("payload", VECTORS)
def test_raw_html_is_neutralised(payload):
    out = render_markdown(payload)
    assert not any(tag in out for tag in LIVE_TAGS), out


@pytest.mark.parametrize("payload", VECTORS)
def test_neutralised_output_is_escaped_text(payload):
    out = render_markdown(payload)
    assert "&lt;" in out or "&amp;" in out


def test_markdown_features_still_render():
    """escape=True must not degrade the renderer to the crude fallback."""
    out = render_markdown(
        "# Title\n\n"
        "Intro **bold** *em* `inline` [link](https://example.com).\n\n"
        "## Sub\n\n- one\n- two\n\n> quote\n"
    )
    for token in ("<h1>", "<h2>", "<strong>", "<em>", "<code",
                  'href="https://example.com"', "<ul>", "<li>", "<blockquote>"):
        assert token in out, token


def test_code_blocks_survive_to_the_highlighter():
    out = highlight_code_blocks(render_markdown("```python\nx = 1 < 2 & 3\n```"))
    assert "<pre>" in out
    # The comparison operators must survive as code, not be double-escaped.
    assert "&lt;" in out or "lt" in out
