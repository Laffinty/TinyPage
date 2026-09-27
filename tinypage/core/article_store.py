"""Article file storage: metadata header in HTML, body in a sibling .md file.

Why this module exists
----------------------
The original format stored the article body as::

    <!-- markdown: {escape_html(content)} -->

That is lossy in two ways, and both were live data-corruption bugs:

1. **Non-idempotent escaping.** ``write_article`` escaped the content on the
   way in, and ``regenerate_all_articles`` read the already-escaped text back
   and escaped it *again* on the way out. Every rebuild added a layer, so
   ``&`` became ``&amp;`` then ``&amp;amp;`` then ``&amp;amp;amp;`` -- and the
   rendered page visibly degraded each time.

2. **``-->`` truncated the body.** The reader used a non-greedy regex that
   stopped at the first ``-->``, so any article containing an HTML comment or
   a ``-->`` inside a fenced code block silently lost everything after it.

Neither is fixable while the body lives *inside* the HTML file: an HTML comment
cannot losslessly contain arbitrary text, and anything outside a comment is
rendered by the browser as visible page content ahead of the real document.

So the body moves to a sibling ``.md`` file next to the generated HTML::

    pages/article/2026-01-01-x.md    <- source of truth, byte-exact
    pages/article/2026-01-01-x.html  <- metadata comments + generated page

That also makes content genuinely Git-friendly, which the README promises and
.gitignore previously defeated by ignoring ``pages/article/``.

Legacy and intermediate files stay readable: bodies are still recovered from
either comment form (see ``decode_content``) and migrated into the ``.md`` on
first read, so no manual migration step is required.
"""

from __future__ import annotations

import html
import os
import re
from pathlib import Path

CONTENT_MARKER = "tinypage:markdown"

# Matches the opening line of an intermediate-format content block and
# captures its length. Read-only: new files no longer embed the body.
_V2_HEADER = re.compile(
    rf"<!--\s*{re.escape(CONTENT_MARKER)}\s+(\d+)\s*-->\r?\n?"
)

# Legacy single-line form, kept for reading old files only.
#
# The writer emitted exactly "<payload> -->\n", so the first pattern -- which
# pins the separating space -- preserves a trailing newline in the payload. A
# trailing "\s*" would instead swallow it, silently trimming every legacy body
# by one character. The second pattern is a tolerant fallback for files that
# were hand-written without the separating space.
_LEGACY_MARKER_EXACT = re.compile(r"<!--\s*markdown:\s*(.*?) -->", re.DOTALL)
_LEGACY_MARKER_LOOSE = re.compile(r"<!--\s*markdown:\s*(.*?)\s*-->", re.DOTALL)

# A meta value must stay on one line or parse_meta() cannot read it.
_UNSAFE_META = re.compile(r"[\r\n]+")


def source_path(html_path: Path) -> Path:
    """Return the markdown source path that belongs to a generated HTML file."""
    return html_path.with_suffix(".md")


def write_source(html_path: Path, content: str) -> Path:
    """Write the article body to its .md sibling, atomically.

    Returns the path written.
    """
    target = source_path(html_path)
    temp = target.with_suffix(".md.tmp")
    try:
        with open(temp, "w", encoding="utf-8", newline="") as f:
            f.write(content)
        os.replace(temp, target)
    except Exception:
        if temp.exists():
            temp.unlink()
        raise
    return target


def meta_value(value: object) -> str:
    """Render a metadata value safe to embed on a single comment line."""
    return html.escape(_UNSAFE_META.sub(" ", str(value)), quote=True).strip()


def _decode_legacy(text: str) -> str | None:
    """Pull the body out of a legacy comment, undoing accumulated escaping."""
    for pattern in (_LEGACY_MARKER_EXACT, _LEGACY_MARKER_LOOSE):
        match = pattern.search(text)
        if match:
            return _unescape_to_fixpoint(match.group(1))
    return None


def decode_content(text: str) -> str | None:
    """Recover an embedded article body from HTML, or None if there is none.

    Understands both the intermediate length-delimited format and the original
    escaped comment format. New files do not embed a body at all.
    """
    header = _V2_HEADER.search(text)
    if header:
        length = int(header.group(1))
        body = text[header.end():]
        # A hand-edited file can leave the declared length stale. Truncate
        # rather than fail, and let the next write normalise it.
        return body[:length] if length <= len(body) else body.rstrip("\n")

    return _decode_legacy(text)


def decode_legacy_body(text: str) -> str | None:
    """Extract an embedded body, or None if the file has no embedded body.

    Used by the migration path to tell "already migrated" from "needs
    extracting" without rewriting every file on every build.
    """
    if _V2_HEADER.search(text):
        return None
    return _decode_legacy(text)


def _unescape_to_fixpoint(text: str, max_passes: int = 32) -> str:
    """Peel accumulated HTML-escaping until the text stops changing.

    Legacy files were escaped once per rebuild, so the layer count varies per
    article. Peeling to a fixed point recovers the original in one pass
    regardless of depth, with a cap so pathological input cannot loop.

    Note: a body that genuinely contained the text ``&amp;`` decodes to ``&``.
    The *rendered* page is unaffected -- both display as ``&`` -- so this is
    lossy only at the raw-markdown level, and only for legacy files.
    """
    current = text
    for _ in range(max_passes):
        decoded = html.unescape(current)
        if decoded == current:
            break
        current = decoded
    return current


def _unescape_to_fixpoint(text: str, max_passes: int = 32) -> str:
    """Peel accumulated HTML-escaping until the text stops changing.

    Legacy files were escaped once per rebuild, so the layer count varies per
    article. Peeling to a fixed point recovers the original in one pass
    regardless of depth, with a cap so pathological input cannot loop.

    Note: a body that genuinely contained the text ``&amp;`` decodes to ``&``.
    The *rendered* page is unaffected -- both display as ``&`` -- so this is
    lossy only at the raw-markdown level, and only for legacy files.
    """
    current = text
    for _ in range(max_passes):
        decoded = html.unescape(current)
        if decoded == current:
            break
        current = decoded
    return current
