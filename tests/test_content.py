"""Regression tests for P0-2: article content storage must be lossless.

The original format stored the body as ``<!-- markdown: {escape_html(x)} -->``.
That corrupted data twice over:

* every rebuild re-escaped already-escaped text, so ``&`` grew a new
  ``&amp;`` layer each pass and the rendered page visibly degraded;
* the reader's non-greedy regex stopped at the first ``-->``, so any article
  containing one lost everything after it.

The body now lives in a sibling ``.md`` file. Legacy files still parse and are
migrated on first read.
"""

from __future__ import annotations

from tinypage import content as C
from tinypage.core.article_store import (
    decode_content,
    decode_legacy_body,
    meta_value,
    source_path,
)
from tinypage.security import escape_html


def test_round_trip_is_identity(site, article_body):
    C.write_article(
        site.article_dir, "2026-01-01-x.html", "T", "2026-01-01 00:00", "x",
        article_body, skip_html_generation=True,
    )
    path = site.article_dir / "2026-01-01-x.html"
    assert C.get_raw_content(path) == article_body


def test_repeated_rebuilds_do_not_escape(site, article_body):
    """The core regression: N rebuilds must still yield the original body."""
    C.write_article(
        site.article_dir, "2026-01-01-x.html", "T", "2026-01-01 00:00", "x",
        article_body, skip_html_generation=True,
    )
    path = site.article_dir / "2026-01-01-x.html"
    for _ in range(5):
        C.regenerate_all_articles(
            C.list_articles(site.article_dir), site.article_dir, site
        )
        assert C.get_raw_content(path) == article_body


def test_content_with_terminator_survives(site):
    body = "before\n\n```\na --> b\n```\n\nafter\n"
    C.write_article(
        site.article_dir, "2026-01-02-y.html", "T", "2026-01-02 00:00", "y",
        body, skip_html_generation=True,
    )
    assert C.get_raw_content(site.article_dir / "2026-01-02-y.html") == body


def test_content_containing_the_marker_is_safe(site):
    body = "<!-- tinypage:markdown 5 -->\nliteral marker in body"
    C.write_article(
        site.article_dir, "2026-01-03-z.html", "T", "2026-01-03 00:00", "z",
        body, skip_html_generation=True,
    )
    assert C.get_raw_content(site.article_dir / "2026-01-03-z.html") == body


def test_body_lives_in_sibling_md_file(site, article_body):
    C.write_article(
        site.article_dir, "2026-01-06-md.html", "T", "2026-01-06 00:00", "md",
        article_body, skip_html_generation=True,
    )
    src = source_path(site.article_dir / "2026-01-06-md.html")
    assert src.is_file()
    assert src.suffix == ".md"
    assert src.read_text(encoding="utf-8") == article_body


def test_generated_html_has_no_visible_body(site, article_body):
    """The body must not appear as page text ahead of the document.

    An intermediate fix embedded the raw body in the HTML outside any comment,
    which made the browser render the markdown as visible content.
    """
    C.write_article(
        site.article_dir, "2026-01-07-vis.html", "T", "2026-01-07 00:00", "vis",
        article_body, skip_html_generation=True,
    )
    C.regenerate_all_articles(
        C.list_articles(site.article_dir), site.article_dir, site
    )
    html = (site.article_dir / "2026-01-07-vis.html").read_text(encoding="utf-8")
    head = html.split("<!DOCTYPE", 1)[0]
    # Nothing from the body may leak into the pre-document region.
    assert "Cost is $5" not in head
    assert "中文标题" not in head
    assert "tinypage:markdown" not in html


def test_standalone_body_is_preserved(site, article_body):
    """write_standalone used to store no body at all, so editing a page loaded
    only the summary and saved it over the real content."""
    C.write_standalone(site.standalone_dir, "about.html", "About", article_body)
    assert C.get_raw_content(site.standalone_dir / "about.html") == article_body


def test_legacy_file_decodes_to_original(article_body):
    legacy = (
        "<!-- title: T -->\n<!-- date: 2026-01-01 00:00 -->\n"
        f"<!-- markdown: {escape_html(escape_html(article_body))} -->\n"
        "<html><body>old</body></html>"
    )
    assert decode_content(legacy) == article_body


def test_legacy_file_auto_migrates_on_next_build(site, article_body):
    path = site.article_dir / "2026-01-04-legacy.html"
    path.write_text(
        "<!-- title: L -->\n<!-- date: 2026-01-04 00:00 -->\n"
        f"<!-- markdown: {escape_html(escape_html(article_body))} -->\n"
        "<html><body>old</body></html>",
        encoding="utf-8",
    )
    C.regenerate_all_articles(
        C.list_articles(site.article_dir), site.article_dir, site
    )
    assert "tinypage:markdown" not in path.read_text(encoding="utf-8")
    assert source_path(path).is_file()
    assert C.get_raw_content(path) == article_body


def test_delete_article_removes_markdown_source(site, article_body):
    C.write_article(
        site.article_dir, "2026-01-08-del.html", "T", "2026-01-08 00:00", "del",
        article_body, skip_html_generation=True,
    )
    path = site.article_dir / "2026-01-08-del.html"
    src = source_path(path)
    assert src.is_file()
    C.delete_article(path)
    assert not path.exists()
    assert not src.exists()
    assert not list(site.article_dir.glob("*.backup"))


def test_hand_written_article_is_not_truncated(site):
    """A hand-written article keeps its text in the rendered page.

    parse_meta() derives a ~200-character summary from that text. Falling back
    to the summary discarded the rest of the article on the first build, and
    once bodies live in .md files that truncation would have become the
    permanent source of truth.
    """
    body = " ".join(f"sentence{i}" for i in range(120))
    path = site.article_dir / "2026-01-09-hand.html"
    path.write_text(
        "<!-- title: Hand -->\n<!-- date: 2026-01-09 00:00 -->\n"
        "<!-- slug: hand -->\n<!-- tags:  -->\n<!-- summary:  -->\n"
        "<!-- category:  -->\n<!-- status: published -->\n"
        f'<div class="post-content"><p>{body}</p></div>\n',
        encoding="utf-8",
    )

    assert len(C.parse_meta(path).summary) < len(body)  # summary is a truncation
    assert C.get_raw_content(path) == body

    C.regenerate_all_articles(
        C.list_articles(site.article_dir), site.article_dir, site
    )
    assert C.get_raw_content(path) == body
    assert len(source_path(path).read_text(encoding="utf-8")) == len(body)


def test_migrated_file_has_no_embedded_body(article_body):
    """A migrated file carries metadata only; the body lives in the .md."""
    migrated = "<!-- title: T -->\n<!-- status: published -->\n<!DOCTYPE html><html></html>"
    assert decode_legacy_body(migrated) is None
    assert decode_content(migrated) is None


def test_meta_value_is_single_line():
    """A newline in a title used to break the line-based metadata reader."""
    assert "\n" not in meta_value("line1\nline2")
    assert "\r" not in meta_value("line1\r\nline2")
    assert "&" not in meta_value("a & b").replace("&amp;", "")


def test_parse_meta_survives_newline_in_title(site):
    C.write_article(
        site.article_dir, "2026-01-05-nl.html", "line1\nline2",
        "2026-01-05 00:00", "nl", "body", skip_html_generation=True,
    )
    meta = C.parse_meta(site.article_dir / "2026-01-05-nl.html")
    assert meta is not None
    assert "\n" not in meta.title
