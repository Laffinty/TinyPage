"""Tests for the HTML generators."""

from __future__ import annotations

import re

import pytest

from tinypage.config import Config
from tinypage.generator import generate_list_page
from tinypage.models import ArticleMeta, PageInfo


def _render(**cfg_kwargs):
    art = ArticleMeta(
        title=cfg_kwargs.pop("title", "A & B <x>"),
        date="2026-01-01 00:00",
        file="2026-01-01-a.html",
        summary=cfg_kwargs.pop("summary", "R&D"),
    )
    return generate_list_page([art], PageInfo(), Config(**cfg_kwargs))


class TestEscapingIsAppliedExactlyOnce:
    """render_skeleton escapes its arguments, but _build_common_context already
    escaped site_title before handing it over, so the brand name is escaped
    twice and renders as a literal "&amp;" on the page."""

    def test_article_title_not_double_escaped(self):
        html = _render()
        h2 = re.search(r'<h2 class="post-title"><a[^>]*>(.*?)</a>', html, re.S).group(1)
        assert "&amp;amp;" not in h2
        assert "A &amp; B" in h2

    def test_summary_not_double_escaped(self):
        html = _render()
        summary = re.search(r'<p class="post-summary">(.*?)</p>', html, re.S).group(1)
        assert "&amp;amp;" not in summary
        assert "R&amp;D" in summary

    @pytest.mark.xfail(
        reason="P1-1: _build_common_context pre-escapes site_title and "
               "render_skeleton escapes it again; flip to passing when fixed",
        strict=False,
    )
    def test_site_title_not_double_escaped(self):
        html = _render(site_title="Tom & Jerry")
        title = re.search(r"<title>(.*?)</title>", html, re.S).group(1)
        assert "&amp;amp;" not in title
        assert "Tom &amp; Jerry" in title


class TestGeneratedPageStructure:
    def test_doctype_and_lang(self):
        html = _render(lang="zh-CN")
        assert html.lstrip().startswith("<!DOCTYPE html>")
        assert '<html lang="zh-CN">' in html

    def test_article_link_present(self):
        assert 'href="/article/2026-01-01-a.html"' in _render()
