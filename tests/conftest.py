"""Shared pytest fixtures."""

import pytest
from pathlib import Path


@pytest.fixture
def tmp_articles_dir(tmp_path):
    """Create a temporary articles directory."""
    articles = tmp_path / "article"
    articles.mkdir()
    return articles


@pytest.fixture
def sample_article_content():
    return """<!-- title: Test Article -->
<!-- date: 2026-05-16 12:00 -->
<!-- tags: test, demo -->
<!-- category: testing -->
<!-- status: published -->
<!-- markdown: Hello **world** this is a test. -->
<html><body><p>Hello <strong>world</strong> this is a test.</p></body></html>"""
