"""Content processing - text transformation, metadata parsing, article I/O."""

from __future__ import annotations

import logging
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import ArticleMeta
from .security import escape_html, escape_attr, validate_url_protocol, validate_filename

logger = logging.getLogger(__name__)


def slugify_title(title: str) -> str:
    # Keep CJK characters and alphanumeric
    s = re.sub(r"[^a-zA-Z0-9\u4e00-\u9fa5]", "-", title.lower())
    s = re.sub(r"-+", "-", s).strip("-")
    if not s:
        return str(int(time.time()))
    return s[:80]


def text_to_html(content: str) -> str:
    """Convert plain text with lightweight markup to safe HTML."""
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


def parse_meta(path: Path, max_file_size: int = 10 * 1024 * 1024) -> Optional[ArticleMeta]:
    """Safely parse article metadata from HTML comments."""
    try:
        if path.stat().st_size > max_file_size:
            return None

        meta = ArticleMeta()
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                if i >= 5:
                    break
                m = re.match(r"<!--\s*(\w+):\s*(.*)\s*-->", line.strip())
                if m:
                    key, val = m.group(1), m.group(2).strip()
                    if hasattr(meta, key):
                        setattr(meta, key, val)

        # Auto-generate summary from content
        if not meta.summary:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for _ in range(5):
                    next(f, None)
                html_content = f.read()

            content_match = re.search(r'<div class="post-content">(.*?)</div>', html_content, re.DOTALL)
            text = re.sub(r"<[^>]+>", "", content_match.group(1) if content_match else html_content)
            text = re.sub(r"\s+", " ", text).strip()
            meta.summary = text[:200] + "..." if len(text) > 200 else text

        return meta
    except Exception as e:
        logger.error(f"[ERROR] Parse meta {path}: {e}")
        return None


def list_articles(article_dir: Path, max_file_size: int = 10 * 1024 * 1024) -> list[ArticleMeta]:
    """List all valid articles sorted by date descending."""
    arts: list[ArticleMeta] = []
    if not article_dir.exists():
        return arts

    for entry in article_dir.iterdir():
        if not entry.is_file() or entry.suffix != ".html":
            continue
        if not validate_filename(entry.name):
            continue
        if entry.stat().st_size > max_file_size:
            continue

        meta = parse_meta(entry, max_file_size)
        if not meta:
            continue

        try:
            meta.file = entry.name
            meta.date_obj = datetime.strptime(meta.date[:16], "%Y-%m-%d %H:%M")
            arts.append(meta)
        except (ValueError, IndexError):
            continue

    arts.sort(key=lambda x: x.date_obj or datetime.min, reverse=True)
    return arts


def write_article(
    article_dir: Path,
    fname: str,
    title: str,
    date: str,
    slug: str,
    content: str,
    tags: str = "",
    summary: str = "",
    html_generator=None,
) -> None:
    """Safely write an article file with atomic rename."""
    from .security import validate_date_format, validate_content

    if not validate_filename(fname):
        raise ValueError(f"Invalid filename: {fname}")
    if not isinstance(title, str) or len(title) > 200:
        raise ValueError(f"Title invalid or too long: {len(title)}")
    if not validate_content(content):
        raise ValueError(f"Content validation failed: length={len(content)}")
    if not validate_date_format(date):
        raise ValueError(f"Invalid date format: {date}")

    path = article_dir / fname
    path.resolve().relative_to(article_dir.resolve())  # Raises ValueError if traversal

    html_body = text_to_html(content)
    # Lazy import to avoid circular dependency
    from .generator import generate_article_html
    full_html = generate_article_html(title=title, date=date, slug=slug, content=html_body, tags=tags, summary=summary)

    temp_path = path.with_suffix(".html.tmp")
    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(f"<!-- title: {escape_html(title)} -->\n")
            f.write(f"<!-- date: {escape_html(date)} -->\n")
            f.write(f"<!-- slug: {escape_html(slug)} -->\n")
            f.write(f"<!-- tags: {escape_html(tags)} -->\n")
            f.write(f"<!-- summary: {escape_html(summary)} -->\n")
            f.write(full_html)
        os.replace(temp_path, path)
        logger.info(f"[WRITE] Article: {fname}")
    except Exception as e:
        if temp_path.exists():
            temp_path.unlink()
        logger.error(f"[WRITE-FAILED] Article: {fname}, error: {e}")
        raise


def delete_article(path: Path) -> None:
    """Safely delete an article with backup-and-verify."""
    import shutil
    if not path.is_file():
        return
    backup = path.with_suffix(".html.backup")
    try:
        shutil.copy2(path, backup)
        path.unlink()
        if path.exists():
            raise OSError("File deletion verification failed")
        backup.unlink()
        logger.info(f"[DELETE] {path.name}")
    except Exception:
        if backup.exists():
            shutil.move(backup, path)
        raise
