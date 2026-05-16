"""Content processing - text transformation, metadata parsing, article I/O."""

from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import ArticleMeta
from .parsers import (
    render_markdown, highlight_code_blocks, parse_bidirectional_links,
    extract_headings, build_toc_html, add_heading_ids, process_footnotes,
)
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


def _extract_body_from_html(html_content: str) -> str:
    """Extract raw text content from an existing generated article HTML file.
    
    Skips all leading HTML comment metadata lines, then extracts text from
    the post-content div or falls back to stripping all HTML tags.
    """
    lines = html_content.splitlines()
    # Skip leading HTML comment metadata lines
    start_idx = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("<!--") and stripped.endswith("-->"):
            continue
        if not stripped:
            continue
        start_idx = i
        break

    body_html = "\n".join(lines[start_idx:])
    match = re.search(r'<div class="post-content">(.*?)</div>', body_html, re.DOTALL)
    if match:
        text = re.sub(r"<[^>]+>", "", match.group(1))
    else:
        text = re.sub(r"<[^>]+>", "", body_html)
    return re.sub(r"\s+", " ", text).strip()


def parse_meta(path: Path, max_file_size: int = 10 * 1024 * 1024) -> Optional[ArticleMeta]:
    """Safely parse article metadata from HTML comments."""
    try:
        if path.stat().st_size > max_file_size:
            return None

        meta = ArticleMeta()
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                if i >= 7:
                    break
                m = re.match(r"<!--\s*(\w+):\s*(.*)\s*-->", line.strip())
                if m:
                    key, val = m.group(1), m.group(2).strip()
                    if hasattr(meta, key):
                        setattr(meta, key, val)

        # Normalize status
        if not meta.status:
            meta.status = "published"

        # Auto-generate summary from content
        if not meta.summary:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                html_content = f.read()
            text = _extract_body_from_html(html_content)
            meta.summary = text[:200] + "..." if len(text) > 200 else text

        return meta
    except Exception as e:
        logger.error(f"[ERROR] Parse meta {path}: {e}")
        return None


def build_article_title_map(
    articles: list[ArticleMeta],
    prefix: str = "article",
) -> dict[str, tuple[str, str]]:
    """Build a title-to-(slug, url) mapping for bidirectional link resolution."""
    title_map: dict[str, tuple[str, str]] = {}
    for art in articles:
        if art.is_draft:
            continue
        key = art.title.lower()
        slug = art.slug or slugify_title(art.title)
        url = f"/{prefix}/{slug}.html"
        title_map[key] = (slug, url)
    return title_map


def build_backlinks_html(backlinks: list[tuple[str, str, str]]) -> str:
    """Build HTML for backlinks section."""
    if not backlinks:
        return ""
    items = []
    for title, display, url in backlinks:
        items.append(f'<li><a href="{escape_attr(url)}">{escape_html(display)}</a></li>')
    return f"""
<section class="backlinks">
  <h2>反向链接</h2>
  <ul>
    {"".join(items)}
  </ul>
</section>"""


def extract_bidirectional_links(content: str) -> list[str]:
    """Extract all [[Page Title]] links from content."""
    pattern = r"\[\[([^\]|]+)(?:\|[^\]]+)?\]\]"
    return re.findall(pattern, content)


def slugify_for_link(title: str) -> str:
    """Convert title to slug for link matching."""
    return slugify_title(title)


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
        logger.info(f"[DELETE] Article: {path.name}")
    except Exception:
        if backup.exists():
            shutil.move(backup, path)
        raise


def list_articles(
    article_dir: Path,
    max_file_size: int = 10 * 1024 * 1024,
    include_drafts: bool = False,
    category: str = "",
) -> list[ArticleMeta]:
    """List all valid articles sorted by date descending.
    
    Args:
        article_dir: Directory containing article HTML files.
        max_file_size: Maximum file size to consider.
        include_drafts: If False, filter out draft articles.
        category: If non-empty, filter by category (exact match, case-insensitive).
    """
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
        except (ValueError, IndexError):
            continue

        if not include_drafts and meta.is_draft:
            continue
        if category and meta.category.lower() != category.lower():
            continue

        arts.append(meta)

    arts.sort(key=lambda x: x.date_obj or datetime.min, reverse=True)
    return arts


def find_related_articles(
    current: ArticleMeta,
    all_articles: list[ArticleMeta],
    limit: int = 5,
) -> list[ArticleMeta]:
    """Find related articles based on tag similarity (Jaccard index).

    Args:
        current: The current article
        all_articles: List of all articles
        limit: Maximum number of related articles to return

    Returns:
        List of related ArticleMeta objects sorted by similarity
    """
    if not current.tag_list:
        return []

    current_tags = set(current.tag_list)
    related: list[tuple[ArticleMeta, float]] = []

    for article in all_articles:
        if article.file == current.file:
            continue
        if article.is_draft:
            continue
        if not article.tag_list:
            continue

        article_tags = set(article.tag_list)
        intersection = current_tags & article_tags
        union = current_tags | article_tags

        if intersection:
            jaccard = len(intersection) / len(union)
            related.append((article, jaccard))

    related.sort(key=lambda x: x[1], reverse=True)
    return [article for article, _ in related[:limit]]


def write_article(
    article_dir: Path,
    fname: str,
    title: str,
    date: str,
    slug: str,
    content: str,
    tags: str = "",
    summary: str = "",
    category: str = "",
    status: str = "published",
    html_generator=None,
    article_map: Optional[dict] = None,
    related_articles: Optional[list[ArticleMeta]] = None,
    backlinks: Optional[list] = None,
    skip_html_generation: bool = False,
) -> None:
    """Safely write an article file with atomic rename.
    
    Args:
        article_map: Dict mapping title to (slug, url) for bidirectional links
        related_articles: List of all articles for backlinks/related articles
        backlinks: Precomputed backlinks for this article
        skip_html_generation: If True, skip internal HTML generation (for deferred generation)
    """
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

    if skip_html_generation:
        full_html = ""
    else:
        # Phase 3: Process Markdown features
        # 1. Process footnotes first before markdown rendering
        processed_content, footnotes_html = process_footnotes(content)
        
        # 2. Extract headings for ToC
        headings = extract_headings(processed_content)
        toc_html = build_toc_html(headings)
        
        # 3. Process bidirectional links
        if article_map is None:
            article_map = {}
        processed_content, found_links = parse_bidirectional_links(processed_content, article_map)
        
        # Render markdown
        html_body = render_markdown(processed_content)
        
        # Add heading IDs to rendered HTML
        html_body = add_heading_ids(html_body, headings)
        
        # Highlight code blocks
        html_body = highlight_code_blocks(html_body)
        
        # Lazy import to avoid circular dependency
        from .generator import generate_article_html
        full_html = generate_article_html(
            title=title, date=date, slug=slug, content=html_body,
            tags=tags, summary=summary, category=category, status=status,
            toc_html=toc_html, footnotes_html=footnotes_html
        )

    temp_path = path.with_suffix(".html.tmp")
    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(f"<!-- title: {escape_html(title)} -->\n")
            f.write(f"<!-- date: {escape_html(date)} -->\n")
            f.write(f"<!-- slug: {escape_html(slug)} -->\n")
            f.write(f"<!-- tags: {escape_html(tags)} -->\n")
            f.write(f"<!-- summary: {escape_html(summary)} -->\n")
            f.write(f"<!-- category: {escape_html(category)} -->\n")
            f.write(f"<!-- status: {escape_html(status)} -->\n")
            f.write(f"<!-- markdown: {escape_html(content)} -->\n")
            f.write(full_html)
        os.replace(temp_path, path)
        logger.info(f"[WRITE] Article: {fname}")
    except Exception as e:
        if temp_path.exists():
            temp_path.unlink()
        logger.error(f"[WRITE-FAILED] Article: {fname}, error: {e}")
        raise


# ---------- Phase 3: Digital Garden Features ----------

def _get_backlink_cache_path(article_dir: Path) -> Path:
    """Get the path to the backlink cache file."""
    cache_dir = article_dir.parent / ".tinypage"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / "backlinks.json"


def build_backlink_index(
    articles: list[ArticleMeta],
    article_dir: Path,
) -> dict[str, list[ArticleMeta]]:
    """
    Build a backlink index: {target_article_slug: [article_meta_list]}.

    Args:
        articles: List of all articles
        article_dir: Directory containing articles
    """
    cache_path = _get_backlink_cache_path(article_dir)

    if cache_path.exists():
        try:
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            cached_mtime = cached.get("_mtime", 0)
            current_mtime = max(
                (article_dir / art.file).stat().st_mtime
                for art in articles
                if (article_dir / art.file).exists()
            ) if articles else 0

            if current_mtime <= cached_mtime:
                result: dict[str, list[ArticleMeta]] = {}
                for target_file, backlinks_data in cached.items():
                    if target_file.startswith("_"):
                        continue
                    arts = []
                    for art_data in backlinks_data:
                        art = ArticleMeta()
                        art.file = art_data.get("file", "")
                        art.title = art_data.get("title", "")
                        art.slug = art_data.get("slug", "")
                        art.date = art_data.get("date", "")
                        art.tags = art_data.get("tags", "")
                        art.summary = art_data.get("summary", "")
                        art.category = art_data.get("category", "")
                        art.status = art_data.get("status", "published")
                        arts.append(art)
                    result[target_file] = arts
                logger.info("[BACKLINKS] Loaded from cache")
                return result
        except (json.JSONDecodeError, OSError, KeyError):
            pass

    index: dict[str, list[ArticleMeta]] = {}

    for art in articles:
        if art.is_draft:
            continue

        path = article_dir / art.file
        if not path.is_file():
            continue

        content = get_raw_content(path)

        linked_titles = extract_bidirectional_links(content)

        for linked_title in linked_titles:
            linked_slug = slugify_title(linked_title)

            for target in articles:
                if target.is_draft:
                    continue

                if target.title.lower() == linked_title.lower():
                    if target.file not in index:
                        index[target.file] = []
                    if art not in index[target.file]:
                        index[target.file].append(art)
                elif target.slug == linked_slug:
                    if target.file not in index:
                        index[target.file] = []
                    if art not in index[target.file]:
                        index[target.file].append(art)

    try:
        current_mtime = max(
            (article_dir / art.file).stat().st_mtime
            for art in articles
            if (article_dir / art.file).exists()
        ) if articles else 0

        cache_data: dict = {"_mtime": current_mtime}
        for target_file, backlinks in index.items():
            cache_data[target_file] = [
                {
                    "file": art.file,
                    "title": art.title,
                    "slug": art.slug,
                    "date": art.date,
                    "tags": art.tags,
                    "summary": art.summary,
                    "category": art.category,
                    "status": art.status,
                }
                for art in backlinks
            ]
        cache_path.write_text(json.dumps(cache_data, ensure_ascii=False), encoding="utf-8")
        logger.info(f"[BACKLINKS] Cached {len(index)} entries")
    except OSError as e:
        logger.warning(f"[BACKLINKS] Failed to write cache: {e}")

    return index


def get_raw_content(path: Path) -> str:
    """
    Extract raw markdown content from article HTML file.
    Tries to extract <!-- markdown: ... --> comment, or returns summary.
    """
    try:
        if not path.is_file():
            return ""
        
        content = path.read_text(encoding="utf-8")
        
        # Look for <!-- markdown: ... --> comment
        markdown_match = re.search(r"<!-- markdown:\s*(.*?)\s*-->", content, re.DOTALL)
        if markdown_match:
            return markdown_match.group(1)
        
        # Fallback: extract from summary
        return parse_meta(path, 10*1024*1024).summary or ""
    except Exception:
        return ""


def regenerate_all_articles(
    articles: list[ArticleMeta],
    article_dir: Path,
    config,
    theme_css: str = "",
    dark_css: str = "",
    has_dark: bool = False,
    standalones: list[ArticleMeta] | None = None,
) -> None:
    """
    Regenerate all articles with full Phase 3 features.
    
    This is the main integration point for:
    - Bidirectional links
    - Table of Contents
    - Footnotes
    - Related articles
    - Backlinks
    """
    from .generator import generate_article_html
    
    logger.info("[PHASE3] Regenerating articles with digital garden features...")
    
    # Build article map for bidirectional links
    article_map = build_article_title_map(articles, "article")
    
    # Build backlink index
    backlink_index = build_backlink_index(articles, article_dir)
    
    count = 0
    for art in articles:
        path = article_dir / art.file
        if not path.is_file():
            continue
        
        # Get raw content
        raw_content = get_raw_content(path)
        
        if not raw_content:
            raw_content = art.summary or ""
        
        # 1. Process footnotes
        processed_content, footnotes_html = process_footnotes(raw_content)
        
        # 2. Extract headings and build ToC
        headings = extract_headings(processed_content)
        toc_html = build_toc_html(headings)
        
        # 3. Process bidirectional links
        processed_content, found_links = parse_bidirectional_links(processed_content, article_map)
        
        # 4. Render markdown
        html_body = render_markdown(processed_content)
        
        # 5. Add heading IDs to rendered HTML
        html_body = add_heading_ids(html_body, headings)
        
        # 6. Syntax highlighting
        html_body = highlight_code_blocks(html_body)
        
        # 7. Find related articles
        related = find_related_articles(art, articles, limit=5)
        
        # 8. Build backlinks HTML
        backlinks_html = ""
        if art.file in backlink_index:
            backlink_arts = backlink_index[art.file]
            if backlink_arts:
                backlinks_html = build_backlinks_html(
                    [(back.title, back.title, back.url) for back in backlink_arts]
                )
        
        # 9. Generate full HTML
        full_html = generate_article_html(
            title=art.title,
            date=art.date,
            slug=art.slug,
            content=html_body,
            tags=art.tags,
            summary=art.summary,
            category=art.category,
            status=art.status,
            config=config,
            theme_css=theme_css,
            dark_css=dark_css,
            has_dark=has_dark,
            standalones=standalones,
            toc_html=toc_html,
            footnotes_html=footnotes_html,
            backlinks_html=backlinks_html,
            related_articles=related,
        )
        
        # Save the updated article
        temp_path = path.with_suffix(".html.tmp")
        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                f.write(f"<!-- title: {escape_html(art.title)} -->\n")
                f.write(f"<!-- date: {escape_html(art.date)} -->\n")
                f.write(f"<!-- slug: {escape_html(art.slug)} -->\n")
                f.write(f"<!-- tags: {escape_html(art.tags)} -->\n")
                f.write(f"<!-- summary: {escape_html(art.summary)} -->\n")
                f.write(f"<!-- category: {escape_html(art.category)} -->\n")
                f.write(f"<!-- status: {escape_html(art.status)} -->\n")
                f.write(f"<!-- markdown: {escape_html(raw_content)} -->\n")
                f.write(full_html)
            os.replace(temp_path, path)
            count += 1
        except Exception as e:
            if temp_path.exists():
                temp_path.unlink()
            logger.error(f"[REGEN-FAILED] {art.file}, error: {e}")
    
    logger.info(f"[PHASE3] Regenerated {count} articles")


# ---------- Standalone Pages ----------

SAFE_PAGE_FILENAME = re.compile(r"^[a-zA-Z0-9\u4e00-\u9fa5_-]+\.html$")


def validate_page_filename(filename: str) -> bool:
    """Validate standalone page filename (no date prefix required)."""
    if not SAFE_PAGE_FILENAME.match(filename):
        return False
    if ".." in filename or "/" in filename or "\\" in filename:
        return False
    return True


def list_standalones(
    standalone_dir: Path,
    max_file_size: int = 10 * 1024 * 1024,
) -> list[ArticleMeta]:
    """List all valid standalone pages sorted by title."""
    pages: list[ArticleMeta] = []
    if not standalone_dir.exists():
        return pages

    for entry in standalone_dir.iterdir():
        if not entry.is_file() or entry.suffix != ".html":
            continue
        if not validate_page_filename(entry.name):
            continue
        if entry.stat().st_size > max_file_size:
            continue

        meta = parse_meta(entry, max_file_size)
        if not meta:
            continue
        meta.file = entry.name
        meta.slug = entry.stem
        pages.append(meta)

    pages.sort(key=lambda x: x.title or x.file)
    return pages


def write_standalone(
    standalone_dir: Path,
    fname: str,
    title: str,
    content: str,
    summary: str = "",
    html_generator=None,
) -> None:
    """Safely write a standalone page file with atomic rename."""
    from .security import validate_content

    if not validate_page_filename(fname):
        raise ValueError(f"Invalid page filename: {fname}")
    if not isinstance(title, str) or len(title) > 200:
        raise ValueError(f"Title invalid or too long: {len(title)}")
    if not validate_content(content):
        raise ValueError(f"Content validation failed: length={len(content)}")

    path = standalone_dir / fname
    path.resolve().relative_to(standalone_dir.resolve())

    html_body = render_markdown(content)
    html_body = highlight_code_blocks(html_body)
    from .generator import generate_standalone_html
    full_html = generate_standalone_html(
        title=title, content=html_body, summary=summary,
    )

    temp_path = path.with_suffix(".html.tmp")
    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(f"<!-- title: {escape_html(title)} -->\n")
            f.write(f"<!-- summary: {escape_html(summary)} -->\n")
            f.write(full_html)
        os.replace(temp_path, path)
        logger.info(f"[WRITE] Standalone: {fname}")
    except Exception as e:
        if temp_path.exists():
            temp_path.unlink()
        logger.error(f"[WRITE-FAILED] Standalone: {fname}, error: {e}")
        raise


def delete_standalone(path: Path) -> None:
    """Safely delete a standalone page with backup-and-verify."""
    delete_article(path)


# ---------- Phase 4: AI & Translation ----------

def translate_article(
    article_dir: Path,
    fname: str,
    target_lang: str,
    config,
) -> dict:
    """Translate an article to target language.

    Args:
        article_dir: Directory containing articles
        fname: Article filename to translate
        target_lang: Target language code ('en' or 'ja')
        config: Config object

    Returns:
        dict with 'success' bool and optional 'error' message
    """
    from .core.ai_assistance import build_ai_assistance, AIAssistanceError, fallback_summarize

    path = article_dir / fname
    if not path.is_file():
        return {"success": False, "error": "Article not found"}

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            html_content = f.read()
    except Exception as e:
        return {"success": False, "error": f"Read error: {e}"}

    meta = parse_meta(path)
    if not meta:
        return {"success": False, "error": "Failed to parse article metadata"}

    raw_content = get_raw_content(path)
    if not raw_content:
        return {"success": False, "error": "No content to translate"}

    lang_map = {"en": "English", "ja": "Japanese"}
    lang_name = lang_map.get(target_lang, "English")

    ai = build_ai_assistance(config)
    if not ai:
        return {"success": False, "error": "AI not configured. Set ai_api_key in config."}

    try:
        translated_content = ai.translate_text(raw_content, lang_name)
        translated_summary = ai.summarize(translated_content, 200)
    except AIAssistanceError as e:
        return {"success": False, "error": f"AI error: {e}"}

    lang_dir_map = {"en": "en", "ja": "ja"}
    lang_subdir = lang_dir_map.get(target_lang, "en")

    trans_dir = article_dir.parent / lang_subdir / "article"
    trans_dir.mkdir(parents=True, exist_ok=True)

    trans_fname = fname
    if trans_dir / trans_fname.exists():
        base = path.stem
        suffix = path.suffix
        counter = 1
        while (trans_dir / f"{base}-{counter}{suffix}").exists():
            counter += 1
        trans_fname = f"{base}-{counter}{suffix}"

    trans_slug = slugify_title(meta.title)
    translated_tags = meta.tags

    write_article(
        trans_dir,
        trans_fname,
        f"[{lang_name}] {meta.title}",
        datetime.now().strftime("%Y-%m-%d %H:%M"),
        f"{trans_slug}-{target_lang}",
        translated_content,
        translated_tags,
        translated_summary,
        meta.category,
        "published",
    )

    return {"success": True, "filename": trans_fname, "language": lang_name}

