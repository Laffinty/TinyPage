"""Incremental build engine for TinyPage."""

from __future__ import annotations

import filecmp
import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..config import Config
    from ..models import ArticleMeta

logger = logging.getLogger(__name__)


def get_modified_files(
    source_dir: Path,
    output_dir: Path,
    extensions: tuple[str, ...] = (".html",),
) -> list[Path]:
    """Return list of source files that are newer than their outputs.

    Args:
        source_dir: Directory containing source files
        output_dir: Directory containing generated output files
        extensions: Tuple of file extensions to check

    Returns:
        List of source files that need regeneration
    """
    modified = []
    if not source_dir.exists():
        return modified

    for src in source_dir.glob("*"):
        if not src.is_file():
            continue
        if src.suffix not in extensions:
            continue

        out = output_dir / src.name
        if not out.exists():
            modified.append(src)
        elif src.stat().st_mtime > out.stat().st_mtime:
            modified.append(src)

    return modified


def get_modified_articles(
    modified_files: list[Path],
    cfg: Config,
) -> list[ArticleMeta]:
    """Get ArticleMeta objects for modified article files.

    Args:
        modified_files: List of modified file paths
        cfg: Config object

    Returns:
        List of ArticleMeta objects for modified articles
    """
    from ..content import parse_meta

    articles = []
    for path in modified_files:
        if path.suffix != ".html":
            continue
        meta = parse_meta(path, cfg.max_file_size)
        if meta:
            meta.file = path.name
            articles.append(meta)

    return articles


def compare_directories(dir1: Path, dir2: Path) -> tuple[list[Path], list[Path], list[Path]]:
    """Compare two directories and return added, removed, and modified files.

    Args:
        dir1: First directory (source)
        dir2: Second directory (output)

    Returns:
        Tuple of (added, removed, modified) file lists
    """
    if not dir1.exists():
        return [], [], []

    comparison = filecmp.dircmp(str(dir1), str(dir2), ignore=["__pycache__", ".DS_Store"])

    added: list[Path] = []
    removed: list[Path] = []
    modified: list[Path] = []

    def _collect_files(cmp: filecmp.dircmp) -> None:
        for f in cmp.left_only:
            path = Path(cmp.left) / f
            if path.is_file() and path.suffix == ".html":
                added.append(path)
        for f in cmp.right_only:
            path = Path(cmp.right) / f
            if path.is_file() and path.suffix == ".html":
                removed.append(path)
        for f in cmp.diff_files:
            path = Path(cmp.left) / f
            if path.is_file() and path.suffix == ".html":
                modified.append(path)
        for sub in cmp.subdirs.values():
            _collect_files(sub)

    _collect_files(comparison)
    return added, removed, modified


def estimate_build_time(article_count: int) -> float:
    """Estimate build time based on article count.

    Args:
        article_count: Number of articles to build

    Returns:
        Estimated time in seconds
    """
    time_per_article = 0.01
    overhead = 0.5
    return article_count * time_per_article + overhead


def should_use_incremental(
    source_dir: Path,
    output_dir: Path,
    threshold: int = 100,
) -> bool:
    """Determine if incremental build should be used.

    Args:
        source_dir: Source directory
        output_dir: Output directory
        threshold: Minimum article count to consider incremental

    Returns:
        True if incremental build is recommended
    """
    if not source_dir.exists():
        return False

    article_count = len(list(source_dir.glob("*.html")))
    if article_count < threshold:
        return False

    modified = get_modified_files(source_dir, output_dir)
    modified_ratio = len(modified) / article_count if article_count > 0 else 1.0

    return modified_ratio < 0.1


def build_cache_key(article_dir: Path) -> str:
    """Build a cache key based on article directory state.

    Args:
        article_dir: Article directory path

    Returns:
        Cache key string
    """
    import hashlib
    import os

    if not article_dir.exists():
        return "empty"

    mtimes = []
    for f in sorted(article_dir.glob("*.html")):
        mtimes.append(f"{f.name}:{int(f.stat().st_mtime)}")

    content = "|".join(mtimes)
    return hashlib.md5(content.encode()).hexdigest()[:12]


def get_unchanged_articles(
    articles: list[ArticleMeta],
    article_dir: Path,
    cache_file: Path | None = None,
) -> tuple[list[ArticleMeta], list[ArticleMeta]]:
    """Split articles into unchanged and changed based on cache.

    Args:
        articles: All articles
        article_dir: Article directory
        cache_file: Optional cache file path

    Returns:
        Tuple of (unchanged_articles, changed_articles)
    """
    if cache_file and cache_file.exists():
        try:
            cached_key = cache_file.read_text().strip()
            current_key = build_cache_key(article_dir)
            if cached_key == current_key:
                logger.info("[INCREMENTAL] Cache hit, no changes detected")
                return articles, []
        except Exception:
            pass

    modified_files = get_modified_files(article_dir, article_dir)
    modified_names = {f.name for f in modified_files}

    changed = []
    unchanged = []
    for art in articles:
        if art.file in modified_names:
            changed.append(art)
        else:
            unchanged.append(art)

    if cache_file:
        try:
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(build_cache_key(article_dir))
        except Exception:
            pass

    return unchanged, changed


def update_cache(article_dir: Path, cache_file: Path) -> None:
    """Update the build cache file.

    Args:
        article_dir: Article directory
        cache_file: Cache file path
    """
    try:
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(build_cache_key(article_dir))
        logger.info(f"[CACHE] Updated: {cache_file}")
    except Exception as e:
        logger.warning(f"[CACHE] Failed to update: {e}")