"""Data models using dataclasses."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class ArticleMeta:
    """Article metadata extracted from HTML comments."""

    title: str = ""
    date: str = ""
    slug: str = ""
    tags: str = ""
    summary: str = ""
    file: str = ""
    date_obj: Optional[datetime] = None

    @property
    def tag_list(self) -> list[str]:
        """Return tags as a list."""
        if not self.tags:
            return []
        return [t.strip() for t in self.tags.split(",") if t.strip()]

    @property
    def iso_date(self) -> str:
        """Return ISO 8601 date string."""
        if self.date_obj:
            return self.date_obj.isoformat()
        return self.date.replace(" ", "T") if " " in self.date else self.date

    @property
    def url(self) -> str:
        """Return relative URL for this article."""
        return f"/article/{self.file}"


@dataclass
class PageInfo:
    """Pagination information."""

    current: int = 1
    total: int = 1
    has_prev: bool = False
    has_next: bool = False
    prev_url: str = ""
    next_url: str = ""


@dataclass
class ThemeAssets:
    """Collected theme CSS content."""

    base_css: str = ""
    dark_css: str = ""
    has_dark: bool = False
