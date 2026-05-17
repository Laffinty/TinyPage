"""Template loading and rendering for admin dashboard.

Uses Python's built-in string.Template — zero external dependencies.
"""

from __future__ import annotations

from pathlib import Path
from string import Template
from typing import Any

# Project root relative to this file
_TEMPLATES_DIR = Path(__file__).resolve().parent.parent.parent / "admin_templates"
_template_cache: dict[str, Template] = {}


def load_template(name: str) -> Template:
    """Load a template from disk and cache it."""
    if name not in _template_cache:
        path = _TEMPLATES_DIR / name
        if not path.is_file():
            raise FileNotFoundError(f"Admin template not found: {path}")
        _template_cache[name] = Template(path.read_text(encoding="utf-8"))
    return _template_cache[name]


def render_template(name: str, **kwargs: Any) -> str:
    """Load and render a template with the given substitutions."""
    t = load_template(name)
    # Convert non-string values to strings for Template.substitute
    safe = {k: str(v) for k, v in kwargs.items()}
    return t.safe_substitute(safe)


def build_nav_html(nav_items: list[tuple[str, str, str]], current_path: str) -> str:
    """Build sidebar navigation HTML.

    Args:
        nav_items: list of (href, label, icon_name)
        current_path: current request path for active state
    """
    lines = []
    icons = {
        "dashboard": "◈",
        "article": "+",
        "page": "◉",
        "pages": "☰",
        "theme": "◐",
    }
    for href, label, icon_name in nav_items:
        icon = icons.get(icon_name, "•")
        active = ' aria-current="page"' if href == current_path else ""
        active_cls = " nav-active" if href == current_path else ""
        lines.append(
            f'<a href="{href}" class="nav-item{active_cls}"{active}>'
            f'<span class="nav-icon">{icon}</span>'
            f'<span class="nav-label">{label}</span></a>'
        )
    return "\n".join(lines)
