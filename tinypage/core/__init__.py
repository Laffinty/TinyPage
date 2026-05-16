"""TinyPage core module - template system and theme management."""

from .template import (
    render_skeleton,
    load_theme_manifest,
    list_themes,
    build_article_context,
    build_list_context,
    build_search_context,
    build_standalone_context,
    build_category_context,
)
from .ai_assistance import AIAssistance, AIAssistanceError, build_ai_assistance, fallback_summarize

__all__ = [
    "render_skeleton",
    "load_theme_manifest",
    "list_themes",
    "build_article_context",
    "build_list_context",
    "build_search_context",
    "build_standalone_context",
    "build_category_context",
    "AIAssistance",
    "AIAssistanceError",
    "build_ai_assistance",
    "fallback_summarize",
]