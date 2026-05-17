"""TinyPage admin package — modular dashboard backend."""

from .app import AdminApp
from .responses import (
    redirect_response,
    error_response,
    json_error_response,
    html_response,
    render_admin_page,
)
from .templates import load_template, render_template

__all__ = [
    "AdminApp",
    "redirect_response",
    "error_response",
    "json_error_response",
    "html_response",
    "render_admin_page",
    "load_template",
    "render_template",
]
