"""Configuration management with environment variables and optional config file."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Config:
    """Immutable application configuration."""

    # Site
    site_title: str = "TinyPage"
    site_description: str = "A modern static blog"
    site_url: str = ""
    site_author: str = ""
    footer_text: str = "Powered by TinyPage"
    lang: str = "zh-CN"

    # Security
    admin_user: str = field(default_factory=lambda: os.getenv("ADMIN_USER", "admin"))
    admin_pass: str = field(default_factory=lambda: os.getenv("ADMIN_PASS", ""))

    # Server
    static_host: str = field(
        default_factory=lambda: os.getenv("STATIC_HOST", "127.0.0.1")
    )
    static_port: int = field(
        default_factory=lambda: int(os.getenv("STATIC_PORT", "8080"))
    )
    admin_port: int = field(
        default_factory=lambda: int(os.getenv("ADMIN_PORT", "8081"))
    )
    bind_domain: str = field(default_factory=lambda: os.getenv("BIND_DOMAIN", ""))

    # Paths
    root_dir: Path = field(default_factory=lambda: Path("pages").resolve())
    theme_name: str = "default"

    # Content
    page_size: int = 10
    max_file_size: int = 10 * 1024 * 1024
    max_title_length: int = 200
    max_content_length: int = 50000

    # Features
    enable_pwa: bool = True
    enable_dark_mode: bool = True
    enable_search: bool = True
    enable_rss: bool = True
    enable_sitemap: bool = True
    enable_view_transitions: bool = True

    # PWA
    pwa_short_name: str = "TinyPage"
    pwa_theme_color: str = "#2c3e50"
    pwa_bg_color: str = "#ffffff"

    # AI (optional - requires extras_require ai)
    ai_provider: str = "openai"
    ai_api_key: str = ""
    ai_model: str = "gpt-3.5-turbo"
    ai_endpoint: str = ""
    ai_enabled: bool = False

    @property
    def article_dir(self) -> Path:
        return self.root_dir / "article"

    @property
    def list_dir(self) -> Path:
        return self.root_dir / "list"

    @property
    def standalone_dir(self) -> Path:
        return self.root_dir / "standalone"

    @property
    def static_dir(self) -> Path:
        return self.root_dir / "static"

    @property
    def theme_dir(self) -> Path:
        return Path("themes") / self.theme_name

    @classmethod
    def from_env(cls) -> Config:
        """Build config from environment variables and persisted config file."""
        config = cls()
        config_dir = Path(".") / ".tinypage"
        config_file = config_dir / "config.json"
        if config_file.exists():
            try:
                config_data = json.loads(config_file.read_text(encoding="utf-8"))
                if "theme_name" in config_data:
                    config = config.merge(theme_name=config_data["theme_name"])
            except (OSError, json.JSONDecodeError):
                pass
        return config

    def __post_init__(self):
        """Validate configuration values at creation time."""
        if not (1 <= self.static_port <= 65535):
            raise ValueError(
                f"Invalid static_port: {self.static_port}. Must be 1-65535."
            )
        if not (1 <= self.admin_port <= 65535):
            raise ValueError(f"Invalid admin_port: {self.admin_port}. Must be 1-65535.")
        if self.admin_port == self.static_port:
            raise ValueError(
                f"admin_port and static_port must differ (both {self.admin_port})."
            )
        if self.page_size < 1:
            raise ValueError(f"Invalid page_size: {self.page_size}. Must be >= 1.")
        if self.max_file_size < 1024:
            raise ValueError(
                f"Invalid max_file_size: {self.max_file_size}. Must be >= 1024."
            )
        if self.max_title_length < 1:
            raise ValueError(
                f"Invalid max_title_length: {self.max_title_length}. Must be >= 1."
            )
        if self.max_content_length < 100:
            raise ValueError(
                f"Invalid max_content_length: {self.max_content_length}. Must be >= 100."
            )

    def validate_startup(self) -> list[str]:
        """Validate config for startup. Returns list of warnings."""
        warnings = []
        if not self.admin_pass:
            warnings.append(
                "ADMIN_PASS is not set. A random password will be generated "
                "and saved to a temp file. Set ADMIN_PASS env var for persistent auth."
            )
        if len(self.admin_pass) < 16 and self.admin_pass:
            warnings.append(
                f"ADMIN_PASS is only {len(self.admin_pass)} chars. "
                "Recommend at least 16 characters."
            )
        return warnings

    def merge(self, **kwargs: Any) -> Config:
        """Return a new config with overrides."""
        current = {k: getattr(self, k) for k in self.__dataclass_fields__}
        current.update(kwargs)
        # Convert path strings back to Path
        if "root_dir" in kwargs and isinstance(kwargs["root_dir"], str):
            current["root_dir"] = Path(kwargs["root_dir"]).resolve()
        return Config(**current)
