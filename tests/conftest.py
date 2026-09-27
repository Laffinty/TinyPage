"""Shared fixtures for TinyPage tests."""

from __future__ import annotations

import pytest

from tinypage.config import Config


@pytest.fixture
def site(tmp_path):
    """A minimal but complete on-disk site layout."""
    themes = tmp_path / "themes" / "default"
    themes.mkdir(parents=True)
    (themes / "theme.css").write_text("body{color:#333}", encoding="utf-8")
    (themes / "theme.dark.css").write_text("body{background:#000}", encoding="utf-8")

    cfg = Config(
        root_dir=(tmp_path / "pages").resolve(),
        admin_user="admin",
        admin_pass="x" * 24,
        admin_port=8081,
        static_port=8080,
    )
    for sub in ("article", "standalone", "list", "static"):
        (cfg.root_dir / sub).mkdir(parents=True, exist_ok=True)

    # Config.theme_dir is relative to CWD; point it at this fixture's themes.
    cfg = cfg.merge(theme_name=str(themes).replace("\\", "/").split("/")[-1])
    return cfg


@pytest.fixture
def article_body() -> str:
    """Content that exercises every case that used to corrupt data."""
    return (
        "Cost is $5 & <10, >2, \"quoted\", 'single'.\n\n"
        "<!-- an html comment that contains no terminator -->\n\n"
        "```js\nconst s = 'a --> b'; // tricky\n```\n\n"
        "Tail [^1] with a footnote.\n\n[^1]: note text\n\n"
        "中文标题和 emoji \U0001f600 保留。\n"
    )
