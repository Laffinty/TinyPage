"""TinyPage - A modern static site generator for docs and digital gardens.

TinyPage is a lightweight, zero-dependency (core) static site generator
with built-in support for digital garden features like bidirectional links,
table of contents, footnotes, and AI-powered writing assistance.

Core Features:
    - Markdown-based content with optional mistune parser
    - Syntax highlighting with Pygments
    - Digital garden features (wikilinks, ToC, footnotes, backlinks)
    - AI writing assistance with OpenAI/DeepSeek
    - Dual-service architecture (public static + private admin)
    - Security: HTTP Basic Auth, CSRF protection, CSP headers

Quick Start:
    >>> from tinypage import Config
    >>> from tinypage.content import list_articles, write_article
    >>> cfg = Config.from_env()
    >>> articles = list_articles(cfg.article_dir)
    >>> for art in articles:
    ...     print(art.title, art.url)

Server Usage:
    $ python -m tinypage serve --port 8080

CLI Usage:
    $ tinypage build
    $ tinypage serve
    $ tinypage new-site myblog

Architecture:
    - Config: Configuration management (environment variables, defaults)
    - Content: Article/page CRUD, metadata parsing, digital garden features
    - Generator: HTML generation, RSS, sitemap, search index
    - Frontend: Static file serving WSGI app
    - Admin: Admin dashboard WSGI app with HTMX
    - Security: CSRF, auth, path validation, CSP headers
    - Parsers: Markdown, syntax highlighting, ToC, wikilinks, footnotes
"""

__version__ = "2.0.0"
__author__ = "Laffinty"

__all__ = [
    "__version__",
    "Config",
    "ArticleMeta",
    "PageInfo",
]
