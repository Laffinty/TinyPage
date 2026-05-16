"""TinyPage CLI - Command line interface for TinyPage."""

from __future__ import annotations

import logging
import os
import shutil
import sys
import time
from pathlib import Path

import click

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)


def _setup_directories(cfg) -> None:
    """Ensure all required directories exist."""
    dirs = [
        cfg.article_dir,
        cfg.list_dir,
        cfg.standalone_dir,
        cfg.static_dir,
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)


def _get_template_static() -> str:
    """Return minimal static directory template."""
    return """/* TinyPage Static Files */
:root {
    --tp-color: #2c3e50;
}
"""


def _get_template_article(title: str) -> str:
    """Return a template article file."""
    date = time.strftime("%Y-%m-%d %H:%M")
    slug = title.lower().replace(" ", "-")
    return f"""<!-- title: {title} -->
<!-- date: {date} -->
<!-- slug: {slug} -->
<!-- tags: -->
<!-- summary: A new article -->
<!-- category: -->
<!-- status: published -->
<!-- markdown: Start writing your article here...

## Introduction

Write your content in Markdown format.

## Section 1

More content goes here.

## Conclusion

Wrap up your article.
-->

<h1>{title}</h1>
<p>This is a template article. Edit the <code>markdown:</code> section above to write your content.</p>
"""


def _get_template_standalone(title: str, fname: str) -> str:
    """Return a template standalone page."""
    return f"""<!-- title: {title} -->
<!-- summary: A standalone page -->
<!-- markdown: Write your standalone page content here...

## {title}

This is a standalone page. Edit the content above.
-->
<h1>{title}</h1>
<p>Edit this template to create your standalone page.</p>
"""


@click.group()
@click.version_option(version="2.0.0", prog_name="tinypage")
def cli():
    """TinyPage - Zero-dependency static site generator for docs and digital gardens."""
    pass


@cli.command()
@click.option("--config", "-c", type=click.Path(exists=True), help="Config file path")
@click.option("--incremental/--full", default=False, help="Incremental build (default: full rebuild)")
@click.option("--source", "-s", type=click.Path(file_okay=False), default="pages", help="Source directory")
def build(config: str | None, incremental: bool, source: str):
    """Build static site.

    Examples:

        tinypage build                    # Full rebuild
        tinypage build --incremental     # Only changed files
        tinypage build --source ./content
    """
    from .config import Config
    from .content import list_articles, list_standalones, regenerate_all_articles
    from .generator import generate_static_pages, load_theme_css

    logger.info("[BUILD] Starting static site generation...")

    cfg = Config.from_env()
    if config:
        logger.info(f"[BUILD] Config file not yet implemented: {config}")
    cfg = cfg.merge(root_dir=Path(source).resolve())

    if not cfg.article_dir.exists():
        logger.error(f"[BUILD] Article directory not found: {cfg.article_dir}")
        logger.info("[BUILD] Run 'tinypage new-site' first or check --source path")
        sys.exit(1)

    _setup_directories(cfg)

    start = time.time()

    if incremental:
        logger.info("[BUILD] Incremental mode enabled")
        from .core.incremental import get_modified_files, get_modified_articles

        modified = get_modified_files(cfg.article_dir, cfg.root_dir)
        if not modified:
            logger.info("[BUILD] No modified files found")
            return

        logger.info(f"[BUILD] Found {len(modified)} modified files")
        articles = get_modified_articles(modified, cfg)
        theme_css, dark_css, _ = load_theme_css(cfg.theme_dir)
        standalones = list_standalones(cfg.standalone_dir, cfg.max_file_size)

        regenerate_all_articles(
            articles,
            cfg.article_dir,
            cfg,
            theme_css,
            dark_css,
            False,
            standalones,
        )
    else:
        logger.info("[BUILD] Full rebuild mode")
        articles = list_articles(cfg.article_dir, cfg.max_file_size)
        standalones = list_standalones(cfg.standalone_dir, cfg.max_file_size)
        generate_static_pages(articles, cfg, standalones)

    elapsed = time.time() - start
    logger.info(f"[BUILD] Complete in {elapsed:.2f}s")


@cli.command()
@click.option("--host", "-h", default="127.0.0.1", help="Static server host")
@click.option("--port", "-p", default=8080, type=int, help="Static server port")
@click.option("--admin-port", default=8081, type=int, help="Admin server port")
@click.option("--source", "-s", type=click.Path(file_okay=False), default="pages", help="Source directory")
@click.option("--no-admin", is_flag=True, help="Disable admin server")
def serve(host: str, port: int, admin_port: int, source: str, no_admin: bool):
    """Start development server with admin panel.

    Examples:

        tinypage serve                      # Default ports
        tinypage serve -h 0.0.0.0 -p 80   # Custom host/port
        tinypage serve --no-admin          # Static server only
    """
    import threading
    from .config import Config
    from .content import list_articles, list_standalones
    from .frontend import StaticApp
    from .admin import AdminApp
    from .generator import generate_static_pages

    cfg = Config.from_env()
    cfg = cfg.merge(
        root_dir=Path(source).resolve(),
        static_host=host,
        static_port=port,
        admin_port=admin_port,
    )

    _setup_directories(cfg)

    logger.info("[SERVE] Initializing servers...")

    if not (cfg.article_dir.exists() and any(cfg.article_dir.glob("*.html"))):
        logger.info("[SERVE] First run, generating initial pages...")
        arts = list_articles(cfg.article_dir, cfg.max_file_size)
        standalones = list_standalones(cfg.standalone_dir, cfg.max_file_size)
        if arts or standalones:
            generate_static_pages(arts, cfg, standalones)
        else:
            logger.warning("[SERVE] No articles found, admin will be empty")

    def run_static():
        from waitress import serve as wserve
        app = StaticApp(cfg)
        logger.info(f"[SERVE] Static server: http://{host}:{port}")
        wserve(app, host=host, port=port, threads=4)

    def run_admin():
        from waitress import serve as wserve
        app = AdminApp(cfg)
        logger.info(f"[SERVE] Admin server: http://127.0.0.1:{admin_port}")
        wserve(app, host="127.0.0.1", port=admin_port, threads=2)

    t1 = threading.Thread(target=run_static, daemon=True)
    t1.start()

    if not no_admin:
        t2 = threading.Thread(target=run_admin, daemon=True)
        t2.start()

    logger.info("[SERVE] Servers started. Press Ctrl+C to stop.")
    print("\n" + "=" * 60)
    print(f"Site:     http://{host}:{port}")
    if not no_admin:
        print(f"Admin:    http://127.0.0.1:{admin_port}")
    print("=" * 60 + "\n")

    try:
        t1.join()
    except KeyboardInterrupt:
        logger.info("[SERVE] Shutting down...")


@cli.command()
@click.argument("name")
@click.option("--template", "-t", type=click.Choice(["blog", "docs", "garden"]), default="blog", help="Site template")
@click.option("--dir", "-d", type=click.Path(), default=None, help="Target directory (default: NAME)")
def new_site(name: str, template: str, dir: str | None):
    """Create a new TinyPage site.

    Examples:

        tinypage new-site my-docs
        tinypage new-site my-blog --template blog
        tinypage new-site my-garden --template garden
    """
    target = Path(dir) if dir else Path.cwd() / name

    if target.exists() and any(target.iterdir()):
        logger.error(f"[NEW] Directory already exists and is not empty: {target}")
        sys.exit(1)

    logger.info(f"[NEW] Creating new TinyPage site: {name}")
    logger.info(f"[NEW] Template: {template}")
    logger.info(f"[NEW] Target: {target}")

    target.mkdir(parents=True, exist_ok=True)

    dirs = ["pages/article", "pages/list", "pages/standalone", "pages/static", "themes/default", "static"]
    for d in dirs:
        (target / d).mkdir(parents=True, exist_ok=True)

    config_py = '''"""TinyPage Configuration."""
ADMIN_USER = "admin"
ADMIN_PASS = ""  # Set your password here
STATIC_HOST = "127.0.0.1"
STATIC_PORT = 8080
ADMIN_PORT = 8081
SITE_TITLE = "My TinyPage Site"
SITE_URL = ""
'''
    (target / "config.py").write_text(config_py, encoding="utf-8")

    static_css = """/* TinyPage Theme - Default */
:root {
    --bg-color: #ffffff;
    --text-color: #333;
    --link-color: #2c3e50;
    --heading-color: #1a1a1a;
    --code-bg: #f5f5f5;
    --border-color: #ddd;
}
@media (prefers-color-scheme: dark) {
    :root {
        --bg-color: #1a1a1a;
        --text-color: #ccc;
        --link-color: #6ab0de;
        --heading-color: #fff;
        --code-bg: #2d2d2d;
        --border-color: #444;
    }
}
body {
    font-family: system-ui, -apple-system, sans-serif;
    max-width: 800px;
    margin: 0 auto;
    padding: 2rem;
    background: var(--bg-color);
    color: var(--text-color);
}
a { color: var(--link-color); }
h1, h2, h3 { color: var(--heading-color); }
code { background: var(--code-bg); padding: 0.2em 0.4em; border-radius: 3px; }
"""
    (target / "themes/default/theme.css").write_text(static_css, encoding="utf-8")

    manifest = """{
    "name": "default",
    "version": "1.0.0",
    "layouts": ["blog"]
}
"""
    (target / "themes/default/manifest.json").write_text(manifest, encoding="utf-8")

    article_content = """<!-- title: Welcome to TinyPage -->
<!-- date: 2024-01-01 00:00 -->
<!-- slug: welcome -->
<!-- tags: getting-started -->
<!-- summary: Welcome to your new TinyPage site! -->
<!-- category: -->
<!-- status: published -->
<!-- markdown: # Welcome to TinyPage!

Congratulations on creating your new site. Here's how to get started:

## Writing Articles

Create new `.html` files in `pages/article/` with the following format:

```
<!-- title: Your Title -->
<!-- date: 2024-01-01 00:00 -->
<!-- tags: tag1, tag2 -->
<!-- summary: Brief description -->
<!-- status: published -->
<!-- markdown: Your content in **Markdown** format.
-->
```

## Features

- **Bidirectional links**: Use `[[Page Title]]` syntax
- **Table of Contents**: Auto-generated from headings
- **Footnotes**: Use `[^1]` syntax
- **Code highlighting**: Syntax highlighting for code blocks
- **Dark mode**: Automatic theme switching

## Admin Panel

Start the server with `tinypage serve` and visit http://127.0.0.1:8081

## Documentation

See the README for more information.
-->
<h1>Welcome to TinyPage!</h1>
<p>Congratulations on creating your new site.</p>
"""
    (target / "pages/article/welcome.html").write_text(article_content, encoding="utf-8")

    standalone_about = """<!-- title: About -->
<!-- summary: About this site -->
<!-- markdown: # About

This is a TinyPage site. Edit `pages/standalone/about.html` to customize this page.
-->
<h1>About</h1>
<p>Edit this page to tell visitors about yourself or your project.</p>
"""
    (target / "pages/standalone/about.html").write_text(standalone_about, encoding="utf-8")

    readme_content = f"""# {name}

A TinyPage site.

## Quick Start

```bash
pip install tinypage[full]
tinypage serve
```

Visit http://127.0.0.1:8081 to see your site.
Visit http://127.0.0.1:8081/admin for the admin panel.

## Writing Articles

Create `.html` files in `pages/article/` with metadata comments and Markdown content.

## Commands

- `tinypage build` - Build static site
- `tinypage serve` - Start development server
- `tinypage new-site NAME` - Create new site

## Documentation

See https://github.com/Laffinty/TinyPage for full documentation.
"""
    (target / "README.md").write_text(readme_content, encoding="utf-8")

    gitignore = """__pycache__/
*.pyc
*.pyo
.env
.env.local
admin_password.txt
security_audit.log
*.html.backup
"""
    (target / ".gitignore").write_text(gitignore, encoding="utf-8")

    logger.info(f"[NEW] Site created successfully: {target}")
    logger.info(f"[NEW] Next steps:")
    logger.info(f"  cd {target}")
    logger.info(f"  pip install -e .[full]")
    logger.info(f"  tinypage serve")


@cli.command()
def init():
    """Initialize Git hooks for this project.

    Examples:

        tinypage init
    """
    hooks_dir = Path(".git/hooks")
    if not hooks_dir.exists():
        logger.error("[INIT] Not a Git repository. Run 'git init' first.")
        sys.exit(1)

    install_script = Path(__file__).parent.parent / "scripts" / "git-hooks" / "install.py"
    if install_script.exists():
        logger.info("[INIT] Running git-hooks install script...")
        os.system(f"{sys.executable} {install_script}")
    else:
        logger.warning("[INIT] Git hooks install script not found")


if __name__ == "__main__":
    cli()