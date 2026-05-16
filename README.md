# TinyPage

A modern static site generator for documentation and digital gardens. Built with Python, stores content as HTML files without requiring a database.

基于 Python 构建的现代化静态站点生成器，支持文档和数字花园功能。内容以 HTML 文件形式存储，无需数据库。

---

## Features / 特性

### Core / 核心功能
- **Zero-dependency core** / 核心零依赖：Run with `pip install tinypage` or extend with extras
- **Markdown support** / Markdown 支持：Rich content with optional mistune parser
- **Syntax highlighting** / 代码高亮：Pygments integration with theme support
- **Pagination** / 分页支持：Auto-generate paginated article lists
- **Full-text search** / 全文搜索：Frontend JavaScript search with JSON index
- **RSS & Sitemap** / RSS 与站点地图：Auto-generated for SEO

### Digital Garden / 数字花园
- **Bidirectional links** / 双向链接：`[[Page Title]]` wikilink syntax
- **Table of Contents** / 目录导航：Auto-generated from headings
- **Footnotes** / 脚注：`[^1]` footnote syntax
- **Mermaid diagrams** / Mermaid 图表：Flowcharts and sequence diagrams
- **Backlinks** / 反向链接：See what links to your articles
- **Related articles** / 相关文章：Tag-based Jaccard similarity
- **Tag graph** / 标签图谱：Visual tag network

### Modern Web / 现代 Web
- **PWA support** / PWA 支持：Offline-capable with service worker
- **Dark mode** / 深色模式：System preference + manual toggle
- **CSS View Transitions** / CSS 视图过渡：Smooth page navigation
- **SEO optimized** / SEO 优化：JSON-LD, Open Graph, Twitter Cards
- **Responsive design** / 响应式设计：Mobile-friendly layouts

### Admin & Security / 管理与安全
- **Admin dashboard** / 管理后台：HTMX-enhanced modern UI
- **HTTP Basic Auth** / 基础认证：Protected admin access
- **CSRF protection** / CSRF 防护：HMAC token + double-submit cookie
- **Content Security Policy** / CSP：Modern security headers
- **Rate limiting** / 速率限制：In-memory request throttling
- **Audit logging** / 审计日志：Security event tracking

### AI Features / AI 功能 (optional)
- **AI writing assistant** / AI 写作助手：Complete, polish, translate
- **Auto summarization** / 自动摘要：AI-powered summaries
- **Smart tag suggestions** / 智能标签推荐：Keyword extraction

### Theme System / 主题系统
- **Theme switching** / 主题切换：Live preview in admin
- **Dark mode themes** / 深色主题：Built-in theme support
- **Extensible layouts** / 可扩展布局：Blog, doc, garden layouts

---

## Quick Start / 快速开始

```bash
# Install core (zero dependencies)
pip install tinypage

# Or install with extras
pip install tinypage[markdown,syntax]     # Markdown + syntax highlighting
pip install tinypage[ai]                  # AI features
pip install tinypage[full]                 # All features

# Run the server
python -m tinypage serve

# Or use CLI
tinypage build
tinypage serve --port 8080
```

The application will start two services: / 应用将启动两个服务：

- **Static frontend**: `http://127.0.0.1:8080` - Public-facing site
- **Admin backend**: `http://127.0.0.1:8081` - Content management

Admin credentials are generated automatically on first run if `ADMIN_PASS` is not set. Check the console output.  
如果未设置 `ADMIN_PASS`，首次运行时将自动生成管理员密码，请查看控制台输出。

---

## Installation Options / 安装选项

| Extra | Description |
|-------|-------------|
| `markdown` | Mistune 3.x parser for extended Markdown |
| `syntax` | Pygments for syntax highlighting |
| `ai` | OpenAI/DeepSeek for AI writing assistance |
| `server` | Waitress WSGI server |
| `full` | All features |

---

## Environment Variables / 环境变量

| Variable | Description | Default |
|----------|-------------|---------|
| `ADMIN_USER` | Admin username | `admin` |
| `ADMIN_PASS` | Admin password | auto-generated |
| `STATIC_PORT` | Frontend port | `8080` |
| `ADMIN_PORT` | Backend port | `8081` |
| `STATIC_HOST` | Bind address | `127.0.0.1` |
| `BIND_DOMAIN` | Domain for Nginx proxy | (empty) |

---

## Deployment / 部署

### Docker

```bash
docker-compose up -d
```

### Nginx Reverse Proxy / Nginx 反向代理

```nginx
# Frontend (static pages) - Public HTTPS
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/your/cert.pem;
    ssl_certificate_key /path/to/your/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Admin backend - Private HTTPS port
server {
    listen 10443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /path/to/your/cert.pem;
    ssl_certificate_key /path/to/your/key.pem;

    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
    }
}
```

### GitHub Actions / CI/CD

See `.github/workflows/` for deployment templates:
- GitHub Pages
- Cloudflare Pages
- Vercel

---

## Project Structure / 项目结构

```
TinyPage/
├── tinypage/              # Core Python package
│   ├── __init__.py        # Package entry point
│   ├── config.py          # Configuration management
│   ├── server.py          # Server startup
│   ├── frontend.py        # Static file WSGI app
│   ├── admin.py           # Admin dashboard WSGI app
│   ├── generator.py       # HTML generators
│   ├── content.py         # Article I/O & digital garden
│   ├── models.py          # Data models
│   ├── security.py        # Security utilities
│   ├── parsers/          # Content parsers
│   │   ├── markdown.py    # Markdown rendering
│   │   ├── syntax.py      # Syntax highlighting
│   │   ├── toc.py         # Table of contents
│   │   ├── footnotes.py   # Footnote processing
│   │   ├── wikilinks.py   # Bidirectional links
│   │   └── tag_graph.py   # Tag visualization
│   ├── core/              # Core utilities
│   │   ├── template.py    # Page skeleton templates
│   │   └── ai_assistance.py # AI writing tools
│   └── cli.py             # CLI commands
├── themes/                 # Theme CSS files
├── static/                 # Static assets
├── pages/                  # Generated site output
├── scripts/                # Deployment scripts
├── Dockerfile
├── docker-compose.yml
└── pyproject.toml
```

---

## Architecture / 架构

TinyPage uses a dual-service architecture:

1. **Static Server** (port 8080): Serves pre-generated HTML, CSS, JS, and images
2. **Admin Server** (port 8081): Protected backend for content management

Content is stored as plain HTML files in the `pages/` directory, making it:
- **Git-friendly**: Version control your content
- **Database-free**: No SQLite or external DB required
- **Portable**: Deploy anywhere that serves static files

---

## Security Notes / 安全说明

- Admin backend is bound to `127.0.0.1` by default
- Use HTTPS reverse proxy for production
- Change default admin credentials
- Enable rate limiting in high-traffic scenarios

---

## License / 许可证

MIT License - See [LICENSE](LICENSE) file for details.

Copyright (c) 2026 Laffinty
