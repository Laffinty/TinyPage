# TinyPage

A static page/blog generator built with Python. Stores content as HTML files without requiring a database. Experimental project for testing ideas.  
基于 Python 构建的静态页面/博客生成器。内容以 HTML 文件形式存储，无需数据库。这是一个用于测试想法的实验性项目。

---

## ⚠️ WARNING / 警告

**This is an experimental project for testing the author's ideas only. DO NOT use in any production environment. No warranty or support is provided.**  
**本项目仅为作者测试想法而创建的实验性项目。请勿用于任何生产环境。不提供任何担保或支持。**

---

## Features / 特性

- Simple static page generation / 简单的静态页面生成
- Basic admin interface with HTTP Basic Auth + CSRF protection / 基础管理后台，支持 HTTP Basic 认证与 CSRF 防护
- Markdown-like text formatting (bold, italic, code, links) / 类 Markdown 文本格式（粗体、斜体、代码、链接）
- Pagination support / 分页支持
- Full-text search (frontend JavaScript) / 全文搜索（前端 JavaScript 实现）
- RSS 2.0 feed and XML sitemap / RSS 2.0 订阅源与 XML 站点地图
- PWA support (manifest + service worker) / PWA 支持（清单 + Service Worker）
- Dark mode (system preference + manual toggle) / 深色模式（跟随系统偏好 + 手动切换）
- CSS View Transitions / CSS 视图过渡效果
- Security features (path traversal prevention, security headers, CSP, audit logging) / 安全特性（路径遍历防护、安全响应头、CSP、审计日志）

---

## Quick Start / 快速开始

```bash
# Install dependencies / 安装依赖
pip install waitress

# Run the application / 运行应用
python tiny_page.py
```

The application will start two services: / 应用将启动两个服务：
- Static frontend: http://127.0.0.1:8080 / 静态前端：http://127.0.0.1:8080
- Admin backend: http://127.0.0.1:8081 / 管理后台：http://127.0.0.1:8081

Admin credentials are generated automatically on first run if `ADMIN_PASS` is not set. Check the console output.  
如果未设置 `ADMIN_PASS`，首次运行时将自动生成管理员密码，请查看控制台输出。

---

## Nginx Reverse Proxy / Nginx 反向代理

Configure Nginx as a reverse proxy (HTTPS example):  
将 Nginx 配置为反向代理（HTTPS 示例）：

```nginx
# Frontend (static pages) - Public HTTPS / 前端（静态页面）- 公共 HTTPS
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    # SSL certificates / SSL 证书
    ssl_certificate /path/to/your/cert.pem;
    ssl_certificate_key /path/to/your/key.pem;

    # SSL configuration / SSL 配置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Admin backend - Private HTTPS port / 管理后台 - 私有 HTTPS 端口
server {
    listen 10443 ssl http2;
    server_name your-domain.com;

    # SSL certificates / SSL 证书
    ssl_certificate /path/to/your/cert.pem;
    ssl_certificate_key /path/to/your/key.pem;

    # SSL configuration / SSL 配置
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Basic auth timeout / 基础认证超时
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
    }
}
```

---

## Environment Variables / 环境变量

| Variable / 变量 | Description / 说明 | Default / 默认值 |
|---|---|---|
| `ADMIN_USER` | Admin username / 管理员用户名 | `admin` |
| `ADMIN_PASS` | Admin password / 管理员密码 | auto-generated / 自动生成 |
| `STATIC_PORT` | Frontend port / 前端端口 | `8080` |
| `ADMIN_PORT` | Backend port / 后台端口 | `8081` |
| `STATIC_HOST` | Bind address / 绑定地址 | `127.0.0.1` |
| `BIND_DOMAIN` | Domain for Nginx proxy / Nginx 代理域名 | (empty / 空) |

---

## Project Structure / 项目结构

```
TinyPage/
├── tinypage/           # Core Python package / 核心 Python 包
│   ├── config.py       # Configuration / 配置管理
│   ├── server.py       # Entry point & startup / 入口与启动逻辑
│   ├── frontend.py     # Static file WSGI app / 静态文件 WSGI 应用
│   ├── admin.py        # Admin WSGI app / 管理后台 WSGI 应用
│   ├── generator.py    # HTML generators / HTML 生成器
│   ├── content.py      # Article I/O / 文章读写
│   ├── models.py       # Data models / 数据模型
│   └── security.py     # Security utilities / 安全工具
├── themes/default/     # Theme CSS files / 主题 CSS 文件
├── static_inject/      # Injected static assets / 注入式静态资源
├── pages/              # Generated static site output / 生成的静态站点输出
├── tiny_page.py        # Launcher script / 启动脚本
├── test_runner.py      # Integration tests / 集成测试
├── make_snapshots.py   # Snapshot generator / 快照生成器
└── README.md           # This file / 本文件
```

---

## Testing / 测试

Run integration tests (requires the server to be running):  
运行集成测试（需要服务正在运行）：

```bash
python tiny_page.py   # in another terminal / 在另一个终端运行
python test_runner.py
```

---

## Important Notes / 重要提示

1. **Security / 安全**：This is experimental code with basic security measures. It may have vulnerabilities. / 这是带有基础安全措施的实验性代码，可能存在漏洞。
2. **Performance / 性能**：Not optimized for high traffic or large datasets. / 未针对高流量或大数据量进行优化。
3. **Data Persistence / 数据持久化**：All data is stored as HTML files in the `pages/` directory. / 所有数据均以 HTML 文件形式存储在 `pages/` 目录中。
4. **No Backup / 无备份**：No built-in backup mechanism. Data loss is possible. / 没有内置备份机制，可能发生数据丢失。
5. **No Updates / 无自动更新**：No automatic updates or maintenance mode. / 没有自动更新或维护模式。

---

## Limitations / 限制

- Single admin user only / 仅支持单个管理员账户
- No user management / 无用户管理
- No media upload / 无媒体上传
- No comments system / 无评论系统
- Basic text formatting only / 仅支持基础文本格式

---

## License / 许可证

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.  
本项目采用 MIT 许可证。详情请参阅 [LICENSE](LICENSE) 文件。

Copyright (c) 2026 Laffinty
