# TinyPage

A minimal experimental page/blog system built with Python. This is a toy project for testing ideas, not for production use.

## ⚠️ WARNING

**This is an experimental project for testing the author's ideas only. DO NOT use in any production environment. No warranty or support is provided.**

## Features

- Simple static page generation
- Basic admin interface with authentication
- Markdown-like text formatting
- Pagination support
- Security features (CSRF protection, path traversal prevention, etc.)

## Quick Start

```bash
# Install dependencies
pip install waitress

# Run the application
python tiny_page.py
```

The application will start two services:
- Static frontend: http://127.0.0.1:8080
- Admin backend: http://127.0.0.1:8081

Default admin credentials are generated automatically on first run. Check the console output or `admin_password.txt` file.

## Nginx Reverse Proxy

Configure Nginx as a reverse proxy:

```nginx
server {
    listen 80;
    server_name your-domain.com;

    # Frontend (static pages)
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Admin backend
    location /admin/ {
        proxy_pass http://127.0.0.1:8081/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Basic auth timeout
        proxy_read_timeout 300s;
        proxy_connect_timeout 75s;
    }
}
```

## Important Notes

1. **Security**: This is experimental code with basic security measures. It may have vulnerabilities.
2. **Performance**: Not optimized for high traffic or large datasets.
3. **Data Persistence**: All data is stored as HTML files in the `pages/` directory.
4. **No Backup**: No built-in backup mechanism. Data loss is possible.
5. **No Updates**: No automatic updates or maintenance mode.

## Environment Variables

- `ADMIN_USER`: Admin username (default: admin)
- `ADMIN_PASS`: Admin password (auto-generated if not set)
- `STATIC_PORT`: Frontend port (default: 8080)
- `ADMIN_PORT`: Backend port (default: 8081)
- `STATIC_HOST`: Bind address (default: 127.0.0.1)
- `BIND_DOMAIN`: Domain for Nginx proxy (optional)

## Limitations

- Single admin user only
- No user management
- No media upload
- No search functionality
- No comments system
- Basic text formatting only

## License

This is a personal experimental project. No license provided. Use at your own risk.

---