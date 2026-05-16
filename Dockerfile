# TinyPage Docker Image
FROM python:3.12-slim

LABEL maintainer="Laffinty"
LABEL description="Zero-dependency static site generator for docs and digital gardens"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    STATIC_HOST=0.0.0.0 \
    STATIC_PORT=8080 \
    ADMIN_PORT=8081

WORKDIR /app

# Dependency install (leveraging Docker layer cache)
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .[full]

# Copy only necessary application code (.dockerignore excludes sensitive files)
COPY tinypage/ tinypage/
COPY static_inject/ static_inject/
COPY themes/ themes/
COPY tiny_page.py .

RUN mkdir -p pages/article pages/list pages/standalone pages/static

EXPOSE 8080 8081

VOLUME ["/app/pages", "/app/themes"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080')" || exit 1

ENTRYPOINT ["tinypage"]
CMD ["serve", "-h", "0.0.0.0"]
