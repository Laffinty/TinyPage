"""Server startup with dual-service architecture."""

from __future__ import annotations

import logging
import os
import sys
import threading
from pathlib import Path

# Ensure UTF-8 output on Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

from .config import Config
from .content import list_articles
from .frontend import StaticApp
from .generator import generate_static_pages
from .admin import AdminApp

logger = logging.getLogger(__name__)


def ensure_admin_password(cfg: Config) -> str:
    """Generate random admin password if not set."""
    password = cfg.admin_pass
    if password:
        return password
    import secrets
    base = secrets.token_urlsafe(24)
    suffix = secrets.choice(["#", "+", "%"])
    password = base[:31] + suffix
    password_file = Path(__file__).resolve().parent.parent / "admin_password.txt"
    try:
        with open(password_file, "w", encoding="utf-8") as f:
            f.write(f"ADMIN_PASS={password}\n")
            f.write(f"Generated at: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("\n" + "=" * 70 + "\n")
            f.write("⚠️  阅后即焚 - 请立即复制此密码并删除本文件 ⚠️\n")
            f.write("=" * 70 + "\n")
        print(f"\n{'='*70}")
        print("⚠️  警告：ADMIN_PASS 未设置！")
        print(f"随机密码已生成并保存到: {password_file}")
        print("请立即查看该文件并删除！")
        print(f"{'='*70}\n")
        logger.warning(f"[INIT] Random password saved to {password_file}")
    except Exception as e:
        logger.error(f"[INIT-FAILED] {e}")
    return password


def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler("security_audit.log"),
            logging.StreamHandler(),
        ],
    )


def run_static_server(cfg: Config) -> None:
    from waitress import serve
    app = StaticApp(cfg)
    logger.info(f"[START] Static server: http://{cfg.static_host}:{cfg.static_port}")
    serve(app, host=cfg.static_host, port=cfg.static_port, threads=4, channel_timeout=30)


def run_admin_server(cfg: Config) -> None:
    from waitress import serve
    app = AdminApp(cfg)
    host = "127.0.0.1"
    logger.info(f"[START] Admin server: http://{host}:{cfg.admin_port}")
    logger.info(f"[AUTH] User: {cfg.admin_user}")
    logger.info(f"[AUTH] Password: {'*' * min(len(cfg.admin_pass or ''), 16)} chars")
    serve(app, host=host, port=cfg.admin_port, threads=2, channel_timeout=30)


def main() -> None:
    setup_logging()
    cfg = Config.from_env()

    # Ensure directories exist
    cfg.article_dir.mkdir(parents=True, exist_ok=True)
    cfg.list_dir.mkdir(parents=True, exist_ok=True)

    # Ensure admin password
    password = ensure_admin_password(cfg)
    cfg = cfg.merge(admin_pass=password)

    # Generate initial pages
    index_path = cfg.root_dir / "index.html"
    if not index_path.exists():
        logger.info("[INIT] First run, generating static pages...")
        arts = list_articles(cfg.article_dir, cfg.max_file_size)
        generate_static_pages(arts, cfg)

    # Print startup banner
    print("\n" + "=" * 70)
    print(f"Site Title: {cfg.site_title}")
    print(f"Data Directory: {cfg.root_dir}")
    print(f"Static Server: http://{cfg.static_host}:{cfg.static_port}")
    print(f"Admin Server: http://127.0.0.1:{cfg.admin_port}")
    print(f"Admin User: {cfg.admin_user}")
    print(f"HTTPS: Reverse Proxy Recommended")
    if cfg.bind_domain:
        print(f"Domain Bind: {cfg.bind_domain}")
    else:
        print("Domain Bind: Not set")
    print(f"\nNginx Tips:")
    print("   proxy_set_header X-Real-IP $remote_addr;")
    print("   proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
    print("   proxy_set_header Host $http_host;")
    pw_len = len(cfg.admin_pass or "")
    if pw_len < 16:
        print(f"⚠️  WARNING: Password too short ({pw_len} chars)")
    else:
        print(f"Password: {'*' * 16}... (length: {pw_len})")
    print(f"Audit Log: security_audit.log")
    print("=" * 70 + "\n")

    # Start servers
    logger.info("[START] Starting servers...")
    t1 = threading.Thread(target=run_static_server, args=(cfg,), daemon=True)
    t2 = threading.Thread(target=run_admin_server, args=(cfg,), daemon=True)
    t1.start()
    t2.start()

    try:
        t1.join()
        t2.join()
    except KeyboardInterrupt:
        logger.info("[SHUTDOWN] Graceful shutdown initiated...")


if __name__ == "__main__":
    main()
