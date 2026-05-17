"""Admin POST action handlers — process forms and API calls."""

from __future__ import annotations

import base64
import json
import logging
import re
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any
from wsgiref.types import StartResponse

from ..config import Config
from ..content import (
    list_articles,
    write_article,
    delete_article,
    list_standalones,
    write_standalone,
    delete_standalone,
    translate_article,
)
from ..generator import generate_static_pages
from ..security import (
    get_real_ip,
    validate_filename,
    validate_csrf_token,
    slugify,
)
from .responses import redirect_response, error_response, json_error_response, html_response

logger = logging.getLogger(__name__)


def create_article(environ: dict, cfg: Config, post_data: dict) -> list[bytes]:
    title = post_data.get("title", [""])[0]
    date = post_data.get("date", [""])[0]
    content = post_data.get("content", [""])[0]
    tags = post_data.get("tags", [""])[0]
    category = post_data.get("category", [""])[0]
    status = post_data.get("status", ["published"])[0]
    if status not in ("published", "draft"):
        status = "published"
    client_ip = get_real_ip(environ)

    if not all([title, date, content]):
        return error_response(start_response, "400 Bad Request", "Missing fields")

    s = slugify(title)
    fname = f"{date[:10]}-{s}.html"
    if (cfg.article_dir / fname).exists():
        fname = f"{date[:10]}-{s}-{secrets.token_urlsafe(4)}.html"

    write_article(
        cfg.article_dir, fname, title, date, s, content, tags, "", category, status,
        skip_html_generation=True,
    )
    arts = list_articles(cfg.article_dir, cfg.max_file_size)
    standalones = list_standalones(cfg.standalone_dir, cfg.max_file_size)
    generate_static_pages(arts, cfg, standalones)
    logger.info(f"[CREATE] {fname} from {client_ip}")
    return redirect_response(start_response, "/")


def save_article(environ: dict, cfg: Config, post_data: dict) -> list[bytes]:
    fname = post_data.get("file", [""])[0]
    title = post_data.get("title", [""])[0]
    date = post_data.get("date", [""])[0]
    content = post_data.get("content", [""])[0]
    tags = post_data.get("tags", [""])[0]
    category = post_data.get("category", [""])[0]
    status = post_data.get("status", ["published"])[0]
    if status not in ("published", "draft"):
        status = "published"
    client_ip = get_real_ip(environ)

    if not all([fname, title, date, content]):
        return error_response(start_response, "400 Bad Request", "Missing fields")
    if not validate_filename(fname):
        return error_response(start_response, "400 Bad Request", "Invalid filename")

    s = slugify(title)
    write_article(
        cfg.article_dir, fname, title, date, s, content, tags, "", category, status,
        skip_html_generation=True,
    )
    arts = list_articles(cfg.article_dir, cfg.max_file_size)
    standalones = list_standalones(cfg.standalone_dir, cfg.max_file_size)
    generate_static_pages(arts, cfg, standalones)
    logger.info(f"[SAVE] {fname} from {client_ip}")
    return redirect_response(start_response, "/")


def delete_article_action(environ: dict, cfg: Config, post_data: dict) -> list[bytes]:
    fname = post_data.get("file", [""])[0]
    client_ip = get_real_ip(environ)
    if not validate_filename(fname):
        return error_response(start_response, "400 Bad Request", "Invalid filename")
    path = cfg.article_dir / fname
    if path.is_file():
        delete_article(path)
        arts = list_articles(cfg.article_dir, cfg.max_file_size)
        standalones = list_standalones(cfg.standalone_dir, cfg.max_file_size)
        generate_static_pages(arts, cfg, standalones)
        logger.info(f"[DELETE] {fname} from {client_ip}")

    is_htmx = environ.get("HTTP_HX_REQUEST", "") == "true"
    if is_htmx:
        from ..security import get_security_headers
        start_response("200 OK", get_security_headers())
        return [b""]
    return redirect_response(start_response, "/")


def create_page(environ: dict, cfg: Config, post_data: dict) -> list[bytes]:
    from ..content import validate_page_filename

    title = post_data.get("title", [""])[0]
    slug = post_data.get("slug", [""])[0]
    content = post_data.get("content", [""])[0]
    client_ip = get_real_ip(environ)

    if not all([title, slug, content]):
        return error_response(start_response, "400 Bad Request", "Missing fields")

    fname = f"{slug}.html"
    if not validate_page_filename(fname):
        return error_response(start_response, "400 Bad Request", "Invalid slug")
    if (cfg.standalone_dir / fname).exists():
        return error_response(start_response, "409 Conflict", "Page already exists")

    cfg.standalone_dir.mkdir(parents=True, exist_ok=True)
    write_standalone(cfg.standalone_dir, fname, title, content)
    arts = list_articles(cfg.article_dir, cfg.max_file_size)
    standalones = list_standalones(cfg.standalone_dir, cfg.max_file_size)
    generate_static_pages(arts, cfg, standalones)
    logger.info(f"[CREATE-PAGE] {fname} from {client_ip}")
    return redirect_response(start_response, "/pages")


def save_page(environ: dict, cfg: Config, post_data: dict) -> list[bytes]:
    from ..content import validate_page_filename

    fname = post_data.get("file", [""])[0]
    title = post_data.get("title", [""])[0]
    slug = post_data.get("slug", [""])[0]
    content = post_data.get("content", [""])[0]
    client_ip = get_real_ip(environ)

    if not all([fname, title, slug, content]):
        return error_response(start_response, "400 Bad Request", "Missing fields")
    if not validate_page_filename(fname):
        return error_response(start_response, "400 Bad Request", "Invalid filename")

    new_fname = f"{slug}.html"
    if new_fname != fname:
        old_path = cfg.standalone_dir / fname
        if old_path.is_file():
            delete_standalone(old_path)

    write_standalone(cfg.standalone_dir, new_fname, title, content)
    arts = list_articles(cfg.article_dir, cfg.max_file_size)
    standalones = list_standalones(cfg.standalone_dir, cfg.max_file_size)
    generate_static_pages(arts, cfg, standalones)
    logger.info(f"[SAVE-PAGE] {new_fname} from {client_ip}")
    return redirect_response(start_response, "/pages")


def delete_page_action(environ: dict, cfg: Config, post_data: dict) -> list[bytes]:
    from ..content import validate_page_filename

    fname = post_data.get("file", [""])[0]
    client_ip = get_real_ip(environ)
    if not validate_page_filename(fname):
        return error_response(start_response, "400 Bad Request", "Invalid filename")
    path = cfg.standalone_dir / fname
    if path.is_file():
        delete_standalone(path)
        arts = list_articles(cfg.article_dir, cfg.max_file_size)
        standalones = list_standalones(cfg.standalone_dir, cfg.max_file_size)
        generate_static_pages(arts, cfg, standalones)
        logger.info(f"[DELETE-PAGE] {fname} from {client_ip}")

    is_htmx = environ.get("HTTP_HX_REQUEST", "") == "true"
    if is_htmx:
        from ..security import get_security_headers
        start_response("200 OK", get_security_headers())
        return [b""]
    return redirect_response(start_response, "/pages")


def upload_image(environ: dict, cfg: Config, post_data: dict) -> list[bytes]:
    client_ip = get_real_ip(environ)
    filename = post_data.get("filename", [""])[0]
    data_b64 = post_data.get("data", [""])[0]
    csrf_token = post_data.get("csrf_token", [""])[0]

    if not filename or not data_b64:
        return json_error_response(start_response, "400 Bad Request", "Missing filename or data")

    filename = re.sub(r"[^a-zA-Z0-9._-]", "_", filename)
    if not filename or ".." in filename:
        return json_error_response(start_response, "400 Bad Request", "Invalid filename")

    ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp"}
    ext = Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return json_error_response(start_response, "400 Bad Request", f"File type not allowed: {ext}")

    now = datetime.now()
    subdir = cfg.static_dir / "images" / f"{now.year:04d}-{now.month:02d}"
    subdir.mkdir(parents=True, exist_ok=True)

    if "," in data_b64:
        data_b64 = data_b64.split(",", 1)[1]

    try:
        raw_data = base64.b64decode(data_b64)
    except Exception:
        return json_error_response(start_response, "400 Bad Request", "Invalid base64 data")

    if len(raw_data) > 10 * 1024 * 1024:
        return json_error_response(start_response, "400 Bad Request", "File too large (max 10MB)")

    MAGIC_BYTES = {
        b"\x89PNG\r\n\x1a\n": ".png",
        b"\xff\xd8\xff": ".jpg",
        b"GIF87a": ".gif",
        b"GIF89a": ".gif",
        b"RIFF": ".webp",
    }
    is_valid = False
    for magic, expected_ext in MAGIC_BYTES.items():
        if raw_data[:len(magic)] == magic:
            if ext == expected_ext:
                is_valid = True
                break
            if expected_ext == ".webp" and ext == ".webp" and len(raw_data) >= 12:
                if raw_data[8:12] == b"WEBP":
                    is_valid = True
                    break

    if not is_valid:
        return json_error_response(start_response, "400 Bad Request", "Invalid image format")

    target = subdir / filename
    if target.exists():
        stem = target.stem
        suffix = target.suffix
        counter = 1
        while target.exists():
            target = subdir / f"{stem}-{counter}{suffix}"
            counter += 1

    target.write_bytes(raw_data)
    rel_path = f"/static/images/{now.year:04d}-{now.month:02d}/{target.name}"
    logger.info(f"[UPLOAD] {rel_path} from {client_ip}")

    headers = [("Content-Type", "application/json")]
    from ..security import get_security_headers
    headers += get_security_headers()
    start_response("200 OK", headers)
    return [json.dumps({"success": True, "url": rel_path}).encode("utf-8")]


def regenerate(environ: dict, cfg: Config) -> list[bytes]:
    client_ip = get_real_ip(environ)
    arts = list_articles(cfg.article_dir, cfg.max_file_size)
    standalones = list_standalones(cfg.standalone_dir, cfg.max_file_size)
    generate_static_pages(arts, cfg, standalones)
    logger.info(f"[REGEN] from {client_ip}")

    is_htmx = environ.get("HTTP_HX_REQUEST", "") == "true"
    if is_htmx:
        headers = [("Content-Type", "text/html; charset=utf-8")]
        from ..security import get_security_headers
        headers += get_security_headers()
        start_response("200 OK", headers)
        return ['<span style="color:var(--a-primary);font-size:0.9rem;">✓ 已重新生成</span>'.encode("utf-8")]
    return redirect_response(start_response, "/")


def live_preview(environ: dict, cfg: Config, post_data: dict) -> list[bytes]:
    from ..parsers import render_markdown
    from ..security import get_security_headers

    content = post_data.get("content", [""])[0]
    html = render_markdown(content) if content else '<p class="preview-placeholder">（无内容）</p>'
    headers = [("Content-Type", "text/html; charset=utf-8")] + get_security_headers()
    start_response("200 OK", headers)
    return [html.encode("utf-8")]


def ai_assist(environ: dict, cfg: Config, post_data: dict) -> list[bytes]:
    from ..core.ai_assistance import build_ai_assistance, AIAssistanceError

    action = post_data.get("action", [""])[0]
    text = post_data.get("text", [""])[0]

    ai = build_ai_assistance(cfg)
    if not ai:
        result = {"error": "AI 未启用或未配置 API Key"}
    else:
        try:
            if action == "complete":
                result = {"result": ai.complete_text(text)}
            elif action == "polish":
                result = {"result": ai.polish_text(text)}
            elif action == "translate":
                lang = post_data.get("lang", ["English"])[0]
                lang_map = {"en": "English", "ja": "Japanese"}
                target = lang_map.get(lang, "English")
                result = {"result": ai.translate_text(text, target)}
            elif action == "suggest_tags":
                result = {"result": ai.suggest_tags(text)}
            elif action == "summarize":
                result = {"result": ai.summarize(text)}
            else:
                result = {"error": f"未知操作: {action}"}
        except AIAssistanceError as e:
            result = {"error": str(e)}

    headers = [("Content-Type", "application/json")]
    from ..security import get_security_headers
    headers += get_security_headers()
    start_response("200 OK", headers)
    return [json.dumps(result).encode("utf-8")]


def translate_article_action(environ: dict, cfg: Config, post_data: dict) -> list[bytes]:
    fname = post_data.get("file", [""])[0]
    target_lang = post_data.get("lang", ["en"])[0]
    client_ip = get_real_ip(environ)

    if not validate_filename(fname):
        return error_response(start_response, "400 Bad Request", "Invalid filename")

    result = translate_article(cfg.article_dir, fname, target_lang, cfg)
    if result.get("success"):
        logger.info(f"[TRANSLATE] {fname} -> {target_lang} from {client_ip}")
        return redirect_response(start_response, "/")
    else:
        return error_response(start_response, "400 Bad Request", result.get("error", "翻译失败"))


def set_theme(environ: dict, cfg: Config, post_data: dict) -> list[bytes]:
    theme_name = post_data.get("theme", [""])[0]
    if not theme_name:
        return error_response(start_response, "400 Bad Request", "Missing theme name")

    manifest_path = Path("themes") / theme_name / "manifest.json"
    if not manifest_path.is_file():
        return error_response(start_response, "400 Bad Request", "Theme not found")

    cfg = cfg.merge(theme_name=theme_name)
    _save_theme_config(theme_name)

    arts = list_articles(cfg.article_dir, cfg.max_file_size)
    standalones = list_standalones(cfg.standalone_dir, cfg.max_file_size)
    generate_static_pages(arts, cfg, standalones)
    logger.info(f"[THEME] Switched to: {theme_name}")
    return redirect_response(start_response, "/theme")


def _save_theme_config(theme_name: str) -> None:
    config_dir = Path(".") / ".tinypage"
    config_dir.mkdir(parents=True, exist_ok=True)
    config_file = config_dir / "config.json"
    try:
        if config_file.exists():
            config_data = json.loads(config_file.read_text(encoding="utf-8"))
        else:
            config_data = {}
        config_data["theme_name"] = theme_name
        config_file.write_text(json.dumps(config_data, ensure_ascii=False, indent=2), encoding="utf-8")
    except (OSError, json.JSONDecodeError) as e:
        logger.warning(f"[THEME] Failed to persist config: {e}")


def login_handler(environ: dict, start_response: StartResponse, cfg: Config, post_data: dict, session_manager, auth_tracker) -> list[bytes]:
    from ..security import validate_csrf_token

    csrf_token = post_data.get("csrf_token", [""])[0]
    client_ip = get_real_ip(environ)

    if not validate_csrf_token(environ, csrf_token, cfg.admin_port, cfg.bind_domain):
        return redirect_response(start_response, "/login?error=1")

    if auth_tracker.is_locked_out(client_ip):
        return redirect_response(start_response, "/login?locked=1")

    username = post_data.get("username", [""])[0]
    password = post_data.get("password", [""])[0]

    if not secrets.compare_digest(username, cfg.admin_user) or not secrets.compare_digest(password, cfg.admin_pass):
        auth_tracker.record_failure(client_ip)
        failures = len(auth_tracker._failures.get(client_ip, []))
        logger.warning(f"[AUTH-FAIL] Login from {client_ip} (attempt {failures}/{auth_tracker.max_failures})")
        return redirect_response(start_response, "/login?error=1")

    session_token = session_manager.create_session(client_ip)
    is_secure = bool(cfg.bind_domain)
    from ..security import get_session_cookie_header
    session_cookie = get_session_cookie_header(session_token, secure=is_secure)
    logger.info(f"[LOGIN] Successful login from {client_ip}")
    headers = [("Location", "/"), session_cookie]
    from ..security import get_security_headers
    headers += get_security_headers()
    start_response("302 Found", headers)
    return [b""]


def logout_handler(environ: dict, start_response: StartResponse, cfg: Config, post_data: dict, session_manager) -> list[bytes]:
    session_token = session_manager.get_session_from_environ(environ)
    if session_token:
        session_manager.destroy_session(session_token)
    is_secure = bool(cfg.bind_domain)
    from ..security import get_session_clear_cookie_header
    clear_cookie = get_session_clear_cookie_header(secure=is_secure)
    headers = [("Location", "/login"), clear_cookie]
    from ..security import get_security_headers
    headers += get_security_headers()
    start_response("302 Found", headers)
    return [b""]
