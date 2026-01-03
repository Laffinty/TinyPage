#!/usr/bin/env python3

# 标准库导入 - 按字母顺序排列
import base64
import datetime
import hashlib
import hmac
import html
import io
import json
import logging
import os
import re
import secrets
import shutil
import string
import threading
import time
from urllib.parse import parse_qs, quote, urlparse
from wsgiref.headers import Headers

# 第三方库导入
try:
    from waitress import serve
    WAITRESS_AVAILABLE = True
except ImportError:
    print("[ERROR] Waitress not installed. Run: pip install waitress")
    WAITRESS_AVAILABLE = False
    exit(1)

# Check for Waitress
try:
    from waitress import serve
    WAITRESS_AVAILABLE = True
except ImportError:
    print("[ERROR] Waitress not installed. Run: pip install waitress")
    WAITRESS_AVAILABLE = False
    exit(1)

# ====== 全局配置 ======
# 网站配置
SITE_TITLE = "TinyPage"  # 网站标题
FOOTER_TEXT = "Powered by TinyPage"  # 版底文字

# 安全配置
ADMIN_USER = os.getenv('ADMIN_USER', 'admin')
ADMIN_PASS = os.getenv('ADMIN_PASS')

# 服务器配置
STATIC_PORT = int(os.getenv('STATIC_PORT', '8080'))  # 前台端口，默认8080
ADMIN_PORT = int(os.getenv('ADMIN_PORT', '8081'))  # 后台端口，默认8081
STATIC_HOST = os.getenv('STATIC_HOST', '127.0.0.1')  # 绑定IP，默认127.0.0.1



# 域名绑定（如果使用Nginx反向代理，请设置为你的域名，例如：example.com）
BIND_DOMAIN = os.getenv('BIND_DOMAIN', '')  # 绑定域名，留空则不绑定

# 分页配置
PAGE_SIZE = 10  # 每页文章数

# 路径配置
ROOT_DIR = os.path.abspath("pages")
ARTICLE_DIR = os.path.join(ROOT_DIR, "article")
LIST_DIR = os.path.join(ROOT_DIR, "list")

# 文件限制
MAX_FILE_SIZE = 10 * 1024 * 1024
MAX_TITLE_LENGTH = 200
MAX_CONTENT_LENGTH = 50000
SAFE_FILENAME_PATTERN = re.compile(r'^\d{4}-\d{2}-\d{2}-[a-zA-Z0-9\u4e00-\u9fa5-]+\.html$')
LOG_FILE = 'security_audit.log'

# CSRF保护密钥 (内存中)
_CSRF_SECRET = secrets.token_bytes(32)

# 安全的URL协议白名单
SAFE_URL_PROTOCOLS = {
    'http', 'https', 'ftp', 'ftps',
    'mailto', 'tel', 'sip', 'sips',
    'news', 'nntp', 'telnet', 'irc',
    'ircs', 'gopher', 'wais'
}

# 危险的URL协议黑名单
DANGEROUS_PROTOCOLS = {
    'javascript', 'data', 'vbscript',
    'file', 'about', 'chrome', 'chrome-extension',
    'ms-help', 'ms-windows-store', 'ms-settings',
    'jar', 'rmi', 'jndi', 'ldap', 'dns'
}

# ========================

# 日志配置
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# 密码管理
class TinyPageException(Exception):
    """TinyPage基础异常类"""
    pass

class ValidationException(TinyPageException):
    """验证异常"""
    pass

class SecurityException(TinyPageException):
    """安全异常"""
    pass

def initialize_admin_password():
    """初始化管理员密码,仅在未设置时生成随机密码并保存到文件"""
    global ADMIN_PASS
    if not ADMIN_PASS:
        # 生成32位随机密码，并确保以 # + % 或 # 结尾
        # 使用 secrets.token_urlsafe 生成更安全的随机密码
        base_password = secrets.token_urlsafe(24)  # 生成约32个字符
        suffix = secrets.choice(['#', '+', '%'])
        ADMIN_PASS = base_password[:31] + suffix
        
        # 保存到文件
        password_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'admin_password.txt')
        try:
            with open(password_file, 'w', encoding='utf-8') as f:
                f.write(f"ADMIN_PASS={ADMIN_PASS}\n")
                f.write(f"Generated at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("\n" + "="*70 + "\n")
                f.write("⚠️  阅后即焚 - 请立即复制此密码并删除本文件 ⚠️\n")
                f.write("="*70 + "\n")
            
            print(f"\n{'='*70}")
            print("⚠️  警告：ADMIN_PASS 未设置！")
            print(f"随机密码已生成并保存到: {password_file}")
            print("请立即查看该文件并删除！")
            print(f"{'='*70}\n")
            logger.warning(f"[INIT] ADMIN_PASS not set, random password generated and saved to file")
        except Exception as e:
            logger.error(f"[INIT-FAILED] Failed to save password to file: {e}")
            # 如果文件写入失败，作为备用方案记录到日志（但仍然不直接打印密码）
            logger.warning(f"[INIT] Random password generated but could not save to file")
    return ADMIN_PASS

ADMIN_PASS = initialize_admin_password()

# 创建目录
os.makedirs(ARTICLE_DIR, exist_ok=True)
os.makedirs(LIST_DIR, exist_ok=True)

# ---------- 安全工具函数 ----------

def validate_url_protocol(url):
    """
    验证URL协议是否安全,用于过滤Markdown链接
    
    Returns:
        bool: True if safe, False if dangerous
    """
    if not url or not isinstance(url, str):
        return False
    
    url_lower = url.lower().strip()
    if not url_lower:
        return False
    
    # 协议相对URL是安全的
    if url_lower.startswith('//'):
        return True
    
    # 没有冒号 - 相对路径是安全的
    colon_pos = url_lower.find(':')
    if colon_pos == -1:
        return True
    
    # 提取协议
    protocol = url_lower[:colon_pos].strip()
    
    # 检查是否在黑名单
    if protocol in DANGEROUS_PROTOCOLS:
        logger.warning(f"[XSS-BLOCK] Dangerous protocol in URL: {url}")
        return False
    
    # 检查是否在白名单
    if protocol in SAFE_URL_PROTOCOLS:
        return True
    
    # 默认拒绝未知协议
    logger.warning(f"[XSS-BLOCK] Unknown protocol in URL: {url}")
    return False

def safe_path_check(path, base_dir):
    """
    增强的路径检查,使用realpath解析符号链接防止路径遍历
    """
    try:
        base_path = os.path.abspath(os.path.realpath(base_dir))
        
        # 规范化请求路径
        if path.startswith('/'):
            path = path[1:]
        
        # 构建完整路径并解析符号链接
        full_path = os.path.abspath(os.path.join(base_dir, path))
        real_path = os.path.realpath(full_path)
        
        # 检查是否在base_dir范围内
        if not real_path.startswith(base_path):
            logger.warning(f"[BLOCK] Path traversal attempt: {path} -> {real_path}")
            return False, None
        
        # 检查文件扩展名
        if not real_path.endswith('.html'):
            if os.path.isfile(real_path):
                logger.warning(f"[BLOCK] Non-HTML file access: {path}")
                return False, None
        
        return True, real_path
    except Exception as e:
        logger.error(f"[ERROR] Path check failed: {e}")
        return False, None

def validate_filename(filename):
    """验证文件名格式"""
    if not SAFE_FILENAME_PATTERN.match(filename):
        logger.warning(f"[BLOCK] Invalid filename format: {filename}")
        return False
    
    # 额外验证日期部分
    try:
        parts = filename.split('-')
        if len(parts) < 4:
            return False
        
        year = int(parts[0])
        month = int(parts[1])
        day = int(parts[2])
        
        if not (2000 <= year <= 2100 and 1 <= month <= 12 and 1 <= day <= 31):
            return False
            
    except (ValueError, IndexError):
        return False
    
    return True

def validate_date_format(date_str):
    """验证日期格式 YYYY-MM-DD HH:MM"""
    try:
        if not re.match(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$', date_str):
            return False
        
        # 尝试解析日期
        dt = datetime.datetime.strptime(date_str, "%Y-%m-%d %H:%M")
        
        # 合理的日期范围
        if not (2000 <= dt.year <= 2100):
            return False
        
        return True
    except ValueError:
        return False

def escape_html(text):
    """HTML转义"""
    return html.escape(text, quote=True)

def escape_attr(text):
    """HTML属性转义"""
    return html.escape(text, quote=True).replace('"', '&quot;')

# ---------- CSRF保护函数 ----------

def generate_csrf_token():
    """生成安全的CSRF token"""
    random_bytes = secrets.token_bytes(16)
    timestamp = int(time.time()).to_bytes(4, 'big')
    token_data = random_bytes + timestamp
    signature = hmac.new(_CSRF_SECRET, token_data, hashlib.sha256).digest()
    signed_token = token_data + signature
    return base64.urlsafe_b64encode(signed_token).decode('ascii')

def validate_csrf_token_improved(environ, token):
    """改进的CSRF token验证（增强安全性）"""
    client_ip = get_real_ip(environ)
    
    if not token or not isinstance(token, str) or len(token) < 32:
        logger.warning(f"[CSRF-FAIL] Invalid token format from {client_ip}")
        return False
    
    try:
        signed_token = base64.urlsafe_b64decode(token.encode('ascii'))
        
        if len(signed_token) != 52:  # 16 + 4 + 32
            logger.warning(f"[CSRF-FAIL] Invalid token length from {client_ip}")
            return False
        
        token_data = signed_token[:20]
        signature = signed_token[20:]
        
        expected_sig = hmac.new(_CSRF_SECRET, token_data, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected_sig):
            logger.warning(f"[CSRF-FAIL] Invalid signature from {client_ip}")
            return False
        
        # 检查时间戳 (1小时有效期)
        timestamp = int.from_bytes(token_data[16:20], 'big')
        current_time = time.time()
        if current_time - timestamp > 3600:
            logger.warning(f"[CSRF-FAIL] Token expired from {client_ip}")
            return False
        
        # 防止未来时间戳
        if timestamp > current_time + 60:
            logger.warning(f"[CSRF-FAIL] Token timestamp in future from {client_ip}")
            return False
        
        # 检查cookie token (双重提交Cookie模式)
        cookie_header = environ.get('HTTP_COOKIE', '')
        cookie_token = None
        
        for cookie in cookie_header.split(';'):
            cookie = cookie.strip()
            if cookie.startswith('csrf_token='):
                cookie_token = cookie[11:]
                break
        
        if not cookie_token:
            logger.warning(f"[CSRF-FAIL] No CSRF cookie from {client_ip}")
            return False
        
        # 常数时间比较，防止时序攻击
        if not hmac.compare_digest(token, cookie_token):
            logger.warning(f"[CSRF-FAIL] Token mismatch from {client_ip}")
            return False
        
        # 检查Origin/Referer头（额外的安全防护）
        origin = environ.get('HTTP_ORIGIN', '')
        referer = environ.get('HTTP_REFERER', '')
        
        # 如果提供了Origin/Referer，验证它们
        if origin or referer:
            # 支持本地和Nginx反向代理两种情况
            expected_hosts = [
                f"http://127.0.0.1:{ADMIN_PORT}",
                f"http://localhost:{ADMIN_PORT}",
            ]
            
            # 如果设置了域名绑定，也允许该域名
            if BIND_DOMAIN:
                expected_hosts.extend([
                    f"http://{BIND_DOMAIN}",
                    f"https://{BIND_DOMAIN}"
                ])
            
            # 检查Origin
            if origin:
                if not any(origin.startswith(host) for host in expected_hosts):
                    # 允许origin为null的情况（某些浏览器或插件导致）
                    if origin.lower() != 'null':
                        logger.warning(f"[CSRF-FAIL] Invalid Origin: {origin} from {client_ip}")
                        return False
            
            # 检查Referer
            if referer:
                if not any(referer.startswith(host) for host in expected_hosts):
                    logger.warning(f"[CSRF-FAIL] Invalid Referer: {referer} from {client_ip}")
                    return False
        
        return True
    except Exception as e:
        logger.error(f"[CSRF-ERROR] Validation failed from {client_ip}: {e}")
        return False

# 保持向后兼容
validate_csrf_token = validate_csrf_token_improved

def get_csrf_cookie_header(token=None):
    """生成CSRF cookie头"""
    if token is None:
        token = generate_csrf_token()
    return ('Set-Cookie', f'csrf_token={token}; Path=/; HttpOnly; SameSite=Strict')

def get_real_ip(environ):
    """获取真实客户端IP（支持反向代理）"""
    # 优先检查X-Forwarded-For头
    x_forwarded_for = environ.get('HTTP_X_FORWARDED_FOR', '')
    if x_forwarded_for:
        # 取第一个IP（真实客户端IP）
        return x_forwarded_for.split(',')[0].strip()
    
    # 检查X-Real-IP头
    x_real_ip = environ.get('HTTP_X_REAL_IP', '')
    if x_real_ip:
        return x_real_ip.strip()
    
    # 回退到REMOTE_ADDR
    return environ.get('REMOTE_ADDR', 'unknown')

# ---------- 内容处理函数 ----------

def slugify_title(title):
    """将标题转换为slug"""
    s = re.sub(r"[^a-zA-Z0-9]", "-", title.lower())
    s = re.sub(r"-+", "-", s).strip("-")
    if not s:
        return str(int(time.time()))
    return s[:80]

def text_to_html(content):
    """
    转换纯文本到HTML,带安全的URL协议过滤
    """
    content = escape_html(content)
    paragraphs = re.split(r'\n\s*\n', content.strip())
    
    html_paragraphs = []
    for para in paragraphs:
        if not para.strip():
            continue
        
        # 处理内联格式
        para = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', para)
        para = re.sub(r'\*(.+?)\*', r'<em>\1</em>', para)
        para = re.sub(r'`(.+?)`', r'<code>\1</code>', para)
        
        # 处理链接(带URL验证)
        def replace_link(match):
            text = match.group(1)
            url = match.group(2)
            if validate_url_protocol(url):
                return f'<a href="{escape_attr(url)}" rel="noopener noreferrer">{text}</a>'
            else:
                # 不安全链接显示为纯文本
                return f'[{text}]({url})'
        
        para = re.sub(r'\[([^\]]+)\]\(([^\)]+)\)', replace_link, para)
        
        # 处理换行
        lines = para.strip().split('\n')
        html_lines = '<br>\n'.join(lines)
        html_paragraphs.append(f'<p>{html_lines}</p>')
    
    return '\n'.join(html_paragraphs)

def parse_meta_safe(path):
    """安全解析文章元数据"""
    try:
        if os.path.getsize(path) > MAX_FILE_SIZE:
            return None
        
        meta = {}
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            for i, line in enumerate(f):
                if i >= 5:
                    break
                m = re.match(r"<!--\s*(\w+):\s*(.*)\s*-->", line.strip())
                if m:
                    meta[m.group(1)] = m.group(2).strip()
        
        # 生成摘要（从正文提取前200字）
        if "summary" not in meta or not meta["summary"]:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for _ in range(5):
                    next(f, None)
                html_content = f.read()
                
                # 提取正文内容（在post-content div内）
                content_match = re.search(r'<div class="post-content">(.*?)</div>', html_content, re.DOTALL)
                if content_match:
                    content_text = content_match.group(1)
                else:
                    content_text = html_content
                
                # 移除HTML标签
                text = re.sub(r'<[^>]+>', '', content_text)
                text = re.sub(r'\s+', ' ', text).strip()
                
                # 取前200字
                if len(text) > 200:
                    meta["summary"] = text[:200] + "..."
                else:
                    meta["summary"] = text
        
        return meta
    except Exception as e:
        logger.error(f"[ERROR] Parse meta {path}: {e}")
        return None

def list_articles_safe():
    """安全列出所有文章"""
    try:
        files = [f for f in os.listdir(ARTICLE_DIR) if f.endswith('.html')]
        arts = []
        for fn in files:
            if not validate_filename(fn):
                continue
            
            path = os.path.join(ARTICLE_DIR, fn)
            if os.path.getsize(path) > MAX_FILE_SIZE:
                continue
            
            meta = parse_meta_safe(path)
            if not meta:
                continue
            
            try:
                meta["file"] = fn
                meta["date_obj"] = datetime.datetime.strptime(meta.get("date", "")[:16], "%Y-%m-%d %H:%M")
                arts.append(meta)
            except:
                continue
        
        arts.sort(key=lambda x: x["date_obj"], reverse=True)
        return arts
    except Exception as e:
        logger.error(f"[ERROR] List articles: {e}")
        return []



def validate_content_strict(content):
    """严格的内容验证"""
    if not isinstance(content, str):
        return False
    
    # 检查长度
    if len(content) > MAX_CONTENT_LENGTH:
        return False
    
    # 检查 Unicode 攻击 (检查UTF-8编码后的长度)
    if len(content.encode('utf-8')) > MAX_CONTENT_LENGTH * 4:
        return False
    
    # 检查控制字符（过多可能表示攻击）
    control_chars = sum(1 for c in content if ord(c) < 32 and c not in '\t\n\r')
    if control_chars > len(content) * 0.1:  # 控制字符超过10%
        return False
    
    return True

def write_article_safe(fname, title, date, slug, content):
    """安全写入文章"""
    # 输入验证
    if not validate_filename(fname):
        raise ValidationException(f"Invalid filename: {fname}")
    
    if not isinstance(title, str) or len(title) > MAX_TITLE_LENGTH:
        raise ValidationException(f"Title too long or invalid: {len(title)}")
    
    if not isinstance(content, str) or not validate_content_strict(content):
        raise ValidationException(f"Content validation failed: length={len(content)}")
    
    if not validate_date_format(date):
        raise ValidationException(f"Invalid date format: {date}")
    
    # 路径验证
    path = os.path.join(ARTICLE_DIR, fname)
    is_safe, full_path = safe_path_check(path, ARTICLE_DIR)
    if not is_safe:
        raise SecurityException(f"Path validation failed: {path}")
    
    # 生成文章正文内容（应用完整样式）
    html_body = text_to_html(content)
    
    # 生成完整HTML页面
    main_content = f"""<article class="post">
  <header class="post-header">
    <h1 class="post-title">{escape_html(title)}</h1>
    <time class="post-date" datetime="{date}">{date}</time>
  </header>
  <div class="post-content">
{html_body}
  </div>
</article>"""
    
    full_html = generate_full_html(title, main_content)
    
    # 写入文件（增加临时文件和原子操作）
    temp_path = path + '.tmp'
    try:
        with open(temp_path, 'w', encoding='utf-8') as f:
            f.write(f"<!-- title: {escape_html(title)} -->\n")
            f.write(f"<!-- date: {escape_html(date)} -->\n")
            f.write(f"<!-- slug: {escape_html(slug)} -->\n")
            f.write(f"<!-- tags: -->\n")
            f.write(f"<!-- summary: -->\n")
            f.write(full_html)
        
        # 原子性重命名
        os.replace(temp_path, path)
        logger.info(f"[WRITE] Article: {fname}")
    except Exception as e:
        # 清理临时文件
        if os.path.exists(temp_path):
            os.remove(temp_path)
        logger.error(f"[WRITE-FAILED] Article: {fname}, error: {e}")
        raise

def generate_static_pages():
    """生成静态页面"""
    try:
        arts = list_articles_safe()
        total = len(arts)
        pages = (total + PAGE_SIZE - 1) // PAGE_SIZE
        
        logger.info(f"[GENERATE-START] Generating {pages} pages with {total} articles")
        
        def make_page(items, page_idx, pages):
            items_html = []
            for art in items:
                safe_title = escape_html(art['title'])
                safe_summary = escape_html(art['summary']).replace('<p>', '').replace('</p>', '')
                items_html.append(f"""
<article class="post-preview">
  <header>
    <h2 class="post-title"><a href="/article/{art['file']}">{safe_title}</a></h2>
    <time class="post-date" datetime="{art['date']}">{art['date']}</time>
  </header>
  <p class="post-summary">{safe_summary}</p>
  <a href="/article/{art['file']}" class="read-more">阅读全文 →</a>
</article>
""")
            
            # 导航
            nav_links = []
            if page_idx > 1:
                if page_idx == 2:
                    nav_links.append('<a href="/" class="prev">← 上一页</a>')
                else:
                    nav_links.append(f'<a href="/list/{page_idx-1}.html" class="prev">← 上一页</a>')
            
            page_numbers = []
            for p in range(1, pages + 1):
                if p == page_idx:
                    page_numbers.append(f'<span class="current">{p}</span>')
                elif p == 1:
                    page_numbers.append('<a href="/">1</a>')
                else:
                    page_numbers.append(f'<a href="/list/{p}.html">{p}</a>')
            
            if page_idx < pages:
                nav_links.append(f'<a href="/list/{page_idx+1}.html" class="next">下一页 →</a>')
            
            nav_html = f"""
<nav class="pagination">
  <div class="nav-links">{''.join(nav_links)}</div>
  <div class="page-numbers">{''.join(page_numbers)}</div>
</nav>"""
            
            return generate_full_html(
                f"第{page_idx}页" if page_idx > 1 else "首页",
                f"""
<main class="posts">
  <h1 class="page-title">文章列表</h1>
  {''.join(items_html)}
</main>
{nav_html}
"""
            )
        
        os.makedirs(LIST_DIR, exist_ok=True)
        
        # 生成首页
        items = arts[:PAGE_SIZE]
        with open(os.path.join(ROOT_DIR, "index.html"), 'w', encoding='utf-8') as f:
            f.write(make_page(items, 1, pages))
        
        # 生成分页
        for p in range(2, pages + 1):
            start = (p - 1) * PAGE_SIZE
            items = arts[start:start + PAGE_SIZE]
            with open(os.path.join(LIST_DIR, f"{p}.html"), 'w', encoding='utf-8') as f:
                f.write(make_page(items, p, pages))
        
        logger.info(f"[GENERATE-COMPLETE] {pages} pages generated successfully")
    except Exception as e:
        logger.error(f"[GENERATE-ERROR] {e}")

# 统一的安全头（全局常量）
SECURITY_HEADERS_BASE = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self';"
}

def get_security_headers():
    """获取标准安全头"""
    return [(k, v) for k, v in SECURITY_HEADERS_BASE.items()]

def generate_full_html(title, main_content):
    """生成完整HTML页面"""
    # FOOTER_TEXT 为空时不显示footer
    footer_html = f'<p>{escape_html(FOOTER_TEXT)}</p>' if FOOTER_TEXT and FOOTER_TEXT.strip() else ''
    
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="X-Content-Type-Options" content="nosniff">
<meta http-equiv="X-Frame-Options" content="DENY">
<meta http-equiv="X-XSS-Protection" content="1; mode=block">
<meta http-equiv="Referrer-Policy" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self';">
<title>{escape_html(title)} - {escape_html(SITE_TITLE)}</title>
<style>
:root {{ --primary: #2c3e50; --accent: #e74c3c; --text: #34495e; --light: #7f8c8d; --bg: #fff; --border: #ecf0f1; --code: #f8f9fa; }}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: var(--text); background: var(--bg); line-height: 1.6; font-size: 16px; }}
.container {{ max-width: 800px; margin: 0 auto; padding: 2rem 1.5rem; }}
header {{ border-bottom: 2px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 3rem; }}
.site-title {{ font-size: 2rem; font-weight: 700; color: var(--primary); text-decoration: none; }}
.site-title:hover {{ color: var(--accent); }}
main {{ min-height: calc(100vh - 300px); }}
.posts {{ display: flex; flex-direction: column; gap: 3rem; }}
.page-title {{ font-size: 1.8rem; color: var(--primary); margin-bottom: 1rem; }}
.post-preview {{ padding-bottom: 2rem; border-bottom: 1px solid var(--border); }}
.post-preview:last-child {{ border-bottom: none; }}
.post-preview .post-title {{ font-size: 1.5rem; font-weight: 600; margin-bottom: 0.5rem; }}
.post-preview .post-title a {{ color: var(--primary); text-decoration: none; }}
.post-preview .post-title a:hover {{ color: var(--accent); text-decoration: underline; }}
.post-date {{ color: var(--light); font-size: 0.9rem; display: block; margin-bottom: 1rem; }}
.post-summary {{ color: var(--text); margin-bottom: 1rem; line-height: 1.7; }}
.read-more {{ color: var(--accent); text-decoration: none; font-weight: 500; }}
.read-more:hover {{ text-decoration: underline; }}
.post {{ background: var(--bg); padding: 2rem 0; }}
.post-header {{ text-align: center; margin-bottom: 3rem; }}
.post-title {{ font-size: 2.2rem; color: var(--primary); margin-bottom: 1rem; }}
.post-content {{ font-size: 1.1rem; line-height: 1.8; }}
.post-content p {{ margin-bottom: 1.5rem; }}
.post-content strong {{ color: var(--primary); }}
.post-content em {{ font-style: italic; }}
.post-content code {{ background: var(--code); padding: 0.2rem 0.4rem; border-radius: 3px; font-family: 'Courier New', monospace; font-size: 0.9em; }}
.post-content a {{ color: var(--accent); }}
.post-content a:hover {{ text-decoration: none; }}
.pagination {{ margin-top: 3rem; padding-top: 2rem; border-top: 2px solid var(--border); }}
.nav-links {{ display: flex; justify-content: space-between; margin-bottom: 1rem; }}
.nav-links a {{ color: var(--accent); text-decoration: none; font-weight: 500; padding: 0.5rem 1rem; border: 1px solid currentColor; border-radius: 4px; }}
.nav-links a:hover {{ background: var(--accent); color: white; }}
.page-numbers {{ display: flex; justify-content: center; gap: 0.5rem; flex-wrap: wrap; }}
.page-numbers a, .page-numbers .current {{ display: inline-flex; align-items: center; justify-content: center; width: 36px; height: 36px; text-decoration: none; border-radius: 4px; font-weight: 500; }}
.page-numbers a {{ color: var(--primary); border: 1px solid var(--border); }}
.page-numbers a:hover {{ background: var(--primary); color: white; }}
.page-numbers .current {{ background: var(--accent); color: white; border: 1px solid var(--accent); }}
@media (max-width: 600px) {{ body {{ font-size: 15px; }} .container {{ padding: 1.5rem 1rem; }} .post-title {{ font-size: 1.8rem; }} }}
</style>
</head>
<body>
<div class="container">
  <header>
    <a href="/" class="site-title">{escape_html(SITE_TITLE)}</a>
  </header>
  <main>
{main_content}
  </main>
  <footer style="margin-top: 4rem; padding-top: 2rem; border-top: 1px solid var(--border); text-align: center; color: var(--light); font-size: 0.9rem;">
    {footer_html}
  </footer>
</div>
</body>
</html>"""

# 向后兼容
# 如果项目中其他代码需要generate_full_html这个名称，保持它
generate_full_html = generate_full_html

# ---------- WSGI应用 ----------

class StaticApp:
    """静态文件WSGI应用"""
    def __init__(self, document_root):
        self.document_root = document_root
    
    def __call__(self, environ, start_response):
        path = environ.get('PATH_INFO', '/')
        
        # 规范化路径
        if path == '/' or path.endswith('/'):
            path += 'index.html'
        
        # 安全检查
        is_safe, full_path = safe_path_check(path, self.document_root)
        if not is_safe:
            status = '403 Forbidden'
            headers = self._security_headers()
            start_response(status, headers)
            return [b'403 Forbidden - Invalid path']
        
        # 检查文件是否存在
        if not os.path.isfile(full_path):
            status = '404 Not Found'
            headers = self._security_headers()
            start_response(status, headers)
            return [b'404 Not Found']
        
        # 读取文件
        try:
            with open(full_path, 'rb') as f:
                content = f.read()
            
            status = '200 OK'
            headers = self._security_headers() + [
                ('Content-Type', 'text/html; charset=utf-8'),
                ('Content-Length', str(len(content)))
            ]
            start_response(status, headers)
            return [content]
        except Exception as e:
            logger.error(f"[STATIC-ERROR] {e}")
            status = '500 Internal Server Error'
            headers = self._security_headers()
            start_response(status, headers)
            return [b'500 Internal Server Error']
    
    def _security_headers(self):
        """返回安全响应头"""
        return [
            ('Cache-Control', 'no-cache, no-store, must-revalidate'),
            ('Pragma', 'no-cache'),
            ('Expires', '0'),
            ('X-Content-Type-Options', 'nosniff'),
            ('X-Frame-Options', 'DENY'),
            ('X-XSS-Protection', '1; mode=block'),
            ('Referrer-Policy', 'no-referrer'),
        ]

class AdminApp:
    """管理后台WSGI应用"""
    def __init__(self, user, password):
        self.user = user
        self.password = password
    
    def __call__(self, environ, start_response):
        method = environ.get('REQUEST_METHOD', 'GET')
        path = environ.get('PATH_INFO', '/')
        
        # Basic认证
        if not self._check_auth(environ):
            return self._send_auth_required(environ, start_response)
        
        # 路由处理
        try:
            if method == 'GET':
                if path == '/' or path == '/dashboard':
                    return self._handle_dashboard(environ, start_response)
                elif path == '/new':
                    return self._handle_new_form(environ, start_response)
                elif path == '/edit':
                    return self._handle_edit_form(environ, start_response)
                else:
                    return self._send_404(environ, start_response)
            
            elif method == 'POST':
                # 验证CSRF token
                post_data = self._get_post_data(environ)
                csrf_token = post_data.get('csrf_token', [''])[0]
                
                if not validate_csrf_token(environ, csrf_token):
                    return self._send_error(environ, start_response, '403 Forbidden', 'CSRF token validation failed')
                
                if path == '/create':
                    return self._handle_create(environ, start_response, post_data)
                elif path == '/save':
                    return self._handle_save(environ, start_response, post_data)
                elif path == '/delete':
                    return self._handle_delete(environ, start_response, post_data)
                elif path == '/regen':
                    return self._handle_regen(environ, start_response, post_data)
                else:
                    return self._send_404(environ, start_response)
            
            else:
                return self._send_error(environ, start_response, '405 Method Not Allowed', 'Method not allowed')
        
        except Exception as e:
            logger.error(f"[ADMIN-ERROR] {e}")
            return self._send_error(environ, start_response, '500 Internal Server Error', 'Server error')
    
    def _check_auth(self, environ):
        """检查Basic认证"""
        try:
            auth_header = environ.get('HTTP_AUTHORIZATION', '')
            if not auth_header.startswith('Basic '):
                client_ip = get_real_ip(environ)
                logger.warning(f"[AUTH-FAIL] Missing or invalid authorization header from {client_ip}")
                return False
            
            try:
                decoded = base64.b64decode(auth_header[6:], validate=True).decode('utf-8', errors='strict')
            except Exception:
                logger.warning("[AUTH-FAIL] Invalid base64 encoding")
                return False
            
            if ':' not in decoded:
                logger.warning("[AUTH-FAIL] Invalid credentials format")
                return False
                
            username, password = decoded.split(':', 1)
            
            # 使用secrets.compare_digest防止时序攻击
            user_valid = secrets.compare_digest(username, self.user)
            pass_valid = secrets.compare_digest(password, self.password)
            
            if not (user_valid and pass_valid):
                client_ip = get_real_ip(environ)
                # 安全地记录部分密码信息（只显示前3个字符，保护敏感信息）
                safe_password = password[:3] + '*' * max(0, len(password) - 3) if len(password) > 3 else '*' * len(password)
                logger.warning(f"[AUTH-FAIL] Invalid credentials from {client_ip}, attempted password: {safe_password}")
                return False
            
            # 登录成功日志
            client_ip = get_real_ip(environ)
            logger.info(f"[AUTH-SUCCESS] User {username} logged in from {client_ip}")
            return True
            
            return True
        except Exception as e:
            logger.error(f"[AUTH-ERROR] Unexpected error: {e}")
            return False
    
    def _handle_regen(self, environ, start_response, post_data):
        """处理重新生成静态页面"""
        try:
            client_ip = get_real_ip(environ)
            generate_static_pages()
            logger.info(f"[REGEN] Static pages regenerated by {self.user} from {client_ip}")
            return self._redirect(environ, start_response, '/')
        except Exception as e:
            logger.error(f"[REGEN-ERROR] {e}")
            return self._send_error(environ, start_response, '500 Internal Server Error', 'Regeneration failed')
    
    def _send_auth_required(self, environ, start_response):
        """发送401认证要求"""
        status = '401 Unauthorized'
        headers = [
            ('WWW-Authenticate', 'Basic realm="Secure Admin"'),
            ('Content-Type', 'text/plain'),
        ] + self._security_headers()
        start_response(status, headers)
        return [b'401 Unauthorized - Access Denied']
    
    def _security_headers(self):
        """安全响应头"""
        return [
            ('Cache-Control', 'no-cache, no-store, must-revalidate'),
            ('X-Content-Type-Options', 'nosniff'),
            ('X-Frame-Options', 'DENY'),
            ('X-XSS-Protection', '1; mode=block'),
            ('Referrer-Policy', 'no-referrer'),
        ]
    
    def _get_post_data(self, environ):
        """获取POST数据"""
        try:
            content_length = int(environ.get('CONTENT_LENGTH', 0))
            if content_length > 0:
                post_data = environ['wsgi.input'].read(content_length)
                # 重置输入流以便重新读取
                environ['wsgi.input'] = io.BytesIO(post_data)
                return parse_qs(post_data.decode('utf-8'))
        except (ValueError, KeyError):
            pass
        return {}
    
    def _handle_dashboard(self, environ, start_response):
        """处理后台首页（带分页）"""
        client_ip = get_real_ip(environ)
        logger.info(f"[VIEW-DASHBOARD] Accessed by {self.user} from {client_ip}")
        
        # 获取分页参数
        qs = parse_qs(environ.get('QUERY_STRING', ''))
        page_str = qs.get('page', ['1'])[0]
        try:
            page = max(1, int(page_str))
        except (ValueError, TypeError):
            page = 1
        
        # 获取所有文章并分页
        arts = list_articles_safe()
        total = len(arts)
        pages = (total + PAGE_SIZE - 1) // PAGE_SIZE
        
        # 计算当前页的文章
        start = (page - 1) * PAGE_SIZE
        end = start + PAGE_SIZE
        page_arts = arts[start:end]
        
        rows = []
        csrf_token = generate_csrf_token()
        for art in page_arts:
            safe_title = escape_html(art['title'][:80])
            rows.append(f"""
<tr>
  <td><a href="/edit?file={art['file']}">{safe_title}</a></td>
  <td>{escape_html(art['date'])}</td>
  <td>
    <form method="post" action="/delete" style="display:inline;" onsubmit="return confirm('删除不可恢复，确定？')">
      <input type="hidden" name="csrf_token" value="{csrf_token}">
      <input type="hidden" name="file" value="{art['file']}">
      <button type="submit" style="background: var(--accent); color: white; border: none; padding: 0.25rem 0.5rem; cursor: pointer; font-size: 0.8rem;">删除</button>
    </form>
  </td>
</tr>""")
        
        # 生成分页导航
        nav_links = []
        if page > 1:
            if page == 2:
                nav_links.append('<a href="/" class="prev">← 上一页</a>')
            else:
                nav_links.append(f'<a href="/?page={page-1}" class="prev">← 上一页</a>')
        
        page_numbers = []
        for p in range(1, pages + 1):
            if p == page:
                page_numbers.append(f'<span class="current">{p}</span>')
            elif p == 1:
                page_numbers.append('<a href="/">1</a>')
            else:
                page_numbers.append(f'<a href="/?page={p}">{p}</a>')
        
        if page < pages:
            nav_links.append(f'<a href="/?page={page+1}" class="next">下一页 →</a>')
        
        nav_html = f"""
<nav class="pagination">
  <div class="nav-links">{''.join(nav_links)}</div>
  <div class="page-numbers">{''.join(page_numbers)}</div>
</nav>""" if pages > 1 else ""
        
        csrf_cookie = get_csrf_cookie_header(csrf_token)
        status = '200 OK'
        headers = [
            ('Content-Type', 'text/html; charset=utf-8'),
            csrf_cookie
        ] + self._security_headers()
        
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="X-Content-Type-Options" content="nosniff">
<title>管理后台</title>
<style>
:root {{ --primary: #2c3e50; --accent: #e74c3c; }}
body {{ max-width: 900px; margin: 2rem auto; padding: 0 1.5rem; font-family: system-ui, sans-serif; }}
h1 {{ color: var(--primary); margin-bottom: 1rem; }}
.security-notice {{ background: #d4edda; border-left: 4px solid #28a745; padding: 0.5rem 1rem; margin-bottom: 1.5rem; }}
table {{ width: 100%; border-collapse: collapse; margin-top: 1.5rem; }}
th, td {{ text-align: left; padding: 0.75rem; border-bottom: 1px solid #ddd; }}
th {{ background: #f8f9fa; }}
a {{ color: var(--accent); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
.actions {{ margin: 1.5rem 0; display: flex; gap: 0.5rem; }}
button {{ background: var(--accent); color: white; border: none; padding: 0.5rem 1rem; cursor: pointer; border-radius: 4px; }}
button:hover {{ opacity: 0.9; }}
.pagination {{ margin-top: 2rem; padding-top: 1.5rem; border-top: 1px solid #ddd; }}
.nav-links {{ display: flex; justify-content: space-between; margin-bottom: 0.5rem; }}
.page-numbers {{ display: flex; justify-content: center; gap: 0.5rem; flex-wrap: wrap; }}
.page-numbers a, .page-numbers .current {{ display: inline-flex; align-items: center; justify-content: center; width: 32px; height: 32px; text-decoration: none; border-radius: 4px; font-weight: 500; }}
.page-numbers a {{ color: var(--primary); border: 1px solid #ddd; }}
.page-numbers a:hover {{ background: var(--primary); color: white; }}
.page-numbers .current {{ background: var(--accent); color: white; border: 1px solid var(--accent); }}
</style>
</head>
<body>
<h1>管理后台</h1>
<div class="security-notice">
  <strong>安全提醒：</strong>所有操作已记录审计日志 | CSRF保护已启用
</div>
<div class="actions">
  <a href="/new"><button>+ 新建文章</button></a>
  <form method="post" action="/regen" style="display:inline;">
    <input type="hidden" name="csrf_token" value="{csrf_token}">
    <button type="submit">重新生成</button>
  </form>
</div>
<table>
<thead><tr><th style="width:50%">标题</th><th style="width:30%">发布时间</th><th style="width:20%">操作</th></tr></thead>
<tbody>{''.join(rows)}</tbody>
</table>
{nav_html}
<p style="margin-top: 1rem; color: #666; font-size: 0.9rem;">共 {total} 篇文章，第 {page}/{max(1, pages)} 页</p>
</body>
</html>"""
        
        start_response(status, headers)
        return [html.encode('utf-8')]
    
    def _handle_new_form(self, environ, start_response):
        """处理新建文章表单"""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        csrf_token = generate_csrf_token()
        csrf_cookie = ('Set-Cookie', f'csrf_token={csrf_token}; Path=/; HttpOnly; SameSite=Strict')
        
        status = '200 OK'
        headers = [
            ('Content-Type', 'text/html; charset=utf-8'),
            csrf_cookie
        ] + self._security_headers()
        
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="X-Content-Type-Options" content="nosniff">
<title>新建文章 - 纯文本</title>
<style>
:root {{ --primary: #2c3e50; --accent: #e74c3c; }}
body {{ max-width: 800px; margin: 2rem auto; padding: 0 1.5rem; font-family: system-ui; }}
h1 {{ color: var(--primary); }}
form {{ margin-top: 1.5rem; }}
input, textarea {{ width: 100%; font-family: inherit; font-size: 1rem; padding: 0.5rem; margin-bottom: 1rem; border: 1px solid #ccc; border-radius: 4px; }}
textarea {{ height: 400px; resize: vertical; line-height: 1.6; }}
button {{ background: var(--accent); color: white; border: none; padding: 0.75rem 1.5rem; cursor: pointer; font-size: 1rem; border-radius: 4px; }}
.help {{ background: #e3f2fd; border-left: 4px solid #2196f3; padding: 0.75rem; margin: 1rem 0; font-size: 0.9rem; }}
</style>
</head>
<body>
<h1>新建文章（纯文本）</h1>
<div class="help">
  <strong>格式提示：</strong><br>
  • **粗体文字** ← 用两个星号包围<br>
  • *斜体文字* ← 用一个星号包围<br>
  • `代码片段` ← 用反引号包围<br>
  • [链接文字](https://example.com) ← 链接格式（仅允许安全协议）<br>
  • 空一行分段落
</div>
<form method="post" action="/create">
  <input type="hidden" name="csrf_token" value="{csrf_token}">
  <p><input name="title" placeholder="文章标题" required maxlength="{MAX_TITLE_LENGTH}"></p>
  <p><input name="date" value="{now}" required pattern="\\d{{4}}-\\d{{2}}-\\d{{2}} \\d{{2}}:\\d{{2}}"></p>
  <p><textarea name="content" placeholder="请输入纯文本内容" required maxlength="{MAX_CONTENT_LENGTH}"></textarea></p>
  <p><button type="submit">发布</button></p>
</form>
<p><a href="/">← 返回管理面板</a></p>
</body>
</html>"""

        start_response(status, headers)
        return [html.encode('utf-8')]
    
    def _handle_edit_form(self, environ, start_response):
        """处理编辑文章表单"""
        qs = parse_qs(environ.get('QUERY_STRING', ''))
        fname = qs.get('file', [''])[0]
        
        if not validate_filename(fname):
            return self._send_error(environ, start_response, '400 Bad Request', 'Invalid filename')
        
        path = os.path.join(ARTICLE_DIR, fname)
        is_safe, full_path = safe_path_check(path, ARTICLE_DIR)
        if not is_safe or not os.path.isfile(full_path):
            return self._send_error(environ, start_response, '404 Not Found', 'Article not found')
        
        meta = parse_meta_safe(full_path)
        if not meta:
            return self._send_error(environ, start_response, '500 Internal Server Error', 'Failed to parse article')
        
        # 提取文本内容
        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
            for _ in range(5):
                next(f, None)
            html_content = f.read()
        
        match = re.search(r'<div class="post-content">(.*?)</div>', html_content, re.DOTALL)
        if match:
            text_content = re.sub(r'<[^>]+>', '', match.group(1)).strip()
        else:
            text_content = re.sub(r'<[^>]+>', '', html_content).strip()
        
        csrf_token = generate_csrf_token()
        csrf_cookie = ('Set-Cookie', f'csrf_token={csrf_token}; Path=/; HttpOnly; SameSite=Strict')
        status = '200 OK'
        headers = [
            ('Content-Type', 'text/html; charset=utf-8'),
            csrf_cookie
        ] + self._security_headers()
        
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="X-Content-Type-Options" content="nosniff">
<title>编辑: {escape_html(meta['title'])}</title>
<style>
:root {{ --primary: #2c3e50; --accent: #e74c3c; }}
body {{ max-width: 800px; margin: 2rem auto; padding: 0 1.5rem; font-family: system-ui; }}
h1 {{ color: var(--primary); }}
form {{ margin-top: 1.5rem; }}
input, textarea {{ width: 100%; font-family: inherit; font-size: 1rem; padding: 0.5rem; margin-bottom: 1rem; border: 1px solid #ccc; border-radius: 4px; }}
textarea {{ height: 400px; resize: vertical; line-height: 1.6; }}
button {{ background: var(--accent); color: white; border: none; padding: 0.75rem 1.5rem; cursor: pointer; font-size: 1rem; border-radius: 4px; }}
</style>
</head>
<body>
<h1>编辑文章</h1>
<form method="post" action="/save">
  <input type="hidden" name="csrf_token" value="{csrf_token}">
  <p><input name="title" value="{escape_attr(meta['title'])}" required maxlength="{MAX_TITLE_LENGTH}"></p>
  <p><input name="date" value="{escape_html(meta['date'])}" required></p>
  <p><textarea name="content" required maxlength="{MAX_CONTENT_LENGTH}">{escape_html(text_content)}</textarea></p>
  <p><input type="hidden" name="file" value="{fname}"></p>
  <p><button type="submit">保存更改</button></p>
</form>
<p><a href="/">← 返回管理面板</a></p>
</body>
</html>"""
        
        start_response(status, headers)
        return [html.encode('utf-8')]
    
    def _handle_create(self, environ, start_response, post_data):
        """处理创建文章"""
        title = post_data.get('title', [''])[0]
        date = post_data.get('date', [''])[0]
        content = post_data.get('content', [''])[0]
        client_ip = get_real_ip(environ)
        
        # 验证输入
        if not all([title, date, content]):
            logger.warning(f"[CREATE-FAIL] Missing fields from {client_ip} by {self.user}")
            return self._send_error(environ, start_response, '400 Bad Request', 'Missing required fields')
        
        if len(title) > MAX_TITLE_LENGTH or len(content) > MAX_CONTENT_LENGTH:
            logger.warning(f"[CREATE-FAIL] Content too large from {client_ip} by {self.user}")
            return self._send_error(environ, start_response, '413 Payload Too Large', 'Title or content too long')
        
        if not validate_date_format(date):
            logger.warning(f"[CREATE-FAIL] Invalid date format from {client_ip} by {self.user}")
            return self._send_error(environ, start_response, '400 Bad Request', 'Invalid date format')
        
        slug = slugify_title(title)
        if not slug:
            logger.warning(f"[CREATE-FAIL] Invalid title from {client_ip} by {self.user}")
            return self._send_error(environ, start_response, '400 Bad Request', 'Invalid title')
        
        fname = f"{date[:10]}-{slug}.html"
        if os.path.exists(os.path.join(ARTICLE_DIR, fname)):
            suffix = secrets.token_urlsafe(4)
            fname = f"{date[:10]}-{slug}-{suffix}.html"
        
        try:
            write_article_safe(fname, title, date, slug, content)
            generate_static_pages()
            logger.info(f"[CREATE] {fname} by {self.user} from {client_ip}")
            return self._redirect(environ, start_response, '/')
        except ValueError as e:
            logger.error(f"[CREATE-ERROR] {fname} from {client_ip} by {self.user}: {e}")
            return self._send_error(environ, start_response, '400 Bad Request', str(e))
    
    def _handle_save(self, environ, start_response, post_data):
        """处理保存文章"""
        fname = post_data.get('file', [''])[0]
        title = post_data.get('title', [''])[0]
        date = post_data.get('date', [''])[0]
        content = post_data.get('content', [''])[0]
        client_ip = get_real_ip(environ)
        
        if not all([fname, title, date, content]):
            logger.warning(f"[SAVE-FAIL] Missing fields from {client_ip} by {self.user}")
            return self._send_error(environ, start_response, '400 Bad Request', 'Missing required fields')
        
        if not validate_filename(fname):
            logger.warning(f"[SAVE-FAIL] Invalid filename from {client_ip} by {self.user}: {fname}")
            return self._send_error(environ, start_response, '400 Bad Request', 'Invalid filename')
        
        if len(title) > MAX_TITLE_LENGTH or len(content) > MAX_CONTENT_LENGTH:
            logger.warning(f"[SAVE-FAIL] Content too large from {client_ip} by {self.user}: {fname}")
            return self._send_error(environ, start_response, '413 Payload Too Large', 'Title or content too long')
        
        if not validate_date_format(date):
            logger.warning(f"[SAVE-FAIL] Invalid date format from {client_ip} by {self.user}: {fname}")
            return self._send_error(environ, start_response, '400 Bad Request', 'Invalid date format')
        
        path = os.path.join(ARTICLE_DIR, fname)
        if os.path.exists(path):
            meta = parse_meta_safe(path)
            slug = meta.get('slug', '') if meta else slugify_title(title)
        else:
            slug = slugify_title(title)
        
        try:
            write_article_safe(fname, title, date, slug, content)
            generate_static_pages()
            logger.info(f"[SAVE] {fname} by {self.user} from {client_ip}")
            return self._redirect(environ, start_response, '/')
        except ValueError as e:
            logger.error(f"[SAVE-ERROR] {fname} from {client_ip} by {self.user}: {e}")
            return self._send_error(environ, start_response, '400 Bad Request', str(e))
    
    def safe_delete_file(self, filepath, client_ip='unknown'):
        """安全删除文件"""
        if not os.path.isfile(filepath):
            return False
        
        try:
            # 先备份到临时目录
            backup_path = filepath + '.backup'
            import shutil
            shutil.copy2(filepath, backup_path)
            
            # 执行删除
            os.remove(filepath)
            
            # 验证删除成功
            if os.path.exists(filepath):
                raise OSError("File deletion verification failed")
                
            # 清理备份
            os.remove(backup_path)
            
            return True
        except Exception as e:
            # 恢复备份
            if os.path.exists(backup_path):
                shutil.move(backup_path, filepath)
            raise e
    
    def _handle_delete(self, environ, start_response, post_data):
        """处理删除文章(POST)"""
        fname = post_data.get('file', [''])[0]
        client_ip = get_real_ip(environ)
        
        if not validate_filename(fname):
            logger.warning(f"[DELETE-FAIL] Invalid filename from {client_ip} by {self.user}: {fname}")
            return self._send_error(environ, start_response, '400 Bad Request', 'Invalid filename')
        
        path = os.path.join(ARTICLE_DIR, fname)
        is_safe, full_path = safe_path_check(path, ARTICLE_DIR)
        
        if not is_safe:
            logger.warning(f"[DELETE-FAIL] Path validation failed from {client_ip} by {self.user}: {path}")
            return self._send_error(environ, start_response, '403 Forbidden', 'Path validation failed')
        
        if os.path.isfile(full_path):
            try:
                self.safe_delete_file(full_path, client_ip)
                generate_static_pages()
                logger.info(f"[DELETE] {fname} by {self.user} from {client_ip}")
            except Exception as e:
                logger.error(f"[DELETE-FAIL] {fname} from {client_ip} by {self.user}: {e}")
                return self._send_error(environ, start_response, '500 Internal Server Error', 'Delete failed')
        else:
            logger.warning(f"[DELETE-FAIL] File not found from {client_ip} by {self.user}: {fname}")
        
        return self._redirect(environ, start_response, '/')
    
    def _redirect(self, environ, start_response, location):
        """重定向"""
        status = '302 Found'
        headers = [
            ('Location', location),
        ] + self._security_headers()
        start_response(status, headers)
        return [b'']
    
    def _send_error(self, environ, start_response, status, message):
        """发送错误响应"""
        headers = [
            ('Content-Type', 'text/plain'),
        ] + self._security_headers()
        start_response(status, headers)
        return [message.encode('utf-8')]
    
    def _send_404(self, environ, start_response):
        """发送404"""
        return self._send_error(environ, start_response, '404 Not Found', 'Not Found')

# ---------- 启动函数 ----------

def run_static_server():
    """启动静态文件服务器(使用Waitress)"""
    app = StaticApp(ROOT_DIR)
    try:
        logger.info(f"[START] Static server: http://{STATIC_HOST}:{STATIC_PORT}")
        serve(app, host=STATIC_HOST, port=STATIC_PORT, threads=4, channel_timeout=30)
    except Exception as e:
        logger.critical(f"[FATAL] Static server: {e}")
        raise

def run_admin_server():
    """启动管理后台服务器(使用Waitress)"""
    app = AdminApp(ADMIN_USER, ADMIN_PASS)
    try:
        admin_host = '127.0.0.1'  # 后台始终绑定本地
        logger.info(f"[START] Admin server: http://{admin_host}:{ADMIN_PORT}")
        logger.info(f"[AUTH] User: {ADMIN_USER}")
        logger.info(f"[AUTH] Password: {'*' * min(len(ADMIN_PASS), 16)} ({len(ADMIN_PASS)} chars)")
        serve(app, host=admin_host, port=ADMIN_PORT, threads=2, channel_timeout=30)
    except Exception as e:
        logger.critical(f"[FATAL] Admin server: {e}")
        raise

# ---------- 主程序 ----------

if __name__ == "__main__":
    
    # 显示精简启动信息
    print("\n" + "="*70)
    print(f"Site Title: {SITE_TITLE}")
    print(f"Data Directory: {ROOT_DIR}")
    print(f"Static Server: http://{STATIC_HOST}:{STATIC_PORT}")
    print(f"Admin Server: http://127.0.0.1:{ADMIN_PORT}")
    print(f"Admin User: {ADMIN_USER}")
    
    print(f"HTTPS: Reverse Proxy Recommended")
    
    # 域名绑定
    if BIND_DOMAIN:
        print(f"Domain Bind: {BIND_DOMAIN}")
        print(f"  Nginx users: CSRF validation enabled for {BIND_DOMAIN}")
    else:
        print(f"Domain Bind: Not set")
        print(f"  Nginx users: Set BIND_DOMAIN to your domain (e.g., example.com)")
    
    # Nginx配置提示
    print(f"\nNginx Configuration Tip:")
    print(f"   Add these headers to your Nginx config:")
    print(f"   proxy_set_header X-Real-IP $remote_addr;")
    print(f"   proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
    print(f"   proxy_set_header Host $http_host;")
    
    if len(ADMIN_PASS) < 16:
        print(f"⚠️  WARNING: Password too short ({len(ADMIN_PASS)} chars) - Recommend 16+ characters")
    else:
        print(f"Password: {'*' * 16}... (length: {len(ADMIN_PASS)})")
    
    print(f"Audit Log: {LOG_FILE}")
    print("="*70 + "\n")
    
    # 生成初始页面
    if not os.path.exists(os.path.join(ROOT_DIR, "index.html")):
        logger.info("[INIT] First run, generating pages...")
        generate_static_pages()
    
    # 启动服务器
    logger.info("[START] Starting servers...")
    
    t1 = threading.Thread(target=run_static_server, daemon=True)
    t2 = threading.Thread(target=run_admin_server, daemon=True)
    
    t1.start()
    t2.start()
    
    try:
        t1.join()
        t2.join()
    except KeyboardInterrupt:
        logger.info("\n[SHUTDOWN] Graceful shutdown initiated...")
        print("\nService stopped by user")
