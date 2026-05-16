# TinyPage 代码审计 — 详细优化实施方案

**基于**: `docs/code-audit-report.md`  
**目标**: 提供编程 agent 可直接执行的、包含完整代码的优化方案  
**日期**: 2026-05-16

---

## 目录

1. [P0 — 立即修复（安全风险）](#p0--立即修复安全风险)
2. [P1 — 近期修复（1-2 周）](#p1--近期修复1-2-周)
3. [P2 — 中期改进（1-2 月）](#p2--中期改进1-2-月)
4. [P3 — 长期演进](#p3--长期演进)

---

## P0 — 立即修复（安全风险）

---

### P0-1: 删除 `admin_password.txt` 并清理 git 历史 ✅ 已完成

**问题**: `admin_password.txt` 包含明文密码，可能已被 git 跟踪。

**完成情况**: 文件从未被 git 跟踪，无需清理历史；`.gitignore` 已包含排除规则；物理文件已删除；密码保存位置已改为系统临时目录（P0-2 实现）。

**步骤**:

```bash
# 步骤1: 确认文件是否在 git 历史中
git log --all --full-history -- admin_password.txt

# 步骤2: 从 git 历史中彻底删除（使用 BFG Repo-Cleaner，更安全）
# 先安装 BFG: https://rtyley.github.io/bfg-repo-cleaner/
java -jar bfg.jar --delete-files admin_password.txt
git reflog expire --expire=now --all
git gc --prune=now --aggressive

# 如果没有 BFG，使用 git filter-branch:
git filter-branch --force --index-filter \
  'git rm --cached --ignore-unmatch admin_password.txt' \
  --prune-empty --tag-name-filter cat -- --all

# 步骤3: 确认 .gitignore 中已有排除
# 检查 .gitignore 是否包含 admin_password.txt
grep "admin_password" .gitignore
# 如果没有，添加:
echo "admin_password.txt" >> .gitignore

# 步骤4: 物理删除文件
rm admin_password.txt

# 步骤5: 强制推送（如果已推送到远程，需要所有协作者重新 clone）
git push origin --force --all
```

**密码文件新位置**: 改为写入系统临时目录，见 P0-2。

---

### P0-2: 强制要求设置管理员密码，拒绝空密码启动 ✅ 已完成

**问题**: `config.py:27` 默认 `admin_pass` 为空，`server.py:25-50` 每次启动生成新密码，重启后密码变更。

**完成情况**: 
- ✅ `server.py` — `ensure_admin_password` 函数已改为密码缓存到系统临时目录，重启后复用
- ✅ `server.py` — `main()` 函数密码提示已更新
- ✅ `config.py` — `validate_startup()` 方法已添加，检查空密码和短密码
- ✅ `server.py` — 启动时调用 `cfg.validate_startup()` 输出警告日志

**文件1**: `tinypage/config.py`

```python
# === 修改前 (第25-26行) ===
    admin_user: str = field(default_factory=lambda: os.getenv("ADMIN_USER", "admin"))
    admin_pass: str = field(default_factory=lambda: os.getenv("ADMIN_PASS", ""))

# === 修改后 ===
    admin_user: str = field(default_factory=lambda: os.getenv("ADMIN_USER", "admin"))
    admin_pass: str = field(default_factory=lambda: os.getenv("ADMIN_PASS", ""))
```

`config.py` 本身不需要改动，改动在 `server.py` 和验证逻辑中。

**文件2**: `tinypage/config.py` — 添加 `__post_init__` 验证（与 P2-16 合并，此处仅做密码相关部分）

在 `Config` 类的 `merge` 方法之后（第106行后）添加：

```python
    def validate_startup(self) -> list[str]:
        """Validate config for startup. Returns list of warnings."""
        warnings = []
        if not self.admin_pass:
            warnings.append(
                "ADMIN_PASS is not set. A random password will be generated "
                "and saved to a temp file. Set ADMIN_PASS env var for persistent auth."
            )
        if len(self.admin_pass) < 16 and self.admin_pass:
            warnings.append(
                f"ADMIN_PASS is only {len(self.admin_pass)} chars. "
                "Recommend at least 16 characters."
            )
        return warnings
```

**文件3**: `tinypage/server.py` — 完整替换 `ensure_admin_password` 函数和 `main` 函数

```python
# === 修改前 (第25-50行) ===
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

# === 修改后 ===
import tempfile

_PASSWORD_CACHE_FILE = Path(tempfile.gettempdir()) / ".tinypage_admin_pass"


def ensure_admin_password(cfg: Config) -> str:
    """Get or generate admin password. Persist generated password to temp dir."""
    password = cfg.admin_pass
    if password:
        return password

    # 尝试读取上次生成的临时密码（支持重启后密码不丢失）
    if _PASSWORD_CACHE_FILE.exists():
        try:
            cached = _PASSWORD_CACHE_FILE.read_text(encoding="utf-8").strip()
            if cached and len(cached) >= 24:
                logger.info("[INIT] Reusing cached admin password from temp file")
                return cached
        except (OSError, ValueError):
            pass

    # 生成新的随机密码
    import secrets
    base = secrets.token_urlsafe(24)
    suffix = secrets.choice(["#", "+", "%"])
    password = base[:31] + suffix

    # 保存到系统临时目录（而非项目目录）
    try:
        _PASSWORD_CACHE_FILE.write_text(password, encoding="utf-8")
        _PASSWORD_CACHE_FILE.chmod(0o600)  # 仅当前用户可读写
    except OSError:
        # Windows 不完全支持 chmod，但 write_text 仍然可用
        try:
            _PASSWORD_CACHE_FILE.write_text(password, encoding="utf-8")
        except OSError as e:
            logger.error(f"[INIT-FAILED] Cannot save password cache: {e}")

    print(f"\n{'='*70}")
    print("WARNING: ADMIN_PASS is not set!")
    print(f"Random password generated and cached to: {_PASSWORD_CACHE_FILE}")
    print("Set ADMIN_PASS environment variable for persistent authentication.")
    print(f"{'='*70}\n")
    logger.warning(f"[INIT] Random password cached to {_PASSWORD_CACHE_FILE}")
    return password
```

同时修改 `main()` 函数中密码长度提示部分（第116-120行）：

```python
# === 修改前 (第116-120行) ===
    pw_len = len(cfg.admin_pass or "")
    if pw_len < 16:
        print(f"⚠️  WARNING: Password too short ({pw_len} chars)")
    else:
        print(f"Password: {'*' * 16}... (length: {pw_len})")

# === 修改后 ===
    pw_len = len(cfg.admin_pass or "")
    if pw_len == 0:
        print("Password: AUTO-GENERATED (set ADMIN_PASS env var to customize)")
    elif pw_len < 16:
        print(f"WARNING: Password too short ({pw_len} chars)")
    else:
        print(f"Password: {'*' * 16}... (length: {pw_len})")
```

---

### P0-3: 管理后台模板中所有用户输入使用 `escape_attr()` ✅ 已完成

**问题**: `admin.py` 中多处 `art.file`、`page.file`、`fname`、`theme["name"]` 等用户可控值直接嵌入 HTML 属性，未转义。

**文件**: `tinypage/admin.py`

以下是需要修改的每一处，给出精确行号和修改方式：

**3a. 第296行** — `_dashboard` 方法中的隐藏输入：

```python
# === 修改前 ===
    value="{art.file}"

# === 修改后 ===
    value="{escape_attr(art.file)}"
```

**3b. 第310行** — `_dashboard` 方法中的编辑链接：

```python
# === 修改前 ===
    f'<a href="/edit?file={art.file}">'

# === 修改后 ===
    f'<a href="/edit?file={escape_attr(art.file)}">'
```

注意：更安全的做法是对 URL 参数使用 `urllib.parse.quote`：

```python
    from urllib.parse import quote
    f'<a href="/edit?file={quote(art.file, safe="")}">'
```

**3c. 第315行** — `_dashboard` 方法中的隐藏输入（删除表单）：

```python
# === 修改前 ===
    value="{art.file}"

# === 修改后 ===
    value="{escape_attr(art.file)}"
```

**3d. 第496行** — `_edit_form` 方法中的隐藏输入：

```python
# === 修改前 ===
    value="{fname}"

# === 修改后 ===
    value="{escape_attr(fname)}"
```

**3e. 第841行** — `_pages_dashboard` 方法中的编辑链接：

```python
# === 修改前 ===
    href="/edit-page?file={page.file}"

# === 修改后 ===
    href="/edit-page?file={escape_attr(page.file)}"
```

**3f. 第847行** — `_pages_dashboard` 方法中的隐藏输入：

```python
# === 修改前 ===
    value="{page.file}"

# === 修改后 ===
    value="{escape_attr(page.file)}"
```

**3g. 第941行** — `_edit_page_form` 方法中的隐藏输入：

```python
# === 修改前 ===
    value="{fname}"

# === 修改后 ===
    value="{escape_attr(fname)}"
```

**3h. 第711行** — `_theme_page` 方法中的隐藏输入：

```python
# === 修改前 ===
    value="{theme["name"]}"

# === 修改后 ===
    value="{escape_attr(theme["name"])}"
```

**3i. CSRF token 也应转义** — 以下行号的 `value="{csrf_token}"` 应改为 `value="{escape_attr(csrf_token)}"`：

- 第295行（`_dashboard`）
- 第313行（`_dashboard` 删除表单）
- 第340行（`_dashboard` 底部）
- 第406行（`_new_form`）
- 第710行（`_theme_page`）
- 第846行（`_pages_dashboard`）
- 第876行（`_new_page_form`）
- 第940行（`_edit_page_form`）

```python
# === 修改前 ===
    value="{csrf_token}"

# === 修改后 ===
    value="{escape_attr(csrf_token)}"
```

**自动化替换命令**（适用于 grep 确认后的批量替换）：

```bash
# 在 admin.py 中，将所有 value="{art.file}" 替换为 value="{escape_attr(art.file)}"
# 注意：需要逐个确认，不要盲目全局替换
```

---

## P1 — 近期修复（1-2 周）

---

### P1-4: 添加 POST 请求体大小限制 ✅ 已完成

**完成情况**: 
- ✅ `AdminApp` 类添加 `MAX_POST_SIZE = 10 * 1024 * 1024` 类属性
- ✅ `_get_post_data` 方法增加 `try/except` 处理无效 `CONTENT_LENGTH`
- ✅ `_get_post_data` 方法增加 POST body 大小检查，超限返回空字典并记录日志

**文件**: `tinypage/admin.py`

**修改位置**: 第1363-1371行，`_get_post_data` 方法

```python
# === 修改前 ===
    def _get_post_data(self, environ: dict) -> dict:
        cl = int(environ.get("CONTENT_LENGTH", 0))
        if cl > 0:
            data = environ["wsgi.input"].read(cl)
            return parse_qs(data.decode("utf-8", errors="replace"))
        return {}

# === 修改后 ===
    MAX_POST_SIZE = 10 * 1024 * 1024  # 10MB

    def _get_post_data(self, environ: dict) -> dict:
        try:
            cl = int(environ.get("CONTENT_LENGTH", 0))
        except (ValueError, TypeError):
            cl = 0
        if cl <= 0:
            return {}
        if cl > self.MAX_POST_SIZE:
            logger.warning(
                f"[BLOCK] POST body too large: {cl} bytes "
                f"(max {self.MAX_POST_SIZE})"
            )
            return {}
        data = environ["wsgi.input"].read(cl)
        return parse_qs(data.decode("utf-8", errors="replace"))
```

同时将 `MAX_POST_SIZE` 作为类属性放在 `AdminApp` 类开头（第94行附近）：

```python
class AdminApp:
    MAX_POST_SIZE = 10 * 1024 * 1024  # 10MB max POST body

    def __init__(self, config: Config):
        ...
```

---

### P1-5: 统一 Mermaid 安全等级为 `strict` ✅ 已完成

**完成情况**: 
- ✅ `parsers/mermaid_init.py` securityLevel 已改为 `'strict'`
- ✅ `generator.py` securityLevel 已为 `'strict'`
- ✅ `core/template.py` securityLevel 已为 `'strict'`

**文件1**: `tinypage/parsers/mermaid_init.py`

```python
# === 修改前 (第13行) ===
      securityLevel: 'loose',

# === 修改后 ===
      securityLevel: 'strict',
```

**文件2**: `tinypage/generator.py` — 无需修改，已经是 `strict`（第216行）。

**验证**: 全局搜索 `securityLevel` 确认只有 `strict`：

```bash
grep -rn "securityLevel" tinypage/
# 应只输出包含 'strict' 的行
```

---

### P1-6: 改进 IP 检测逻辑，默认不信任代理头 ✅ 已完成

**完成情况**: 
- ✅ `security.py` 添加 `_TRUSTED_PROXIES` 全局变量和 `configure_trusted_proxies()` 函数
- ✅ `security.py` 的 `get_real_ip()` 改为仅当请求来自可信代理时读取代理头
- ✅ `server.py` 的 `main()` 中，当 `bind_domain` 设置时自动配置可信代理

**文件**: `tinypage/security.py`

**修改位置**: 第121-128行，`get_real_ip` 函数

```python
# === 修改前 ===
def get_real_ip(environ: dict) -> str:
    x_forwarded_for = environ.get("HTTP_X_FORWARDED_FOR", "")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    x_real_ip = environ.get("HTTP_X_REAL_IP", "")
    if x_real_ip:
        return x_real_ip.strip()
    return environ.get("REMOTE_ADDR", "unknown")

# === 修改后 ===
_TRUSTED_PROXIES: set[str] = set()  # 由 server.py 在启动时配置


def configure_trusted_proxies(proxies: set[str]) -> None:
    """Set trusted reverse proxy IPs. Only these proxies' headers are trusted."""
    global _TRUSTED_PROXIES
    _TRUSTED_PROXIES = proxies


def get_real_ip(environ: dict) -> str:
    """Get client IP, trusting proxy headers only from trusted proxies."""
    remote_addr = environ.get("REMOTE_ADDR", "unknown")

    # 只有当请求来自可信代理时，才读取代理头
    if remote_addr in _TRUSTED_PROXIES:
        x_forwarded_for = environ.get("HTTP_X_FORWARDED_FOR", "")
        if x_forwarded_for:
            # X-Forwarded-For: client, proxy1, proxy2
            # 取最右边的可信代理之前的那个IP
            ips = [ip.strip() for ip in x_forwarded_for.split(",")]
            return ips[0]
        x_real_ip = environ.get("HTTP_X_REAL_IP", "")
        if x_real_ip:
            return x_real_ip.strip()

    return remote_addr
```

**文件**: `tinypage/server.py` — 在 `main()` 中配置可信代理

在第91行 `cfg = cfg.merge(admin_pass=password)` 之后添加：

```python
    # Configure trusted proxies if bind_domain is set (implies reverse proxy)
    if cfg.bind_domain:
        from .security import configure_trusted_proxies
        # 常见的 Docker/本地反向代理地址
        configure_trusted_proxies({"127.0.0.1", "::1", "172.17.0.1"})
```

---

### P1-7: 添加 Basic Auth 暴力破解防护 ✅ 已完成

**完成情况**: 
- ✅ `AuthFailureTracker` 类已添加（max_failures=5, lockout_seconds=300）
- ✅ `AdminApp.__init__` 已初始化 `self.auth_tracker`
- ✅ `__call__` 中先检查锁定状态（返回 429 + Retry-After），再检查 Basic Auth
- ✅ 认证失败时记录 `record_failure`，日志包含尝试次数

**文件**: `tinypage/admin.py`

**步骤1**: 在 `RateLimiter` 类之后（第88行后）添加 `AuthFailureTracker` 类：

```python
class AuthFailureTracker:
    """Track authentication failures and implement progressive lockout."""

    def __init__(
        self,
        max_failures: int = 5,
        lockout_seconds: int = 300,
        cleanup_interval: int = 60,
    ):
        self.max_failures = max_failures
        self.lockout_seconds = lockout_seconds
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()
        self._last_cleanup = time.time()
        self._cleanup_interval = cleanup_interval

    def record_failure(self, client_ip: str) -> None:
        """Record an authentication failure."""
        now = time.time()
        with self._lock:
            if client_ip not in self._failures:
                self._failures[client_ip] = []
            cutoff = now - self.lockout_seconds
            self._failures[client_ip] = [
                t for t in self._failures[client_ip] if t > cutoff
            ]
            self._failures[client_ip].append(now)
            self._maybe_cleanup(now)

    def is_locked_out(self, client_ip: str) -> bool:
        """Check if an IP is currently locked out."""
        now = time.time()
        with self._lock:
            cutoff = now - self.lockout_seconds
            recent = [
                t for t in self._failures.get(client_ip, [])
                if t > cutoff
            ]
            return len(recent) >= self.max_failures

    def get_lockout_remaining(self, client_ip: str) -> int:
        """Get seconds remaining in lockout."""
        now = time.time()
        with self._lock:
            cutoff = now - self.lockout_seconds
            recent = [
                t for t in self._failures.get(client_ip, [])
                if t > cutoff
            ]
            if len(recent) < self.max_failures:
                return 0
            oldest = min(recent)
            return int(self.lockout_seconds - (now - oldest)) + 1

    def _maybe_cleanup(self, now: float) -> None:
        """Periodically clean up expired IP entries."""
        if now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now
        cutoff = now - self.lockout_seconds
        expired = [
            ip for ip, times in self._failures.items()
            if not times or times[-1] < cutoff
        ]
        for ip in expired:
            del self._failures[ip]
```

**步骤2**: 在 `AdminApp.__init__` 中初始化（第94行附近）：

```python
# === 修改前 ===
    def __init__(self, config: Config):
        self.cfg = config
        self.user = config.admin_user
        self.password = config.admin_pass
        self.rate_limiter = RateLimiter(max_requests=60, window_seconds=60)

# === 修改后 ===
    def __init__(self, config: Config):
        self.cfg = config
        self.user = config.admin_user
        self.password = config.admin_pass
        self.rate_limiter = RateLimiter(max_requests=60, window_seconds=60)
        self.auth_tracker = AuthFailureTracker(
            max_failures=5,
            lockout_seconds=300,
        )
```

**步骤3**: 修改 `__call__` 中的认证检查（第117-119行）：

```python
# === 修改前 ===
        if not check_basic_auth(environ, self.user, self.password):
            logger.warning(f"[AUTH-FAIL] Admin access from {client_ip}")
            return self._auth_required(start_response)

# === 修改后 ===
        # Check auth lockout first
        if self.auth_tracker.is_locked_out(client_ip):
            remaining = self.auth_tracker.get_lockout_remaining(client_ip)
            logger.warning(
                f"[AUTH-LOCKOUT] {client_ip} locked out for {remaining}s"
            )
            headers = [
                ("Content-Type", "text/plain"),
                ("Retry-After", str(remaining)),
            ] + get_security_headers()
            start_response("429 Too Many Requests", headers)
            return [b"Account temporarily locked. Try again later."]

        if not check_basic_auth(environ, self.user, self.password):
            self.auth_tracker.record_failure(client_ip)
            failures = len(self.auth_tracker._failures.get(client_ip, []))
            logger.warning(
                f"[AUTH-FAIL] Admin access from {client_ip} "
                f"(attempt {failures}/{self.auth_tracker.max_failures})"
            )
            return self._auth_required(start_response)
```

---

### P1-8: 删除 `core/template.py` 中的死代码 ✅ 已完成

**完成情况**: 
- ✅ `build_article_context`、`build_list_context`、`build_search_context`、`build_standalone_context`、`build_category_context` 五个死代码函数已删除
- ✅ `core/template.py` 仅保留 `render_skeleton`、`load_theme_manifest`、`list_themes`
- ✅ `core/__init__.py` 仅导出这三个函数

**文件**: `tinypage/core/template.py`

**需要删除的函数**（第163-576行，共约414行）：

| 函数名 | 起始行 | 结束行 |
|--------|--------|--------|
| `build_article_context` | 163 | ~260 |
| `build_list_context` | ~263 | ~340 |
| `build_search_context` | ~343 | ~400 |
| `build_standalone_context` | ~403 | ~480 |
| `build_category_context` | ~483 | ~576 |

**操作**: 删除第163行到第576行的全部内容。保留 `_PAGE_SKELETON`、`render_skeleton`、`load_theme_manifest`、`list_themes` 这些在用的函数。

**同步修改**: `tinypage/core/__init__.py` — 移除死代码的导出：

```python
# === 修改前 ===
from .template import (
    render_skeleton,
    load_theme_manifest,
    list_themes,
    build_article_context,
    build_list_context,
    build_search_context,
    build_standalone_context,
    build_category_context,
)

# === 修改后 ===
from .template import (
    render_skeleton,
    load_theme_manifest,
    list_themes,
)
```

**验证**: 全局搜索这些函数名，确认无其他调用：

```bash
grep -rn "build_article_context\|build_list_context\|build_search_context\|build_standalone_context\|build_category_context" tinypage/
```

---

### P1-9: 统一 `escape_html` 为单一实现 ✅ 已完成

**完成情况**: 
- ✅ `parsers/bidirectional_links.py` — 本地 `escape_html` 已删除，改用 `from ..security import escape_html`
- ✅ `parsers/footnotes.py` — 本地 `escape_html` 已删除，改用 `from ..security import escape_html`
- ✅ `parsers/toc.py` — 本地 `escape_html` 已删除，改用 `from ..security import escape_html`
- ✅ 全局搜索确认 `def escape_html` 仅存在于 `security.py:34`

**需要修改的文件和行号**:

**9a. `tinypage/parsers/bidirectional_links.py`** — 删除第87-95行的本地 `escape_html`，改用 `security.escape_html`

```python
# === 修改前 (第1-5行 import 区域) ===
import re
from typing import Optional

# === 修改后 ===
import re
from typing import Optional
from ..security import escape_html
```

```python
# === 删除 (第87-95行) ===
def escape_html(text: str) -> str:
    """Basic HTML escaping for display text."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )
```

**9b. `tinypage/parsers/footnotes.py`** — 删除本地 `escape_html`，改用 `security.escape_html`

```python
# === 修改前 (第1-5行 import 区域) ===
import re
from dataclasses import dataclass
from typing import Optional

# === 修改后 ===
import re
from dataclasses import dataclass
from typing import Optional
from ..security import escape_html
```

找到并删除 `footnotes.py` 中的 `escape_html` 函数（约第109-116行）：

```python
# === 删除 ===
def escape_html(text: str) -> str:
    """Basic HTML escaping for display text."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )
```

**9c. `tinypage/parsers/toc.py`** — 删除本地 `escape_html`，改用 `security.escape_html`

```python
# === 修改前 (第1-5行 import 区域) ===
import re
from dataclasses import dataclass
from typing import Optional

# === 修改后 ===
import re
from dataclasses import dataclass
from typing import Optional
from ..security import escape_html
```

找到并删除 `toc.py` 中的 `escape_html` 函数（约第143-150行）。

**验证**: 搜索确认无遗漏：

```bash
grep -rn "def escape_html" tinypage/
# 应只剩 security.py:34 的一处
```

---

### P1-10: 修复速率限制器内存泄漏 ✅ 已完成

**完成情况**: 
- ✅ `RateLimiter` 添加 `MAX_TRACKED_IPS = 10000` 类属性
- ✅ 添加 `_cleanup()` 方法，定期清理过期 IP 条目
- ✅ 添加 `_last_cleanup` 和 `_cleanup_interval` 字段
- ✅ `is_allowed()` 方法中调用 `_cleanup()`，新 IP 数量达上限时拒绝

**文件**: `tinypage/admin.py`

**修改位置**: `RateLimiter` 类（第48-88行）

```python
# === 修改前 ===
class RateLimiter:
    """Simple in-memory rate limiter using sliding window."""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def is_allowed(self, client_ip: str) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            if client_ip not in self._requests:
                self._requests[client_ip] = []
            self._requests[client_ip] = [
                t for t in self._requests[client_ip] if t > cutoff
            ]
            if len(self._requests[client_ip]) >= self.max_requests:
                return False
            self._requests[client_ip].append(now)
            return True

    def get_retry_after(self, client_ip: str) -> int:
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            if client_ip not in self._requests:
                return 0
            valid_times = [t for t in self._requests[client_ip] if t > cutoff]
            if not valid_times:
                return 0
            oldest = min(valid_times)
            return int(self.window_seconds - (now - oldest)) + 1

# === 修改后 ===
class RateLimiter:
    """In-memory rate limiter using sliding window with automatic cleanup."""

    MAX_TRACKED_IPS = 10000  # 防止字典无限增长

    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = {}
        self._lock = threading.Lock()
        self._last_cleanup = time.time()
        self._cleanup_interval = 60  # 每60秒清理一次

    def _cleanup(self, now: float) -> None:
        """Remove expired IP entries to prevent memory leak."""
        if now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now
        cutoff = now - self.window_seconds
        expired = [
            ip for ip, times in self._requests.items()
            if not times or times[-1] < cutoff
        ]
        for ip in expired:
            del self._requests[ip]

    def is_allowed(self, client_ip: str) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            self._cleanup(now)
            if client_ip not in self._requests:
                # 如果 IP 数量已达上限，拒绝新 IP（保留已有 IP 的正常访问）
                if len(self._requests) >= self.MAX_TRACKED_IPS:
                    return False
                self._requests[client_ip] = []
            self._requests[client_ip] = [
                t for t in self._requests[client_ip] if t > cutoff
            ]
            if len(self._requests[client_ip]) >= self.max_requests:
                return False
            self._requests[client_ip].append(now)
            return True

    def get_retry_after(self, client_ip: str) -> int:
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            if client_ip not in self._requests:
                return 0
            valid_times = [t for t in self._requests[client_ip] if t > cutoff]
            if not valid_times:
                return 0
            oldest = min(valid_times)
            return int(self.window_seconds - (now - oldest)) + 1
```

---

## P2 — 中期改进（1-2 月）

---

### P2-11: 抽取公共页面上下文构建器，消除 generator 重复代码

**文件**: `tinypage/generator.py`

**核心思路**: 抽取 `_build_common_context()` 辅助函数，返回5个页面生成函数共享的上下文字典。

**步骤1**: 在 `_nav_links` 函数之后（约第96行后）添加辅助函数：

```python
def _build_common_context(
    config: Optional[Config],
    theme_css: str,
    dark_css: str,
    has_dark: bool,
    standalones: list[ArticleMeta] | None,
    current_path: str = "",
) -> dict:
    """Build common page context shared by all page generation functions.

    Returns a dict with keys:
        cfg, site_title, theme_css, dark_css, has_dark,
        dark_mode_meta, dark_mode_script, pwa_meta, pwa_manifest,
        vt_meta, search_script, nav, theme_toggle
    """
    cfg = config or Config()
    if not theme_css:
        theme_css, dark_css, has_dark = load_theme_css(cfg.theme_dir)
    site_title = escape_html(cfg.site_title)

    dark_mode_meta = '<meta name="color-scheme" content="light dark">' if has_dark else ""
    dark_mode_script = (
        """<script>(function(){try{var m=localStorage.getItem('theme');if(m==='dark'||(!m&&window.matchMedia('(prefers-color-scheme: dark)').matches)){document.documentElement.classList.add('dark')}}catch(e){}})();</script>"""
        if has_dark else ""
    )

    if cfg.enable_pwa:
        pwa_meta = f'<meta name="theme-color" content="{escape_attr(cfg.pwa_theme_color)}" media="(prefers-color-scheme: light)"><meta name="theme-color" content="{escape_attr(cfg.pwa_bg_color)}" media="(prefers-color-scheme: dark)">'

        pwa_manifest = '<link rel="manifest" href="/manifest.json">'
    else:
        pwa_meta = ""
        pwa_manifest = ""

    vt_meta = '<meta name="view-transition" content="same-origin">' if cfg.enable_view_transitions else ""
    search_script = '<script src="/search.js" defer></script>' if cfg.enable_search else ""
    nav = _nav_links(cfg, standalones, current_path)
    theme_toggle = '<button class="theme-toggle" aria-label="切换主题" onclick="document.documentElement.classList.toggle(\'dark\');try{localStorage.setItem(\'theme\',document.documentElement.classList.contains(\'dark\')?\'dark\':\'light\')}catch(e){}">🌓</button>' if has_dark else ''

    return {
        "cfg": cfg,
        "site_title": site_title,
        "theme_css": theme_css,
        "dark_css": dark_css,
        "has_dark": has_dark,
        "dark_mode_meta": dark_mode_meta,
        "dark_mode_script": dark_mode_script,
        "pwa_meta": pwa_meta,
        "pwa_manifest": pwa_manifest,
        "vt_meta": vt_meta,
        "search_script": search_script,
        "nav": nav,
        "theme_toggle": theme_toggle,
    }
```

**步骤2**: 重写5个页面生成函数以使用公共上下文。以 `generate_search_page` 为例（最简单的）：

```python
# === 修改前 (第401-455行) ===
def generate_search_page(config: Optional[Config] = None, theme_css: str = "", dark_css: str = "", has_dark: bool = False, standalones: list[ArticleMeta] | None = None) -> str:
    cfg = config or Config()
    if not theme_css:
        theme_css, dark_css, has_dark = load_theme_css(cfg.theme_dir)
    site_title = escape_html(cfg.site_title)

    dark_mode_meta = '<meta name="color-scheme" content="light dark">' if has_dark else ""
    dark_mode_script = (
        """<script>(function(){try{var m=localStorage.getItem('theme');if(m==='dark'||(!m&&window.matchMedia('(prefers-color-scheme: dark)').matches)){document.documentElement.classList.add('dark')}}catch(e){}})();</script>"""
        if has_dark else ""
    )
    pwa_meta = f'<meta name="theme-color" content="{escape_attr(cfg.pwa_theme_color)}">'
    pwa_manifest = '<link rel="manifest" href="/manifest.json">' if cfg.enable_pwa else ""
    nav = _nav_links(cfg, standalones)
    theme_toggle = '<button class="theme-toggle" aria-label="切换主题" onclick="document.documentElement.classList.toggle(\'dark\');try{localStorage.setItem(\'theme\',document.documentElement.classList.contains(\'dark\')?\'dark\':\'light\')}catch(e){}">🌓</button>' if has_dark else ''

    # ... body_content 构建 ...

    return render_skeleton(
        page_type="search",
        site_title=site_title,
        page_title=f"搜索 - {site_title}",
        description=f"搜索 {site_title}",
        body_content=body_content,
        theme_css=theme_css,
        dark_css=dark_css,
        has_dark=has_dark,
        nav_links=nav,
        footer_text=escape_html(cfg.footer_text),
        lang=cfg.lang,
        dark_mode_meta=dark_mode_meta,
        pwa_meta=pwa_meta,
        vt_meta="",
        og_html="",
        pwa_manifest=pwa_manifest,
        dark_mode_script=dark_mode_script,
        search_script='<script src="/search.js" defer></script>',
        mermaid_script="",
        json_ld_html="",
        theme_toggle=theme_toggle,
    )

# === 修改后 ===
def generate_search_page(
    config: Optional[Config] = None,
    theme_css: str = "",
    dark_css: str = "",
    has_dark: bool = False,
    standalones: list[ArticleMeta] | None = None,
) -> str:
    ctx = _build_common_context(config, theme_css, dark_css, has_dark, standalones)
    cfg = ctx["cfg"]

    body_content = f"""<div class="search-container">
<h1>搜索</h1>
<div class="search-box">
  <input type="text" id="search-input" placeholder="输入关键词..." autofocus>
</div>
<div id="search-results"></div>
</div>"""

    return render_skeleton(
        page_type="search",
        site_title=ctx["site_title"],
        page_title=f"搜索 - {ctx['site_title']}",
        description=f"搜索 {cfg.site_title}",
        body_content=body_content,
        theme_css=ctx["theme_css"],
        dark_css=ctx["dark_css"],
        has_dark=ctx["has_dark"],
        nav_links=ctx["nav"],
        footer_text=escape_html(cfg.footer_text),
        lang=cfg.lang,
        dark_mode_meta=ctx["dark_mode_meta"],
        pwa_meta=ctx["pwa_meta"],
        vt_meta="",
        og_html="",
        pwa_manifest=ctx["pwa_manifest"],
        dark_mode_script=ctx["dark_mode_script"],
        search_script='<script src="/search.js" defer></script>',
        mermaid_script="",
        json_ld_html="",
        theme_toggle=ctx["theme_toggle"],
    )
```

其他4个函数按相同模式重构，将重复的上下文构建部分替换为 `ctx = _build_common_context(...)`，然后在 `render_skeleton()` 调用中使用 `ctx["xxx"]` 引用。

**预估减少代码**: ~141行重复代码 → ~30行辅助函数定义，净减 ~110行。

---

### P2-12: 管理后台 HTML 模板提取为 Jinja2

**注意**: 此任务工作量较大（~8h），建议分步骤执行。

**步骤1**: 创建模板目录和基础模板

```bash
mkdir -p tinypage/templates/admin
```

**步骤2**: 创建 `tinypage/templates/admin/base.html`（Jinja2 布局模板）

从 `admin.py` 第1176-1327行的 `_render_page` 方法中提取 HTML 结构：

```html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title | e }} - TinyPage Admin</title>
{% if extra_script %}
<script src="{{ htmx_cdn }}"></script>
{% endif %}
<style>
/* 从 admin.py 第1185-1220行复制 CSS 内容到此处 */
:root { --primary: #2c3e50; ... }
/* ... 完整 CSS ... */
</style>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github.min.css" id="hljs-light">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github-dark.min.css" id="hljs-dark" media="(prefers-color-scheme: dark)">
</head>
<body>
<nav class="admin-nav">
  <a href="/">Dashboard</a>
  <a href="/new">New Article</a>
  <a href="/new-page">New Page</a>
  <a href="/theme">Theme</a>
  <button class="theme-toggle" onclick="document.documentElement.classList.toggle('dark');try{localStorage.setItem('theme',document.documentElement.classList.contains('dark')?'dark':'light')}catch(e){}">🌓</button>
</nav>
<main>
{% block content %}{{ body | safe }}{% endblock %}
</main>
<script>
/* 从 admin.py 第1223-1321行复制 JS 内容到此处 */
function handleDrop(e) { ... }
/* ... 完整 JS ... */
</script>
</body>
</html>
```

**步骤3**: 创建各页面模板

```bash
# 为每个页面创建 Jinja2 模板
touch tinypage/templates/admin/dashboard.html
touch tinypage/templates/admin/edit.html
touch tinypage/templates/admin/new.html
touch tinypage/templates/admin/pages.html
touch tinypage/templates/admin/edit_page.html
touch tinypage/templates/admin/new_page.html
touch tinypage/templates/admin/theme.html
```

**步骤4**: 修改 `AdminApp.__init__` 初始化 Jinja2 环境

```python
# 在 AdminApp.__init__ 中添加:
from jinja2 import Environment, FileSystemLoader
import os

template_dir = os.path.join(os.path.dirname(__file__), "templates", "admin")
self.jinja_env = Environment(
    loader=FileSystemLoader(template_dir),
    autoescape=True,  # 自动转义，防止 XSS
)
```

**步骤5**: 逐步替换各方法中的 HTML 构建

以 `_dashboard` 为例：

```python
# === 修改前: 手动拼接 HTML ===
def _dashboard(self, environ, start_response):
    # ... 100+ 行 HTML 拼接 ...

# === 修改后: 使用 Jinja2 模板 ===
def _dashboard(self, environ, start_response):
    csrf_token = self._get_existing_csrf(environ)
    articles = list_articles(self.cfg.article_dir, self.cfg.max_file_size)
    articles = [a for a in articles if not a.is_draft]

    template = self.jinja_env.get_template("dashboard.html")
    html = template.render(
        articles=articles,
        csrf_token=csrf_token,
        escape_html=escape_html,
        escape_attr=escape_attr,
    )

    headers = [
        ("Content-Type", "text/html; charset=utf-8"),
        get_csrf_cookie_header(csrf_token),
        get_csp_header(),
    ] + get_security_headers()
    start_response("200 OK", headers)
    return [html.encode("utf-8")]
```

**步骤6**: 验证 `pyproject.toml` 中已有 `jinja2` 依赖：

```bash
grep "jinja2" pyproject.toml
# 如果没有，添加: jinja2>=3.0
```

---

### P2-13: 解除 generator ↔ content 循环依赖

**问题**: `content.py` 内部懒导入 `generator.py`，`generator.py` 内部懒导入 `content.py`。这是架构问题的症状。

**解决方案**: 将 HTML 生成职责从 `content.py` 中完全剥离，由上层（`server.py`/`cli.py`）协调。

**步骤1**: 在 `content.py` 中，将 `write_article` 和 `regenerate_all_articles` 中对 `generator` 的调用改为回调/参数注入。

修改 `write_article` 签名（第275行）：

```python
# === 修改前 ===
def write_article(
    title: str,
    date: str,
    content: str,
    tags: str = "",
    summary: str = "",
    category: str = "",
    status: str = "published",
    config: Optional[Config] = None,
) -> tuple[bool, str]:

# === 修改后 ===
from typing import Callable, Optional

def write_article(
    title: str,
    date: str,
    content: str,
    tags: str = "",
    summary: str = "",
    category: str = "",
    status: str = "published",
    config: Optional[Config] = None,
    html_renderer: Optional[Callable] = None,
) -> tuple[bool, str]:
```

在 `write_article` 函数体中，将：

```python
# 原来的懒导入
from .generator import generate_article_html
```

改为：

```python
    if html_renderer is None:
        from .generator import generate_article_html as html_renderer
```

然后所有调用 `generate_article_html` 的地方改为 `html_renderer`。

**步骤2**: 同样修改 `regenerate_all_articles` 的签名，添加 `html_renderer` 参数。

**步骤3**: 在 `admin.py` 和 `cli.py` 中，显式传入 `html_renderer`：

```python
# admin.py 中的调用
from .generator import generate_article_html
success, msg = write_article(..., html_renderer=generate_article_html)
```

**步骤4**: 删除 `generator.py` 中的全局懒加载变量（第16-33行），改为在 `generate_static_pages` 函数内部导入：

```python
# === 删除 ===
_render_markdown = None
_extract_body = None

def _get_render_markdown():
    global _render_markdown
    if _render_markdown is None:
        from .parsers import render_markdown as _rm
        _render_markdown = _rm
    return _render_markdown

def _get_extract_body():
    global _extract_body
    if _extract_body is None:
        from .content import _extract_body_from_html as _eb
        _extract_body = _eb
    return _extract_body

# === 在 generate_static_pages 函数内部直接导入 ===
def generate_static_pages(articles, config, standalones=None):
    from .parsers import render_markdown
    from .content import _extract_body_from_html
    # ... 使用 render_markdown 和 _extract_body_from_html ...
```

---

### P2-14: 添加核心安全函数的单元测试

**步骤1**: 创建测试目录和文件

```bash
mkdir -p tests
touch tests/__init__.py
touch tests/test_security.py
touch tests/test_content.py
touch tests/test_generator.py
touch tests/conftest.py
```

**步骤2**: 编写 `tests/test_security.py`

```python
"""Unit tests for tinypage.security module."""

import time
import base64
import hashlib
import hmac
import pytest
from pathlib import Path
from tinypage.security import (
    escape_html,
    escape_attr,
    validate_filename,
    validate_date_format,
    validate_content,
    validate_url_protocol,
    safe_path_check,
    generate_csrf_token,
    validate_csrf_token,
    check_basic_auth,
    get_real_ip,
    configure_trusted_proxies,
)


class TestEscapeHtml:
    def test_basic_chars(self):
        assert escape_html("<script>") == "&lt;script&gt;"

    def test_quotes(self):
        assert escape_html('"hello"') == "&quot;hello&quot;"

    def test_ampersand(self):
        assert escape_html("a&b") == "a&amp;b"

    def test_chinese_preserved(self):
        assert escape_html("你好世界") == "你好世界"

    def test_empty_string(self):
        assert escape_html("") == ""


class TestEscapeAttr:
    def test_double_quotes(self):
        result = escape_attr('value="x"')
        assert '"' not in result
        assert "&quot;" in result

    def test_xss_in_attr(self):
        result = escape_attr('"><script>alert(1)</script>')
        assert "<script>" not in result


class TestValidateFilename:
    def test_valid_filename(self):
        assert validate_filename("2026-05-16-my-article.html") is True

    def test_chinese_filename(self):
        assert validate_filename("2026-05-16-你好世界.html") is True

    def test_no_date_prefix(self):
        assert validate_filename("my-article.html") is False

    def test_path_traversal(self):
        assert validate_filename("../../etc/passwd") is False

    def test_empty(self):
        assert validate_filename("") is False

    def test_wrong_extension(self):
        assert validate_filename("2026-05-16-article.txt") is False

    def test_sql_injection(self):
        assert validate_filename("2026-05-16-'; DROP TABLE--.html") is False


class TestValidateUrlProtocol:
    def test_https(self):
        assert validate_url_protocol("https://example.com") is True

    def test_javascript_xss(self):
        assert validate_url_protocol("javascript:alert(1)") is False

    def test_data_uri(self):
        assert validate_url_protocol("data:text/html,<h1>hi</h1>") is False

    def test_protocol_relative(self):
        assert validate_url_protocol("//example.com/path") is True

    def test_empty(self):
        assert validate_url_protocol("") is False

    def test_mailto(self):
        assert validate_url_protocol("mailto:user@example.com") is True


class TestSafePathCheck:
    def test_valid_path(self, tmp_path):
        result, resolved = safe_path_check("test.html", tmp_path)
        assert result is True
        assert resolved is not None

    def test_path_traversal(self, tmp_path):
        result, resolved = safe_path_check("../../etc/passwd", tmp_path)
        assert result is False

    def test_absolute_path_escape(self, tmp_path):
        result, resolved = safe_path_check("/etc/passwd", tmp_path)
        assert result is False


class TestValidateContent:
    def test_normal_content(self):
        assert validate_content("Hello, world!") is True

    def test_too_long(self):
        assert validate_content("x" * 50001) is False

    def test_binary_content(self):
        binary_like = "\x00\x01\x02" * 1000
        assert validate_content(binary_like) is False

    def test_not_string(self):
        assert validate_content(123) is False


class TestCsrfToken:
    def test_generate_and_validate(self):
        token = generate_csrf_token()
        environ = {
            "HTTP_COOKIE": f"csrf_token={token}",
            "HTTP_ORIGIN": "http://127.0.0.1:8081",
            "REMOTE_ADDR": "127.0.0.1",
        }
        assert validate_csrf_token(environ, token, admin_port=8081) is True

    def test_invalid_token(self):
        environ = {"REMOTE_ADDR": "127.0.0.1"}
        assert validate_csrf_token(environ, "invalid_token", admin_port=8081) is False

    def test_cookie_mismatch(self):
        token = generate_csrf_token()
        environ = {
            "HTTP_COOKIE": "csrf_token=different_token",
            "HTTP_ORIGIN": "http://127.0.0.1:8081",
            "REMOTE_ADDR": "127.0.0.1",
        }
        assert validate_csrf_token(environ, token, admin_port=8081) is False


class TestBasicAuth:
    def test_valid_credentials(self):
        import base64
        creds = base64.b64encode(b"admin:secret123").decode()
        environ = {"HTTP_AUTHORIZATION": f"Basic {creds}"}
        assert check_basic_auth(environ, "admin", "secret123") is True

    def test_wrong_password(self):
        import base64
        creds = base64.b64encode(b"admin:wrong").decode()
        environ = {"HTTP_AUTHORIZATION": f"Basic {creds}"}
        assert check_basic_auth(environ, "admin", "secret123") is False

    def test_missing_header(self):
        assert check_basic_auth({}, "admin", "secret123") is False


class TestGetRealIp:
    def test_no_proxy(self):
        environ = {"REMOTE_ADDR": "192.168.1.1"}
        assert get_real_ip(environ) == "192.168.1.1"

    def test_with_trusted_proxy(self):
        configure_trusted_proxies({"127.0.0.1"})
        environ = {
            "REMOTE_ADDR": "127.0.0.1",
            "HTTP_X_FORWARDED_FOR": "10.0.0.1, 10.0.0.2",
        }
        assert get_real_ip(environ) == "10.0.0.1"

    def test_untrusted_proxy_ignores_header(self):
        configure_trusted_proxies(set())
        environ = {
            "REMOTE_ADDR": "10.0.0.1",
            "HTTP_X_FORWARDED_FOR": "spoofed_ip",
        }
        assert get_real_ip(environ) == "10.0.0.1"
```

**步骤3**: 编写 `tests/conftest.py`

```python
import pytest
from pathlib import Path


@pytest.fixture
def tmp_articles_dir(tmp_path):
    """Create a temporary articles directory."""
    articles = tmp_path / "article"
    articles.mkdir()
    return articles


@pytest.fixture
def sample_article_content():
    return """<!-- title: Test Article -->
<!-- date: 2026-05-16 12:00 -->
<!-- tags: test, demo -->
<!-- category: testing -->
<!-- status: published -->
<!-- markdown: Hello **world** this is a test. -->
<html><body><p>Hello <strong>world</strong> this is a test.</p></body></html>"""
```

**步骤4**: 添加测试运行配置到 `pyproject.toml`

```toml
[project.optional-dependencies]
test = ["pytest>=7.0", "pytest-cov>=4.0"]
```

**步骤5**: 运行测试

```bash
pip install -e ".[test]"
pytest tests/ -v
```

---

### P2-15: 管理后台路由重构为路由表

**文件**: `tinypage/admin.py`

**修改位置**: `AdminApp.__call__` 方法（第100-209行）

**步骤1**: 在 `AdminApp` 类中定义路由表（放在 `__init__` 之后）：

```python
    _GET_ROUTES: dict[str, str] = {
        "/": "_dashboard",
        "/dashboard": "_dashboard",
        "/pages": "_pages_dashboard",
        "/new": "_new_form",
        "/new-page": "_new_page_form",
        "/edit": "_edit_form",
        "/edit-page": "_edit_page_form",
        "/theme": "_theme_page",
    }

    _POST_ROUTES: dict[str, str] = {
        "/upload": "_upload",
        "/create": "_create",
        "/create-page": "_create_page",
        "/save": "_save",
        "/save-page": "_save_page",
        "/delete": "_delete",
        "/delete-page": "_delete_page",
        "/regen": "_regen",
        "/preview": "_live_preview",
        "/set-theme": "_set_theme",
        "/ai-assist": "_ai_assist",
        "/translate": "_translate",
    }

    _CSRF_EXEMPT_POST = {"/upload"}
```

**步骤2**: 重写 `__call__` 方法：

```python
    def __call__(self, environ: dict, start_response):
        method = environ.get("REQUEST_METHOD", "GET")
        path = environ.get("PATH_INFO", "/")
        client_ip = get_real_ip(environ)

        if not self.rate_limiter.is_allowed(client_ip):
            retry_after = self.rate_limiter.get_retry_after(client_ip)
            logger.warning(f"[RATE-LIMIT] Blocked {client_ip}, retry after {retry_after}s")
            headers = [
                ("Content-Type", "text/plain"),
                ("Retry-After", str(retry_after)),
            ] + get_security_headers()
            start_response("429 Too Many Requests", headers)
            return [b"Rate limit exceeded. Please try again later."]

        # Auth lockout check
        if self.auth_tracker.is_locked_out(client_ip):
            remaining = self.auth_tracker.get_lockout_remaining(client_ip)
            logger.warning(f"[AUTH-LOCKOUT] {client_ip} locked out for {remaining}s")
            headers = [
                ("Content-Type", "text/plain"),
                ("Retry-After", str(remaining)),
            ] + get_security_headers()
            start_response("429 Too Many Requests", headers)
            return [b"Account temporarily locked. Try again later."]

        if not check_basic_auth(environ, self.user, self.password):
            self.auth_tracker.record_failure(client_ip)
            logger.warning(f"[AUTH-FAIL] Admin access from {client_ip}")
            return self._auth_required(start_response)

        try:
            if method == "GET":
                return self._handle_get(environ, start_response, path)
            if method == "POST":
                return self._handle_post(environ, start_response, path)
            return self._error(start_response, "405 Method Not Allowed", "Method not allowed")
        except Exception as e:
            logger.error(f"[ADMIN-ERROR] {e}")
            return self._error(start_response, "500 Internal Server Error", "Server error")

    def _handle_get(self, environ, start_response, path):
        """Dispatch GET requests."""
        from .frontend import _INJECTED_ASSETS

        if path in _INJECTED_ASSETS:
            ct, data = _INJECTED_ASSETS[path]
            headers = [
                ("Content-Type", ct),
                ("Content-Length", str(len(data))),
                ("Cache-Control", "max-age=3600"),
            ] + get_security_headers()
            start_response("200 OK", headers)
            return [data]

        handler_name = self._GET_ROUTES.get(path)
        if handler_name:
            handler = getattr(self, handler_name)
            return handler(environ, start_response)

        return self._send_404(start_response)

    def _handle_post(self, environ, start_response, path):
        """Dispatch POST requests with CSRF validation."""
        handler_name = self._POST_ROUTES.get(path)
        if not handler_name:
            return self._send_404(start_response)

        post_data = self._get_post_data(environ)
        csrf_token = post_data.get("csrf_token", [""])[0]

        # CSRF validation (with special handling for JSON endpoints)
        is_valid_csrf = validate_csrf_token(
            environ, csrf_token, self.cfg.admin_port, self.cfg.bind_domain
        )

        if path in self._CSRF_EXEMPT_POST:
            if not is_valid_csrf:
                headers = [("Content-Type", "application/json")] + get_security_headers()
                start_response("403 Forbidden", headers)
                return [json.dumps({"success": False, "error": "CSRF validation failed"}).encode("utf-8")]
        else:
            if not is_valid_csrf:
                return self._error(start_response, "403 Forbidden", "CSRF validation failed")

        handler = getattr(self, handler_name)

        # Routes that need post_data
        needs_post_data = path not in {"/regen"}
        if needs_post_data:
            return handler(environ, start_response, post_data)
        return handler(environ, start_response)
```

---

### P2-16: Config 添加验证逻辑 ✅ 已完成

**完成情况**: 
- ✅ `Config` 类添加 `__post_init__` 方法（兼容 `frozen=True`），验证端口范围、page_size、max_file_size、max_title_length、max_content_length
- ✅ `validate_startup()` 方法已存在（P0-2 实现），检查空密码和短密码

**文件**: `tinypage/config.py`

在 `Config` 类中添加 `__post_init__` 方法（因为 `frozen=True`，需在 `__post_init__` 中做验证）：

```python
    def __post_init__(self):
        """Validate configuration values."""
        if not (1 <= self.static_port <= 65535):
            raise ValueError(f"Invalid static_port: {self.static_port}. Must be 1-65535.")
        if not (1 <= self.admin_port <= 65535):
            raise ValueError(f"Invalid admin_port: {self.admin_port}. Must be 1-65535.")
        if self.admin_port == self.static_port:
            raise ValueError(f"admin_port and static_port must differ (both {self.admin_port}).")
        if self.page_size < 1:
            raise ValueError(f"Invalid page_size: {self.page_size}. Must be >= 1.")
        if self.max_file_size < 1024:
            raise ValueError(f"Invalid max_file_size: {self.max_file_size}. Must be >= 1024.")
        if self.max_title_length < 1:
            raise ValueError(f"Invalid max_title_length: {self.max_title_length}. Must be >= 1.")
        if self.max_content_length < 100:
            raise ValueError(f"Invalid max_content_length: {self.max_content_length}. Must be >= 100.")
```

---

## P3 — 长期演进

---

### P3-17: CSP 升级为 nonce-based

**目标**: 移除 `unsafe-inline`，使用 nonce 方式加载内联脚本。

**文件1**: `tinypage/security.py` — 修改 `get_csp_header`

```python
# === 修改前 ===
def get_csp_header() -> Tuple[str, str]:
    """Content Security Policy header."""
    policy = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self';"
    )
    return ("Content-Security-Policy", policy)

# === 修改后 ===
def get_csp_header(nonce: str = "") -> Tuple[str, str]:
    """Content Security Policy header with optional nonce support."""
    script_src = "'self'"
    style_src = "'self'"
    if nonce:
        script_src += f" 'nonce-{nonce}'"
        style_src += f" 'nonce-{nonce}'"
    else:
        # Fallback for non-nonce mode (backwards compatibility)
        script_src += " 'unsafe-inline'"
        style_src += " 'unsafe-inline'"

    policy = (
        f"default-src 'self'; "
        f"style-src {style_src}; "
        f"img-src 'self' data: https:; "
        f"font-src 'self'; "
        f"script-src {script_src}; "
        f"connect-src 'self'; "
        f"frame-ancestors 'none'; "
        f"base-uri 'self';"
    )
    return ("Content-Security-Policy", policy)
```

**文件2**: `tinypage/admin.py` — 修改 `_render_page`

在 `_render_page` 中生成 nonce 并应用到所有 `<script>` 和 `<style>` 标签：

```python
    def _render_page(self, start_response, title: str, body: str, csrf_token: str, extra_script: bool = False):
        import secrets
        nonce = secrets.token_urlsafe(16)

        htmx_script = f'<script src="{HTMX_CDN}" nonce="{nonce}"></script>' if extra_script else ""
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape_html(title)} - TinyPage Admin</title>
{htmx_script}
<style nonce="{nonce}">
/* ... CSS content ... */
</style>
<!-- ... rest of head ... -->
</head>
<body>
<!-- ... body ... -->
<script nonce="{nonce}">
// ... JS content ...
</script>
</body>
</html>"""

        headers = [
            ("Content-Type", "text/html; charset=utf-8"),
            get_csrf_cookie_header(csrf_token),
            get_csp_header(nonce=nonce),  # 传入 nonce
        ] + get_security_headers()
        start_response("200 OK", headers)
        return [html.encode("utf-8")]
```

**文件3**: `tinypage/generator.py` — 在 `render_skeleton` 调用中传入 nonce

需要在 `render_skeleton` 函数（`core/template.py`）中添加 `nonce` 参数支持：

```python
def render_skeleton(
    page_type: str,
    *,
    # ... 现有参数 ...
    nonce: str = "",
) -> str:
```

在 `_PAGE_SKELETON` 模板中，将 `<style>` 和 `<script>` 标签改为：

```python
    <style{nonce_attr}>
        {theme_css}
        {dark_css}
    </style>
    <script{nonce_attr}>
        {dark_mode_script}
    </script>
```

其中 `nonce_attr = f' nonce="{nonce}"' if nonce else ""`。

---

### P3-18: 管理后台认证升级为 session-based

**当前问题**: Basic Auth 每次请求都传输密码，无法实现精细的会话管理。

**方案**: 使用 HMAC 签名的 session cookie。

**步骤1**: 在 `security.py` 中添加 session 管理

```python
_SESSION_SECRET = secrets.token_bytes(32)
_SESSION_MAX_AGE = 86400  # 24 hours


def create_session(username: str) -> Tuple[str, str]:
    """Create a signed session cookie. Returns (cookie_value, cookie_header)."""
    import struct
    timestamp = int(time.time())
    payload = f"{username}:{timestamp}"
    signature = hmac.new(
        _SESSION_SECRET, payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    session_value = base64.urlsafe_b64encode(
        f"{payload}:{signature}".encode("utf-8")
    ).decode("ascii")
    header = (
        "Set-Cookie",
        f"tinypage_session={session_value}; Path=/; HttpOnly; "
        f"SameSite=Strict; Max-Age={_SESSION_MAX_AGE}"
        f"{'; Secure' if False else ''}"  # 根据是否 HTTPS 添加 Secure
    )
    return session_value, header


def validate_session(environ: dict) -> Optional[str]:
    """Validate session cookie. Returns username if valid, None otherwise."""
    cookie_header = environ.get("HTTP_COOKIE", "")
    for cookie in cookie_header.split(";"):
        cookie = cookie.strip()
        if cookie.startswith("tinypage_session="):
            try:
                decoded = base64.urlsafe_b64decode(cookie[18:]).decode("utf-8")
                parts = decoded.rsplit(":", 1)
                if len(parts) != 2:
                    return None
                payload, signature = parts
                expected_sig = hmac.new(
                    _SESSION_SECRET, payload.encode("utf-8"), hashlib.sha256
                ).hexdigest()
                if not hmac.compare_digest(signature, expected_sig):
                    return None
                username, ts_str = payload.rsplit(":", 1)
                timestamp = int(ts_str)
                if time.time() - timestamp > _SESSION_MAX_AGE:
                    return None
                return username
            except Exception:
                return None
    return None
```

**步骤2**: 修改 `AdminApp.__call__` 的认证逻辑

```python
# 替换 Basic Auth 检查为 session 检查 + 登录表单
def __call__(self, environ, start_response):
    # ... rate limit check ...

    # 先尝试 session 认证
    username = validate_session(environ)
    if not username:
        # 再尝试 Basic Auth（兼容 API 调用）
        if not check_basic_auth(environ, self.user, self.password):
            return self._login_page(start_response)
        username = self.user
        # Basic Auth 首次成功后自动创建 session
```

**步骤3**: 添加登录页面 `_login_page`

```python
def _login_page(self, start_response, error: str = ""):
    """Render login form."""
    # HTML 登录表单，POST /login
    ...
```

**步骤4**: 添加 `/login` 和 `/logout` 路由

```python
# _POST_ROUTES 中添加:
"/login": "_login",

# _GET_ROUTES 中添加:
"/logout": "_logout",
```

---

### P3-19: 文章存储格式从 HTML 注释迁移到独立 .md 文件

**当前问题**: Markdown 内容存储在 HTML 注释 `<!-- markdown: ... -->` 中，如果内容包含 `-->` 会破坏解析。

**方案**: 分离源文件（`.md`）和生成文件（`.html`），源文件使用 YAML front matter。

**步骤1**: 定义新的源文件格式

```
# 文件: pages/article/2026-05-16-my-article.md

---
title: 我的文章
date: 2026-05-16 12:00
tags: test, demo
category: testing
status: published
---

# 我的文章

Hello **world** this is a test.

## 子标题

More content here...
```

**步骤2**: 创建 `parsers/frontmatter.py`

```python
"""Parse YAML-like front matter from markdown files."""

import re
from dataclasses import dataclass
from typing import Optional


FRONT_MATTER_PATTERN = re.compile(
    r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL
)


@dataclass
class FrontMatter:
    title: str = ""
    date: str = ""
    tags: str = ""
    category: str = ""
    status: str = "published"
    summary: str = ""


def parse_front_matter(content: str) -> tuple[FrontMatter, str]:
    """Parse front matter and return (metadata, body).

    Args:
        content: Full file content with optional front matter.

    Returns:
        Tuple of (FrontMatter, body_text).
    """
    match = FRONT_MATTER_PATTERN.match(content)
    if not match:
        return FrontMatter(), content

    metadata_text = match.group(1)
    body = content[match.end():]

    fm = FrontMatter()
    for line in metadata_text.split("\n"):
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if hasattr(fm, key):
            setattr(fm, key, value)

    return fm, body
```

**步骤3**: 添加向后兼容的迁移脚本

```python
"""Migrate articles from HTML-comment format to .md files."""

import re
from pathlib import Path
from tinypage.parsers.frontmatter import FrontMatter


def migrate_article(html_path: Path, md_path: Path) -> None:
    """Convert an HTML article with comment metadata to a .md source file."""
    content = html_path.read_text(encoding="utf-8", errors="replace")

    # Extract metadata from HTML comments
    fm = FrontMatter()
    body_lines = []
    in_meta = True
    for line in content.split("\n"):
        m = re.match(r"<!--\s*(\w+):\s*(.*)\s*-->", line.strip())
        if m and in_meta:
            key, val = m.group(1), m.group(2).strip()
            if hasattr(fm, key):
                setattr(fm, key, val)
        else:
            in_meta = False

    # Extract markdown from <!-- markdown: ... --> comment
    md_match = re.search(r"<!--\s*markdown:\s*(.*?)\s*-->", content, re.DOTALL)
    markdown_content = md_match.group(1) if md_match else ""

    # Write .md file with front matter
    front_matter = f"""---
title: {fm.title}
date: {fm.date}
tags: {fm.tags}
category: {fm.category}
status: {fm.status}
---

{markdown_content}
"""
    md_path.write_text(front_matter, encoding="utf-8")
```

**步骤4**: 修改 `content.py` 的 `parse_meta` 和 `write_article` 支持双格式读取

在 `parse_meta` 中：

```python
def parse_meta(path: Path, max_file_size: int = 10 * 1024 * 1024) -> Optional[ArticleMeta]:
    """Parse article metadata. Supports both .html and .md source files."""
    # 先尝试 .md 源文件
    md_path = path.with_suffix(".md")
    if md_path.exists():
        return _parse_md_meta(md_path, max_file_size)

    # 回退到旧的 .html 格式
    return _parse_html_meta(path, max_file_size)
```

---

### P3-20: 国际化支持

**短期方案**: 将 UI 文本集中到常量文件。

**步骤1**: 创建 `tinypage/i18n.py`

```python
"""Internationalization support for TinyPage."""

MESSAGES = {
    "zh-CN": {
        "admin_title": "TinyPage 管理后台",
        "dashboard": "仪表盘",
        "new_article": "新建文章",
        "new_page": "新建页面",
        "edit": "编辑",
        "delete": "删除",
        "save": "保存",
        "cancel": "取消",
        "title": "标题",
        "date": "日期",
        "tags": "标签",
        "category": "分类",
        "status": "状态",
        "published": "已发布",
        "draft": "草稿",
        "content": "内容",
        "upload": "上传",
        "preview": "预览",
        "theme": "主题",
        "regenerate": "重新生成",
        "backlinks": "反向链接",
        "search": "搜索",
        "search_placeholder": "输入关键词...",
        "confirm_delete": "确定要删除吗？",
        "save_success": "保存成功",
        "delete_success": "删除成功",
        "delete_confirm": "此操作不可撤销，确定要删除吗？",
        "theme_toggle": "切换主题",
        "ai_assist": "AI 助手",
        "ai_polish": "润色",
        "ai_complete": "补全",
        "ai_translate": "翻译",
        "ai_suggest_tags": "推荐标签",
        "login": "登录",
        "logout": "退出",
        "username": "用户名",
        "password": "密码",
        "login_failed": "用户名或密码错误",
        "no_articles": "暂无文章",
        "article_count": "篇文章",
        "powered_by": "由 TinyPage 驱动",
    },
    "en": {
        "admin_title": "TinyPage Admin",
        "dashboard": "Dashboard",
        "new_article": "New Article",
        "new_page": "New Page",
        "edit": "Edit",
        "delete": "Delete",
        "save": "Save",
        "cancel": "Cancel",
        "title": "Title",
        "date": "Date",
        "tags": "Tags",
        "category": "Category",
        "status": "Status",
        "published": "Published",
        "draft": "Draft",
        "content": "Content",
        "upload": "Upload",
        "preview": "Preview",
        "theme": "Theme",
        "regenerate": "Regenerate",
        "backlinks": "Backlinks",
        "search": "Search",
        "search_placeholder": "Enter keywords...",
        "confirm_delete": "Are you sure you want to delete?",
        "save_success": "Saved successfully",
        "delete_success": "Deleted successfully",
        "delete_confirm": "This action cannot be undone. Are you sure?",
        "theme_toggle": "Toggle theme",
        "ai_assist": "AI Assistant",
        "ai_polish": "Polish",
        "ai_complete": "Complete",
        "ai_translate": "Translate",
        "ai_suggest_tags": "Suggest Tags",
        "login": "Login",
        "logout": "Logout",
        "username": "Username",
        "password": "Password",
        "login_failed": "Invalid username or password",
        "no_articles": "No articles yet",
        "article_count": "articles",
        "powered_by": "Powered by TinyPage",
    },
}

_current_lang = "zh-CN"


def set_language(lang: str) -> None:
    global _current_lang
    if lang in MESSAGES:
        _current_lang = lang


def t(key: str, lang: str = "") -> str:
    """Get translated message by key."""
    language = lang or _current_lang
    return MESSAGES.get(language, MESSAGES["zh-CN"]).get(key, key)
```

**步骤2**: 在模板和生成器中使用 `t()` 函数

```python
# 示例：在 generator.py 中
from .i18n import t

# 原来:
theme_toggle = '<button class="theme-toggle" aria-label="切换主题" ...>🌓</button>'

# 改为:
theme_toggle = f'<button class="theme-toggle" aria-label="{t("theme_toggle")}" ...>🌓</button>'
```

---

## 补充：审计报告中遗漏的额外问题

---

### X1: `parse_meta` 中 `hasattr` 检查不安全（详细版） ✅ 已完成

**完成情况**: 
- ✅ `content.py` 添加 `_META_ALLOWED_KEYS = frozenset({...})` 白名单常量
- ✅ `parse_meta()` 中 `if hasattr(meta, key)` 已改为 `if key in _META_ALLOWED_KEYS`

**文件**: `tinypage/content.py`，第102-106行

**问题**: `hasattr(meta, key)` 允许 HTML 注释中的任意键覆盖 `ArticleMeta` 的任何属性，包括 `tag_list`、`is_draft`、`is_published` 等 property。攻击者可以构造恶意文件名或注入 HTML 注释来覆盖这些属性。

**完整修复**:

```python
# === 修改前 (第102-106行) ===
                m = re.match(r"<!--\s*(\w+):\s*(.*)\s*-->", line.strip())
                if m:
                    key, val = m.group(1), m.group(2).strip()
                    if hasattr(meta, key):
                        setattr(meta, key, val)

# === 修改后 ===
                m = re.match(r"<!--\s*(\w+):\s*(.*)\s*-->", line.strip())
                if m:
                    key, val = m.group(1), m.group(2).strip()
                    if key in _META_ALLOWED_KEYS:
                        setattr(meta, key, val)
```

在文件顶部（第20行附近）添加白名单常量：

```python
_META_ALLOWED_KEYS = frozenset({
    "title", "date", "slug", "tags", "summary",
    "category", "status", "markdown",
})
```

---

### X2: `content.py` 中重复函数的删除方案 ✅ 已完成

**完成情况**: 
- ✅ `content.py:build_article_title_map` — 已删除本地定义，改为从 `parsers` 导入
- ✅ `content.py:build_backlinks_html` — 已删除本地定义，改为从 `parsers` 导入
- ✅ `content.py:text_to_html` — 已删除，使用 `parsers/markdown.py` 的 `render_markdown`
- ✅ `slugify` 函数已统一到 `security.py`，`content.py` 和 `bidirectional_links.py` 均从 `security` 导入

**X2a. 删除 `content.py:build_article_title_map`（第125-138行）**

`parsers/bidirectional_links.py:115-133` 中有更通用的版本。需要确认调用方：

```bash
grep -rn "build_article_title_map" tinypage/
```

将所有调用改为从 `parsers` 导入：

```python
# 原来:
from .content import build_article_title_map

# 改为:
from .parsers import build_article_title_map
```

然后删除 `content.py` 第125-138行。

**X2b. 删除 `content.py:build_backlinks_html`（第141-154行）**

同上，`parsers/bidirectional_links.py` 中有更完善的版本。删除后更新调用方。

**X2c. 删除 `content.py:text_to_html`（第33-61行）**

`parsers/markdown.py:_fallback_text_to_html` 功能相同。删除 `content.py` 中的版本，将调用方改为：

```python
from .parsers.markdown import _fallback_text_to_html as text_to_html
```

或在 `parsers/__init__.py` 中导出：

```python
from .markdown import render_markdown, has_markdown_support, _fallback_text_to_html as text_to_html
```

**X2d. 合并 `slugify` 函数**

`content.py:24-30` 的 `slugify_title` 和 `parsers/bidirectional_links.py:21-25` 的 `slugify_for_link`。

推荐统一到 `security.py` 中（因为涉及安全相关的输入处理）：

```python
# 在 security.py 中添加:

def slugify(text: str, max_length: int = 80, fallback: str = "") -> str:
    """Convert text to URL-safe slug, preserving CJK characters.

    Args:
        text: Input text to slugify.
        max_length: Maximum slug length.
        fallback: Fallback value if result is empty.

    Returns:
        URL-safe slug string.
    """
    import re
    slug = re.sub(r"[^\w\u4e00-\u9fff-]", "-", text.lower()).strip("-")
    slug = re.sub(r"-{2,}", "-", slug)
    if max_length:
        slug = slug[:max_length].rstrip("-")
    return slug or fallback or f"untitled-{int(time.time())}"
```

然后删除 `content.py:slugify_title` 和 `parsers/bidirectional_links.py:slugify_for_link`，改为调用 `security.slugify`。

---

### X3: Nginx 配置安全头（详细版） ✅ 已完成

**完成情况**: 
- ✅ 全局安全头已添加（X-Content-Type-Options, X-Frame-Options, Referrer-Policy, COOP, Permissions-Policy）
- ✅ 管理后台和 API 代理已添加 `client_max_body_size 10m`
- ✅ 静态资源缓存已添加 `X-Content-Type-Options` 安全头
- ✅ 隐藏文件和敏感文件访问已阻止（`/.`、`admin_password.txt`、`.env`、`.git`）

**文件**: `nginx.conf`

```nginx
# === 修改前 ===
server {
    listen 80;
    server_name localhost;

    root /usr/share/nginx/html;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }

    location /admin/ {
        proxy_pass http://tinypage:8081/admin/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /api/ {
        proxy_pass http://tinypage:8081/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}

# === 修改后 ===
server {
    listen 80;
    server_name localhost;

    root /usr/share/nginx/html;
    index index.html;

    # 全局安全头
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Permissions-Policy "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()" always;

    # HSTS (仅在 HTTPS 时启用)
    # add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        try_files $uri $uri/ =404;
    }

    # 管理后台代理 — 限制请求体大小
    location /admin/ {
        proxy_pass http://tinypage:8081/admin/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        client_max_body_size 10m;
    }

    # API 代理 — 限制请求体大小
    location /api/ {
        proxy_pass http://tinypage:8081/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        client_max_body_size 10m;
    }

    # 静态资源 — 长缓存 + 安全头
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        add_header X-Content-Type-Options "nosniff" always;
    }

    # 禁止访问隐藏文件和敏感文件
    location ~ /\. {
        deny all;
        return 404;
    }
    location ~* (admin_password\.txt|\.env|\.git) {
        deny all;
        return 404;
    }
}
```

---

### X4: Dockerfile 和 `.dockerignore` 优化 ✅ 已完成

**完成情况**: 
- ✅ `.dockerignore` 已重写，排除 `.git`、`__pycache__`、`*.pyc`、`admin_password.txt`、`.env`、`docs/`、`scripts/` 等
- ✅ `Dockerfile` 改为选择性 COPY（`tinypage/`、`static_inject/`、`themes/`、`tiny_page.py`）替代 `COPY . .`
- ✅ 删除了不必要的 `apt-get` 安装步骤
- ✅ VOLUME 仅声明 `/app/pages` 和 `/app/themes`

**文件1**: `.dockerignore`（如不存在则创建）

```
.git
.github
__pycache__
*.pyc
*.pyo
.ruff_cache
.pytest_cache
.mypy_cache
admin_password.txt
.env
.env.*
*.log
docs/
*.md
!README.md
scripts/
.venv
venv
```

**文件2**: `Dockerfile`

```dockerfile
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

# 依赖安装（利用 Docker 缓存层）
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .[full]

# 仅复制必要的应用代码（.dockerignore 排除敏感文件）
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
```

---

### X5: CSRF Cookie 添加 Secure 标志 ✅ 已完成

**完成情况**: 
- ✅ `security.py:get_csrf_cookie_header` 已添加 `secure: bool = False` 参数
- ✅ `admin.py:_render_page` 已使用 `is_secure = bool(self.cfg.bind_domain)` 传入 `secure` 参数

**文件**: `tinypage/security.py`，第115-118行

```python
# === 修改前 ===
def get_csrf_cookie_header(token: Optional[str] = None) -> Tuple[str, str]:
    if token is None:
        token = generate_csrf_token()
    return ("Set-Cookie", f"csrf_token={token}; Path=/; HttpOnly; SameSite=Strict")

# === 修改后 ===
def get_csrf_cookie_header(
    token: Optional[str] = None,
    secure: bool = False,
) -> Tuple[str, str]:
    """Generate Set-Cookie header for CSRF token.

    Args:
        token: CSRF token string. Generated if not provided.
        secure: Add Secure flag. Should be True when served over HTTPS.
    """
    if token is None:
        token = generate_csrf_token()
    cookie = f"csrf_token={token}; Path=/; HttpOnly; SameSite=Strict"
    if secure:
        cookie += "; Secure"
    return ("Set-Cookie", cookie)
```

在 `AdminApp._render_page` 和其他设置 CSRF cookie 的地方传入 `secure` 参数：

```python
# 在 AdminApp._render_page 中:
is_secure = bool(self.cfg.bind_domain)  # 有绑定域名则通常走 HTTPS
get_csrf_cookie_header(csrf_token, secure=is_secure)
```

---

### X6: `_get_existing_csrf` 消除私有逻辑复制 ✅ 已完成

**完成情况**: 
- ✅ `security.py` 添加了 `is_valid_csrf_format()` 公共方法
- ✅ `admin.py:_get_existing_csrf` 已改用 `is_valid_csrf_format(token)` 替代内联验证逻辑

**文件**: `tinypage/admin.py`，第216-254行

**方案**: 在 `security.py` 中暴露一个公共方法 `is_valid_csrf_format`，仅检查 token 格式和签名（不检查 Origin/Referer，因为 GET 请求不需要）。

**文件1**: `tinypage/security.py` — 添加新函数

```python
def is_valid_csrf_format(token: str, max_age: int = 3600) -> bool:
    """Check if a CSRF token has valid format and signature (no origin check).

    Use this for reusing existing tokens in cookies without requiring
    a full request context. Does NOT replace validate_csrf_token() for
    POST request validation.

    Args:
        token: CSRF token string.
        max_age: Maximum token age in seconds.

    Returns:
        True if token format and HMAC signature are valid.
    """
    if not token or len(token) < 32:
        return False
    try:
        signed_token = base64.urlsafe_b64decode(token.encode("ascii"))
        if len(signed_token) != 52:
            return False
        token_data = signed_token[:20]
        signature = signed_token[20:]
        expected_sig = hmac.new(_CSRF_SECRET, token_data, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected_sig):
            return False
        timestamp = int.from_bytes(token_data[16:20], "big")
        now = time.time()
        if now - timestamp > max_age or timestamp > now + 60:
            return False
        return True
    except Exception:
        return False
```

**文件2**: `tinypage/admin.py` — 重写 `_get_existing_csrf`

```python
# === 修改前 (第216-254行) ===
    def _get_existing_csrf(self, environ: dict) -> str:
        """Reuse existing CSRF cookie if present and valid, otherwise generate new."""
        cookie_header = environ.get("HTTP_COOKIE", "")
        for cookie in cookie_header.split(";"):
            cookie = cookie.strip()
            if cookie.startswith("csrf_token="):
                token = cookie[11:]
                try:
                    from .security import validate_csrf_token
                    import base64, time, hmac, hashlib
                    from .security import _CSRF_SECRET
                    # ... 30+ 行重复的验证逻辑 ...
                except Exception:
                    break
        return generate_csrf_token()

# === 修改后 ===
    def _get_existing_csrf(self, environ: dict) -> str:
        """Reuse existing CSRF cookie if present and valid, otherwise generate new."""
        from .security import is_valid_csrf_format
        cookie_header = environ.get("HTTP_COOKIE", "")
        for cookie in cookie_header.split(";"):
            cookie = cookie.strip()
            if cookie.startswith("csrf_token="):
                token = cookie[11:]
                if is_valid_csrf_format(token):
                    return token
                break
        return generate_csrf_token()
```

---

### X7: `object.__setattr__` 绕过 frozen dataclass 的修复 ✅ 已完成

**完成情况**: 
- ✅ `admin.py` 第754行已使用 `self.cfg = self.cfg.merge(theme_name=theme_name)` 替代 `object.__setattr__`

**文件**: `tinypage/admin.py`，第738行

```python
# === 修改前 ===
    object.__setattr__(self.cfg, "theme_name", theme_name)

# === 修改后 ===
    self.cfg = self.cfg.merge(theme_name=theme_name)
```

同时检查 `_save_theme_config` 方法（第749行）是否也需要调整。如果它直接操作文件，保持不变即可，因为 `Config.merge` 已经创建新实例。

---

### X8: `errors="ignore"` 替换为 `errors="replace"` + 日志警告 ✅ 已完成

**完成情况**: 
- ✅ `content.py` 中所有 `errors="ignore"` 已替换为 `errors="replace"`

**文件**: `tinypage/content.py`，第98、114、739行

```python
# === 修改前 (第98行) ===
        with open(path, "r", encoding="utf-8", errors="ignore") as f:

# === 修改后 ===
        with open(path, "r", encoding="utf-8", errors="replace") as f:
```

对所有3处做相同替换。`errors="replace"` 会将无法解码的字节替换为 `\ufffd`（Unicode 替换字符），而非静默丢弃，这样至少能在输出中看到有数据丢失。

更完善的方案（如果需要知道哪些文件有问题）：

```python
    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        logger.warning(f"[ENCODING] {path} has encoding issues: {e}")
        content = path.read_text(encoding="utf-8", errors="replace")
```

---

### X9: `build_cache_key` 中 MD5 替换为 SHA-256 ✅ 已完成

**完成情况**: 
- ✅ `core/incremental.py` 第179行已使用 `hashlib.sha256(content.encode()).hexdigest()[:12]`

**文件**: `tinypage/core/incremental.py`，第179行

```python
# === 修改前 ===
    import hashlib
    key_str = ":".join(f"{name}:{mtime}" for name, mtime in file_mtimes)
    return hashlib.md5(key_str.encode()).hexdigest()

# === 修改后 ===
    import hashlib
    key_str = ":".join(f"{name}:{mtime}" for name, mtime in file_mtimes)
    return hashlib.sha256(key_str.encode()).hexdigest()[:32]
```

---

### X10: WSGI 类型注解 ✅ 已完成

**完成情况**: 
- ✅ `admin.py:190` — `def __call__(self, environ: dict[str, Any], start_response: StartResponse) -> list[bytes]`
- ✅ `frontend.py:42` — `def __call__(self, environ: dict[str, Any], start_response: StartResponse) -> list[bytes]`
- ✅ 两处均已导入 `from wsgiref.types import StartResponse` 和 `from typing import Any`

**文件**: `tinypage/admin.py`，第100行；`tinypage/frontend.py`，第43行

```python
# === 修改前 ===
    def __call__(self, environ: dict, start_response):

# === 修改后 ===
    from wsgiref.types import StartResponse
    from typing import Any

    def __call__(self, environ: dict[str, Any], start_response: StartResponse) -> list[bytes]:
```

对 `frontend.py` 做相同修改。

---

### X11: 模块级副作用的惰性化 ✅ 已完成

**完成情况**: 
- ✅ `frontend.py` — `_INJECTED_ASSETS` 初始为 `None`，通过 `_get_injected_assets()` 延迟加载
- ✅ `admin.py` 已改用 `_get_injected_assets()` 而非直接访问 `_INJECTED_ASSETS`

**修复记录**: X11 实施后 `admin.py` 仍直接引用 `_INJECTED_ASSETS`（可能为 None），导致 `path in None` TypeError。已修复为调用 `_get_injected_assets()`。

**文件**: `tinypage/frontend.py`，第32-33行

```python
# === 修改前 ===
_INJECTED_ASSETS: dict[str, tuple[str, bytes]] = {}

def _load_injected_assets():
    ...

_load_injected_assets()  # 模块导入时立即执行

# === 修改后 ===
_INJECTED_ASSETS: dict[str, tuple[str, bytes]] | None = None

def _get_injected_assets() -> dict[str, tuple[str, bytes]]:
    """Lazy-load injected assets on first access."""
    global _INJECTED_ASSETS
    if _INJECTED_ASSETS is None:
        _INJECTED_ASSETS = {}
        inject_dir = Path(__file__).resolve().parent.parent / "static_inject"
        if inject_dir.exists():
            for asset in inject_dir.iterdir():
                if asset.is_file():
                    mime_type, _ = mimetypes.guess_type(str(asset))
                    if mime_type:
                        key = f"/{asset.name}"
                        _INJECTED_ASSETS[key] = (mime_type, asset.read_bytes())
    return _INJECTED_ASSETS
```

然后在 `AdminApp.__call__` 和 `StaticApp.__call__` 中，将所有 `_INJECTED_ASSETS` 的直接访问改为 `_get_injected_assets()`。

---

## 执行优先级总结

| 序号 | 优化项 | 优先级 | 预估时间 | 风险等级 | 前置依赖 | 状态 |
|------|--------|--------|---------|---------|----------|
| P0-1 | 删除密码文件+清理 git 历史 | P0 | 30min | 低 | 无 | ✅ 已完成 |
| P0-2 | 密码持久化到临时目录 | P0 | 1h | 低 | P0-1 | ✅ 已完成 |
| P0-3 | 全部用户输入使用 escape_attr | P0 | 2h | 低 | 无 | ✅ 已完成 |
| P1-4 | POST 请求体大小限制 | P1 | 30min | 低 | 无 | ✅ 已完成 |
| P1-5 | Mermaid 安全等级统一 | P1 | 15min | 低 | 无 | ✅ 已完成 |
| P1-6 | IP 检测可信代理配置 | P1 | 1h | 中 | 无 | ✅ 已完成 |
| P1-7 | Basic Auth 暴力破解防护 | P1 | 2h | 中 | P1-6 | ✅ 已完成 |
| P1-8 | 删除 template.py 死代码 | P1 | 1h | 低 | 无 | ✅ 已完成 |
| P1-9 | 统一 escape_html | P1 | 1h | 低 | 无 | ✅ 已完成 |
| P1-10 | 速率限制器内存泄漏修复 | P1 | 1h | 低 | 无 | ✅ 已完成 |
| P2-11 | 抽取公共页面上下文构建器 | P2 | 3h | 中 | P1-8 | ❌ 未完成 |
| P2-12 | 管理后台 Jinja2 模板 | P2 | 8h | 中 | P0-3 | ❌ 未完成 |
| P2-13 | 解除循环依赖 | P2 | 4h | 高 | P2-11 | ❌ 未完成 |
| P2-14 | 核心安全函数单元测试 | P2 | 4h | 低 | P1-9, X1 | ❌ 未完成 |
| P2-15 | 路由重构为路由表 | P2 | 2h | 中 | P1-7 | ❌ 未完成 |
| P2-16 | Config 验证逻辑 | P2 | 1h | 低 | 无 | ✅ 已完成 |
| P3-17 | CSP nonce-based | P3 | 8h | 高 | P2-12 | ❌ 未完成 |
| P3-18 | Session-based 认证 | P3 | 8h | 高 | P3-17 | ❌ 未完成 |
| P3-19 | 存储格式迁移 | P3 | 16h | 高 | P2-13, P2-14 | ❌ 未完成 |
| P3-20 | 国际化支持 | P3 | 16h | 中 | P2-12 | ❌ 未完成 |
| X1 | parse_meta 白名单 | P1 | 15min | 低 | 无 | ✅ 已完成 |
| X2 | 删除重复函数 | P1 | 1h | 中 | P1-9 | ✅ 已完成 |
| X3 | Nginx 安全头 | P1 | 30min | 低 | 无 | ✅ 已完成 |
| X4 | Dockerfile 优化 | P1 | 30min | 低 | 无 | ✅ 已完成 |
| X5 | CSRF Cookie Secure 标志 | P1 | 15min | 低 | P0-3 | ✅ 已完成 |
| X6 | 消除 CSRF 私有逻辑复制 | P1 | 30min | 低 | 无 | ✅ 已完成 |
| X7 | 修复 frozen 绕过 | P1 | 5min | 低 | 无 | ✅ 已完成 |
| X8 | errors="replace" | P1 | 15min | 低 | 无 | ✅ 已完成 |
| X9 | MD5 → SHA-256 | P1 | 5min | 低 | 无 | ✅ 已完成 |
| X10 | WSGI 类型注解 | P2 | 30min | 低 | 无 | ✅ 已完成 |
| X11 | 模块级副作用惰性化 | P2 | 30min | 低 | 无 | ✅ 已完成 |

**建议执行顺序**:
1. 第一天: P0-1, P0-2, P0-3, X1, X7, X9（所有快速安全修复）
2. 第一周: P1-4 ~ P1-10, X2 ~ X8（所有 P1 级别修复）
3. 第二周: P2-16, P2-14（Config 验证 + 测试）
4. 第3-4周: P2-11, P2-15（重构 generator + 路由）
5. 第2月: P2-12, P2-13（模板 + 依赖解耦）
6. 长期: P3-17 ~ P3-20
