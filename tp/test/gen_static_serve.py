"""生成 tp/lib/static_serve.wll —— 静态文件服务内核（卡 S3-1）。

⚠ 输出的 .wll 由本文件生成，不要手改（业主裁决 D7：.wll 一律由生成器产出）。

**为什么是「纯函数」**：HTTP 语义与传输必须分开 —— 前者可以**脱网**测，
后者不能。本模块**不碰 socket**、**不 import `tls`**（否则没装 TLS 扩展时
连编译都过不去）。两个入口（`tp/bin/serve_public.wll` 明文、
`tp/bin/serve_tls.wll` TLS）只负责「收字节 → 调 HANDLE → 发字节」。

**对齐目标（权威落点）**：
  · `SECURITY_HEADERS()`  == `nginx.conf:9-13` == `tinypage/security.py:331`
  · `MIME_TYPE(opts)`      == `tinypage/frontend.py:74` 的 `mimetypes.guess_type(...) or "text/html"`
  · 长缓存扩展名           == `nginx.conf:43`
  · 隐藏文件 / 敏感文件    == `nginx.conf:50-57`
  · 目录回落 `index.html`  == `nginx.conf:4-6,18-20`
  · `Cache-Control` 短缓存值 == `tinypage/frontend.py:78`

**三处刻意的取舍（都登记在夹具的 meta 里，不是沉默偏离）**：
  ① **长缓存 = 一个 `Cache-Control`**。nginx 的 `expires 1y`（行为
     `Cache-Control: max-age=31536000`）与 `add_header Cache-Control "public, immutable"`
     **并存** ⇒ 严格照抄 nginx 会发**两个** `Cache-Control`。Python 的 `StaticApp`
     全程只发**一个**（`frontend.py:78`）。取**一个**：两个 `Cache-Control`
     对客户端是「后一个未必覆盖前一个」的未定义合并，且卡 S3-1 的验收值就是
     单头 `public, max-age=31536000, immutable`。
  ② **非长缓存资源用 `max-age=300, must-revalidate`**（`frontend.py:78` 的实测值），
     而不是「不发」。nginx 对 `.html` 不发 `Cache-Control`；这里选 Python 的显式值，
     因为它**有源码坐标**，而「不发」只能靠「nginx 没写」推断。测试钉住这个值。
  ③ **字体类的 MIME 取 nginx/IANA 的值**（`font/woff2` 等）。本机 CPython 3.13
     （Windows）实测 `mimetypes.guess_type("x.woff2")` ⇒ `(None, None)`
     ⇒ 照 `frontend.py:74` 的回落会给出 `text/html`（字体被当 HTML 发）。
     该表**随平台/注册表变化**（Linux 上同调用给 `font/woff2`）⇒ 它不是契约。
     除字体这 4 个外，其余值都是本机实测的 Python 输出。

**不做的东西（非目标）**：`security.py:283` 的扩展名白名单
（`safe_exts` 里有 `.woff2` 却**没有** `.woff`，且 nginx 侧没有这条）
—— 公开站以 nginx 语义为准，白名单只属于旧的 WSGI 开发服务器。
也不做 CSP（`security.py:342` 是 admin 专用，公开站不发）。

用法：python gen_static_serve.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, fn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'lib', 'static_serve.wll')

# ── 5 个安全头（顺序 = nginx.conf:9-13 = security.py:331 的列表序）────────
# ⚠ Permissions-Policy 是 **9 项**，不是 nginx.conf 卡片摘要里那个 "..."。
SECURITY = [
    ('X-Content-Type-Options', 'nosniff'),
    ('X-Frame-Options', 'DENY'),
    ('Referrer-Policy', 'no-referrer'),
    ('Cross-Origin-Opener-Policy', 'same-origin'),
    ('Permissions-Policy',
     'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), '
     'microphone=(), payment=(), usb=()'),
]

# ── MIME 表 ────────────────────────────────────────────────────────────────
# 右边是 Python `mimetypes.guess_type` 的**本机实测值**；字体四个用 nginx 的值
# （Python 实测 None —— 见模块 docstring 的取舍 ③）。
MIME = [
    ('html', 'text/html'),
    ('htm', 'text/html'),
    ('xhtml', 'application/xhtml+xml'),
    ('css', 'text/css'),
    ('js', 'application/javascript'),
    ('json', 'application/json'),
    ('webmanifest', 'application/manifest+json'),
    ('xml', 'text/xml'),
    ('txt', 'text/plain'),
    ('md', 'text/markdown'),
    ('map', 'text/plain'),
    ('png', 'image/png'),
    ('jpg', 'image/jpeg'),
    ('jpeg', 'image/jpeg'),
    ('gif', 'image/gif'),
    ('ico', 'image/x-icon'),
    ('svg', 'image/svg+xml'),
    ('webp', 'image/webp'),
    ('avif', 'image/avif'),
    ('woff', 'font/woff'),      # ← nginx；Python 实测 None
    ('woff2', 'font/woff2'),    # ← nginx；Python 实测 None
    ('ttf', 'font/ttf'),        # ← nginx；Python 实测 None
    ('otf', 'font/otf'),        # ← nginx；Python 实测 None
    ('pdf', 'application/pdf'),
    ('wasm', 'application/wasm'),
]

# ── 长缓存扩展名（nginx.conf:43，**不含前导点** —— PATH_EXT 的口径）──────
LONG_CACHE_EXTS = ['js', 'css', 'png', 'jpg', 'jpeg', 'gif', 'ico', 'svg', 'woff', 'woff2']

LONG_CACHE_VALUE = 'public, max-age=31536000, immutable'
SHORT_CACHE_VALUE = 'max-age=300, must-revalidate'


def wl(s):
    """Python 字符串 → WLWL 字面量。⚠ 字面美元符在 WLWL 里是插值 ⇒ 写 \\$。"""
    out = []
    for ch in s:
        if ch == '\\':
            out.append('\\\\')
        elif ch == '"':
            out.append('\\"')
        elif ch == '$':
            out.append('\\$')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif ch == '\t':
            out.append('\\t')
        else:
            out.append(ch)
    return '"' + ''.join(out) + '"'


def index_set_chain(pairs):
    """[(k, v)] → 一条嵌套 INDEX_SET 表达式（键序 = 插入序）。

    ⚠ 只能**单行**：`paren_check` / `check_semis` 按逐行 `(` 深度判定
      顶层语句，多行嵌套会被当成多条语句（实测：金字塔缩进 + 误报）。
    """
    expr = 'DICT()'
    for k, v in pairs:
        expr = 'INDEX_SET(%s, %s, %s)' % (expr, wl(k), wl(v))
    return expr


def main():
    src = []
    A = src.append
    A('// tp/lib/static_serve.wll —— 静态文件服务内核（卡 S3-1）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_static_serve.py 生成 —— 请勿手改。')
    A('//')
    A('// 本模块是**纯函数**：不碰 socket、不 import `tls`、不写文件。')
    A('// 传输在入口里（tp/bin/serve_public.wll 明文 / tp/bin/serve_tls.wll TLS），')
    A('// 二者只做「收字节 → HANDLE → 发字节」⇒ HTTP 语义可以脱网测。')
    A('//')
    A('// 权威落点：')
    A('//   SECURITY_HEADERS() == nginx.conf:9-13 == tinypage/security.py:331')
    A('//   MIME_TYPE(opts)     == tinypage/frontend.py:74 的 guess_type 回落')
    A('//   长缓存扩展名        == nginx.conf:43')
    A('//   隐藏 / 敏感文件     == nginx.conf:50-57')
    A('//   目录回落 index.html == nginx.conf:4-6,18-20')
    A('//   短缓存值            == tinypage/frontend.py:78')
    A('//')
    A('// ⚠ 三处刻意的取舍（理由见生成器 docstring，夹具 meta 里也登记了）：')
    A('//   ① 长缓存只发**一个** Cache-Control（nginx 会发两个、Python 只发一个）')
    A('//   ② 非长缓存资源发 max-age=300, must-revalidate（frontend.py:78 的有据值）')
    A('//   ③ 字体四个扩展名的 MIME 取 nginx/IANA 值（本机 Python 实测给 None）')
    A('')
    A('IMPORT("wlwl:std.fs", ["PATH_JOIN", "PATH_EXT", "PATH_CANONICAL", "PATH_CONTAINS",')
    A('    "FILE_META", "READ_FILE"]);')
    A('IMPORT("wlwl:std.str", ["INDEX_OF", "CONTAINS_SUB"]);')
    A('IMPORT("wlwl:std.text", ["TO_LOWER", "TO_UPPER"]);')
    A('IMPORT("wlwl:std.encode", ["BYTE_LEN", "URL_DECODE"]);')
    A('IMPORT("wlwl:std.regex", ["RE", "RE_FIND_ALL"]);')
    A('')
    A('// 含字面 ".." 的输入 ⇒ 404（D3 / 卡 S3-1 反向守卫）')
    A('// ⚠ 正则里字面点必须写字符类 `[.]`（tp/README 坑 26）；判「含子串」用 RE_FIND_ALL')
    A('//   计数（坑 36：RE_TEST 是整串锚定）。')
    A('LET(DOTDOT_RE, RE("[.][.]"));')
    A('')
    A('// 路径含 "/." ⇒ 404（nginx.conf:50-53 的 `location ~ /\\.`）')
    A('LET(HIDDEN_RE, RE("/[.]"));')
    A('')
    A('// MIME 表（键 = PATH_EXT 的小写输出，**不含前导点**）')
    A('// ⚠ 一行很长是**故意的**：paren_check / check_semis 只按 `(` 计数，'
      '多行数组/多行链会被它们当成「多条顶层语句」误报。')
    A('//   要看清楚请读本生成器里的 MIME 表（每行一对，已排序）。')
    A('LET(MIME_TABLE, ' + index_set_chain(sorted(MIME)) + ');')
    A('')
    A('// 长缓存扩展名（nginx.conf:43；同样不带前导点）')
    A('LET(LONG_CACHE_EXTS, [' + ', '.join(wl(x) for x in LONG_CACHE_EXTS) + ']);')
    A('')

    # ── 小工具 ────────────────────────────────────────────────────────
    src += fn('HAS_DOTDOT', 'p', [
        '// p 里是否含字面 ".."',
        '>(LEN(RE_FIND_ALL(DOTDOT_RE, p)), 0)',
    ], '// 是否含字面 ".."')

    src += fn('HAS_HIDDEN_SEG', 'p', [
        '// p 里是否含 "/."（隐藏文件 / 隐藏目录）',
        '>(LEN(RE_FIND_ALL(HIDDEN_RE, p)), 0)',
    ], '// 是否含 "/."')

    src += fn('IS_SENSITIVE', 'lowered', [
        '// 敏感文件：**子串**匹配，且大小写不敏感（nginx 用 `~*`）',
        '// ⚠ 传进来的必须是 TO_LOWER 之后的值。',
        '||(CONTAINS_SUB(lowered, "admin_password.txt"), '
        '||(CONTAINS_SUB(lowered, ".env"), CONTAINS_SUB(lowered, ".git")))',
    ], '// 敏感文件子串判定（入参须已小写）')

    src += fn('IS_READ_METHOD', 'm', [
        '// 只认 GET / HEAD；其余一律 405（卡 S3-1）',
        '||(==(m, "GET"), ==(m, "HEAD"))',
    ], '// GET/HEAD 判定')

    src += fn('STRIP_QUERY', 'p', [
        '// 去掉 "?" 之后的部分（入口也会先切一遍，这里是兜底）',
        'LET(i, INDEX_OF(p, "?"))',
        'IF(<(i, 0), p, SUB(p, 0, i))',
    ], '// 去掉查询串')

    src += fn('STRIP_LEADING_SLASH', 'p', [
        '// Python: if path_str.startswith("/"): path_str = path_str[1:]',
        'IF(==(SUB(p, 0, 1), "/"), SUB(p, 1), p)',
    ], '// 去掉开头一个 "/"')

    src += fn('DECODE_PATH', 'p', [
        '// percent-decode（对齐 nginx「先解码再匹配 location」的口径）。',
        '// ⚠ ERR 必须**就地**消费（tp/README 坑 25）⇒ 调用直接写在 IS_ERR 里；',
        '//   else 分支再调一次是**纯函数**、代价 O(n)，换来「值 + 失败」两个出口。',
        C('IF', 'IS_ERR(URL_DECODE(p))', ['NULL'], ['URL_DECODE(p)']),
    ], '// percent-decode，失败返回 NULL')

    src += fn('CACHE_CONTROL', 'file', [
        '// 长缓存命中 ⇒ nginx.conf:43 的语义（值取卡 S3-1 的验收串）',
        '// 未命中 ⇒ frontend.py:78 的显式值（见生成器取舍 ②）',
        C('IF', 'CONTAINS(LONG_CACHE_EXTS, TO_LOWER(PATH_EXT(file)))',
          [wl(LONG_CACHE_VALUE)], [wl(SHORT_CACHE_VALUE)]),
    ], '// Cache-Control 取值')

    # ── SECURITY_HEADERS ─────────────────────────────────────────────
    src += fn('SECURITY_HEADERS', '', [
        '// 5 个安全头，**键序 = nginx.conf:9-13 = security.py:331 的列表序**。',
        '// ⚠ Permissions-Policy 的取值是 8 项（accelerometer … usb），逐字对齐源码'
        '（卡 S3-1 写「9 项」是数错，见夹具 meta.findings）。',
        index_set_chain(SECURITY),
    ], '// 5 个安全头（顺序 = nginx.conf:9-13）')

    # ── MIME_TYPE ────────────────────────────────────────────────────
    src += fn('MIME_TYPE', 'opts', [
        '// opts 键：path（文件路径或 URL 路径）',
        '// 对齐 frontend.py:74：`mimetypes.guess_type(...) or "text/html"`',
        '// ⚠ PATH_EXT 不含前导点、且**保留原大小写**（实测 `f.WOFF2` ⇒ "WOFF2"）',
        '//   ⇒ 查表前必须 TO_LOWER。',
        'LET(p, AT_K(opts, "path", ""))',
        'AT_K(MIME_TABLE, TO_LOWER(PATH_EXT(p)), "text/html")',
    ], '// MIME 类型（对齐 frontend.py:74）')

    src += fn('CONTENT_TYPE_VALUE', 'file', [
        '// 对齐 frontend.py:76：text/* 补 "; charset=utf-8"，其余原样',
        'LET(ct, MIME_TYPE(INDEX_SET(DICT(), "path", file)))',
        'IF(==(SUB(ct, 0, 5), "text/"), +(ct, "; charset=utf-8"), ct)',
    ], '// Content-Type 头值（text/* 补 charset）')

    # ── 响应构造 ─────────────────────────────────────────────────────
    src += fn('RESPONSE', 'status, headers, body', [
        '// handler 契约形：{status, headers, body}',
        'INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "status", status), "headers", headers), '
        '"body", body)',
    ], '// 响应字典')

    src += fn('WITH_SECURITY', 'h', [
        '// 把 5 个安全头按序**追加**到 h 后面（h 先放业务头 ⇒ 业务头在前）。',
        '// ⚠ DICT 的键序 = 插入序（实测 KEYS 按插入序返回）⇒ 插入序即线上顺序。',
        'LET(sh, SECURITY_HEADERS())',
        'LET MUT(out, h)',
        C('FOR', 'k, KEYS(sh)', ['SET(out, INDEX_SET(out, k, AT_K(sh, k, "")))']),
        'out',
    ], '// 追加 5 个安全头（保持顺序）')

    src += fn('ERROR_RESPONSE', 'status, message', [
        '// 错误响应：先 Content-Type / Content-Length，再 5 个安全头。',
        '// ⚠ 不发 Cache-Control（frontend.py:88 的 `_error` 也不发）。',
        '// ⚠ 不发 CSP（security.py:342 是 admin 专用）。',
        'LET(h, INDEX_SET(INDEX_SET(DICT(), "Content-Type", "text/plain"), '
        '"Content-Length", STR(BYTE_LEN(message))))',
        'RESPONSE(status, WITH_SECURITY(h), message)',
    ], '// 错误响应（404 / 405 / 500）')

    src += fn('OK_RESPONSE', 'file, method, body', [
        '// 200 响应。头序：Content-Type / Content-Length / Cache-Control / 5 个安全头。',
        '// ⚠ HEAD 时 body 清空，但 **Content-Length 仍是真实长度** ——',
        '//   那正是 HEAD 的语义（「与 GET 相同的头，只是没有体」）。',
        'LET MUT(h, INDEX_SET(DICT(), "Content-Type", CONTENT_TYPE_VALUE(file)))',
        'SET(h, INDEX_SET(h, "Content-Length", STR(BYTE_LEN(body))))',
        'SET(h, INDEX_SET(h, "Cache-Control", CACHE_CONTROL(file)))',
        'RESPONSE(200, WITH_SECURITY(h), IF(==(method, "HEAD"), "", body))',
    ], '// 200 响应（HEAD 清空 body 但保留 Content-Length）')

    # ── 路径解析 ─────────────────────────────────────────────────────
    src += fn('SERVE_FILE_AT', 'method, file', [
        '// 到这一步 file 已是「非目录」候选；不存在 / 仍是目录 ⇒ 404（不得 500）。',
        '// ⚠ FILE_META 对「不存在」不返 ERR（exists=FALSE）⇒ 可以安全绑定。',
        'LET(meta, FILE_META(file))',
        C('IF', '||(!AT_K(meta, "exists", FALSE), AT_K(meta, "is_dir", FALSE))',
          ['ERROR_RESPONSE(404, "Not found")'],
          [C('IF', 'IS_ERR(READ_FILE(file))',
             ['ERROR_RESPONSE(500, "Server error")'],
             ['OK_RESPONSE(file, method, READ_FILE(file))'])]),
    ], '// 读文件并构造 200')

    src += fn('SERVE_TARGET', 'method, target', [
        '// 目录 ⇒ 回落该目录的 index.html（nginx.conf:18-20 的 try_files $uri $uri/）。',
        '// ⚠ `/list`（无尾斜杠）也走这条 ⇒ 与 nginx 的意图一致（nginx 会先 301 到',
        '//   /list/，这里直接给 index.html；不引入重定向头，登记在夹具 meta 里）。',
        'LET(meta, FILE_META(target))',
        C('IF', '!AT_K(meta, "exists", FALSE)',
          ['ERROR_RESPONSE(404, "Not found")'],
          [C('IF', 'AT_K(meta, "is_dir", FALSE)',
             ['SERVE_FILE_AT(method, PATH_JOIN(target, "index.html"))'],
             ['SERVE_FILE_AT(method, target)'])]),
    ], '// 目录回落 index.html')

    src += fn('SERVE_DECODED', 'root, method, p', [
        '// p 已 percent-decode、且已过「隐藏 / 敏感 / ..」三道门。',
        'LET(base, PATH_CANONICAL(root))',
        'LET(target, PATH_CANONICAL(PATH_JOIN(base, STRIP_LEADING_SLASH(p))))',
        '// 包含性判定：PATH_CONTAINS 是**逐段**判定（挡得住 pages-evil 这类同前缀兄弟）。',
        '// ⚠ target == base 是合法的（请求 "/"）⇒ 单独放行。',
        C('IF', '&&(!=(target, base), !PATH_CONTAINS(base, target))',
          ['ERROR_RESPONSE(404, "Not found")'],
          ['SERVE_TARGET(method, target)']),
    ], '// 解析到磁盘路径并服务')

    src += fn('HANDLE_URL', 'root, method, raw', [
        '// ① 解码（失败 ⇒ 404，fail closed）→ ② 三道门 → ③ 服务。',
        'LET(d, DECODE_PATH(STRIP_QUERY(raw)))',
        C('IF', '==(TYPE(d), "NULL")',
          ['ERROR_RESPONSE(404, "Not found")'],
          [C('IF', '||(HAS_DOTDOT(d), ||(HAS_HIDDEN_SEG(d), IS_SENSITIVE(TO_LOWER(d))))',
             ['ERROR_RESPONSE(404, "Not found")'],
             ['SERVE_DECODED(root, method, d)'])]),
    ], '// 解码 + 安全门 + 服务')

    # ── HANDLE（导出主入口）──────────────────────────────────────────
    src += fn('HANDLE', 'opts', [
        '// opts 键：root（产物根目录）/ method（GET|HEAD）/ path / query',
        '//   · path 可带查询串（入口可能没切干净）⇒ STRIP_QUERY 兜底',
        '//   · query **不参与**解析（对齐 WSGI 的 PATH_INFO / QUERY_STRING 分离）',
        '// 返回 {"status": INTEGER, "headers": DICT, "body": STRING}',
        'LET(root, AT_K(opts, "root", ""))',
        'LET(method, TO_UPPER(AT_K(opts, "method", "GET")))',
        'LET(raw, AT_K(opts, "path", "/"))',
        C('IF', 'IS_READ_METHOD(method)',
          ['HANDLE_URL(root, method, raw)'],
          ['ERROR_RESPONSE(405, "Method not allowed")']),
    ], '// 一次静态请求的完整响应（纯函数）')

    A('EXPORT(["HANDLE", "MIME_TYPE", "SECURITY_HEADERS"]);')

    chars, lines = write(OUT, src)
    print('wrote %s (%d chars, %d lines)' % (OUT, chars, lines))


if __name__ == '__main__':
    main()
