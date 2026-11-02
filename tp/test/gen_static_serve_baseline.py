"""生成 tp/test/fixtures/static_serve_baseline.json —— 静态服务内核的验收基准。

⚠ 输出的 JSON 由本文件生成，不要手改。

**为什么是「手写期望值 + 出处行号」**：Python 侧没有与 `HANDLE` 等价的纯函数
（`tinypage/frontend.py:35` 的 `StaticApp` 是 WSGI 应用，且它**不实现** nginx 的
长缓存 / 隐藏文件 / 敏感文件 / 405 门），所以本卡的目标语义按 `nginx.conf` 定，
逐条标注出处行号；**能拿真 Python 对照的部分照旧对照**（见 `cross_checks`）。

**真 Python 交叉校验**（生成期跑，结果写进 JSON 的 `meta.cross_checks`）：
  ① `tinypage/security.py:331 get_security_headers()` 与本基准的 5 个头**逐字逐序**相等；
  ② 对 4 条 200 用例，直接调 `tinypage/frontend.py:35 StaticApp`，要求
     `status` / `Content-Type` / `Content-Length` / `body` / 头序 / 5 个安全头
     **全部相等**（唯一例外：Cache-Control，见 divergences）。

用法：python gen_static_serve_baseline.py
"""
import json
import os
import sys
import tempfile
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, HERE)

# 单一真相：头表 / MIME 表 / 缓存值都从实现生成器里取，避免两处漂移。
from gen_static_serve import (  # noqa: E402
    LONG_CACHE_VALUE, SECURITY, SHORT_CACHE_VALUE,
)

OUT = os.path.join(HERE, 'fixtures', 'static_serve_baseline.json')

# ── 产物树（测试运行期在 TEMP_DIR 里逐一写出来）──────────────────────────
FILES = {
    'index.html': '<!doctype html>\n<html lang="zh">\n<head><title>home</title></head>\n'
                  '<body><h1>首页</h1></body>\n</html>\n',
    'article/x.html': '<!doctype html>\n<html><body><article>x</article></body></html>\n',
    'article/中文.html': '<!doctype html>\n<html><body><article>中文</article></body></html>\n',
    'list/index.html': '<!doctype html>\n<html><body><ul><li>2</li></ul></body></html>\n',
    'list/2.html': '<!doctype html>\n<html><body><article>2</article></body></html>\n',
    'style.css': 'body{margin:0}\n',
    'font.woff2': 'wOF2 fake font bytes for tests\n',
    'app.woff': 'wOFF fake font bytes for tests\n',
    'static/app.js': 'console.log("hi");\n',
    'plain.txt': 'hello 中文\n',
    '.git/config': '[core]\n\trepositoryformatversion = 0\n',
    'admin_password.txt': 'hunter2\n',
    'nested/.env': 'SECRET=1\n',
}

DIRS = ['article', 'list', 'static', 'nested', '.git', 'emptydir']

NOT_FOUND = 'Not found'
METHOD_NOT_ALLOWED = 'Method not allowed'


def hdr_200(file_path, method, body, length_text=None):
    """200 的头序：Content-Type / Content-Length / Cache-Control / 5 个安全头。

    出处：frontend.py:75-79 的三个业务头 + security.py:331 的 5 个头（顺序照抄）。
    """
    from gen_static_serve import MIME
    mime = dict(MIME)
    ext = file_path.rsplit('.', 1)[-1].lower() if '.' in os.path.basename(file_path) else ''
    ct = mime.get(ext, 'text/html')
    if ct.startswith('text/'):
        ct += '; charset=utf-8'
    long_cache = ext in ('js', 'css', 'png', 'jpg', 'jpeg', 'gif', 'ico', 'svg', 'woff', 'woff2')
    cc = LONG_CACHE_VALUE if long_cache else SHORT_CACHE_VALUE
    # ⚠ HEAD 的 Content-Length 仍是**真实长度**（body 只是不发）⇒ 长度可以另给
    measured = body if length_text is None else length_text
    out = [('Content-Type', ct), ('Content-Length', str(len(measured.encode('utf-8')))),
           ('Cache-Control', cc)]
    return out + [list(x) for x in SECURITY]


def hdr_error(message):
    """错误响应的头序：Content-Type / Content-Length / 5 个安全头（不发 Cache-Control）。"""
    out = [('Content-Type', 'text/plain'),
           ('Content-Length', str(len(message.encode('utf-8'))))]
    return out + [list(x) for x in SECURITY]


def main():
    cases = []

    def add(name, method, path, status, body, note, source, query='', file_for_ct=None,
            length_from=None):
        if status == 200:
            hdrs = hdr_200(file_for_ct or path, method, body, length_text=length_from)
        else:
            hdrs = hdr_error(body)
        cases.append({
            'name': name,
            'method': method,
            'path': path,
            'query': query,
            'status': status,
            'headers': hdrs,
            'body': body,
            'note': note,
            'source': source,
        })

    # ── 200：正常文件 / 目录回落 ────────────────────────────────────────
    add('root_index', 'GET', '/', 200, FILES['index.html'],
        '请求 / ⇒ 回落根目录 index.html',
        'nginx.conf:4-6,18-20; frontend.py:49-50')
    add('index_explicit', 'GET', '/index.html', 200, FILES['index.html'],
        '显式 /index.html 与 / 等价',
        'nginx.conf:18-20')
    add('article', 'GET', '/article/x.html', 200, FILES['article/x.html'],
        '普通子目录文件；.html ⇒ 短缓存（长缓存未命中）',
        'nginx.conf:43（未命中）; frontend.py:78')
    add('list_dir_slash', 'GET', '/list/', 200, FILES['list/index.html'],
        '目录（带尾斜杠）⇒ 回落 index.html',
        'nginx.conf:18-20')
    add('list_dir_noslash', 'GET', '/list', 200, FILES['list/index.html'],
        '目录（无尾斜杠）⇒ 也给 index.html（nginx 会先 301 到 /list/，本实现不重定向）',
        'nginx.conf:18-20（登记为偏差 D-3）')
    add('percent_cjk', 'GET', '/article/%E4%B8%AD%E6%96%87.html', 200,
        FILES['article/中文.html'],
        'percent-decode：中文文件名（浏览器把 CJK 编码成 %XX）',
        'nginx 先解码再匹配 location；URL_DECODE（std.encode）',
        file_for_ct='/article/中文.html')

    # ── 200：长缓存命中 / 未命中 ───────────────────────────────────────
    add('css_long_cache', 'GET', '/style.css', 200, FILES['style.css'],
        'nginx.conf:43 命中 ⇒ public, max-age=31536000, immutable',
        'nginx.conf:43-47')
    add('woff2_long_cache', 'GET', '/font.woff2', 200, FILES['font.woff2'],
        '字体命中长缓存；MIME 取 nginx 值（见 divergences D-2）',
        'nginx.conf:43; 见 meta.divergences')
    add('woff_long_cache', 'GET', '/app.woff', 200, FILES['app.woff'],
        '.woff 也在 nginx.conf:43 的列表里',
        'nginx.conf:43')
    add('js_long_cache', 'GET', '/static/app.js', 200, FILES['static/app.js'],
        '.js 命中长缓存（子目录同样命中）',
        'nginx.conf:43')
    add('multibyte_length', 'GET', '/plain.txt', 200, FILES['plain.txt'],
        '含 CJK ⇒ Content-Length 必须是 **UTF-8 字节数**（不是码点数）',
        'frontend.py:77（len(bytes)）; BYTE_LEN')

    # ── 200：HEAD / query ──────────────────────────────────────────────
    add('head_article', 'HEAD', '/article/x.html', 200, '',
        'HEAD：body 空，但头齐全且 Content-Length 是**真实长度**',
        'HTTP 语义；frontend.py:75-79 的头集（Python 的 WSGI 不区分 HEAD）',
        length_from=FILES['article/x.html'])
    add('query_opt_ignored', 'GET', '/article/x.html', 200, FILES['article/x.html'],
        'query 不参与解析（对齐 WSGI 的 PATH_INFO / QUERY_STRING 分离）',
        'frontend.py:43（只用 PATH_INFO）', query='utm=1&a=2')
    add('path_with_query_string', 'GET', '/article/x.html?utm=1&a=2', 200,
        FILES['article/x.html'],
        'path 自带查询串也能切掉（入口兜底）',
        'frontend.py:43')

    # ── 404：不存在 / 隐藏 / 敏感 / 穿越 ───────────────────────────────
    add('not_found', 'GET', '/nope.html', 404, NOT_FOUND,
        '不存在 ⇒ 404（不得 500）', 'nginx.conf:19 =404; frontend.py:69-70')
    add('not_found_dir', 'GET', '/nope/', 404, NOT_FOUND,
        '不存在的目录 ⇒ 404', 'nginx.conf:19 =404')
    add('empty_dir_no_index', 'GET', '/emptydir/', 404, NOT_FOUND,
        '目录存在但没有 index.html ⇒ 404',
        'nginx.conf:18-20（try_files … =404）')
    add('hidden_git_config', 'GET', '/.git/config', 404, NOT_FOUND,
        '【反向守卫】隐藏路径 ⇒ 404', 'nginx.conf:50-53')
    add('hidden_dir_slash', 'GET', '/.git/', 404, NOT_FOUND,
        '【反向守卫】隐藏目录 ⇒ 404', 'nginx.conf:50-53')
    add('traversal_plain', 'GET', '/../secret.txt', 404, NOT_FOUND,
        '【反向守卫】字面 .. ⇒ 404（PATH_CONTAINS + 显式拒绝）',
        '卡 S3-1 反向守卫; security.py:269-287 的包含性判定')
    add('traversal_nested', 'GET', '/article/../../secret.txt', 404, NOT_FOUND,
        '【反向守卫】夹在中间 .. ⇒ 404', '卡 S3-1 反向守卫')
    add('traversal_encoded', 'GET', '/%2e%2e/secret.txt', 404, NOT_FOUND,
        '【反向守卫】percent-encoded .. ⇒ 解码后仍是 .. ⇒ 404',
        'nginx 先解码再匹配；卡 S3-1 反向守卫')
    add('sensitive_admin_password', 'GET', '/admin_password.txt', 404, NOT_FOUND,
        '【反向守卫】admin_password.txt ⇒ 404', 'nginx.conf:54-57')
    add('sensitive_env_file', 'GET', '/nested/.env', 404, NOT_FOUND,
        '.env 文件 ⇒ 404（隐藏规则也会命中，两条都对）', 'nginx.conf:50-57')
    add('sensitive_env_substring', 'GET', '/foo.env', 404, NOT_FOUND,
        '敏感名是**子串**匹配 ⇒ /foo.env 即使不存在也 404（不是「文件不存在」那一路）',
        'nginx.conf:54-57（`~*` 子串）')
    add('sensitive_git_substring', 'GET', '/my.git-repo/x.html', 404, NOT_FOUND,
        '`.git` 子串匹配 ⇒ /my.git-repo/… 也 404',
        'nginx.conf:54-57（`~*` 子串）')
    add('sensitive_case_insensitive', 'GET', '/Admin_Password.TXT', 404, NOT_FOUND,
        '敏感名大小写不敏感（nginx 用 `~*`）', 'nginx.conf:54（`~*`）')
    add('bad_percent_escape', 'GET', '/bad%zz', 404, NOT_FOUND,
        '非法 percent 转义 ⇒ fail closed 404', 'URL_DECODE 返 ERR（std.encode）')

    # ── 405：方法门 ────────────────────────────────────────────────────
    add('post_root', 'POST', '/', 405, METHOD_NOT_ALLOWED,
        'POST ⇒ 405（Python 的 StaticApp 没有这道门，见 D-4）', '卡 S3-1')
    add('put_index', 'PUT', '/index.html', 405, METHOD_NOT_ALLOWED,
        'PUT ⇒ 405', '卡 S3-1')
    add('delete_article', 'DELETE', '/article/x.html', 405, METHOD_NOT_ALLOWED,
        'DELETE ⇒ 405', '卡 S3-1')

    # ── 单元基准 ───────────────────────────────────────────────────────
    unit_mime = [
        ('a.html', 'text/html'),
        ('a.htm', 'text/html'),
        ('a.css', 'text/css'),
        ('a.js', 'application/javascript'),
        ('a.json', 'application/json'),
        ('a.webmanifest', 'application/manifest+json'),
        ('a.xml', 'text/xml'),
        ('a.txt', 'text/plain'),
        ('a.md', 'text/markdown'),
        ('a.png', 'image/png'),
        ('a.jpg', 'image/jpeg'),
        ('a.jpeg', 'image/jpeg'),
        ('a.gif', 'image/gif'),
        ('a.ico', 'image/x-icon'),
        ('a.svg', 'image/svg+xml'),
        ('a.webp', 'image/webp'),
        ('a.avif', 'image/avif'),
        ('a.woff', 'font/woff'),
        ('a.woff2', 'font/woff2'),
        ('a.ttf', 'font/ttf'),
        ('a.otf', 'font/otf'),
        ('a.pdf', 'application/pdf'),
        ('a.wasm', 'application/wasm'),
        # 回落（frontend.py:74 的 `or "text/html"`）
        ('noext', 'text/html'),
        ('a.unknownext', 'text/html'),
        ('dir/sub/page.html', 'text/html'),
        # 大小写：PATH_EXT 保留原大小写 ⇒ 查表前 TO_LOWER
        ('A.CSS', 'text/css'),
        ('A.WOFF2', 'font/woff2'),
    ]

    meta = {
        'generated_by': 'tp/test/gen_static_serve_baseline.py',
        'target': 'tp/lib/static_serve.wll（HANDLE / MIME_TYPE / SECURITY_HEADERS）',
        'sources': [
            'nginx.conf:4-6,18-20   index index.html + try_files $uri $uri/ =404',
            'nginx.conf:9-13        5 个安全头（顺序）',
            'nginx.conf:43-47       长缓存扩展名 js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2',
            'nginx.conf:50-53       location ~ /\\. ⇒ 404（隐藏文件）',
            'nginx.conf:54-57       admin_password.txt|.env|.git ⇒ 404（子串、大小写不敏感）',
            'tinypage/security.py:331   get_security_headers()（逐字逐序对照）',
            'tinypage/frontend.py:49-50 / ⇒ index.html',
            'tinypage/frontend.py:74-79 200 头的名字/取值/顺序',
            'tinypage/frontend.py:86-90 _error 的错误头',
            'tinypage/security.py:342   get_csp_header() 是 admin 专用 ⇒ 公开站不发',
        ],
        'decisions': {
            'cache_control_per_response': 1,
            'asset_long_cache': LONG_CACHE_VALUE,
            'non_asset_cache': SHORT_CACHE_VALUE,
            'header_order_200': ['Content-Type', 'Content-Length', 'Cache-Control',
                                 'X-Content-Type-Options', 'X-Frame-Options',
                                 'Referrer-Policy', 'Cross-Origin-Opener-Policy',
                                 'Permissions-Policy'],
            'header_order_error': ['Content-Type', 'Content-Length',
                                   'X-Content-Type-Options', 'X-Frame-Options',
                                   'Referrer-Policy', 'Cross-Origin-Opener-Policy',
                                   'Permissions-Policy'],
            'method_gate': 'GET / HEAD 之外一律 405（先于任何路径判定）',
            'query': '不参与解析',
        },
        'divergences': [
            'D-1 长缓存只发**一个** Cache-Control：nginx 的 expires 1y 与 '
            'add_header Cache-Control 并存会输出两个；Python StaticApp 全程只发一个'
            '（frontend.py:78）⇒ 取一个，值取卡 S3-1 的验收串。',
            'D-2 字体四个扩展名（woff/woff2/ttf/otf）的 MIME 取 nginx/IANA 值：本机 '
            'CPython 3.13 实测 mimetypes.guess_type 对它们返回 None ⇒ 照 '
            'frontend.py:74 的回落会发 text/html。该表随平台/注册表变化 ⇒ 不是契约。',
            'D-3 目录无尾斜杠（/list）直接给 index.html；nginx 会先 301 到 /list/。'
            '不引入重定向头。',
            'D-4 非 GET/HEAD ⇒ 405：nginx 与 Python StaticApp 都没有这道门（nginx 对 '
            '静态文件本就会回 405/400 之间的实现细节；Python 会照常返回 200 的体）'
            '⇒ 按卡 S3-1 显式实现。',
            'D-5 错误响应带 Content-Length 且放在 Content-Type 之后：Python 的 _error '
            '（frontend.py:88）不写 Content-Length（由 WSGI 服务器补），且把 '
            'Content-Type 放在最后 ⇒ 本实现统一头序（业务头在前、安全头在后），'
            '线上值相同、顺序不同。',
            'D-6 未采纳 security.py:283 的 safe_exts 扩展名白名单（它含 .woff2 却'
            '没有 .woff，且 nginx 侧没有这条）⇒ 公开站以 nginx 语义为准。',
        ],
        'findings': [
            'F-1 Permissions-Policy 的项数：卡 S3-1 写「9 项」，但 '
            'nginx.conf:13 与 tinypage/security.py:338 的取值里都只有 **8 项**'
            '（accelerometer / camera / geolocation / gyroscope / magnetometer / '
            'microphone / payment / usb）。本实现与**两个权威源逐字一致**'
            '（meta.cross_checks 的第 1 条就是这条断言），测试按 8 定格。',
            'F-2 HEAD 的 Content-Length 必须等于**文件真实字节数**（不是 0）：'
            '本次实现先按 0 写基准，测试直接把这个错误抓了出来。',
        ],
        'mime_measurement':
            'python -c "import mimetypes,sys;print(sys.version);'
            '[print(e, mimetypes.guess_type(\'x.\'+e)) for e in '
            '\'html htm css js json xml txt md png jpg jpeg gif ico svg webp avif '
            'woff woff2 ttf otf map pdf wasm webmanifest\'.split()]" '
            '→ CPython 3.13.13 (Windows)；woff/woff2/ttf/otf 实测 (None, None)',
        'cross_checks': [],
    }

    # ── 真 Python 交叉校验 ①：5 个安全头逐字逐序 ───────────────────────
    from tinypage.security import get_security_headers
    py_sec = [list(x) for x in get_security_headers()]
    assert py_sec == [list(x) for x in SECURITY], (py_sec, SECURITY)
    meta['cross_checks'].append(
        'security.py:331 get_security_headers() == SECURITY_HEADERS()（5 条、逐字、同序）')

    # ── 真 Python 交叉校验 ②：直接调 StaticApp 对照 200 用例 ───────────
    tmp = Path(tempfile.mkdtemp(prefix='tp-static-baseline-'))
    for d in DIRS:
        (tmp / d).mkdir(parents=True, exist_ok=True)
    for rel, text in FILES.items():
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding='utf-8', newline='\n')

    from tinypage.config import Config
    from tinypage.frontend import StaticApp
    app = StaticApp(Config(root_dir=tmp.resolve()))

    def py_get(path_info):
        captured = []

        def start_response(status, headers, exc_info=None):
            captured.append((status, headers))

        chunks = app({'PATH_INFO': path_info}, start_response)
        return captured[0][0], captured[0][1], b''.join(chunks)

    checks = [
        ('/index.html', 'index_explicit'),
        ('/article/x.html', 'article'),
        ('/plain.txt', 'multibyte_length'),
        ('/style.css', 'css_long_cache'),
    ]
    for path_info, case_name in checks:
        exp = next(c for c in cases if c['name'] == case_name)
        status, headers, raw = py_get(path_info)
        py_names = [k for k, _ in headers]
        py_map = dict(headers)
        assert status == '200 OK', (path_info, status)
        assert py_names[:3] == ['Content-Type', 'Content-Length', 'Cache-Control'], py_names
        assert py_names[3:] == [k for k, _ in SECURITY], py_names
        assert py_map['Content-Type'] == exp['headers'][0][1], (path_info, py_map)
        assert py_map['Content-Length'] == exp['headers'][1][1], (path_info, py_map)
        assert raw.decode('utf-8') == exp['body'], path_info
        if case_name == 'css_long_cache':
            # 已知偏差 D-1：Python 对静态资源也只发短缓存
            assert py_map['Cache-Control'] == SHORT_CACHE_VALUE, py_map
            meta['cross_checks'].append(
                'StaticApp(%s): 头序/CT/CL/body 全等；Cache-Control 为 %r（偏差 D-1）'
                % (path_info, py_map['Cache-Control']))
        else:
            assert py_map['Cache-Control'] == exp['headers'][2][1], (path_info, py_map)
            meta['cross_checks'].append(
                'StaticApp(%s): 头序/CT/CL/Cache-Control/5 个安全头/body 全等' % path_info)

    # 错误路径对照：Python 走 403/404 两条，头序不同（偏差 D-5）
    status_404, headers_404, body_404 = py_get('/nope.html')
    assert status_404 == '404 Not Found', status_404
    assert [k for k, _ in headers_404][0] == 'X-Content-Type-Options', headers_404
    assert body_404 == b'Not found', body_404
    meta['cross_checks'].append(
        'StaticApp(/nope.html): 404 + body %r + 5 个安全头在前；无 Content-Length'
        '（偏差 D-5）' % body_404.decode())
    status_403, _, body_403 = py_get('/../secret.txt')
    meta['cross_checks'].append(
        'StaticApp(/../secret.txt): Python 回 %s（403 路径检查）；本实现按 nginx '
        '与卡 S3-1 回 404（登记为偏差）' % status_403)

    payload = {
        'meta': meta,
        'tree': {'dirs': DIRS, 'files': FILES},
        'unit': {
            'security_headers': [list(x) for x in SECURITY],
            'mime': [{'path': p, 'want': w} for p, w in unit_mime],
        },
        'cases': cases,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.write('\n')
    print('wrote %s (%d cases, %d mime rows)' % (OUT, len(cases), len(unit_mime)))


if __name__ == '__main__':
    main()
