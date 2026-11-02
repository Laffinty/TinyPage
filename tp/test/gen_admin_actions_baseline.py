"""生成 tp/test/fixtures/admin_actions_baseline.json —— admin_actions 的真 Python 基准。

⚠ 输出的 .json 由本文件生成，不要手改。

**对齐目标（全部直接 import 真 Python 实现，不重写规则）**：

| 基准段 | 对齐的 Python 函数 | 位置 |
|---|---|---|
| `slugify` | `tinypage.security.slugify` | security.py:357 |
| `article.create` / `.save` / `.delete` | `actions.create_article` / `save_article` / `delete_article_action` | actions.py:37 / 67 / 96 |
| `page.create` / `.save` / `.delete` | `actions.create_page` / `save_page` / `delete_page_action` | actions.py:117 / 143 / 171 |
| `uploads` | `actions.upload_image` | actions.py:194 |
| `theme` | `actions.set_theme` + `_save_theme_config` | actions.py:348 / 367 |
| `preview` | `actions.live_preview`（内部 `parsers.render_markdown`） | actions.py:285 |
| `errors` | 上述动作的对外表现（`start_response` 的状态码 + 正文里的消息） | — |

**交叉校验**（生成期就断言，不是留给人看）：
  · 每个 `want_error` 都断言**真的是** Python 抛出来/回出来的那句（`ValueError` 的
    `str(e)` 或 `error_response` 正文里的子串）；对不上就让本脚本失败。
  · `article` / `page` 的期望文件内容取自**真写出来的文件**（`norm()` 归一化 CRLF），
    并额外断言「文章 .html == 7 行 meta 头」「独立页 .html == 2 行 meta 头」。
  · `theme` 段同时记录 Python 写的 config.json 原文与语义，**语义**必须等于我们记录的
    `expected_config`（D6：WLWL 侧用紧凑 + 键名排序，字节不同、语义相同）。

**为了能在临时目录里跑真代码做的三处 patch（只改「与本卡无关的副作用」）**：
  ① `tinypage.admin.actions.generate_static_pages` → no-op（全站构建不在本卡范围）
  ② `tinypage.generator.generate_standalone_html` → 返回 ""（D5：整页渲染不在本卡范围）
  ③ `tinypage.admin.actions.datetime` → 固定 2026-11-02（上传目录的 YYYY-MM 要确定）

**除这三处外**，所有写盘、校验、错误消息都由真 Python 产生。

**已知差异（D1–D11）不在本文件里「修正」**：夹具记录的是 Python 的口径；
WLWL 侧的差异在 `gen_admin_actions.py` 的 docstring 里逐条编号，测试里用
`deviations` 段单独钉（例如 `.jpeg` 一定会被 magic bytes 拒、slugify 的 `ü`）。

用法：python gen_admin_actions_baseline.py
"""
import base64
import io
import json
import os
import shutil
import sys
import tempfile
from contextlib import redirect_stdout
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, REPO_ROOT)

from tinypage.security import slugify  # noqa: E402
from tinypage import generator as tp_generator  # noqa: E402
from tinypage import content as tp_content  # noqa: E402
from tinypage.admin import actions  # noqa: E402
from tinypage.parsers import render_markdown  # noqa: E402

OUT = os.path.join(HERE, 'fixtures', 'admin_actions_baseline.json')

FIXED_NOW = datetime(2026, 11, 2, 12, 0, 0)


# ── 真 Python 的调用脚手架 ────────────────────────────────────────────
def norm(text):
    """Python 在 Windows 上文本模式写 CRLF ⇒ 归一成 LF 再比（差异 D7 / 陷阱 #55）。"""
    return text.replace('\r\n', '\n')


class Response:
    def __init__(self):
        self.status = None
        self.headers = None
        self.body = b''

    def start_response(self, status, headers):
        self.status = status
        self.headers = headers


def call(action, cfg, post_data, **kw):
    """调一个 actions.py 的处理函数，返回它的对外表现。"""
    resp = Response()
    body = action({}, resp.start_response, cfg, post_data, **kw)
    resp.body = b''.join(body)
    return resp


def mkcfg(root, name):
    base = Path(root) / name
    (base / 'articles').mkdir(parents=True, exist_ok=True)
    (base / 'pages').mkdir(parents=True, exist_ok=True)
    cfg = SimpleNamespace(
        article_dir=base / 'articles',
        standalone_dir=base / 'pages',
        max_file_size=10 * 1024 * 1024,
        static_dir=base / 'static',
    )

    def merge(**kw):
        merged = SimpleNamespace(**vars(cfg))
        for k, v in kw.items():
            setattr(merged, k, v)
        return merged

    cfg.merge = merge
    return cfg


def read(path):
    with io.open(path, encoding='utf-8', newline='') as f:
        return f.read()


# ── 期望值 ────────────────────────────────────────────────────────────
def slugify_cases():
    cases = []
    for title in [
        'Hello World',
        '中文 标题',
        'a--b',
        '  Trim Me  ',
        'Hello, World! 2026',
        'UPPER CASE',
        'a_b-c',
        '2026-01-02 标题',
        'x' * 100,
        ('y' * 79) + '--' + 'z',
        'Ünïcode',
    ]:
        cases.append({
            'title': title,
            'fallback': '',
            'want': slugify(title),
        })
    # 兜底形状（D4）：Python 是 untitled-<int(time.time())>，两边只能比**形状**
    for title in ['', '!!!', '---']:
        cases.append({
            'title': title,
            'fallback': 'fallback-x',
            'want': slugify(title, fallback='fallback-x'),
        })
    return cases


def article_section(root):
    cfg = mkcfg(root, 'article')
    p = Path(root) / 'article'

    create_post = {
        'title': ['Hello World'],
        'date': ['2026-01-02 10:30'],
        'content': ['正文 **粗体**\n\n- 一\n- 二'],
        'tags': ['a,b'],
        'category': ['tech'],
        'status': ['draft'],
    }
    resp = call(actions.create_article, cfg, create_post)
    fname = '2026-01-02-hello-world.html'
    html_path = cfg.article_dir / fname
    md_path = html_path.with_suffix('.md')
    assert resp.status == '302 Found', resp.status
    assert html_path.is_file(), 'create_article 没写出 .html'
    assert md_path.is_file(), 'create_article 没写出兄弟 .md'

    create = {
        'post': {k: v[0] for k, v in create_post.items()},
        'want_file': fname,
        'want_slug': 'hello-world',
        'md': norm(read(md_path)),
        'html': norm(read(html_path)),
        'status': resp.status,
    }
    # 文章 .html 必须是「7 行 meta 头」且正文为空（skip_html_generation）
    assert create['html'] == tp_content._meta_header(
        'Hello World', '2026-01-02 10:30', 'hello-world', 'a,b', '', 'tech', 'draft'), \
        '文章 .html 不等于 _meta_header（skip_html_generation 口径变了）'
    assert create['html'].count('-->') == 7

    # ── save：同 fname 覆盖 ──
    save_post = {
        'file': [fname],
        'title': ['Hello World v2'],
        'date': ['2026-01-03 08:00'],
        'content': ['第二版正文'],
        'tags': ['x'],
        'category': ['misc'],
        'status': ['published'],
    }
    resp2 = call(actions.save_article, cfg, save_post)
    assert resp2.status == '302 Found', resp2.status
    save = {
        'post': {k: v[0] for k, v in save_post.items()},
        'md': norm(read(md_path)),
        'html': norm(read(html_path)),
        'status': resp2.status,
    }
    assert save['md'] == '第二版正文'
    assert save['html'].count('-->') == 7

    # ── delete：成功路径 ──
    resp3 = call(actions.delete_article_action, cfg, {'file': [fname]})
    assert resp3.status == '302 Found', resp3.status
    assert not html_path.exists() and not md_path.exists(), 'delete_article 没删干净'
    delete = {
        'file': fname,
        'status': resp3.status,
        'backup_left': sorted(q.name for q in cfg.article_dir.iterdir()),
    }

    # ── delete：文件不存在 ⇒ 什么都不做（仍然 302）──
    resp4 = call(actions.delete_article_action, cfg, {'file': ['2026-01-02-nope.html']})
    delete_missing = {'file': '2026-01-02-nope.html', 'status': resp4.status}

    # ── delete：回滚（Python 侧注入 copy2 失败）──
    # 真失败点：把 shutil.copy2 打成「第二次调用就抛」，等价于「.md 备份失败」。
    # 断言：文章与 .md 都回到原位（对照 content.py:145-150 的 except 分支）。
    rcfg = mkcfg(root, 'article_rollback')
    rf = '2026-02-03-rollback.html'
    (rcfg.article_dir / rf).write_text('<!-- title: R -->\n', encoding='utf-8')
    (rcfg.article_dir / rf).with_suffix('.md').write_text('回滚正文', encoding='utf-8')
    real_copy2 = shutil.copy2
    calls = {'n': 0}

    def flaky_copy2(a, b, *args, **kw):
        calls['n'] += 1
        if calls['n'] >= 2:
            raise OSError('injected copy failure')
        return real_copy2(a, b, *args, **kw)

    shutil.copy2 = flaky_copy2
    raised = False
    try:
        tp_content.delete_article(rcfg.article_dir / rf)
    except OSError:
        raised = True
    finally:
        shutil.copy2 = real_copy2
    rollback = {
        'file': rf,
        'raised': raised,
        'html_still_there': (rcfg.article_dir / rf).is_file(),
        'md_still_there': (rcfg.article_dir / rf).with_suffix('.md').is_file(),
        'html_text': norm(read(rcfg.article_dir / rf)),
        'md_text': norm(read((rcfg.article_dir / rf).with_suffix('.md'))),
    }
    assert raised and rollback['html_still_there'] and rollback['md_still_there']

    # ── create：重名 → Python 换成 `<date>-<slug>-<token>.html` ──
    ccfg = mkcfg(root, 'article_collision')
    (ccfg.article_dir / fname).write_text('<!-- title: old -->\n', encoding='utf-8')
    # ⚠ token_urlsafe 的字母表含 `_`，而 SAFE_FILENAME_PATTERN 不含 ⇒ Python 自己
    #   有约 9% 概率把重名创建打成 ValueError（500）。这里把 token 钉死成不含 `_`
    #   的 6 字符，才能得到确定期望；该缺陷单独记录在 meta.findings 里。
    real_token = actions.secrets.token_urlsafe
    actions.secrets.token_urlsafe = lambda n=4: 'AbC123'
    try:
        resp5 = call(actions.create_article, ccfg, create_post)
    finally:
        actions.secrets.token_urlsafe = real_token
    names = sorted(q.name for q in ccfg.article_dir.iterdir() if q.suffix == '.html')
    assert resp5.status == '302 Found'
    prefix = '2026-01-02-hello-world-'
    others = [n for n in names if n != fname]
    assert len(others) == 1, names
    assert others[0] == prefix + 'AbC123.html', others[0]
    collision = {
        'existing': fname,
        'prefix': prefix,
        'names_after': names,
        'python_token_len': len('AbC123'),
        'spec': 'Python: secrets.token_urlsafe(4) ⇒ 6 字符；WLWL: opts.suffix 或 RANDOM_HEX(4) ⇒ 8 字符（差异 D2）',
        'want_file': prefix + 'AbC123.html',
        'want_suffix': 'AbC123',
    }

    return {
        'dirs': {'articles': 'articles', 'pages': 'pages'},
        'create': create,
        'save': save,
        'delete': delete,
        'delete_missing': delete_missing,
        'rollback': rollback,
        'collision': collision,
    }


def collision_prefix():
    return '2026-01-02-hello-world-'


def page_section(root):
    cfg = mkcfg(root, 'page')
    pdir = cfg.standalone_dir

    create_post = {
        'title': ['关于'],
        'slug': ['about'],
        'content': ['# 关于\n\n你好'],
    }
    resp = call(actions.create_page, cfg, create_post)
    assert resp.status == '302 Found', resp.status
    html_path = pdir / 'about.html'
    md_path = pdir / 'about.md'
    assert html_path.is_file() and md_path.is_file()
    html_text = norm(read(html_path))
    # D5：整页渲染被 patch 成 "" ⇒ 只剩两行 meta 头
    assert html_text == '<!-- title: 关于 -->\n<!-- summary:  -->\n', repr(html_text)

    create = {
        'post': {k: v[0] for k, v in create_post.items()},
        'want_file': 'about.html',
        'md': norm(read(md_path)),
        'html': html_text,
        'status': resp.status,
    }

    # save：slug 变了 ⇒ 旧文件被删、新文件生成
    save_post = {
        'file': ['about.html'],
        'title': ['联系'],
        'slug': ['contact'],
        'content': ['联系正文'],
    }
    resp2 = call(actions.save_page, cfg, save_post)
    assert resp2.status == '302 Found', resp2.status
    assert not (pdir / 'about.html').exists(), 'save_page 没删旧文件'
    assert (pdir / 'contact.html').is_file() and (pdir / 'contact.md').is_file()
    save = {
        'post': {k: v[0] for k, v in save_post.items()},
        'old_file': 'about.html',
        'new_file': 'contact.html',
        'md': norm(read(pdir / 'contact.md')),
        'html': norm(read(pdir / 'contact.html')),
        'status': resp2.status,
        'left': sorted(q.name for q in pdir.iterdir()),
    }

    # delete
    resp3 = call(actions.delete_page_action, cfg, {'file': ['contact.html']})
    assert resp3.status == '302 Found'
    assert not (pdir / 'contact.html').exists() and not (pdir / 'contact.md').exists()
    delete = {
        'file': 'contact.html',
        'status': resp3.status,
        'left': sorted(q.name for q in pdir.iterdir()),
    }

    return {'create': create, 'save': save, 'delete': delete}


def error_section(root):
    """每条错误：跑一次真动作，断言状态码 + 正文消息，然后把消息记下来。"""
    out = []

    def case(name, action, cfg, post, want_status, want_in_body, want_error):
        resp = call(action, cfg, post)
        body = resp.body.decode('utf-8', 'replace')
        assert resp.status == want_status, (name, resp.status, want_status)
        assert want_in_body in body, (name, body[:200], want_in_body)
        out.append({
            'name': name,
            'want_status': want_status,
            'want_error': want_error,
        })

    # ── create_article ──
    cfg = mkcfg(root, 'err_article')
    base = {'title': ['T'], 'date': ['2026-01-02 10:30'], 'content': ['c']}
    case('create_missing_title', actions.create_article, cfg,
         {**base, 'title': ['']}, '400 Bad Request', 'Missing fields', 'Missing fields')
    case('create_missing_date', actions.create_article, cfg,
         {**base, 'date': ['']}, '400 Bad Request', 'Missing fields', 'Missing fields')

    # 写盘层：ValueError（被 WSGI 兜成 500）——这里直接捕获 str(e)
    def value_error(fn, *args, **kw):
        try:
            fn(*args, **kw)
        except ValueError as e:
            return str(e)
        raise AssertionError('expected ValueError')

    msg = value_error(tp_content.write_article, cfg.article_dir,
                      'bad-name.html', 'T', '2026-01-02 10:30', 't', 'c',
                      '', '', '', 'published', skip_html_generation=True)
    assert msg == 'Invalid filename: bad-name.html', msg
    out.append({'name': 'write_invalid_filename', 'want_status': None,
                'want_error': msg})

    msg = value_error(tp_content.write_article, cfg.article_dir,
                      '2026-01-02-t.html', 'T' * 201, '2026-01-02 10:30', 't', 'c',
                      '', '', '', 'published', skip_html_generation=True)
    assert msg == 'Title invalid or too long: 201', msg
    out.append({'name': 'write_title_201', 'want_status': None, 'want_error': msg})

    msg = value_error(tp_content.write_article, cfg.article_dir,
                      '2026-01-02-t.html', 'T', '2026-01-02 10:30', 't', 'x' * 50001,
                      '', '', '', 'published', skip_html_generation=True)
    assert msg == 'Content validation failed: length=50001', msg
    out.append({'name': 'write_content_50001', 'want_status': None, 'want_error': msg})

    msg = value_error(tp_content.write_article, cfg.article_dir,
                      '2026-01-02-t.html', 'T', '2026-13-01 10:00', 't', 'c',
                      '', '', '', 'published', skip_html_generation=True)
    assert msg == 'Invalid date format: 2026-13-01 10:00', msg
    out.append({'name': 'write_bad_date', 'want_status': None, 'want_error': msg})

    # ── save_article 的表单级校验 ──
    case('save_missing_file', actions.save_article, cfg,
         {'file': [''], 'title': ['T'], 'date': ['2026-01-02 10:30'], 'content': ['c']},
         '400 Bad Request', 'Missing fields', 'Missing fields')
    case('save_invalid_filename', actions.save_article, cfg,
         {'file': ['bad.html'], 'title': ['T'], 'date': ['2026-01-02 10:30'],
          'content': ['c']}, '400 Bad Request', 'Invalid filename', 'Invalid filename')

    # ── delete_article ──
    case('delete_invalid_filename', actions.delete_article_action, cfg,
         {'file': ['/etc/passwd']}, '400 Bad Request', 'Invalid filename',
         'Invalid filename')

    # ── create_page ──
    pcfg = mkcfg(root, 'err_page')
    case('page_missing_slug', actions.create_page, pcfg,
         {'title': ['T'], 'slug': [''], 'content': ['c']},
         '400 Bad Request', 'Missing fields', 'Missing fields')
    case('page_invalid_slug', actions.create_page, pcfg,
         {'title': ['T'], 'slug': ['a/b'], 'content': ['c']},
         '400 Bad Request', 'Invalid slug', 'Invalid slug')
    (pcfg.standalone_dir / 'dup.html').write_text('<!-- title: d -->\n', encoding='utf-8')
    case('page_exists', actions.create_page, pcfg,
         {'title': ['T'], 'slug': ['dup'], 'content': ['c']},
         '409 Conflict', 'Page already exists', 'Page already exists')

    # ── save_page / delete_page ──
    case('save_page_invalid_filename', actions.save_page, pcfg,
         {'file': ['a b.html'], 'title': ['T'], 'slug': ['s'], 'content': ['c']},
         '400 Bad Request', 'Invalid filename', 'Invalid filename')
    case('delete_page_invalid_filename', actions.delete_page_action, pcfg,
         {'file': ['x.txt']}, '400 Bad Request', 'Invalid filename', 'Invalid filename')

    # ── set_theme ──
    case('theme_missing_name', actions.set_theme, pcfg, {'theme': ['']},
         '400 Bad Request', 'Missing theme name', 'Missing theme name')
    case('theme_not_found', actions.set_theme, pcfg, {'theme': ['nope']},
         '400 Bad Request', 'Theme not found', 'Theme not found')

    # ── upload ──
    case('upload_missing', actions.upload_image, pcfg, {'filename': [''], 'data': ['x']},
         '400 Bad Request', 'Missing filename or data', 'Missing filename or data')
    case('upload_bad_ext', actions.upload_image, pcfg,
         {'filename': ['shell.php'], 'data': [base64.b64encode(b'<?php').decode()]},
         '400 Bad Request', 'File type not allowed', 'File type not allowed: .php')
    case('upload_bad_b64', actions.upload_image, pcfg,
         {'filename': ['a.png'], 'data': ['AAAAA']},
         '400 Bad Request', 'Invalid base64 data', 'Invalid base64 data')
    case('upload_wrong_magic', actions.upload_image, pcfg,
         {'filename': ['a.png'], 'data': [base64.b64encode(b'<?php echo 1; ?>').decode()]},
         '400 Bad Request', 'Invalid image format', 'Invalid image format')
    return out


# ── 上传 ──────────────────────────────────────────────────────────────
PNG_1PX = base64.b64decode(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFAAH/q842'
    'iQAAAABJRU5ErkJggg==')
GIF_1PX = base64.b64decode('R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7')
JPEG_1PX = base64.b64decode(
    '/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0'
    'aHBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/wAALCAABAAEBAREA/8QAFAABAAAAAAAA'
    'AAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AVN//2Q==')
WEBP_1PX = b'RIFF' + (20).to_bytes(4, 'little') + b'WEBPVP8 ' + b'\x00' * 8


def upload_section(root):
    real_datetime = actions.datetime

    class FakeDatetime:
        @classmethod
        def now(cls):
            return FIXED_NOW

    actions.datetime = FakeDatetime
    out = []
    try:
        cases = [
            ('png_ok', 'a.png', base64.b64encode(PNG_1PX).decode(), None),
            ('jpeg_ok', 'b.jpg', base64.b64encode(JPEG_1PX).decode(), None),
            ('gif_ok', 'c.gif', base64.b64encode(GIF_1PX).decode(), None),
            ('webp_ok', 'd.webp', base64.b64encode(WEBP_1PX).decode(), None),
            # D10：`.jpeg` 在白名单里，但 magic 的 expected_ext 是 `.jpg` ⇒ 必拒
            ('jpeg_ext_rejected', 'e.jpeg', base64.b64encode(JPEG_1PX).decode(),
             'Invalid image format'),
            # D10：WEBP 的 12 字节分支是死代码 ⇒ 只要 RIFF 就过
            ('webp_riff_only', 'f.webp', base64.b64encode(b'RIFF' + b'\x00' * 12).decode(),
             None),
            # 扩展名白名单：内容再合法也拒
            ('php_ext_rejected', 'g.php', base64.b64encode(PNG_1PX).decode(),
             'File type not allowed: .php'),
            ('html_ext_rejected', 'h.html', base64.b64encode(PNG_1PX).decode(),
             'File type not allowed: .html'),
            # 扩展名合法但内容是 PHP（magic bytes 挡）
            ('php_as_png', 'i.png', base64.b64encode(b'<?php echo 1; ?>').decode(),
             'Invalid image format'),
            # data URL 前缀（只在第一个逗号处切）
            ('data_url', 'j.png',
             'data:image/png;base64,' + base64.b64encode(PNG_1PX).decode(), None),
            # 非法 base64：长度「比 4 的倍数多 1」/ 缺补位
            ('bad_base64_len1', 'k.png', 'AAAAA', 'Invalid base64 data'),
            ('bad_base64_nopad', 'l.png', 'QQ', 'Invalid base64 data'),
        ]
        for name, filename, data, want_err in cases:
            base = Path(root) / ('up_' + name)
            static = base / 'static'
            static.mkdir(parents=True, exist_ok=True)
            cfg = SimpleNamespace(static_dir=static)
            resp = call(actions.upload_image, cfg, {'filename': [filename], 'data': [data]})
            body = json.loads(resp.body.decode('utf-8'))
            files = sorted(p for p in static.rglob('*') if p.is_file())
            rec = {
                'name': name,
                'filename': filename,
                'data': data,
                'want_ok': want_err is None,
                'want_error_prefix': want_err,
                'want_status': resp.status,
                'files': [],
            }
            if want_err is None:
                assert body.get('success') is True, (name, body)
                assert len(files) == 1, (name, files)
                rec['want_url'] = body['url']
                rel = files[0].relative_to(static).as_posix()
                rec['file'] = rel
                rec['bytes'] = list(files[0].read_bytes())
                assert body['url'].endswith('/' + files[0].name), (name, body, rel)
            else:
                assert want_err in json.dumps(body, ensure_ascii=False), (name, body)
            out.append(rec)

        # 重名：同名再传一次 ⇒ `-1`
        base = Path(root) / 'up_collision'
        static = base / 'static'
        static.mkdir(parents=True, exist_ok=True)
        cfg = SimpleNamespace(static_dir=static)
        first = PNG_1PX
        second = GIF_1PX  # 内容不同，便于确认 -1 是新内容
        call(actions.upload_image, cfg, {'filename': ['same.png'],
                                         'data': [base64.b64encode(first).decode()]})
        # 第二次仍用 .png 名，但内容换成 PNG 变体，避免扩展名/magic 拦截
        second = PNG_1PX + b'\x00\x00'
        resp = call(actions.upload_image, cfg, {'filename': ['same.png'],
                                                'data': [base64.b64encode(second).decode()]})
        body = json.loads(resp.body.decode('utf-8'))
        files = sorted(p for p in static.rglob('*') if p.is_file())
        names = [p.name for p in files]
        assert body['url'].endswith('/same-1.png'), body
        out.append({
            'name': 'collision',
            'filename': 'same.png',
            'data': base64.b64encode(second).decode(),
            'precreate': [{'file': 'same.png', 'bytes': list(first)}],
            'want_ok': True,
            'want_url': body['url'],
            'file': [p.relative_to(static).as_posix() for p in files if p.name == 'same-1.png'][0],
            'bytes': list([p for p in files if p.name == 'same-1.png'][0].read_bytes()),
            'all_names': names,
        })
    finally:
        actions.datetime = real_datetime
    return out


# ── 主题 ──────────────────────────────────────────────────────────────
def theme_section(root):
    base = Path(root) / 'theme'
    base.mkdir(parents=True, exist_ok=True)
    (base / 'themes' / 'default').mkdir(parents=True, exist_ok=True)
    (base / 'themes' / 'default' / 'manifest.json').write_text(
        '{"name": "default"}', encoding='utf-8')

    old_cwd = os.getcwd()
    os.chdir(base)
    try:
        # ① 全新（没有 .tinypage/config.json）
        cfg = mkcfg(root, 'theme_cfg')
        resp = call(actions.set_theme, cfg, {'theme': ['default']})
        assert resp.status == '302 Found', resp.status
        fresh = json.loads((base / '.tinypage' / 'config.json').read_text(encoding='utf-8'))
        fresh_text = (base / '.tinypage' / 'config.json').read_text(encoding='utf-8')
        assert fresh == {'theme_name': 'default'}, fresh

        # ② 已有配置 ⇒ 合并（既有键保留）
        (base / '.tinypage' / 'config.json').write_text(
            json.dumps({'locale': 'zh'}, ensure_ascii=False), encoding='utf-8')
        resp2 = call(actions.set_theme, cfg, {'theme': ['default']})
        merged = json.loads((base / '.tinypage' / 'config.json').read_text(encoding='utf-8'))
        assert merged == {'locale': 'zh', 'theme_name': 'default'}, merged

        # ③ 已有配置文件是坏 JSON ⇒ Python 只 warning、**不写**（内容原样）
        (base / '.tinypage' / 'config.json').write_text('{oops', encoding='utf-8')
        resp3 = call(actions.set_theme, cfg, {'theme': ['default']})
        broken_text = (base / '.tinypage' / 'config.json').read_text(encoding='utf-8')
        assert broken_text == '{oops', broken_text
        assert resp3.status == '302 Found', resp3.status
    finally:
        os.chdir(old_cwd)

    return {
        'theme': 'default',
        'manifest': 'themes/default/manifest.json',
        'fresh_config': json.dumps({'theme_name': 'default'}, ensure_ascii=False,
                                   sort_keys=True, separators=(',', ':')),
        'merged_config': json.dumps({'locale': 'zh', 'theme_name': 'default'},
                                    ensure_ascii=False, sort_keys=True,
                                    separators=(',', ':')),
        'broken_input': '{oops',
        'python_fresh_bytes': fresh_text,
    }


# ── 预览 ──────────────────────────────────────────────────────────────
def preview_section(root):
    cfg = mkcfg(root, 'preview')
    contents = [
        '# 标题\n\n正文 **粗** 与 `code`\n',
        '- a\n- b\n',
        '段落一\n\n段落二\n',
        '',
    ]
    out = []
    for c in contents:
        resp = call(actions.live_preview, cfg, {'content': [c]})
        out.append({
            'content': c,
            'want_html': resp.body.decode('utf-8'),
        })
    # 空内容 ⇒ 占位串（actions.py:290）
    assert out[-1]['want_html'] == '<p class="preview-placeholder">（无内容）</p>', \
        out[-1]['want_html']
    return out


def main():
    root = tempfile.mkdtemp(prefix='adm_base_')
    real_generate = actions.generate_static_pages
    real_standalone = tp_generator.generate_standalone_html
    actions.generate_static_pages = lambda *a, **k: None
    tp_generator.generate_standalone_html = lambda **k: ''
    try:
        art = article_section(root)
        page = page_section(root)
        errs = error_section(root)
        ups = upload_section(root)
        theme = theme_section(root)
        prev = preview_section(root)
    finally:
        actions.generate_static_pages = real_generate
        tp_generator.generate_standalone_html = real_standalone
        shutil.rmtree(root, ignore_errors=True)

    fixture = {
        'meta': {
            'source': 'tinypage/admin/actions.py + tinypage/content.py',
            'fixed_now': '2026-11-02 12:00:00',
            'patches': [
                'actions.generate_static_pages -> no-op（全站构建不在 S4-4 范围）',
                'generator.generate_standalone_html -> ""（差异 D5：整页渲染交给 REGEN）',
                'actions.datetime -> 2026-11-02（上传目录的 YYYY-MM 要确定）',
            ],
            'line_endings': 'D7：Python 写 CRLF，WLWL 写 LF ⇒ 两侧都归一成 LF 再比',
            # 真跑出来的上游缺陷（不是我们的差异）：重名 token 可能带 `_`
            'findings': [
                {
                    'id': 'F1',
                    'where': 'actions.py:54 + security.py:22',
                    'bug': '重名分支用 secrets.token_urlsafe(4)（字母表含 `_`），'
                           '而 SAFE_FILENAME_PATTERN 不允许 `_` ⇒ 约 9% 的重名创建会抛 '
                           'ValueError("Invalid filename: …")（500）',
                    'evidence': {
                        'pattern_rejects_underscore': not bool(
                            __import__('tinypage.security', fromlist=['SAFE_FILENAME_PATTERN'])
                            .SAFE_FILENAME_PATTERN.match(
                                '2026-01-02-hello-world-_LPQbA.html')),
                        'observed_value_error': 'Invalid filename: '
                                                '2026-01-02-hello-world-_LPQbA.html',
                    },
                    'wlwl_side': 'D2 用 opts.suffix 或 RANDOM_HEX(4)（纯十六进制）'
                                 '⇒ 不可能含 `_` 或 `-`，不会踩到这条',
                },
            ],
        },
        'slugify': slugify_cases(),
        # 已知差异：夹具里记录**两套值**（Python 的 / WLWL 的），让测试正面钉住差异，
        # 而不是把差异藏进「没比这一条」。
        'deviations': {
            # D3：Python 的 \w 是 Unicode；WLWL 侧只认 ASCII + CJK
            'slug_unicode': {
                'title': 'Ünïcode',
                'python': slugify('Ünïcode'),
                'wlwl': 'n-code',
                'why': 'D3: Python \\w 匹配 Unicode 字母；WLWL 的正则类只有 ASCII + CJK'
                       ' ⇒ ü/ï 各被换成 "-"，再被折叠/去首尾 ⇒ "n-code"',
            },
            # D1b：binascii 对「多一个 = 的补位」比我们宽松
            'b64_lenient_pad': {
                'data': 'AAAA=',
                'python_bytes': list(base64.b64decode('AAAA=')),
                'wlwl': 'Invalid base64 data',
                'why': 'D1b: binascii 容忍多余的 "="（AAAA= 解出 3 字节）；'
                       '本模块要求「= 只在结尾且补位后恰好补齐一组」⇒ 报 Invalid base64 data。'
                       '两种口径下都不可能通过 magic bytes ⇒ 对外都是 Invalid image format/Invalid base64 data，'
                       '差别只在错误码。',
            },
        },
        'article': art,
        'page': page,
        'errors': errs,
        'uploads': ups,
        'theme': theme,
        'preview': prev,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with io.open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(fixture, f, ensure_ascii=False, indent=1)
        f.write('\n')
    print('wrote %s' % OUT)


if __name__ == '__main__':
    main()
