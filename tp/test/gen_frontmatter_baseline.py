"""生成 tp/test/fixtures/frontmatter_baseline.json —— front-matter 的真 Python 基准。

对齐目标（三块，语义逐条来自真实实现）：
  · META_VALUE  == tinypage.core.article_store.meta_value        （真函数，直接 import）
  · META_HEADER == tinypage.content._meta_header                 （真函数，直接 import）
  · PARSE_META  == tinypage.content.parse_meta 的头部注释读取部分
                   ⚠ parse_meta 接收**文件路径**、会真开文件 ⇒ 无法直接喂字符串。
                   本文件用**与 parse_meta 逐字相同的正则与循环逻辑**复刻一个
                   parse_meta_from_text(text)（见下方函数注释，标明这是复刻）。

⚠ 明确不复刻：summary 从正文自动截 200 字（属 content 层，本卡范围外）。

用法：python gen_frontmatter_baseline.py
"""
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, REPO_ROOT)

# ── 真函数：直接 import，不复刻 ──────────────────────────────
from tinypage.core.article_store import meta_value  # noqa: E402
from tinypage.content import _meta_header  # noqa: E402

OUT = os.path.join(HERE, 'fixtures', 'frontmatter_baseline.json')

# 与 tinypage.content._META_ALLOWED_KEYS 逐字一致（frozenset，8 个键）
_META_ALLOWED_KEYS = frozenset(
    {
        "title",
        "date",
        "slug",
        "tags",
        "summary",
        "category",
        "status",
        "markdown",
    }
)


def parse_meta_from_text(text: str) -> dict:
    """【复刻】tinypage.content.parse_meta 的头部注释读取逻辑。

    parse_meta 接收文件路径并真开文件（且内部还做 summary 自动生成），
    不适合直接喂字符串 ⇒ 这里**逐字复刻**它的头部读取部分：
      ① `for i, line in enumerate(f): if i >= 7: break` —— 只看前 7 行（索引 0..6）；
      ② 每行先 `line.strip()`；
      ③ 同一条正则 `re.match(r"<!--\\s*(\\w+):\\s*(.*)\\s*-->")`（锚行首、不锚行尾；
         `(.*)` 贪婪 ⇒ 值吃到**最后一个** `-->` 之前的全部内容）；
      ④ key 在白名单里才记录，白名单外**静默忽略**；
      ⑤ `if not meta.status: meta.status = "published"`（空串/缺省都兜底）。

    行迭代用 io.StringIO(text)（默认 newline=None ⇒ 通用换行，与
    open(path, "r") 的逐行行为逐字一致：\\r\\n 与单独 \\r 都当行分隔符）。

    ⚠ 不在此复刻：summary 自动生成（content 层职责，本模块不做）。
    """
    meta = {}
    for i, line in enumerate(io.StringIO(text)):
        if i >= 7:
            break
        m = re.match(r"<!--\s*(\w+):\s*(.*)\s*-->", line.strip())
        if m:
            key, val = m.group(1), m.group(2).strip()
            if key in _META_ALLOWED_KEYS:
                meta[key] = val

    if not meta.get("status"):
        meta["status"] = "published"
    return meta


# ── META_VALUE 用例（真 meta_value） ─────────────────────────
MV_CASES = {
    # 连续换行压成**一个**空格（[\r\n]+ 是「一个或多个连续换行符」）
    'mv_collapse_newlines': 'a\n\n\nb',
    'mv_crlf': 'a\r\nb',
    'mv_mixed_newlines': 'a\nb\r\nc',
    'mv_lone_newline': '\n',
    # HTML 转义（quote=True ⇒ 单引号出 &#x27;）
    'mv_apostrophe': "it's",
    'mv_html': '<b>&x</b>',
    'mv_amp': '&',
    # TRIM：两端空白去掉（含 \t），内部保留
    'mv_strip_edges': '  pad  ',
    'mv_tab_edges': '\tx\t',
    'mv_empty': '',
    # 中文与 ASCII 混排
    'mv_cjk': '标题 & <正文>',
}

# meta_value 接收 object ⇒ 用 int 锁 STR(v) 的字符串化行为
MV_INT_CASES = {
    'mv_int': 42,
}

# ── PARSE_META 用例（复刻的 parse_meta_from_text） ───────────
PM_CASES = {
    # 全字段（7 行放不下 8 个键：此处 7 行 7 键，无 category）
    'pm_full_7keys': (
        '<!-- title: T -->\n'
        '<!-- date: 2026-01-01 -->\n'
        '<!-- slug: s-1 -->\n'
        '<!-- tags: a, b -->\n'
        '<!-- summary: sum -->\n'
        '<!-- markdown: body -->\n'
        '<!-- status: draft -->\n'
    ),
    # 含 category 的常规 7 行头
    'pm_full_category': (
        '<!-- title: 标题 -->\n'
        '<!-- date: 2026-02-02 -->\n'
        '<!-- slug: slug-2 -->\n'
        '<!-- tags: x -->\n'
        '<!-- summary: 摘要 -->\n'
        '<!-- category: cat -->\n'
        '<!-- status: published -->\n'
    ),
    # 没读到 status ⇒ 兜底 "published"
    'pm_default_status': (
        '<!-- title: t -->\n'
        '<!-- date: d -->\n'
        '<!-- tags: a -->\n'
    ),
    # status 行存在但值为空 ⇒ 触发 "published" 兜底（if not meta.status）
    #   （`: ` 之后只剩 `-->` 三字符，(.*) 贪婪回溯只能取空串 —— 实测确认）
    'pm_dash_value': '<!-- status: -->\n',
    # 白名单外的键静默丢弃
    'pm_bogus_dropped': (
        '<!-- title: t -->\n'
        '<!-- bogus: x -->\n'
        '<!-- date: 2026-03-03 -->\n'
    ),
    # 第 8 行（索引 7）的键**不得**被读入：前 6 行空行占位
    'pm_line8_ignored': (
        '<!-- title: t -->\n'
        '\n'
        '\n'
        '\n'
        '\n'
        '\n'
        '\n'
        '<!-- slug: toolate -->\n'
    ),
    # ⚠ 贪婪匹配：值吃到**最后一个** --> 之前
    'pm_greedy_tail': '<!-- title: a --> tail -->\n',
    # 行先 strip 再匹配；值两端空白再 strip
    'pm_indented_line': '    <!-- title:  hello world  -->   \n',
    # 值内部空白保留
    'pm_value_inner_spaces': '<!-- summary: a  b -->\n',
    # 值里可以有冒号
    'pm_colon_in_value': '<!-- summary: x: y -->\n',
    # 完全没有注释行 ⇒ 只有 status 兜底
    'pm_no_match': 'just text\nmore text\n',
    # 没闭合的 --> 不匹配
    'pm_unclosed': '<!-- title: x\n',
    # 空文本 ⇒ 只有 status 兜底
    'pm_empty': '',
    # CRLF 行尾（Python 通用换行 vs WLWL SPLIT_LINES 去 \r）
    'pm_crlf': (
        '<!-- title: t -->\r\n'
        '<!-- date: d -->\r\n'
        '<!-- tags: a -->\r\n'
    ),
    # 超过 7 行：只读前 7 行，第 8 行的 title 覆盖无效
    'pm_overflow10': (
        '<!-- title: first -->\n'
        '<!-- date: d -->\n'
        '<!-- slug: s -->\n'
        '<!-- tags: a -->\n'
        '<!-- summary: sum -->\n'
        '<!-- category: c -->\n'
        '<!-- status: draft -->\n'
        '<!-- title: later -->\n'
        '<!-- slug: even-later -->\n'
        '<!-- bogus: nope -->\n'
    ),
    # 往返①：真 _meta_header 的输出喂回 parse（含转义值）
    'pm_roundtrip_escaped': _meta_header(
        "T & 'x'", '2026-01-01', 'slug-1', 'a, b', 'sum\nmary', 'cat', 'draft'
    ),
    # 往返②：status 为空 ⇒ header 里 status 行的值解析回 "" ⇒ 兜底 "published"
    #   （锁真实行为：parse 不会把转义值还原，空 status 也确实触发兜底）
    'pm_roundtrip_status_blank': _meta_header(
        'T', 'D', 'S', 'G', 'U', 'C', ''
    ),
}

# ── META_HEADER 用例（真 _meta_header） ──────────────────────
MH_ARGS = {
    'mh_basic': ('标题', '2026-01-01', 'slug-1', 'a, b', 'sum', 'cat', 'draft'),
    'mh_newline_flatten': ('a\nb', 'D', 'S', 'G', 'x\r\ny', 'C', 'published'),
    'mh_apostrophe': ("it's", 'D', 'S', 'G', 'U', 'C', 'published'),
    'mh_empty_fields': ('', '', '', '', '', '', ''),
}


def main():
    out = {
        'meta_value': {},
        'parse_meta': {},
        'meta_header': {},
    }
    for name, src in MV_CASES.items():
        out['meta_value'][name] = {
            'src_type': 'str',
            'src': src,
            'want': meta_value(src),
        }
    for name, src in MV_INT_CASES.items():
        out['meta_value'][name] = {
            'src_type': 'int',
            'src': src,
            'want': meta_value(src),
        }
    for name, src in PM_CASES.items():
        out['parse_meta'][name] = {
            'src': src,
            'want': parse_meta_from_text(src),
        }
    for name, args in MH_ARGS.items():
        out['meta_header'][name] = {
            'args': list(args),
            'want': _meta_header(*args),
        }

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(out, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write('\n')
    n_mv = len(out['meta_value'])
    n_pm = len(out['parse_meta'])
    n_mh = len(out['meta_header'])
    print(f'wrote {OUT} (meta_value {n_mv}, parse_meta {n_pm}, meta_header {n_mh})')


if __name__ == '__main__':
    main()
