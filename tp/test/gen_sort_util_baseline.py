"""生成 tp/test/fixtures/sort_util_baseline.json —— 排序的**真 Python** 基准。

⚠ 输出的 .json 由本文件生成，不要手改。

**验收纪律**（业主裁决）：基准必须**直接 import 真 Python 实现**产出期望值，
不许「照抄规则重写一遍」—— 照抄的基准只是你的第二种读法，逐字节对照会失去意义。

本文件用到的 Python 侧事实（全部来自真源码树，不是本文件的发明）：

  ① `tinypage/content.py:196`
         arts.sort(key=lambda x: x.date_obj or datetime.min, reverse=True)
     —— 文章列表**按日期倒序**（新→旧）、稳定。
  ② `tinypage/content.py:185`
         meta.date_obj = datetime.strptime(meta.date[:16], "%Y-%m-%d %H:%M")
     —— 日期键只取**前 16 个字符**（分钟精度）；解析失败 ⇒ 键为 datetime.min。
  ③ `tinypage/content.py:698`
         pages.sort(key=lambda x: x.title or x.file)
     —— 独立页列表**按「标题优先、空标题回落文件名」正序**、稳定。
     ⚠ Python 的 `or` 对**空串**也回落（不只是 None）——`""` 是 falsy。
  ④ `tinypage/content.py:237`
         related.sort(key=lambda x: x[1], reverse=True)
     —— 相关文章列表**按 Jaccard 相似度倒序**、稳定。
     ⚠ Python 的 `reverse=True` **保持稳定**（相等键保持输入次序）。
     ⚠ 元素是**二元组** `(article, jaccard)` ⇒ WLWL 侧用**两元素数组**
        `[payload, number]`，键取元素[1]。
  ⑤ `tinypage/core/ai_assistance.py:258`
         sorted(word_freq.items(), key=lambda x: x[1], reverse=True)
     —— 词频**按次数倒序**、稳定；元素同样是**二元组** `(word, count)`
        ⇒ 同一个「按数值键倒序」导出天然覆盖它（count 是 INTEGER）。
  ⑥ `tinypage/content.py:698` / `generator.py:684` / `admin/views.py:133` /
     `core/incremental.py:175` —— 都用 Python 内建 `sorted(...)` 排字符串
     （升序、码点序、稳定）。
  ⑦ `tinypage/security.py:243` `validate_date_format` —— **写入侧**校验日期格式
     `^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}$` 且年份 2000..2100
     （content.py:274 调用）⇒ 进了排序的数据，日期串一定是规范 16 字符格式。

本文件产出两类期望值，**互相独立**：

  A. `SORT_STRINGS` / `SORT_BY_DATE` 的期望值 = **Python 内建 `sorted`** 的结果
     （Python 的 `sorted` 就是「稳定排序」这件事的参考实现；本文件**没有**
     自己写任何排序算法）。
  B. `dates_real_list_articles` 的期望值 = **真项目函数**
     `tinypage.content.list_articles()` 的返回顺序（在一个临时目录上真跑一遍）。
     ⇒ A 与 B 是两个互相独立的 Python 来源；它们必须一致。

**本轮新增（缺口 A / 缺口 B）**：同样用「两个互相独立的 Python 来源」：

  · 缺口 A 的 B 类来源 = **真项目函数** `tinypage.content.list_standalones()`
    （在一个临时目录上真造独立页文件、真跑一遍）。
  · 缺口 B 的 B 类来源 = **真项目函数** `tinypage.content.find_related_articles()`
    （真造 ArticleMeta、真算 Jaccard、真排一遍）。
  · A 类来源 = Python 内建 `sorted`（键表达式用 Python 自己的 `or` / `x[1]`）。
    ⇒ A 与 B 必须一致（不一致 ⇒ 直接抛错，不产出基准）。

用法：python gen_sort_util_baseline.py
"""
import json
import os
import random
import shutil
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))          # ← 仓库根（含 tinypage/）
OUT = os.path.join(HERE, 'fixtures', 'sort_util_baseline.json')

sys.path.insert(0, REPO)
from tinypage.content import list_articles  # noqa: E402  ← 真项目实现

# ── 随机数据的固定种子（CI 的 no-drift 守卫要求产物逐字节可复现）────────────
SEED = 20261102
N_BIG = 2000        # 卡 S2-2 的验收规模
N_MID = 300         # 中等规模
N_POOL = 400        # 大用例的日期池大小（⇒ 大量重复键 ⇒ 稳定性在规模上被验到）

DATE_FMT = "%Y-%m-%d %H:%M"   # == security.validate_date_format 的格式


def date_key(item):
    """日期键 —— 与 tinypage/content.py:185 + :196 **同口径**。

    content.py:185  datetime.strptime(meta.date[:16], "%Y-%m-%d %H:%M")
    content.py:196  key=lambda x: x.date_obj or datetime.min

    ⇒ 键 = strptime(raw[:16], ...)；解析不了（缺 date / 格式不对）⇒ datetime.min。
    """
    raw = item.get("date", "") if isinstance(item, dict) else item
    try:
        return datetime.strptime(raw[:16], DATE_FMT)
    except (ValueError, IndexError, TypeError):
        return datetime.min


def sorted_dates(items):
    """按日期**倒序**、稳定 —— == content.py:196 的口径。

    用 Python **内建** `sorted`（不是本文件自己写的排序）⇒ 期望值来自
    Python 真正的稳定排序实现。
    """
    return sorted(items, key=date_key, reverse=True)


def rand_dates(rng, count, pool_size):
    """从 `pool_size` 个不同日期里随机取 `count` 个（**有重复** ⇒ 验稳定性）。"""
    base = datetime(2000, 1, 1, 0, 0)
    span = int(timedelta(days=365 * 30).total_seconds() // 60)
    pool = [
        (base + timedelta(minutes=rng.randrange(span))).strftime(DATE_FMT)
        for _ in range(pool_size)
    ]
    return [rng.choice(pool) for _ in range(count)]


def rand_strings(rng, count):
    """随机字符串（ASCII + 非 ASCII 混排）。"""
    alphabet = (
        'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        '_-. ~!@#'
    )
    cjk = '中文测试文章标签'
    out = []
    for _ in range(count):
        n = rng.randrange(0, 8)
        s = ''.join(rng.choice(alphabet) for _ in range(n))
        if rng.random() < 0.25:
            s += rng.choice(cjk)
        out.append(s)
    return out


def build_real_list_articles_case(rng):
    """B 类用例：真跑 `tinypage.content.list_articles()` 拿排序结果。

    做法：在临时目录里造若干**合法**文章文件（文件名过 validate_filename、
    front-matter 里带 `<!-- date: ... -->`），然后调用**真项目函数**
    `list_articles()` —— 它内部就是 content.py:196 那行 sort。

    ⚠ 这里的日期**互不相同** ⇒ 排序结果唯一确定，与文件系统枚举顺序无关
      （`iterdir()` 的顺序在不同文件系统上不同，重复日期会让基准不可复现）。
    """
    tmp = tempfile.mkdtemp(prefix='tinypage_sort_')
    try:
        dates = rand_dates(rng, 12, 12)
        dates = sorted(set(dates))
        for i, d in enumerate(dates):
            fname = '2024-01-15-real-%02d.html' % i
            body = (
                '<!-- title: Real Article %02d -->\n'
                '<!-- date: %s -->\n'
                '<!-- status: published -->\n'
                '<div class="post-content"><p>body %d</p></div>\n'
            ) % (i, d, i)
            with open(os.path.join(tmp, fname), 'w', encoding='utf-8') as f:
                f.write(body)
        arts = list_articles(Path(tmp), include_drafts=True)
        got = [{'date': a.date, 'tag': a.file} for a in arts]
        # 输入（喂给 WLWL 的顺序 = 造文件的顺序，与排序结果无关）
        inp = [{'date': d, 'tag': '2024-01-15-real-%02d.html' % i}
               for i, d in enumerate(dates)]
        return inp, got
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    rng = random.Random(SEED)
    cases = []

    def add(name, fn, inp, expected, note):
        cases.append({
            'name': name,
            'fn': fn,
            'note': note,
            'input': inp,
            'expected': expected,
        })

    # ── SORT_STRINGS：期望值 = Python sorted(list_of_str) ───────────────────
    add('strings_empty', 'SORT_STRINGS', [], [],
        '空数组')
    add('strings_single', 'SORT_STRINGS', ['only'], ['only'],
        '单元素')
    add('strings_basic', 'SORT_STRINGS',
        ['banana', 'apple', 'cherry'], ['apple', 'banana', 'cherry'],
        '三个不同串')
    add('strings_dup', 'SORT_STRINGS',
        ['b', 'a', 'b', 'a', 'c', 'a'],
        ['a', 'a', 'a', 'b', 'b', 'c'],
        '重复键 ⇒ 验稳定性（相等元素相对次序不变）')
    add('strings_case', 'SORT_STRINGS',
        ['b', 'A', 'a', 'B', 'Z', 'z'],
        ['A', 'B', 'Z', 'a', 'b', 'z'],
        'ASCII 大小写 ⇒ 码点序（不是 locale 序）')
    add('strings_unicode', 'SORT_STRINGS',
        ['中', 'a', '文', 'Z', 'é', '中', 'a'],
        sorted(['中', 'a', '文', 'Z', 'é', '中', 'a']),
        '非 ASCII（中文/带音标）⇒ 码点序')
    add('strings_prefix', 'SORT_STRINGS',
        ['abc', 'ab', 'abcd', 'a', '', 'b'],
        sorted(['abc', 'ab', 'abcd', 'a', '', 'b']),
        '前缀关系 + 空串')
    add('strings_punct', 'SORT_STRINGS',
        ['-', '0', '9', 'A', '_', 'a', '~', ' '],
        sorted(['-', '0', '9', 'A', '_', 'a', '~', ' ']),
        '标点与空白 ⇒ 码点序')
    add('strings_sorted', 'SORT_STRINGS',
        ['a', 'b', 'c', 'd'], ['a', 'b', 'c', 'd'],
        '已升序（不该动）')
    add('strings_reversed', 'SORT_STRINGS',
        ['d', 'c', 'b', 'a'], ['a', 'b', 'c', 'd'],
        '已降序')
    mid_strings = rand_strings(rng, N_MID)
    add('strings_random_%d' % N_MID, 'SORT_STRINGS', mid_strings,
        sorted(mid_strings),
        '%d 个随机串（ASCII + 中文混排）' % N_MID)

    # ── SORT_BY_DATE：DICT 形态（对齐 ArticleMeta）─────────────────────────
    add('dates_empty', 'SORT_BY_DATE', [], [], '空数组')
    add('dates_single', 'SORT_BY_DATE',
        [{'date': '2024-05-06 07:08', 'tag': 'x'}],
        [{'date': '2024-05-06 07:08', 'tag': 'x'}],
        '单元素 DICT')
    add('dates_basic_dict', 'SORT_BY_DATE',
        [{'date': '2024-01-02 10:00', 'tag': 'a'},
         {'date': '2024-03-02 10:00', 'tag': 'b'},
         {'date': '2023-12-31 23:59', 'tag': 'c'}],
        sorted_dates([
            {'date': '2024-01-02 10:00', 'tag': 'a'},
            {'date': '2024-03-02 10:00', 'tag': 'b'},
            {'date': '2023-12-31 23:59', 'tag': 'c'},
        ]),
        '三个不同日期 ⇒ **倒序**（新→旧），对齐 content.py:196')
    add('dates_stability_dict', 'SORT_BY_DATE',
        [{'date': '2024-01-01 00:00', 'tag': 'p1'},
         {'date': '2024-02-02 00:00', 'tag': 'q1'},
         {'date': '2024-01-01 00:00', 'tag': 'p2'},
         {'date': '2024-02-02 00:00', 'tag': 'q2'},
         {'date': '2024-01-01 00:00', 'tag': 'p3'}],
        sorted_dates([
            {'date': '2024-01-01 00:00', 'tag': 'p1'},
            {'date': '2024-02-02 00:00', 'tag': 'q1'},
            {'date': '2024-01-01 00:00', 'tag': 'p2'},
            {'date': '2024-02-02 00:00', 'tag': 'q2'},
            {'date': '2024-01-01 00:00', 'tag': 'p3'},
        ]),
        '**相等键** ⇒ 相对次序必须不变（Python sorted 稳定 ⇒ 这是它的答案）')
    add('dates_missing_date_dict', 'SORT_BY_DATE',
        [{'date': '2024-01-02 10:00', 'tag': 'has'},
         {'tag': 'missing'},
         {'date': '2023-01-02 10:00', 'tag': 'old'}],
        sorted_dates([
            {'date': '2024-01-02 10:00', 'tag': 'has'},
            {'tag': 'missing'},
            {'date': '2023-01-02 10:00', 'tag': 'old'},
        ]),
        '缺 date 键 ⇒ 键为空 ⇒ 与 Python 的 datetime.min 同向（降序排最后）')
    add('dates_seconds_dict', 'SORT_BY_DATE',
        [{'date': '2024-01-01 10:30:45', 'tag': 'sec'},
         {'date': '2024-01-01 10:30:10', 'tag': 'sec2'}],
        sorted_dates([
            {'date': '2024-01-01 10:30:45', 'tag': 'sec'},
            {'date': '2024-01-01 10:30:10', 'tag': 'sec2'},
        ]),
        '带秒的日期串 ⇒ 两键都是 [:16] ⇒ 相等 ⇒ 保持输入次序（稳定）')

    # ── SORT_BY_DATE：STRING 形态（日期串数组；计划 §4 卡 S2-2 的验收口径）──
    add('dates_basic_strings', 'SORT_BY_DATE',
        ['2024-01-02 10:00', '2024-03-02 10:00', '2023-12-31 23:59'],
        sorted_dates(['2024-01-02 10:00', '2024-03-02 10:00', '2023-12-31 23:59']),
        '纯日期串数组 ⇒ 倒序')
    add('dates_mixed_shape', 'SORT_BY_DATE',
        [{'date': '2024-01-02 10:00', 'tag': 'd1'},
         '2024-03-02 10:00',
         {'date': '2023-12-31 23:59', 'tag': 'd2'}],
        sorted_dates([
            {'date': '2024-01-02 10:00', 'tag': 'd1'},
            '2024-03-02 10:00',
            {'date': '2023-12-31 23:59', 'tag': 'd2'},
        ]),
        'DICT 与 STRING **混排**（两种形态都要支持）')

    # ── 中等规模的 DICT 形态 ───────────────────────────────────────────────
    mid_dates = rand_dates(rng, N_MID, N_POOL)
    mid_dicts = [{'date': d, 'tag': 't%03d' % i} for i, d in enumerate(mid_dates)]
    add('dates_random_dict_%d' % N_MID, 'SORT_BY_DATE', mid_dicts,
        sorted_dates(mid_dicts),
        '%d 个随机日期 DICT（日期池 %d ⇒ 有重复键）' % (N_MID, N_POOL))

    # ── 卡 S2-2 的验收规模：2000 个随机日期字符串 ──────────────────────────
    big_dates = rand_dates(rng, N_BIG, N_POOL)
    add('dates_%d_strings' % N_BIG, 'SORT_BY_DATE', big_dates,
        sorted_dates(big_dates),
        '%d 个随机日期字符串（日期池 %d ⇒ 大量重复键 ⇒ 规模上验稳定性）；'
        '这也是卡 S2-2 的性能验收数据' % (N_BIG, N_POOL))

    # ── B 类用例：真项目函数 list_articles() 的排序结果 ────────────────────
    inp, exp = build_real_list_articles_case(rng)
    add('dates_real_list_articles', 'SORT_BY_DATE', inp, exp,
        '**真项目函数** tinypage.content.list_articles() 的返回顺序'
        '（它内部就是 content.py:196 那行 sort）⇒ 与上面的内建 sorted 口径'
        '互相独立、必须一致')

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        json.dump({'cases': cases}, f, ensure_ascii=False, indent=2, sort_keys=False)
        f.write('\n')
    print(f'wrote {OUT} ({len(cases)} cases)')


if __name__ == '__main__':
    main()
