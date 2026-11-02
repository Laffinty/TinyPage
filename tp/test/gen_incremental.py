"""生成 tp/lib/incremental.wll —— 增量构建（对齐 tinypage/core/incremental.py）。

⚠ 输出的 .wll 由本文件生成，不要手改（业主裁决 D7：.wll 一律由生成器产出）。

**对齐的 Python 实现**（`tinypage/core/incremental.py`，真源码树）：

  · `SHOULD_USE_INCREMENTAL(opts) -> BOOLEAN`        （:131 `should_use_incremental`）
        Python 签名是 `(source_dir, output_dir, threshold=100)`；WLWL 侧按卡片契约改成
        「传**计数**」：opts 键 = `article_count` / `modified_count` / `threshold`。
        口径逐条对齐：
          `article_count < threshold`            ⇒ FALSE
          `modified_ratio = modified_count / article_count`（`article_count == 0` ⇒ 1.0）
          `modified_ratio < 0.1`（**严格小于**）  ⇒ TRUE
        ⚠ threshold 的默认值 **100** 来自函数签名（:134），不是配置文件。
        ⚠ `article_count` 的口径在 Python 侧是 `len(list(source_dir.glob("*.html")))` ——
          **会把名字以 `.html` 结尾的目录也算进去**（实测）。WLWL 侧收的是现成计数
          ⇒ 该口径由调用方负责（本函数不碰目录）。
        ⚠ 比值必须是**浮点**除法：WLWL 的 `/(整数, 整数)` 是**截断除法**（实测
          `/(1, 10)` = 0，不是 0.1）⇒ 两侧都先 `FLOAT(...)`，否则 1/10 会被算成 0
          ⇒ 「恰好 0.1」那条边界判反。

  · `BUILD_CACHE_KEY(opts) -> STRING`                 （:159 `build_cache_key`）
        opts 键 = `article_dir`（STRING）。
        口径：
          目录**不存在** ⇒ 字面量 `"empty"`
          否则：`sorted(glob("*.html"))` 每项拼 `"<名>:<int(st_mtime)>"`，
                用 `|` 连接 ⇒ `sha256(utf8).hexdigest()[:12]`
        ⚠ `int(st_mtime)` 是**秒级截断**；`FILE_META` / `DIR_ENTRIES` 的 `mtime` 是
          **毫秒** ⇒ 必须自己 `/1000`（截断除法，对非负毫秒即 floor）。
        ⚠ 存在的**空目录**不是 `"empty"`：内容是空串 ⇒ `sha256("")[:12]` =
          `e3b0c44298fc`（实测）。两者必须分开。
        ⚠ `glob("*.html")` 会把**目录**也算进去（实测 `dir.html/` 被匹配），而 Python 的
          `f.stat()` 对目录给**真实 mtime**；`DIR_ENTRIES` 却把目录的 `mtime` **归零**
          ⇒ 目录项必须另取 `FILE_META`，否则含同名目录的目录会算出不同的 key。
        ⚠ 排序：Python 的 `sorted(WindowsPath)` 按 **lower** 比较；`DIR_ENTRIES` 的
          「按名排序」是**码点序** ⇒ 仅「大小写交错」的名字集合会有差异（见
          `LIMITATIONS` 注释与夹具 `limitations.case_interleaved_order`）。
        ⚠ SHA256 吃的是**字符串**（按 UTF-8 字节哈希，输出**小写** 64 位 hex，
          实测 `SHA256("abc")` = NIST 检验值）⇒ `[:12]` 用 `SUB(..., 0, 12)`。

  · `GET_UNCHANGED(opts) -> DICT`                     （:182 `get_unchanged_articles`）
        opts 键 = `article_dir` / `cache`（DICT 名→秒；或 NULL）
        返回 `{"unchanged": ARRAY[STRING], "modified": ARRAY[STRING]}`，
        元素是**文件名**（不含目录），两组都按**名字升序**（= `DIR_ENTRIES` 的序）。
        口径（**本卡唯一一处故意与现状不同**，详见下）：
          · 枚举 `article_dir` 下的 `*.html` **文件**（目录不参与：目录不是文章）；
          · `cache` 不是 DICT（NULL / 缺失 / 类型错）⇒ **全部进 modified**；
          · 否则逐文件比：`cache[名]` 是 INTEGER 且 == 当前秒 ⇒ unchanged，否则 modified
            （键缺失 = 新增文件 ⇒ modified；值不等 = 已改 ⇒ modified；值不是整数 ⇒ modified）；
          · `cache` 里有、目录里已无的名字 ⇒ **两组都不出现**（没有对应文章；删除须由调用方另处）。

**⚠ 故意与 Python 不同的一处（卡面要求）—— 「判定目录不匹配」缺陷**

    Python `get_unchanged_articles` 的兜底路径是：

        modified_files = get_modified_files(article_dir, article_dir)   # :207

    把 `article_dir` **同时**当 source 与 output ⇒ `out = article_dir / src.name` 就是
    `src` **自己** ⇒ `src.stat().st_mtime > out.stat().st_mtime` **恒假**
    ⇒ `modified_files` **恒空** ⇒ 每篇都被判「未变」。
    实测（夹具 `known_differences[0].evidence`，由真 Python 跑出）：
      · 改 `a.html` 的 mtime 后 key 从 `c48123754eb4` 变成 `674ff4c0f72b`（内容确实变了），
        但 `changed` 仍是 `[]`；
      · **新增** `c.html` 后 `changed` 仍是 `[]`。
    ⇒ 后果：调用方按 `changed` 决定重建 ⇒ **该重建的全被漏掉**；若调用方另把
      「key 变了但 changed 为空」当异常，就只能退回**全量重建**（卡面「恒全量重建」
      就是这条链的下游表现）。
    ⇒ **WLWL 侧不再复现**：不与任何目录比较，改为**逐文件比 cache 里记录的秒级 mtime**；
      `cache` 缺失 ⇒ 全部 modified（退化为全量重建 = 安全侧，而不是静默不重建）。
      ⚠ 判据**仍是 mtime**（秒级截断），**不引入内容 hash** —— 反向守卫在
      `tp/test/gen_test_incremental.py` 里（静态禁 `READ_FILE` / `READ_BYTES`，
      并用「毫秒版 digest 必须不等」钉住秒级截断）。

**已知没做到（不是「故意差异」，见夹具 `limitations`）**
  · 大小写交错的名字集合：Python 按 lower 排序、`DIR_ENTRIES` 按码点 ⇒ key 不同。
    本卡不重排（lower 相同的名字在 Python 侧本身按文件系统枚举序 ⇒ 不可复现）。
  · 目录不可读（权限）：`FILE_META` 返 ERR ⇒ 本模块按「不存在」处理 ⇒ `"empty"`；
    Python 的 `exists()` 会吞掉 OSError。本机造不出稳定复现 ⇒ 未实测。

**逐字节对照基准**：tp/test/fixtures/incremental_baseline.json
    （由 tp/test/gen_incremental_baseline.py 用**真 Python** 生成）

用法：python gen_incremental.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, fn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'lib', 'incremental.wll')


def main():
    src = []
    A = src.append

    # ── 文件头 ──────────────────────────────────────────────────────────
    A('// tp/lib/incremental.wll —— 增量构建（对齐 tinypage/core/incremental.py）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_incremental.py 生成 —— 请勿手改。')
    A('//   改实现请改生成器（WLWL 的括号诊断不告诉你缺了几层）。')
    A('//')
    A('// 导出（三个）：')
    A('//   SHOULD_USE_INCREMENTAL(opts) -> BOOLEAN   opts: article_count / modified_count / threshold')
    A('//        == tinypage/core/incremental.py:131 should_use_incremental')
    A('//        article_count < threshold ⇒ FALSE；ratio = modified/article（0 篇 ⇒ 1.0）；')
    A('//        ratio **<** 0.1（严格小于）⇒ TRUE。threshold 默认 100（来自函数签名 :134）。')
    A('//        ⚠ 比值必须走浮点：WLWL 的 /(整数, 整数) 是截断除法（实测 /(1,10)=0）。')
    A('//   BUILD_CACHE_KEY(opts) -> STRING           opts: article_dir')
    A('//        == incremental.py:159 build_cache_key')
    A('//        sorted(glob("*.html")) 取 "<名>:<int(st_mtime)>"（**秒级截断**）用 | 拼接')
    A('//        ⇒ sha256 的**前 12 位**；目录不存在 ⇒ "empty"（存在但空 ⇒ sha256("")[:12]）。')
    A('//        ⚠ mtime 是**毫秒** ⇒ 必须按 1000 整除。')
    A('//   GET_UNCHANGED(opts) -> DICT              opts: article_dir / cache')
    A('//        == incremental.py:182 get_unchanged_articles（**故意修掉兜底缺陷**，见下）')
    A('//        返回 ["unchanged": [名…], "modified": [名…]]，两组按名字升序。')
    A('//')
    A('// ⚠ 故意与 Python 不同的一处：「判定目录不匹配」缺陷')
    A('//   Python 的兜底路径 get_modified_files(article_dir, article_dir)（:207）把同一目录')
    A('//   既当 source 又当 output ⇒ src.st_mtime > out.st_mtime 恒假 ⇒ modified 恒空')
    A('//   ⇒ 该重建的全被漏掉（实测：改 mtime 后 key 变了但 changed=[]；新增文件也 changed=[]）。')
    A('//   WLWL 侧改为**逐文件与 cache 里记录的秒级 mtime 比**；cache 缺失 ⇒ 全部 modified。')
    A('//   ⚠ 判据仍是 mtime，**不引入内容 hash**。')
    A('//')
    A('// 已知没做到：大小写交错的名字集合排序口径不同（Python 按 lower、DIR_ENTRIES 按码点）；')
    A('//   目录不可读时按「不存在」处理。两项都登记在夹具 limitations 里。')
    A('//')
    A('// 逐字节对照基准：tp/test/fixtures/incremental_baseline.json')
    A('//   （由 tp/test/gen_incremental_baseline.py 用真 Python 生成）')
    A('')
    A('IMPORT("wlwl:std.encode", ["SHA256"]);')
    A('IMPORT("wlwl:std.fs", ["DIR_ENTRIES", "FILE_META", "PATH_EXT"]);')
    A('IMPORT("wlwl:std.str", ["CAT", "JOIN"]);')
    A('')

    # ── 内部工具 ────────────────────────────────────────────────────────
    src += fn('_OPT', 'opts, key, dflt', [
        '// opts 不是 DICT ⇒ 回落 dflt（AT_K(NULL, …) 是运行时 E0030，坑 35）。',
        'IF(==(TYPE(opts), "DICT"), AT_K(opts, key, dflt), dflt)',
    ], '// 内部：读 opts 的一个键')

    src += fn('_IS_HTML_NAME', 'name', [
        '// 对齐 Python glob("*.html")：只比**后缀**，大小写敏感（实测 A.HTML 不匹配）。',
        '==(PATH_EXT(name), "html")',
    ], '// 内部：名字是否 *.html')

    src += fn('_DIR_MS', 'path', [
        '// DIR_ENTRIES 把**目录**的 mtime 归零 ⇒ 目录项必须另取 FILE_META',
        '// （Python 的 f.stat() 对目录给真实 mtime ⇒ 不补这一步 key 就对不上）。',
        '// ⚠ FILE_META 可能返 ERR ⇒ 直接内联进 IS_ERR（坑 25）；ERR 时按 0 处理',
        '//   （未实测的边界，见夹具 limitations.permission_denied_dir）。',
        'IF(IS_ERR(FILE_META(path)), 0, AT_K(FILE_META(path), "mtime", 0))',
    ], '// 内部：目录的真实 mtime（毫秒）')

    src += fn('_ENTRY_MS', 'dir, e', [
        '// 文件用 DIR_ENTRIES 的 mtime（一次 stat 的快照）；目录走 FILE_META。',
        'IF(AT_K(e, "is_dir", FALSE), '
        '_DIR_MS(CAT(dir, "/", AT_K(e, "name", ""))), '
        'AT_K(e, "mtime", 0))',
    ], '// 内部：一个目录项的 mtime（毫秒）')

    src += fn('_ENTRY_SEC', 'dir, e', [
        '// 毫秒 → **秒级截断**：== Python 的 int(st_mtime)（对非负毫秒即 floor）。',
        '// ⚠ 这里是本模块唯一的「秒级」入口；改成毫秒会立刻被反向守卫抓住。',
        '/(_ENTRY_MS(dir, e), 1000)',
    ], '// 内部：一个目录项的 mtime（秒级截断，== Python int(st_mtime)）')

    src += fn('_CACHE_LINE', 'dir, e', [
        '// == Python 的 f"{f.name}:{int(f.stat().st_mtime)}"',
        'CAT(AT_K(e, "name", ""), ":", STR(_ENTRY_SEC(dir, e)))',
    ], '// 内部：preimage 的一行 "<名>:<秒>"')

    # ── 导出 1：SHOULD_USE_INCREMENTAL ─────────────────────────────────
    src += fn('SHOULD_USE_INCREMENTAL', 'opts', [
        'LET MUT(article_count, _OPT(opts, "article_count", 0))',
        'LET MUT(modified_count, _OPT(opts, "modified_count", 0))',
        'LET MUT(threshold, _OPT(opts, "threshold", 100))',
        '// Python 的顺序就是这三步：先篇数阈值，再比值；0 篇时比值取 1.0（不除零）。',
        C('IF', '<(article_count, threshold)', ['FALSE'], [
            C('IF', '<=(article_count, 0)', ['FALSE'], [
                '// 浮点除法：/(整数, 整数) 是截断除法 ⇒ 1/10 会变 0（实测）。',
                '<(/(FLOAT(modified_count), FLOAT(article_count)), 0.1)',
            ]),
        ]),
    ], '// 是否值得走增量（== Python incremental.py:131）')

    # ── 导出 2：BUILD_CACHE_KEY ────────────────────────────────────────
    build_body = [
        'LET MUT(dir, _OPT(opts, "article_dir", ""))',
        '// Python: `if not article_dir.exists(): return "empty"`（:171）。',
        'LET MUT(exists, IF(IS_ERR(FILE_META(dir)), FALSE, '
        'AT_K(FILE_META(dir), "exists", FALSE)))',
        C('IF', '!(exists)', ['"empty"'], [
            '// 存在但不是目录（例如传了文件）⇒ DIR_ENTRIES 返 ERR；',
            '// Python 侧 glob 对文件路径给空集 ⇒ 内容是空串 ⇒ 同一个 digest。',
            C('IF', 'IS_ERR(DIR_ENTRIES(dir))', ['SUB(SHA256(""), 0, 12)'], [
                'LET MUT(lines, [])',
                C('FOR', 'e, DIR_ENTRIES(dir)', [
                    C('IF', '_IS_HTML_NAME(AT_K(e, "name", ""))', [
                        'SET(lines, PUSH(lines, _CACHE_LINE(dir, e)))',
                    ], [
                        'NULL',
                    ]),
                ]),
                '// DIR_ENTRIES 已按名排序（spec std.fs）⇒ 与 Python 的 sorted() 同序',
                '// （除大小写交错，见文件头）。JOIN 的空数组 ⇒ "" ⇒ 与空目录同 digest。',
                'SUB(SHA256(JOIN(lines, "|")), 0, 12)',
            ]),
        ]),
    ]
    src += fn('BUILD_CACHE_KEY', 'opts', build_body,
              '// 目录状态摘要（== Python incremental.py:159）')

    # ── 导出 3：GET_UNCHANGED ──────────────────────────────────────────
    inner_for = [
        '// 目录项不参与：目录不是文章（Python 侧的 articles 全是文件）。',
        C('IF', 'AT_K(e, "is_dir", FALSE)', ['NULL'], [
            C('IF', '!(_IS_HTML_NAME(AT_K(e, "name", "")))', ['NULL'], [
                'LET(nm, AT_K(e, "name", ""))',
                'LET(sec, _ENTRY_SEC(dir, e))',
                '// cache 不是 DICT 时不能 AT_K（坑 35）⇒ 先判类型再取值。',
                'LET(cached, IF(==(TYPE(cache), "DICT"), AT_K(cache, nm, NULL), NULL))',
                C('IF', '&&(==(TYPE(cached), "INTEGER"), ==(cached, sec))', [
                    'SET(unchanged, PUSH(unchanged, nm))',
                ], [
                    'SET(modified, PUSH(modified, nm))',
                ]),
            ]),
        ]),
    ]
    gu_body = [
        'LET MUT(dir, _OPT(opts, "article_dir", ""))',
        'LET MUT(cache, _OPT(opts, "cache", NULL))',
        '// 两组都按名字升序（DIR_ENTRIES 的序）—— 返回形状写死在文件头。',
        'LET MUT(unchanged, [])',
        'LET MUT(modified, [])',
        C('IF', 'IS_ERR(DIR_ENTRIES(dir))', ['NULL'], [
            C('FOR', 'e, DIR_ENTRIES(dir)', inner_for),
        ]),
        '["unchanged": unchanged, "modified": modified]',
    ]
    src += fn('GET_UNCHANGED', 'opts', gu_body,
              '// 按 cache 分出「未变 / 已变」（== Python :182，但修掉兜底缺陷）')

    A('// 导出面（三个，卡 S2-5 的契约）')
    A('EXPORT(["BUILD_CACHE_KEY", "GET_UNCHANGED", "SHOULD_USE_INCREMENTAL"]);')

    chars, lines = write(OUT, src)
    print('wrote %s (%d chars, %d lines)' % (OUT, chars, lines))


if __name__ == '__main__':
    main()
