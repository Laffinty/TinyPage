"""生成 tp/lib/admin_ai.wll —— 管理后台 AI 端点适配层（卡 S5-3）。

⚠ 输出的 .wll 由本文件生成，不要手改（业主裁决 D7：.wll 一律由生成器产出）。

**权威实现**
  · `tinypage/admin/actions.py:296-329` —— `ai_assist()`：先判 AI 是否可用，
    **再**按 `action` 分派，未知 action 报 `未知操作: <action>`，出参
    永远是 `{"result": …}` / `{"error": …}`（200 + application/json）。
  · `tinypage/content.py:757-842` —— `translate_article()`（`/translate` 的正文层）：
    `lang_map = {"en": "English", "ja": "Japanese"}`（:794-795，**只有 ja**），
    `translate_text(raw, lang_name)`（:805），`summarize(translated, 200)`（:806）。

**这一层只做「分派 + 出参口径」**，五个能力本身全部复用卡 S5-2 的
`tp/lib/ai.wll`（163 个断言脱网全绿）：
  · 不重写提示词、不重写 HTTP、不重写降级 —— 只把 `opts.cfg` 摊平成
    ai.wll 认识的调用选项，再把它的结果交给 `JSON_ENVELOPE`。
  · `JSON_ENVELOPE` 就是出参口径（`{"result": …}` / `{"error": …}`），
    **不自己拼 JSON**。

**三条必须照抄的语义**
  ① 未启用 / 未配 key ⇒ `{"error": "AI 未启用或未配置 API Key"}`
     （actions.py:304 的**原文**，逐字；常量 `AIA_MSG_UNCONFIGURED` 只出现一次）
  ② 后端错误也必须是 JSON（actions.py:322-329：`AIAssistanceError` ⇒ 200 + JSON）
  ③ 未知 action ⇒ `{"error": "未知操作: <action>"}`（actions.py:320-321），
     **不得**落到某个能力的默认分支

**分派顺序照抄源码（actions.py:302-321）**：先 `build_ai_assistance(cfg)` 判空，
再分派。所以「未配置 + 未知 action」必须报**未配置**，不是「未知操作」——
这是本卡最容易写反的一处，测试里钉住了。

**登记在夹具 meta.divergences 的刻意语义（不沉默）**
  · `/translate` 的**文章层**（定位文件 / 摘要(200) / 落盘，content.py:776-840）
    不在本模块：`file`/`article_dir` 归文章层，本模块只交付「AI 这一跳」
    ⇒ `TRANSLATE_ENDPOINT` 收的是**正文文本**。
  · `/translate` 在 Python 里未配置时返回 `{"success": false, "error":
    "AI not configured. Set ai_api_key in config."}`（content.py:798-802，真实跑出来过，
    见夹具 `article_unconfigured`）；本模块按卡面第 ① 条统一用 ai_assist 的文案。
  · 非 JSON 响应体：Python 的 `json.loads` 抛 `JSONDecodeError`（**不是**
    `AIAssistanceError`）⇒ 未被捕获 ⇒ WSGI 层 500；我们返回 JSON 错误（本卡要求 ②）。
  · `ai_enabled` 只认布尔 TRUE（Python 认任意真值）—— 继承 ai.wll 的刻意语义 ⑥。
  · 目标语言按**语言码**映射：只有 `"ja"` ⇒ Japanese，其余（含未知码、
    甚至把语言*名*当码传）⇒ English（`lang_map.get(x, "English")` 的字面行为）。

**顶层命名**：私有名一律 `AIA_` 前缀（tp/README 坑 52：顶层绑定**跨模块共享**）。
公共面 4 个导出：`AI_ASSIST` / `TRANSLATE_ENDPOINT` / `AI_ASSIST_JSON` / `TRANSLATE_JSON`。

**出参形状（给接线方看）**
  · `AI_ASSIST(opts)`         → DICT，键就是 `JSON_ENVELOPE` 读的那几个：
                                成功 `{ok:TRUE, content}` 或 `{ok:TRUE, tags}`，
                                失败 `{ok:FALSE, error}`
  · `TRANSLATE_ENDPOINT(opts)`→ 同上（`/translate` 的文本层）
  · `AI_ASSIST_JSON(opts)`    → STRING，**等于** `JSON_ENVELOPE(AI_ASSIST(opts))`
  · `TRANSLATE_JSON(opts)`    → STRING，**等于** `JSON_ENVELOPE(TRANSLATE_ENDPOINT(opts))`
  ⇒ 接线方拿后者直接当响应体（200 + application/json），拿前者做动作层判断。

**opts 契约（一律 DICT）**
  · `action`   complete / polish / translate / summarize / suggest_tags
  · `text`     正文
  · `target`   目标语言**码**（en / ja；也接受 `lang` 同义键；缺省 en）
  · `cfg`      配置字典（ai_enabled / ai_api_key / ai_model / ai_provider /
               ai_endpoint，以及传输项 ca / verify / timeout_ms）
  · `exchange` 可选，注入假传输（卡 S5-1 的测试缝），原样透传

用法：python gen_admin_ai.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import fn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'lib', 'admin_ai.wll')

# actions.py:304 的原文（逐字，不许改文案）
MSG_UNCONFIGURED = 'AI 未启用或未配置 API Key'
# actions.py:321 的前缀（f"未知操作: {action}"）
MSG_UNKNOWN_PREFIX = '未知操作: '


def wl(s):
    """Python 字符串 → WLWL 字面量。⚠ `${…}` / `$x` 是插值 ⇒ 字面美元符写 \\$。"""
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


def main():
    src = []
    A = src.append

    A('// tp/lib/admin_ai.wll —— 管理后台 AI 端点适配层（卡 S5-3）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_admin_ai.py 生成 —— 请勿手改。')
    A('//')
    A('// 权威实现：')
    A('//   admin/actions.py:296-329  ai_assist()：判空 → 分派 → {"result"|"error"}')
    A('//   content.py:757-842        translate_article()：lang_map(:794-795) → translate_text(:805)')
    A('//')
    A('// 导出 → 权威源码行号')
    A('//   AI_ASSIST          admin/actions.py:302-304（判空）+ :307-321（分派表）+ :322-329（出参）')
    A('//   TRANSLATE_ENDPOINT content.py:794-805（lang_map + translate_text）')
    A('//                       + actions.py:311-315（/ai-assist 的 translate 分支，同一张 lang_map）')
    A('//   AI_ASSIST_JSON     admin/actions.py:325-329（200 + application/json）')
    A('//   TRANSLATE_JSON     同上')
    A('//')
    A('// 五个能力全部复用 tp/lib/ai.wll（卡 S5-2）：本模块只做「cfg 摊平 + 分派 + 出参口径」。')
    A('//')
    A('// 三条必须照抄的语义')
    A('//   ① 未启用/未配 key ⇒ {"error": "AI 未启用或未配置 API Key"}（actions.py:304 原文）')
    A('//   ② 后端错误也必须是 JSON（actions.py:322-329：错误也是 200 + JSON）')
    A('//   ③ 未知 action ⇒ {"error": "未知操作: <action>"}（actions.py:320-321），不落默认分支')
    A('//')
    A('// ⚠ 顺序：先判 AI 是否可用（:302-304），**再**分派（:307-321）')
    A('//   ⇒ 「未配置 + 未知 action」报**未配置**，不是「未知操作」')
    A('//')
    A('// ⚠ 目标语言是**码**：只有 "ja" ⇒ Japanese，其余 ⇒ English（lang_map.get 的字面行为）')
    A('//   把语言*名*当码传（如 "Japanese"）按源码口径会落到 English —— 别在接线层改这个')
    A('//')
    A('// ⚠ 顶层绑定跨模块共享（tp/README 坑 52）⇒ 私有名一律 AIA_ 前缀；')
    A('//   下面 4 个导出名是本卡的公共面，别处不得再用作顶层绑定。')
    A('')
    A('IMPORT("wlwl:std.str", ["CAT"]);')
    A('// 五个能力 + JSON_ENVELOPE（出参口径）全部来自卡 S5-2，不重写')
    A('IMPORT("./ai.wll", ["IS_ENABLED", "COMPLETE", "POLISH", "TRANSLATE", "SUMMARIZE",')
    A('        "SUGGEST_TAGS", "JSON_ENVELOPE"]);')
    A('')
    A('// ── 常量 ────────────────────────────────────────────────────────')
    A('// actions.py:304 的原文（逐字）。⚠ 只在这里出现一次：改文案就改这一处。')
    A('LET(AIA_MSG_UNCONFIGURED, %s);' % wl(MSG_UNCONFIGURED))
    A('// actions.py:321 的前缀（f"未知操作: {action}"）')
    A('LET(AIA_MSG_UNKNOWN, %s);' % wl(MSG_UNKNOWN_PREFIX))
    A('')

    # ── 小工具 ──────────────────────────────────────────────────────
    src += fn('AIA_STR', 'opts, key, d', [
        '// 取一个「必须是 STRING」的选项（NULL / 其它类型 ⇒ 缺省）',
        'LET(v, AT_K(opts, key, d))',
        'IF(==(TYPE(v), "STRING"), v, d)',
    ], '// 取 STRING 选项')

    src += fn('AIA_CFG', 'opts', [
        '// opts.cfg 是**配置字典**（ai_enabled / ai_api_key / ai_model / ai_provider / ai_endpoint）',
        '// ⚠ 不是 DICT ⇒ 当空配置（AT_K 对 NULL 基值是 E0030，坑 35）',
        'LET(c, AT_K(opts, "cfg", NULL))',
        'IF(==(TYPE(c), "DICT"), c, DICT())',
    ], '// 取配置字典')

    src += fn('AIA_TARGET', 'opts', [
        '// 目标语言**码**：actions.py:312 先取 lang（缺省 "English" ⇒ 映射后仍是 English）；',
        '//   本模块的 opts 用 `target`，并接受 `lang` 同义键',
        'LET(t, AIA_STR(opts, "target", ""))',
        'IF(!=(t, ""), t, AIA_STR(opts, "lang", "en"))',
    ], '// 目标语言码')

    src += fn('AIA_LANG_NAME', 'code', [
        '// actions.py:313-314 / content.py:794-795 的 lang_map：',
        '//   {"en": "English", "ja": "Japanese"}，`get(code, "English")`',
        '// ⇒ **只有** "ja" 是 Japanese；未知码、语言名（"Japanese"）都落 English',
        'IF(==(code, "ja"), "Japanese", "English")',
    ], '// 语言码 → 语言名（硬编码 en/ja）')

    src += fn('AIA_CALL_OPTS', 'opts', [
        '// 把 cfg 摊平成 ai.wll 认识的调用选项：cfg 打底 → 盖 text / target_lang → 透传 exchange',
        '// ⚠ ai.wll 读 `ai_enabled` / `ai_api_key` / `ai_model` / ...，正是配置名 ⇒ 直接沿用',
        'LET(base, INDEX_SET(INDEX_SET(AIA_CFG(opts), "text", AIA_STR(opts, "text", "")), "target_lang", AIA_LANG_NAME(AIA_TARGET(opts))))',
        'LET(ex, AT_K(opts, "exchange", NULL))',
        'IF(==(TYPE(ex), "FUNCTION"), INDEX_SET(base, "exchange", ex), base)',
    ], '// 摊平 cfg 成 ai.wll 的调用选项')

    src += fn('AIA_FAIL', 'message', [
        '// 动作层失败形状：JSON_ENVELOPE 读 ok / error（与 admin_actions 的 {ok, error} 同构）',
        'INDEX_SET(INDEX_SET(DICT(), "ok", FALSE), "error", message)',
    ], '// 动作层失败结果')

    # ── 分派 ────────────────────────────────────────────────────────
    src += fn('AIA_DISPATCH', 'action, o', [
        '// admin/actions.py:307-321 的分派表（顺序照抄）：complete / polish / translate /',
        '//   suggest_tags / summarize，最后 else 是「未知操作」（:320-321）',
        '// ⚠ 未知 action **不得**落到某个能力：最后一个分支只造错误',
        'IF(==(action, "complete"), COMPLETE(o), IF(==(action, "polish"), POLISH(o), '
        'IF(==(action, "translate"), TRANSLATE(o), IF(==(action, "suggest_tags"), SUGGEST_TAGS(o), '
        'IF(==(action, "summarize"), SUMMARIZE(o), AIA_FAIL(CAT(AIA_MSG_UNKNOWN, action)))))))',
    ], '// action 分派（未知 ⇒ 错误）')

    src += fn('AI_ASSIST', 'opts', [
        '// 对齐 admin/actions.py:296-329：',
        '//   ① 先判 AI 是否可用（:302-304）—— **早于**分派 ⇒ 未配置时连未知 action 也报未配置',
        '//   ② 再按 action 分派（:307-321），未知 action ⇒ 错误（:320-321）',
        '//   ③ 结果交给 JSON_ENVELOPE（:325-329）出 {"result":…} / {"error":…}',
        'LET(o, AIA_CALL_OPTS(opts))',
        'IF(!IS_ENABLED(AIA_CFG(opts)), AIA_FAIL(AIA_MSG_UNCONFIGURED), '
        'AIA_DISPATCH(AIA_STR(opts, "action", ""), o))',
    ], '// /ai-assist 的动作层（分派 + 出参）')

    src += fn('TRANSLATE_ENDPOINT', 'opts', [
        '// /translate 的**文本层**：content.py:794-805 的 lang_map + translate_text。',
        '// ⚠ 不在本模块：定位文章 / summarize(200) / 落盘（content.py:776-840）',
        '//   ⇒ 收的是正文文本；文章层调用方自己接（本层不碰文件系统）。',
        '// 未配置的文案按卡面第 ① 条统一（Python 的 /translate 另有文案，见夹具 meta.divergences）',
        'IF(!IS_ENABLED(AIA_CFG(opts)), AIA_FAIL(AIA_MSG_UNCONFIGURED), '
        'TRANSLATE(AIA_CALL_OPTS(opts)))',
    ], '// /translate 的 AI 一跳')

    src += fn('AI_ASSIST_JSON', 'opts', [
        '// 直接给出响应体：等于 JSON_ENVELOPE(AI_ASSIST(opts))（不自己拼 JSON）',
        'JSON_ENVELOPE(AI_ASSIST(opts))',
    ], '// /ai-assist 的响应体（JSON 文本）')

    src += fn('TRANSLATE_JSON', 'opts', [
        '// 直接给出响应体：等于 JSON_ENVELOPE(TRANSLATE_ENDPOINT(opts))',
        'JSON_ENVELOPE(TRANSLATE_ENDPOINT(opts))',
    ], '// /translate 的响应体（JSON 文本）')

    A('EXPORT(["AI_ASSIST", "TRANSLATE_ENDPOINT", "AI_ASSIST_JSON", "TRANSLATE_JSON"]);')

    chars, lines = write(OUT, src)
    print('wrote %s (%d chars, %d lines)' % (OUT, chars, lines))


if __name__ == '__main__':
    main()
