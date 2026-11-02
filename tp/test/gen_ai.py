"""生成 tp/lib/ai.wll —— 五个 AI 能力与降级（卡 S5-2）。

⚠ 输出的 .wll 由本文件生成，不要手改（业主裁决 D7：.wll 一律由生成器产出）。

**权威实现**：`tinypage/core/ai_assistance.py`（`AIAssistance` 的五个方法 +
`build_ai_assistance`），端点形状取自 `tinypage/admin/actions.py:296-329`。

**分层（本卡的核心设计决定）**
  · `BUILD_MESSAGES(opts)`   纯函数：能力名 + 文本 ⇒ system/user 两条消息 + temperature + model
  · `EXTRACT_CONTENT(opts)`  纯函数：响应 JSON ⇒ `choices[0].message.content`
  · `FINISH(opts)`           纯函数：能力相关的后处理（strip / 摘要截断 / 标签解析）
  · `FALLBACK_SUGGEST_TAGS`  纯函数：词频降级（脱网可测）
  · `ENDPOINT_PARTS(opts)`   纯函数：provider 缺省端点 + URL 拆成 host/port/path
  · `JSON_ENVELOPE(opts)`    纯函数：错误也要是 JSON（卡 S5-2 的反向守卫）
  · `IS_ENABLED(opts)`       纯函数：`build_ai_assistance` 的「未配置 ⇒ 不构建」
  · `COMPLETE` / `POLISH` / `TRANSLATE` / `SUMMARIZE` / `SUGGEST_TAGS`
                             **有网络**：建消息 → `HTTPS_POST_JSON`（卡 S5-1）→ 解析 → 后处理

**为什么不重写 HTTP/TLS**：卡 S5-1 的 `tp/lib/http_client_tls.wll` 已经做了请求报文、
响应解析、Content-Length、4xx/5xx 判定；本模块只把 `body` 交给它、把它的 `body` 拿回来。
⚠ 唯一的例外是**请求体**：它按 `STRINGIFY`（紧凑 + 键名字典序）序列化，与 Python 的
`json.dumps`（`", "` / `": "` + 插入序）**字节不同**（登记在夹具的 `meta.divergences`）。

**五处刻意语义（都登记在夹具的 `meta.divergences`，不是沉默偏离）**
  ① `content` 缺字段 / 不是字符串 ⇒ `ok:FALSE`（Python 静默给 `""`）；
  ② 端点结尾的 `/` 先剥再拼（Python 会拼出 `//chat/completions`）；
  ③ 只接受 `https://` 端点（传输层 TLS-only，明文 http 明确失败）；
  ④ JSON 出参保留原字符（Python 的 `json.dumps` 默认写 `\\uXXXX`）；
  ⑤ 请求体按 `STRINGIFY` 口径（见上）。
  另：`ai_enabled` 只认布尔 `TRUE`（Python 认任意真值）。

**没有 `max_tokens`**：卡面提到「`model`、`max_tokens` 等」，但**源码里没有**
（`_call_api` 的 payload 只有 model / messages / temperature，ai_assistance.py:61-65）
⇒ 按「以源码为准」不新增该字段，免得发出 Python 不发的东西。

**错误形状**（全模块统一，调用方只需判 `ok`）
  · 失败：`{"ok": FALSE, "status": INTEGER|NULL, "error": STRING}`
  · 文本类成功：`{"ok": TRUE, "status": INTEGER|NULL, "content": STRING}`
  · 标签类成功：`{"ok": TRUE, "tags": ARRAY, "fallback": BOOLEAN}`
  · `BUILD_MESSAGES`：`{ok, capability, model, temperature, messages, skip}`
  · `FINISH`：`{ok, content}` / `{ok, tags, valid_shape}` / `{ok: FALSE, status, error}`

**顶层命名**：私有名一律 `AI_` 前缀（tp/README 坑 52：顶层绑定**跨模块共享**）。
下面 12 个导出名是本卡的公共面；同仓其它模块**不得**再把它们用作顶层绑定。

**测试缝**：`opts.exchange` 会原样透传给 `HTTPS_POST_JSON`（卡 S5-1 的注入点）
⇒ 测试能在**完全不碰网络**的情况下跑完「建消息 → 建请求 → 解析 → 定 ok → 后处理」。

用法：python gen_ai.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import C, fn, write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'lib', 'ai.wll')

DEFAULT_MODEL = 'gpt-3.5-turbo'
EP_OPENAI = 'https://api.openai.com/v1'
EP_DEEPSEEK = 'https://api.deepseek.com/v1'
TIMEOUT_MS = 30000
TAGS_TEXT_MAX = 2000
MAX_LENGTH_DEFAULT = 160
MAX_TAGS_DEFAULT = 5

# ── 与 Python 逐字相同的提示词（ai_assistance.py:103,130,157,184,216）────────
SYS_COMPLETE = ("You are a helpful writing assistant. Continue the user's text "
                "naturally and coherently.")
SYS_POLISH = ("You are a professional editor. Improve the text for clarity, flow, "
              "and style while keeping the original meaning. Only return the improved "
              "text, no explanations.")
SYS_TRANSLATE = ("You are a professional translator. Translate the text to {} "
                 "accurately and naturally. Only return the translated text, "
                 "no explanations.")
SYS_SUMMARIZE = ("You are a content summarizer. Create a concise summary in no more "
                 "than {} characters. The summary should capture the main points. "
                 "Only return the summary, no labels.")
SYS_TAGS = ('You are a content analyst. Suggest exactly {} relevant tags for this '
            'article. Tags should be short (1-3 words), lowercase, and relevant to '
            'the main topics. Return ONLY a JSON array of tag strings, like '
            '["python", "web", "tutorial"]. No explanations.')

# 停用词表（ai_assistance.py:245-250，逐字）
STOPWORDS = ["的", "了", "是", "在", "和", "与", "或", "这", "那", "也", "都",
             "the", "a", "an", "is", "are", "was", "were", "be", "been",
             "and", "or", "but", "in", "on", "at", "to", "for", "of",
             "with", "by", "from", "as", "that", "this", "it"]

# Python str.isspace() 的 29 个字符（UTF-8 字节）；同 tp/lib/article_page.wll 的 PY_WS。
# ⚠ 内建 TRIM 只剥 ASCII 空白（坑 41）⇒ 要对齐 Python 的 .strip() 必须用这一集合。
PY_WS_BYTES = [9, 10, 11, 12, 13, 28, 29, 30, 31, 32, 194, 133, 194, 160, 225, 154,
               128, 226, 128, 128, 226, 128, 129, 226, 128, 130, 226, 128, 131,
               226, 128, 132, 226, 128, 133, 226, 128, 134, 226, 128, 135,
               226, 128, 136, 226, 128, 137, 226, 128, 138, 226, 128, 168,
               226, 128, 169, 226, 128, 175, 226, 129, 159, 227, 128, 128]


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


def iset(pairs, base='DICT()'):
    """[(k, v_expr)] → 一条嵌套 INDEX_SET 表达式（单行，括号由本函数配平）。"""
    expr = base
    for k, v in pairs:
        expr = 'INDEX_SET(%s, %s, %s)' % (expr, wl(k), v)
    return expr


def main():
    src = []
    A = src.append

    A('// tp/lib/ai.wll —— 五个 AI 能力与降级（卡 S5-2）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_ai.py 生成 —— 请勿手改。')
    A('//')
    A('// 权威实现：tinypage/core/ai_assistance.py（AIAssistance + build_ai_assistance），')
    A('//   端点形状取自 tinypage/admin/actions.py:296-329。')
    A('//')
    A('// 分层（传输层**不在**这里 —— 请求报文/响应解析/TLS 全在 tp/lib/http_client_tls.wll）：')
    A('//   BUILD_MESSAGES        纯函数：能力名 + 文本 ⇒ system/user 两条消息 + temperature + model')
    A('//   EXTRACT_CONTENT       纯函数：响应 JSON ⇒ choices[0].message.content')
    A('//   FINISH                纯函数：能力相关的后处理（strip / 摘要截断 / 标签解析）')
    A('//   FALLBACK_SUGGEST_TAGS 纯函数：词频降级（脱网可测）')
    A('//   ENDPOINT_PARTS        纯函数：provider 缺省端点 + URL 拆 host/port/path')
    A('//   JSON_ENVELOPE         纯函数：**错误也要是 JSON**（卡 S5-2 的反向守卫）')
    A('//   IS_ENABLED            纯函数：build_ai_assistance 的「未配置 ⇒ 不构建」')
    A('//   COMPLETE / POLISH / TRANSLATE / SUMMARIZE / SUGGEST_TAGS')
    A('//                         建消息 → HTTPS_POST_JSON（卡 S5-1）→ 解析 → 后处理')
    A('//')
    A('// 导出 → 权威源码行号')
    A('//   IS_ENABLED            ai_assistance.py:273-276')
    A('//   BUILD_MESSAGES        :103-110 / :127-136 / :154-163 / :181-190 / :213-222（messages）')
    A('//                         + :112 / :138 / :165 / :192 / :225（temperature）')
    A('//   EXTRACT_CONTENT       :77-81')
    A('//   FINISH                :113 / :139 / :166（strip）、:193-196（摘要截断）、:226-235（标签解析）')
    A('//   FALLBACK_SUGGEST_TAGS :240-261（词频 + 停用词表 :245-250）')
    A('//   ENDPOINT_PARTS        :45-48（_get_default_endpoint）+ :60（url 拼接）')
    A('//   JSON_ENVELOPE         admin/actions.py:304-329')
    A('//   COMPLETE              :90-113')
    A('//   POLISH                :115-139')
    A('//   TRANSLATE             :141-166（+ admin/actions.py:313-314 的 en/ja 映射）')
    A('//   SUMMARIZE             :168-198')
    A('//   SUGGEST_TAGS          :200-238')
    A('//')
    A('// 六处刻意语义（登记在夹具 meta.divergences，不是沉默偏离）')
    A('//   ① content 缺字段 / 不是字符串 ⇒ ok:FALSE（Python `.get(..., "")` 静默给 ""）')
    A('//   ② 端点结尾的 / 先剥再拼（Python 拼出 `//chat/completions`）')
    A('//   ③ 只接受 https://（传输层 TLS-only；明文 http 明确失败）')
    A('//   ④ JSON 出参保留原字符（Python json.dumps 默认写 \\uXXXX）')
    A('//   ⑤ 请求体按 STRINGIFY 口径（紧凑 + 键名字典序），与 json.dumps 字节不同')
    A('//   ⑥ ai_enabled 只认布尔 TRUE（Python 认任意真值）')
    A('//')
    A('// ⚠ 选项名有两套来源（枚举在 AI_OPT 上）：构造器名优先、配置名兜底')
    A('//   api_key ↔ ai_api_key、model ↔ ai_model、provider ↔ ai_provider、endpoint ↔ ai_endpoint')
    A('//')
    A('// ⚠ 源码里**没有** max_tokens（:61-65 的 payload 只有 model/messages/temperature）')
    A('//   ⇒ 本模块不发明该字段，即使卡面提到「等」。')
    A('//')
    A('// ⚠ 顶层绑定跨模块共享（tp/README 坑 52）⇒ 私有名一律 AI_ 前缀；')
    A('//   下面 12 个导出名是本卡的公共面，别处不得再用作顶层绑定。')
    A('')
    A('IMPORT("wlwl:std.str", ["CAT", "JOIN", "INDEX_OF"]);')
    A('IMPORT("wlwl:std.text", ["TO_LOWER", "TO_INT"]);')
    A('IMPORT("wlwl:std.encode", ["UTF8_DECODE"]);')
    A('IMPORT("wlwl:std.regex", ["RE", "RE_FIND_ALL", "RE_REPLACE"]);')
    A('IMPORT("wlwl:std.json", ["JSON_VALIDATE", "PARSE", "STRINGIFY"]);')
    A('IMPORT("./http_client_tls.wll", ["HTTPS_POST_JSON"]);')
    A('')
    A('// ── 常量（全部对齐 Python 的缺省值）────────────────────────────────')
    A('LET(AI_DEFAULT_MODEL, %s);' % wl(DEFAULT_MODEL))
    A('LET(AI_EP_OPENAI, %s);' % wl(EP_OPENAI))
    A('LET(AI_EP_DEEPSEEK, %s);' % wl(EP_DEEPSEEK))
    A('// 非流式 + timeout=30（ai_assistance.py:76）：显式透传给传输层，与 Python 的 timeout=30 同义')
    A('LET(AI_TIMEOUT_MS, %d);' % TIMEOUT_MS)
    A('// suggest_tags 的正文上限（:220 的 `text[:2000]`）')
    A('LET(AI_TAGS_TEXT_MAX, %d);' % TAGS_TEXT_MAX)
    A('LET(AI_MAX_LENGTH_DEFAULT, %d);' % MAX_LENGTH_DEFAULT)
    A('LET(AI_MAX_TAGS_DEFAULT, %d);' % MAX_TAGS_DEFAULT)
    A('')
    A('// 切词模式：`[a-zA-Z\\u4e00-\\u9fff]{2,}`（:252）。')
    A('// ⚠ 正则不认 `\\uXXXX`（坑 20/26）⇒ 区间必须写**字面**字符 `一-龥`。')
    A('// ⚠ 中英**在同一个字符类里** ⇒ `abc中文` 是**一个** token（与「先按脚本切」不同）。')
    A('LET(AI_TOKEN_RE, RE("[a-zA-Z一-龥]{2,}"));')
    A('// 标签围栏（:229-230）：`^```(?:json)?\\s*` 与 `\\s*```$`')
    A('// ⚠ 源码里是 `\\s`；WLWL 字符串里 `\\s` 不是合法转义（E0001）⇒ 正则里要写 `\\\\s`。')
    A('LET(AI_FENCE_HEAD_RE, RE("^```(?:json)?\\\\s*"));')
    A('LET(AI_FENCE_TAIL_RE, RE("\\\\s*```\\$"));')
    A('')

    # ── 小工具 ──────────────────────────────────────────────────────
    src += fn('AI_STR', 'opts, key, d', [
        '// 取一个「必须是 STRING」的选项',
        'LET(v, AT_K(opts, key, d))',
        'IF(==(TYPE(v), "STRING"), v, d)',
    ], '// 取 STRING 选项')

    src += fn('AI_OPT', 'opts, primary, alias, d', [
        '// 同名选项的两个来源：构造器名（ai_assistance.py:33-39）优先，配置名（config.py:63-68）兜底。',
        '// 例：api_key ↔ ai_api_key、model ↔ ai_model、provider ↔ ai_provider、endpoint ↔ ai_endpoint',
        'AI_STR(opts, primary, AI_STR(opts, alias, d))',
    ], '// 取一个有两个来源的字符串选项')

    src += fn('AI_INT_OR', 'v, d', [
        '// 「可能是整数 / 数字串 / 垃圾」→ 整数（失败取缺省）。',
        '// ⚠ TO_INT 失败返 ERR ⇒ 不能先绑定（坑 25）',
        'IF(!=(TYPE(v), "STRING"), IF(==(TYPE(v), "INTEGER"), v, d), IF(IS_ERR(TO_INT(v)), d, TO_INT(v)))',
    ], '// 宽松取整数')

    src += fn('AI_MAX_LENGTH', 'opts', [
        '// summarize 的 max_length（缺省 160，:168）',
        'AI_INT_OR(AT_K(opts, "max_length", AI_MAX_LENGTH_DEFAULT), AI_MAX_LENGTH_DEFAULT)',
    ], '// 摘要长度上限')

    src += fn('AI_MAX_TAGS', 'opts', [
        '// suggest_tags 的 max_tags（缺省 5，:200）',
        'AI_INT_OR(AT_K(opts, "max_tags", AI_MAX_TAGS_DEFAULT), AI_MAX_TAGS_DEFAULT)',
    ], '// 标签个数上限')

    src += fn('AI_PY_WS', '', [
        '// Python str.isspace() 全集（29 个字符）。⚠ UTF8_DECODE 的实参是**字节**（0-255）；',
        '// 内建 TRIM 只剥 ASCII 空白（坑 41）⇒ 别用 TRIM 代替 AI_STRIP。',
        'UTF8_DECODE([%s])' % ', '.join(str(b) for b in PY_WS_BYTES),
    ], '// Python 的空白字符集合')

    A('// 首尾空白模式（运行期用上面的集合拼出来 —— 字符类是**字面**字符，无转义问题）')
    A('LET(AI_WS_LEAD_RE, RE(CAT("^[", AI_PY_WS(), "]+")));')
    A('// ⚠ 结尾锚 `$` 要写 `\\$`（裸 `$` 在字面量里是插值）')
    A(r'LET(AI_WS_TRAIL_RE, RE(CAT("[", AI_PY_WS(), "]+\$")));')
    A('')

    src += fn('AI_STRIP', 's', [
        '// Python `s.strip()`：两侧都按 29 字符集合剥（:113/:139/:166 都是 .strip()）',
        'IF(!=(TYPE(s), "STRING"), "", RE_REPLACE(AI_WS_TRAIL_RE, RE_REPLACE(AI_WS_LEAD_RE, s, ""), ""))',
    ], '// Python str.strip()')

    src += fn('AI_HEAD', 's, n', [
        '// 前 n 个码点（n<0 / 不越界都安全）',
        'IF(<(n, 0), "", IF(>(LEN(s), n), SUB(s, 0, n), s))',
    ], '// 取前 n 个码点')

    src += fn('AI_RSTRIP_SLASH', 's', [
        '// 去掉结尾所有 /（对齐 rstrip("/")；本模块用它把端点尾斜杠归一）',
        'LET MUT(n, LEN(s))',
        'WHILE(&&(>(n, 0), ==(SUB(s, -(n, 1), 1), "/")), SET(n, -(n, 1)))',
        'SUB(s, 0, n)',
    ], '// 去掉结尾的 /')

    # ── 结果形状 ────────────────────────────────────────────────────
    src += fn('AI_FAIL', 'status, message', [
        '// 全模块统一的失败形状：{ok:FALSE, status, error}',
        iset([('ok', 'FALSE'), ('status', 'status'), ('error', 'message')]),
    ], '// 失败结果')

    src += fn('AI_OK_TEXT', 'status, content', [
        '// 文本类成功：{ok:TRUE, status, content}',
        iset([('ok', 'TRUE'), ('status', 'status'), ('content', 'content')]),
    ], '// 文本成功结果')

    src += fn('AI_TAGS_RESULT', 'tags, fb', [
        '// 标签类成功：{ok:TRUE, tags, fallback}（fallback 说明是否走了词频降级）',
        iset([('ok', 'TRUE'), ('tags', 'tags'), ('fallback', 'fb')]),
    ], '// 标签成功结果')

    # ── 能力表 ──────────────────────────────────────────────────────
    src += fn('AI_TEMPS', '', [
        # 五个能力的温度（:112/:138/:165/:192/:225）。用字典而不是 IF 链：
        # 查不到 ⇒ NULL（调用方据此报错），也避开 `IF` 分支字面量形状不一致的 W0013。
        iset([('complete', '0.8'), ('polish', '0.5'), ('translate', '0.3'),
              ('summarize', '0.3'), ('suggest_tags', '0.3')]),
    ], '// 能力 → 温度表')

    src += fn('AI_CAP_TEMP', 'cap', [
        '// 未知能力 ⇒ NULL',
        'AT_K(AI_TEMPS(), cap, NULL)',
    ], '// 能力 → 温度（未知 ⇒ NULL）')

    src += fn('AI_LANG_NAME', 'code', [
        '// 目标语言**硬编码** en/ja（admin/actions.py:313-314 的 lang_map）；未知码回落 English',
        'IF(==(code, "ja"), "Japanese", "English")',
    ], '// lang 码 → 语言名')

    src += fn('AI_TARGET_NAME', 'opts', [
        '// target_lang 显式给了就用它（ai_assistance.py:141 的具名参数），否则按 lang 码映射',
        'LET(t, AI_STR(opts, "target_lang", ""))',
        'IF(!=(t, ""), t, AI_LANG_NAME(AI_STR(opts, "lang", "en")))',
    ], '// 目标语言名')

    src += fn('AI_MSG', 'role, content', [
        '// 一条消息（键序 role → content，与 Python 的字典字面量同序）',
        'INDEX_SET(INDEX_SET(DICT(), "role", role), "content", content)',
    ], '// 一条 messages 项')

    src += fn('AI_COMPLETE_SYSTEM', 'hint', [
        '// :103-105：有 hint 就在 system 末尾**追加**（不是替换）',
        'IF(==(hint, ""), %s, CAT(%s, " The user wants to focus on: ", hint))'
        % (wl(SYS_COMPLETE), wl(SYS_COMPLETE)),
    ], '// complete 的 system 提示词')

    tr_head, tr_tail = SYS_TRANSLATE.split('{}')
    sm_head, sm_tail = SYS_SUMMARIZE.split('{}')
    tg_head, tg_tail = SYS_TAGS.split('{}')
    src += fn('AI_SYSTEM', 'cap, opts', [
        # 五个能力的 system 消息（逐字对齐 :103 / :130 / :157 / :184 / :216）。
        # ⚠ 整条 IF 链是**一个** body 项（多行会被逐行补 `;`，坑 29）。
        'IF(==(cap, "complete"), AI_COMPLETE_SYSTEM(AI_STR(opts, "prompt_hint", "")), '
        'IF(==(cap, "polish"), %s, '
        'IF(==(cap, "translate"), CAT(%s, AI_TARGET_NAME(opts), %s), '
        'IF(==(cap, "summarize"), CAT(%s, STR(AI_MAX_LENGTH(opts)), %s), '
        'CAT(%s, STR(AI_MAX_TAGS(opts)), %s)))))'
        % (wl(SYS_POLISH), wl(tr_head), wl(tr_tail),
           wl(sm_head), wl(sm_tail), wl(tg_head), wl(tg_tail)),
    ], '// 能力 → system 消息')

    src += fn('AI_USER', 'cap, opts', [
        # 五个能力的 user 消息（逐字对齐 :109 / :134 / :161 / :188 / :220）。
        # ⚠ suggest_tags 的正文被截到前 2000 码点。
        'LET(text, AI_STR(opts, "text", ""))',
        'IF(==(cap, "complete"), CAT("Continue this text:\\n\\n", text), '
        'IF(==(cap, "polish"), CAT("Polish this text:\\n\\n", text), '
        'IF(==(cap, "translate"), CAT("Translate to ", AI_TARGET_NAME(opts), ":\\n\\n", text), '
        'IF(==(cap, "summarize"), CAT("Summarize this text:\\n\\n", text), '
        'CAT("Suggest tags for:\\n\\n", AI_HEAD(text, AI_TAGS_TEXT_MAX))))))',
    ], '// 能力 → user 消息')

    src += fn('AI_BUILT', 'cap, model, temp, msgs, skip', [
        '// BUILD_MESSAGES 的形状（键集合固定，调用方可以安全地 AT_K）',
        iset([('ok', 'TRUE'), ('capability', 'cap'), ('model', 'model'),
              ('temperature', 'temp'), ('messages', 'msgs'), ('skip', 'skip')]),
    ], '// 消息构造结果')

    src += fn('BUILD_MESSAGES', 'opts', [
        '// 纯函数：给定 **文本 + 能力名**，产出要发给 API 的两条消息与三要素。',
        '// opts：capability（complete/polish/translate/summarize/suggest_tags）',
        '//       text / prompt_hint / target_lang / lang / max_length / max_tags / model',
        '// ⚠ 空文本 ⇒ skip:TRUE + messages:[]（Python :100/:124/:151/:178/:210 直接返回，不构建）',
        'LET(cap, AI_STR(opts, "capability", "complete"))',
        'LET(temp, AI_CAP_TEMP(cap))',
        C('IF', '==(temp, NULL)', [
            'AI_FAIL(NULL, CAT("unknown capability: ", cap))',
        ], [
            'LET(model, AI_OPT(opts, "model", "ai_model", AI_DEFAULT_MODEL))',
            C('IF', '==(AI_STR(opts, "text", ""), "")', [
                '// 空文本 ⇒ 没有消息、也没有温度（Python 根本没构造请求）',
                'AI_BUILT(cap, model, NULL, [], TRUE)',
            ], [
                'AI_BUILT(cap, model, temp, [AI_MSG("system", AI_SYSTEM(cap, opts)), AI_MSG("user", AI_USER(cap, opts))], FALSE)',
            ]),
        ]),
    ], '// 消息构造（纯函数）')

    # ── 后处理 ──────────────────────────────────────────────────────
    src += fn('AI_LAST_SPACE', 's', [
        '// s 里**最后一个**空格的下标（没有 ⇒ -1）—— 对齐 `rsplit(" ", 1)[0]`',
        'LET MUT(i, -1)',
        'LET MUT(j, 0)',
        'WHILE(<(j, LEN(s)), (IF(==(SUB(s, j, 1), " "), SET(i, j), NULL); SET(j, +(j, 1))))',
        'i',
    ], '// 最后一个空格的下标')

    src += fn('AI_TRIM_OVER', 's, max_length', [
        '// 超长摘要的截断：前 max_length 码点里**最后一个空格之前** + "..."（:196）',
        'LET(head, AI_HEAD(s, max_length))',
        'LET(i, AI_LAST_SPACE(head))',
        'CAT(IF(<(i, 0), head, SUB(head, 0, i)), "...")',
    ], '// 截断超长摘要')

    src += fn('AI_TRIM_SUMMARY', 's, max_length', [
        '// 判定是 `>`（等于上限**不**截断，:195）',
        'IF(!(>(LEN(s), max_length)), s, AI_TRIM_OVER(s, max_length))',
    ], '// summarize 的长度截断')

    src += fn('AI_ALL_STR', 'arr', [
        '// 数组元素全是 STRING？(:233 的 `all(isinstance(t, str) …)`）',
        'LET MUT(ok, TRUE)',
        'FOR(x, arr, IF(!=(TYPE(x), "STRING"), SET(ok, FALSE), NULL))',
        'ok',
    ], '// 元素全是字符串')

    src += fn('AI_TAKE', 'arr, n', [
        '// 前 n 个元素（`tags[:max_tags]`）；n<=0 ⇒ []',
        'LET MUT(out, [])',
        'LET MUT(i, 0)',
        'WHILE(&&(<(i, n), <(i, LEN(arr))), (SET(out, PUSH(out, AT(arr, i, ""))); SET(i, +(i, 1))))',
        'out',
    ], '// 取前 n 个元素')

    src += fn('AI_TAGS_OK', 'tags', [
        '// 解析成功且形状合法',
        iset([('ok', 'TRUE'), ('tags', 'tags'), ('valid_shape', 'TRUE')]),
    ], '// 标签解析成功')

    src += fn('AI_TAGS_BAD_SHAPE', '', [
        '// 解析成功但**形状非法** ⇒ Python 返回 [] 且**不**降级（:233-235）',
        iset([('ok', 'TRUE'), ('tags', '[]'), ('valid_shape', 'FALSE')]),
    ], '// 标签形状非法')

    src += fn('AI_PARSE_TAGS', 's, max_tags', [
        '// :226-235：剥围栏 → JSON 解析 → 必须是「字符串数组」',
        '// ⚠ `std.json::PARSE` 失败是 **E0070 中止**（坑 47）⇒ 先 JSON_VALIDATE',
        'LET(t, IF(==(SUB(s, 0, 3), "```"), RE_REPLACE(AI_FENCE_TAIL_RE, RE_REPLACE(AI_FENCE_HEAD_RE, s, ""), ""), s))',
        C('IF', 'IS_ERR(JSON_VALIDATE(t))', [
            'AI_FAIL(NULL, "tags payload is not valid JSON")',
        ], [
            'LET(arr, PARSE(t))',
            C('IF', '!=(TYPE(arr), "ARRAY")', [
                'AI_TAGS_BAD_SHAPE()',
            ], [
                C('IF', 'AI_ALL_STR(arr)', [
                    'AI_TAGS_OK(AI_TAKE(arr, max_tags))',
                ], [
                    'AI_TAGS_BAD_SHAPE()',
                ]),
            ]),
        ]),
    ], '// 解析 AI 返回的标签数组')

    src += fn('AI_FIN_OPTS', 'opts, cap, content', [
        '// 交给 FINISH 的选项（把 capability / content 与两个上限聚在一起）',
        iset([('capability', 'cap'), ('content', 'content'),
              ('max_length', 'AI_MAX_LENGTH(opts)'), ('max_tags', 'AI_MAX_TAGS(opts)')]),
    ], '// FINISH 的选项')

    src += fn('FINISH', 'opts', [
        '// 纯函数：能力相关的**后处理**（Python 里散在五个方法尾部的那几行）。',
        '// opts：capability / content / max_length / max_tags',
        '// ⚠ summarize 先 strip 再截断（:193-196 的顺序）',
        'LET(cap, AI_STR(opts, "capability", "complete"))',
        'LET(content, AI_STR(opts, "content", ""))',
        C('IF', '||(==(cap, "complete"), ||(==(cap, "polish"), ==(cap, "translate")))', [
            'AI_OK_TEXT(NULL, AI_STRIP(content))',
        ], [
            C('IF', '==(cap, "summarize")', [
                'AI_OK_TEXT(NULL, AI_TRIM_SUMMARY(AI_STRIP(content), AI_MAX_LENGTH(opts)))',
            ], [
                C('IF', '==(cap, "suggest_tags")', [
                    'AI_PARSE_TAGS(AI_STRIP(content), AI_MAX_TAGS(opts))',
                ], [
                    'AI_FAIL(NULL, CAT("unknown capability: ", cap))',
                ]),
            ]),
        ]),
    ], '// 能力相关的后处理（纯函数）')

    # ── 词频降级 ────────────────────────────────────────────────────
    src += fn('AI_STOPWORDS', '', [
        '// 中英停用词表（:245-250，逐字）',
        iset([(w, 'TRUE') for w in STOPWORDS]),
    ], '// 停用词表')

    src += fn('FALLBACK_SUGGEST_TAGS', 'opts', [
        '// 纯函数：词频降级（:240-261）。返回值是**数组**（与 Python 同名函数一致）。',
        '// opts：text / max_tags',
        '// 步骤：lower → 切词 {2,} → 去停用词 → 计数 → 按次数降序（同频按**首次出现**）',
        '// ⚠ 两道门槛叠加：切词要求 {2,}，计数前还有 `len(word) > 2`（:255）',
        '//    ⇒ **两字**的词（含中文两字词）一律取不到；这是源码行为，不是我们的取舍',
        'LET(text, AI_STR(opts, "text", ""))',
        'LET(mt, AI_MAX_TAGS(opts))',
        C('IF', '||(==(text, ""), <(mt, 1))', [
            '[]',
        ], [
            'LET(stop, AI_STOPWORDS())',
            'LET MUT(freq, DICT())',
            C('FOR', 't, RE_FIND_ALL(AI_TOKEN_RE, TO_LOWER(text))', [
                'LET(w, AT_K(t, "matched", ""))',
                C('IF', '>(LEN(w), 2)', [
                    C('IF', '!HAS(stop, w)', [
                        'SET(freq, INDEX_SET(freq, w, +(AT_K(freq, w, 0), 1)))',
                    ], ['NULL']),
                ], ['NULL']),
            ]),
            '// 选 top-N：每轮扫一遍（按**插入序**取第一个最大计数 ⇒ 等价于 Python 的稳定排序）',
            'LET MUT(used, DICT())',
            'LET MUT(out, [])',
            'LET MUT(k, 0)',
            C('WHILE', '<(k, mt)', [
                'LET MUT(best, "")',
                'LET MUT(bc, -1)',
                C('FOR', 'w, KEYS(freq)', [
                    C('IF', '!HAS(used, w)', [
                        C('IF', '>(AT_K(freq, w, 0), bc)', [
                            'SET(best, w)',
                            'SET(bc, AT_K(freq, w, 0))',
                        ], ['NULL']),
                    ], ['NULL']),
                ]),
                C('IF', '==(best, "")', [
                    'SET(k, mt)',
                ], [
                    'SET(out, PUSH(out, best))',
                    'SET(used, INDEX_SET(used, best, TRUE))',
                    'SET(k, +(k, 1))',
                ]),
            ]),
            'out',
        ]),
    ], '// 词频降级（纯函数）')

    # ── 是否构建 ────────────────────────────────────────────────────
    src += fn('IS_ENABLED', 'opts', [
        '// 对齐 build_ai_assistance（:273-276）：**未启用**或**没有 key** ⇒ 不构建。',
        '// ⚠ ai_enabled 只认布尔 TRUE（Python 认任意真值）—— 登记为刻意语义',
        '&&(==(AT_K(opts, "ai_enabled", FALSE), TRUE), !=(AI_STR(opts, "ai_api_key", ""), ""))',
    ], '// 是否构建 AI（纯函数）')

    # ── 端点 ────────────────────────────────────────────────────────
    src += fn('AI_EP_OK', 'endpoint, scheme, host, port, path', [
        '// ENDPOINT_PARTS 的成功形状',
        iset([('ok', 'TRUE'), ('endpoint', 'endpoint'), ('scheme', 'scheme'),
              ('host', 'host'), ('port', 'port'), ('path', 'path')]),
    ], '// 端点拆分结果')

    src += fn('ENDPOINT_PARTS', 'opts', [
        '// 纯函数：provider 缺省端点（:45-48）+ URL 拆成 host/port/path（:60 的拼接）。',
        '// opts：provider（缺省 openai）/ endpoint（空 ⇒ 按 provider 取缺省）',
        '// ⚠ 只接受 https：本模块的传输层是 TLS-only，静默把 http 走成 TLS 就是撒谎',
        'LET(ep0, AI_OPT(opts, "endpoint", "ai_endpoint", ""))',
        'LET(ep, IF(!=(ep0, ""), ep0, IF(==(TO_LOWER(AI_OPT(opts, "provider", "ai_provider", "openai")), "deepseek"), AI_EP_DEEPSEEK, AI_EP_OPENAI)))',
        'LET(i, INDEX_OF(ep, "://"))',
        C('IF', '<(i, 0)', [
            'AI_FAIL(NULL, "endpoint must be an absolute URL (scheme://host)")',
        ], [
            'LET(scheme, TO_LOWER(SUB(ep, 0, i)))',
            'LET(rest, SUB(ep, +(i, 3)))',
            'LET(ip, INDEX_OF(rest, "/"))',
            'LET(auth, IF(<(ip, 0), rest, SUB(rest, 0, ip)))',
            'LET(pfx, IF(<(ip, 0), "", SUB(rest, +(ip, 1))))',
            'LET(ic, INDEX_OF(auth, ":"))',
            'LET(host, IF(<(ic, 0), auth, SUB(auth, 0, ic)))',
            'LET(ptxt, IF(<(ic, 0), "", SUB(auth, +(ic, 1))))',
            C('IF', '!=(scheme, "https")', [
                'AI_FAIL(NULL, CAT("only https endpoints are supported, got: ", scheme))',
            ], [
                C('IF', '==(host, "")', [
                    'AI_FAIL(NULL, "endpoint has no host")',
                ], [
                    'LET(port, IF(==(ptxt, ""), 443, AI_INT_OR(ptxt, -1)))',
                    C('IF', '||(<(port, 1), >(port, 65535))', [
                        'AI_FAIL(NULL, CAT("endpoint has an invalid port: ", ptxt))',
                    ], [
                        'LET(p, AI_RSTRIP_SLASH(pfx))',
                        'AI_EP_OK(ep, scheme, host, port, IF(==(p, ""), "/chat/completions", CAT("/", p, "/chat/completions")))',
                    ]),
                ]),
            ]),
        ]),
    ], '// 端点 → host/port/path（纯函数）')

    # ── 响应取内容 ──────────────────────────────────────────────────
    src += fn('EXTRACT_CONTENT', 'opts', [
        '// 纯函数：响应 JSON → choices[0].message.content（:77-81）。',
        '// opts：body（STRING）/ status（原样回带）',
        '// ⚠ 每一层都先判 TYPE：AT_K 对 NULL 基值是 E0030（坑 35）',
        '// ⚠「缺字段」与「空串」分开：空串是合法结果，缺字段是 ok:FALSE（刻意语义 ①）',
        'LET(body, AI_STR(opts, "body", ""))',
        'LET(st, AT_K(opts, "status", NULL))',
        C('IF', 'IS_ERR(JSON_VALIDATE(body))', [
            'AI_FAIL(st, "response body is not valid JSON")',
        ], [
            'LET(doc, PARSE(body))',
            C('IF', '!=(TYPE(doc), "DICT")', [
                'AI_FAIL(st, "response JSON is not an object")',
            ], [
                'LET(choices, AT_K(doc, "choices", NULL))',
                C('IF', '!=(TYPE(choices), "ARRAY")', [
                    'AI_FAIL(st, "No response from AI: choices is not an array")',
                ], [
                    C('IF', '==(LEN(choices), 0)', [
                        'AI_FAIL(st, "No response from AI: choices is empty")',
                    ], [
                        'LET(c0, AT(choices, 0, NULL))',
                        C('IF', '!=(TYPE(c0), "DICT")', [
                            'AI_FAIL(st, "choices[0] is not an object")',
                        ], [
                            'LET(msg, AT_K(c0, "message", NULL))',
                            C('IF', '!=(TYPE(msg), "DICT")', [
                                'AI_FAIL(st, "choices[0].message is missing")',
                            ], [
                                'LET(content, AT_K(msg, "content", NULL))',
                                C('IF', '!=(TYPE(content), "STRING")', [
                                    'AI_FAIL(st, "choices[0].message.content is missing or not a string")',
                                ], [
                                    'AI_OK_TEXT(st, content)',
                                ]),
                            ]),
                        ]),
                    ]),
                ]),
            ]),
        ]),
    ], '// 响应 JSON → content（纯函数）')

    # ── 请求体 + 一次调用 ───────────────────────────────────────────
    src += fn('AI_PAYLOAD', 'model, msgs, temp', [
        # 请求体：{model, messages, temperature}（:61-65 的三个键，**没有** max_tokens）。
        # ⚠ STRINGIFY 是「紧凑 + 键名排序」⇒ 与 json.dumps 字节不同（刻意语义 ⑤）
        'STRINGIFY(%s)' % iset([('model', 'model'), ('messages', 'msgs'),
                                ('temperature', 'temp')]),
    ], '// 请求体 JSON')

    src += fn('AI_RUN', 'opts, cap', [
        '// 一次调用：建消息 → 端点 → 请求体 → HTTPS_POST_JSON（卡 S5-1）→ 取 content。',
        '// ⚠ 传输层要 api_key（:57-58）：空 ⇒ 明确失败，且**在碰传输之前**返回。',
        'LET(key, AI_STR(opts, "api_key", AI_OPT(opts, "ai_api_key", "key", "")))',
        C('IF', '==(key, "")', [
            'AI_FAIL(NULL, "API key not configured")',
        ], [
            'LET(ep, ENDPOINT_PARTS(opts))',
            C('IF', '!AT_K(ep, "ok", FALSE)', [
                'AI_FAIL(NULL, AT_K(ep, "error", "invalid endpoint"))',
            ], [
                'LET(spec, BUILD_MESSAGES(INDEX_SET(opts, "capability", cap)))',
                C('IF', '!AT_K(spec, "ok", FALSE)', [
                    'AI_FAIL(NULL, AT_K(spec, "error", "cannot build messages"))',
                ], [
                    C('IF', 'AT_K(spec, "skip", FALSE)', [
                        'AI_OK_TEXT(NULL, "")',
                    ], [
                        'LET(body, AI_PAYLOAD(AT_K(spec, "model", AI_DEFAULT_MODEL), AT_K(spec, "messages", []), AT_K(spec, "temperature", 0.3)))',
                        '// 传输层（卡 S5-1）只认 `api_key`：配置名 `ai_api_key` 在这里换成它',
                        'LET(o, INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(INDEX_SET(opts, "host", AT_K(ep, "host", "")), "port", AT_K(ep, "port", 443)), "path", AT_K(ep, "path", "/chat/completions")), "body", body), "timeout_ms", AI_INT_OR(AT_K(opts, "timeout_ms", AI_TIMEOUT_MS), AI_TIMEOUT_MS)), "api_key", key))',
                        'LET(r, HTTPS_POST_JSON(o))',
                        C('IF', '!AT_K(r, "ok", FALSE)', [
                            'AI_FAIL(AT_K(r, "status", NULL), AT_K(r, "error", "transport failed"))',
                        ], [
                            'EXTRACT_CONTENT(INDEX_SET(INDEX_SET(DICT(), "body", AT_K(r, "body", "")), "status", AT_K(r, "status", NULL)))',
                        ]),
                    ]),
                ]),
            ]),
        ]),
    ], '// 一次 AI 调用（建 → 传 → 取）')

    src += fn('AI_CAPABILITY', 'opts, cap', [
        '// 五个文本能力共用的编排：未配置 → 调用 → 后处理',
        '// ⚠ 未配置 ⇒ **明确失败**（Python 的 build_ai_assistance 返回 None，调用方报错）',
        C('IF', '!IS_ENABLED(opts)', [
            'AI_FAIL(NULL, "AI not configured (ai_enabled / ai_api_key)")',
        ], [
            'LET(raw, AI_RUN(opts, cap))',
            C('IF', '!AT_K(raw, "ok", FALSE)', [
                'AI_FAIL(AT_K(raw, "status", NULL), AT_K(raw, "error", "request failed"))',
            ], [
                'LET(fin, FINISH(AI_FIN_OPTS(opts, cap, AT_K(raw, "content", ""))))',
                C('IF', '!AT_K(fin, "ok", FALSE)', [
                    'AI_FAIL(AT_K(raw, "status", NULL), AT_K(fin, "error", "post-process failed"))',
                ], [
                    'AI_OK_TEXT(AT_K(raw, "status", NULL), AT_K(fin, "content", ""))',
                ]),
            ]),
        ]),
    ], '// 文本能力编排')

    src += fn('COMPLETE', 'opts', [
        '// :90-113 —— 续写（temperature 0.8，五个能力里最高）',
        '// opts：ai_enabled / ai_api_key / text / prompt_hint / model / provider / endpoint',
        '//       + 传输项（ca / verify / timeout_ms / exchange）原样透传',
        'AI_CAPABILITY(opts, "complete")',
    ], '// 续写')

    src += fn('POLISH', 'opts', [
        '// :115-139 —— 润色（temperature 0.5）',
        'AI_CAPABILITY(opts, "polish")',
    ], '// 润色')

    src += fn('TRANSLATE', 'opts', [
        '// :141-166 —— 翻译（temperature 0.3）。lang 码 en/ja 硬编码（admin/actions.py:313-314）',
        'AI_CAPABILITY(opts, "translate")',
    ], '// 翻译')

    src += fn('SUMMARIZE', 'opts', [
        '// :168-198 —— 摘要（temperature 0.3；max_length 既进 system 也做截断）',
        'AI_CAPABILITY(opts, "summarize")',
    ], '// 摘要')

    src += fn('SUGGEST_TAGS', 'opts', [
        '// :200-238 —— 标签（temperature 0.3；失败/非 JSON ⇒ 词频降级）',
        '// ⚠ 三种结局要分清（与 Python 逐条对齐）：',
        '//   ① 未配置 ⇒ ok:FALSE（**不**降级；Python 的 build_ai_assistance 返回 None）',
        '//   ② 空文本 ⇒ {tags: []}，不发请求（:210）',
        '//   ③ 请求失败 / 内容不是 JSON ⇒ 降级（:236-238）；',
        '//      解析成功但**形状非法** ⇒ []（**不**降级，:233-235）',
        C('IF', '!IS_ENABLED(opts)', [
            'AI_FAIL(NULL, "AI not configured (ai_enabled / ai_api_key)")',
        ], [
            'LET(text, AI_STR(opts, "text", ""))',
            C('IF', '==(text, "")', [
                'AI_TAGS_RESULT([], FALSE)',
            ], [
                'LET(raw, AI_RUN(opts, "suggest_tags"))',
                C('IF', '!AT_K(raw, "ok", FALSE)', [
                    'AI_TAGS_RESULT(FALLBACK_SUGGEST_TAGS(opts), TRUE)',
                ], [
                    'LET(fin, FINISH(AI_FIN_OPTS(opts, "suggest_tags", AT_K(raw, "content", ""))))',
                    C('IF', '!AT_K(fin, "ok", FALSE)', [
                        'AI_TAGS_RESULT(FALLBACK_SUGGEST_TAGS(opts), TRUE)',
                    ], [
                        'AI_TAGS_RESULT(AT_K(fin, "tags", []), FALSE)',
                    ]),
                ]),
            ]),
        ]),
    ], '// 标签推荐（含词频降级）')

    # ── 出参 JSON（反向守卫）───────────────────────────────────────
    src += fn('AI_JSON_VALUE', 'v', [
        '// 一个 JSON 值：标量交给 STRINGIFY；数组要手工拼（STRINGIFY 的数组是 `["a","b"]`，',
        '// Python 的 json.dumps 是 `["a", "b"]` ⇒ 分隔符必须自己写才能逐字节对齐）',
        C('IF', '==(TYPE(v), "ARRAY")', [
            'LET MUT(parts, [])',
            'FOR(x, v, SET(parts, PUSH(parts, STRINGIFY(x))))',
            'CAT("[", JOIN(parts, ", "), "]")',
        ], [
            'STRINGIFY(v)',
        ]),
    ], '// 一个 JSON 值')

    src += fn('JSON_ENVELOPE', 'opts', [
        '// 纯函数：**后端错误也必须是 JSON**（卡 S5-2 的反向守卫）。',
        '// 对齐 admin/actions.py:304-329：始终 200 + application/json，',
        '//   成功 {"result": ...}，失败 {"error": ...}。',
        '// opts：ok（缺省 TRUE）/ content（STRING）/ tags（ARRAY）/ error（STRING）',
        '// ⚠ 非 ASCII 不转义（Python 的 json.dumps 默认 ensure_ascii=True ⇒ 刻意语义 ④）',
        C('IF', '!AT_K(opts, "ok", TRUE)', [
            'CAT("{\\"error\\": ", STRINGIFY(AI_STR(opts, "error", "")), "}")',
        ], [
            'LET(v, IF(==(TYPE(AT_K(opts, "tags", NULL)), "ARRAY"), AT_K(opts, "tags", []), AI_STR(opts, "content", "")))',
            'CAT("{\\"result\\": ", AI_JSON_VALUE(v), "}")',
        ]),
    ], '// 出参 JSON（纯函数）')

    A('EXPORT(["IS_ENABLED", "BUILD_MESSAGES", "EXTRACT_CONTENT", "FINISH",')
    A('        "FALLBACK_SUGGEST_TAGS", "ENDPOINT_PARTS", "JSON_ENVELOPE",')
    A('        "COMPLETE", "POLISH", "TRANSLATE", "SUMMARIZE", "SUGGEST_TAGS"]);')

    chars, lines = write(OUT, src)
    print('wrote %s (%d chars, %d lines)' % (OUT, chars, lines))


if __name__ == '__main__':
    main()
