"""生成 tp/test/test_ai.wll —— 五个 AI 能力与降级的**脱网**测试（卡 S5-2）。

⚠ 输出的 .wll 由本文件生成，不要手改。

**为什么能脱网**：`tp/lib/ai.wll` 把「消息构造 / 结果解析 / 后处理 / 降级」全部做成
**纯函数**，真正发请求的五个能力则把 `opts.exchange` 透传给卡 S5-1 的
`HTTPS_POST_JSON` —— 那正是 S5-1 用来替代 TLS 传输的**同一个**测试缝。
所以本文件的每个用例都不出网：
  · 纯函数组（build / extract / finish / fallback / enabled / endpoint / envelope）
  · 全链路组（pipeline）用 `T2_exchange` 注入假传输、回放夹具里的响应报文
    ⇒「建消息 → 建请求 → 解析 → 定 ok → 后处理」整条跑完，仍不碰 `tls`。

**基准**：`tp/test/fixtures/ai_baseline.json`（由 `gen_ai_baseline.py` 生成，
期望值全部由真 Python 现算：抓 `_call_api` 的真实 messages、假 `urlopen` 跑真 `_call_api`、
直接调 `_fallback_suggest_tags` / `build_ai_assistance` / `json.dumps`）。

**覆盖**
  · build：五个能力的 system+user 逐字、温度表、空文本 skip、prompt_hint 追加、
    en/ja 硬编码、max_length/max_tags 进 system、正文截到 2000 码点、未知能力失败
  · extract：正常 / 中文 / 转义换行 / 空串 / 多余字段 / 空 choices / 缺 choices /
    choices 非数组 / 缺 message / content 非字符串 / 非 JSON / 根是数组 / status 回带
  · finish：strip（含 U+3000 / NBSP）/ 摘要截断（有空格、无空格、恰好等于上限、中文、max=200）/
    标签围栏与形状
  · fallback：词频、同频取先出现、停用词、两字词被丢、中英混排一整串、max_tags 边界
  · enabled + endpoint：两个前置条件、provider 缺省、大小写、端口、尾斜杠、http/无 scheme
  · envelope：错误与结果都是 JSON，`", "` / `": "` 分隔与转义逐字节对齐
  · pipeline：五个能力的全链路 + 401 / 未配置 / 禁用 / 空文本 / 标签降级 / 形状非法

**自己把关退出码**：`RUN_TESTS()` 的失败**不影响退出码**（规范明载）
⇒ 末尾必须 `IF(>(failed, 0), PANIC(...), NULL)`。

用法：python gen_test_ai.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'test_ai.wll')

# 测试实例自己的顶层名一律 T2_ 前缀（坑 52：顶层绑定跨模块共享）
SEEN = 'T2_seen'
REPLY = 'T2_reply'
EXCHANGE = 'T2_exchange'

EXPORTS = ["IS_ENABLED", "BUILD_MESSAGES", "EXTRACT_CONTENT", "FINISH",
           "FALLBACK_SUGGEST_TAGS", "ENDPOINT_PARTS", "JSON_ENVELOPE",
           "COMPLETE", "POLISH", "TRANSLATE", "SUMMARIZE", "SUGGEST_TAGS"]

CAP_FN = {
    'complete': 'COMPLETE',
    'polish': 'POLISH',
    'translate': 'TRANSLATE',
    'summarize': 'SUMMARIZE',
    'suggest_tags': 'SUGGEST_TAGS',
}


def wl(s):
    """Python 字符串 → WLWL 字面量。⚠ `${…}` / `$x` 是插值 ⇒ 字面美元符写 \\$。"""
    out = []
    for ch in s:
        if ch == '\\':
            out.append('\\\\')
        elif ch == '"':
            out.append('\\"')
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif ch == '\t':
            out.append('\\t')
        elif ch == '$':
            out.append('\\$')
        else:
            out.append(ch)
    return '"' + ''.join(out) + '"'


def expr(v):
    """JSON 值 → WLWL 表达式（字典保序 ⇒ INDEX_SET 链；与夹具的键序一致）。"""
    if isinstance(v, bool):
        return 'TRUE' if v else 'FALSE'
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, str):
        return wl(v)
    if isinstance(v, list):
        return '[' + ', '.join(expr(x) for x in v) + ']'
    if isinstance(v, dict):
        out = 'DICT()'
        for k, val in v.items():
            out = 'INDEX_SET(%s, %s, %s)' % (out, wl(k), expr(val))
        return out
    if v is None:
        return 'NULL'
    raise TypeError('bad JSON value: %r' % (v,))


def opts_with_exchange(opts):
    """把测试缝塞进 opts（键序 = 夹具里的顺序 + exchange 在最后）。"""
    out = 'DICT()'
    for k, v in opts.items():
        out = 'INDEX_SET(%s, %s, %s)' % (out, wl(k), expr(v))
    return 'INDEX_SET(%s, "exchange", %s)' % (out, EXCHANGE)


def slug(s):
    """测试名里的参数片段（保持可读、避免引号与逗号）。"""
    return (s.replace(' ', '_').replace(':', '_').replace('/', '_')
             .replace('"', '').replace(',', ''))


def main():
    with open(os.path.join(FIXTURES, 'ai_baseline.json'), encoding='utf-8') as f:
        base = json.load(f)

    src = []
    A = src.append
    A('// tp/test/test_ai.wll —— 五个 AI 能力与降级的脱网测试（卡 S5-2）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_test_ai.py 生成 —— 请勿手改。')
    A('//')
    A('// 被测：tp/lib/ai.wll')
    A('//   BUILD_MESSAGES / EXTRACT_CONTENT / FINISH / FALLBACK_SUGGEST_TAGS /')
    A('//   ENDPOINT_PARTS / JSON_ENVELOPE / IS_ENABLED   —— 纯函数，逐字对照真 Python')
    A('//   COMPLETE / POLISH / TRANSLATE / SUMMARIZE / SUGGEST_TAGS —— 用注入的假传输跑全链路')
    A('// 基准：tp/test/fixtures/ai_baseline.json')
    A('//   · 期望值由 gen_ai_baseline.py 从真 Python 现算（不是手抄）')
    A('//   · 六处刻意偏离登记在该 JSON 的 meta.divergences')
    A('//')
    A('// ⚠ **本文件不出网**：`opts.exchange` 是卡 S5-1 的传输注入点，')
    A('//   假传输回放夹具里的原始响应报文 ⇒ 不带 --ext、也不碰 tls 就能全绿。')
    A('//')
    A('// ⚠ RUN_TESTS() 的失败**不影响退出码**（规范明载）⇒ 本文件自己把关。')
    A('IMPORT("wlwl:std.test", ["TEST", "ASSERT", "ASSERT_EQ", "RUN_TESTS"]);')
    A('IMPORT("wlwl:std.str", ["CAT", "JOIN", "INDEX_OF", "CONTAINS_SUB"]);')
    A('IMPORT("wlwl:std.json", ["STRINGIFY"]);')
    A('IMPORT("./../lib/ai.wll", [')
    for i, name in enumerate(EXPORTS):
        tail = ']);' if i == len(EXPORTS) - 1 else ','
        A('        "%s"%s' % (name, tail))
    A('')
    A('// ── 测试缝：假传输（记下真实请求文本，回放夹具里的响应报文）──────────')
    A('// ⚠ 闭包可以写外层的 LET MUT（坑 12），所以这里能记下 T2_seen。')
    A('LET MUT(%s, "");' % SEEN)
    A('LET MUT(%s, "");' % REPLY)
    A('LET(%s, FUN((req), (SET(%s, req); %s)));' % (EXCHANGE, SEEN, REPLY))
    A('')

    # ── ① 消息构造 ──────────────────────────────────────────────────
    A('// ── ① 消息构造（纯函数 BUILD_MESSAGES）──────────────────────────')
    A('// ⚠ 期望值来自抓到的**真实** messages（Python 的 _call_api 被记录器顶替）')
    for c in base['messages']:
        A('// %s' % c['name'])
        A('//   %s' % c['note'])
        A('//   出处：%s' % c['source'])
        A('LET(T2_build_%s, BUILD_MESSAGES(%s));' % (c['name'], expr(c['opts'])))
    A('')

    for c in base['messages']:
        name = c['name']
        want = c['want']
        var = 'T2_build_%s' % name
        msgs = want['messages']
        A('')
        A('TEST("build/%s", FUN(() ,' % name)
        A('    (ASSERT_EQ(AT_K(%s, "ok", "?"), TRUE));' % var)
        A('    (ASSERT_EQ(AT_K(%s, "capability", "?"), %s));' % (var, wl(want['capability'])))
        A('    (ASSERT_EQ(AT_K(%s, "model", "?"), %s));' % (var, wl(want['model'])))
        if want['skip']:
            A('    // 空文本 ⇒ Python 没构建消息（也没有温度）')
            A('    (ASSERT_EQ(TYPE(AT_K(%s, "temperature", 0)), "NULL"));' % var)
        else:
            A('    (ASSERT_EQ(AT_K(%s, "temperature", -1), %r));' % (var, want['temperature']))
        A('    (ASSERT_EQ(AT_K(%s, "skip", "?"), %s));'
          % (var, 'TRUE' if want['skip'] else 'FALSE'))
        A('    (ASSERT_EQ(LEN(AT_K(%s, "messages", [])), %d));' % (var, len(msgs)))
        for idx, m in enumerate(msgs):
            A('    (ASSERT_EQ(AT_K(AT(AT_K(%s, "messages", []), %d, DICT()), "role", "?"), %s));'
              % (var, idx, wl(m['role'])))
            A('    (ASSERT_EQ(AT_K(AT(AT_K(%s, "messages", []), %d, DICT()), "content", "?"), %s));'
              % (var, idx, wl(m['content'])))
            A('    (ASSERT_EQ(JOIN(KEYS(AT(AT_K(%s, "messages", []), %d, DICT())), "|"), "role|content"));'
              % (var, idx))
        A('    TRUE));')

    # 未知能力：必须是明确失败（不是静默空消息）
    A('')
    A('// 反向守卫：未知能力 ⇒ ok:FALSE（**不得**静默返回空消息）')
    A('TEST("build/unknown_capability", FUN(() ,')
    A('    (LET(bad, BUILD_MESSAGES(INDEX_SET(DICT(), "capability", "frobnicate")));')
    A('     (ASSERT_EQ(AT_K(bad, "ok", "?"), FALSE));')
    A('     (ASSERT(CONTAINS_SUB(AT_K(bad, "error", ""), "unknown capability"),')
    A('             "unknown capability must be reported, not silently skipped"));')
    A('     TRUE)));')

    # 温度表：五个能力一次钉死（卡面点名的数字）
    A('')
    A('// 卡面点名的温度：complete 0.8 / polish 0.5 / translate 0.3 / summarize 0.3 / suggest_tags 0.3')
    for cap, temp in [('complete', 0.8), ('polish', 0.5), ('translate', 0.3),
                      ('summarize', 0.3), ('suggest_tags', 0.3)]:
        A('TEST("temperature/%s", FUN(() ,' % cap)
        A('    (ASSERT_EQ(AT_K(BUILD_MESSAGES(INDEX_SET(INDEX_SET(DICT(), "capability", %s), "text", "x")), "temperature", -1), %r));'
          % (wl(cap), temp))
        A('    TRUE));')

    # ── ② 取 content ────────────────────────────────────────────────
    A('')
    A('// ── ② 响应取内容（纯函数 EXTRACT_CONTENT）────────────────────────')
    for c in base['extract']:
        A('// %s' % c['name'])
        A('//   %s' % c['note'])
        A('//   出处：%s' % c['source'])
        A('LET(T2_extract_%s, EXTRACT_CONTENT(%s));'
          % (c['name'], expr({'body': c['body'], 'status': c['status']})))
    A('')

    for c in base['extract']:
        name = c['name']
        want = c['want']
        var = 'T2_extract_%s' % name
        A('')
        A('TEST("extract/%s", FUN(() ,' % name)
        A('    (ASSERT_EQ(AT_K(%s, "ok", "?"), %s));'
          % (var, 'TRUE' if want['ok'] else 'FALSE'))
        A('    (ASSERT_EQ(AT_K(%s, "status", -999), %d));' % (var, c['status']))
        if want['ok']:
            A('    (ASSERT_EQ(AT_K(%s, "content", "?"), %s));' % (var, wl(want['content'])))
        else:
            A('    (ASSERT(CONTAINS_SUB(AT_K(%s, "error", ""), %s),'
              % (var, wl(want['error_contains'])))
            A('            %s));' % wl('%s: error must mention the failed check' % name))
        A('    TRUE));')

    # ── ③ 后处理 ────────────────────────────────────────────────────
    A('')
    A('// ── ③ 后处理（纯函数 FINISH：strip / 摘要截断 / 标签解析）──────────')
    for c in base['finish']:
        name = c['name']
        want = c['want']
        opts = {'capability': c['capability'], 'content': c['content']}
        if 'max_length' in c:
            opts['max_length'] = c['max_length']
        if 'max_tags' in c:
            opts['max_tags'] = c['max_tags']
        A('// %s' % name)
        A('//   %s' % c['note'])
        A('//   出处：%s' % c['source'])
        A('LET(T2_fin_%s, FINISH(%s));' % (name, expr(opts)))
    A('')

    for c in base['finish']:
        name = c['name']
        want = c['want']
        var = 'T2_fin_%s' % name
        A('')
        A('TEST("finish/%s", FUN(() ,' % name)
        A('    (ASSERT_EQ(AT_K(%s, "ok", "?"), %s));'
          % (var, 'TRUE' if want['ok'] else 'FALSE'))
        if not want['ok']:
            A('    (ASSERT(CONTAINS_SUB(AT_K(%s, "error", ""), "not valid JSON"),'
              % var)
            A('            %s));' % wl('%s: unparsable tag payload must be reported' % name))
        elif c['capability'] == 'suggest_tags':
            A('    (ASSERT_EQ(JOIN(AT_K(%s, "tags", []), "|"), %s));'
              % (var, wl('|'.join(want['tags']))))
            A('    (ASSERT_EQ(AT_K(%s, "valid_shape", "?"), %s));'
              % (var, 'TRUE' if want['valid_shape'] else 'FALSE'))
        else:
            A('    (ASSERT_EQ(AT_K(%s, "content", "?"), %s));' % (var, wl(want['content'])))
        A('    TRUE));')

    # ── ④ 词频降级 ──────────────────────────────────────────────────
    A('')
    A('// ── ④ 词频降级（纯函数 FALLBACK_SUGGEST_TAGS）────────────────────')
    for c in base['fallback']:
        A('// %s' % c['name'])
        A('//   %s' % c['note'])
        A('//   出处：%s' % c['source'])
        A('LET(T2_fb_%s, FALLBACK_SUGGEST_TAGS(%s));'
          % (c['name'], expr({'text': c['text'], 'max_tags': c['max_tags']})))
    A('')

    for c in base['fallback']:
        name = c['name']
        want = c['want']
        var = 'T2_fb_%s' % name
        A('')
        A('TEST("fallback/%s", FUN(() ,' % name)
        A('    (ASSERT_EQ(LEN(%s), %d));' % (var, len(want)))
        A('    (ASSERT_EQ(JOIN(%s, "|"), %s));' % (var, wl('|'.join(want))))
        A('    TRUE));')

    A('')
    A('// 反向守卫：停用词**永远**不能出现在标签里（两字词也被 `len > 2` 挡掉）')
    A('TEST("fallback/guard_no_stopwords", FUN(() ,')
    A('    (LET(t, FALLBACK_SUGGEST_TAGS(INDEX_SET(INDEX_SET(DICT(), "text", "the and of to in is are be been"), "max_tags", 5)));')
    A('     (ASSERT(==(LEN(t), 0), "stopword-only text must yield no tags"));')
    A('     TRUE)));')

    # ── ⑤ enabled + endpoint ────────────────────────────────────────
    A('')
    A('// ── ⑤ 是否构建 + 端点（IS_ENABLED / ENDPOINT_PARTS）────────────────')
    for c in base['enabled']:
        A('// %s —— %s' % (c['name'], c['note']))
        A('LET(T2_en_%s, IS_ENABLED(%s));' % (c['name'], expr(c['cfg'])))
    A('')
    for c in base['enabled']:
        A('TEST("enabled/%s", FUN(() ,' % c['name'])
        A('    (ASSERT_EQ(T2_en_%s, %s));'
          % (c['name'], 'TRUE' if c['want'] else 'FALSE'))
        A('    TRUE));')

    A('')
    A('// ⚠ 一个坑：`ai_enabled` 只认布尔 TRUE（Python 认任意真值）—— 刻意语义，钉住')
    A('TEST("enabled/guard_truthy_int_is_false", FUN(() ,')
    A('    (ASSERT_EQ(IS_ENABLED(INDEX_SET(INDEX_SET(DICT(), "ai_enabled", 1), "ai_api_key", "k")), FALSE));')
    A('    TRUE));')

    A('')
    for c in base['endpoint']:
        A('// %s —— %s' % (c['name'], c['note']))
        A('//   Python 拼出的 url：%s' % c['python_url'])
        A('LET(T2_ep_%s, ENDPOINT_PARTS(%s));'
          % (c['name'], expr({'provider': c['provider'], 'endpoint': c['endpoint']})))
    A('')
    for c in base['endpoint']:
        name = c['name']
        want = c['want']
        var = 'T2_ep_%s' % name
        A('')
        A('TEST("endpoint/%s", FUN(() ,' % name)
        A('    (ASSERT_EQ(AT_K(%s, "ok", "?"), %s));'
          % (var, 'TRUE' if want['ok'] else 'FALSE'))
        if want['ok']:
            A('    (ASSERT_EQ(AT_K(%s, "host", "?"), %s));' % (var, wl(want['host'])))
            A('    (ASSERT_EQ(AT_K(%s, "port", -1), %d));' % (var, want['port']))
            A('    (ASSERT_EQ(AT_K(%s, "path", "?"), %s));' % (var, wl(want['path'])))
        else:
            A('    (ASSERT(CONTAINS_SUB(AT_K(%s, "error", ""), %s),'
              % (var, wl(want['error_contains'])))
            A('            %s));' % wl('%s: error must mention why the endpoint is rejected' % name))
        A('    TRUE));')

    # ── ⑥ 出参 JSON ─────────────────────────────────────────────────
    A('')
    A('// ── ⑥ 出参 JSON（纯函数 JSON_ENVELOPE —— 反向守卫「错误也必须是 JSON」）──')
    for c in base['envelope']:
        A('// %s —— %s' % (c['name'], c['note']))
        A('LET(T2_env_%s, JSON_ENVELOPE(%s));'
          % (c['name'], expr({'ok': c['ok'], 'error': c.get('error'),
                              'content': c.get('content'), 'tags': c.get('tags')})))
    A('')
    for c in base['envelope']:
        A('')
        A('TEST("envelope/%s", FUN(() ,' % c['name'])
        A('    (ASSERT_EQ(T2_env_%s, %s));' % (c['name'], wl(c['want'])))
        A('    // 反向守卫：整条响应必须是一个 JSON 对象（以 { 开头、以 } 结尾）')
        A('    (ASSERT_EQ(SUB(T2_env_%s, 0, 1), "{"));' % c['name'])
        A('    (ASSERT_EQ(SUB(T2_env_%s, -(LEN(T2_env_%s), 1)), "}"));'
          % (c['name'], c['name']))
        A('    TRUE));')

    # ── ⑦ 全链路（假传输）──────────────────────────────────────────
    A('')
    A('// ── ⑦ 全链路（五个能力 + 注入的假传输；仍然不出网）───────────────')
    for c in base['pipeline']:
        name = c['name']
        A('// %s' % name)
        A('//   %s' % c['note'])
        A('//   出处：%s' % c['source'])
        A('SET(%s, "");' % SEEN)
        A('SET(%s, %s);' % (REPLY, wl(c['raw'])))
        A('LET(T2_pipe_%s, %s(%s));'
          % (name, CAP_FN[c['capability']], opts_with_exchange(c['opts'])))
        # ⚠ 必须**就地快照**：所有用例是「先全部调用、后统一断言」
        A('LET(T2_wire_%s, %s);' % (name, SEEN))
    A('')

    for c in base['pipeline']:
        name = c['name']
        want = c['want']
        var = 'T2_pipe_%s' % name
        wire = 'T2_wire_%s' % name
        A('')
        A('// %s' % name)
        A('TEST("pipeline/%s/ok", FUN(() ,' % name)
        A('    (ASSERT_EQ(AT_K(%s, "ok", "?"), %s));'
          % (var, 'TRUE' if want['ok'] else 'FALSE'))
        A('    TRUE));')
        if want.get('status_is_null'):
            A('TEST("pipeline/%s/status_null", FUN(() ,' % name)
            A('    (ASSERT_EQ(TYPE(AT_K(%s, "status", NULL)), "NULL"));' % var)
            A('    TRUE));')
        elif 'status' in want:
            A('TEST("pipeline/%s/status", FUN(() ,' % name)
            A('    (ASSERT_EQ(AT_K(%s, "status", -999), %d));' % (var, want['status']))
            A('    TRUE));')
        if 'content' in want:
            A('TEST("pipeline/%s/content", FUN(() ,' % name)
            A('    (ASSERT_EQ(AT_K(%s, "content", "?"), %s));' % (var, wl(want['content'])))
            A('    TRUE));')
        if 'tags' in want:
            A('TEST("pipeline/%s/tags", FUN(() ,' % name)
            A('    (ASSERT_EQ(JOIN(AT_K(%s, "tags", []), "|"), %s));'
              % (var, wl('|'.join(want['tags']))))
            A('    TRUE));')
            A('TEST("pipeline/%s/fallback", FUN(() ,' % name)
            A('    (ASSERT_EQ(AT_K(%s, "fallback", "?"), %s));'
              % (var, 'TRUE' if want['fallback'] else 'FALSE'))
            A('    TRUE));')
        if 'result' in want:
            A('TEST("pipeline/%s/empty", FUN(() ,' % name)
            A('    (ASSERT_EQ(AT_K(%s, "content", "?"), ""));' % var)
            A('    TRUE));')
        for sub in ([want['error_contains']] if 'error_contains' in want else []):
            A('TEST("pipeline/%s/error", FUN(() ,' % name)
            A('    (ASSERT(CONTAINS_SUB(AT_K(%s, "error", ""), %s),'
              % (var, wl(sub)))
            A('            %s));' % wl('%s: error must mention %r' % (name, sub)))
            A('    TRUE));')
        # 传输是否真的被调用
        if want['transport_called']:
            A('TEST("pipeline/%s/transport_called", FUN(() ,' % name)
            A('    (ASSERT(>(LEN(%s), 0), %s));' % (wire, wl('%s: exchange must be called' % name)))
            A('    TRUE));')
            if 'wire_body' in want:
                A('TEST("pipeline/%s/wire_body", FUN(() ,' % name)
                A('    // 请求体 = 报文里第一个 CRLFCRLF 之后的全部（逐字节对照 STRINGIFY 口径）')
                A('    (ASSERT_EQ(SUB(%s, +(INDEX_OF(%s, "\\r\\n\\r\\n"), 4)), %s));'
                  % (wire, wire, wl(want['wire_body'])))
                A('    TRUE));')
            A('TEST("pipeline/%s/wire_has_auth", FUN(() ,' % name)
            A('    // 传输层（卡 S5-1）负责 Authorization；这里只确认它真的进了报文')
            A('    (ASSERT(CONTAINS_SUB(%s, "Authorization: Bearer "),'
              % wire)
            A('            %s));' % wl('%s: bearer header must be present' % name))
            A('    TRUE));')
        else:
            A('// 反向守卫：未配置 / 禁用 / 空文本 ⇒ **根本不碰传输**')
            A('TEST("pipeline/%s/transport_not_called", FUN(() ,' % name)
            A('    (ASSERT_EQ(%s, ""));' % wire)
            A('    TRUE));')

    # ── ⑧ 反向守卫：4xx 必须变成 JSON 错误 ──────────────────────────
    A('')
    A('// ── ⑧ 反向守卫：后端 4xx 必须变成 JSON 错误（卡 S5-2 的核心守卫）────────')
    A('// 直接拿 pipeline 里那次 401 的**真实**失败结果去做出参 JSON')
    A('LET(T2_err_body, JSON_ENVELOPE(INDEX_SET(INDEX_SET(DICT(), "ok", AT_K(T2_pipe_complete_http_401, "ok", TRUE)), "error", AT_K(T2_pipe_complete_http_401, "error", ""))));')
    A('TEST("guard/401_envelope_is_json", FUN(() ,')
    A('    (ASSERT_EQ(SUB(T2_err_body, 0, 10), "{\\"error\\": "));')
    A('    (ASSERT(CONTAINS_SUB(T2_err_body, "HTTP 401"), "status must survive into the JSON error"));')
    A('    TRUE));')

    # ── ⑨ 形状契约 ──────────────────────────────────────────────────
    A('')
    A('// ── ⑨ 形状契约（键集合固定，调用方可以安全地 AT_K）──────────────────')
    A('TEST("shape/build_keys", FUN(() ,')
    A('    (ASSERT_EQ(JOIN(KEYS(T2_build_complete_basic), "|"),')
    A('        "ok|capability|model|temperature|messages|skip"));')
    A('    TRUE));')
    A('TEST("shape/extract_keys", FUN(() ,')
    A('    (ASSERT_EQ(JOIN(KEYS(T2_extract_normal), "|"), "ok|status|content"));')
    A('    TRUE));')
    A('TEST("shape/failure_keys", FUN(() ,')
    A('    (ASSERT_EQ(JOIN(KEYS(T2_pipe_no_api_key), "|"), "ok|status|error"));')
    A('    TRUE));')
    A('TEST("shape/tags_keys", FUN(() ,')
    A('    (ASSERT_EQ(JOIN(KEYS(T2_pipe_tags_ok), "|"), "ok|tags|fallback"));')
    A('    TRUE));')
    A('TEST("shape/endpoint_keys", FUN(() ,')
    A('    (ASSERT_EQ(JOIN(KEYS(T2_ep_openai_default), "|"),')
    A('        "ok|endpoint|scheme|host|port|path"));')
    A('    TRUE));')

    # ── 跑测试 + 自己把关退出码 ─────────────────────────────────────
    A('')
    A('// ── 跑测试 + 自己把关退出码 ─────────────────────────────────────')
    A('LET(records, RUN_TESTS());')
    A('PRINT("test_ai: ", LEN(records), " test(s) run");')
    A('LET MUT(failed, 0);')
    A('FOR(rec, records,')
    A('    (IF(AT_K(rec, "passed", FALSE),')
    A('        PRINT("  PASS ", AT_K(rec, "name", "?")),')
    A('        (SET(failed, +(failed, 1));')
    A('         PRINT("  FAIL ", AT_K(rec, "name", "?"), " :: ", '
      'AT_K(rec, "error", ""))))));')
    A('PRINT("test_ai: failed=", failed);')
    A('IF(>(failed, 0), (PRINT_ERR("test_ai: FAILED"); PANIC("ai tests failed")), NULL);')
    A('PRINT("test_ai: OK");')

    chars, lines = write(OUT, src)
    print('wrote %s (%d chars, %d lines)' % (OUT, chars, lines))


if __name__ == '__main__':
    main()
