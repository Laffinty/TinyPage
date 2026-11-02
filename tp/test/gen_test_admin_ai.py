"""生成 tp/test/test_admin_ai.wll —— AI 端点接线的**脱网**测试（卡 S5-3）。

⚠ 输出的 .wll 由本文件生成，不要手改。

**为什么能脱网**：`tp/lib/admin_ai.wll` 自己不碰网络 —— 它把 `opts.exchange` 原样透传给
卡 S5-2 的 `tp/lib/ai.wll`，而那一层的 `opts.exchange` 又是卡 S5-1 的传输注入点。
本文件用一个假传输回放夹具里的原始响应报文 ⇒ 整条
「cfg 摊平 → 分派 → 建消息 → 建请求 → 解析 → 后处理 → 出参 JSON」都不出网。

**基准**：`tp/test/fixtures/admin_ai_baseline.json`（由 `gen_admin_ai_baseline.py` 生成）
  · 期望值全部由真 Python 现算：`tinypage.admin.actions.ai_assist()` + 假 `urlopen`
    （`AIAssistance._call_api` 与五个能力全是**真**的）；
  · 每条用例同时钉：出参 JSON（`JSON_ENVELOPE`）、`ok`、是否真的发了请求、
    以及**请求体**（按 `std.json::STRINGIFY` 口径复现的 Python payload）。

**覆盖**
  · assist：五个 action 的成功路径 + 空文本 + 未知 action + 两种「未配置」 +
    「未配置 + 未知 action」的**顺序**守卫 + 后端 500 / 空 choices / 非 JSON 响应体
  · endpoint：/translate 的 en 缺省 / ja / 未知码 / 未配置 / 后端 500
  · guard：错误也是 JSON（每个用例都验）、未知 action 不落默认分支、
    `AI_ASSIST_JSON` / `TRANSLATE_JSON` **就是** `JSON_ENVELOPE(...)` 的组合、
    `ai_enabled` 非布尔（继承 ai.wll 的刻意语义 ⑥）

**自己把关退出码**：`RUN_TESTS()` 的失败**不影响退出码**（规范明载）
⇒ 末尾必须 `IF(>(failed, 0), PANIC(...), NULL)`。

用法：python gen_test_admin_ai.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from wllgen import write  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, 'fixtures')
OUT = os.path.join(HERE, 'test_admin_ai.wll')

# 测试实例自己的顶层名一律 T5_ 前缀（坑 52：顶层绑定跨模块共享）
SEEN = 'T5_seen'
REPLY = 'T5_reply'
EXCHANGE = 'T5_exchange'

EXPORTS = ["AI_ASSIST", "TRANSLATE_ENDPOINT", "AI_ASSIST_JSON", "TRANSLATE_JSON"]


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
    """JSON 值 → WLWL 表达式（字典保序 ⇒ INDEX_SET 链）。"""
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


def opts_of(c, with_exchange):
    """构造被测 opts（键序：业务键 → 可选 exchange 在最后）。"""
    d = {}
    if c.get('action'):
        d['action'] = c['action']
    d['text'] = c['text']
    if c.get('lang'):
        d['target'] = c['lang']
    d['cfg'] = c['cfg']
    out = 'DICT()'
    for k, v in d.items():
        out = 'INDEX_SET(%s, %s, %s)' % (out, wl(k), expr(v))
    if with_exchange:
        out = 'INDEX_SET(%s, "exchange", %s)' % (out, EXCHANGE)
    return out


def main():
    with open(os.path.join(FIXTURES, 'admin_ai_baseline.json'), encoding='utf-8') as f:
        base = json.load(f)

    src = []
    A = src.append
    A('// tp/test/test_admin_ai.wll —— AI 端点接线的脱网测试（卡 S5-3）')
    A('//')
    A('// ⚠ 本文件由 tp/test/gen_test_admin_ai.py 生成 —— 请勿手改。')
    A('//')
    A('// 被测：tp/lib/admin_ai.wll')
    A('//   AI_ASSIST / TRANSLATE_ENDPOINT      —— 分派 + cfg 摊平 + 出参口径')
    A('//   AI_ASSIST_JSON / TRANSLATE_JSON     —— 响应体（= JSON_ENVELOPE(...)）')
    A('// 基准：tp/test/fixtures/admin_ai_baseline.json')
    A('//   · 期望值由 gen_admin_ai_baseline.py 调**真** ai_assist() 现算（不是手抄）')
    A('//   · 六条刻意偏离登记在该 JSON 的 meta.divergences')
    A('//')
    A('// ⚠ **本文件不出网**：`opts.exchange` 逐层透传到卡 S5-1 的传输注入点，')
    A('//   假传输回放夹具里的原始响应报文 ⇒ 不带 --ext、不碰 tls 也能全绿。')
    A('//')
    A('// ⚠ RUN_TESTS() 的失败**不影响退出码**（规范明载）⇒ 本文件自己把关。')
    A('IMPORT("wlwl:std.test", ["TEST", "ASSERT", "ASSERT_EQ", "RUN_TESTS"]);')
    A('IMPORT("wlwl:std.str", ["CAT", "JOIN", "CONTAINS_SUB", "INDEX_OF"]);')
    A('IMPORT("wlwl:std.json", ["JSON_VALIDATE", "PARSE"]);')
    A('IMPORT("./../lib/admin_ai.wll", [')
    for i, name in enumerate(EXPORTS):
        tail = ']);' if i == len(EXPORTS) - 1 else ','
        A('        "%s"%s' % (name, tail))
    A('// 出参口径来自卡 S5-2（这里直接 import，钉的是**接线公式**而非另造形状）')
    A('IMPORT("./../lib/ai.wll", ["JSON_ENVELOPE"]);')
    A('')
    A('// ── 测试缝：假传输（记下真实请求文本，回放夹具里的响应报文）──────────')
    A('LET MUT(%s, "");' % SEEN)
    A('LET MUT(%s, "");' % REPLY)
    A('LET(%s, FUN((req), (SET(%s, req); %s)));' % (EXCHANGE, SEEN, REPLY))
    A('')
    A('// ── 用例 ────────────────────────────────────────────────────────')
    A('// ⚠ 每个用例都是「先全部调用、后统一断言」⇒ 请求文本必须**就地快照**，')
    A('//   并且每次调用前都要重设 T5_reply（否则回放的是上一条用例的响应）。')

    for c in base['assist']:
        name = c['name']
        A('')
        A('// %s —— %s' % (name, c['note']))
        A('//   出处：%s' % c['source'])
        A('SET(%s, "");' % SEEN)
        A('SET(%s, %s);' % (REPLY, wl(c['raw'])))
        A('LET(T5_a_%s, AI_ASSIST(%s));'
          % (name, opts_of(c, c['want']['transport_called'])))
        A('LET(T5_aw_%s, %s);' % (name, SEEN))
        A('LET(T5_aj_%s, JSON_ENVELOPE(T5_a_%s));' % (name, name))

    for c in base['endpoint']:
        name = c['name']
        A('')
        A('// endpoint/%s —— %s' % (name, c['note']))
        A('//   出处：%s' % c['source'])
        A('SET(%s, "");' % SEEN)
        A('SET(%s, %s);' % (REPLY, wl(c['raw'])))
        A('LET(T5_e_%s, TRANSLATE_ENDPOINT(%s));'
          % (name, opts_of(c, c['want']['transport_called'])))
        A('LET(T5_ew_%s, %s);' % (name, SEEN))
        A('LET(T5_ej_%s, JSON_ENVELOPE(T5_e_%s));' % (name, name))

    def emit_block(cases, var_prefix, wire_prefix, json_prefix, label):
        for c in cases:
            name = c['name']
            want = c['want']
            var = '%s%s' % (var_prefix, name)
            wire = '%s%s' % (wire_prefix, name)
            env = '%s%s' % (json_prefix, name)
            A('')
            A('TEST("%s/%s/ok", FUN(() ,' % (label, name))
            A('    (ASSERT_EQ(AT_K(%s, "ok", "?"), %s));'
              % (var, 'TRUE' if want['ok'] else 'FALSE'))
            A('    TRUE));')
            # 出参必须是 JSON 对象（卡面第 ② 条：错误也必须是 JSON）
            A('TEST("%s/%s/json", FUN(() ,' % (label, name))
            A('    (ASSERT_EQ(IS_ERR(JSON_VALIDATE(%s)), FALSE));' % env)
            A('    (ASSERT_EQ(TYPE(PARSE(%s)), "DICT"));' % env)
            A('    TRUE));')
            if want.get('envelope') is not None and not c['error_text_diverges']:
                A('TEST("%s/%s/body", FUN(() ,' % (label, name))
                A('    // 逐字节对齐真 Python 的 {"result"|"error": …}（ensure_ascii=False 口径）')
                A('    (ASSERT_EQ(%s, %s));' % (env, wl(want['envelope'])))
                A('    TRUE));')
            elif c['error_text_diverges']:
                A('TEST("%s/%s/error_shape", FUN(() ,' % (label, name))
                A('    // 刻意语义 ④：后端错误的**文案**与 Python 不同，形状必须相同')
                A('    (ASSERT_EQ(AT_K(%s, "ok", "?"), FALSE));' % var)
                A('    (ASSERT(>(LEN(AT_K(%s, "error", "")), 0),' % var)
                A('            %s));' % wl('%s: backend error must carry a message' % name))
                A('    TRUE));')
            else:
                # Python 自己 500 了（JSONDecodeError）⇒ 只能钉我们的形状与原因
                A('TEST("%s/%s/error_shape", FUN(() ,' % (label, name))
                A('    // 刻意语义 ③：Python 在这条上直接 500（JSONDecodeError 不被捕获）')
                A('    (ASSERT_EQ(AT_K(%s, "ok", "?"), FALSE));' % var)
                A('    (ASSERT(CONTAINS_SUB(%s, %s),' % (env, wl(c['error_contains'] or '')))
                A('            %s));' % wl('%s: malformed body must be reported as JSON' % name))
                A('    TRUE));')
            # 传输是否真的被调用（反向守卫：未配置 / 未知 action / 空文本 一律不碰网络）
            A('TEST("%s/%s/transport", FUN(() ,' % (label, name))
            if want['transport_called']:
                A('    (ASSERT(>(LEN(%s), 0),' % wire)
                A('            %s));' % wl('%s: exchange must be called' % name))
            else:
                A('    (ASSERT_EQ(%s, ""));' % wire)
            A('    TRUE));')
            if want.get('wire_body'):
                A('TEST("%s/%s/wire_body", FUN(() ,' % (label, name))
                A('    // 请求体 = 报文里第一个 CRLFCRLF 之后的全部（STRINGIFY 口径）')
                A('    (ASSERT_EQ(SUB(%s, +(INDEX_OF(%s, "\\r\\n\\r\\n"), 4)), %s));'
                  % (wire, wire, wl(want['wire_body'])))
                A('    TRUE));')
            if want.get('wire_contains'):
                A('TEST("%s/%s/wire_lang", FUN(() ,' % (label, name))
                A('    (ASSERT(CONTAINS_SUB(%s, %s),' % (wire, wl(want['wire_contains'])))
                A('            %s));' % wl('%s: target language must reach the request' % name))
                A('    TRUE));')

    A('')
    A('// ── ① /ai-assist ────────────────────────────────────────────────')
    A('// ⚠ 期望值 = 真 ai_assist() 的 JSON；请求体 = 真 payload 按 STRINGIFY 口径重排')
    emit_block(base['assist'], 'T5_a_', 'T5_aw_', 'T5_aj_', 'assist')

    A('')
    A('// ── ② /translate（文本层）───────────────────────────────────────')
    emit_block(base['endpoint'], 'T5_e_', 'T5_ew_', 'T5_ej_', 'endpoint')

    # ── ③ 反向守卫 ───────────────────────────────────────────────────
    guard = base['guards']
    A('')
    A('// ── ③ 反向守卫 ──────────────────────────────────────────────────')
    A('// 空 opts（连 cfg 都没有）⇒ 必须是同一句未配置文案，且**是 JSON**')
    A('LET(T5_g_empty_assist, JSON_ENVELOPE(AI_ASSIST(DICT())));')
    A('TEST("guard/empty_opts_unconfigured", FUN(() ,')
    A('    (ASSERT_EQ(T5_g_empty_assist, %s));'
      % wl('{"error": "%s"}' % guard['unconfigured_message']))
    A('    TRUE));')
    A('LET(T5_g_empty_translate, JSON_ENVELOPE(TRANSLATE_ENDPOINT(DICT())));')
    A('TEST("guard/empty_opts_translate", FUN(() ,')
    A('    (ASSERT_EQ(T5_g_empty_translate, %s));'
      % wl('{"error": "%s"}' % guard['unconfigured_message']))
    A('    TRUE));')
    A('')
    A('// 失败形状固定为 {ok, error}（调用方可以安全地 AT_K）')
    A('TEST("shape/failure_keys", FUN(() ,')
    A('    (ASSERT_EQ(JOIN(KEYS(AI_ASSIST(DICT())), "|"), "ok|error"));')
    A('    TRUE));')
    A('')
    A('// ⚠ 已登记刻意语义 ⑤：ai_enabled 只认布尔 TRUE（Python 认任意真值）')
    A('LET(T5_g_truthy, JSON_ENVELOPE(AI_ASSIST(INDEX_SET(INDEX_SET(INDEX_SET(DICT(), "action", "complete"), "text", "x"), "cfg", INDEX_SET(INDEX_SET(DICT(), "ai_enabled", 1), "ai_api_key", "sk-test")))));')
    A('TEST("guard/truthy_int_is_unconfigured", FUN(() ,')
    A('    (ASSERT_EQ(T5_g_truthy, %s));'
      % wl('{"error": "%s"}' % guard['unconfigured_message']))
    A('    TRUE));')
    A('')
    A('// `AI_ASSIST_JSON` / `TRANSLATE_JSON` **就是** JSON_ENVELOPE(...) 的组合（接线公式）')
    A('// ⚠ 在顶层求值：每次调用前重设 T5_reply，否则回放的是上一条用例的响应')
    A('SET(%s, "");' % SEEN)
    A('SET(%s, %s);' % (REPLY, wl(base['assist'][0]['raw'])))
    A('LET(T5_g_assist_json, AI_ASSIST_JSON(%s));'
      % opts_of(base['assist'][0], True))
    A('SET(%s, "");' % SEEN)
    A('SET(%s, %s);' % (REPLY, wl(base['endpoint'][1]['raw'])))
    A('LET(T5_g_translate_json, TRANSLATE_JSON(%s));'
      % opts_of(base['endpoint'][1], True))
    A('TEST("guard/assist_json_is_envelope", FUN(() ,')
    A('    (ASSERT_EQ(T5_g_assist_json, %s));'
      % wl(base['assist'][0]['want']['envelope']))
    A('    TRUE));')
    A('TEST("guard/translate_json_is_envelope", FUN(() ,')
    A('    (ASSERT_EQ(T5_g_translate_json, %s));'
      % wl(base['endpoint'][1]['want']['envelope']))
    A('    TRUE));')
    A('')
    A('// 未知 action 的错误**不是**任何能力的成功结果（不落默认分支）')
    A('TEST("guard/unknown_is_not_a_result", FUN(() ,')
    A('    (ASSERT(CONTAINS_SUB(T5_aj_unknown_action, %s),'
      % wl(guard['unknown_prefix']))
    A('            "unknown action must be named in the error"));')
    A('    (ASSERT(==(INDEX_OF(T5_aj_unknown_action, "\\"result\\""), -1),')
    A('            "unknown action must not produce a result"));')
    A('    TRUE));')

    # ── 跑测试 + 自己把关退出码 ─────────────────────────────────────
    A('')
    A('// ── 跑测试 + 自己把关退出码 ─────────────────────────────────────')
    A('LET(records, RUN_TESTS());')
    A('PRINT("test_admin_ai: ", LEN(records), " test(s) run");')
    A('LET MUT(failed, 0);')
    A('FOR(rec, records,')
    A('    (IF(AT_K(rec, "passed", FALSE),')
    A('        PRINT("  PASS ", AT_K(rec, "name", "?")),')
    A('        (SET(failed, +(failed, 1));')
    A('         PRINT("  FAIL ", AT_K(rec, "name", "?"), " :: ", '
      'AT_K(rec, "error", ""))))));')
    A('PRINT("test_admin_ai: failed=", failed);')
    A('IF(>(failed, 0), (PRINT_ERR("test_admin_ai: FAILED"); PANIC("admin_ai tests failed")), NULL);')
    A('PRINT("test_admin_ai: OK");')

    chars, lines = write(OUT, src)
    print('wrote %s (%d chars, %d lines)' % (OUT, chars, lines))


if __name__ == '__main__':
    main()
