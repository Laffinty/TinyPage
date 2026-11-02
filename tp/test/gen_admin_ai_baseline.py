"""生成 tp/test/fixtures/admin_ai_baseline.json —— AI 端点接线的验收基准（卡 S5-3）。

⚠ 输出的 JSON 由本文件生成，不要手改。

**期望值全部由真 Python 现算**（不是手抄）：
  · 直接调 `tinypage.admin.actions.ai_assist()`（**真**分派表、真出参 JSON）；
  · 只把 `urllib.request.urlopen` 换成假响应 —— `AIAssistance._call_api` 仍是**真**的
    （`json.loads` + `choices[0].message.content` + 三条 except 全跑），
    五个能力的消息构造与后处理（strip / 截断 / 标签解析 / 词频降级）也全是**真**的；
  · 请求体（`wire_body`）按 `std.json::STRINGIFY` 的口径
    （`json.dumps(..., sort_keys=True, separators=(",", ":"), ensure_ascii=False)`）
    从**抓到的真实 payload** 重排 ⇒ 与 Python 自己那份（`python_body`，插入序 + `", "` 分隔）
    字节不同，这是 ai.wll 已登记的刻意语义 ⑤。
  · `/translate` 在 Python 里未配置时的**真实**文案，用临时目录里的一篇真文章
    跑 `content.translate_article()` 得到（不是从源码抄的）。

**为什么要这么做**：卡面要求「未启用 ⇒ 逐字文案」「未知 action 不得落默认分支」
「后端错误必须是 JSON」——这三条只有对着真 Python 比才有意义。

**登记在 meta.divergences 的刻意语义（不是沉默偏离）**
  ① `/translate` 的文章层（定位文件 / summarize(200) / 落盘，content.py:776-840）不在
     `admin_ai.wll`：本卡只交付「AI 这一跳」，`TRANSLATE_ENDPOINT` 收正文文本。
  ② `/translate` 未配置时 Python 的文案是
     `AI not configured. Set ai_api_key in config.`（content.py:798-802，真实跑出来了，
     见 `article_unconfigured`）；本模块按卡面第 ① 条统一用 ai_assist 的文案。
  ③ 响应体不是 JSON 时 Python 抛 `JSONDecodeError`（**不是** `AIAssistanceError`）
     ⇒ 未被 `ai_assist` 捕获 ⇒ WSGI 层 500；我们返回 JSON 错误（卡面第 ② 条）。
  ④ 后端 5xx 的**错误文案**不同（Python `API error: 500`，传输层 `HTTP 500 ...`），
     但形状相同（200 + `{"error": …}`）⇒ 该用例只钉形状，不钉文案。
  ⑤ `ai_enabled` 只认布尔 TRUE（Python 认任意真值）—— 继承 ai.wll 的刻意语义 ⑥。

**⚠ 夹具里没有任何随机值 / 时间戳**：本文件不生成 CSRF、不写 `datetime.now()`
⇒ 「重生成无漂移」恒成立。

用法：python gen_admin_ai_baseline.py
"""
import io
import json
import os
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
sys.path.insert(0, ROOT)

from tinypage.admin.actions import ai_assist  # noqa: E402
from tinypage.content import translate_article, write_article  # noqa: E402

OUT = os.path.join(HERE, 'fixtures', 'admin_ai_baseline.json')


class StubCfg:
    """Config 的最小替身：`build_ai_assistance` 只 getattr 这几个属性（ai_assistance.py:273-283）。"""

    def __init__(self, ai_enabled=False, ai_api_key='', ai_model='gpt-3.5-turbo',
                 ai_provider='openai', ai_endpoint=''):
        self.ai_enabled = ai_enabled
        self.ai_api_key = ai_api_key
        self.ai_model = ai_model
        self.ai_provider = ai_provider
        self.ai_endpoint = ai_endpoint


class FakeResp:
    """`urllib.request.urlopen` 的假响应（只有 `read()` 与上下文管理器被用到，:76-77）。"""

    def __init__(self, body):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


CFG_ON = {'ai_enabled': True, 'ai_api_key': 'sk-test'}
CFG_OFF = {'ai_enabled': False}
CFG_NO_KEY = {'ai_enabled': True, 'ai_api_key': ''}


def ok_http(reply, status=200, reason='OK'):
    """构造一个「真 HTTP 响应」：body 是 OpenAI 形状的 chat completion。"""
    body = json.dumps({
        'id': 'chatcmpl-test',
        'object': 'chat.completion',
        'choices': [{
            'index': 0,
            'message': {'role': 'assistant', 'content': reply},
            'finish_reason': 'stop',
        }],
    }, ensure_ascii=False)
    return {'status': status, 'reason': reason, 'body': body}


def raw_http(status, reason, body, ctype='application/json'):
    """HTTP 响应报文（卡 S5-1 的传输层解析它）—— Content-Length 按 UTF-8 **字节**算。"""
    blob = body.encode('utf-8')
    return ('HTTP/1.1 %d %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n'
            % (status, reason, ctype, len(blob))) + body


def http_to_raw(http):
    if 'raise' in http:
        r = http['raise']
        ctype = 'text/plain' if 'html' in r['body'] else 'application/json'
        return raw_http(r['status'], r.get('reason', 'Internal Server Error'), r['body'], ctype)
    return raw_http(http.get('status', 200), http.get('reason', 'OK'), http['body'])


def run_python(case):
    """跑**真的** `ai_assist`（只换 urlopen），返回它实际吐出的 JSON 与抓到的请求。"""
    http = case['http']
    captured = {}

    def fake_urlopen(req, timeout=30):
        captured['url'] = req.full_url
        captured['timeout'] = timeout
        captured['body'] = req.data.decode('utf-8')
        if 'raise' in http:
            r = http['raise']
            raise urllib.error.HTTPError(req.full_url, r['status'], 'err', {},
                                         io.BytesIO(r['body'].encode('utf-8')))
        return FakeResp(http['body'].encode('utf-8'))

    post = {'action': [case['action']], 'text': [case['text']]}
    if 'lang' in case:
        post['lang'] = [case['lang']]

    rec = {}

    def start_response(status, headers):
        rec['status'] = status
        rec['headers'] = headers

    orig = urllib.request.urlopen
    urllib.request.urlopen = fake_urlopen
    try:
        try:
            chunks = ai_assist({}, start_response, StubCfg(**case['cfg']), post)
            body = json.loads(b''.join(chunks).decode('utf-8'))
            raised = None
        except Exception as exc:  # noqa: BLE001 —— 记录真 Python 的行为（③ 的实证）
            body = None
            raised = '%s: %s' % (type(exc).__name__, exc)
    finally:
        urllib.request.urlopen = orig

    out = {
        'http_status': rec.get('status'),
        'content_type': dict(rec.get('headers') or []).get('Content-Type'),
        'body': body,
        'envelope': None if body is None else json.dumps(body, ensure_ascii=False),
        'raises': raised,
        'transport_called': bool(captured),
        'url': captured.get('url'),
        'timeout': captured.get('timeout'),
    }
    if captured:
        payload = json.loads(captured['body'])
        out['python_body'] = captured['body']
        out['payload'] = payload
        out['wire_body'] = json.dumps(payload, sort_keys=True,
                                      separators=(',', ':'), ensure_ascii=False)
        # 目标语言出现在 user 消息开头（如 "Translate to Japanese:\n\n…"）⇒ 截出可断言的片段
        user = ''
        for m in payload.get('messages', []):
            if m.get('role') == 'user':
                user = m.get('content', '')
        if user.startswith('Translate to '):
            out['wire_contains'] = user.split(':\n\n')[0]
    return out


# ── /ai-assist 的用例（action / text / lang / cfg / 假响应）─────────────────
ASSIST_CASES = [
    {
        'name': 'complete_ok',
        'action': 'complete',
        'text': 'Hello world',
        'cfg': CFG_ON,
        'http': ok_http('  continued words.  '),
        'note': 'complete：真消息构造 → 假 200 → content 取回后 strip ⇒ result "continued words."',
        'source': 'admin/actions.py:307-308 + ai_assistance.py:100-113',
    },
    {
        'name': 'polish_ok',
        'action': 'polish',
        'text': 'rough text',
        'cfg': CFG_ON,
        'http': ok_http('\n\nPolished.\n'),
        'note': 'polish：result 也 strip',
        'source': 'admin/actions.py:309-310 + ai_assistance.py:138-139',
    },
    {
        'name': 'polish_chinese',
        'action': 'polish',
        'text': 'Chinese body',
        'cfg': CFG_ON,
        'http': ok_http('  中文润色  '),
        'note': '出参 JSON 保留原字符（ensure_ascii=False 口径）⇒ 中文字面出现，不写 \\\\uXXXX',
        'source': 'actions.py:325-329（json.dumps 的字节口径）+ ai.wll 刻意语义 ④',
    },
    {
        'name': 'translate_default',
        'action': 'translate',
        'text': 'Hello',
        'cfg': CFG_ON,
        'http': ok_http('  hello  '),
        'note': '不给 lang ⇒ Python 的缺省 "English" ⇒ lang_map 后仍是 English',
        'source': 'admin/actions.py:312-315',
    },
    {
        'name': 'translate_en',
        'action': 'translate',
        'text': 'Hello',
        'lang': 'en',
        'cfg': CFG_ON,
        'http': ok_http(' hello '),
        'note': 'lang=en ⇒ English（硬编码映射）',
        'source': 'admin/actions.py:313-314 + ai_assistance.py:141-166',
    },
    {
        'name': 'translate_ja',
        'action': 'translate',
        'text': 'Hello',
        'lang': 'ja',
        'cfg': CFG_ON,
        'http': ok_http(' こんにちは '),
        'note': 'lang=ja ⇒ Japanese（**只有** ja 是日语，:314）',
        'source': 'admin/actions.py:313-314 + content.py:794-795',
    },
    {
        'name': 'translate_fr',
        'action': 'translate',
        'text': 'Hello',
        'lang': 'fr',
        'cfg': CFG_ON,
        'http': ok_http(' hello '),
        'note': '未知语言码 ⇒ `lang_map.get("fr", "English")` ⇒ English（不是原样透传）',
        'source': 'admin/actions.py:314',
    },
    {
        'name': 'summarize_long',
        'action': 'summarize',
        'text': 'long text',
        'cfg': CFG_ON,
        'http': ok_http('word ' * 40),
        'note': 'summarize：缺省 max_length=160，超长在最后一个空格前截断 + "..."',
        'source': 'admin/actions.py:318-319 + ai_assistance.py:193-196',
    },
    {
        'name': 'summarize_short',
        'action': 'summarize',
        'text': 'long text',
        'cfg': CFG_ON,
        'http': ok_http('  Short.  '),
        'note': '不超上限 ⇒ strip 后原样',
        'source': 'ai_assistance.py:193-196',
    },
    {
        'name': 'tags_json',
        'action': 'suggest_tags',
        'text': 'python web',
        'cfg': CFG_ON,
        'http': ok_http('["python", "web"]'),
        'note': 'suggest_tags：JSON 数组 ⇒ result 是数组（出参里是 ["python", "web"]）',
        'source': 'admin/actions.py:316-317 + ai_assistance.py:226-235',
    },
    {
        'name': 'tags_fallback',
        'action': 'suggest_tags',
        'text': 'python web python tutorial web python',
        'cfg': CFG_ON,
        'http': ok_http('Sure! tags: python, web'),
        'note': '内容不是 JSON ⇒ **词频降级**（不是报错）：python 3 / web 2 / tutorial 1',
        'source': 'ai_assistance.py:236-261',
    },
    {
        'name': 'complete_empty',
        'action': 'complete',
        'text': '',
        'cfg': CFG_ON,
        'http': ok_http('never used'),
        'note': '空文本 ⇒ Python 直接返回 ""，**不发请求**（:100-101）',
        'source': 'ai_assistance.py:100-101',
    },
    {
        'name': 'unknown_action',
        'action': 'frobnicate',
        'text': 'x',
        'cfg': CFG_ON,
        'http': ok_http('never used'),
        'note': '未知 action ⇒ `{"error": "未知操作: frobnicate"}`，**不落默认分支**，也不发请求',
        'source': 'admin/actions.py:320-321',
    },
    {
        'name': 'unconfigured_disabled',
        'action': 'complete',
        'text': 'Hello',
        'cfg': CFG_OFF,
        'http': ok_http('never used'),
        'note': 'ai_enabled 为假 ⇒ 卡面第 ① 条的逐字文案',
        'source': 'admin/actions.py:302-304 + ai_assistance.py:273-274',
    },
    {
        'name': 'unconfigured_no_key',
        'action': 'polish',
        'text': 'Hello',
        'cfg': CFG_NO_KEY,
        'http': ok_http('never used'),
        'note': '启用但没 key ⇒ 同一句文案（:275-276 的第二个前置条件）',
        'source': 'admin/actions.py:302-304 + ai_assistance.py:275-276',
    },
    {
        'name': 'unconfigured_unknown_action',
        'action': 'frobnicate',
        'text': 'x',
        'cfg': CFG_OFF,
        'http': ok_http('never used'),
        'note': '⚠ 顺序守卫：未配置**先于**分派 ⇒ 报「未启用」，不是「未知操作」',
        'source': 'admin/actions.py:302-304（判空在前）vs :320-321（分派在后）',
    },
    {
        'name': 'backend_500',
        'action': 'complete',
        'text': 'Hello',
        'cfg': CFG_ON,
        'http': {'raise': {'status': 500, 'body': '{"error": "boom"}'}},
        'note': '后端 5xx ⇒ Python 抛 AIAssistanceError("API error: 500") ⇒ 200 + JSON 错误',
        'source': 'ai_assistance.py:82-85 + actions.py:322-329',
        'error_text_diverges': True,
    },
    {
        'name': 'backend_empty_choices',
        'action': 'complete',
        'text': 'Hello',
        'cfg': CFG_ON,
        'http': {'status': 200, 'body': '{"id": "x", "choices": []}'},
        'note': 'choices 为空 ⇒ AIAssistanceError("No response from AI") ⇒ JSON 错误',
        'source': 'ai_assistance.py:78-80',
        'error_text_diverges': True,
    },
    {
        'name': 'backend_html',
        'action': 'complete',
        'text': 'Hello',
        'cfg': CFG_ON,
        'http': {'status': 200, 'body': '<html>bad gateway</html>', 'reason': 'OK'},
        'note': '⚠ 非 JSON 响应体：Python 的 JSONDecodeError **不被** ai_assist 捕获 ⇒ WSGI 500；'
                '我们返回 JSON 错误（卡面第 ② 条，登记为刻意语义 ③）',
        'source': 'ai_assistance.py:77（json.loads）+ actions.py:322（只捕 AIAssistanceError）',
        'error_contains': 'not valid JSON',
        'python_500': True,
    },
]

# ── /translate 的用例（走同一张 lang_map；期望值同样由真 Python 现算）────────
ENDPOINT_CASES = [
    {
        'name': 'translate_en_default',
        'lang': None,
        'text': 'Hello',
        'cfg': CFG_ON,
        'http': ok_http(' hello '),
        'note': '/translate 不给 lang ⇒ content.py 的缺省 "en" ⇒ English',
        'source': 'content.py:794-795 + actions.py:334',
    },
    {
        'name': 'translate_ja',
        'lang': 'ja',
        'text': 'Hello',
        'cfg': CFG_ON,
        'http': ok_http(' こんにちは '),
        'note': '/translate lang=ja ⇒ Japanese',
        'source': 'content.py:794-795,805',
    },
    {
        'name': 'translate_fr',
        'lang': 'fr',
        'text': 'Hello',
        'cfg': CFG_ON,
        'http': ok_http(' hello '),
        'note': '未知码 ⇒ English（`lang_map.get(target_lang, "English")`）',
        'source': 'content.py:794-795',
    },
    {
        'name': 'unconfigured',
        'lang': 'en',
        'text': 'Hello',
        'cfg': CFG_OFF,
        'http': ok_http('never used'),
        'note': '/translate 未配置 ⇒ 本模块用卡面 ① 的文案；Python 的文章层另有文案（见 divergences ②）',
        'source': 'content.py:797-802（对比）+ actions.py:304（本模块采用）',
        'ok': False,
    },
    {
        'name': 'backend_500',
        'lang': 'en',
        'text': 'Hello',
        'cfg': CFG_ON,
        'http': {'raise': {'status': 500, 'body': '{"error": "boom"}'}},
        'note': '/translate 的后端错误同样必须是 JSON',
        'source': 'actions.py:322-329',
        'error_text_diverges': True,
    },
]


def article_unconfigured():
    """真跑一次 `content.translate_article()`（AI 未配置）—— 拿到 /translate 的**真实**文案。"""
    with tempfile.TemporaryDirectory() as tmp:
        art = Path(tmp) / 'article'
        art.mkdir()
        write_article(art, '2026-01-01-hello.html', 'T', '2026-01-01 00:00', 's',
                      'hello body', '', '', 'x', 'published', skip_html_generation=True)
        return translate_article(art, '2026-01-01-hello.html', 'en', StubCfg(**CFG_OFF))


def build_assist(case):
    py = run_python(case)
    want = {
        'ok': py['body'] is not None and 'result' in py['body'],
        'transport_called': py['transport_called'],
    }
    if py['body'] is not None:
        want['envelope'] = py['envelope']
        want['has_error'] = 'error' in py['body']
    if 'wire_body' in py:
        want['wire_body'] = py['wire_body']
    if 'wire_contains' in py:
        want['wire_contains'] = py['wire_contains']
    return {
        'name': case['name'],
        'action': case['action'],
        'text': case['text'],
        'lang': case.get('lang'),
        'cfg': case['cfg'],
        'note': case['note'],
        'source': case['source'],
        'raw': http_to_raw(case['http']),
        'python': py,
        'want': want,
        'error_contains': case.get('error_contains'),
        'error_text_diverges': case.get('error_text_diverges', False),
        'python_500': case.get('python_500', False),
    }


def main():
    assist = [build_assist(c) for c in ASSIST_CASES]

    endpoint = []
    for c in ENDPOINT_CASES:
        case = dict(c)
        case['action'] = 'translate'          # 期望值就走 ai_assist 的 translate 分支
        py = run_python(case)
        want = {
            'ok': py['body'] is not None and 'result' in py['body'],
            'transport_called': py['transport_called'],
        }
        if py['body'] is not None:
            want['envelope'] = py['envelope']
            want['has_error'] = 'error' in py['body']
        if 'wire_body' in py:
            want['wire_body'] = py['wire_body']
        if 'wire_contains' in py:
            want['wire_contains'] = py['wire_contains']
        endpoint.append({
            'name': c['name'],
            'text': c['text'],
            'lang': c['lang'],
            'cfg': c['cfg'],
            'note': c['note'],
            'source': c['source'],
            'raw': http_to_raw(c['http']),
            'python': py,
            'want': want,
            'error_text_diverges': c.get('error_text_diverges', False),
        })

    doc = {
        'meta': {
            'card': 'S5-3 AI 端点接线',
            'generated_by': 'tp/test/gen_admin_ai_baseline.py',
            'authority': [
                'tinypage/admin/actions.py:296-329 (ai_assist)',
                'tinypage/content.py:757-842 (translate_article)',
            ],
            'under_test': 'tp/lib/admin_ai.wll',
            'regen': 'python tp/test/gen_admin_ai_baseline.py',
            'no_randomness': '本夹具不含随机值/时间戳/CSRF ⇒ 重生成必须无漂移',
            'divergences': [
                '① /translate 的文章层（定位文件 / summarize(200) / 落盘，content.py:776-840）'
                '不在 admin_ai.wll：TRANSLATE_ENDPOINT 只做 AI 这一跳（收正文文本）',
                '② /translate 未配置时 Python 的文案是 "AI not configured. Set ai_api_key in '
                'config."（content.py:798-802，见 article_unconfigured）；本模块按卡面 ① 统一用 '
                '"AI 未启用或未配置 API Key"',
                '③ 响应体不是 JSON 时 Python 抛 JSONDecodeError（不被 ai_assist 捕获 ⇒ WSGI 500）；'
                '我们返回 JSON 错误',
                '④ 后端 5xx 的错误**文案**不同（Python "API error: 500"，传输层 "HTTP 500 ..."），'
                '形状相同（200 + {"error": …}）⇒ 只钉形状',
                '⑤ ai_enabled 只认布尔 TRUE（Python 认任意真值）—— 继承 ai.wll 刻意语义 ⑥',
                '⑥ 请求体按 std.json::STRINGIFY 口径（紧凑 + 键名字典序），与 Python json.dumps 字节不同'
                '（ai.wll 刻意语义 ⑤）；wire_body 就是按 STRINGIFY 口径复现的',
            ],
            'article_unconfigured': article_unconfigured(),
        },
        'assist': assist,
        'endpoint': endpoint,
        'guards': {
            'unconfigured_message': 'AI 未启用或未配置 API Key',
            'unknown_prefix': '未知操作: ',
        },
    }

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
        f.write('\n')
    print('wrote %s (assist=%d, endpoint=%d)' % (OUT, len(assist), len(endpoint)))


if __name__ == '__main__':
    main()
