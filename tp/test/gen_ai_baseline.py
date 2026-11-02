"""生成 tp/test/fixtures/ai_baseline.json —— 五个 AI 能力的验收基准（卡 S5-2）。

⚠ 输出的 JSON 由本文件生成，不要手改。

**期望值全部由真 Python 现算**（不是手抄）：
本文件用 `importlib` 直接加载 `tinypage/core/ai_assistance.py`（不走 `tinypage` 包，
避免 `tangypage/core/__init__.py` 的连带 import），然后

  · 把 `AIAssistance._call_api` 换成记录器 ⇒ 抓出**真实的** `messages` / `temperature`
    （`complete_text` / `polish_text` / `translate_text` / `summarize` / `suggest_tags`
    各自构造的那两条消息，逐字）；
  · 把 `urllib.request.urlopen` 换成假响应 ⇒ 让**真实的** `_call_api` 跑完
    `json.loads` + `choices[0].message.content` 那一整段（含它的错误消息）；
  · 直接调 `_fallback_suggest_tags` / `build_ai_assistance` / `json.dumps`。

**三个刻意的偏离（登记在 `meta.divergences`，不是沉默放过）**
  ① `choices[0].message.content` **缺字段 / 不是字符串** ⇒ 我们 `ok:FALSE`；
     Python 的 `.get("content", "")` 会**静默**给出 `""`（乃至 `123`、`None`）。
  ② `endpoint` 以 `/` 结尾时，Python 直接拼成 `.../v1//chat/completions`；
     我们先把结尾的 `/` 去掉再拼（服务端可能把 `//` 当另一个路径）。
  ③ 只接受 `https://` 端点：本模块的传输层（S5-1）是 TLS-only，
     `http://` 端点会**明确失败**，而 Python 会真的发明文 HTTP。
     （另：`json.dumps` 默认 `ensure_ascii=True`，中文写 `\\uXXXX`；
      我们的 JSON 出参保留原字符 —— 语义等价、字节不同，同样登记。）

**请求体字节口径**：WLWL 的 `std.json::STRINGIFY` 对容器是「紧凑 + 键名字典序」，
而 Python 的 `json.dumps` 是 `", "` / `": "` + 插入序。本基准用
`json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
**按 STRINGIFY 的口径**复现一份（`pipeline[].want.wire_body`），
同时把 Python 自己那份（`python_body`）也记下来 —— 两者不同是**已登记**的事实。

用法：python gen_ai_baseline.py
"""
import importlib.util
import json
import os
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
SRC = os.path.join(ROOT, 'tinypage', 'core', 'ai_assistance.py')
OUT = os.path.join(HERE, 'fixtures', 'ai_baseline.json')

CRLF = '\r\n'

ORIG_CALL_API = None


def load_module():
    """直接按路径加载 ai_assistance.py（不触发 tinypage 包的其他 import）。"""
    spec = importlib.util.spec_from_file_location('tinypage_ai_under_test', SRC)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


MOD = load_module()


# ── 记录器：替换 _call_api，抓真实构造的消息与温度 ────────────────────────
class CallRecorder:
    def __init__(self):
        self.reply = ''
        self.calls = []

    def install(self):
        rec = self
        self.orig = MOD.AIAssistance._call_api

        def fake_call(self_ai, messages, temperature=0.7):
            rec.calls.append({
                'messages': messages,
                'temperature': temperature,
                'model': self_ai.model,
                'endpoint': self_ai.endpoint,
            })
            return rec.reply

        MOD.AIAssistance._call_api = fake_call


def run_method(rec, method, kwargs, reply):
    """跑一次真实方法，返回 (返回值, 调用记录或 None, 异常消息或 None)。"""
    rec.reply = reply
    rec.calls = []
    ai = MOD.AIAssistance(api_key='sk-test')
    try:
        value = getattr(ai, method)(**kwargs)
        err = None
    except Exception as exc:  # noqa: BLE001 —— 记录真 Python 的行为
        value = None
        err = '%s: %s' % (type(exc).__name__, exc)
    call = rec.calls[0] if rec.calls else None
    return value, call, err


# ── ① 消息构造（BUILD_MESSAGES）────────────────────────────────────────
MSG_CASES = [
    {
        'name': 'complete_basic',
        'capability': 'complete',
        'method': 'complete_text',
        'kwargs': {'text': 'Hello world'},
        'reply': ' continued text ',
        'note': 'complete：system 一条 + user 一条，温度 0.8',
        'source': 'ai_assistance.py:103-112（complete_text）',
    },
    {
        'name': 'complete_hint',
        'capability': 'complete',
        'method': 'complete_text',
        'kwargs': {'text': 'Hello', 'prompt_hint': 'tone: friendly'},
        'reply': 'x',
        'note': 'complete + prompt_hint ⇒ system 末尾**追加** ` The user wants to focus on: …`',
        'source': 'ai_assistance.py:104-105',
    },
    {
        'name': 'complete_empty',
        'capability': 'complete',
        'method': 'complete_text',
        'kwargs': {'text': ''},
        'reply': 'never used',
        'note': '空文本 ⇒ Python 直接返回 ""，**不构建消息、不发请求**（skip）',
        'source': 'ai_assistance.py:100-101',
    },
    {
        'name': 'complete_spaces_only',
        'capability': 'complete',
        'method': 'complete_text',
        'kwargs': {'text': '   '},
        'reply': 'x',
        'note': '只有空格**不是**空文本（Python 的 `if not text` 只判真空串）⇒ 仍要发请求',
        'source': 'ai_assistance.py:100（`if not text` 的空值判定）',
    },
    {
        'name': 'polish_basic',
        'capability': 'polish',
        'method': 'polish_text',
        'kwargs': {'text': '  some rough text  '},
        'reply': 'x',
        'note': 'polish：温度 0.5；text **原样**进入 user 消息（不 strip）',
        'source': 'ai_assistance.py:127-138',
    },
    {
        'name': 'translate_default',
        'capability': 'translate',
        'method': 'translate_text',
        'kwargs': {'text': '你好'},
        'reply': 'x',
        'note': 'translate 不给 target_lang ⇒ Python 默认 "English"',
        'source': 'ai_assistance.py:141（签名默认值 "English"）',
    },
    {
        'name': 'translate_ja',
        'capability': 'translate',
        'method': 'translate_text',
        'kwargs': {'text': '你好', 'target_lang': 'Japanese'},
        'reply': 'x',
        'note': 'translate → Japanese（lang 码 "ja" 经 lang_map 得到的就是这个名字）',
        'source': 'ai_assistance.py:154-163 + admin/actions.py:313-315（lang_map）',
        'opts_extra': {'lang': 'ja'},
    },
    {
        'name': 'translate_en_code',
        'capability': 'translate',
        'method': 'translate_text',
        'kwargs': {'text': '你好', 'target_lang': 'English'},
        'reply': 'x',
        'note': 'lang 码 "en" ⇒ English（硬编码映射，不认其它码）',
        'source': 'admin/actions.py:313-314（{"en": "English", "ja": "Japanese"}）',
        'opts_extra': {'lang': 'en'},
    },
    {
        'name': 'translate_unknown_code',
        'capability': 'translate',
        'method': 'translate_text',
        'kwargs': {'text': '你好', 'target_lang': 'English'},
        'reply': 'x',
        'note': '未知 lang 码 ⇒ 回落 English（`lang_map.get(lang, "English")`）',
        'source': 'admin/actions.py:314（get 的缺省 "English"）',
        'opts_extra': {'lang': 'fr'},
    },
    {
        'name': 'summarize_default',
        'capability': 'summarize',
        'method': 'summarize',
        'kwargs': {'text': 'long text'},
        'reply': 'x',
        'note': 'summarize：温度 0.3；max_length 缺省 160 写进 system',
        'source': 'ai_assistance.py:168-192',
    },
    {
        'name': 'summarize_200',
        'capability': 'summarize',
        'method': 'summarize',
        'kwargs': {'text': 'long text', 'max_length': 200},
        'reply': 'x',
        'note': 'max_length=200（content.py:806 的调用就是这么传的）',
        'source': 'content.py:806（`ai.summarize(translated_content, 200)`）',
    },
    {
        'name': 'tags_default',
        'capability': 'suggest_tags',
        'method': 'suggest_tags',
        'kwargs': {'text': 'short text'},
        'reply': '["a", "b"]',
        'note': 'suggest_tags：温度 0.3；max_tags 缺省 5 写进 system',
        'source': 'ai_assistance.py:213-225',
    },
    {
        'name': 'tags_max3',
        'capability': 'suggest_tags',
        'method': 'suggest_tags',
        'kwargs': {'text': 'short text', 'max_tags': 3},
        'reply': '["a", "b", "c", "d"]',
        'note': 'max_tags=3 ⇒ system 里是 "exactly 3"',
        'source': 'ai_assistance.py:216',
    },
    {
        'name': 'tags_long_text',
        'capability': 'suggest_tags',
        'method': 'suggest_tags',
        'kwargs': {'text': 'a' + 'b' * 2499},
        'reply': '["a"]',
        'note': 'user 消息里的正文被截到**前 2000 码点**（`text[:2000]`）',
        'source': 'ai_assistance.py:220（`text[:2000]`）',
    },
    {
        'name': 'tags_empty',
        'capability': 'suggest_tags',
        'method': 'suggest_tags',
        'kwargs': {'text': ''},
        'reply': 'never used',
        'note': '空文本 ⇒ Python 返回 []，不构建消息',
        'source': 'ai_assistance.py:210-211',
    },
]

# ── ② 后处理（FINISH）：strip / 截断 / 标签解析 ──────────────────────────
FINISH_CASES = [
    {
        'name': 'complete_strip',
        'capability': 'complete',
        'reply': '  Text with spaces. \n',
        'note': 'complete 的返回值过 `.strip()`',
        'source': 'ai_assistance.py:113（`result.strip()`）',
    },
    {
        'name': 'complete_ideographic_space',
        'capability': 'complete',
        'reply': '\u3000全角空白\u3000',
        'note': 'Python 的 strip 去掉 U+3000；内建 TRIM **只去 ASCII 空白** ⇒ 必须用 PY_WS 集合',
        'source': 'ai_assistance.py:113 + tp/README 坑 41',
    },
    {
        'name': 'complete_nbsp',
        'capability': 'complete',
        'reply': '\u00a0nbsp text\u00a0',
        'note': 'NBSP（U+00A0）同样要剥',
        'source': 'ai_assistance.py:113 + Python str.isspace()',
    },
    {
        'name': 'polish_strip',
        'capability': 'polish',
        'reply': '\n\nPolished.\n',
        'note': 'polish 也 strip',
        'source': 'ai_assistance.py:139',
    },
    {
        'name': 'translate_strip',
        'capability': 'translate',
        'reply': ' 翻訳 ',
        'note': 'translate 也 strip',
        'source': 'ai_assistance.py:166',
    },
    {
        'name': 'summarize_short',
        'capability': 'summarize',
        'max_length': 160,
        'reply': 'Short.',
        'note': '不超过上限 ⇒ 原样',
        'source': 'ai_assistance.py:195-196',
    },
    {
        'name': 'summarize_exact_160',
        'capability': 'summarize',
        'max_length': 160,
        'reply': 'z' * 160,
        'note': '**恰好** 160 ⇒ 不截断（判定是 `>`，不是 `>=`）',
        'source': 'ai_assistance.py:195',
    },
    {
        'name': 'summarize_over_spaces',
        'capability': 'summarize',
        'max_length': 160,
        'reply': 'word ' * 40,
        'note': '超长且有空格 ⇒ 前 160 码点里**最后一个空格**之前 + "..."（`rsplit(" ", 1)[0]`）',
        'source': 'ai_assistance.py:196',
    },
    {
        'name': 'summarize_over_nospace',
        'capability': 'summarize',
        'max_length': 160,
        'reply': 'y' * 300,
        'note': '超长且**没有**空格 ⇒ 前 160 码点原样 + "..."',
        'source': 'ai_assistance.py:196（rsplit 无空格时只剩整段）',
    },
    {
        'name': 'summarize_cjk',
        'capability': 'summarize',
        'max_length': 160,
        'reply': '中' * 200,
        'note': '中文没有空格 ⇒ 按**码点**截到 160（不是字节）',
        'source': 'ai_assistance.py:195-196',
    },
    {
        'name': 'summarize_max200',
        'capability': 'summarize',
        'max_length': 200,
        'reply': 'q' * 180,
        'note': '180 < 200 ⇒ 不截断（max_length 是参数，不是常量 160）',
        'source': 'ai_assistance.py:168,195',
    },
    {
        'name': 'tags_fenced_json',
        'capability': 'suggest_tags',
        'max_tags': 5,
        'reply': '```json\n["python", "web"]\n```',
        'note': '带 json 语言标记的围栏要剥掉再解析',
        'source': 'ai_assistance.py:228-231',
    },
]

TAGS_CASES = [
    {
        'name': 'plain_array',
        'max_tags': 5,
        'reply': '["python", "web"]',
        'note': '纯 JSON 数组',
        'source': 'ai_assistance.py:232-234',
    },
    {
        'name': 'fenced_json',
        'max_tags': 5,
        'reply': '```json\n["python", "web"]\n```',
        'note': '```json 围栏',
        'source': 'ai_assistance.py:228-230',
    },
    {
        'name': 'fenced_plain',
        'max_tags': 5,
        'reply': '```\n["python"]\n```',
        'note': '``` 无语言标记',
        'source': 'ai_assistance.py:229（`(?:json)?` 可选）',
    },
    {
        'name': 'fenced_upper_json',
        'max_tags': 5,
        'reply': '```JSON\n["python"]\n```',
        'note': '```JSON 大写**不**被 `(?:json)?` 吃掉 ⇒ 解析失败 ⇒ 走词频降级',
        'source': 'ai_assistance.py:229（正则区分大小写）',
    },
    {
        'name': 'fenced_spaces',
        'max_tags': 5,
        'reply': '  ```json\n  ["a", "b"]  \n```  ',
        'note': '先 strip，再剥围栏与围栏后的空白',
        'source': 'ai_assistance.py:226-230',
    },
    {
        'name': 'with_numbers',
        'max_tags': 5,
        'reply': '["a", 1]',
        'note': '数组里有非字符串 ⇒ Python 返回 **[]**（**不**降级）',
        'source': 'ai_assistance.py:233-235',
    },
    {
        'name': 'object_root',
        'max_tags': 5,
        'reply': '{"tags": ["a"]}',
        'note': '根不是数组 ⇒ []',
        'source': 'ai_assistance.py:233-235',
    },
    {
        'name': 'string_root',
        'max_tags': 5,
        'reply': '"just text"',
        'note': '根是字符串 ⇒ []',
        'source': 'ai_assistance.py:233-235',
    },
    {
        'name': 'empty_array',
        'max_tags': 5,
        'reply': '[]',
        'note': '空数组 ⇒ [] 且**形状合法**（与「解析失败」要能分开）',
        'source': 'ai_assistance.py:233-234',
    },
    {
        'name': 'not_json',
        'max_tags': 5,
        'reply': 'Sure! Here are tags: python, web',
        'note': '不是 JSON ⇒ JSONDecodeError ⇒ 走词频降级',
        'source': 'ai_assistance.py:236-238',
    },
    {
        'name': 'too_many',
        'max_tags': 3,
        'reply': '["a", "b", "c", "d", "e"]',
        'note': '超过 max_tags ⇒ 只取前 N 个',
        'source': 'ai_assistance.py:234（`tags[:max_tags]`）',
    },
    {
        'name': 'nested_array',
        'max_tags': 5,
        'reply': '[["a"], "b"]',
        'note': '元素是数组 ⇒ 形状非法 ⇒ []',
        'source': 'ai_assistance.py:233',
    },
]

# ── ③ 响应取内容（EXTRACT_CONTENT）──────────────────────────────────────
EXTRACT_CASES = [
    {
        'name': 'normal',
        'body': '{"choices": [{"message": {"role": "assistant", "content": "Hello there"}}]}',
        'status': 200,
        'note': '正常：取 choices[0].message.content',
        'source': 'ai_assistance.py:77-81',
    },
    {
        'name': 'unicode_content',
        'body': '{"choices": [{"message": {"content": "中文内容"}}]}',
        'status': 200,
        'note': '中文内容原样取回（转义 \\u4e2d 由 JSON 解析处理）',
        'source': 'ai_assistance.py:77-81',
    },
    {
        'name': 'escaped_newline',
        'body': '{"choices": [{"message": {"content": "line1\\nline2"}}]}',
        'status': 200,
        'note': '内容里的转义换行要还原成真换行',
        'source': 'ai_assistance.py:77-81',
    },
    {
        'name': 'empty_content',
        'body': '{"choices": [{"message": {"content": ""}}]}',
        'status': 200,
        'note': '空串 content 是**合法**结果（不是缺字段）',
        'source': 'ai_assistance.py:81',
    },
    {
        'name': 'extra_fields',
        'body': '{"id": "x", "choices": [{"index": 0, "message": {"content": "ok"}, "finish_reason": "stop"}]}',
        'status': 200,
        'note': '多余字段不影响',
        'source': 'ai_assistance.py:78-81',
    },
    {
        'name': 'empty_choices',
        'body': '{"choices": []}',
        'status': 200,
        'note': 'choices 空 ⇒ Python 抛 "No response from AI"；我们 ok:FALSE',
        'source': 'ai_assistance.py:78-80',
        'want': {'ok': False, 'error_contains': 'No response'},
    },
    {
        'name': 'no_choices',
        'body': '{"id": "x"}',
        'status': 200,
        'note': '没有 choices 键 ⇒ 同「空」',
        'source': 'ai_assistance.py:78-80',
        'want': {'ok': False, 'error_contains': 'No response'},
    },
    {
        'name': 'choices_not_array',
        'body': '{"choices": {"message": {"content": "x"}}}',
        'status': 200,
        'note': 'choices 不是数组 ⇒ 我们 ok:FALSE；Python 会 `choices[0]` 崩成 KeyError/TypeError',
        'source': 'ai_assistance.py:78-81',
        'diverges': True,
        'want': {'ok': False, 'error_contains': 'choices'},
    },
    {
        'name': 'no_message',
        'body': '{"choices": [{"index": 0}]}',
        'status': 200,
        'note': '缺 message ⇒ Python **静默返回 ""**（`.get("message", {}).get("content", "")`）；我们 ok:FALSE',
        'source': 'ai_assistance.py:81',
        'diverges': True,
        'want': {'ok': False, 'error_contains': 'message is missing'},
    },
    {
        'name': 'content_number',
        'body': '{"choices": [{"message": {"content": 123}}]}',
        'status': 200,
        'note': 'content 不是字符串 ⇒ Python 返回 int 123（后续 .strip() 会崩）；我们 ok:FALSE',
        'source': 'ai_assistance.py:81',
        'diverges': True,
        'want': {'ok': False, 'error_contains': 'content is missing'},
    },
    {
        'name': 'content_null',
        'body': '{"choices": [{"message": {"content": null}}]}',
        'status': 200,
        'note': 'content 是 null ⇒ Python 返回 None；我们 ok:FALSE',
        'source': 'ai_assistance.py:81',
        'diverges': True,
        'want': {'ok': False, 'error_contains': 'content is missing'},
    },
    {
        'name': 'not_json',
        'body': '<html>502 Bad Gateway</html>',
        'status': 502,
        'note': '不是 JSON ⇒ ok:FALSE（先 JSON_VALIDATE，别让 PARSE 以 E0070 中止）',
        'source': 'ai_assistance.py:77（json.loads 抛 JSONDecodeError）',
        'want': {'ok': False, 'error_contains': 'not valid JSON'},
    },
    {
        'name': 'json_array_root',
        'body': '["choices"]',
        'status': 200,
        'note': '根是数组 ⇒ ok:FALSE',
        'source': 'ai_assistance.py:78（`result.get` 会 AttributeError）',
        'want': {'ok': False, 'error_contains': 'not an object'},
    },
    {
        'name': 'status_echo',
        'body': '{"choices": [{"message": {"content": "ok"}}]}',
        'status': 201,
        'note': 'status 原样回带（不参与判定）',
        'source': '卡 S5-1 的形状：{ok, status, content}',
    },
]

# ── ④ 词频降级（FALLBACK_SUGGEST_TAGS）─────────────────────────────────
FALLBACK_CASES = [
    {
        'name': 'english_repeat',
        'text': 'python python web python web tutorial',
        'max_tags': 5,
        'note': '按词频降序；同频按**首次出现**顺序（sorted 是稳定排序）',
        'source': 'ai_assistance.py:252-259',
    },
    {
        'name': 'cjk_repeat',
        'text': '中文 文章 中文 文章 测试',
        'max_tags': 5,
        'note': '两字词**全被丢**：切词要求 {2,}，但计数前还有 `len(word) > 2` ⇒ 中文两字词取不到',
        'source': 'ai_assistance.py:252,255（两个门槛叠加）',
    },
    {
        'name': 'cjk_run_no_space',
        'text': '中文文章测试',
        'max_tags': 5,
        'note': '**没有空格**的中文是一个整串（Python 的 `{2,}` 是贪心连续匹配），不是分词',
        'source': 'ai_assistance.py:252',
    },
    {
        'name': 'stopwords_only',
        'text': 'the and of to in is are be been',
        'max_tags': 5,
        'note': '全是停用词 ⇒ []',
        'source': 'ai_assistance.py:245-250（停用词表）',
    },
    {
        'name': 'short_words',
        'text': 'ab cd ef gh',
        'max_tags': 5,
        'note': '切词要求 {2,}，但**计数前**还要求 `len(word) > 2` ⇒ 两字符的词全被丢',
        'source': 'ai_assistance.py:255（`len(word) > 2`）',
    },
    {
        'name': 'ties',
        'text': 'alpha beta gamma delta',
        'max_tags': 2,
        'note': '同频 ⇒ 取**先出现**的两个（稳定排序）',
        'source': 'ai_assistance.py:258-259',
    },
    {
        'name': 'punctuation',
        'text': 'test-tag foo_bar hey! end.',
        'max_tags': 5,
        'note': '`-` `_` `!` `.` 都不是词内字符 ⇒ 各切成两段',
        'source': 'ai_assistance.py:252',
    },
    {
        'name': 'numbers',
        'text': 'abc123 def456 7 89',
        'max_tags': 5,
        'note': '数字不是词内字符 ⇒ "abc"/"def" 留下，纯数字段**不匹配**',
        'source': 'ai_assistance.py:252',
    },
    {
        'name': 'mixed_script_run',
        'text': 'abc中文 def',
        'max_tags': 5,
        'note': '中英混排**在同一个字符类里** ⇒ "abc中文" 是**一个**词（与「先按脚本切」不同）',
        'source': 'ai_assistance.py:252',
    },
    {
        'name': 'uppercase_fold',
        'text': 'Python PYTHON python',
        'max_tags': 5,
        'note': '先 `.lower()` 再切词 ⇒ 三次都落到 python',
        'source': 'ai_assistance.py:252（`text.lower()`）',
    },
    {
        'name': 'max_tags_zero',
        'text': 'python python web',
        'max_tags': 0,
        'note': 'max_tags=0 ⇒ []',
        'source': 'ai_assistance.py:259（`[:0]`）',
    },
    {
        'name': 'max_tags_one',
        'text': 'python web web',
        'max_tags': 1,
        'note': '只取最高频的一个',
        'source': 'ai_assistance.py:259',
    },
    {
        'name': 'empty_text',
        'text': '',
        'max_tags': 5,
        'note': '空文本 ⇒ []',
        'source': 'ai_assistance.py:242-243',
    },
    {
        'name': 'ordering_by_count',
        'text': 'ccc bbb aaa ccc bbb ccc',
        'max_tags': 3,
        'note': 'ccc=3 在前，bbb=2 次之，aaa=1 最后（不是字典序）',
        'source': 'ai_assistance.py:258',
    },
]

# ── ⑤ 是否构建（IS_ENABLED）+ 端点拆分（ENDPOINT_PARTS）────────────────
ENABLED_CASES = [
    {'name': 'both_set', 'cfg': {'ai_enabled': True, 'ai_api_key': 'sk-x'},
     'note': '两项都满足 ⇒ 构建', 'source': 'ai_assistance.py:273-283'},
    {'name': 'no_key', 'cfg': {'ai_enabled': True, 'ai_api_key': ''},
     'note': 'enabled 但没 key ⇒ 不构建', 'source': 'ai_assistance.py:275-276'},
    {'name': 'disabled', 'cfg': {'ai_enabled': False, 'ai_api_key': 'sk-x'},
     'note': '有 key 但没启用 ⇒ 不构建', 'source': 'ai_assistance.py:273-274'},
    {'name': 'nothing_set', 'cfg': {},
     'note': '都没设 ⇒ 不构建（getattr 缺省 FALSE / ""）', 'source': 'ai_assistance.py:273-276'},
]

ENDPOINT_CASES = [
    {'name': 'openai_default', 'provider': 'openai', 'endpoint': '',
     'note': '缺省 provider ⇒ OpenAI 端点', 'source': 'ai_assistance.py:45-48'},
    {'name': 'deepseek_default', 'provider': 'deepseek', 'endpoint': '',
     'note': 'provider=deepseek ⇒ api.deepseek.com/v1', 'source': 'ai_assistance.py:46-47'},
    {'name': 'provider_case', 'provider': 'DeepSeek', 'endpoint': '',
     'note': 'provider 先 `.lower()`（大小写不敏感）', 'source': 'ai_assistance.py:42'},
    {'name': 'explicit', 'provider': 'openai', 'endpoint': 'https://example.com/custom/v1',
     'note': '显式端点 ⇒ host/path 从它拆', 'source': 'ai_assistance.py:43,60'},
    {'name': 'explicit_port', 'provider': 'openai', 'endpoint': 'https://example.com:8443/v1',
     'note': '端点带端口 ⇒ Host/port 都要带', 'source': 'ai_assistance.py:60 + urllib 的 URL 拆分'},
    {'name': 'trailing_slash', 'provider': 'openai', 'endpoint': 'https://example.com/v1/',
     'note': '端点以 / 结尾：Python 拼出 `//chat/completions`；我们先剥尾斜杠（**已登记偏离**）',
     'source': 'ai_assistance.py:60（f"{endpoint}/chat/completions"）'},
    {'name': 'no_path', 'provider': 'openai', 'endpoint': 'https://example.com',
     'note': '端点没有路径 ⇒ 补一个斜杠再拼（Python 同样只有一个 /）',
     'source': 'ai_assistance.py:60'},
    {'name': 'http_scheme', 'provider': 'openai', 'endpoint': 'http://example.com/v1',
     'note': '明文 http：Python 会发明文请求；我们**明确失败**（传输层是 TLS-only，**已登记偏离**）',
     'source': 'ai_assistance.py:60 + 卡 S5-1（传输层只做 HTTPS）'},
    {'name': 'no_scheme', 'provider': 'openai', 'endpoint': 'example.com/v1',
     'note': '没有 scheme：urllib 抛 `unknown url type`；我们明确失败',
     'source': 'urllib.request.Request 的 URL 校验'},
]

# ── ⑥ 出错也要是 JSON（JSON_ENVELOPE）───────────────────────────────────
ENVELOPE_CASES = [
    {'name': 'error_ascii', 'ok': False, 'error': 'API key not configured',
     'note': '`json.dumps({"error": …})` —— admin 侧 200 + application/json',
     'source': 'admin/actions.py:322-329'},
    {'name': 'error_unknown_action', 'ok': False, 'error': '未知操作: frobnicate',
     'note': '中文错误消息：Python 写 \\uXXXX（ensure_ascii=True），我们保留原字符（**已登记偏离**）',
     'source': 'admin/actions.py:304,321'},
    {'name': 'result_ascii', 'ok': True, 'content': 'Polished text.',
     'note': '`{"result": ...}`',
     'source': 'admin/actions.py:308,329'},
    {'name': 'result_quotes', 'ok': True, 'content': 'He said "hi"\\nbye',
     'note': '引号 / 反斜杠 / 换行的转义要与 json.dumps 逐字节一致',
     'source': 'admin/actions.py:329（json.dumps）'},
    {'name': 'result_tags', 'ok': True, 'tags': ['python', 'web', 'tutorial'],
     'note': '标签是数组 ⇒ `{"result": ["a", "b"]}`（`", "` 分隔）',
     'source': 'admin/actions.py:317,329'},
    {'name': 'result_empty_tags', 'ok': True, 'tags': [],
     'note': '空数组 ⇒ `{"result": []}`',
     'source': 'admin/actions.py:317,329'},
]

# ── ⑦ 端到端（注入假传输；仍然是脱网）─────────────────────────────────
PIPELINE_CASES = [
    {
        'name': 'complete_ok',
        'capability': 'complete',
        'opts': {'ai_enabled': True, 'ai_api_key': 'sk-test', 'text': 'Hello'},
        'reply_content': '  continued words.  ',
        'status': 200,
        'note': '整条链：建消息 → 建请求 → （假传输）→ 解析 → 取 content → strip',
        'source': 'ai_assistance.py:100-113 + 卡 S5-1 的 exchange 测试缝',
    },
    {
        'name': 'polish_ok',
        'capability': 'polish',
        'opts': {'ai_enabled': True, 'ai_api_key': 'sk-test', 'text': 'rough  text'},
        'reply_content': 'Polished text.',
        'status': 200,
        'note': 'polish 全链路（温度 0.5 进请求体）',
        'source': 'ai_assistance.py:115-139',
    },
    {
        'name': 'summarize_ok',
        'capability': 'summarize',
        'opts': {'ai_enabled': True, 'ai_api_key': 'sk-test', 'text': 'long text', 'max_length': 20},
        'reply_content': 'This is a very long summary that should be cut down.',
        'status': 200,
        'note': 'summarize 全链路：max_length 既进 system 也做截断',
        'source': 'ai_assistance.py:168-198',
    },
    {
        'name': 'translate_ja_ok',
        'capability': 'translate',
        'opts': {'ai_enabled': True, 'ai_api_key': 'sk-test', 'text': '你好', 'lang': 'ja'},
        'reply_content': 'こんにちは',
        'status': 200,
        'note': 'lang=ja ⇒ 消息里是 Japanese，内容原样（strip 后）',
        'source': 'ai_assistance.py:141-166 + admin/actions.py:313-314',
    },
    {
        'name': 'complete_http_401',
        'capability': 'complete',
        'opts': {'ai_enabled': True, 'ai_api_key': 'sk-bad', 'text': 'Hello'},
        'reply_content': '{"error": {"message": "Incorrect API key provided"}}',
        'status': 401,
        'note': '4xx ⇒ ok:FALSE（**不得**当正常结果）；错误里头要能看见 401',
        'source': '卡 S5-1 反向守卫 + 卡 S5-2「错误必须是 JSON」',
    },
    {
        'name': 'no_api_key',
        'capability': 'complete',
        'opts': {'ai_enabled': True, 'text': 'Hello'},
        'reply_content': 'never sent',
        'status': 200,
        'note': '没有 key ⇒ 明确失败，且**根本不碰传输**',
        'source': 'ai_assistance.py:57-58 + 卡 S5-1 反向守卫',
    },
    {
        'name': 'disabled',
        'capability': 'complete',
        'opts': {'ai_enabled': False, 'ai_api_key': 'sk-test', 'text': 'Hello'},
        'reply_content': 'never sent',
        'status': 200,
        'note': '未启用 ⇒ 不构建 AI（错误，而不是静默空串）',
        'source': 'ai_assistance.py:273-276 + admin/actions.py:302-304',
    },
    {
        'name': 'tags_ok',
        'capability': 'suggest_tags',
        'opts': {'ai_enabled': True, 'ai_api_key': 'sk-test', 'text': 'python web python'},
        # ⚠ 标签必须与**降级结果**不同（降级对这段文本给 ["python", "web"]），
        #   否则「永远降级」的实现也能过这一条（2026-11-02 实测假阳性）。
        'reply_content': '["python", "tutorial"]',
        'status': 200,
        'note': '标签全链路：解析成功 ⇒ fallback=FALSE',
        'source': 'ai_assistance.py:200-238',
    },
    {
        'name': 'tags_shape_bad',
        'capability': 'suggest_tags',
        'opts': {'ai_enabled': True, 'ai_api_key': 'sk-test', 'text': 'python web python'},
        'reply_content': '["python", 1]',
        'status': 200,
        'note': '形状非法 ⇒ **[]**（Python 此时**不**降级）',
        'source': 'ai_assistance.py:233-235',
    },
    {
        'name': 'tags_not_json',
        'capability': 'suggest_tags',
        'opts': {'ai_enabled': True, 'ai_api_key': 'sk-test', 'text': 'python web python'},
        'reply_content': 'Here you go: python, web',
        'status': 200,
        'note': '不是 JSON ⇒ 词频降级（与形状非法要分开）',
        'source': 'ai_assistance.py:236-238',
    },
    {
        'name': 'tags_http_500',
        'capability': 'suggest_tags',
        'opts': {'ai_enabled': True, 'ai_api_key': 'sk-test', 'text': 'python web python'},
        'reply_content': '{"error": "server exploded"}',
        'status': 500,
        'note': '后端错误 ⇒ 降级词频（AIAssistanceError 分支）',
        'source': 'ai_assistance.py:236-238（`except (JSONDecodeError, AIAssistanceError)`）',
    },
    {
        'name': 'complete_empty_text',
        'capability': 'complete',
        'opts': {'ai_enabled': True, 'ai_api_key': 'sk-test', 'text': ''},
        'reply_content': 'never sent',
        'status': 200,
        'note': '空文本 ⇒ ""，且**不发请求**（transport_called=FALSE）',
        'source': 'ai_assistance.py:100-101',
    },
]


# ── 工具 ────────────────────────────────────────────────────────────────
def raw_response(status, body):
    """(状态码, body) → 原始 HTTP 响应报文（Content-Length 按 UTF-8 字节）。"""
    reason = {200: 'OK', 201: 'Created', 401: 'Unauthorized', 500: 'Internal Server Error',
              502: 'Bad Gateway'}.get(status, 'X')
    head = ('HTTP/1.1 %d %s' % (status, reason) + CRLF
            + 'Content-Type: application/json' + CRLF
            + 'Content-Length: %d' % len(body.encode('utf-8')) + CRLF
            + CRLF)
    return head + body


def chat_body(content):
    return json.dumps({'choices': [{'message': {'role': 'assistant', 'content': content}}]},
                      ensure_ascii=False)


def stringify_like(obj):
    """按 WLWL `STRINGIFY` 的口径（紧凑 + 键名字典序 + 不转义非 ASCII）复现。"""
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def fake_cfg(**kw):
    class Cfg:
        pass
    c = Cfg()
    for k, v in kw.items():
        setattr(c, k, v)
    return c


class FakeResp:
    def __init__(self, body):
        self._raw = body.encode('utf-8')

    def read(self):
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _FellBack(Exception):
    """哨兵：把 suggest_tags 的「降级」变成可判信号。"""


def probe_fell_back(reply, text, max_tags):
    """模型给出 reply 时，Python 的 suggest_tags 到底有没有走词频降级？

    ⚠ 不能用「结果 == 降级结果」判：模型恰好给出与降级相同的标签时两者相等
      （2026-11-02 实测：tags_ok 因此假阳性）。
    """
    ai = MOD.AIAssistance(api_key='k')
    ai._call_api = lambda messages, temperature=0.3, _r=reply: _r
    ai._fallback_suggest_tags = lambda t, m=5: (_ for _ in ()).throw(_FellBack())
    try:
        ai.suggest_tags(text, max_tags)
        return False
    except _FellBack:
        return True


def main():
    # 基准里有**故意**让 json.loads 失败的用例（tags_not_json 等）⇒ Python 的
    # logger.warning 会往 stderr 刷噪音。关掉，日志不是本基准的产物。
    import logging
    logging.disable(logging.CRITICAL)

    rec = CallRecorder()
    rec.install()
    global ORIG_CALL_API
    ORIG_CALL_API = rec.orig

    # ① messages
    messages = []
    for case in MSG_CASES:
        value, call, err = run_method(rec, case['method'], case['kwargs'], case['reply'])
        if err:
            raise SystemExit('unexpected error in %s: %s' % (case['name'], err))
        want = {
            'ok': True,
            'capability': case['capability'],
            'model': call['model'] if call else 'gpt-3.5-turbo',
            'temperature': call['temperature'] if call else None,
            'skip': call is None,
            'messages': call['messages'] if call else [],
        }
        entry = {
            'name': case['name'],
            'note': case['note'],
            'source': case['source'],
            'opts': dict({'capability': case['capability']}, **case['kwargs'],
                         **case.get('opts_extra', {})),
            'want': want,
            'python_result': value,
            'python_endpoint': call['endpoint'] if call else MOD.AIAssistance(api_key='k').endpoint,
        }
        # want.opts 的键名要与 Python 具名参数同名 ⇒ text/prompt_hint/target_lang/…
        messages.append(entry)

    # ② finish（strip / 截断 / 标签解析）
    finish = []
    for case in FINISH_CASES:
        if case['capability'] == 'suggest_tags':
            continue  # 标签解析在 TAGS_CASES 里统一处理
        kwargs = {'text': 'x'}
        if case['capability'] == 'summarize':
            kwargs['max_length'] = case['max_length']
        value, call, err = run_method(rec, {
            'complete': 'complete_text',
            'polish': 'polish_text',
            'translate': 'translate_text',
            'summarize': 'summarize',
        }[case['capability']], kwargs, case['reply'])
        if err:
            raise SystemExit('unexpected error in finish/%s: %s' % (case['name'], err))
        want = {'ok': True, 'content': value}
        entry = {
            'name': case['name'],
            'note': case['note'],
            'source': case['source'],
            'capability': case['capability'],
            'content': case['reply'],
            'want': want,
        }
        if case['capability'] == 'summarize':
            entry['max_length'] = case['max_length']
        finish.append(entry)

    # ②b 标签解析：真 suggest_tags + 「降级哨兵」+ 逐行转写（交叉校验）
    import re as _re

    def transcribe_parse(result, max_tags):
        """把 ai_assistance.py:226-235 那一段**逐行转写**（步数/顺序一致）。

        返回 (decode_ok, shape_ok, tags)；decode_ok=False ⇔ 源码走降级分支。
        这个转写的可信度由下面的「真 Python 交叉校验」保证 —— 不一致就中止。
        """
        result = result.strip()
        if result.startswith('```'):
            result = _re.sub(r'^```(?:json)?\s*', '', result)
            result = _re.sub(r'\s*```$', '', result)
        try:
            tags = json.loads(result)
        except json.JSONDecodeError:
            return (False, False, None)
        if isinstance(tags, list) and all(isinstance(t, str) for t in tags):
            return (True, True, tags[:max_tags])
        return (True, False, [])

    tags_finish = []
    for case in TAGS_CASES:
        real = MOD.AIAssistance(api_key='k')
        real._call_api = lambda messages, temperature=0.3, _r=case['reply']: _r
        final_tags = real.suggest_tags('python web python', case['max_tags'])
        fallback_tags = real._fallback_suggest_tags('python web python', case['max_tags'])

        # 用哨兵把「降级」变成可判信号 ⇒ 区分「解析失败」与「形状非法但解析成功」
        probe = MOD.AIAssistance(api_key='k')
        probe._call_api = lambda messages, temperature=0.3, _r=case['reply']: _r

        class Sentinel(Exception):
            pass

        def boom(text, max_tags=5):
            raise Sentinel()

        probe._fallback_suggest_tags = boom
        try:
            probe.suggest_tags('python web python', case['max_tags'])
            fell_back = False
        except Sentinel:
            fell_back = True

        decode_ok, shape_ok, tags = transcribe_parse(case['reply'], case['max_tags'])
        # 交叉校验：转写的结论必须与**真 Python 的可观察行为**一致
        if decode_ok == fell_back:
            raise SystemExit('tags decode cross-check mismatch on %s: transcribed=%r fell_back=%r'
                             % (case['name'], decode_ok, fell_back))
        if decode_ok and final_tags != tags:
            raise SystemExit('tags value cross-check mismatch on %s: real=%r transcribed=%r'
                             % (case['name'], final_tags, tags))
        if not decode_ok and final_tags != fallback_tags:
            raise SystemExit('tags fallback cross-check mismatch on %s: real=%r fallback=%r'
                             % (case['name'], final_tags, fallback_tags))

        tags_finish.append({
            'name': 'tags_' + case['name'],
            'note': case['note'],
            'source': case['source'],
            'capability': 'suggest_tags',
            'content': case['reply'],
            'max_tags': case['max_tags'],
            'want': {
                'ok': decode_ok,
                'valid_shape': shape_ok,
                'tags': tags,
            },
            'python_final_tags': final_tags,
            'python_fallback_tags': fallback_tags,
        })

    # ③ extract：真 _call_api + 假 urlopen
    # ⚠ 先把记录器摘掉：上面那一段把 `_call_api` 换成了记录器，
    #   不还原就永远读不到 `response.read()`（2026-11-02 实测：14 条全返回了上一条 reply）。
    extract = []
    orig_urlopen = MOD.urllib.request.urlopen
    MOD.AIAssistance._call_api = ORIG_CALL_API
    try:
        for case in EXTRACT_CASES:
            MOD.urllib.request.urlopen = (
                lambda req, timeout=30, _b=case['body']: FakeResp(_b))
            ai = MOD.AIAssistance(api_key='k')
            try:
                value = ai._call_api([], 0.3)
                py = {'ok': True, 'value': value, 'value_type': type(value).__name__}
            except Exception as exc:  # noqa: BLE001 —— 记录真 Python 的行为
                py = {'ok': False, 'error': '%s: %s' % (type(exc).__name__, exc)}
            if 'want' in case:
                want = case['want']
            else:
                want = {'ok': True, 'content': py['value']}
            entry = {
                'name': case['name'],
                'note': case['note'],
                'source': case['source'],
                'body': case['body'],
                'status': case['status'],
                'python': py,
                'want': want,
                'diverges': bool(case.get('diverges')),
            }
            extract.append(entry)
    finally:
        MOD.urllib.request.urlopen = orig_urlopen
        rec.install()

    # ④ fallback：真 _fallback_suggest_tags
    fallback = []
    ai = MOD.AIAssistance(api_key='k')
    for case in FALLBACK_CASES:
        tags = ai._fallback_suggest_tags(case['text'], case['max_tags'])
        fallback.append({
            'name': case['name'],
            'note': case['note'],
            'source': case['source'],
            'text': case['text'],
            'max_tags': case['max_tags'],
            'want': tags,
        })

    # ⑤ enabled + endpoint
    enabled = []
    for case in ENABLED_CASES:
        got = MOD.build_ai_assistance(fake_cfg(**case['cfg']))
        enabled.append({
            'name': case['name'],
            'note': case['note'],
            'source': case['source'],
            'cfg': case['cfg'],
            'want': got is not None,
        })

    endpoint = []
    for case in ENDPOINT_CASES:
        ai2 = MOD.AIAssistance(provider=case['provider'], endpoint=case['endpoint'])
        url = '%s/chat/completions' % ai2.endpoint
        entry = {
            'name': case['name'],
            'note': case['note'],
            'source': case['source'],
            'provider': case['provider'],
            'endpoint': case['endpoint'],
            'python_url': url,
            'python_endpoint': ai2.endpoint,
        }
        if case['name'] == 'no_scheme':
            entry['want'] = {'ok': False, 'error_contains': 'absolute URL'}
        elif case['name'] == 'http_scheme':
            entry['want'] = {'ok': False, 'error_contains': 'https'}
        elif case['name'] == 'trailing_slash':
            entry['want'] = {'ok': True, 'host': 'example.com', 'port': 443,
                             'path': '/v1/chat/completions'}
        else:
            parts = urllib.parse.urlsplit(url)
            entry['want'] = {
                'ok': True,
                'host': parts.hostname,
                'port': parts.port or (443 if parts.scheme == 'https' else 80),
                'path': parts.path,
            }
        endpoint.append(entry)

    # ⑥ envelope：真 json.dumps
    envelope = []
    for case in ENVELOPE_CASES:
        if case['ok']:
            obj = {'result': case['tags'] if 'tags' in case else case['content']}
        else:
            obj = {'error': case['error']}
        envelope.append({
            'name': case['name'],
            'note': case['note'],
            'source': case['source'],
            'ok': case['ok'],
            'error': case.get('error'),
            'content': case.get('content'),
            'tags': case.get('tags'),
            'python_dumps': json.dumps(obj),
            # want = **我们**的输出口径：不转义非 ASCII，其余（", " / ": " 分隔、转义）同 json.dumps
            'want': json.dumps(obj, ensure_ascii=False),
        })

    # ⑦ pipeline：用真 Python 的 messages 推出请求体，再用真 Python 的后处理推结果
    pipeline = []
    for case in PIPELINE_CASES:
        cap = case['capability']
        opts = dict(case['opts'])
        text = opts.pop('text', '')
        kwargs = {'text': text}
        if 'prompt_hint' in opts:
            kwargs['prompt_hint'] = opts['prompt_hint']
        if 'lang' in opts:
            kwargs['target_lang'] = {'en': 'English', 'ja': 'Japanese'}.get(opts['lang'], 'English')
        if 'max_length' in opts:
            kwargs['max_length'] = opts['max_length']
        if 'max_tags' in opts:
            kwargs['max_tags'] = opts['max_tags']
        method = {'complete': 'complete_text', 'polish': 'polish_text',
                  'translate': 'translate_text', 'summarize': 'summarize',
                  'suggest_tags': 'suggest_tags'}[cap]
        value, call, err = run_method(rec, method, kwargs, case['reply_content'])
        if err:
            raise SystemExit('unexpected error in pipeline/%s: %s' % (case['name'], err))
        # 「有没有走词频降级」不能用「结果 == 降级结果」判：
        # 模型恰好给出与降级相同的标签时两者相等（2026-11-02 实测 tags_ok 假阳性）
        # ⇒ 用哨兵把降级变成可判信号。
        fell_back = None
        if cap == 'suggest_tags' and call is not None:
            fell_back = probe_fell_back(case['reply_content'], text,
                                        int(opts.get('max_tags', 5)))
        ai_ok = bool((opts.get('ai_enabled') is True) and opts.get('ai_api_key'))
        entry = {
            'name': case['name'],
            'note': case['note'],
            'source': case['source'],
            'capability': cap,
            'opts': case['opts'],
            'status': case['status'],
            'reply_content': case['reply_content'],
            'raw': raw_response(case['status'], chat_body(case['reply_content'])),
            'transport_called': call is not None,
            'python_result': value,
            'want': {},
        }
        want = entry['want']
        if not ai_ok:
            want['ok'] = False
            want['status_is_null'] = True
            want['transport_called'] = False
            want['error_contains'] = 'not configured'
        elif call is None:
            # 空文本 ⇒ 不构建、不发请求
            want['ok'] = True
            want['status_is_null'] = True
            want['transport_called'] = False
            want['result'] = value
        elif case['status'] >= 400:
            # 后端错误：Python 侧的 HTTPError 会抛 AIAssistanceError ⇒
            # suggest_tags 降级；其余能力必须 ok:FALSE（卡 S5-1/52 的反向守卫）
            want['transport_called'] = True
            if cap == 'suggest_tags':
                want['ok'] = True
                want['tags'] = ai._fallback_suggest_tags(text, int(opts.get('max_tags', 5)))
                want['fallback'] = True
            else:
                want['ok'] = False
                want['status'] = case['status']
                want['error_contains'] = str(case['status'])
        else:
            payload = {
                'model': call['model'],
                'messages': call['messages'],
                'temperature': call['temperature'],
            }
            want['transport_called'] = True
            want['wire_body'] = stringify_like(payload)
            want['python_body'] = json.dumps(payload)
            if cap == 'suggest_tags':
                want['ok'] = True
                want['tags'] = value
                want['fallback'] = fell_back
            else:
                want['ok'] = True
                want['status'] = case['status']
                want['content'] = value
        pipeline.append(entry)

    divergences = [
        {
            'id': 'D-AI-CONTENT-LENIENT',
            'ours': 'choices[0].message.content 缺字段 / 不是字符串 ⇒ ok:FALSE',
            'python': '`.get("message", {}).get("content", "")` ⇒ 静默给出 ""（或 123 / None）',
            'why': '卡 S5-2 的「形状不对 ⇒ ok:FALSE」；静默空串会把协议错误当成空答案',
            'evidence': 'ai_assistance.py:81 + fixtures/extract 的 no_message / content_number / content_null',
        },
        {
            'id': 'D-AI-ENDPOINT-SLASH',
            'ours': '端点结尾的 / 先剥掉再拼 path',
            'python': 'f"{endpoint}/chat/completions" ⇒ "…/v1//chat/completions"',
            'why': '双斜杠会被部分服务端当成另一个路径；语义不变、形状更稳',
            'evidence': 'ai_assistance.py:60 + fixtures/endpoint.trailing_slash',
        },
        {
            'id': 'D-AI-HTTPS-ONLY',
            'ours': 'http:// 端点 ⇒ ok:FALSE',
            'python': 'urllib 真的发明文 HTTP',
            'why': '本模块的传输层（卡 S5-1）是 TLS-only；静默走 TLS 才是撒谎',
            'evidence': 'ai_assistance.py:60、卡 S5-1 的 HTTP_CLIENT 只做 HTTPS',
        },
        {
            'id': 'D-AI-JSON-ASCII',
            'ours': 'JSON 出参保留原字符（中文原样）',
            'python': 'json.dumps 默认 ensure_ascii=True ⇒ 写 \\uXXXX',
            'why': '语义等价；ASCII 载荷下逐字节一致，非 ASCII 的差异登记在此',
            'evidence': 'admin/actions.py:329 + fixtures/envelope.error_unknown_action',
        },
        {
            'id': 'D-AI-BODY-ORDER',
            'ours': '请求体 = STRINGIFY（紧凑、键名排序）',
            'python': 'json.dumps（", " / ": " 分隔、插入序）',
            'why': '与卡 S5-1 的 HC_PAYLOAD 同一口径；服务端按 JSON 语义解析，不看字节序',
            'evidence': 'fixtures/pipeline[].want.wire_body vs python_body',
        },
        {
            'id': 'D-AI-ENABLED-TYPE',
            'ours': 'ai_enabled 必须是布尔 TRUE 才启用',
            'python': '任意真值（1、"yes"）都算启用',
            'why': '配置来自 WLWL 字典；非布尔值传进来是调用方的错，fail closed 更安全',
            'evidence': 'ai_assistance.py:273（`if not getattr(...)`）',
        },
    ]

    doc = {
        'meta': {
            'card': 'S5-2',
            'generator': 'tp/test/gen_ai_baseline.py',
            'sources': [
                'tinypage/core/ai_assistance.py:30-307（AIAssistance 与 build_ai_assistance / fallback_summarize）',
                'tinypage/admin/actions.py:296-329（/ai-assist 的 JSON 形状与 lang_map）',
                'tinypage/content.py:794-808（翻译：lang_map + summarize(…, 200)）',
                'tinypage/config.py:63-68（ai_provider / ai_api_key / ai_model / ai_endpoint / ai_enabled）',
                '卡 S5-2（docs/plans/tinypage-wlwl-rewrite-plan.md:1407-1421）',
            ],
            'conventions': [
                'messages 用例的 want.temperature 为 None ⇔ skip（Python 没构建消息，也就没有温度）',
                'pipeline 用例的 want.wire_body 用 STRINGIFY 口径（sort_keys + 紧凑 + 不转义非 ASCII）复现',
                'extract 用例的 want.error_contains 只钉「错误里必须出现的词」，不钉整句（错误文案来自我们自己的分层）',
                'finish 的 tags 用例里 want.ok=FALSE ⇔ Python 的 json.loads 失败（⇒ 走词频降级）',
            ],
            'divergences': divergences,
        },
        'messages': messages,
        'extract': extract,
        'finish': finish + tags_finish,
        'fallback': fallback,
        'enabled': enabled,
        'endpoint': endpoint,
        'envelope': envelope,
        'pipeline': pipeline,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(doc, f, ensure_ascii=False, indent=2, sort_keys=False)
        f.write('\n')
    print('wrote %s' % OUT)
    print('  messages=%d extract=%d finish=%d fallback=%d enabled=%d endpoint=%d envelope=%d pipeline=%d'
          % (len(messages), len(extract), len(finish) + len(tags_finish), len(fallback),
             len(enabled), len(endpoint), len(envelope), len(pipeline)))
    print('  divergences=%d' % len(divergences))


if __name__ == '__main__':
    main()
