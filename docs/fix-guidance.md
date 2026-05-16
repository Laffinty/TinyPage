# TinyPage 管理后台修复指导书

> **目标读者**：执行修复的开发 Agent  
> **前置文档**：`docs/admin-audit-report.md`（审计报告）  
> **当前状态**：P0/P1 已部分修复，存在 **3 个新引入的阻塞性问题** + **6 个遗留重要问题**  
> **目标**：使管理后台所有核心功能可用

---

## 零、关键前置：已修复验证与新增问题

主力 Agent 已修复了审计报告中的大部分 P0/P1 问题，但修复过程中引入了 **3 个新的阻塞性问题**，不修复这些 HTMX 实际上仍无法工作。

### 🔴 NEW-1：Admin 应用无法提供 HTMX 文件（阻塞性）

**现象**：HTMX 仍然无法加载，与修复前等效。

**根因**：`HTMX_CDN` 从 `https://unpkg.com/...` 改为 `/htmx.min.js`，但 Admin 应用运行在 **8081 端口**，浏览器请求 `http://127.0.0.1:8081/htmx.min.js`，而 Admin 应用没有对应的路由处理该请求（返回 404）。`htmx.min.js` 文件存在于 `static_inject/` 目录，但仅由 8080 端口的 `StaticApp` 提供。

**修复方案**：在 `AdminApp.__call__` 的 GET 路由分支中添加静态文件服务：

```python
# admin.py AdminApp.__call__ 方法，GET 分支最前面添加：
if method == "GET":
    # Serve injected static assets (htmx.min.js etc.)
    from .frontend import _INJECTED_ASSETS
    if path in _INJECTED_ASSETS:
        ct, data = _INJECTED_ASSETS[path]
        headers = [
            ("Content-Type", ct),
            ("Content-Length", str(len(data))),
            ("Cache-Control", "max-age=3600"),
        ] + get_security_headers()
        start_response("200 OK", headers)
        return [data]
    # ... 原有路由继续
```

---

### 🔴 NEW-2：HTMX integrity 哈希与本地文件不匹配（阻塞性）

**位置**：`admin.py:930`

**现象**：即使 Admin 能提供 HTMX 文件，浏览器仍会因 integrity 校验失败而拒绝执行。

**根因**：`_render_page` 中的 integrity 属性值是旧 CDN 版本的哈希，与本地 `static_inject/htmx.min.js` 不匹配。

```python
# admin.py:930 — 旧哈希
htmx_script = f'<script src="{HTMX_CDN}" integrity="sha384-oeUn82QN6ta..." crossorigin="anonymous"></script>'
```

**正确哈希值**（已通过 `sha384` 计算）：

```
sha384-HGfztofotfshcF7+8n44JQL2oJmowVChPTg48S+jvZoztPfvwD79OC/LTtG6dMp+
```

**修复方案**：替换 integrity 值，或直接移除 integrity 属性（因为是本地文件，完整性由同源保证）：

```python
# 方案 A（推荐）：移除 integrity，同源已保证完整性
htmx_script = f'<script src="{HTMX_CDN}"></script>' if extra_script else ""

# 方案 B：更新为正确哈希
htmx_script = f'<script src="{HTMX_CDN}" integrity="sha384-HGfztofotfshcF7+8n44JQL2oJmowVChPTg48S+jvZoztPfvwD79OC/LTtG6dMp+" crossorigin="anonymous"></script>' if extra_script else ""
```

---

### 🔴 NEW-3：仪表盘和独立页面管理页未加载 HTMX 脚本（阻塞性）

**位置**：`admin.py:287`（`_dashboard`）、`admin.py:704`（`_pages_dashboard`）

**现象**：仪表盘和页面管理页使用了 HTMX 属性（`hx-post`、`hx-target`、`hx-swap`），但页面不加载 HTMX 脚本，导致所有 HTMX 增强交互失效。

**根因**：这两个方法调用 `_render_page` 时未传 `extra_script=True`：

```python
# admin.py:287
return self._render_page(start_response, "管理后台", body, csrf_token)
#                                                              ← 缺少 extra_script=True

# admin.py:704
return self._render_page(start_response, "独立页面", body, csrf_token)
#                                                              ← 同上
```

**修复方案**：两个调用都添加 `extra_script=True`：

```python
return self._render_page(start_response, "管理后台", body, csrf_token, extra_script=True)
return self._render_page(start_response, "独立页面", body, csrf_token, extra_script=True)
```

**注意**：主题管理页（`/theme`）没有 HTMX 交互，无需修改。

---

## 一、遗留 P1 问题修复指导

### BUG-H005：文章翻译功能无前端入口

**当前状态**：后端 `/translate` POST 路由存在但无 UI 触发。

**修复位置**：`admin.py` 的 `_dashboard` 方法

**修复方案**：在仪表盘文章列表的删除按钮旁添加翻译下拉按钮：

```html
<td>
  <!-- 现有删除表单 -->
  <form method="post" action="/delete" ...>...</form>
  <!-- 新增翻译下拉 -->
  <form method="post" action="/translate" style="display:inline;">
    <input type="hidden" name="csrf_token" value="{csrf_token}">
    <input type="hidden" name="file" value="{art.file}">
    <select name="lang" onchange="if(this.value)this.form.submit()" 
            style="padding:0.2rem 0.4rem;font-size:0.8rem;border-radius:4px;
                   background:var(--surface);color:var(--text);border:1px solid var(--border);">
      <option value="">翻译▼</option>
      <option value="en">English</option>
      <option value="ja">日本語</option>
    </select>
  </form>
</td>
```

**注意**：翻译需要 AI 配置，建议在 `ai_enabled` 为 True 时才显示。

---

### BUG-H005 扩展：独立页面编辑缺 drop-zone 和 AI 面板

**当前状态**：`_edit_page_form`（`admin.py:733-776`）没有图片上传区域和 AI 面板。

**修复方案**：在 `_edit_page_form` 的表单中添加与 `_edit_form` 相同的 drop-zone HTML 和条件 AI 面板。

参照 `admin.py:415`（drop-zone）和 `admin.py:370-383`（AI 面板条件渲染）的模式，在 `_edit_page_form` 的 textarea 前插入相同代码。

---

## 二、遗留 P2 重要问题修复指导

### BUG-P2-1：独立页面管理删除按钮缺少确认提示

**位置**：`admin.py:687`

**当前状态**：仪表盘文章删除按钮已添加 `onclick="return confirm()"`，但独立页面管理的删除按钮未添加。

**修复**：

```python
# admin.py:687 — 当前
<button type="submit" class="btn-danger btn-sm">删除</button>

# 改为
<button type="submit" class="btn-danger btn-sm" onclick="return confirm('删除不可恢复，确定？')">删除</button>
```

---

### BUG-P2-2：上传接口非 CSRF 错误返回非 JSON

**位置**：`admin.py:849-925`（`_upload` 方法）

**当前状态**：CSRF 失败已返回 JSON，但其他错误（文件类型不允许、base64 无效、文件过大等）仍通过 `self._error()` 返回 `text/plain`。前端 `r.json()` 会解析失败。

**修复方案**：将 `_upload` 中的所有 `self._error()` 调用替换为 JSON 错误响应：

```python
def _json_error(self, start_response, status: str, message: str):
    headers = [("Content-Type", "application/json")] + get_security_headers()
    start_response(status, headers)
    return [json.dumps({"success": False, "error": message}).encode("utf-8")]
```

然后将 `_upload` 中的 `self._error(` 替换为 `self._json_error(`。共 6 处需替换（行 857, 862, 868, 881, 884, 907）。

---

### BUG-P2-3：图片上传插入语法错误

**位置**：`admin.py:1000`

**当前状态**：

```javascript
ta.value += '\\n![](`' + data.url + '`)\\n';
```

生成的是 `` ![](`/static/images/...`) `` — 反引号包裹 URL 不是合法 Markdown 图片语法。

**修复**：

```javascript
ta.value += '\\n![](' + data.url + ')\\n';
```

生成标准语法 `![](/static/images/...)`。

---

### BUG-P2-4：delete_standalone 重复定义

**位置**：`content.py:362-365` 和 `content.py:708-710`

**修复**：删除 `content.py:362-365` 的第一处定义，仅保留行 708-710 的版本。

---

### BUG-P2-5：write_article 双重生成

**位置**：`admin.py:466`（`_create`）、`admin.py:492`（`_save`）

**当前逻辑**：
1. `write_article()` → 内部调用 `generate_article_html()` 使用默认 `Config()` 生成一次 HTML
2. `generate_static_pages()` → 内部调用 `regenerate_all_articles()` 再生成一次（使用正确 Config）

**修复方案**：给 `write_article` 添加参数 `skip_html_generation=False`，当为 True 时跳过内部 HTML 生成，仅写入元数据注释 + 占位内容（由后续 `generate_static_pages` 完整生成）：

```python
# content.py write_article 函数签名添加：
def write_article(..., skip_html_generation: bool = False) -> None:
    ...
    if skip_html_generation:
        full_html = ""  # 占位，由 regenerate_all_articles 填充
    else:
        full_html = generate_article_html(...)
    ...

# admin.py _create 和 _save 中调用：
write_article(..., skip_html_generation=True)
```

---

### BUG-P2-6：仪表盘缺少文章搜索/过滤

**修复位置**：`admin.py` 的 `_dashboard` 方法

**修复方案**：在仪表盘顶部添加搜索输入框：

```html
<div class="actions">
  <a href="/new" class="btn-primary">+ 新建文章</a>
  ...
  <input type="search" id="article-search" placeholder="搜索文章标题..." 
         style="max-width:200px;margin-left:auto;" 
         oninput="filterArticles(this.value)">
</div>

<script>
function filterArticles(q) {{
  var rows = document.querySelectorAll('table.admin-table tbody tr');
  q = q.toLowerCase();
  rows.forEach(function(row) {{
    var text = row.textContent.toLowerCase();
    row.style.display = text.includes(q) ? '' : 'none';
  }});
}}
</script>
```

---

## 三、修复执行顺序

按以下顺序修复，每步完成后验证：

### 步骤 1：修复 3 个阻塞性新问题（HTMX 不可用）

| 序号 | 任务 | 文件 | 预计耗时 |
|------|------|------|---------|
| 1.1 | Admin 添加静态文件路由（NEW-1） | `admin.py` | 10 分钟 |
| 1.2 | 移除/更新 HTMX integrity（NEW-2） | `admin.py:930` | 2 分钟 |
| 1.3 | 仪表盘和页面管理加载 HTMX（NEW-3） | `admin.py:287,704` | 2 分钟 |

**验证**：启动服务器，打开 `http://127.0.0.1:8081/`，打开浏览器 DevTools Network 面板：
- 确认 `htmx.min.js` 请求返回 200
- 确认 Console 无 integrity 或 CSP 错误
- 点击"重新生成静态页"，确认出现"✓ 已重新生成"反馈
- 点击删除按钮，确认 HTMX 平滑移除行

### 步骤 2：修复遗留 P1 问题

| 序号 | 任务 | 文件 | 预计耗时 |
|------|------|------|---------|
| 2.1 | 添加翻译 UI 入口（BUG-H005） | `admin.py:_dashboard` | 15 分钟 |
| 2.2 | 编辑页面添加 drop-zone + AI 面板 | `admin.py:_edit_page_form` | 10 分钟 |

**验证**：
- 仪表盘文章列表出现翻译下拉
- 编辑独立页面时可见拖拽上传区域
- AI 配置时编辑页面显示 AI 面板，未配置时不显示

### 步骤 3：修复 P2 重要问题

| 序号 | 任务 | 文件 | 预计耗时 |
|------|------|------|---------|
| 3.1 | 页面删除确认提示 | `admin.py:687` | 2 分钟 |
| 3.2 | 上传错误返回 JSON | `admin.py:_upload` | 10 分钟 |
| 3.3 | 图片插入语法修复 | `admin.py:1000` | 2 分钟 |
| 3.4 | delete_standalone 去重 | `content.py:362-365` | 1 分钟 |
| 3.5 | write_article 避免双重生成 | `content.py` + `admin.py` | 20 分钟 |
| 3.6 | 仪表盘搜索过滤 | `admin.py:_dashboard` | 15 分钟 |

### 步骤 4：最终验证

启动开发服务器 `tinypage serve`，逐一验证以下用户流程：

| 流程 | 验证点 |
|------|--------|
| 新建文章 | 表单渲染 → 实时预览 → 图片上传 → AI 面板 → 保存成功 → 跳转仪表盘 |
| 编辑文章 | Markdown 正确加载 → 预览同步 → 保存后 Markdown 保留 |
| 删除文章 | 确认弹窗 → HTMX 平滑删除 / 非 HTMX 重定向 |
| 翻译文章 | 下拉选择语言 → 创建翻译版本 |
| 独立页面 CRUD | 新建 → 编辑（含 drop-zone）→ 删除 |
| 主题切换 | 切换 → 自动重生成 → 重启后保持 |
| 重新生成 | HTMX 状态反馈 |

---

## 四、技术约束提醒

1. **CSP 策略**：Admin CSP 为 `script-src 'self' 'unsafe-inline'`，所有脚本必须来自同源或内联。Admin 应用需要能提供 HTMX 文件（NEW-1 的核心）。

2. **双端口架构**：StaticApp 在 8080，AdminApp 在 8081，互不相通。Admin 页面中的资源引用（如 `/htmx.min.js`）必须由 AdminApp 自身提供，不能依赖 StaticApp。

3. **CSRF 双重提交**：所有 POST 请求需携带 `csrf_token` 表单字段，且浏览器会自动发送同源 `csrf_token` Cookie。`_get_existing_csrf` 尝试复用已有 Cookie 中的 token，避免每次生成新 token 导致旧页面表单失效。

4. **HTMX 加载位置**：`_render_page` 中 HTMX 脚本在 body 末尾（`{htmx_script}` 在 `</body>` 前），HTMX 加载后会自动扫描 DOM 中的 `hx-*` 属性并绑定事件。

5. **AI 条件渲染**：`_new_form` 和 `_edit_form` 已实现条件渲染（`self.cfg.ai_enabled and self.cfg.ai_api_key`），新添加的 AI 面板也必须遵循相同模式。
