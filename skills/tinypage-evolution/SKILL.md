# TinyPage Evolution — 从试验项目到产品级套件

## 概述

本 Skill 为 TinyPage 项目提供一套完整的产品化演进方案。TinyPage 是一个基于 Python 标准库的静态站点生成器，核心优势是**零依赖、文件即数据、现代 CSS 实验场**。本方案将其从"个人博客试验品"重新定位为"轻量级文档与知识花园生成器"，避开夕阳赛道，切入逆势增长的高价值领域。

---

## 1. 市场分析与战略定位

### 1.1 为什么传统博客/CMS 是夕阳赛道

- **社交媒体分流**：长文写作 migrated 到微信公众号、知乎、Substack、Medium
- **SaaS 化挤压**：Notion、Ghost、WordPress.com 提供托管服务，自托管需求萎缩
- **技术栈断层**：新一代开发者使用 Node/VitePress/Docusaurus，Python 生态缺少对标物

### 1.2 逆势增长的三个高价值赛道

| 赛道 | 代表产品 | 年增长率 | TinyPage 适配度 |
|------|---------|---------|---------------|
| **文档站点生成器 (Docs-as-Code)** | VitePress, Docusaurus, MkDocs, Starlight | 极高 | ★★★★☆ |
| **数字花园 / 知识发布** | Quartz, Obsidian Publish, Foam | 高 | ★★★★☆ |
| **AI 增强型内容工作流** | Hashnode AI, Vercel AI SDK Docs | 爆发期 | ★★★☆☆ |

### 1.3 TinyPage 的差异化定位

> **"零依赖 Python 原生文档与知识花园生成器 —— 一个文件即可运行的现代站点引擎"**

核心差异化卖点：
1. **单文件可运行**：仅依赖 waitress，比 Hugo/VitePress 部署简单 10 倍
2. **Python 生态原生**：Python 项目需要文档，但团队不想引入 Node 工具链
3. **现代 CSS 展示平台**：原生 Container Queries、View Transitions、OKLCH —— 前端开发者的实验沙盒
4. **文件即数据**：Git 原生友好，无需数据库迁移
5. **双服务架构**：Admin 后台实时写作 + 静态站点即时发布，比纯 CLI 工具更直观

---

## 2. 技术演进路线图（五阶段）

### Phase 1: 内容引擎升级 — 成为合格的文档工具（1-2 周）

**目标**：让 TinyPage 能写真正的技术文档，而不仅是短文博客。

关键任务：
- **引入真正的 Markdown 解析器**（mistune 2.x，纯 Python，单文件即可替换现有 `text_to_html`）
- **支持独立页面**（`pages/standalone/`）：About、Projects、API Reference 等非文章页面
- **目录/分类系统**：从扁平 tag 进化为层级 category，支持文档树导航
- **草稿模式**：文章元数据增加 `status: draft | published`，草稿不生成到公开页面
- **代码块与高亮**：集成 Pygments（纯 Python）实现语法高亮
- **图片/资源上传**：Admin 后台增加 `/upload` 接口，资源存入 `static/` 目录

### Phase 2: 主题与模板系统 — 支持多场景（2-3 周）

**目标**：摆脱"只能换 CSS"的局限，支持文档、博客、花园三种布局模式。

关键任务：
- **模板抽象层**：用 Python 标准库 `string.Template` 替换硬编码 f-string，保持零外部依赖
- **主题 manifest.json**：每个主题声明名称、作者、支持布局、可配置变量
- **多布局引擎**：
  - `layout: doc` — 左侧目录树 + 右侧内容（文档模式）
  - `layout: garden` — 网状标签云 + 双向链接（花园模式）
  - `layout: blog` — 现有列表页布局（博客模式）
- **主题热切换**：Admin 后台提供主题选择器，一键切换并重新生成
- **组件化 HTML**：提取 `<head>`、导航栏、页脚、目录树为可复用模板片段

### Phase 3: 数字花园特性 — 差异化杀手锏（2-3 周）

**目标**：引入知识管理领域的热门概念，打造独特卖点。

关键任务：
- **双向链接解析**：支持 `[[Page Title]]` 和 `[[Page Title|Display Text]]` 语法，自动生成反向链接列表
- **标签图谱可视化**：用 D3.js 或原生 Canvas 生成标签关联网络图
- **Table of Contents (ToC)**：根据 Markdown 标题层级自动生成页面内导航
- **最近更新/相关文章**：基于标签相似度推荐相关内容
- **脚注与引用**：支持 Markdown 脚注、文献引用
- **Mermaid 图表**：支持文本绘制流程图、时序图（前端渲染，无需后端依赖）

### Phase 4: AI 增强工作流 — 拥抱趋势（2-3 周）

**目标**：将 AI 集成到写作和发布流程中，降低内容生产成本。

关键任务：
- **AI 辅助写作面板**：Admin 后台集成 OpenAI/DeepSeek API 的"续写/润色/翻译"按钮
- **自动摘要生成**：发布时自动提取摘要写入 meta description
- **智能标签推荐**：基于内容自动生成标签建议
- **SEO 自动优化**：自动生成结构化数据 (JSON-LD)、Open Graph 标签、Twitter Cards
- **多语言翻译工作流**：一键生成英文/日文版本文章（存入 `pages/en/article/`）

### Phase 5: 工程化与生态 — 产品化收尾（持续迭代）

**目标**：从"脚本"升级为"可安装的工具"。

关键任务：
- **CLI 重构**：`tinypage build`、`tinypage serve`、`tinypage new-site my-docs`
- **pip 可安装**：`pip install tinypage`，入口命令 `tinypage`
- **增量生成**：仅重新生成变更的页面，全站重建耗时 < 1 秒（1000 篇文章）
- **Git 钩子集成**：预提交自动格式化、预推送自动构建
- **Docker 镜像**：单容器部署，包含静态服务和 Admin 后台
- **GitHub Actions 模板**：一键部署到 GitHub Pages / Cloudflare Pages / Vercel
- **Python API 文档自动生成**：集成 docstring 提取，自动生成模块 API Reference

---

## 3. 架构调整原则

### 3.1 保持核心优势
- **零依赖承诺**：核心功能不引入任何非标准库依赖，可选功能通过 `extras_require` 引入
- **文件即数据**：坚持 HTML 文件存储，不引入 SQLite/数据库
- **双服务架构保留**：Admin 后台是差异化优势，不要改成纯 CLI

### 3.2 必须引入的抽象

```
tinypage/
├── core/                    # 新增：核心抽象层
│   ├── __init__.py
│   ├── renderer.py          # Renderer 抽象：Markdown → HTML
│   ├── template.py          # Template 抽象：布局渲染
│   ├── plugin.py            # Plugin 钩子系统
│   └── incremental.py       # 增量生成引擎
├── parsers/                 # 新增：解析器插件
│   ├── __init__.py
│   └── markdown.py          # mistune 封装
├── layouts/                 # 新增：布局模板
│   ├── doc.html
│   ├── garden.html
│   └── blog.html
├── themes/                  # 现有保留
├── admin.py                 # 现有保留，扩展功能
├── generator.py             # 现有重构，调用 core 抽象
├── content.py               # 现有重构，支持 draft/standalone
├── server.py                # 现有保留
└── ...
```

### 3.3 插件钩子设计（最小 viable）

```python
# tinypage/core/plugin.py
from typing import Protocol, Callable
from dataclasses import dataclass

class Plugin(Protocol):
    name: str
    
    def on_before_render(self, article: Article) -> Article: ...
    def on_after_render(self, html: str, article: Article) -> str: ...
    def on_generate_index(self, articles: list[Article]) -> dict: ...

# 注册方式：tinypage/plugins/ 目录自动发现，或 config.plugins = ["mermaid", "search"]
```

---

## 4. 快速启动：Phase 1 详细任务清单

如果你是第一次使用本 Skill，按以下顺序执行 Phase 1，将项目从"博客玩具"升级为"可用文档工具"。

### Phase 1 完成状态

| 任务 | 状态 | 说明 |
|------|------|------|
| 1.1 Markdown 解析器 | ✅ 已完成 | `parsers/markdown.py` 已集成 mistune，支持 fallback |
| 1.2 独立页面 | ✅ 已完成 | `pages/standalone/`、`write_standalone()`/`list_standalones()`、`/pages` 管理页 |
| 1.3 目录/分类系统 | ✅ 已完成 | `ArticleMeta.category`、`generate_category_page()`、category datalist |
| 1.4 草稿模式 | ✅ 已完成 | `status: draft|published`、draft 背景色标识、`include_drafts` 参数 |
| 1.5 代码高亮 | ✅ 已完成 | `parsers/syntax.py` Pygments 集成，`load_theme_css()` 自动注入 Pygments CSS |
| 1.6 图片上传 | ✅ 已完成 | `/upload` 路由、base64 处理、按月组织、10MB 限制 |
| pyproject.toml | ✅ 已新增 | `extras_require`: markdown/syntax/full，`tinypage` CLI 入口 |
| Admin 拖拽上传 | ✅ 已新增 | 编辑器 div drop-zone，拖拽/点击上传自动插入 Markdown 图片语法 |

### Phase 2 完成状态

| 任务 | 状态 | 说明 |
|------|------|------|
| 2.1 模板抽象层 | ✅ 已完成 | `core/template.py` — `render_skeleton()` + 5 个 `build_*_context()` |
| 2.2 主题 manifest.json | ✅ 已完成 | `layouts: ["blog"]`，`planned_layouts: ["doc", "garden"]` 待实现 |
| 2.3 多布局引擎 | 🔄 部分 | 5 个 `generate_*` 函数已模板化；doc/garden CSS 待实现 |
| 2.4 主题热切换 | ✅ 已完成 | Admin `/theme` 管理页 + `/set-theme` POST + `list_themes()` 扫描 |
| 2.5 组件化 HTML | ✅ 已完成 | `_PAGE_SKELETON` 单模板，`render_skeleton()` 渲染所有页面类型 |

### Phase 3 完成状态

| 任务 | 状态 | 说明 |
|------|------|------|
| 3.1 双向链接解析 | ✅ 已完成 | `parsers/bidirectional_links.py`，支持 `[[Page Title]]` 和 `[[Page Title\|Display Text]]` |
| 3.2 Table of Contents | ✅ 已完成 | `parsers/toc.py`，自动提取标题生成目录 |
| 3.3 脚注与引用 | ✅ 已完成 | `parsers/footnotes.py`，支持 Markdown 脚注语法 |
| 3.4 Mermaid 图表 | ✅ 已完成 | 前端 CDN 渲染，支持流程图、时序图 |
| 3.5 相关文章推荐 | ✅ 已完成 | `content.py` 的 `find_related_articles()`，基于 Jaccard 相似度 |
| 3.6 标签图谱可视化 | ✅ 已完成 | `parsers/tag_graph.py`，Canvas 绘制标签关联网络图 |
| 3.7 反向链接索引 | ✅ 已完成 | `content.py` 的 `build_backlink_index()` 和 `build_backlinks_html()` |

### Phase 4 完成状态

| 任务 | 状态 | 说明 |
|------|------|------|
| 4.1 AI 辅助写作面板 | ✅ 已完成 | Admin 编辑器集成"续写/润色/翻译/推荐标签"按钮 |
| 4.2 自动摘要生成 | ✅ 已完成 | `ai_assistance.py` 的 `summarize()` 方法 |
| 4.3 智能标签推荐 | ✅ 已完成 | `ai_assistance.py` 的 `suggest_tags()` 方法，含 fallback |
| 4.4 SEO 自动优化 | ✅ 已完成 | JSON-LD、Open Graph、Twitter Cards |
| 4.5 多语言翻译工作流 | ✅ 已完成 | `content.py` 的 `translate_article()`，支持英/日文 |

### 任务 3.1：双向链接解析 ✅ 已完成

- `parsers/bidirectional_links.py` 实现 `parse_bidirectional_links()` 函数
- 支持 `[[Page Title]]` 和 `[[Page Title|Display Text]]` 两种语法
- `build_article_title_map()` 构建标题到 slug 的映射
- `regenerate_all_articles()` 集成双向链接处理

### 任务 3.2：Table of Contents ✅ 已完成

- `parsers/toc.py` 实现 `extract_headings()` 和 `build_toc_html()` 函数
- `add_heading_ids()` 为渲染后的 HTML 标题添加锚点 ID
- 支持 h2-h3 层级，可在 `build_toc_html()` 调整 `min_level`/`max_level`

### 任务 3.3：脚注与引用 ✅ 已完成

- `parsers/footnotes.py` 实现 `process_footnotes()` 函数
- 支持 Markdown 脚注语法 `[^1]` 和对应的 `[^1]: definition`
- 脚注渲染在文章底部，带有回到原文的链接

### 任务 3.4：Mermaid 图表 ✅ 已完成

- `parsers/mermaid_init.py` 包含 Mermaid 初始化脚本
- `generator.py` 在文章页面注入 Mermaid CDN 和初始化代码
- 支持流程图、时序图、饼图等多种图表类型

### 任务 3.5：相关文章推荐 ✅ 已完成

- `content.py` 实现 `find_related_articles()` 函数
- 使用 Jaccard 相似度计算标签重叠度
- `regenerate_all_articles()` 中调用并传递相关文章列表

### 任务 3.6：标签图谱可视化 ✅ 已完成

- `parsers/tag_graph.py` 实现 `get_tag_graph_html()` 函数
- 使用原生 Canvas API 绘制标签关联网络图
- 基于标签共现次数计算连接权重

### 任务 3.7：反向链接索引 ✅ 已完成

- `content.py` 实现 `build_backlink_index()` 函数
- `build_backlinks_html()` 生成反向链接 section HTML
- `regenerate_all_articles()` 中构建并使用反向链接索引

### 任务 4.1：AI 辅助写作面板 ✅ 已完成

- `admin.py` 在新建/编辑文章表单中添加 AI 面板
- 面板包含"续写"、"润色"、"译英"、"译日"、"推荐标签"按钮
- `/ai-assist` POST 路由处理所有 AI 请求

### 任务 4.2：自动摘要生成 ✅ 已完成

- `ai_assistance.py` 实现 `summarize()` 方法
- 使用 AI API 生成摘要，支持 `max_length` 参数控制长度
- `fallback_summarize()` 提供无 API 时的简单回退实现

### 任务 4.3：智能标签推荐 ✅ 已完成

- `ai_assistance.py` 实现 `suggest_tags()` 方法
- AI 返回 JSON 格式的标签数组
- `_fallback_suggest_tags()` 使用关键词提取作为回退

### 任务 4.4：SEO 自动优化 ✅ 已完成

- `generator.py` 实现 `build_json_ld()` 函数生成结构化数据
- `generate_article_html()` 中集成 OG meta 和 Twitter Cards
- `template.py` 的 `render_skeleton()` 支持 `json_ld_html` 参数

### 任务 4.5：多语言翻译工作流 ✅ 已完成

- `content.py` 实现 `translate_article()` 函数
- 支持英文（en）和日文（ja）翻译
- 翻译文章存储到 `en/article/` 或 `ja/article/` 目录

### Phase 5 完成状态

| 任务 | 状态 | 说明 |
|------|------|------|
| 5.1 CLI 重构 | ✅ 已完成 | `__main__.py` + `cli.py`，支持 build/serve/new-site 命令 |
| 5.2 pip 可安装 | ✅ 已完成 | `pyproject.toml` 配置正确，`tinypage` 命令可用 |
| 5.3 增量生成 | ✅ 已完成 | `core/incremental.py`，支持增量构建和缓存 |
| 5.4 Git 钩子集成 | ✅ 已完成 | pre-commit/pre-push 钩子，支持自动安装 |
| 5.5 Docker 镜像 | ✅ 已完成 | Dockerfile、docker-compose.yml、nginx.conf |
| 5.6 GitHub Actions | ✅ 已完成 | GH Pages、Cloudflare、Vercel 部署模板 |
| 5.7 API 文档生成 | 🔄 部分 | 模块 docstring 完善中 |

### 任务 5.1：CLI 重构 ✅ 已完成

- `tinypage/__main__.py` 作为 CLI 入口，调用 `cli.py`
- `tinypage/cli.py` 实现 Click 命令组
- `build` 命令：支持 `--incremental` 增量构建和 `--source` 指定源目录
- `serve` 命令：启动静态服务器和 Admin 后台
- `new-site` 命令：创建新的 TinyPage 站点，支持 blog/docs/garden 模板

### 任务 5.2：pip 可安装 ✅ 已完成

- `pyproject.toml` 配置完整的 `[project]` 和 `[project.scripts]`
- 依赖：`click`、`waitress`
- 可选依赖：`markdown`(mistune)、`syntax`(pygments)、`ai`(openai/deepseek)

### 任务 5.3：增量生成 ✅ 已完成

- `tinypage/core/incremental.py` 实现增量构建引擎
- `get_modified_files()` 检测需要重新生成的文件
- `get_unchanged_articles()` 基于缓存分割已变更/未变更文章
- `build_cache_key()` 基于文件修改时间生成缓存键
- `should_use_incremental()` 判断是否应使用增量构建

### 任务 5.4：Git 钩子集成 ✅ 已完成

- `scripts/git-hooks/install.py` 自动安装钩子脚本
- `scripts/git-hooks/pre-commit` 预提交钩子：Python 语法检查、debug 代码检测
- `scripts/git-hooks/pre-push` 预推送钩子：自动运行 `tinypage build --incremental`

### 任务 5.5：Docker 镜像 ✅ 已完成

- `Dockerfile` 基于 Python 3.12 slim 镜像
- `docker-compose.yml` 包含 TinyPage + Nginx 的完整部署
- `nginx.conf` 反向代理配置
- `.dockerignore` 排除不必要的文件

### 任务 5.6：GitHub Actions ✅ 已完成

- `.github/workflows/deploy-gh-pages.yml` GitHub Pages 部署
- `.github/workflows/deploy-cloudflare.yml` Cloudflare Pages 部署
- `.github/workflows/deploy-vercel.yml` Vercel 部署
- 支持 `workflow_dispatch` 手动触发

### 任务 5.7：API 文档生成 🔄 部分完成

- 核心模块已添加 docstring
- `tinypage/__init__.py` 需添加公共 API 文档

### 任务 2.1：模板抽象层 ✅ 已完成

- `tinypage/core/template.py` 实现 `render_skeleton()` 使用 Python 标准库 `string.Template`
- 5 个 `build_*_context()` 函数（article/list/search/standalone/category）构建模板上下文
- `_PAGE_SKELETON` 常量存储单一页面骨架，消除约 150 行重复 HTML

### 任务 2.2：主题 manifest.json ✅ 已完成

- `themes/default/manifest.json` 已创建
- `layouts: ["blog"]`（当前唯一支持的布局）
- `planned_layouts: ["doc", "garden"]` — doc/garden 布局 CSS 和 HTML 待实现
- `list_themes()` 函数扫描 `themes/` 目录加载所有主题

### 任务 2.3：多布局引擎 🔄 部分完成

- 5 个 `generate_*` 函数已全部重构使用 `render_skeleton()`
- doc/garden 布局 CSS 和 HTML 片段待实现

### 任务 2.4：主题热切换 ✅ 已完成

- Admin 后台 `/theme` GET 路由显示主题管理页
- `/set-theme` POST 路由处理主题切换
- `list_themes()` 扫描 `themes/` 目录，读取 `manifest.json`

### 任务 2.5：组件化 HTML ✅ 已完成

- 页面骨架（`<html>`, `<head>`, header, nav, footer）统一为 `_PAGE_SKELETON` 模板
- `render_skeleton()` 通过上下文字典渲染所有页面类型

---

## 5. 产品化非技术清单

### 5.1 品牌重塑

| 项目 | 当前状态 | 建议调整 |
|------|---------|---------|
| 项目名 | TinyPage | **保留**，但副标题改为 "Zero-dependency docs & garden generator" |
| GitHub 描述 | Experimental blog generator | "Single-file Python static site generator for docs and digital gardens" |
| README 首屏 | 警告不要用于生产 | **删除警告**，改为 "Production-ready for small-to-medium sites" |
| 演示站点 | 无 | 部署一个展示文档 + 花园混合布局的 demo |

### 5.2 目标用户画像

1. **Python 开源项目维护者**：需要文档站点，但不想维护 Node 工具链
2. **独立开发者/技术写作者**：想要自托管的博客 + 知识库混合站点
3. **前端 CSS 爱好者**：需要一个能跑最新 CSS 标准的真实项目来实验
4. **小型团队**：需要内部文档/wiki，但 Confluence/Notion 太贵或太复杂

### 5.3 竞品对标与超越点

| 竞品 | 优势 | TinyPage 超越点 |
|------|------|----------------|
| VitePress | Vue 生态、极快 HMR | **零 Node 依赖**、Python 原生、Admin 后台写作 |
| Docusaurus | React 生态、插件丰富 | **部署更简单**、文件即数据、无需构建步骤 |
| MkDocs | Python 原生、成熟 | **内置 Admin 后台**、现代 CSS、PWA、View Transitions |
| Quartz | 数字花园标杆 | **实时写作后台**、部署简单 10 倍 |
| Hugo | 极速生成、主题丰富 | **零配置启动**、Admin 后台、Python 可扩展 |

---

## 6. 如何使用本 Skill

### 6.1 作为开发路线图使用

当你需要决定"下一步做什么"时，打开本 Skill，查看当前所处 Phase，按任务清单逐项实现。

### 6.2 作为 Kimi Code CLI 的上下文引导使用

在与 Kimi Code CLI 对话时，先引用本 Skill：

```
请基于 tinypage-evolution skill，帮我实现 Phase 1 任务 1.3（目录/分类系统）。
```

Kimi 会自动读取本文件，理解整体架构目标，给出与长期路线图一致的具体实现。

### 6.3 作为架构决策参考使用

当面临技术选型分歧时（例如"要不要引入 Jinja2 模板引擎？"），查阅"架构调整原则"章节，确保决策不破坏核心差异化优势。

---

## 7. 迭代检查点

每完成一个 Phase，对照以下检查点确认质量：

- [ ] **零依赖承诺**：`pip install tinypage` 后，不装任何 extras 也能完整运行核心功能
- [ ] **向后兼容**：原有 `pages/` 目录结构和 HTML 注释格式不被破坏
- [ ] **Admin 可用**：所有新增功能在 Admin 后台都有对应 UI，不依赖手动编辑文件
- [ ] **测试通过**：`python test_runner.py` 通过，新增功能补充测试
- [ ] **快照更新**：`python make_snapshots.py` 生成的新快照与预期一致
- [ ] **文档更新**：README 同步更新功能列表和截图

---

## 8. 长期愿景

> TinyPage 成为 Python 生态中 "最简单但足够强大" 的静态站点生成器 —— 就像 Python 本身是"最简单但足够强大"的编程语言一样。

我们不与 VitePress 拼前端生态，不与 Hugo 拼生成速度，不与 Docusaurus 拼插件数量。我们的战场是：
- **极简部署**（一个文件，pip install 即运行）
- **实时写作体验**（Admin 后台是核心竞争力）
- **Python 原生扩展**（用 Python 写插件，而非 JavaScript）
- **现代 WEB 标准先锋**（最新 CSS 特性的首发展示平台）

保持简单，保持差异化，保持迭代。
