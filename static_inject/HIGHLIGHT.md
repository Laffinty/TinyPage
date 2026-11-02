# 前端代码高亮资产（highlight.js）

本目录下的两个第三方/项目资产，用于在浏览器端给围栏代码块上色：

| 文件 | 字节数 | 性质 |
| --- | ---: | --- |
| `highlight.min.js` | 124980 | 第三方压缩包，原样入库，**banner 与许可未改动** |
| `highlight-theme.css` | 3197 | 本项目自写（token 配色），非上游主题拷贝 |

## 1. highlight.js

- **版本**：`11.10.0`（banner 内标注 `git: 366a8bd012`）
- **来源 URL**：
  `https://cdn.jsdelivr.net/npm/@highlightjs/cdn-assets@11.10.0/highlight.min.js`
  （`@highlightjs/cdn-assets` 的默认包 = "common languages" 构建，实测 `listLanguages()` 返回 36 种语言）
- **取回日期**：2026-11-02
- **字节数 / 校验**：`124980` 字节，`sha256 = 471ef9ae90c407af440fcdc48edfeeb562106b3267bd12d99071c162fb52ed32`
- **许可**：BSD-3-Clause。文件首个注释块为原始 banner，**必须原样保留**：

```js
/*!
  Highlight.js v11.10.0 (git: 366a8bd012)
  (c) 2006-2024 Josh Goebel <hello@joshgoebel.com> and other contributors
  License: BSD-3-Clause
 */
```

## 2. 用法（接线时页面需要什么）

静态注入是按**站点根路径**暴露的（`tinypage/frontend.py:25` 把 `static_inject/` 下每个文件映射成
`/<filename>`，与 `/search.js`、`/htmx.min.js` 同体例），所以引用路径是：

```html
<link rel="stylesheet" href="/highlight-theme.css">
<script src="/highlight.min.js" defer></script>
<script defer>hljs.highlightAll();</script>
```

要点：

1. **必须显式调用 `hljs.highlightAll()`**。这个构建**不会自动高亮**——实测文件里是
   `let w=!1;` 加 `window.addEventListener("DOMContentLoaded",()=>{w&&N()})`，即
   `w` 只在「DOM 还没解析完就调了 highlightAll」时才置真，属于**延迟补跑**，不是自动启动。
   两个 `defer` 脚本按顺序在 DOMContentLoaded 之前执行，所以第二段可直接调用。
2. **不需要额外配置语言探测**：`md.wll` 产出的围栏代码块已经是
   `<pre><code class="language-xxx">`，highlight.js 默认就认 `class="language-*"`；
   它会自行给 `<code>` 加上 `class="hljs"`，主题 CSS 就是以 `.hljs` 为作用域根。
3. **必须自托管、不能引 CDN**：`tinypage/security.py:349` 的 CSP 是
   `script-src 'self' 'unsafe-inline'`，外域脚本会被浏览器拦掉。
4. **PWA 离线缓存未覆盖**：`static_inject/sw.js` 的预缓存清单里没有这两个文件；
   若接线并要求离线可用，需要另行加入（本卡未改，属接线阶段的事）。

> 当前状态：**没有任何页面引用这两个资产**。是否注入 `<script>`/`<link>` 与
> 「构建产物与 Python 逐字节相同」这条约束存在冲突，业主正在裁决；本卡只交付资产。

## 3. 主题 CSS 的约定

- **只写 token 颜色**（`.hljs-keyword`、`.hljs-string` 等），**不写** `pre code {}` 这类
  会影响布局的规则。代码块背景、内边距、圆角、顶部渐变条都由
  `themes/default/theme.css` 的 `pre` / `pre code`（`theme.css:119`、`theme.css:136`）负责。
- **明暗切换跟本站机制走**：本站**默认暗色**（`:root` 里就是暗色 palette），明色靠
  `<html class="light">` 切换（`themes/default/theme.css:59` 的 `html.light {}`；
  页面里由注入脚本 `document.documentElement.classList.add('light')` 添加）。
  因此 CSS 用「默认暗色 + `html.light` 覆盖」两套 palette，**故意不用
  `@media (prefers-color-scheme: dark)`** —— 本站主题由 class 决定，不跟随 OS 偏好，
  用媒体查询会出现「页面是暗的、代码块是亮的」这种错配。
- 两套 palette 以 CSS 变量挂在 `.hljs` 上，token 规则统一 `color: var(--hljs-*)`，
  改色只需改两个变量块。
- 覆盖已实测：用 python/javascript/xml/css/bash 五个样例实际高亮，收集到的
  `hljs-*` class 在 CSS 中**全部有对应规则**（见下方自查记录）。

## 4. 为什么不用服务端 Pygments

Python 生成路径用的是**服务端 Pygments**（`tinypage/parsers/syntax.py`），已被裁决**不迁移**
（计划 §0 的 D3、cards 里的 D7）。原因是两条渲染路径要保持可对齐的产物，而 Pygments
会把颜色写死进 HTML（内联 style 或固定 class），与本站的 CSS 变量主题、暗色切换都冲突：

- 服务端上色 ⇒ 颜色在构建时定死，`html.light` 切换时无法换配色；前端 token class 则跟着 CSS 走。
- 服务端上色 ⇒ 需要构建期依赖 Pygments 及其词法包；前端只需一个静态文件，无运行时依赖。
- 服务端上色 ⇒ 产物体积膨胀（每个 token 一个 `<span>` 带样式）；前端只是在已有 `<code>` 内加 class。

所以高亮改到前端，颜色交给 CSS，主题切换天然生效。

## 5. 自查记录（真实执行）

环境：Windows + PowerShell 5.1，`node` 位于 `C:\Program Files\nodejs\node.exe`（**有 node**）。

```text
node --check static_inject/highlight.min.js        -> exit 0（语法通过）
首行 = "/*!"，banner 第 2..5 行含 v11.10.0 / BSD-3-Clause（原文见 §1）
contains("hljs")                = True
contains("highlightElement")    = True
contains("document.write")      = False
CR 字符                          = False（LF 换行，124980 字符 == 124980 字节，无 BOM）
node require(...)               -> versionString=11.10.0, typeof highlightElement=function,
                                   languages=36, python/javascript 均可用
token 类覆盖                     -> 5 个样例实际高亮产出 15 个 hljs-* class，missing_rules=none
```
