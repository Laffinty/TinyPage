# syntax=docker/dockerfile:1
#
# TinyPage —— **纯 WLWL** 运行时镜像（无 Python、无 nginx）
# ⚠ 本文件由 S6-1 卡产出，**尚未在真 Docker 上构建过**（本机没有 docker，见计划书 S6-1 状态）。
#   已验证的部分：容器要用的环境变量/端口/路径契约（本机直跑三入口 + curl，见计划书）。
#   未验证的部分：镜像能否构建、起栈后 curl -k https://localhost/ 是否 200。
#
# ── 为什么是 Windows 容器 ────────────────────────────────────────────
# WLWL 编译器**只有** Windows MSVC 构建（`wlwl-v0.12.1-x86_64-pc-windows-msvc.zip`，
# 没有 linux/musl 产物）⇒ 基础镜像必须是 Windows。
# 又因为 `wlwl.exe` 的导入表含 **VCRUNTIME140.dll**（实测：二进制里能找到该导入名），
# 而 nanoserver 不带它 ⇒ 用 servercore。
#
# ── WLWL 运行时从哪来 ────────────────────────────────────────────────
# `wlwl.exe` 与 `lib/` **不入库**（体积 + 来源纪律），构建前放到构建上下文的
# `wlwl-runtime/`：
#   wlwl-runtime/wlwl.exe
#   wlwl-runtime/lib/wlwl_tls.dll
#   wlwl-runtime/lib/stdlib/*.wll
#   wlwl-runtime/lib/ABI_VERSION
# 目录不存在时 `COPY` 直接失败（fail-closed，不会静默产出一个跑不起来的镜像）。
#
# 构建：
#   docker build -t tinypage:wlwl .

FROM mcr.microsoft.com/windows/servercore:ltsc2022

# TLS 扩展的 SHA-256（小写 hex，64 字符）。宿主强制校验，不匹配即拒绝加载。
ARG WLWL_TLS_SHA256=202379c21f2c2950635442fce895d71383a9e100e2eac65a2fd0e1da42e3599b

# ── WLWL 运行时 ─────────────────────────────────────────────────────
COPY wlwl-runtime/ C:/opt/wlwl/
ENV PATH="C:\\opt\\wlwl;${PATH}"

WORKDIR C:\\app

# ── 站点代码 ────────────────────────────────────────────────────────
# tp/ 是 S1–S5 的全部实现（lib/ 26 个模块 + bin/ 4 个入口）。
# 它的父目录决定项目根：`./../lib/*.wll` 这类相对 IMPORT 依赖这条链。
COPY tp/ tp/

# ── 内容与主题（运行时用 volume 覆盖，见 docker-compose.yml）────────
COPY themes/ themes/
COPY admin_templates/ admin_templates/
COPY static_inject/ static_inject/

# 证书与私钥**不进镜像**：由 compose 把 ./certs 挂到 C:\\app\\certs
RUN mkdir C:\\app\\pages C:\\app\\certs

ENV TP_ROOT=C:\\app\\pages

# 默认只给用法；每个服务在 compose 里覆盖 command。
# 公开站有两个入口且**不能同进程**（同进程两个 *_SERVE 会串行冻结运行时）：
#   tp/bin/serve_tls.wll     —— 443，tls.LISTEN（需 --ext）
#   tp/bin/serve_public.wll  —— 明文，仅当明确需要 80 时用
CMD ["wlwl.exe", "run", "tp\\bin\\serve_tls.wll"]
