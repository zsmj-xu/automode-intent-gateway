# AutoMode Enterprise AI Shadow DLP Gateway

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue)](https://www.python.org/)
[![Node 20+](https://img.shields.io/badge/Node-20%2B-green)](https://nodejs.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose%20Ready-2496ed)](docker-compose.yml)

一个提供**标准事件入口、独立分析引擎与管理端**的企业 AI 出站数据合规服务。外部接入服务可以提交模型请求与响应事件；原 Agent 到模型的透明代理保留为可选适配器。分析完整出站 JSON，结合可信身份和模型目标识别敏感数据外发。MVP 处于 **Shadow / Observe 模式**：命中策略时记录和告警，但**不阻断**模型调用。

控制台提供 DLP 总览、出站请求时间线、告警、自然语言数据策略、目标注册表、测试实验室和加密证据调查。

## 特性

- **多协议透明代理**：Anthropic Messages / OpenAI Chat Completions / OpenAI Responses，JSON 与 SSE 流式原样转发，零协议转换。
- **完整出站请求检测**：扫描 user/system/developer、tool result、历史消息和工具描述中的文本。
- **可治理的本地检测**：内置检测器与管理员自定义正则均可按类别启停；识别凭据、Token、密码、私钥、连接串、PII、源码/配置及管理员关键词。
- **目标与身份上下文**：模型注册表区分 trusted/external；可信代理网段注入用户、部门、角色和 Agent。
- **确定性策略优先**：敏感数据发往 external 目标直接告警，LLM 不能推翻硬策略。
- **加密证据**：Trace 只保存脱敏请求；原文使用 AES-256-GCM 加密保存并审计每次查看。
- **兼容旁证**：模型工具调用和旧动作规则继续保留，但不参与 DLP 主判定。
- **会话风险态势**：后台识别用户目的风险与外发动作意图；high/critical 升级会告警，但不代表动作已发生、更不会阻断请求。
- **实时控制台**：总览、会话时间线、判定瀑布、告警中心、规则管理、测试实验室、模型设置，SSE 实时刷新。
- **安全落库**：凭据脱敏、reasoning 不持久化、响应捕获有界、管理 API 强制 Token。

## 架构

```text
 Agent (Claude Code / OpenAI SDK)
        │  POST /v1/messages | /v1/chat/completions | /v1/responses
        ▼
┌───────────────────────────────────────────────────────────────┐
│                    AutoMode Intent Gateway                     │
│  ┌──────────┐   ┌──────────────┐   ┌───────────────────────┐  │
│  │ 完整请求扫描 │ → │ 数据/身份/目标归一 │ → │ DLP 策略 (Shadow)     │  │
│  │ (分析副本)  │   │ 本地确定性检测     │   │ allow / alert         │  │
│  └──────────┘   └──────────────┘   └──────────┬────────────┘  │
│        │ 存储/事件/告警                         │ allow / alert   │
│  SQLite  TraceStore ── SSE ── 管理控制台 / API  │ (不阻断、不执行)  │
└───────────────────────────────────────────────────────────────┘
        │  原始字节透传（不改写）
        ▼
   上游模型 (LiteLLM / Anthropic / OpenAI / 自建)
```

未注册模型默认视为 external。模型响应中的 `tool_use`、`tool_calls` 或 `function_call` 会被记录为调查旁证，但不会改变出站数据策略结论。

### Shadow DLP 判定流水线

```text
完整请求 → 本地敏感检测 → 目标注册表 → 企业数据策略 → allow / alert
                         ├ 未注册目标 = external
                         ├ sensitive + external = alert
                         └ Shadow 模式始终继续转发
```

检测线索或 `review` 策略触发 Fast/Deep 脱敏复核。规则与 LLM 分别记录结论：规则高危／严重不会因 LLM 失败或无告警而降级，中危规则被 LLM 确认后升为至少高危。LLM 失败、未完成和明确无告警分别展示；不完整正文不能被视为完整检查通过。

## 快速开始（本地）

需要 Python 3.9+ 与 Node.js 20+：

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
npm --prefix web install
npm --prefix web run build
```

启动独立事件服务（无需配置模型上游）：

```bash
export AUTOMODE_ADMIN_TOKEN=replace-with-a-random-token
.venv/bin/auto-intent evidence-key .automode-evidence.key
export AUTOMODE_EVIDENCE_KEY_FILE="$PWD/.automode-evidence.key"
export AUTOMODE_TRUSTED_PROXY_CIDRS=127.0.0.0/8,::1/128
.venv/bin/auto-intent serve --host 127.0.0.1 --port 8787
```

在控制台“事件 → 来源与授权”创建接入来源，使用来源 Token 提交 `POST /v1/events`。标准入口需要加密密钥，持久化完成后返回 `202`；来源 Token 与管理 Token 分离。完整契约及示例见 [标准事件接入](docs/event-ingress.md)。

要同时启用原代理，启动前设置 `AUTOMODE_UPSTREAM_BASE_URL=http://127.0.0.1:4000`。代理异步投递审计事件，落盘前存在进程崩溃丢失窗口；管理端分别展示磁盘缓冲与代理可靠性。未配置密钥时，代理仅提供有界的尽力分析，不具备事件恢复保证。

历史 Trace 迁移为加密证据并用脱敏副本替换：

```bash
.venv/bin/auto-intent migrate-evidence --db automode.db --key-file .automode-evidence.key
```

打开 `http://127.0.0.1:8787/`。默认数据库是 `automode.db`；可通过 `--db` 指定路径，通过 `--no-store-raw` 关闭原始请求保存。

Agent 接入时，Anthropic Base URL 使用 `http://127.0.0.1:8787`；OpenAI 客户端通常使用 `http://127.0.0.1:8787/v1`。不同 SDK 拼接 `/v1` 的方式不同，最终落到上表中的路径即可。

## Docker Compose 部署

仓库自带 `Dockerfile`（多阶段：Node 构建控制台 → Python 运行网关）与 `docker-compose.yml`。服务器上部署：

```bash
cp .env.example .env        # 编辑 .env：设置 AUTOMODE_ADMIN_TOKEN；模型代理的 upstream 可选
docker compose up -d --build
docker compose ps           # 等待 healthy
curl -H "Authorization: Bearer $AUTOMODE_ADMIN_TOKEN" http://127.0.0.1:8787/health
```

- 控制台与 API：`http://<服务器>:8787/`；管理 API 需要 `Authorization: Bearer <AUTOMODE_ADMIN_TOKEN>`。
- 启用 `AUTOMODE_ADMIN_TOKEN` 后，控制台首次打开会显示“管理端认证”界面，输入 Token 后保存在浏览器本地存储，用于访问本网关的管理 API。
- 上游模型服务：外部地址直接填；宿主机上的服务填 `http://host.docker.internal:PORT`（compose 已配置 `extra_hosts`）；同一 Docker 网络内的容器填服务名，如 `http://litellm:4000`。
- SQLite 数据持久化在命名卷 `automode-data`（容器内 `/app/data/automode.db`）；升级镜像后数据保留。
- 控制台静态目录默认按源码位置解析；wheel 安装（如 Docker 镜像）时通过 `AUTOMODE_WEB_DIST` 指向 `web/dist`（镜像已内置，无需手动配置）。
- 生产建议在网关前加反向代理提供 TLS，并限制 `8787` 端口的公网暴露。

## 配置参考

| 环境变量 | 必填 | 默认 | 说明 |
|---|---|---|---|
| `AUTOMODE_UPSTREAM_BASE_URL` | | — | 配置时启用模型代理；为空则为独立事件服务（也可用 `--upstream`） |
| `AUTOMODE_ADMIN_TOKEN` | 非本机监听 ✅ | — | 管理 API 的 Bearer Token（`/api/*`） |
| `AUTOMODE_UPSTREAM_API_KEY` | | 透传 Agent 头 | 上游统一 Bearer Key |
| `AUTOMODE_TRUSTED_PROXY_CIDRS` | | — | 可信身份头直连来源网段；不读取 X-Forwarded-For |
| `AUTOMODE_EVIDENCE_KEY_FILE` | | — | 0600 的本地 AES-256-GCM 密钥文件 |
| `AUTOMODE_FAST_URL` / `AUTOMODE_FAST_MODEL` / `AUTOMODE_FAST_API_KEY` | | — | Fast 分类器（无思考），OpenAI Chat Completions 兼容 |
| `AUTOMODE_DEEP_URL` / `AUTOMODE_DEEP_MODEL` / `AUTOMODE_DEEP_API_KEY` | | — | Deep 分类器（带思考） |
| `AUTOMODE_FAST_TIMEOUT` / `AUTOMODE_DEEP_TIMEOUT` | | `10` | 分类请求超时（秒） |
| `AUTOMODE_FAST_MAX_TOKENS` / `AUTOMODE_DEEP_MAX_TOKENS` | | `2400` | 分类输出上限，截断时按提示调大 |
| `AUTOMODE_RESPONSE_CAPTURE_BYTES` | | `8388608` | 响应捕获上限（8 MiB），超限仍流式转发并告警 |
| `AUTOMODE_DB_FLUSH_INTERVAL_MS` | | `25` | 落库合并间隔（毫秒） |
| `AUTOMODE_DB` | | `automode.db` | SQLite 路径（serve 也可用 `--db`） |
| `AUTOMODE_WEB_DIST` | | 源码相对路径 | 控制台静态目录（wheel 安装时指向 `web/dist`） |

Fast/Deep 也可在控制台“设置”页临时应用 URL、模型和 Key。Key 只写入当前网关进程环境，API 只返回末四位掩码，SQLite 不保存凭据。模型名末尾空格或中英文引号会被拒绝。

## 控制台与 API

| 路径 | 说明 |
|---|---|
| `/` | 管理控制台 |
| `/health` | 网关、上游与分类器配置状态 |
| `/api/dashboard` | 健康状态、请求/会话/判定统计与延迟 |
| `/api/sessions` | 会话列表，支持时间、协议、模型、风险、判定、能力筛选 |
| `/api/sessions/{id}/timeline` | 会话时间线（用户→模型→动作→三级阶段→最终结果） |
| `/api/alerts` | 告警查询、状态流转（open/acknowledged/false_positive/resolved）与人工反馈 |
| `/api/destinations` | 模型目标注册表，维护模型模式、供应商、区域和信任级别 |
| `/api/dlp-policies` | 出站数据策略编译、测试、启停和版本 |
| `/api/detectors` | 内置及自定义正则检测器的查询、启停、创建和删除；自定义规则先经本地正则校验 |
| `/api/evidence/{id}/raw` | 仅 loopback + 管理 Token 可用的加密原文查看，并记录访问审计 |
| `/api/rules` | 兼容的模型动作旁证规则 |
| `/api/playground/classify` | 三协议完整出站请求 DLP 测试，不执行工具、不转发模型 |
| `/api/events` | SSE 实时事件（Trace/阶段/分类/告警/规则） |
| `/traces`、`/traces/{id}` | 兼容的 Trace 查询接口 |

响应附带 `x-automode-trace-id`，便于从 Agent 日志定位会话。`Server-Timing` 记录转发关键路径内部耗时。

## 数据与安全边界

- 请求头中的 Authorization、Cookie、API Key、Token 等落库前统一脱敏。
- 普通 Trace 中的凭据、PII、源码/配置和管理员关键词会在落库前脱敏。
- 原文证据只在配置密钥后使用 AES-256-GCM 加密保存；密钥必须位于 0600 文件中。
- 原文证据默认保留 30 天；查看接口要求 loopback、管理 Token，并写入独立访问日志。
- reasoning/thinking/analysis 不进入分类记录、测试记录或告警。
- 模型普通回答不持久化；为提取工具调用，仅在内存中限量捕获响应，默认 8 MiB。
- 超过捕获上限时仍持续流式转发，并以 `response_capture_incomplete` 进入告警。
- 非 loopback 监听必须设置 `AUTOMODE_ADMIN_TOKEN`，管理 API 未授权返回 401。
- 当前网关只观察和告警敏感数据外发，不阻断模型请求；真正防外发需要后续 Request Enforce。模型工具动作仍只是旁证，若要阻断 Shell、MCP、HTTP，还需要独立 Action Gateway。
- 会话风险识别区分“用户目的风险”和“外发动作意图”；后者不代表网盘上传或 Git 推送已发生。低置信度风险 reviewer 可接收实时用户原文，但风险记录、API、SSE 和控制台不保存或显示该原文。
- 当前网关只观察和告警敏感数据外发，不阻断模型请求；真正防外发需要后续 Request Enforce。模型工具动作仍只是旁证，若要阻断 Shell、MCP、HTTP，还需要独立 Action Gateway。

## 项目结构

```text
automode_gateway/   # Python 后端：代理、协议解析、规则、流水线、存储
  gateway.py        #   透明代理与请求入口
  pipeline.py       #   三级判定流水线（Rules → Fast → Deep）
  dlp.py            #   完整请求扫描、可信身份、目标解析和策略判定
  evidence.py       #   AES-GCM 密钥加载、加密和解密
  dlp_rule_compiler.py # 自然语言出站数据策略编译
  human_request.py  #   兼容的人类需求分类能力
  classifier.py     #   本地正则基线分类器（意图/能力/风险/敏感度）
  policy.py         #   规则评估与 CompileRule
  rule_compiler.py  #   自然语言规则 → 受限结构化条件
  llm_classifier.py #   Fast/Deep 分类器 HTTP 传输
  response_parser.py#   从 JSON/SSE 响应提取工具调用
  review_context.py #   去推理化审查上下文构建
  storage.py        #   SQLite TraceStore（10 张表，WAL，脱敏）
  admin_api.py      #   管理 API 与测试实验室
web/                # React + TypeScript + Vite 控制台
tests/              # 后端回归与性能测试
docs/               # 实施计划、验收标准与验收报告
examples/           # 示例请求日志
```

## 验证

```bash
.venv/bin/coverage run -m unittest discover -s tests
.venv/bin/coverage report -m
.venv/bin/coverage report \
  --include='automode_gateway/dlp.py,automode_gateway/evidence.py,automode_gateway/dlp_rule_compiler.py' \
  --fail-under=85
npm --prefix web test
npm --prefix web run build
npm --prefix web audit
```

当前本地基线（2026-09-09）：后端 204 个测试、前端 9 个测试和生产构建通过。事件接入与代理修复的范围和验证见 [代码审查修复记录](docs/event-refactor-review-fixes.md)；这不是生产部署或全量容量验证。

## 文档

- `docs/implementation-plan.md`：现役 Shadow DLP 架构、数据流和安全边界
- `docs/acceptance-criteria.md`：当前 DLP、证据、管理面和兼容验收标准
- `docs/acceptance-report.md`：2026-08-28 本地实测结果与未验证项
- `docs/frontend-redesign.md`：当前控制台信息架构和交互规范

## 路线图

- [x] 多协议透明代理（Anthropic / OpenAI Chat / OpenAI Responses）
- [x] 完整出站请求 Shadow DLP 与目标注册表
- [x] 自然语言出站数据策略与治理控制台
- [x] AES-GCM 原文证据、30 天留存与访问审计
- [x] Docker Compose 部署
- [ ] **Request Enforce**：在上游模型调用前真正阻断危险需求
- [ ] **Action Gateway**：独立阻断未授权工具调用
- [ ] SSO / RBAC 管理端
- [ ] 多机部署（共享数据库与事件总线）

## 许可证

[MIT](LICENSE)
