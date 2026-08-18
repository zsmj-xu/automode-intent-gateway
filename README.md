# AutoMode Intent Gateway

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue)](https://www.python.org/)
[![Node 20+](https://img.shields.io/badge/Node-20%2B-green)](https://nodejs.org/)
[![Docker](https://img.shields.io/badge/Docker-Compose%20Ready-2496ed)](docker-compose.yml)

一个位于 **Agent 与模型之间**的透明观察网关。它原样转发 Anthropic 与 OpenAI 请求/流式响应，从**模型响应**提取真实工具调用，并按 `Rules → Fast LLM → Deep LLM` 三级流水线判断工具意图是否符合用户授权。MVP 处于 **Observe 模式**：安全动作直接允许，其余动作升级复核并产生告警，但**不阻断** Agent。

控制台提供总览、会话时间线、三级判定瀑布、告警、自然语言规则、测试实验室和模型设置。

## 特性

- **双协议透明代理**：Anthropic Messages / OpenAI Chat Completions / OpenAI Responses，JSON 与 SSE 流式原样转发，零协议转换。
- **三级意图判定**：`Rules → Fast LLM → Deep LLM`，规则短路安全/必告警动作，LLM 只处理语义不确定性。
- **去推理化审查**：分类器只看到真实用户文本与历史/当前工具调用，剔除 thinking/reasoning、普通回答、system/developer、tool result 与 Claude system reminder。
- **自然语言规则**：受限结构化编译（不执行规则文本中的代码），支持预览、测试、确认、启停、版本与回滚。
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
│  │  代理转发  │ → │ 响应工具抽取    │ → │  三级判定流水线 (Observe) │  │
│  │ (原样字节) │   │ tool_use 等   │   │  Rules → Fast → Deep │  │
│  └──────────┘   └──────────────┘   └──────────┬────────────┘  │
│        │ 存储/事件/告警                         │ allow / alert   │
│  SQLite  TraceStore ── SSE ── 管理控制台 / API  │ (不阻断、不执行)  │
└───────────────────────────────────────────────────────────────┘
        │  原始字节透传（不改写）
        ▼
   上游模型 (LiteLLM / Anthropic / OpenAI / 自建)
```

请求中的 `tools` 只是能力声明，不作为执行意图；只有模型响应中的 `tool_use`、`tool_calls` 或 `function_call` 才是本轮拟执行动作。

### 三级判定流水线

```text
Rules SAFE          → allow            （零 LLM 调用）
Rules ALWAYS_ALERT  → alert            （规则短路）
Rules RISKY/UNKNOWN → Fast LLM（无思考）→ allow → allow
                     └ reject/error → Deep LLM（带思考）→ allow → allow
                                                      └ reject/error → alert
```

未配置 Fast/Deep 时，风险动作按 **fail-alert** 原则告警；安全、无工具动作的请求仍由 Rules 直接允许。

## 快速开始（本地）

需要 Python 3.9+ 与 Node.js 20+：

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
npm --prefix web install
npm --prefix web run build
```

设置模型上游并启动：

```bash
export AUTOMODE_UPSTREAM_BASE_URL=http://127.0.0.1:4000
.venv/bin/auto-intent serve --host 127.0.0.1 --port 8787
```

打开 `http://127.0.0.1:8787/`。默认数据库是 `automode.db`；可通过 `--db` 指定路径，通过 `--no-store-raw` 关闭原始请求保存。

Agent 接入时，Anthropic Base URL 使用 `http://127.0.0.1:8787`；OpenAI 客户端通常使用 `http://127.0.0.1:8787/v1`。不同 SDK 拼接 `/v1` 的方式不同，最终落到上表中的路径即可。

## Docker Compose 部署

仓库自带 `Dockerfile`（多阶段：Node 构建控制台 → Python 运行网关）与 `docker-compose.yml`。服务器上部署：

```bash
cp .env.example .env        # 编辑 .env：必填 AUTOMODE_UPSTREAM_BASE_URL 与 AUTOMODE_ADMIN_TOKEN
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
| `AUTOMODE_UPSTREAM_BASE_URL` | ✅ | — | 上游模型服务地址（serve 也可用 `--upstream`） |
| `AUTOMODE_ADMIN_TOKEN` | 非本机监听 ✅ | — | 管理 API 的 Bearer Token（`/api/*`） |
| `AUTOMODE_UPSTREAM_API_KEY` | | 透传 Agent 头 | 上游统一 Bearer Key |
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
| `/api/rules` | 自然语言规则编译、测试、启停、版本与回滚 |
| `/api/playground/classify` | 三协议、临时规则、Rules-only 或完整管线测试，不执行工具 |
| `/api/events` | SSE 实时事件（Trace/阶段/分类/告警/规则） |
| `/traces`、`/traces/{id}` | 兼容的 Trace 查询接口 |

响应附带 `x-automode-trace-id`，便于从 Agent 日志定位会话。`Server-Timing` 记录转发关键路径内部耗时。

## 数据与安全边界

- 请求头中的 Authorization、Cookie、API Key、Token 等落库前统一脱敏。
- 请求体中的常见密钥字段和疑似 Token 字符串会脱敏。
- reasoning/thinking/analysis 不进入分类记录、测试记录或告警。
- 模型普通回答不持久化；为提取工具调用，仅在内存中限量捕获响应，默认 8 MiB。
- 超过捕获上限时仍持续流式转发，并以 `response_capture_incomplete` 进入告警。
- 非 loopback 监听必须设置 `AUTOMODE_ADMIN_TOKEN`，管理 API 未授权返回 401。
- 该网关只能观察模型拟调用的工具。真正阻断 Shell、MCP、HTTP 等动作需要后续 Action Gateway/Enforce 模式。

## 项目结构

```text
automode_gateway/   # Python 后端：代理、协议解析、规则、流水线、存储
  gateway.py        #   透明代理与请求入口
  pipeline.py       #   三级判定流水线（Rules → Fast → Deep）
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
  --include='automode_gateway/classifier.py,automode_gateway/decision.py,automode_gateway/pipeline.py,automode_gateway/policy.py,automode_gateway/rule_compiler.py' \
  --fail-under=90
npm --prefix web test
npm --prefix web run build
npm --prefix web audit
```

当前基线：后端 76 个测试、前端 4 个测试全部通过；核心判定与规则模块分支覆盖率 ≥ 90%。

## 文档

- `docs/implementation-plan.md`：完整实施方案
- `docs/acceptance-criteria.md`：验收标准（P0/P1/E2E）
- `docs/acceptance-report.md`：实测验收报告（P0 28/28、P1 20/20、E2E 10/10 PASS）

## 路线图

- [x] 双协议透明代理（Anthropic / OpenAI Chat / OpenAI Responses）
- [x] 三级意图判定流水线与去推理化审查
- [x] 自然语言规则管理与控制台
- [x] Docker Compose 部署
- [ ] **Enforce / Action Gateway**：真正阻断未授权工具调用
- [ ] SSO / RBAC 管理端
- [ ] 多机部署（共享数据库与事件总线）

## 许可证

[MIT](LICENSE)
