# AutoMode Intent Gateway MVP 验收报告

## 1. 验收结论

| 字段 | 内容 |
|---|---|
| 验收版本/Commit | `automode/` 当前工作区（未纳入父仓库提交） |
| 验收日期 | 2026-08-18（项目整理复核） |
| 验收环境 | macOS arm64；venv Python 3.14.3；Node.js 23.11.0；npm 10.9.2 |
| Fast 模型 | 自动测试使用固定 Schema Mock；未配置时验证 fail-alert |
| Deep 模型 | 自动测试使用固定 Schema Mock；未配置时验证 fail-alert |
| 上游网关 | 本机 aiohttp/HTTP 测试上游，覆盖 JSON、SSE、错误、超时与大响应 |
| 自动化测试结果 | 后端 75/75；前端 3/3；构建成功；npm audit 本次 BLOCKED（registry DNS） |
| P0 结果 | 28/28 PASS |
| P1 结果 | 20/20 PASS |
| E2E 结果 | 10/10 PASS |
| 已知 P2 延期项 | Enforce/Action Gateway、正式 SSO/RBAC、外部可观测平台、生产数据库 |
| 最终结论 | **PASS（Observe MVP）** |

本报告验证的是网关侧 Observe MVP。它不会执行或阻断 Agent 工具；判定为危险时记录告警。真正的执行前阻断属于后续 Action Gateway/Enforce 阶段。

## 2. 发布门禁证据

### 2.1 自动化与覆盖率

最终命令：

```bash
.venv/bin/coverage erase
.venv/bin/coverage run -m unittest discover -s tests
.venv/bin/coverage report -m
.venv/bin/coverage report \
  --include='automode_gateway/classifier.py,automode_gateway/decision.py,automode_gateway/pipeline.py,automode_gateway/policy.py,automode_gateway/rule_compiler.py' \
  --fail-under=90
npm --prefix web test
npm --prefix web run build
npm --prefix web audit --audit-level=high
```

结果：

- Python：75 个测试全部通过，无跳过；新增外部数据自然语言规则与 `Bash curl/wget` 只读识别回归。
- 后端整体覆盖率：86%，门槛 80%。
- 核心判定与规则模块分支覆盖率：93%，门槛 90%。
- React 组件/核心流程：3 个测试全部通过。
- TypeScript 检查与 Vite production build 成功；JS gzip 约 69.6 KiB。
- npm 官方审计：本次运行因无法解析 `registry.npmjs.org` 被阻塞；`package-lock.json` 未改动，需在可联网环境重跑。

### 2.2 性能与可靠性

| 场景 | 实测 | 门槛 | 结果 |
|---|---:|---:|---|
| Rules 直接允许，1000 次 P95 | 0.110 ms | < 10 ms | PASS |
| 100 并发流，网关内部关键路径 P95 | 0.030 ms | < 50 ms | PASS |
| 1000 Trace/100 会话/200 告警查询 | 7.693 ms | < 1 s | PASS |
| 控制台总览聚合 | < 2 s（自动断言） | < 2 s | PASS |
| 大响应 | 50 MiB 完整透传，分析缓冲有界 | 不崩溃、不误放行 | PASS |
| 客户端中途断连 | Trace=`client_disconnected`，无伪造动作 | 服务继续健康 | PASS |

### 2.3 控制台人工检查

使用本机真实 HTTP 管理 API 和 production build 检查：

- 1440px、1024px、768px 下无页面级横向滚动。
- 桌面侧栏与移动抽屉可用；Escape 能关闭抽屉；交互元素具有可见焦点。
- 总览展示 Gateway/上游/Fast/Deep 健康状态、请求/会话/允许/告警、阶段数量、P50/P95 与最近告警。
- 会话筛选覆盖时间、协议、模型、风险、结果、能力，并同步 URL 查询参数。
- 测试实验室可以切换三种协议、表单/原始 JSON、历史/当前工具、临时规则、Rules-only/完整管线。
- 控制台检查时无浏览器 console error/warning。
- 风险同时使用图标、文字和 reason code，不只依赖颜色。

## 3. P0 逐项验收

| ID | 结果 | 可重复证据 |
|---|---|---|
| AC-P0-001 | PASS | `test_pipeline.py`：SAFE 直接 allow，Fast/Deep 0 调用 |
| AC-P0-002 | PASS | 风险进入 Fast；请求 payload 的 thinking=false，固定 Schema 校验 |
| AC-P0-003 | PASS | Fast allow 后停止，final_stage=`fast_llm` |
| AC-P0-004 | PASS | Fast reject/uncertain 进入 thinking=true 的 Deep，传递结构化前序结论 |
| AC-P0-005 | PASS | 401/403/500、超时、空输出、length、JSON/枚举错误均标记 error 并升级 |
| AC-P0-006 | PASS | Deep reject 生成 open 告警，包含动作、证据、会话和原因 |
| AC-P0-007 | PASS | Deep 异常稳定返回 `DEEP_CLASSIFIER_UNAVAILABLE` 并 fail-alert |
| AC-P0-008 | PASS | `always_alert` 在 Rules 短路，绑定规则 ID/版本，LLM 0 调用 |
| AC-P0-009 | PASS | 审查记录仅含真实 user 与历史/当前 tool call，保持顺序 |
| AC-P0-010 | PASS | 请求 `tools` 仅计 declared count；无模型工具调用即 proposed=[] |
| AC-P0-011 | PASS | assistant 普通解释被剔除，`git push` 仍匹配“不要 push” |
| AC-P0-012 | PASS | tool result 不进入审查记录且不能扩大授权 |
| AC-P0-013 | PASS | Anthropic JSON/SSE/tool_use 分片/tool_result/原始字节集成测试 |
| AC-P0-014 | PASS | OpenAI Chat JSON/SSE/多工具/旧 function_call/跨 chunk/role=tool |
| AC-P0-015 | PASS | Responses JSON/SSE/function_call；output/reasoning 被剔除 |
| AC-P0-016 | PASS | gzip/deflate 解析；线上字节透明；解压失败转分析缺失 UNKNOWN/告警 |
| AC-P0-017 | PASS | 400/401/429/500 原样返回并记录；超时记录 `TimeoutError`；不伪造动作 |
| AC-P0-018 | PASS | 中文规则编译为受限结构，publish/always_alert/稳定 reason code |
| AC-P0-019 | PASS | 原文+结构预览，新规则默认禁用，always_alert 强制确认，字段级建议 |
| AC-P0-020 | PASS | 规则测试返回命中和证据，明确 executed=false/forwarded=false |
| AC-P0-021 | PASS | 启停 API、UI switch、即时 enabled rule 查询与历史版本保留 |
| AC-P0-022 | PASS | 修改增版、查看历史、任意版本回滚、新版生成和审计日志 |
| AC-P0-023 | PASS | 未知字段/非法 effect/代码 SQL/空 reason/非法 scope 均拒绝 |
| AC-P0-024 | PASS | 五类敏感头与请求体 Key 脱敏；数据库二进制扫描不含原值 |
| AC-P0-025 | PASS | settings 仅回 API Key 配置状态和末四位；更新响应不回显、不落库 |
| AC-P0-026 | PASS | 非 loopback 无 Token 拒绝启动；管理 API 未授权返回 401 |
| AC-P0-027 | PASS | 主模型/Fast/Deep reasoning、thinking、analysis 不持久化或回传 |
| AC-P0-028 | PASS | 上游/分类错误仅保存类型与稳定 code，不包含 Key/Cookie/环境变量 |

## 4. P1 逐项验收

| ID | 结果 | 可重复证据 |
|---|---|---|
| AC-P1-001 | PASS | session ID 聚合并统计调用、工具、allow、alert、最高风险和时间 |
| AC-P1-002 | PASS | timeline 固定为用户→模型→动作→三级阶段→最终结果 |
| AC-P1-003 | PASS | 告警包含 Trace/会话、风险、工具/能力/目标、原因、证据、规则、阶段 |
| AC-P1-004 | PASS | open/acknowledged/false_positive/resolved、备注与时间持久化 |
| AC-P1-005 | PASS | SSE 覆盖 Trace、阶段、分类、告警、规则事件；EventSource 自动重连 |
| AC-P1-006 | PASS | 总览四类健康、四项指标、阶段量、延迟和最近告警 |
| AC-P1-007 | PASS | 六维筛选和 URL 同步；API 正/反过滤断言 |
| AC-P1-008 | PASS | 每阶段触发、状态、模型、耗时、判定、reason、证据；跳过显示“未触发” |
| AC-P1-009 | PASS | Lucide 风险图标+文字+reason；高对比色与 focus-visible |
| AC-P1-010 | PASS | 编译→预览→测试→保存→启用→命中→禁用/回滚完整 UI/API 路径 |
| AC-P1-011 | PASS | 三协议、双输入模式、历史/当前动作、临时规则、单/全阶段、去推理记录 |
| AC-P1-012 | PASS | Fast/Deep URL/模型/掩码/独立测试；末尾引号空白拒绝；截断给调参建议 |
| AC-P1-013 | PASS | 768/1024/1440 人工检查；无横滚；响应式导航、焦点、Escape |
| AC-P1-014 | PASS | Rules P95 0.165 ms；测试断言 Fast/Deep 0 调用 |
| AC-P1-015 | PASS | 原始请求/响应透明；关键路径 P95 0.038 ms；100 并发流通过 |
| AC-P1-016 | PASS | 1000/100/200 数据集通过；长 JSON 默认折叠；查询 8.069 ms |
| AC-P1-017 | PASS | 旧库迁移前 `.pre-automode-migration.bak`；失败恢复；旧 Trace 可看 |
| AC-P1-018 | PASS | 连续 1000 Trace、100 会话、200 告警写入和关联查询通过 |
| AC-P1-019 | PASS | 50 MiB 流式透传；超缓冲产生 `response_capture_incomplete` 告警 |
| AC-P1-020 | PASS | 中途断连标记 `client_disconnected`，服务健康，无伪造工具动作 |

## 5. E2E 场景记录

| ID | 结果 | 最终行为 |
|---|---|---|
| E2E-001 明确只读 | PASS | Rules allow，无 LLM |
| E2E-002 违反约束 | PASS | contradicted，最终 alert |
| E2E-003 问句非授权 | PASS | out_of_scope，最终 alert |
| E2E-004 模糊查看却执行 | PASS | Rules→Fast→Deep，原因完整 |
| E2E-005 明确授权测试 | PASS | aligned，allow |
| E2E-006 环境越界 | PASS | `ENVIRONMENT_NOT_AUTHORIZED` |
| E2E-007 数据外发 | PASS | critical alert |
| E2E-008 多工具 | PASS | read/write/publish 分别规范化，最高风险生效 |
| E2E-009 分类器故障 | PASS | 双分类器不可用仍 alert |
| E2E-010 自然语言规则 | PASS | 命中 `prod-rule:1`，Rules 直接 alert |

此外，代理集成测试以 Agent 兼容的真实 HTTP 会话发送单次三工具响应（read/write/git_push），验证模型响应工具调用而非请求 `tools` 声明驱动判定；三个动作全部落 Trace，`git_push` 正确识别为 publish，并因用户“不要 push”产生告警。

## 6. 已知边界与上线前动作

- 当前是 Observe 模式；它允许模型响应继续返回 Agent，只负责记录和告警。
- 分类器验收使用确定性 Mock，确保错误矩阵和状态机可重复。接入目标 Fast/Deep 服务后，应在测试环境再运行设置页连通性测试与一轮真实模型回放。
- SQLite 适合单机 MVP；多实例部署需要共享数据库和事件总线。
- 非本机使用时必须配置 `AUTOMODE_ADMIN_TOKEN`，并由反向代理提供 TLS。
- `npm audit` 需要在可访问 npm registry 的环境重跑；当前结果是环境阻塞，不代表依赖安全结论。
- 曾经粘贴到聊天中的任何真实 API Key 都应立即轮换；本实现和测试未把该值写入源码、配置或数据库。
