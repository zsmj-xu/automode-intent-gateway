# AutoMode 控制台前端重构设计方案

> 版本：v1（方案评审稿）
> 范围：`web/` 控制台整体重构，不改动后端判定语义；仅补充少量只读聚合 API（可选）。

---

## 0. 结论先行

当前前端最大的问题不是"界面丑"，而是**后端已经采集并落库的审计数据，前端只展示了不到三分之一，而且把最能解释"为什么"的字段（审查上下文、意图对齐、完整证据、拟执行工具参数）全部丢掉了**。因此重构的第一优先级不是换皮肤，而是"信息补齐 + 判定可解释 + 渐进式下钻"。

本文给出三版可交互 Demo（A / B / C，见 `docs/design-demos/`），对应三种产品定位，供选择：

| Demo | 定位 | 一句话 | 适合 |
|---|---|---|---|
| **A · 审计时间线** | 线性审计流 | 像"账单/审稿"一样从上往下读一个会话 | 默认推荐，审计是第一诉求 |
| **B · 安全运营大屏** | 告警优先 | 像 SIEM，第一眼看到"哪里要处理" | 值班/运营，告警量大 |
| **C · 审查工作台** | 高密度专家视图 | 像 DevTools，单条 trace 全维度并排下钻 | 深度排查、规则调优 |

---

## 1. 现状诊断

### 1.1 信息展示不全（数据有、但界面没给）

对照后端 `storage.py` / `admin_api.py` 实际返回的数据，逐条列出"已落库但未展示"的字段：

| 数据（后端已提供） | 接口 | 前端现状 |
|---|---|---|
| `review_transcript`（去推理化审查上下文：仅用户文本 + 历史/拟调用工具意图） | `/api/traces/{id}/classification` | ❌ 完全没用到，也根本没调这个接口 |
| `action_alignment`（aligned / out_of_scope / contradicted / ambiguous / high_impact / no_action） | 同上 | ❌ 未展示，判定"意图是否越权"的核心字段 |
| `authorization_evidence`（授权证据，逐条） | `/api/alerts/{id}`、管线结果 | ⚠️ 只在告警卡里平铺，未关联到判定节点 |
| `proposed_actions` 完整参数（拟执行工具 + arguments） | `/api/alerts/{id}.actions`、`tool_actions` 表 | ⚠️ 只显示 `tool_name + capability + target`，**arguments 丢失** |
| `matched_rules`（命中了哪条规则、哪个版本） | 同上 | ⚠️ 判定瀑布里有个小字，告警卡里没有 |
| `input_tokens / output_tokens / error_code / input_hash / model` | `/classification` stages | ❌ 未展示（成本、错误、模型来源全丢） |
| 告警处置元数据：`operator_note / feedback / acknowledged_at` | `/api/alerts/{id}` | ❌ 未展示；后端有 `/feedback`（correct/false_positive/unsure）也**没有前端按钮** |
| Replay 重放 | `/api/playground/replay/{trace_id}` | ❌ 未暴露入口 |
| 完整分类结果 | `/api/traces/{id}/classification` | ❌ 前端只调了更瘦的 `/sessions/{id}/timeline` |

**一句话：`timeline` 接口返回的是"瘦版时间线"，而"完整判定报告"在 `classification` + `alert` 两个接口里，前端从没去取。**

### 1.2 交互问题（具体、可复现）

1. **判定瀑布不可解释**：`TraceWaterfall` 里 Rules/Fast/Deep 每个节点只给 `verdict + reason_code + reason + latency + matched_rules`，没有"审查时到底看了什么"（review_transcript）、"为什么对齐/越权"（action_alignment）、"证据是什么"（evidence 用 `title` 提示语挤在一行）。
2. **告警卡的 "Trace {id}" 是死链**：`href="#"` + `preventDefault()`，点了没反应，无法从告警跳回会话时间线定位。
3. **单文件巨石**：`App.tsx` 401 行、`styles.css` 12 行超长压缩行，页面/组件/样式全挤在一起，任何改动都高风险。
4. **无路由、无深链**：`page` 是 `useState`，不能分享链接、不能前进后退；会话详情只通过 `?session=` 弱同步，刷新后 `selected` 会自动跳到第一行，丢失用户上下文。
5. **双重筛选 + 假分页**：会话列表服务端支持筛选，前端又做了一遍客户端 `filter`；`limit` 写死 100/200，没有分页/加载更多，也没有"共 N 条"的完整计数。
6. **SSE 粒度极粗**：任何事件都只 `setRefresh(r => r+1)` 触发全页 refetch，没有增量更新、没有事件通知中心、没有"新告警"提醒。
7. **模型回复解析不完整**：`responseOutput` 只处理 OpenAI `choices` 和简单 SSE，Anthropic `content` 是 `text/tool_use` 块时展示不全。
8. **缺少全局入口**：没有全局搜索、没有命令面板、没有时间范围快捷筛选（只有单个 `date`）、没有告警一键 triage。

### 1.3 结构问题

- 无设计系统：颜色/间距/字号散落，风险色、状态色、能力色没有统一语义。
- 无数据层：`useLoad` 到处复制，无缓存、无失效、无增量。
- 无类型约束：`Json = Record<string, any>`，后端字段变更无编译期保护。

---

## 2. 重构目标与设计原则

### 2.1 目标

让控制台回答四个问题，且**一屏内能回答前两个**：

1. **现在健康吗？**（Gateway / 上游 / Fast / Deep 状态 + 告警量）
2. **这个会话里 Agent 想干什么？**（用户 → 模型 → 拟调用的工具及其参数）
3. **判定为什么是允许/告警？**（Rules→Fast→Deep 瀑布 + 审查上下文 + 意图对齐 + 证据 + 命中规则）
4. **如果告警，我该怎么处置？**（ack / 误报 / resolved + 反馈 + 跳转定位）

### 2.2 原则

- **信息分层，渐进下钻**：概览 → 列表 → 详情 → 原始数据，四层；默认只显示"决策摘要"，一层层展开"为什么"。
- **判定可解释**：任何一条 `alert` 都必须能追溯到"哪条规则/哪个模型、看了什么证据、为什么对齐失败"。
- **实时但不抖动**：SSE 走增量更新 + 通知中心，不整页 refetch、不抢滚动位置。
- **可深链、可键盘**：URL 即状态；每个 trace/告警/规则都有稳定链接；支持 Cmd+K。
- **先高频后低频**：审计时间线 + 告警 triage 是 P0，图表美化是 P1。

---

## 3. 信息架构（IA）

```
┌─ 侧栏 ─────────────────────────────┐
│ 总览 Dashboard                     │
│ 会话 / 时间线 Sessions (审计核心)   │
│ 告警中心 Alerts                    │
│ 规则 Rules                         │
│ 测试实验室 Playground              │
│ 设置 Settings                      │
│ ────────────────────────────────── │
│ 实时状态 · 通知中心 · Cmd+K         │
└────────────────────────────────────┘

层级：Session（工作上下文） → Trace（一次模型调用） → Decision（一次判定） → Evidence（证据/原始数据）
```

新增两个横向能力（贯穿所有页面）：
- **通知中心**：SSE 事件落地成 toast + 未读数，可点击直达。
- **命令面板（Cmd+K）**：跳转页面、按 trace/session/规则/告警检索、快捷操作（清筛选、切换模式）。

---

## 4. 核心页面重设计（逐页）

### 4.1 总览 Dashboard

- **健康条**：Gateway / 上游 / Fast / Deep 四态，保留。
- **KPI 卡**：模型调用、活跃会话、允许率、告警率 → 增加**时间趋势**（近 24h/7d sparkline，数据可后续补一个轻量 `/api/stats` 或前端聚合）。
- **判定分布**：Rules/Fast/Deep 三柱 → 增加**按风险拆分**（low/medium/high/critical 堆叠）与**意图对齐分布**。
- **延迟**：P50/P95 → 增加**分位数曲线**（可选）。
- **高频原因**：保留，但每一项可点击 → 跳到告警中心预筛 `reason_code`。
- **最近活动流**：用 SSE 增量渲染最近 trace 事件（trace.created / completed / alert.created）。

### 4.2 会话 / 时间线（核心，重做）

这是本次重构的重心，分两栏 master-detail：

- **左栏（会话列表）**：
  - 顶部：搜索 + "筛选 chips"（协议 / 模型 / 风险 / 判定 / 能力），已选条件显示为可移除的 chip，而非藏进"更多筛选"。
  - 每行：会话标题、client_type badge、模型、请求次数、**风险最高值**、最近时间；点击进入右侧详情。
  - 支持虚拟滚动/分页（`limit` + 游标），显示总数。
- **右栏（会话时间线）**：
  - 顶部：会话元信息（session id、client、模型、调用次数、风险）+ 操作（复制链接、replay）。
  - 正文：按 trace 纵向排列，每条 trace 是一张"审计卡"，结构固定为：
    1. **轮次头**：`#N · REQUEST {trace前8位}` + 最终判定徽章（allow/alert）+ 风险 + 时间 + 意图对齐。
    2. **用户输入**（默认折叠到最新一条，可展开历史）。
    3. **模型拟调用工具**：名称 + capability + **完整 arguments**（可折叠）+ target + side_effect。
    4. **判定瀑布**（见 §5）。
    5. **审查上下文**：默认折叠，展开显示"分类器实际看到的东西"（review_transcript 的可视化）。
    6. **原始 JSON**：默认折叠。
- 交互：点击任一处告警/风险徽章 → 高亮并滚动到对应判定节点；支持"全部展开/折叠"；URL 携带 `session` + `trace` 两个锚点。

### 4.3 告警中心

- **从卡片列表 → 列表 + 侧边详情**：左侧告警列表（可按状态/风险/reason_code 筛选），右侧选中告警的完整详情（evidence、拟执行 actions、matched_rules、operator_note、feedback、时间线）。
- **一键 triage**：`open / acknowledged / false_positive / resolved` 四个状态切换 + `反馈：正确 / 误报 / 不确定` 三个按钮（调用已有 `/feedback`）。
- **跳转**：每条告警 → "在时间线中定位"（携带 trace_id 跳会话页并高亮），修掉死链。
- **未读角标**：`open` 数量显示在侧栏导航上。

### 4.4 规则 Rules

- 结构基本合理，改造点：
  - 编译→预览→测试→保存流程拆成**向导式多步**（步骤条），避免一屏塞下所有表单。
  - 已保存规则增加**命中统计**（该规则命中多少次，需后端补一个轻量聚合或前端从告警匹配）。
  - 版本历史改为**抽屉（Drawer）**而非内嵌 panel。

### 4.5 测试实验室 Playground

- 左右分栏：左侧构造输入（协议 / 表单或原始 JSON / 拟调用工具 / 临时规则 / 判定范围），右侧**实时结果面板**（最终判定 + 瀑布 + 审查上下文），提交后结果就地刷新而非滚到底部。
- 增加 **"重放历史 trace"**：输入 trace_id 或从会话页"replay"按钮带入，一键重放已有请求。

### 4.6 设置 Settings

- 分组卡片保留，增加**配置状态提示**（未配置 Fast/Deep 时在总览和设置里给醒目提醒，因为这会直接影响 fail-alert 行为）。

---

## 5. 判定瀑布与证据的可视化规范（设计系统核心）

### 5.1 判定节点（Rules / Fast / Deep）

每个节点一张迷你卡，必现字段：

```
[stage 徽章]  verdict（SAFE/RISKY/UNKNOWN/ALWAYS_ALERT/allow/alert）
风险：low/medium/high/critical（色点）
reason_code：等宽徽章
reason：说明文本
status：completed / error / skipped
model：本地规则 / fast模型 / deep模型
latency：xx.x ms
input_tokens / output_tokens（LLM 阶段）
evidence（rules 阶段：授权证据逐条）
matched_rules（rules 阶段：命中规则 id:version）
error_code（error 状态）
```

- **跳过/未触发**用灰、**命中**用实色、**error** 用红描边。
- 瀑布终点一个"最终判定"节点：`decision + final_stage + action_alignment`。

### 5.2 意图对齐（action_alignment）六态 → 中文语义

| 值 | 中文 | 语义 |
|---|---|---|
| aligned | 对齐 | 动作在用户授权范围内 |
| out_of_scope | 越权 | 超出用户明确授权范围 |
| contradicted | 违背约束 | 与用户"不要 X"直接冲突 |
| ambiguous | 不确定 | 无法判断是否授权 |
| high_impact | 高影响 | 高影响动作，需复核 |
| no_action | 无动作 | 纯文本，无工具调用 |

### 5.3 审查上下文（review_transcript）可视化

把 `[{type:"user",text}, {type:"tool_call", phase, name, arguments, capability, target, ...}]` 渲染成一段"**分类器看到的证据流**"：用户文本用普通气泡，`historical` 工具调用打"历史"标签，`proposed` 打"本轮拟调用"标签并高亮。这直接回应"判定到底看没看我的真实意图"。

### 5.4 语义色板（统一 token）

- 风险：low=绿 / medium=黄 / high=橙红 / critical=红。
- 判定：allow=绿 / alert=红 / 分类中=蓝 / 无需分类=灰。
- 能力：read=蓝 / write=黄 / execute=橙 / delete=红 / publish=紫 / unknown=灰。
- 阶段：rules=青 / fast=蓝 / deep=紫。

---

## 6. 三版 Demo（选型参考）

详见同目录三个可交互 HTML 原型（双击即可在浏览器打开，纯静态、无构建）：

- `docs/design-demos/a-audit-timeline.html` — **A · 审计时间线**（推荐默认）
- `docs/design-demos/b-ops-dashboard.html` — **B · 安全运营大屏**
- `docs/design-demos/c-inspector.html` — **C · 审查工作台**

| 维度 | A 审计时间线 | B 运营大屏 | C 审查工作台 |
|---|---|---|---|
| 第一屏焦点 | 会话时间线 | 实时事件流 + 告警队列 | 单条 trace 全维度 |
| 学习成本 | 低 | 低 | 中高 |
| 审计/解释 | ★★★★★ | ★★★ | ★★★★★ |
| 告警 triage | ★★★ | ★★★★★ | ★★★ |
| 信息密度 | 中 | 中 | 高 |
| 键盘/命令面板 | 有 | 有 | 重点 |
| 建议 | 默认起步 | 告警量大时叠加 | 专家/规则调优 |

选型建议：**以 A 为骨架（信息架构 + 组件），把 B 的"告警 triage + 实时事件流"和 C 的"审查上下文并排 + 命令面板"作为能力模块并入**。三者不是互斥，而是同一个 IA 上的三种侧重。

---

## 7. 技术方案与实施路线

### 7.1 工程化改造

- **拆分组件**：按页面 + 领域拆分（`pages/`、`components/`、`lib/api.ts`、`lib/types.ts`、`lib/format.ts`）。
- **路由**：引入 `react-router`（或轻量自研 `useHashRoute`），URL 即状态，支持深链与前进后退。
- **数据层**：引入 `@tanstack/react-query` 做缓存/失效/轮询；SSE 改造成"事件 → 定向失效 + 通知中心"，不再整页 refetch。
- **类型**：把 `Json` 替换为真实 TS 类型（`Session`、`Trace`、`ClassificationRun`、`StageResult`、`Alert`、`Rule`、`ToolIntent`），与后端字段对齐。
- **设计 token**：抽出 §5.4 的语义色板与间距/字号为 CSS 变量 + 基础组件（`Badge`、`Risk`、`StageNode`、`Waterfall`、`EvidenceFlow`、`Drawer`、`CommandPalette`）。

### 7.2 可选后端补充（只读，不改变判定）

优先级从高到低：

1. **`GET /api/sessions/{id}/detail`**：一次返回 session + timeline + 每个 trace 的 `classification`（含 review_transcript/alignment/stages）聚合，避免前端 N 次串行请求。← 收益最大，建议做。
2. **`GET /api/stats/timeseries`**：请求/告警/延迟的时间序列（供总览 sparkline）。
3. **`GET /api/rules/{id}/hits`**：规则命中计数。
4. `/api/alerts` 增加 `reason_code`、`risk` 筛选 + 分页游标。

> 若不想动后端，也可用现有 `classification` + `alert` 接口前端并发拉取，只是请求数多、体验略差。

### 7.3 分阶段落地

- **P0（信息补齐，1–2 天）**：新时间线 + 判定瀑布全字段 + 审查上下文 + 告警详情/triage + 修死链。
- **P1（交互，2–3 天）**：路由/深链、命令面板、通知中心、筛选 chips、分页、告警跳转定位。
- **P2（工程化/美化，2–3 天）**：组件拆分、react-query、类型、设计 token、总览图表、replay 入口。
- 每阶段保持 `npm --prefix web test` 与 `npm --prefix web run build` 通过。

---

## 8. 验收标准（重构后应满足）

1. 任意一条 `alert`，3 次点击内能定位到：拟调用工具完整参数 → 判定瀑布 → 审查上下文 → 命中规则。
2. 任意一个 trace 都有稳定 URL，可直接分享并在他人浏览器还原同一视图。
3. 告警 triage 全流程（含 feedback）无需离开告警页。
4. SSE 事件到达时，列表增量更新、通知中心有未读数，滚动位置不丢失。
5. 会话列表/告警列表支持分页，且显示总数。
6. 键盘可完成主要导航（Cmd+K 面板）；全部交互有 `aria` 语义。
7. 前后端字段类型对齐，后端新增字段有编译期提示。
8. 前端测试从 4 个扩充到覆盖关键交互（瀑布、triage、命令面板、深链）的基线用例。
