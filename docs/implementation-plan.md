# AutoMode Shadow DLP 实施说明

## 1. 现役目标

AutoMode 位于 Agent 与模型之间，透明转发 Anthropic Messages、OpenAI Chat Completions 和 OpenAI Responses。当前模式是 **Shadow / Observe**：扫描完整出站请求、记录合规结论并告警，但不阻断模型调用。

主判定对象是：

```text
完整出站 JSON + 可信身份上下文 + 模型目标 → DLP 策略结论
```

人的用途和模型工具调用只作为调查旁证。旧工具动作规则保留兼容，不参与 DLP 主判定。

## 2. 数据流

```text
Agent request bytes ───────────────────────────────→ Upstream model
        │                                                │
        ├─ analysis copy → local scan → target lookup     │
        │                 → policy evaluation → alert     │
        │                                                │
        └─ redacted Trace + optional AES-GCM evidence     └─ response bytes → Agent
```

- 上游始终收到客户端原始请求字节。
- 本地扫描 user/system/developer、tool result、历史消息、工具描述等 JSON 字符串。
- 图片、音视频和不可解析二进制不在 MVP 范围。
- 响应中的工具调用单独落库为旁证。

## 3. 本地检测与脱敏

MVP 高置信类别：

- `credential`：API Key、Token、密码、私钥、云访问密钥和带密码连接串。
- `pii`：高置信身份证件、手机号、SSN 和邮箱。
- `source_code`：代码块、代码结构和配置结构；所有源码默认敏感。
- `admin_keyword`：已启用 DLP 策略声明的管理员关键词。

每个 finding 包含类别、JSON path、置信度、检测器、不可逆指纹和强脱敏片段。源码不生成正文片段，只输出 `[SOURCE_CODE_REDACTED]`。

普通 Trace 在写入前替换敏感片段；会话摘要不保存原始用户陈述。完整原文只进入可选加密证据。

## 4. 身份与模型目标

可信身份头固定为：

- `x-automode-user-id`
- `x-automode-department`
- `x-automode-roles`
- `x-automode-agent-id`

只有直接连接地址属于 `AUTOMODE_TRUSTED_PROXY_CIDRS` 时这些头才生效；不读取 `X-Forwarded-For`。

目标注册表使用 `upstream_pattern + model_pattern` 匹配，保存供应商、区域和 `trusted|external`。未注册目标默认 `external`。

## 5. 策略流水线

内置硬策略：

```text
data_findings 非空 AND destination.trust = external → alert
```

管理员自然语言策略编译为受限字段：数据类别、目标信任级别、部门、角色、Agent、模型、关键词、`alert|review` 效果和优先级。

- `alert` 和内置硬策略不能被 LLM 降级。
- `review` 才会把结构化信号和强脱敏片段送入 Fast/Deep。
- 分类器不可用或无法确定时，`semantic_status=needs_review` 并保守告警。
- Classification 分开展示 `request_purpose`、`data_findings`、`destination`、`policy_decision`、`matched_policies`、`identity` 和 `evidence_id`。

## 6. 加密证据

- 算法：AES-256-GCM，每条证据独立 12-byte nonce，Trace ID 作为 associated data。
- 密钥：`AUTOMODE_EVIDENCE_KEY_FILE` 指向 0600 文件；密钥不写 SQLite、源码或 API。
- 留存：30 天，启动和管理 API 均可触发过期清理。
- 访问：仅服务以 loopback 监听、请求来自 loopback 且管理 Token 正确时允许解密。
- 审计：每次查看记录 evidence ID、actor、purpose、source 和时间。

密钥和历史迁移：

```bash
.venv/bin/auto-intent evidence-key .automode-evidence.key
.venv/bin/auto-intent migrate-evidence --db automode.db --key-file .automode-evidence.key
```

迁移只处理能检测到敏感内容且尚无加密证据的历史 Trace；成功后用脱敏副本替换请求正文。

## 7. 管理面

- `/api/destinations`：目标注册表。
- `/api/dlp-policies`：策略编译、测试、启停和版本。
- `/api/playground/classify`：不转发模型的 DLP 测试。
- `/api/evidence/{id}/raw`：loopback 原文解密和访问审计。
- `/api/dashboard`：DLP 请求、告警、类别和目标统计。
- 会话、告警、SSE、旧规则和 Trace API 保持兼容。

控制台按“人的用途 → 敏感数据 → 模型目标 → 策略结论”展示；原文默认不显示，解密前明确提示访问会被审计。

## 8. 边界与后续

当前未实现：Request Enforce、工具 Action Gateway、SSO/RBAC、KMS、多机共享存储、OCR、音视频和数据源密级标签。

Shadow 告警不等于阻止外发；只有后续同步 Request Enforce 才能在模型调用前阻断。
