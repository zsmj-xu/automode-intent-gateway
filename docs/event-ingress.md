# 标准事件接入

AutoMode 接收外部接入服务整理后的模型调用事件，不主动连接业务数据库或 LiteLLM。入口仅用于 Observe 分析，不返回在线放行、阻断或路由指令。

事件格式见 [JSON Schema](standard-event.schema.json)。`proxy-adapter` 为进程内代理保留来源，不能通过标准 HTTP 入口提交。

## 启动和来源认证

配置 `AUTOMODE_EVIDENCE_KEY_FILE`（0600 权限的 AES-256 密钥文件）及管理 Token，运行 `auto-intent serve`。未配置 upstream 时只启用事件分析和管理功能。

管理员在“事件 → 来源与授权”登记来源，或使用受管理认证保护的 `POST /api/sources`。接入服务使用该来源的 Token，不能用其他来源 ID 冒充身份。只有明确允许提供可信身份的来源才可声明可信用户上下文；目标的 trusted/external 分类仍由服务端目标注册表解析。

## 提交请求事件

以下示例仅含合成数据。`AUTOMODE_SOURCE_TOKEN` 为来源 Token，与管理 Token 分离。

```bash
curl --fail-with-body http://127.0.0.1:8787/v1/events \
  -H "Authorization: Bearer $AUTOMODE_SOURCE_TOKEN" \
  -H 'Content-Type: application/json' \
  --data-binary @event.json
```

`event.json`：

```json
{
  "version": "1",
  "event_id": "request-001",
  "source_id": "registered-source-id",
  "call_id": "call-001",
  "attempt_id": "1",
  "event_type": "request",
  "protocol": "openai_chat_completions",
  "capture_stage": "model_outbound",
  "content_integrity": "complete",
  "timestamp": "2026-09-09T00:00:00Z",
  "is_realtime": false,
  "model_destination": {"upstream": "https://model.example.invalid/v1"},
  "payload": {
    "model": "example-model",
    "messages": [{"role": "user", "content": "合成测试请求"}]
  }
}
```

| 字段 | 约定 |
|---|---|
| `event_id` | 来源内稳定的事件 ID；重试必须沿用原 ID 和原事件内容 |
| `source_id` | 与来源 Token 对应的已登记来源 |
| `call_id` / `attempt_id` | 模型调用及其重试编号；请求和响应使用相同关联值 |
| `event_type` | `request`、`response` 或 `full_call` |
| `protocol` | `openai_chat_completions`、`openai_responses`、`anthropic_messages` |
| `capture_stage` | `inbound_request`、`model_outbound`、`unknown`；按真实采集位置填写 |
| `content_integrity` | `complete`、`truncated`、`redacted`、`missing`；正文缺失时可传 `null` |
| `timestamp` | 事件原发生时间，而非此次上传时间 |
| `is_realtime` | 历史导入明确传 `false`；历史事件不会回填实时会话意图 |
| `payload` | 原协议请求 JSON；保留 system、历史、工具定义和结果，不能只提取最新 prompt |
| `model_destination` | 实际已知的目标上下文；未知时不猜测最终服务商 |
| `identity` / `session_id` | 可选的用户上下文和来源内会话标识 |

## 确认、查询与重试

- `202` 表示加密正文和接收索引已持久化，不代表分析通过或已完成。
- 使用响应中的 `status_url` 查询进度，仍携带同一来源 Token；不要自行拼接内部存储 ID。
- 相同来源和事件 ID 的重复提交只有在规范化事件内容一致时才作为重复接收；变更身份、目标、协议或正文等判定字段返回 `409`。
- 不同来源可以使用相同外部事件 ID；管理端使用独立内部 ID，不能据此绕过来源权限。
- 容量不足或接收尚未完成时，按接口的可重试错误和 `Retry-After` 稍后补发；未取得 `202` 不得前移来源读取进度。
- 已接收任务的处理异常、LLM 失败和待复核均与“无告警”不同。管理员只能重试仍保留必要正文的失败任务。

## 响应与完整调用记录

响应使用独立 `event_id`，与请求共用 `source_id`、`call_id`、`attempt_id`、`capture_stage` 和实时/历史标记；`event_type` 为 `response`，`payload` 可以是响应 JSON 对象或完整 SSE 文本。响应先到时处理并保存脱敏旁证，不等待请求，也不占用 worker；请求迟到后补齐关联。

完整记录使用 `event_type: "full_call"`，其 `payload` 结构为 `{"request": <原始请求 JSON>, "response": <响应 JSON 或 SSE 文本>}`。只有 `request` 参与请求 DLP，`response` 仅提取旁证；请求缺失不会被当作安全请求。

## 数据保留与证据

临时正文加密保存，成功分析并提交必要结果后释放。产生告警的请求另存加密证据，由管理端受限接口解密并记录访问审计；LLM 只获得脱敏复核内容。响应是调查旁证，不能用于证明 Agent 已执行工具动作。

代理适配器采用后台投递，模型转发成功不等于审计已落盘。其丢失窗口和缓冲满丢弃指标与标准入口的 `202` 接收保证不同。首期验证使用合成数据和本机服务，不构成生产容量证明。
