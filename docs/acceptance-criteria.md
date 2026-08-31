# AutoMode Shadow DLP 验收标准

## 1. 发布门槛

- 后端完整测试、前端测试和生产构建全部通过。
- 三种模型协议保持请求/响应字节透明，JSON/SSE 均不被 DLP 改写。
- 不允许普通 Trace、告警、分类器输入或数据库可搜索区域出现被检测出的原始敏感值。
- Shadow 模式只告警，不阻断或执行 Agent 工具。
- 任何未验证项标为 `BLOCKED`，不得写成 PASS。

## 2. P0 DLP 检测

1. 凭据、Token、密码、私钥和带密码连接串产生 `credential` finding。
2. 高置信身份号码、手机号、SSN 和邮箱产生 `pii` finding。
3. 代码块、代码结构和配置结构产生 `source_code` finding，且不生成源码片段。
4. 已启用策略中的管理员关键词产生 `admin_keyword` finding。
5. 普通公开文本不产生 finding。
6. finding 包含类别、path、confidence、detector、fingerprint 和强脱敏 snippet。
7. 同一路径重叠命中不会把原文写入 Trace。

## 3. P0 策略与上下文

1. 未注册模型目标默认为 `external`。
2. 注册表能按上游和模型通配模式匹配 `trusted|external`。
3. 相同敏感请求发往 external 时 alert，发往 trusted 且无自定义策略时 allow。
4. 内置 `sensitive + external` 硬策略不能被 Fast/Deep 或低优先级策略降级。
5. 自然语言策略只能编译为受限数据类别、目标、部门、角色、Agent、模型和关键词条件。
6. 策略效果只允许 `alert|review`，版本和启停状态可追踪。
7. `review` 只发送结构化信号和强脱敏片段；Fast/Deep 输入不得出现命中值或源码正文。
8. Fast/Deep 不可用时 `semantic_status=needs_review` 并保守告警。
9. 可信身份头只接受 `AUTOMODE_TRUSTED_PROXY_CIDRS` 的直接连接来源，不信任 `X-Forwarded-For`。

## 4. P0 存储与证据

1. 普通 Trace 只保存脱敏请求；上游仍收到原始请求字节。
2. AES-GCM 密钥文件必须为 0600，错误长度或宽松权限拒绝加载。
3. SQLite 二进制内容中搜索不到证据原文。
4. 每条证据使用独立 nonce、内容哈希、类别、位置、目标和 30 天过期时间。
5. 错误密钥无法解密。
6. 原文查看同时要求 loopback 监听、loopback 请求和管理 Token。
7. 每次原文查看写入独立访问审计。
8. 过期证据自动或手动清理后不可读取。
9. 历史迁移只处理未迁移敏感 Trace，并用脱敏副本替换原文。

## 5. P0 管理 API 与控制台

1. 目标注册表支持创建、查询、更新和删除。
2. DLP 策略支持编译、测试、创建、更新、启停和版本查询。
3. Playground 显示用途、findings、目标信任和策略结论，不执行工具、不转发目标模型。
4. Dashboard 展示 DLP 请求、告警、类别和目标分布。
5. 会话详情首屏按用途、敏感数据、目标和策略结论展示，模型动作单列旁证。
6. 告警支持状态和人工反馈，并以渐进披露方式查看加密原文。
7. 风险同时使用文字、图标和 reason code，不只依赖颜色；表单有可见标签和错误反馈。

## 6. 协议、可靠性与兼容

1. Anthropic Messages、OpenAI Chat Completions、OpenAI Responses 的 JSON/SSE 透明代理通过。
2. 上游 400/401/429/500、超时和客户端断连保持原有状态与 Trace。
3. 50 MiB 响应流式透传且分析缓冲有界。
4. 100 路并发流的网关关键路径 P95 小于 50 ms。
5. 1000 Trace/100 会话/200 告警查询小于 1 秒。
6. 请求 `tools` 声明不作为模型已执行动作；响应工具调用继续作为旁证落库。
7. 旧动作规则、会话分组、告警 triage 和兼容 classify API 回归通过。

## 7. 可重复验证

```bash
.venv/bin/python -m unittest discover -s tests -p 'test_*.py'
npm --prefix web test -- --run
npm --prefix web run build
git diff --check
```

核心 DLP、加密、迁移和目标/身份用例见 `tests/test_dlp.py`；HTTP 管理面见 `tests/test_admin_api.py`；透明代理见 `tests/test_proxy_integration.py`；并发与大响应见 `tests/test_performance.py`。
