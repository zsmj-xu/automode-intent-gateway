# AutoMode Shadow DLP Gateway

## 定位

位于 Agent 与模型之间的透明企业 AI 出站数据合规网关。主判定对象是完整出站模型请求、可信身份上下文和模型目标；本地检测敏感数据并按 DLP 策略告警。人的用途和模型工具调用仅保留为调查旁证。

## 启动与验证

- 安装：`.venv/bin/pip install -e '.[dev]'`、`npm --prefix web install`
- 构建控制台：`npm --prefix web run build`
- 启动：设置 `AUTOMODE_UPSTREAM_BASE_URL` 后运行 `.venv/bin/auto-intent serve --host 127.0.0.1 --port 8787`
- 后端测试：`.venv/bin/python -m unittest discover -s tests -p 'test_*.py'`
- 前端测试：`npm --prefix web test`
- 本地控制台：`http://127.0.0.1:8787/`

## 技术与目录

- Python 3.9+、aiohttp、SQLite；前端为 React、TypeScript、Vite。
- `automode_gateway/`：代理、协议解析、规则、流水线和存储。
- `web/`：控制台源码与构建产物；`tests/`：后端回归与性能测试；`docs/`：计划和验收材料。

## 约定与边界

- DLP 扫描完整出站 JSON 文本，包括 user/system/developer、tool result、历史消息和工具描述；暂不处理图片、音视频和二进制。
- 凭据、PII、源码/配置和管理员关键词由本地确定性检测器识别；确定性告警不能被 LLM 降级。
- 未注册模型目标默认 external；可信身份头只接受 `AUTOMODE_TRUSTED_PROXY_CIDRS` 中的直接连接来源，不信任 `X-Forwarded-For`。
- 普通 Trace 只保存脱敏请求；原文证据仅在配置 AES-GCM 密钥时加密保存 30 天。
- 模型响应中的工具调用单独落库为旁证，不触发或替代出站数据判定。
- 会话用户意图风险在后台 Observe：识别目的风险与外发动作意图，high/critical 可告警但不证明真实外发、不会阻断。低置信度 reviewer 可接收实时用户原文；原文不写入风险派生记录。
- 当前是 Observe 模式：只记录、分类和告警，不执行或阻断 Agent 工具。
- 不把 API Key、Cookie、真实生产数据或本地数据库提交到代码库；运行数据库和测试残留保留在本地。

## 当前状态

- Anthropic Messages、OpenAI Chat Completions、OpenAI Responses、JSON/SSE 和 Shadow DLP 均已实现。
- 出站数据策略采用独立受限结构化编译，支持预览、测试、启停和版本；确定性硬检测器矩阵支持独立启停与自定义正则检测器录入，服务端编译校验且控制台提供本地样例匹配预检；审查模型 System Prompts 支持可视化在线修改与重置。
- 会话按优先级归组：显式 session id（header/metadata/`previous_response_id`）→ 会话内容指纹（`session_fingerprint.py`，校验前缀续接）→ trace 级 fallback；历史 capability/constraint 摘要仅作旁证，DLP 结论以完整出站请求、可信身份和目标模型为输入。
- 当前验证基线为后端 127 个测试、前端 6 个测试和生产构建通过；Request Enforce、Action Gateway、SSO/RBAC、KMS、OCR 和多机部署仍未实现。
