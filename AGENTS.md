# AutoMode Intent Gateway

## 定位

位于 Agent 与模型之间的双协议透明观察网关，记录模型返回的工具调用，并按 `Rules → Fast LLM → Deep LLM` 进行意图与风险判定。

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

- 请求中的 `tools` 只是能力声明；只有模型响应中的 `tool_use`、`tool_calls` 或 `function_call` 才进入意图判断。
- 审查输入只保留用户文本和工具调用意图，剔除 thinking/reasoning、普通回答、system/developer、tool result 和 Claude system reminder。
- 当前是 Observe 模式：只记录、分类和告警，不执行或阻断 Agent 工具。
- 不把 API Key、Cookie、真实生产数据或本地数据库提交到代码库；运行数据库和测试残留保留在本地。

## 当前状态

- Anthropic Messages、OpenAI Chat Completions、OpenAI Responses、JSON/SSE 和规则控制台均已实现。
- 自然语言规则采用受限结构化编译，支持预览、测试、确认、启停、版本和回滚。
- 当前验证基线为后端 76 个测试、前端 4 个测试和生产构建通过；Enforce/Action Gateway、SSO/RBAC 和多机部署仍未实现。
