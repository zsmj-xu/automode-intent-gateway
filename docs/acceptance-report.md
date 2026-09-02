# AutoMode Shadow DLP 验收报告

## 1. 当前结论

| 项目 | 结果 |
|---|---|
| 验收日期 | 2026-08-28 |
| 验收对象 | 当前本地工作区，尚未提交、合并或部署 |
| 后端 | 119/119 PASS |
| 前端 | 6/6 PASS |
| TypeScript / Vite production build | PASS |
| `git diff --check` | PASS |
| 运行模式 | Shadow / Observe |
| 结论 | **本地实现与自动化门禁 PASS；生产运行态未验证** |

本报告不声明 deployed 或 live verified。当前工作区保留全部实现和复核现场，等待提交或后续发布决定。

## 2. 核心证据

最终运行命令：

```bash
.venv/bin/python -m unittest discover -s tests -p 'test_*.py'
npm --prefix web test -- --run
npm --prefix web run build
git diff --check
```

实测：

- 后端 119 个测试全部通过。
- 后端整体覆盖率 85%；DLP、证据和 DLP 策略编译模块合计覆盖率 87%，README 门槛 85%。
- React/Vitest 6 个测试全部通过。
- TypeScript 检查和 Vite production build 成功。
- 100 路并发流网关内部关键路径 P95：0.332 ms（门槛 50 ms）。
- Rules 直接判定 P95：0.114 ms（门槛 10 ms）。
- 1000 Trace / 100 会话 / 200 告警查询：9.417 ms（门槛 1 s）。

## 3. Shadow DLP 验收

- 完整出站 JSON 本地扫描覆盖凭据、PII、源码/配置和管理员关键词。
- 未注册目标默认 external；同一敏感请求在 external 与 trusted 目标得到不同策略结论。
- 可信身份只接受配置网段的直接连接，伪造身份头不会成为授权依据。
- 确定性敏感外发硬告警无法被 Fast/Deep 降级。
- `review` 策略只向 Fast/Deep 发送强脱敏片段；测试确认输入不含密码或源码正文。
- 分类器不可用时模糊事件保持 `needs_review` 并保守告警。
- 透明代理端到端测试确认：上游收到原始敏感请求，Trace 只保存脱敏副本，原文仅存在于 AES-GCM 密文中。

## 4. 证据与管理面验收

- 0600 密钥权限、错误密钥、独立 nonce、30 天过期和清理均有测试。
- 原文接口要求 loopback + 管理 Token，每次访问写入独立审计。
- 历史迁移能加密敏感旧 Trace，并用脱敏副本替换。
- 32.8 MB 本地旧 `automode.db` 的临时副本已完成启动 schema 升级验证；真实数据库未修改。
- 目标注册表和 DLP 策略的创建、测试、启停及版本 API 通过 HTTP 集成测试。
- 控制台已切换为 DLP 总览、出站审计、策略/目标治理和加密证据渐进查看。

## 5. 已知边界

- Shadow 模式不会阻止数据外发；Request Enforce 尚未实现。
- 图片、OCR、音视频和不可解析二进制不检测。
- 当前证据密钥来自本机文件，不是 KMS；管理端没有 RBAC。
- 原文查看只在 loopback 监听时开放；默认绑定 `0.0.0.0` 的 Docker 服务不可使用该接口。
- npm 依赖在线审计本次未运行，状态为 `pending`，不能据此声明依赖无漏洞。
- 生产上游、真实模型、TLS、远程部署和 live 控制台均未验证。
- 本机 127.0.0.1:8787 当前未运行；`.env` 尚未配置证据密钥和可信代理网段。

## 6. 2026-09-02 本地跟进

本节补充 2026-08-28 报告后的代码与文档对齐，不回写当日的 119 项历史实测结果。

- 当前 `main` 的本地回归基线为后端 123 项、前端 6 项和 production build 通过。
- 治理控制台新增内置检测器启停、自定义正则检测器的服务端编译校验与本地样例预检；已启用检测器的命中继续参与 `sensitive + external → alert` 硬策略。
- DLP reviewer 的 System Prompt 可在控制台修改和重置，且仅影响需语义复核的强脱敏事件。
- 本节仍不声明 remote、生产、TLS、真实模型或 live 控制台已验证；这些状态保持 `pending`。
