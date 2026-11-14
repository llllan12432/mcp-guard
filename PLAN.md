# MCP Guard 实现计划

每一步都有「完成标准」和「验证方法」。验证必须真实运行；通过后打勾并提交一次 git。

依据的官方资料（2026-11-14 查阅）：
- MCP 规范 `2026-07-28`（当前版）与 `2025-11-25`（上一版，仍有 initialize 握手）
- 官方 Python SDK `mcp` 2.3.0（v2 API：`MCPServer`、`Client`、`stdio_server`、`stdio_client`），
  用法以安装后的 SDK 源码为准，而不是凭记忆

## 步骤

- [x] **0. 调研与环境**
  - 完成标准：确认协议版本、stdio 分帧规则、tools/list 与 tools/call 的 JSON 结构、SDK 的 stdio 传输 API
  - 验证：安装 SDK，读 `mcp/server/stdio.py`、`mcp/client/stdio.py`、`mcp_types` 源码核对

- [x] **1. 透明 stdio 代理**
  - 完成标准：`python -m mcp_guard run --config X --server NAME` 启动下游 server，双向原样转发所有 JSON-RPC 消息
  - 验证：`tests/test_proxy.py` 用真实子进程，分别以新协议（auto）和旧握手协议（legacy）经代理调用工具，结果与直连一致

- [x] **2. 可插拔检测器**
  - 完成标准：统一接口 `Detector.check(text, surface) -> Verdict`；实现 rules / llm / combined（另有 none 作基线）；LLM 的模型和 key 只从环境变量读
  - 验证：`tests/test_detectors.py`；LLM 检测器用 mock 客户端测试（正常、判恶意、接口报错、拒答）

- [x] **3. 策略、会话污点、JSONL 日志，并接入代理**
  - 完成标准：tools/list 中被投毒的工具被移除；被注入的工具返回被替换；读过不可信来源后调用高风险工具被拦下并等待人工批准；所有决定写 JSONL
  - 验证：`tests/test_guard.py`（单元）+ `tests/test_proxy.py`（真实子进程端到端，包括两个代理进程共享会话状态、批准后放行）

- [x] **4. 合成演示环境**
  - 完成标准：`python demo/run_demo.py` 一条命令：不经代理攻击成功，经代理被拦下
  - 验证：`tests/test_demo.py` 运行脚本并断言每个场景的结果（假发件箱里有没有攻击者地址）

- [x] **5. 评测框架**
  - 完成标准：`eval/samples.jsonl` 每类 5 条种子；`python eval/run_eval.py` 输出每种检测器的拦截率、误报率、平均延迟的 markdown 表，并单独列出漏报和误报；没有 API key 时跳过 LLM 并注明
  - 验证：`tests/test_eval.py` + 实际运行生成 `eval/results.md`

- [ ] **6. 日志静态页与 README**
  - 完成标准：`viewer/index.html` 可打开 JSONL 日志；README 含安装、运行、演示、评测结果、局限性、比赛期间编写的内容
  - 验证：浏览器里实际打开页面加载演示日志；README 中的命令逐条执行

- [ ] **7. 干净环境走查**
  - 完成标准：全新目录 `git clone` + 新 venv，严格按 README 操作全部成功
  - 验证：实际执行，发现的问题修掉并回归

## 进度记录

- 步骤 1–3 的代码是连着写的（代理要调用 Guard，Guard 要调用检测器），一起验证：`pytest` 48 个测试全部通过（其中 8 个是真实子进程的端到端测试）。
- 实现中发现并修复：代理收到 EOF 后不退出（要等宿主 2 秒后强杀）——原因是没有关闭写流；下游 server 先退出时代理挂起——原因是读 stdin 的线程无法取消，改为记录后直接退出。
- 步骤 4：`python demo/run_demo.py` 实际运行，四个场景结果符合预期（退出码 0）；`tests/test_demo.py` 断言同样的结果。
- 步骤 5：`python eval/run_eval.py` 实际运行生成 `eval/results.md`。环境里没有 `ANTHROPIC_API_KEY`，所以 `llm` 和 `combined` 标为跳过、没有数字。种子样本的结果没有做任何调整：规则检测器漏 5 条、误报 3 条，都列在报告里。
