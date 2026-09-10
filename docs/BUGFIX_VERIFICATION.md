# 已发现缺陷的修复与本地验证

本轮只修复实现和补充回归测试。未修改简历、历史 28% / 37% 数字或旧实验产物，
未调用真实模型 API。测试继续使用现有 WSL Ubuntu-22.04 与 uv 环境。

## 修复与覆盖

| 缺陷 | 当前行为 | 回归测试 |
| --- | --- | --- |
| 模型可引用不存在的证据，并把读代码标成已确认 | 校验引用；确认/反驳状态必须有对应的、被引用的 typed validator 结果；校验失败返回模型纠正 | `test_evidence_validation.py` |
| 污点传播污染全部形参，类型注解破坏参数解析，通用清洗错误消污 | Python AST 分析表达式；按位置/关键字传递；其他主支持语言用 Tree-sitter 提取形参；清洗效果按 sink 类别区分 | `test_taint_regressions.py` |
| Planner 的依赖只存在于提示词 | 就绪任务调度，传递依赖结果，允许专家再次执行；所有自身任务完成后只形成一票；fast 等待最终票 | `test_planner_dependencies.py` |
| 索引跟随符号链接读出仓库外内容 | 通过目录描述符逐层打开，拒绝文件和目录符号链接；被拒绝的路径记入加载错误 | `test_source_boundaries.py` |
| fixture 未限制文件读取与写入 | 文件只读白名单由 Landlock 执行；默认不能读取文件；HTTP 回调使用同样隔离，保持两次请求间的状态 | `test_fixture_filesystem.py` |
| `import pkg.service` 重复展开模块名 | 区分绑定包名和显式别名；同名函数存在时仍能正确连边 | `test_source_boundaries.py` |
| 超长单词只算一个 token，可绕过模型文本预算 | Agent 序列化文本按 UTF-8 字节上界计数；观察预算跨同一专家的多个任务累计 | `test_agent_budget_units.py`、`test_planner_dependencies.py` |

原有大结果传输测试保留：子进程仍能正确传回 30 万字符的结果；模型投影会报告截断错误，
而不是把全部内容送进模型或保留“已确认”状态。多专家测试覆盖同一专家重复执行不会获得多票，
以及三种标签和置信阈值附近共 729 种投票组合的 full/fast 标签一致性。

## 运行

```bash
cd /home/joker/AAA_NUS_SEM2/cv_agent
uv run --no-sync pytest
uv run --no-sync cv-agent harness-check
uv run --no-sync cv-agent agentic-smoke
uv run --no-sync cv-agent agentic-eval
```

pytest 的现有配置会自动发现新增测试文件。模型交互使用 ScriptedChatModel；
HTTP 验证只访问临时 loopback 服务，文件测试使用临时目录。
fixture 隔离需要 Linux Landlock ABI >= 3 和已有 libseccomp；不满足时阻止执行，
不会静默降低限制。[Landlock 内核文档](https://docs.kernel.org/userspace-api/landlock.html)

## 结果解释

2026-09-05 本轮验证：

- 完整 pytest：**222 passed**，较原有 177 项增加 45 个回归用例。
- `harness-check`：**PASS**。
- `agentic-smoke`：scripted 工作流完成，fast 路径，6 次模型调用、3 次工具调用。
- `agentic-eval`：scripted 开发诊断完成，E4/E5 标签一致，`claim_eligible=false`。
- `git diff --check`：通过。

测试通过支持“已知反例得到修复，并且现有行为未出现已测范围内的回归”。
它不能证明所有语言/框架都没有遗漏，也不能替代真实模型或 held-out 评测。
非 Python 的数据流规则仍有静态近似，结构化验证状态也只具有相应验证器的证明范围。
词法开发预算、Agent 字节上界和 API 实际 usage 是三个不同口径。
