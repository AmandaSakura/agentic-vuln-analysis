# cv-agent

代码漏洞候选点审查 Agent 的研究库。输入一个候选位置和源码快照，检索上下文，规划验证任务，让 scan、taint、authz 专家调用工具，最后输出预测标签、验证状态、引用证据和成本记录。

当前主要系统是 **E1–E5**；V1–V5 确定性系统保留为可运行基线。

| 系统 | 检索 | 专家与调度 |
| --- | --- | --- |
| E1 | 本地上下文 | 单专家 |
| E2 | 文本检索 | 单专家 |
| E3 | 图检索 | 单专家 |
| E4 | 图检索 | 规划器、多专家、完整多数投票 |
| E5 | 图检索 | 规划器、多专家、满足条件后提前多数投票 |

## 从这里开始

1. [当前状态](docs/CURRENT_STATUS.md)：已完成什么、实验结果和已知边界。
2. [架构与阅读路线](docs/ARCHITECTURE.md)：沿数据流阅读核心实现。
3. [实验指南](docs/EXPERIMENTS.md)：配置、入口、原始日志与验收口径。
4. [测试契约](docs/TEST_CONTRACT.md)：修改分析、证据或运行逻辑前必读。
5. [本次重构记录](docs/history/records/REFACTOR_2026-09-21.md)：逐批测试、兼容性和未混入的语义修复。

完整阅读路线见 [文档导航](docs/README.md)。旧审查、计划和结果已归入 [历史资料](docs/history/README.md)；配置与原始实验产物保留原路径。

## 代码分层

| 目录 | 职责 |
| --- | --- |
| `src/cv_agent/domain/` | 候选、源码、聊天、证据、投票和结果数据模型 |
| `src/cv_agent/code_adapters/` | Python、Java、JS/TS、Go 解析及源码加载 |
| `src/cv_agent/retrieval/` | 文本/图检索、上下文裁剪和预算 |
| `src/cv_agent/agents/` | 规划、ReAct、证据输出校验、调度和投票 |
| `src/cv_agent/tools/` | 工具注册、源码工具、静态分析、候选绑定验证 |
| `src/cv_agent/runtime/` | 模型传输、完整测试门禁、请求记账和预算 |
| `src/cv_agent/evaluation/` | 数据集、执行生命周期、统计、验收与操作入口 |
| `src/cv_agent/baselines/` | 原 V1–V5 确定性系统 |
| `src/cv_agent/harness/` | 系统声明、专家策略与预算的类型化契约 |

包根目录现在只保留 `__init__.py`（公共对象）和 `cli.py`（命令行入口）。71 个旧转发模块已删除，代码和测试直接导入上表中的实现包。旧 Python 模块路径不再支持。`scripts/` 根目录只保留四个 shell 入口和[使用说明](scripts/README.md)；两个独立探针集中在 `scripts/probes/`。47 个 Python 转发脚本已删除，其他操作直接使用 `python -m cv_agent.evaluation.…` 调用实现模块。

配置按数据、运行策略、模型、专项实验、准备、诊断和历史版本分目录，见 [配置导航](configs/README.md)。当前门禁／矩阵共用一份数据集，分别读取各自 profile。

## 本地验证

```bash
uv run --no-sync pytest
uv run --no-sync cv-agent harness-check
uv run --no-sync cv-agent synthetic
uv run --no-sync cv-agent agentic-smoke
uv run --no-sync cv-agent agentic-eval
```

这些检查使用离线模型和本地测试夹具，不需要模型凭据。完整测试记录见重构日志；测试通过说明相应回归检查通过，不能代替漏洞检出实验。

## 当前实验

```bash
bash scripts/heldout_gate.sh
bash scripts/heldout_matrix.sh
```

两个命令会真实调用配置的模型。提供商和凭据由 Git 忽略的 `.env.experiments` 配置，公开模板为 `.env.experiments.example`；不自动切换提供商。当前两个入口继续使用固定的 v4 配置和原产物目录，详见实验指南。

真实请求始终经过 `OpenAICompatibleChatModel`：进程内首次请求前执行完整 pytest，源码、配置或测试发生变化后阻断后续请求。没有缓存通行证或跳过变量。

目前三个漏洞/修复对已经用于反复调试，`claim_eligible=false`。一次十项门禁通过不能保证三十项矩阵稳定复现。`VULNERABLE/SAFE/ABSTAIN` 是预测标签，`CONFIRMED/REFUTED/UNRESOLVED` 是证据状态；有预测不等于有漏洞复现证明。
