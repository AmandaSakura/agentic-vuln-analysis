# 实验指南

## 本地离线检查

从仓库根目录执行 `uv run --no-sync pytest`。测试仅使用 scripted/mock 模型、临时源码和项目拥有的本地夹具，不加载真实模型凭据。

`uv run --no-sync cv-agent harness-check` 检查系统声明；`synthetic`、`agentic-smoke`、`agentic-eval` 子命令检查确定性或 scripted 链路。受控 quorum 检查使用 `uv run --no-sync python -m cv_agent.evaluation.quorum_probe`。只执行完整测试准入、不发送模型请求的命令是 `uv run --no-sync python -m cv_agent.runtime.admission`。旧的 `cv_agent.quorum_probe_smoke` 和 `cv_agent.live_gate` 模块地址已删除。

完整 pytest 通过只表示离线契约检查通过，不是实验检测效果的验收。

## 当前固定入口

| 用途 | 命令 | 配置 | 产物目录 |
| --- | --- | --- | --- |
| 10 项开发回归门禁 | `bash scripts/heldout_gate.sh` | `configs/profiles/advisory_gate_v4.json` | `artifacts/python_heldout_pair_gate_v4/<run-id>/` |
| 30 项矩阵 | `bash scripts/heldout_matrix.sh` | `configs/profiles/advisory_matrix_v4.json` | `artifacts/python_heldout_pair_matrix_v4/<run-id>/` |

这些命令会调用真实模型。`.env.experiments` 是本地 Git 忽略文件；公开字段见 `.env.experiments.example`。配置明确选择提供商和模型，凭据单独传递，元数据不记录密钥。本轮重构没有执行这两个命令。

门禁 pointer 仍是 `artifacts/python_heldout_pair_gate_v4.json`。旧配对 v1–v4 配置迁至 `configs/history/`，源码快照及实验产物保持原路径。当前样本已用于调试，目录中的 heldout 命名不代表它们仍满足未观察测试集条件。

## 一次运行的责任划分

- `evaluation/datasets`：解析冻结样本、原始源码哈希、Python import root、中性候选描述和场景条件。
- `evaluation/execution.py`：执行单元、模型/工具事件与结果。
- `runtime/journal.py`、`budget.py`：追加日志、请求上限、时间限制与取消。
- `evaluation/runners`：具体实验入口。
- `evaluation/protocols`：各实验协议的验收规则。
- `evaluation/metrics.py`：保留失败和弃权分母，统计覆盖率、严格召回、成本及配对差异。

advisory pair 与 development fixture 的验收要求不同。复用运行基础设施不意味着放宽或合并它们的证据规则。

## 原始记录怎么读

| 文件 | 内容 |
| --- | --- |
| `metadata.json` | 已解析模型设置、数据/源码身份、运行协议 |
| `events.jsonl` | 实际模型请求、响应、工具观察、错误和每项结果 |
| `results.json` | 计划矩阵与已完成/失败/弃权/未运行单元 |
| `usage.json` | 请求/响应完整性和 provider 报告的 token 消耗 |
| `summary.json` | 完整分母上的系统指标与配对比较 |
| `acceptance.json` | 原协议验收问题，保留历史 JSON 兼容性 |

记录的模型 usage 是实际消耗依据；上下文预算使用的 UTF-8 字节上界是另一种计数单位。unknown usage 和 unknown price 都不是零。

## 验收与消融

应分别问：运行是否完整、证据是否符合协议、检测结果如何。合法弃权会降低覆盖率；它不等同于进程失败。旧 `acceptance.json` 的 `passed` 仍组合了预期标签与运行要求，不能用它代替消融报告，也不能因为 E1 不如 E5 就把整个 E1 运行删除。

E1–E5 比较必须保留同一组计划单元、相同来源和场景、声明预算，以及所有失败与弃权。至少报告覆盖率、严格召回、误报、请求数、reported tokens、延迟。E3/E4 同时改变规划与专家数量，属于组合差异。E4/E5 独立模型调用不保证同票或同成本；固定票序列的早停回放与真实运行统计应分别解释。

一个门禁成功不触发自动扩展实验。本次整理保留 `automatic_expansion=false` 和真实调用前完整测试准入。

## 当前入口共用数据集声明

`configs/datasets/advisory_pairs_v4.json` 保存一份样本定义；
`configs/profiles/advisory_gate_v4.json` 和 `advisory_matrix_v4.json` 保存运行差异。
`evaluation/datasets/composition.py` 的 `AdvisoryDataset`、`AdvisoryRunProfile` 和
`compose_advisory_config` 将两者组合为原 `PythonHeldoutPairExperimentConfig`。
字段不允许交叉覆盖，最终仍执行原配置校验；解析结果可直接交给共同生命周期，
元数据会记录完整解析配置。

两个 shell 入口及 v4 静态审计现在通过 `load_advisory_config` 实际读取上述数据集与 profile，不再读取原 v4 独立文件。原文件迁至 `configs/history/`；目录职责及迁移边界见 [配置导航](../configs/README.md)。
回归测试比较两种写法的完整序列化结果及 10/30 项顺序，确保场景、预算、
import root 与预声明弃权完全相同。不要同时手工修改冻结文件与复用声明来
追逐一次成功运行；新协议应另存名称并明确其开发用途。

## 分开检查运行与检测

`evaluation/protocols/advisory.py` 提供 `review_heldout_pair_rows(rows, usage, config)`，
返回原顺序的 `legacy_issues` 及分开的 `run_integrity_issues`、
`detection_quality_issues`。`evaluation/results.py` 的 `build_heldout_summary`
是纯函数，不修改输入或写文件。这些接口保留预声明弃权策略，不能单凭没有
quality issues 声称全部样本检出。这个分类接口不包含生命周期额外追加的
transport 和 interruption 问题，其 `legacy_passed` 不能替代完整
`acceptance.json.passed`。

分析历史日志时保留原 `acceptance.json`；`results.json` 可能包含为完整分母补入的
`not_run` 行，与当时验收实际收到的已观察行不同。不要把重新计算的 expanded-row
结果冒充原验收结果。

## 其他操作入口

完整入口约定见 [scripts 使用说明](../scripts/README.md)。旧 `python scripts/run_*.py` 等转发路径已删除，改用 `uv run --no-sync python -m cv_agent.evaluation.runners.<模块名>`；准备和诊断分别属于 `preparation`、`diagnostics`。历史记录及冻结配置中的旧脚本名称保留为当时的来源描述，不是当前可执行命令。矩阵入口不会自动先跑 10 项门禁；两者的真实模型请求仍各自受完整 pytest 准入约束。

## VulnGym 全量源码发现评估

`configs/datasets/vulngym_heldout_inputs_v4.json` 是独立于先前 MLflow 矩阵的 152 个提交、17 个仓库输入清单；对应 369 条 VulnGym 正例参考只保存在 evaluator 侧。由于没有验证过的修复负例，`claim_eligible=false`，不能估计误报率或据此宣称研究泛化。

从仓库根目录依次执行：

```sh
uv run --no-sync python -m cv_agent.evaluation.preparation.prepare_vulngym_evaluation_v4
uv run --no-sync python -m cv_agent.evaluation.preparation.prepare_vulngym_checkouts
uv run --no-sync pytest -o addopts=''
uv run --no-sync python -m cv_agent.evaluation.runners.run_vulngym_discovery
uv run --no-sync python -m cv_agent.evaluation.diagnostics.score_vulngym_discovery artifacts/vulngym_discovery/RUN_ID artifacts/vulngym_heldout_preparation_v4/labels.json
```

准备阶段只创建每仓库一个浅层 Git cache。全量发现按提交创建临时干净 worktree，完成源码哈希和候选记录后移除该 worktree，避免同时占用 152 份检出空间。发现会处理清单中的每个提交及该源码树上的全部 Python 候选；它不读取 evaluator 标签、不调用模型，也没有 first-N 截断。最后一步才按仓库、提交、路径和行号精确计分。正例位置匹配属于源码发现指标，不能解释为 agent 漏洞判断或 exploit 确认。
