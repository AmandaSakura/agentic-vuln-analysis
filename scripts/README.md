# 操作入口

从仓库根目录运行。这里只保留四个 shell 命令；实验实现位于 `src/cv_agent/evaluation/`。

| 命令 | 用途 |
| --- | --- |
| `bash scripts/heldout_gate.sh` | 10 项开发门禁，会调用真实模型 |
| `bash scripts/heldout_matrix.sh` | 30 项矩阵，会调用真实模型 |
| `bash scripts/deepseek.sh <CLI 参数>` | 加载 DeepSeek 环境并调用 `cv-agent` CLI |
| `bash scripts/fetch_benchmarks.sh` | 下载固定版本的公开基准仓库，需要网络 |

矩阵不自动先跑门禁。门禁通过不保证矩阵检测结果；每个进程的真实模型调用仍须通过完整离线 pytest。配置、成本及结果解释见[实验指南](../docs/EXPERIMENTS.md)。

`heldout_gate.sh` 和 `heldout_matrix.sh` 根据脚本位置定位仓库，加载该仓库根目录的
`.env.experiments`；移动或重新 clone 项目后无需改写脚本中的机器路径。两者仍无参数，
直接启动各自固定的 Python 模块。离线测试使用临时项目和假环境文件。

## 其他实验、准备与诊断

47 个 Python 转发脚本已删除。同名实现模块直接启动，例如：

```bash
uv run --no-sync python -m cv_agent.evaluation.runners.run_micro_benchmark
```

该示例会运行模型实验，不是离线检查。其他 `run_*` / `reproduce_*` 实现在 `evaluation.runners`，数据准备在 `evaluation.preparation`，审计在 `evaluation.diagnostics`；使用 `python -m` 加对应完整模块名。各模块保留原来的参数和配置，不存在自动选择实验的总入口。运行前检查模块用途；诊断或准备命令也可能写入文件。

VulnGym 的正例来源发现分成三步，保持 detector 输入与 evaluator 标签分开：

```sh
uv run --no-sync python -m cv_agent.evaluation.preparation.prepare_vulngym_evaluation_v4
uv run --no-sync python -m cv_agent.evaluation.preparation.prepare_vulngym_checkouts
uv run --no-sync python -m cv_agent.evaluation.runners.run_vulngym_discovery
```

缓存准备只保留每个仓库一个 Git cache。发现阶段逐提交建立临时 worktree，扫描完成后移除，不调用模型。结果生成后，单独运行 `uv run --no-sync python -m cv_agent.evaluation.diagnostics.score_vulngym_discovery RUN_DIR artifacts/vulngym_heldout_preparation_v4/labels.json`；正例-only 参考不支持误报率。

## 独立探针

`probes/jinja_attr_probe.py` 和 `probes/langchain_template_probe.py` 由对应 reproduction runner 在目标项目解释器中按文件路径启动。它们不依赖安装本项目，不是日常实验入口。

历史记录和冻结配置保留当时的旧脚本名称，当前命令使用上述包路径。
