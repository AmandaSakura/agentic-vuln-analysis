# 见证器停点 2a：两快照首次诊断

按 `2026-09-28-witness-stage2-rev2.md`，此阶段仅做环境准备与诊断运行，不产生候选证明，也不请求模型。当前停止在首次诊断结果；未开始 2b/2c。

## 环境和输入

- `uv 0.9.8` 按两份固定 checkout 的各自 `uv.lock` 导出/安装；Python 3.13.5 因 `mlserver` 要求 `<3.13` 被停止并保留日志，改用计划允许的 Python 3.12.12。两个 3.12 venv 各有 141 个分发包，`uv pip check` 均通过。只安装了与各自 checkout 对应的 MLflow dist-info；`mlflow.__file__` 与 `backend.__file__` 均指向固定 checkout，两个 checkout 均干净。完整命令、哈希、freeze、日志见 `data/diagnostics/hp003-stage2-environment-prep.md` 及两个 `hp003-stage2-{a,b}-py312/` 目录。
- 两份 source-bound manifest 由**同一无标签调用模板**生成，分别绑定提交 `d1312edfca36c7acae0d064ef6a094eded88e14f` 和 `202fac4c83ccc8544c087c142b80196d0e60695c`、各自索引 subject、完整文件 SHA 和 887 个可导入源码模块，以及各自 venv Python。模板不含期望标签、内部 stub 或修复位置。文件为 `artifacts/bounded_execution_witness_stage2/template.json`、`manifest_a.json`、`manifest_b.json`。
- 两次使用同一随机 nonce、同一绝对模型目录与良性目录；`witness_differential_2a.json` 的机器校验显示 `same_concrete_input=true`，并逐项核对路径、nonce 与前提文件摘要。模型目录由运行器实际创建，无内部 MLflow 函数替身。

## 首次观测

| 快照 | 候选状态 | 首事件/最早运行阻断 | `serve` 到达候选 Popen |
| --- | --- | --- | --- |
| hp003_a | `UNRESOLVED` | `target_or_isolation_error`: `NotImplementedError: /dev/urandom (or equivalent) not found` | 否 |
| hp003_b | `UNRESOLVED` | 同上 | 否 |

两个 worker 都用指定的 Python 3.12.12 venv 启动且解释器身份核对通过。当前通用见证器的 Landlock 读取准入没有 `/dev/urandom`，而已有 hp003 局部 fixture 明确准入了它；这是**隔离环境先行阻断**，不能归因于 MLflow 注册表、模型目录或 `serve` 语义。真实源码尚未运行到 Popen，所以这次也未观察到 preexec 的实际效果。

两份记录还保留 7 个**预声明而未核验的证明缺口**：`self._nworkers`、`MLServerDefaultModelName`、`MLServerMLflowRuntime` 三项值假设，以及 Linux、`is_windows()`、LOCAL env、`os.path.exists(artifact_uri)` 四项条件假设。这些不是本次实际路径已经走到的后续失败；见证器在诊断模式下保留它们并继续尝试运行，候选状态始终为 `UNRESOLVED`。源码构造函数的 `self._nworkers = workers or 1` 与数据集声明的 `null` 还需要在后续真实路径上核对，当前不修改声明或对象状态。

## 验证与停点

新增诊断模式保证始终 `UNRESOLVED`，可越过证明缺口观测实际首事件；按 manifest 指定的 venv Python 启动 worker，使用同一持久受控路径保证两版本输入字节相同。针对大清单启动阻塞、旧 `.pyc`、导入阶段误记 Popen、重放目录和跨版本输入不一致均有离线反例。2a 前全量 `uv run --no-sync pytest`：**2002 passed**；`uv run --no-sync cv-agent harness-check`：**PASS**。日志在 `artifacts/bounded_execution_witness_stage2/pytest_2a_preflight.log` 与 `harness_2a_preflight.log`。

按 rev2 的停点，此处等待下一步决定。建议先给通用 worker 的 Landlock 阅读准入补 `/dev/urandom`，保留相同模板/输入/环境重跑一次诊断；随后只对实际暴露的证明缺口做 2b。现在直接实现 `sys.monitoring` 或 preexec 义务缺乏实际调用路径依据。
