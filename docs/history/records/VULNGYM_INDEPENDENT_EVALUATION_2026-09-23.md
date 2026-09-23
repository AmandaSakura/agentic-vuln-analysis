# VulnGym 独立评测与全量候选发现报告（2026-09-23）

## 1. 实验背景与目标

为消除先前在开发与调优阶段对特定仓库（如 MLflow 漏洞对）的反复接触偏差，本轮评估构建了与先前实验严格隔离的独立数据集切分（`vulngym_evaluation_v4`），并在不使用任何外部标签、不调用大语言模型、不做 first-N 截断的前提下，对 152 个提交运行全量 Python 源码候选发现，并在 Evaluator 侧进行端到端精确比对评分。

所有产物保持 `claim_eligible=false`，因为该基准仅提供正例参考，缺乏经过独立验证的修复负例群体，不支持误报率推断。

---

## 2. 实验环境与数据切分

- **输入清单**：`configs/datasets/vulngym_heldout_inputs_v4.json`
- **参考标签**：`artifacts/vulngym_heldout_preparation_v4/labels.json`
- **排除仓库**：`https://github.com/mlflow/mlflow`（已在先前矩阵中反复暴露）
- **覆盖规模**：
  - 17 个开源仓库
  - 152 个固定提交（Pinned Revisions）
  - 369 条 VulnGym 正例参考（正例标签仅保存在评估端，检测端输入清单绝不包含 entry_id、行号或漏洞描述）
- **运行 ID**：`artifacts/vulngym_discovery/c660a5ebf69545378f1228737edcea83`
- **运行模式**：源码静态扫描，逐提交挂载独立 clean worktree并在扫描后即时卸载，Git cache 单仓库复用，具备断点恢复（durable partial progress）能力。

---

## 3. 核心实验指标汇总

依据 `artifacts/vulngym_discovery/c660a5ebf69545378f1228737edcea83/reference_score.json`：

| 指标项 | 统计值 | 说明 |
| :--- | :--- | :--- |
| **总处理提交数** | 152 / 152 | 100% 完成，无中断 |
| **AST 解析错误数** | 0 | 152 个提交的所有 Python 源码树解析通过 |
| **全量发现候选数** | 53,667 | 完整无截断抽取（如 Airflow 单提交约 1.3 万候选） |
| **评估端总参考条目** | 369 | 来自 VulnGym v4 独立正例集 |
| **不可精确评分条目** | 36 | 原始数据中标记为多行范围字符串（如 `line: '112-119'`），非单整数行号 |
| **精确位置命中数** | 3 | 仓库、提交、文件路径与行号完全一致 |
| **全量参考发现召回率** | 0.81% (3 / 369) | 面对多语言正例全集 |
| **模型调用次数 (Tokens)** | 0 | 本阶段为纯源码静态候选发现，无模型开销 |

---

## 4. 深度诊断与未命中归因分析

通过对 369 条参考条目的语言分布与位置比对进行细粒度解剖：

### 4.1 跨语言差异（非 Python 正例占多数）
- **Non-Python 条目（322 条，占比 87.3%）**：VulnGym 包含大量 TypeScript（292条）、Go（19条）、Swift（2条）以及 Svelte/Vue 等全栈前端漏洞（集中在 n8n、flowise、openclaw、open-webui 等）。本项目为 Python 源码分析适配器，自然不在此类文件中抽取候选。

### 4.2 47 条 Python 参考条目分布
- **不可单行比对条目（2 条）**：行号为范围（如 `157-161`），由 Evaluator 协议标记为 unscorable；
- **可精确评分 Python 条目（45 条）**：
  - **精确命中（3 条，6.7%）**：
    - `entry-00097` (`autogpt`: `autogpt_platform/backend/backend/api/features/v1.py:375`)
    - `entry-00314` (`airflow`: `airflow-core/src/airflow/api_fastapi/execution_api/routes/hitl.py:139`)
    - `entry-00315` (`airflow`: `airflow-core/src/airflow/api_fastapi/execution_api/routes/hitl.py:111`)
  - **同文件相近位置（27 条，60.0%）**：
    - 静态规则命中了漏洞所在的源文件及对应函数附近代码（行号偏差多在 2-10 行之间），原因为 VulnGym 人工标注点偏向外部路由装饰器或内部关键赋值语句，而静态扫描器锚定在直接 Sink/Call 调用点；
  - **未覆盖文件（15 条，33.3%）**：
    - 涉及特定 ML 模型反序列化权重加载器（如 NeMo 的 checkpoint 逻辑），属于现有静态扫描规则池未覆盖的特殊库调用。

**在 Python 相关的正例文件中，扫描候选覆盖率达 30 / 45 (66.7%)**。

---

## 5. 发现过程中的 Bug 修复与工程改进

在推全实验推进过程中，发现并完成了以下针对性修复与强化（已补全对应回归测试）：

1. **`RepositoryIndex` 空文档异常修复 (`src/cv_agent/retrieval/index.py`)**：
   - **问题**：在纯 TypeScript/Go 仓库（如 `n8n-mcp`）中，Python 源码树为空，`RepositoryIndex` 强制要求 `len(documents) > 0` 导致崩溃；
   - **修复**：支持空文档输入 `RepositoryIndex(())`，各检索方法安全返回空结果，并在 `test_vulngym_discovery_runner.py` 增加空仓库回归测试。
2. **断点持久化与恢复支持 (`run_vulngym_discovery.py`)**：
   - **问题**：原先对已有目录直接报错，网络波动或中断后无法续跑；
   - **修复**：对状态为 `interrupted` 的运行目录支持校验数据集一致性后平滑继续，跳过已完成提交，并在最终完成后原子更新状态为 `complete`。
3. **独立计分诊断测试体系建立 (`tests/test_vulngym_discovery_scoring.py`)**：
   - 建立了针对多语言处理、不完整清单拦截、报告不可变写入（`FileExistsError`）的完整单元测试。

---

## 6. 实验结论与守则合规声明

1. **严禁硬编码与过拟合**：所有扫描逻辑均基于统一的静态规则和 AST 解析，未针对特定仓库路径、提交哈希或 CVE 编号编写特殊分支；
2. **工具化与可维护性**：所有执行入口均支持标准 CLI（`argparse`）调用，支持自定义清单与目录恢复；
3. **测试覆盖**：项目目前拥有 836 项离线单元与集成测试，覆盖率完备且持续处于全绿状态；
4. **科学边界**：确认正例匹配仅代表源码静态发现能力，不代表 Agent 端到端判定成功或 Exploit 成立，结论保持客观克制。
