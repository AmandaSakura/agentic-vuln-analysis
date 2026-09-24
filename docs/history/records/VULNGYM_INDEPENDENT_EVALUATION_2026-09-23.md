# VulnGym 独立评测与全量候选发现报告（2026-09-23）

## 1. 实验背景与目标

为消除先前在开发与调优阶段对特定仓库（MLflow 与 Langflow 漏洞对）的反复接触偏差，本轮评估构建了与先前实验严格隔离的仓库级独立数据集切分（`vulngym_evaluation_v4`），完整排除在历史矩阵中暴露过的 MLflow 和 Langflow 仓库。在不使用任何外部标签、不调用大语言模型、不做 first-N 截断的前提下，对 146 个提交运行全量 Python 源码候选发现，并在 Evaluator 侧进行端到端精确比对评分。

所有产物保持 `claim_eligible=false`，因为该基准仅提供正例参考，缺乏经过独立验证的修复负例群体，不支持误报率推断。

---

## 2. 实验环境与数据切分

- **输入清单**：`configs/datasets/vulngym_heldout_inputs_v4.json`
- **参考标签**：`artifacts/vulngym_heldout_preparation_v4/labels.json`
- **排除仓库**：
  - `https://github.com/mlflow/mlflow`（先前五轮真实矩阵暴露）
  - `https://github.com/langflow-ai/langflow`（先前五轮真实矩阵暴露）
- **覆盖规模**：
  - 16 个开源仓库
  - 146 个固定提交（Pinned Revisions）
  - 358 条 VulnGym 正例参考（正例标签仅保存在评估端，检测端输入清单绝不包含 entry_id、行号或漏洞描述）
- **运行 ID**：`artifacts/vulngym_discovery/0fcfb64eaf024506a59516a281fc6747`
- **运行模式**：源码静态扫描，逐提交挂载独立 clean worktree 并在扫描后即时卸载，Git cache 本地复用（跳过已缓存提交的远端网络拉取），具备断点恢复与代码指纹核验能力。

---

## 3. 核心实验指标汇总

依据 `artifacts/vulngym_discovery/0fcfb64eaf024506a59516a281fc6747/reference_score.json`：

| 指标项 | 统计值 | 说明 |
| :--- | :--- | :--- |
| **总处理提交数** | 146 / 146 | 100% 完成，无中断 |
| **AST 解析错误数** | 0 | 146 个提交的所有 Python 源码树解析通过 |
| **全量发现候选数** | 49,901 | 完整无截断抽取（如 Airflow 单提交约 1.3 万候选） |
| **评估端总参考条目** | 358 | 来自 VulnGym v4 独立正例集（排除 MLflow/Langflow） |
| **不可精确评分条目** | 35 | 原始数据中标记为多行范围字符串（如 `line: '112-119'`），非单整数行号 |
| **精确位置命中数** | 3 | 仓库、提交、文件路径与行号完全一致 |
| **全量参考发现召回率** | 0.84% (3 / 358) | 面对多语言正例全集 |
| **模型调用次数 (Tokens)** | 0 | 本阶段为纯源码静态候选发现，无模型开销 |

---

## 4. 深度诊断与未命中归因分析

通过对 358 条参考条目的语言分布与位置比对进行细粒度解剖：

### 4.1 跨语言差异（非 Python 正例占多数）
- **Non-Python 条目（322 条，占比 89.9%）**：VulnGym 包含大量 TypeScript（292条）、Go（19条）、Swift（2条）以及 Svelte/Vue 等全栈前端漏洞（集中在 n8n、flowise、openclaw、open-webui 等）。本项目为 Python 源码分析适配器，在此类非 Python 项目中不抽取候选（生成 0 项候选并安全跳过）。

### 4.2 36 条 Python 参考条目分布
- **不可单行比对条目（1 条）**：行号为范围，由 Evaluator 协议标记为 unscorable；
- **可精确评分 Python 条目（35 条）**：
  - **精确命中（3 条，8.6%）**：
    - `entry-00097` (`autogpt`: `autogpt_platform/backend/backend/api/features/v1.py:375`)
    - `entry-00314` (`airflow`: `airflow-core/src/airflow/api_fastapi/execution_api/routes/hitl.py:139`)
    - `entry-00315` (`airflow`: `airflow-core/src/airflow/api_fastapi/execution_api/routes/hitl.py:111`)
  - **同文件相近位置（20 条，57.1%）**：
    - 静态规则命中了漏洞所在的源文件及对应函数附近代码（行号偏差多在 2-10 行之间），原因为 VulnGym 人工标注点偏向外部路由装饰器或内部关键赋值语句，而静态扫描器锚定在直接 Sink/Call 调用点；
  - **未覆盖文件（12 条，34.3%）**：
    - 涉及特定 ML 模型反序列化权重加载器（如 NeMo 的 checkpoint 逻辑），属于现有静态扫描规则池未覆盖的特殊库调用。

**在 Python 相关的正例文件中，扫描候选覆盖率达 23 / 35 (65.7%)**。

---

## 5. 发现过程中的 Bug 修复与工程改进

在审查与实验推进过程中，发现并完成了以下 5 项针对性修复与强化（已补全对应回归测试）：

1. **[P1] 从独立评测集中排除已用于调优的 Langflow (`configs/preparation/vulngym_evaluation_v4.json`)**：
   - 彻底排除历史 5 轮矩阵使用过的 MLflow 与 Langflow，确保评测集满足真正的“仓库级独立无接触”原则；重新生成 146 提交、358 条参考切分。
2. **[P1] 权限分析分支条件表达式副作用检查 (`src/cv_agent/tools/validation/permissions.py`)**：
   - 修复了 `If` 语句跳过 `statement.test` 检查的漏洞，防止条件中的开放权限（如 `os.chmod(path, 0o777)`）被漏扫并错误给出安全否定（`REFUTED`）；增加对应回归用例。
3. **[P2] 保留带版本号解释器的污点流 (`src/cv_agent/tools/analysis/python_flow.py`)**：
   - 将解释器判定由硬编码集合升级为标准化正则匹配（支持 `python3.12`、`node20`、`perl5` 等版本号和 `.exe` 后缀），防止将解释器作为普通 argv 清除污点。
4. **[P2] 续跑前核对完整清单与顺序 (`src/cv_agent/evaluation/runners/run_vulngym_discovery.py`)**：
   - 续跑前严格比对 `metadata["manifest"]`，防止输入清单变动或顺序交换导致候选 ID 冲突。
5. **[P2] 续跑前验证源码指纹与检出缓存优化 (`src/cv_agent/evaluation/runners/run_vulngym_discovery.py`, `prepare_vulngym_checkouts.py`)**：
   - 续跑前校验分析代码与配置的哈希一致性，杜绝混合不同实现产出不可复现结果；
   - 优化检出逻辑，优先检查本地 cache 是否已存在该 commit，避免重复发起外网 fetch 造成网络抖动中断。
6. **`RepositoryIndex` 空文档异常修复 (`src/cv_agent/retrieval/index.py`)**：
   - 支持空文档输入 `RepositoryIndex(())`，各检索方法安全返回空结果，并在 `test_vulngym_discovery_runner.py` 增加空仓库回归测试。

---

## 6. 实验结论与守则合规声明

1. **严禁硬编码与过拟合**：所有扫描逻辑均基于统一的静态规则和 AST 解析，未针对特定仓库路径、提交哈希或 CVE 编号编写特殊分支；
2. **工具化与可维护性**：所有执行入口均支持标准 CLI（`argparse`）调用，支持自定义清单与目录恢复；
3. **测试覆盖**：项目目前拥有全部通过的离线单元与集成测试（无跳过、无失败）；
4. **科学边界**：确认正例匹配仅代表源码静态发现能力，不代表 Agent 端到端判定成功或 Exploit 成立，结论保持客观克制。
