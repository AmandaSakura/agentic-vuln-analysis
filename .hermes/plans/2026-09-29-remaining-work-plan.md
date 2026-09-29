# 剩余工作执行计划（2026-09-29）

执行者照本文件从头做到尾，**只在第 8 节列出的硬停点停下**。本文件与 `AGENTS.md`、`docs/TEST_CONTRACT.md` 冲突时，以后两者为准。开工前先读这两份文件，再读：

- `.hermes/plans/2026-09-27-bounded-execution-witness-design-rev1.md`
- `.hermes/plans/2026-09-28-witness-stage2-rev2.md`
- `.hermes/plans/2026-09-29-model-proposed-witness-scenarios.md`

## 0. 授权范围

用户把本计划交给执行者，即视为批准以下事项，**不再逐项询问**：

| 编号 | 授权内容 | 上限 |
| --- | --- | --- |
| G1 | 提交当前分支上的全部代码、测试、配置、文档和 `.hermes/plans` | — |
| G2 | 阶段 1：DeepSeek 真实模型 2×2 实验（hp003） | 60 请求 |
| G3 | 阶段 2：条件 B 在一轮通用修复后重跑一次（仅 2 格） | 30 请求 |
| G4 | 阶段 3a：近迁移样本 entry-00390 的真实模型运行（仅条件 B） | 40 请求 |
| G5 | 阶段 3b：外部新样本的**选样与环境准备联网**（范围见 3b.1），以及真实模型运行 | 最多 2 对，每对 40 请求 |
| G6 | 累计 reported tokens | 2,500,000，超出即停 |

**不授权**（遇到就硬停）：

- 读取或运行 vulngym held-out 输入及其标签；
- 改动 `claim_eligible`；
- 使用第 3b.1 节以外的网络；
- sudo 或系统级安装；
- 放宽证据契约，包括新增 supported status、给目标内部打桩、删除核验义务；
- Jev 或三臂实验；
- 超出上面任何一项上限。

用户如果不同意某一项（例如 G5），交付前会删掉那一行；删掉的项视为不授权。

## 1. 全局规则（每个阶段都适用）

1. **模型**：`CV_AGENT_PROVIDER=deepseek`，`DEEPSEEK_MODEL=deepseek-flash`。密钥只从用户已有的实验环境文件加载，不打印，不写入产物。每次运行后核对返回的模型 ID，不是 `deepseek-flash` 就硬停。
2. **先提交，再发请求**：每次真实请求前，代码必须已提交、工作树干净，并通过 runner 自带的完整 pytest 门禁（`require_passing_tests`）。门禁不能绕过，也不能复用旧的通过记录。
3. **只跑一次**：每个获批的格子只跑一次。不因结果不理想重跑；只有第 2 节规定的那一次重跑例外。
4. **记录**：每次 API 请求及其 usage 都要记，解析失败的也要记；运行完用 `audit_proof_routing_requests` 或等价的审计程序出逐请求账本。
5. **范围说明**：所有结果都是 `dataset_role=development`、`claim_eligible=false`，报告里要写明。
6. **场景来源分开报告**：`dataset`、`model`、`developer_scripted` 三种来源分别统计，绝不混算。`developer_scripted` 只能作为能力上限的检查，不算系统结果。
7. **修复必须通用**：满足第 7 节的全部条件才能改代码。
8. **保留历史**：不覆盖旧产物，每个阶段用新的目录。

## 2. 阶段 0：提交与预检

1. `git status` 确认当前有 26 处左右未提交改动，包括未跟踪的 `witness_scenario.py`、`run_witness_scenario_matrix.py`、`tests/test_witness_scenario*.py`、`configs/experiments/witness_scenario_2x2.json` 等。
2. 跑完整 `uv run --no-sync pytest` 和 `uv run --no-sync cv-agent harness-check`，都通过后按 G1 提交，提交信息写明"model-proposed witness scenarios + 2x2 runner"。
3. 不联网跑一次 `python -m cv_agent.evaluation.runners.run_witness_scenario_matrix`（preparation 模式），核对以下几点：
   - 4 个格子齐全；
   - 条件 B 的 subject 里没有场景字段；
   - B 的模型消息中，`enable_mlserver`、`os.path.exists(artifact_uri)` 只出现在源码文本里；
   - 两个快照输入一致。

   把结果存档。

## 3. 阶段 1：DeepSeek 2×2 实验（hp003）

### 3.1 启动

```bash
CV_AGENT_PROVIDER=deepseek DEEPSEEK_MODEL=deepseek-flash \
  uv run --no-sync python -m cv_agent.evaluation.runners.run_witness_scenario_matrix --live
```

（密钥按用户现有方式注入环境。）上限 60 请求、3600 秒，均由配置决定。

### 3.2 预先登记的判定标准（跑之前把本节原样抄进结果报告）

| 格子 | 成功 | 可接受 | 警报 |
| --- | --- | --- | --- |
| A-hp003_a（数据集场景） | 见证 `CONFIRMED`，判定 VULNERABLE | — | 其他结果：记录原因，属于协议问题 |
| A-hp003_b | ABSTAIN / UNRESOLVED | 其他不带确认证据的结论 | 判 VULNERABLE，或出现 `CONFIRMED` |
| **B-hp003_a（模型场景）** | **模型自己提出场景，见证 `CONFIRMED`，判定 VULNERABLE** | — | — |
| B-hp003_b | ABSTAIN / UNRESOLVED | 同 A-b | 同 A-b |

- b 格出现 `CONFIRMED` 或 VULNERABLE，就是**可靠性警报 → 硬停**（第 8 节 S1）。
- 任何格子判出 SAFE 时，检查它的证据链。没有合格证据的 SAFE 记为缺陷，走第 7 节修复。

### 3.3 必须产出的分析

- 每格的请求数、tokens、工具调用序列、见证尝试次数与耗时。
- 条件 B 下模型提出的每一份场景假设，原文照录，包括每条前提的分类（攻击者输入 / 部署配置 / 环境）。
- B-a 如果失败，按下表归类：

| 代码 | 含义 |
| --- | --- |
| F1 | 没有调用见证工具，或没走完工具协议 |
| F2 | 场景假设多次被 schema 拒绝 |
| F3 | 场景假设被接受但是错的，见证结果为 UNRESOLVED，列出具体缺口 |
| F4 | 见证基础设施出错：超时、隔离、资源 |
| F5 | 见证已 `CONFIRMED`，但 agent 最终判定不是 VULNERABLE（证据接纳链的问题） |
| F6 | 预算用尽 |

产出 `.hermes/plans/2026-09-29-phase1-results.md` 和 summary JSON，提交后进入阶段 2。

## 4. 阶段 2：按结果分支

- **B-a 成功**：直接进入阶段 3a。
- **B-a 失败，属于 F1/F2/F4/F5**：做**一轮**通用修复（必须满足第 7 节）。修复内容包括合成正反控、完整 pytest 和提交，然后按 G3 只重跑 B 的两格，上限 30 请求。
  - 重跑后无论结果如何都进入阶段 3a。
  - 失败时 3a、3b 只做离线部分，不发模型请求，除非失败原因已明确和样本无关并且已修好。
- **B-a 失败，属于 F3/F6**：不修，如实记录（这属于模型能力，不是工具问题），进入阶段 3a。
  - 3a、3b 的真实模型运行照常进行，因为这正是要测的。
- **任何修复都不得加入针对 hp003 的提示**：不得在 prompt 或工具描述里提 mlserver、`enable_mlserver`、本地目录、`$(...)` 等样本特有的东西。

## 5. 阶段 3a：近迁移样本 entry-00390（不联网）

背景：entry-00390 与 hp003 同属 GHSA-RVHJ-8CHJ-8V3C，漏洞版提交也是 `d1312edf…`，但入口不同，是 `mlflow/models/cli.py:24` 的 click 命令 `serve`；关键操作也不同，是 `mlflow/utils/environment.py:1014` 的 `bash -c`。可以直接复用现有 checkout 和 py312 venv。

### 5.1 建数据集 v6（只追加）

- 复制 v5 为 `advisory_pairs_v6.json`，只新增一对 `hp004_entry_00390_…`。入口和关键操作按 VulnGym 原字段填写。**不写任何场景前提**（`entry_*_assumptions`、`input_parameters` 都留空），因为只跑条件 B。
- 修复版提交先定为 `202fac4c…`，但**必须先核实**：用源码差分和调用链说明，这个提交确实改变了到达 `environment.py:1014` 的命令内容。v6 说明文档里要写出这条调用链。核实不了，就只保留漏洞版一侧，并标注 `pair_incomplete`，不计算配对结果。
- 附带测试：v6 相对 v5 只多了这一对，v1–v5 字节不变。
- advisory 摘要沿用 hp003 的处理方式：去掉编者加的括号注释，只保留标题主干。

### 5.2 离线能力上限检查（`developer_scripted`，不发请求）

1. 用脚本模型给出执行者认为正确的场景，按原协议跑配对见证。
2. 预期可能碰到的通用缺口，都**如实记录**：
   - 入口带装饰器：现在只支持不带装饰器的方法头；
   - `env_manager` 不是 local 时，创建环境会先启动其他进程，首个命令事件被占用（`preempted_by_unrelated_command_event`）；
   - 需要联网安装环境。
3. **允许的通用修复**（第 7 节）：支持通过 click 的 `.callback` 或 `__wrapped__` 调用被装饰的入口。实现成与样本无关、按数据驱动的适配器，并配合成正反控；**只允许这一个框架适配器**。
4. **不允许**：给环境创建打桩、预先造一个假环境、放行非目标命令事件。
5. 如果脚本场景走到的 sink 不是声明的 `environment.py:1014`（例如选了 `env_manager=local`，又走到了 `backend.py:311`），可以记为 `CONFIRMED`（整函数候选的性质是"存在危险路径"），但报告里**必须标明实际发出事件的位置和声明的关键操作不一致**。

### 5.3 真实模型运行（G4）

- **前置条件**：5.2 里脚本场景能让漏洞版得到 `CONFIRMED`。做不到的话，不发请求，直接记录"基础设施上限，模型运行跳过"。
- 满足前置条件时，只跑条件 B 的两格，上限 40 请求，判定标准沿用 3.2 的 B 行。
- 产出 `.hermes/plans/2026-09-29-phase3a-results.md` 和 summary JSON，提交。

## 6. 阶段 3b：外部新样本（需要 G5）

### 6.1 选样（联网范围仅限：GitHub Advisory 页面或 API 只读查询、`git clone` 选中的仓库、从 PyPI 装包并锁 hash）

入选条件，全部满足：

1. GitHub Reviewed Advisory，生态为 PyPI，CWE-78 或 CWE-77。
2. 仓库**不在** `vulngym_heldout_inputs_v4.json` 的 16 个仓库里，**也不在** VulnGym `entries.jsonl` 出现过的任何仓库里，同时不是 mlflow、langflow、open-webui。只比对仓库 URL，**不读** held-out 的标签文件。
3. 有明确的修复提交；漏洞版取修复提交的父提交。
4. sink 是 Python 进程创建：`subprocess.*` 带 shell，或 `os.system`、`os.popen`、`bash -c` 这类。
5. 入口是可以直接调用的 Python 函数或方法，调用它不需要外部服务，例如数据库、云账号、GPU。
6. 依赖能在 Python 3.12 上用 hash 锁定装好，venv 小于 3 GB。

- 按 advisory 发布时间从新到旧逐个检查，**最多检查 15 条**，取前 2 条合格的。选样记录（检查了哪些、为什么排除）全部存档。**这一步不看源码去判断"容不容易检出"**，避免挑选偏差。
- 一条都不合格时，记录后跳过 3b。

### 6.2 接入

- 每对追加进 v7（做法同 5.1：不写场景前提，只写入口和关键操作）。入口和关键操作由执行者根据 advisory 和修复差分标注，**标注理由写进 v7 说明**。
- 环境准备沿用 hp003 的做法：独立的 Python 3.12 venv，目标包从 checkout 通过 `PYTHONPATH` 加载，存 freeze 和 hash。

### 6.3 离线能力上限检查 + 真实模型运行

- 流程和前置条件同 5.2、5.3。
- 允许的通用修复同第 7 节。每对最多一轮修复。
- 隔离准入只能加**单个叶子文件**，写明理由和身份；资源配置只能新增一个**命名的**配置，数值依据实测基线。
- 每对只跑条件 B 两格，上限 40 请求。
- 产出 `.hermes/plans/2026-09-29-phase3b-results.md` 和 summary JSON，提交。

## 7. 通用修复的准入条件（全部满足才能改代码）

1. 代码、prompt、工具描述里**不出现**任何样本特有的名字、路径、函数名、提交号或命令名。
2. 每项修复都配合成 fixture 正控和反控。原有断言不删、不放宽。
3. 不放宽证据契约：
   - 见证仍然只支持 `CONFIRMED`；
   - 只能在进程创建边界拦截；
   - 9 项核验义务一项都不能少；
   - 字面量观察永远不产生 SAFE 或 REFUTED。
4. 隔离和资源的改动只能以显式、带理由的方式新增，默认配置不变。
5. 改完跑完整 pytest 和 harness，然后提交；如果 prompt 或工具定义的哈希快照变了，要写清原因。
6. 在阶段报告里列出每项修复：动机（对应哪个失败）、改了什么、对应哪些测试。

## 8. 硬停点（遇到就停，写报告等用户）

| 代码 | 条件 |
| --- | --- |
| S1 | 任何修复版格子出现 `CONFIRMED`，或判 VULNERABLE（可靠性警报） |
| S2 | 返回的模型 ID 不是 `deepseek-flash`，或者门禁失败且一轮之内修不好 |
| S3 | 任一授权上限（G2–G6）即将超出 |
| S4 | 需要第 0 节"不授权"清单里的任何动作 |
| S5 | 需要修改已有数据集版本（v4–v6）的已有条目，或者需要改证据契约 |
| S6 | 同一类通用修复做了两轮仍然失败 |

停下时写 `.hermes/plans/2026-09-29-STOP-<代码>.md`：说明发生了什么、证据在哪、可选的下一步（不要自行选择）。

## 9. 阶段 4：收尾

1. 汇总报告 `.hermes/plans/2026-09-29-remaining-work-final-report.md`，包括：
   - 每阶段一张结果表：样本、条件、场景来源、见证状态、raw_status、最终判定、请求数和 tokens；
   - 累计请求和 tokens，对照授权上限；
   - **结论边界表**：每条结论能说什么、不能说什么。至少要覆盖：
     - "模型能否在无场景标注时自主得到 CONFIRMED"；
     - "见证基础设施能否不改代码迁移到新样本"；
     - "b 侧从未产生 SAFE，也从未产生假 CONFIRMED"。
   - 每个 `CONFIRMED` 所依赖的前提，分类列出（攻击者输入 / 部署配置 / 环境），不得说成"远程命令注入已证实"；
   - 所有通用修复的清单，以及尚未解决的限制：原生调用、带装饰器的入口、需要创建环境的路径、单样本单次运行。
2. 更新 `docs/CURRENT_STATUS.md` 对应的段落，只写事实，并链接到汇总报告。
3. 完整 pytest 和 harness，最终提交，工作树干净。

## 10. 预算总表

| 阶段 | 请求上限 | 条件 |
| --- | ---: | --- |
| 1 | 60 | 必做 |
| 2 | 30 | 只在 B-a 属于 F1/F2/F4/F5 时 |
| 3a | 40 | 5.2 前置条件满足时 |
| 3b | 80 | G5 授权，且每对都满足前置条件 |
| **合计** | **≤ 210** | 累计 tokens ≤ 2.5M（上一轮约 8.7k tokens/请求，预计 ≤ 1.9M） |
