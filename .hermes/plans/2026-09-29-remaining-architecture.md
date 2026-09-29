# cv_agent 剩余架构（2026-09-29）

本文给出 `2026-09-29-remaining-work-plan.md`（下称 **M0**）之后，以及穿插在 M0 各阶段之间的架构工作。实施者按第 4 节的顺序执行。每个里程碑（K1–K8）都写明：目的、实现要点、测试、预期结果、验收条件，以及失败时怎么处理。

开工前必读：`AGENTS.md`、`docs/TEST_CONTRACT.md`（C1–C6、T01–T16）、`docs/reference/FULL_SYSTEM_SPEC.md`、M0 计划。本文与这些文件冲突时，以它们为准。

## 0. 范围

**在范围内**
- 已有的命令执行见证（`run_bounded_execution_witness`）
- 它的工程化：分层、环境供给、去掉样本特定内容
- E4/E5 集成
- 从"仓库加提交号"自动走到见证的检测链路
- 稳定性与评测协议

**不在范围内**（保持现状，结论一律 `UNRESOLVED`；以后要做须另行设计评审）
- 其他漏洞类别的执行见证，包括授权（hp002）和竞态（hp001）
- 整函数 SAFE 的完整证明
- TypeScript/Go 目标的执行
- Jev 或三臂实验（继续暂停）

**贯穿始终的规则**
- 见证只输出 `CONFIRMED` 或 `UNRESOLVED`。
- 只在进程创建边界拦截，不给目标内部打桩。
- 9 项运行时核验义务一项都不能少。
- 字面量观测永远不产生 SAFE 或 REFUTED。
- 所有开发结果 `claim_eligible=false`。
- 代码修改必须满足 M0 第 7 节的通用修复准入条件。

## 1. 目标数据流

```text
repo + commit
  └─ K3 环境供给 ──────────────► WitnessExecutionContext（venv、准入、资源，均有记录）
  └─ discover_python_repository ─► sink 级候选（StaticScanner，已有）
        └─ K5 入口提升 ──────────► 入口级候选（无场景标注，带 lifted_from / call_chain）
              └─ E1（默认）或 E4 agent
                    ├─ 模型提出 scenario_hypothesis（已有）
                    └─ run_bounded_execution_witness（已有；K1/K2 改造）
                          └─ evidence_policy 准入（已有）→ Verdict
                                └─ Finding：entry_point、critical_operation（取实际发出事件的帧）、前提分类、产物
                                      └─ K8 评测：advisory 级召回，配对修复版上的假 CONFIRMED
```

## 2. 现状与缺口

| 组件 | 现有位置 | 缺口 | 对应里程碑 |
| --- | --- | --- | --- |
| 见证工具 | `tools/validation/bounded_witness.py` | `_SCOPE_NOTE`（第 26 行）把 hp003 的场景文字写死了，每次观察都会带上 | K1 |
| 见证运行时 | `evaluation/diagnostics/bounded_execution_witness.py`、`witness_contract.py`、`witness_values.py`、`witness_branches.py`、`witness_preexec.py`、`witness_scenario_runtime.py`、`isolation_read_policy.py`、`process_resource_accounting.py` | 生产工具反过来依赖 evaluation 层：`bounded_witness.py` 在函数内延迟导入 `run_witness` 等，`witness_manifest.py:23` 导入 `isolation_read_policy` | K2 |
| 执行环境 | `WitnessExecutionContext`（`witness_manifest.py:118`），由可信配置手工提供 | 每个样本都靠手工命令准备（`data/diagnostics/hp003-stage2-*-py312`） | K3 |
| E4 集成 | `plan_policy.py:115-150`：scan 执行 `req-witness-1`，命令构造任务依赖它；taint 的 mandate 允许引用依赖任务的见证结果；`voting.py` 的 quorum=2 | 带见证的 E4/E5 还没做过验收；两张票共用同一个见证观察时，没有单独记账 | K4 |
| 候选发现 | `agents/discovery.py`、`agents/scanner.py` | 只产出 sink 所在行的候选，没有入口，也没有 `input_parameters`；见证要求的是函数头级别的入口候选 | K5 |
| 端到端 runner | `run_vulngym_discovery.py`（只做发现，不调用模型） | 没有"发现 → 提升 → 见证"的整条链路 | K6 |
| 稳定性 | 无 | 每格只跑了一次 | K7 |
| 评测数据 | `vulngym_heldout_inputs_v4.json` | 和这项能力几乎不对应（见 K8），而且没有修复版负例 | K8 |

## 3. 里程碑

### K1 工具输出去掉样本特定内容

**目的**：观察内容里的范围说明必须根据实际执行的场景生成，不能是 hp003 的固定文字。

**实现要点**
1. 删除 `_SCOPE_NOTE` 常量，新增 `_scope_note(scenario, execution_subject)`。它的输出包含两部分：
   - 一句通用说明："This observation covers only the executed concrete input under the listed premises; remote reachability is not established."
   - 结构化的 `premises` 列表，每条给出名称、分类和值的摘要。值摘要复用 `_visible_provenance` 里 `premise()` 的做法：超过 512 字节就只给 sha256。
2. 场景还没确定就返回 `_unresolved` 时，只输出那句通用说明，`premises=[]`。
3. 保留 `remote_authority_established: false`。

**测试**
- 两组不同的合成场景，生成的范围说明不同，各自列出自己的前提。
- 静态测试：`tools/validation/` 下的源码里不能出现 "local directory"、"shell metacharacters" 这类样本特定的文字。
- 更新 prompt/工具定义的哈希快照，写明原因是"范围说明改为按场景生成"。

**预期结果**：hp003 的脚本化配对验收结果不变（a 为 `CONFIRMED/EXPANDED_OBSERVED`，b 为 `UNRESOLVED/LITERAL_OBSERVED`），只有范围说明的文字变了。

**时机**：**在 M0 阶段 2 结束之后、阶段 3a 真实运行之前**落地。不能更早，否则会改变 2×2 实验的条件。

### K2 见证运行时分层

**目的**：核心 agent 不依赖 evaluation 层（`docs/ARCHITECTURE.md` 的依赖边界）。

**实现要点**
1. 新建 `src/cv_agent/runtime/witness/`，把以下文件整体移进去（只移动，不改行为）：
   - `kernel.py` ← `bounded_execution_witness.py`
   - `contract.py` ← `witness_contract.py`
   - `obligations/values.py`、`branches.py`、`preexec.py` ← 对应的 `witness_*.py`
   - `scenario_runtime.py` ← `witness_scenario_runtime.py`
   - `isolation_policy.py` ← `isolation_read_policy.py`
   - `accounting.py` ← `process_resource_accounting.py`
   - `runtime/witness_resources.py` 保持原位。
2. `evaluation/diagnostics/` 下的诊断 CLI（`run_bounded_witness_diagnostic.py` 等）留在原处，改成从新位置导入。**不要保留转发模块**（仓库以前已经删掉过所有转发层）。
3. worker 在目标 venv 里启动（`_worker_path`），它的模块路径会变。必须在两个 hp003 的 py312 venv 里实际验证 worker 能启动。

**测试**
- 新增一个导入边界测试：`cv_agent.tools`、`cv_agent.agents`、`cv_agent.runtime` 都不得导入 `cv_agent.evaluation`。用静态扫描 AST 的方式检查。
- 现有测试只允许改 import 路径，断言一律不动。

**预期结果**：行为完全不变。重跑 hp003 的脚本化配对验收（不调用模型），结果不变；两个快照的 manifest 里目标源码绑定（977 项）完全相同。如果 manifest 摘要有变化，只能出在记录 runner 自身源码的字段上，要逐项列出来。

**时机**：**M0 全部完成之后**。这是一次大范围的源码改动，不能和任何真实运行重叠。

### K3 环境供给模块

**目的**：给新仓库准备 `WitnessExecutionContext` 时，全过程可复现、有记录，不再手工操作。

**实现要点**：新建 `evaluation/preparation/prepare_witness_environment.py`。
- **输入**：仓库 URL、提交号、依赖来源（`uv.lock`、requirements 或 pyproject）、Python 版本、输出目录、`--allow-network`（显式开关，会写进产物）。
- **步骤**：全部照搬 hp003 准备环境时的做法，每一步都记录：
  1. 导出带 hash 的锁定依赖；
  2. 建独立 venv；
  3. 用 `--require-hashes --no-deps` 安装；
  4. 目标包只安装 dist-info，代码通过 `PYTHONPATH` 从 checkout 导入（沿用 `install_metadata_only.py` 的做法）；
  5. 跑 `pip check`；
  6. 导入检查，断言 `__file__` 位于 checkout 内，且 site-packages 里没有目标包；
  7. 测量导入基线（复用 `measure_import_resources.py`）；
  8. 在 strace 模式下跑一次读取拒绝枚举（复用 `isolation_read_diagnostics.py`）。
- **准入**：自动生成的只是**提案**。已经批准过的 4 个叶子文件自动沿用；其他路径列成待审清单，每条要附理由。没有接受记录的一律不生效。
- **资源配置**：按已有公式从基线推导（CPU 取 ×3 后向上取整，AS 取 ×2 等），把基线证据一起写进配置。
- **联网**：只有这个模块可以联网，且只能访问 PyPI 和 GitHub；访问过的 URL 清单写进产物。
- **输出**：`witness_context.json`，包含全部 hash、日志路径和缺口清单。

**测试**（离线）
- 用测试夹具里一个很小的本地项目，配合预构建 wheel 和 `--offline --find-links`。
- 覆盖以下情况：
  - hash 不匹配时拒绝安装；
  - 目标包出现在 site-packages 时拒绝；
  - 准入提案不会自动生效；
  - 没有 `--allow-network` 时不访问网络。

**预期结果**：在新目录里从零重建 hp003 的两个环境，包集合的 hash 与现有 venv 一致，脚本化配对验收结果不变。M0 阶段 3b 的新样本预计有 0–2 对能准备成功；失败要记录 `environment_unavailable` 和具体原因，例如 Python 版本不兼容、原生依赖装不上、需要外部服务。

**时机**：作为 M0 阶段 3b.2 的实现方式，也就是 3b 的环境准备直接用 K3 来做。

### K4 E4/E5 带见证的集成验收，以及共享证据记账

**现状**：在 E4 里，scan 执行一次见证；taint 的命令构造任务依赖这次见证，可以在自己的判断里引用它；quorum 为 2。按设计，一次见证就能支撑两张实质票，但这条路径从来没有验收过。

**实现要点**
1. 仿照 `scripted_witness_acceptance.py`，新建 E4 和 E5 的脚本化验收。使用 hp003 真实快照，见证真实执行，模型由脚本代替。
2. 在 `Verdict` 汇总和结果 summary 里增加两个字段：
   - `material_votes_sharing_validator_observation`：引用同一个验证器观察 ID 的实质票数量；
   - `independent_validator_observations`：实质票引用的不同验证器观察的数量。

   这对应 C5 的原则：多个专家复述同一份证据，不增加证据强度。报告里要写明"quorum 由两名专家解读同一次见证达成"。
3. 断言每个候选每次运行**只执行一次**见证。taint 的工具表里没有见证工具，这一点要写成测试固定下来。

**测试**
- E4 hp003_a：scan 为 VULNERABLE/CONFIRMED；taint 为 VULNERABLE，并引用依赖任务的见证；authz 为 ABSTAIN；最终 VULNERABLE，走 slow 路径。共享计数为 2，独立观察数为 1。
- E4 hp003_b：最终 ABSTAIN，不允许出现 SAFE。
- E5：用固定票序列回放，标签与 E4 完全一致。
- 反例：taint 如果引用一个 `LITERAL_OBSERVED` 的见证去投 SAFE，必须被准入拒绝。

**预期结果**：两个快照的 E4 和 E5 标签分别是 VULNERABLE 和 ABSTAIN，各自只执行一次见证。可选的真实运行：E4 在 hp003 上跑 2 格，上限 60 请求，**需用户另行批准**。

**时机**：M0 阶段 1 出结果之后就可以开始离线部分。如果 A-a 因为协议问题失败，先修协议。

### K5 入口提升：从 sink 候选到入口候选

**目的**：输入只有"仓库加提交号"时，能自动产出见证可以接受的入口候选。

**实现要点**：新建 `agents/entry_lifting.py`，确定性、不读标签。
1. **输入**：`RepositoryDiscovery`（索引加候选），其中一个 `property_id=command-execution` 的 sink 候选。
2. **向上找调用者**：
   - 先取 sink 所在的最小函数，作为 0 跳。
   - 再用 `RepositoryIndex` 的反向图沿调用者往上找，最多 H 跳，默认 3。
   - 只能沿图上已经解析出来的调用边走。已限定名的外部调用不能连到同名的本地函数（遵守现有 Graph 契约）。
3. **入口资格**：复用 `build_witness_manifest` 的入口资格判断（`entry_qualified`）。另外要求至少有一个参数经 `trace_dataflow` 显示 `MAY_REACH` 这个 sink。这只用来排序和筛选，不算证明。
4. **输出**：入口级 `Candidate`：
   - `path` 取入口函数文档路径，`line` 取函数头，`property_id=command-execution`；
   - **不填任何场景字段**；
   - `metadata` 记录 `lifted_from`（sink 候选 ID）、`call_chain`、`hops` 和排序依据。
5. **排序与上限**：先按跳数，再按路径排序。每个 sink 最多保留 K 个入口（默认 3），每个仓库最多 20 个。被截掉的数量要记录下来，不能静默丢弃。
6. **Finding 记录**：见证得到 `CONFIRMED` 后输出 finding，包括：
   - 入口的 file 和 line；
   - critical_operation，取见证里**实际发出事件**的帧（emitter frame）的 file 和 line；
   - 前提分类；
   - 产物路径。

   格式要能直接和 VulnGym 的 ±5 行匹配规则对上。

**测试**（合成仓库）
- sink 分别从 1 跳和 3 跳的入口到达，两种情况都要被提升出来。
- 同名但不在调用链上的诱饵函数不能被提升。
- 没有参数能流到 sink 的函数不能被提升。
- 超出上限时，截断数量要被记录。
- 静态测试：模块不读取任何数据集场景字段或标签文件。

**真实快照离线检查**（开发用）：在 hp003 漏洞版上，从扫描器报出的 `backend.py:311` 这个 sink 出发，提升结果里必须包含 `PyFuncBackend.serve`（0 跳）。CLI 入口 `mlflow/models/cli.py` 的 `serve` 是否也在结果里，如实记录即可。

**预期结果**：hp003 上提升出不超过 20 个入口，已知入口在其中。M0 阶段 3b 的样本上，advisory 标注的入口是否被提升出来，作为开发期的提升召回来观察，不算评测。

**门槛**：M0 里条件 B-a 成功（模型能自己提出场景）才开始。否则提升出来的入口没有场景标注，也不可能得到确认。

### K6 仓库级端到端：发现 → 提升 → 见证

**实现要点**：新建 `evaluation/runners/run_repository_witness_pipeline.py`。
1. 读入开发用的"仓库加提交号"列表，以及每个仓库的 K3 环境记录。
2. 执行顺序：
   - 用 `discover_python_repository` 做全量发现；
   - 只保留 command-execution 类候选；
   - 用 `inspect_command_construction` 的结果**只做排序，不做排除**，因为 `NOT_ESTABLISHED` 不代表安全；
   - K5 入口提升；
   - 对每个入口跑一次 E1 agent，带见证工具，由模型提出场景；
   - 输出 finding。
3. 预算按仓库声明，并写进产物：
   - 每仓库最多见证 10 个入口；
   - 每仓库最多 100 次模型请求；
   - 每仓库最多 20 次见证执行（每次约 16 秒）。
4. 默认使用 E1，成本低。E4 只在对比实验里用。

**测试**
- 合成仓库加脚本模型跑通端到端。
- 预算截断要被记录。
- runner 在运行期间不打开任何标签文件（在测试里拦截文件访问来断言）。
- 同一输入跑两次，finding 的集合和顺序完全一致（不计时间戳）。

**预期结果**（开发样本，需要调用模型）
- **hp003 漏洞版**：产出一条 `CONFIRMED` 的 finding，入口落在 229–231 的 ±5 行内，critical_operation 在 311–317 的 ±5 行内。这就是在开发样本上完成一次 VulnGym 式匹配。
- **hp003 修复版**：同一个 sink 上**不能**出现 `CONFIRMED`；一旦出现，就按 M0 的 S1 可靠性警报处理，立即停下。
- mlflow 里其他 sink 预计大多是 `UNRESOLVED`。其他位置如果出现 `CONFIRMED`，必须人工复核，然后再写进报告：可能是真实问题，也可能是测试工具本身造成的假象。

**门槛**：K5 通过验收。真实运行需要用户另行批准预算。

### K7 稳定性协议

- 在 K4 和 K6 的开发样本上，同一配置每格重复跑 N=3 次。分析方法先登记好：报告每格的成功次数和失败类别（沿用 M0 的 F1–F6），不挑选结果，不改配置重跑。
- **预期结果**：量化出"模型提出场景"这一步的波动。结论只能是描述性的，例如"hp003 上 3 次中有 2 次闭合"，不能外推。
- **门槛**：K4 或 K6 至少有一项真实运行成功过。需用户另行批准预算，预算按 M0 实测的每格成本乘以 3 估算。

### K8 新鲜 held-out 评测协议

**现有 held-out 不适合评测这项能力**。设计时，我统计了 VulnGym v4 held-out 条目的汇总分布，只看了语言和类别的计数，没看具体条目：
- 共 361 条，其中 TypeScript 295 条、Python 36 条；
- Python 这一层里，命令注入最多只有 1 条。

所以用它来评测命令执行见证几乎没有意义。另外，这次统计属于看过评测侧的汇总信息，今后用它做能力相关的结论时要**如实披露**这一点。

**方案**：新建一个能力对口、事前冻结的新鲜评测集，暂名 GHSA-PyPI-CMD-fresh。
1. **选样规则**：GitHub Reviewed Advisory，生态为 PyPI，CWE-78 或 CWE-77，**发布时间晚于冻结日期 T**（由用户指定，必须晚于协议冻结的时间）。
2. **修复版负例**：按 `FULL_SYSTEM_SPEC.md` 里配对负例的规则获取：需要 OSV 的 `fixed` 事件或明确的修复提交，并且 Git 能证明漏洞版提交是修复版提交的祖先。解析不了的样本连同原因一起排除。
3. **排除**：所有开发仓库，以及本项目以往查看过的任何仓库。
4. **选样脚本**：预先提交；按发布时间排序、逐条筛选；目标 20–30 条 advisory。选样过程中不看源码。
5. **数据隔离**：入口和关键操作的标注只保存在评测侧；系统的输入只有"仓库加提交号"，即走 K6 的完整链路。如果另设一档"加 advisory 摘要"的输入条件，就单列为另一个协议，分开报告。
6. **指标**：
   - advisory 级召回：`CONFIRMED` 的 finding 与标注在 ±5 行内匹配；
   - **修复版上的假 CONFIRMED 数**：必须为 0，只要出现就算可靠性失败；
   - 覆盖率、弃权率；
   - 环境准备失败率；
   - 每仓库成本；
   - 按仓库聚类的 bootstrap 区间。
7. **冻结**：代码提交、prompt、预算、模型全部冻结，只跑一次。首次运行后任何修改都只能开一次新的探索性运行，不能替换原结果（spec 已有规定）。
8. **需要用户签字**：冻结日期 T、选样脚本、样本量、预算。

**预期结果**（先写清楚）：召回很可能偏低。失败原因会集中在环境准备、入口提升漏掉入口、模型没提出正确场景这几处。这个评测的价值在于如实量化每一环的损失，以及验证"零假确认"这条可靠性声明。

## 4. 执行顺序与门槛

```text
M0 阶段 0 → 阶段 1（hp003 2×2）
   ├─ K4 离线部分可以同时开始
M0 阶段 2（按 M0 的规则决定是否重跑）
K1（去掉样本特定内容，完整测试后提交）
M0 阶段 3a → 阶段 3b（环境准备用 K3 实现）→ 阶段 4 汇总
K2（运行时分层，不能和任何真实运行重叠）
门槛 G-A：B-a 成功，并且 3b 至少有 1 对迁移成功？
   ├─ 是 → K5 → K6（需批准预算）→ K7（需批准预算）→ K8（需用户签字）
   └─ 否 → 停在这里，写"定位报告"：见证能力作为少量候选的确认工具；列出扩展代价和限制。K5–K8 不启动。
```

每个里程碑的收尾都是同一套流程：完整 `uv run --no-sync pytest` 和 harness-check，然后提交；写 `.hermes/plans/<日期>-<里程碑>-results.md` 和 summary JSON；更新 `docs/CURRENT_STATUS.md` 对应段落，只写事实。

## 5. 预算与授权

| 里程碑 | 是否需要模型请求 | 授权 |
| --- | --- | --- |
| K1、K2、K3（离线测试部分）、K4（离线）、K5 | 否 | 把本文件交给实施者即视为授权 |
| K3 的联网准备 | 否（需要联网） | 按 M0 的 G5 授权 |
| K4 的真实运行 | ≤ 60 | **需用户另批** |
| K6 | 每仓库 ≤ 100 | **需用户另批** |
| K7 | M0 实测每格成本 × 3 | **需用户另批** |
| K8 | 冻结时确定 | **需用户签字** |

硬停点沿用 M0 第 8 节的 S1–S6，另外增加一条：

- **S7**：任何动作需要读取 held-out 或新鲜评测集的评测侧标注。

## 6. 实施者自检清单（每个里程碑提交前逐项核对）

- [ ] 代码、prompt、工具描述里没有样本特定的名字、路径、函数名或提交号
- [ ] 每项行为改动都有正控和反控；原有断言没有被放宽
- [ ] 证据契约没有被放宽：见证只支持 CONFIRMED；没有内部桩；9 项核验义务都在；字面量观测不产生 SAFE
- [ ] 完整 pytest 和 harness 通过；prompt/工具哈希快照的变化写明了原因
- [ ] 结果报告里写明了能说什么、不能说什么；`claim_eligible` 保持不变
