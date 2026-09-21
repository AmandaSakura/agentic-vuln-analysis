# 最新配对实验复核（2026-09-20）

复核对象：`artifacts/python_heldout_pair_matrix/17fadccd191d4d71bdb74483cbe5a28b`，以及其前置 10 项 gate `cb817f80abe94e0a9f5fb9ab7c60df72`。

## 后续修复状态（2026-09-20）

本报告列出的三处已复现问题已完成代码修复并加入离线回归：

- `validate_permission_mode` 不再把 `return/raise` 后的 `chmod`、循环内 `chmod`、非恒定分支、提前退出分支、或 `os` 绑定不明的调用升级为 `CONFIRMED/REFUTED`。
- `inspect_command_construction` 现在跟踪 `cmd`/`command` 的重新赋值、`+=`、最终返回值和 `shlex.quote` 绑定；未转义追加、伪造 `shlex`、以及返回另一条未转义命令均不再被标为全链路 `SANITIZED`。
- held-out pair acceptance 会报告重复 `(case_id, system)` 结果行，`rows_with_truth` 也会保留重复记录，避免失败行被后续成功行覆盖。

验证结果：`uv run --no-sync pytest` 为 **560 passed in 24.70s**；`uv run --no-sync cv-agent harness-check` 为 **PASS**；`git diff --check` 无输出。本次修复没有调用模型 API。

**结论：运行记录和统计可以对上，当前配置下的验收通过属实；“已无已知逻辑问题”不成立。** 本次额外离线反例复现了两处验证语义缺陷和一处验收健壮性缺陷。它们不等于已经证明原实验的 28 个二分类标签错误，但禁止把该次通过解释为验证器已正确、项目已无 bug 或漏洞均已复现。

本次没有修改检测器、验收配置或历史实验文件，没有调用模型 API。新增证据保存在：

- [账本复核](../../../artifacts/python_heldout_pair_result_review_2026-09-20/ledger_audit.json)
- [离线反例、完整源码及工具输出](../../../artifacts/python_heldout_pair_result_review_2026-09-20/offline_reproductions.json)

## 核实通过的内容

- 重新运行完整 `uv run --no-sync pytest`：**547 passed in 26.96s**；`uv run --no-sync cv-agent harness-check`：**PASS**。下面的新增反例不在这 547 项原有测试中，测试通过没有覆盖这些行为。
- 30 个唯一实验单元，无重复、缺失或账本/结果文件分歧；**28 项 completed 且符合配置标签、2 项 abstained、0 项 failed**。总判定覆盖率为 28/30，即 93.3%。
- E1 为 4/6 判定、2/6 弃权；E2—E5 各为 6/6 判定且符合配置标签。E1 两项弃权在此次运行前保存的配置中已列为 `expected_abstentions`，没有被统计成正确预测。hp003 两个 checkout 的 `backend.py` 内容相同，差异在跨文件 helper；E1 的局部信息确实存在能力边界。
- 269 个唯一请求 ID、269 个原始响应、269 个解析成功的回复一一对应。按原始响应独立求和仍为 **1,218,464 tokens**。269 条代理诊断均为 `upstream_response`，输出上限均为 `matched`；本次没有已记录的上游拦截。
- 实验保存的 201 个源码快照文件与复核时的工作区内容一致，快照哈希无差异；前置 gate 与完整实验的共同源码快照也无差异。gate 10/10 符合标签。
- 完整实验账本从 08:59:59 到 09:09:28 UTC，约 9 分 29 秒；这不含此前的准备和测试时间。

## P1：权限验证器把不可执行或绑定不明的语句当成确认

位置：`src/cv_agent/validation_tools.py:394` 的 `_collect_permission_mode_calls`，以及 `_permission_mode_assessment`。

以下函数中的 `chmod` 不会执行，工具却返回 `CONFIRMED`，附带当前 candidate 的 subject：

```python
def check(path, enabled, replacement):
    return
    os.chmod(path, 0o777)
```

另外复现了空循环中的 chmod 返回 `CONFIRMED`、未知条件分支返回 `CONFIRMED`、`import pathlib as os` 后不存在的 chmod 返回 `CONFIRMED`，以及分支内替换 `os` 绑定后返回 `REFUTED`。反例中的合成函数也用记录调用的 stub 执行核对：前两个反例没有调用 chmod；未执行真实文件权限操作。

原因是遍历未在 return/raise 后终止，未知 if 的两侧被顺序收集，循环被直接 `ast.walk`，导入绑定与分支绑定变化未正确传播。把收集到的最后一个字面量模式称为最终权限状态没有成立。

**对本次结果的影响：** hp001 的真实函数存在 Databricks/非 Databricks 分支，工具未验证分支条件或实际执行权限变更。此 pair 的 10 项判定中合计 14 张 `CONFIRMED/REFUTED` 专家票均依赖该工具。`0o777 → 0o750` 的源码变化属实，但这些状态不足以证明所有运行分支或竞态漏洞已经确认/排除。当前复核没有证明这对样本的二分类标签错误。

修复要求：先为上述反例加入失败回归；按可执行路径处理 return、raise、循环和分支，跟踪模块/变量绑定与目标身份。具体确认必须绑定明确的权限假设及分支前提；用项目自有临时目录探针验证受支持分支的实际结果，或实现有明确支持范围的语义解释。未知路径不能被顺序合并为一次执行。保留真实可达 `0o777`、`0o750` 正反控制，以及先放宽后收紧的时间窗口控制；不能通过全部返回 UNRESOLVED 来替代实现。

## P1：命令检查未跟踪最终返回值，却能阻止正确的漏洞判断

位置：`src/cv_agent/validation_tools.py:557` 的 `_command_construction_facts`；`src/cv_agent/react_engine.py:226` 的 `_contradicts_observed_command_evidence`。

```python
def get_cmd(value, suffix, replacement):
    cmd = f"worker {shlex.quote(value)}"
    cmd += suffix
    return cmd, {}
```

当调用方将返回值交给 `subprocess.Popen(["bash", "-c", command])` 时，`suffix` 仍是未转义输入。工具忽略 `AugAssign`，返回 `SANITIZED`；直接调用结论校验发现 **SAFE 被接受，VULNERABLE 被拒绝**。这不涉及模型采样，完全可离线复现。

另两个反例也得到相同错误行为：局部替换 `shlex` 绑定；给未使用的 `cmd` 赋转义字符串，却返回另一条未转义字符串。证据文件保存了构造出的字符串；没有执行 shell。正确转义与直接未转义两个对照分别返回 SANITIZED/UNSANITIZED。

**对本次结果的影响：** hp003_b 的真实 helper 使用 `shlex.quote(model_uri)` 后直接返回 cmd，本次未观察到上述变体，因此不能据此把其 SAFE 标签改成错误。但工具对一般代码不可靠，且 ReAct 校验会把这种不可靠的静态信号升级成拒绝相反结论的硬约束。

修复要求：将结果关联到候选 sink 实际使用的返回值，跟踪别名、重新赋值、`+=`、分支和 return；核实 quote 的绑定及转义上下文。未知变换不能维持全链路 SANITIZED。结论校验必须允许专家引用同一数据流上的后续未转义证据解释冲突，不能因任何一次静态 SANITIZED 信号就否决 VULNERABLE。回归需同时覆盖三个反例、正常转义控制、未转义控制和无关变量的转义。

## P2：重复实验行会被验收静默覆盖

位置：`src/cv_agent/python_heldout_pair_acceptance.py:25`，另需同步检查 `scripts/run_python_heldout_pair_matrix.py` 的 `rows_with_truth`。

验收直接把 rows 转为按 `(case_id, system)` 索引的 dict。给原来 30 行结果前置一条同键 failed 行后，31 行结果仍返回空 issues，失败行被后面的成功行覆盖。

**对本次结果的影响：** 原始 30 行及账本没有重复，所以此次计数未受此缺陷影响。这是已复现的后续运行完整性风险。

修复要求：在构造索引和写汇总前检查唯一性；同键重复必须报错并保留全部原始记录。测试覆盖失败/成功两种顺序、相同记录重复、缺失、额外单元，以及原本合法的 30 行与两项预期弃权。

## 研究结论及修复验收

三对样本均已用于指导修复，应作为开发/回归数据；历史文件名和 `dataset_role` 中的 heldout 不能恢复其独立性。原文件 `claim_eligible=false` 应继续保留。

此次 E2/E3、E3/E4、E4/E5 的六项标签比较均为平局：没有观测到 Code-RAG 相对文本的召回提升，也没有观测到多专家相对单专家的误报下降，不能支持 +28% 或 -37%。E4/E5 的独立运行请求数为 107/82；同一 E4 轨迹的快速退出重放仅在 hp003 两侧可提前退出，共反事实节省 14 次模型调用。独立运行的 25 次差额不能全部归因于 quorum。

修复实施顺序：先补权限路径语义与命令返回值数据流的失败回归和实现，再修复重复行验收，更新回归数据角色说明。完整离线测试与 harness-check 通过后，先运行不超过 10 项、覆盖三个 pair 的版本化 gate；通过后才能评估是否再跑 30 项矩阵。新反例也必须进入离线门禁，不能只重跑旧的 547 项或把预期标签放宽到通过。比较性能的正式实验还需要未参与这些修复的新 advisory 级划分。
