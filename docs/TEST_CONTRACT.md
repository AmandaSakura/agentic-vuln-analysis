# Test contract

The development goal is a reproducible candidate-analysis research system with honest evidence and cost accounting. Passing pytest authorizes an experiment to start; it does not establish vulnerability recall, real-project safety, or research improvement.

| Boundary | Required behavior | Tests |
| --- | --- | --- |
| Candidate evidence | Confirmation belongs to this candidate and source snapshot; other helpers/fixtures cannot supply its proof | security contract, evidence validation |
| Static analysis | Report possible flows and suspicious guards/diffs without claiming exploit confirmation | security contract, taint regressions, validation tools |
| Concrete probe | Reachable builtin eval with controlled inputs is a bounded witness; shadowing/unsupported semantics remain unresolved | Python probe, security contract |
| Graph | A known qualified external call cannot link to an unrelated same-named local function | Python AST, security contract |
| Negative controls | Dead code, safe argv, dictionary update and constant refactoring do not confirm vulnerabilities | security contract |
| Scheduling | One final ballot per expert; dependencies obeyed; fixed-vote fast quorum cannot change full majority label | planner dependencies, agentic workflow, quorum |
| Tool loop | One expert task never re-executes an identical call, and a refused repeat is a blocked observation, never evidence; another task still executes its own assigned validator | react engine, validation tools |
| Retrieval | Same local base and declared augmentation budgets; tools cannot expand admitted paths | retrieval budget, agent budget units, source boundaries |
| Pair evaluation | Benign behavior preserved, intended rejection observed, detector IDs neutral | LangChain reproduction, security contract |
| Usage | Every made request counted; reported usage survives malformed responses and is counted once | model runtime, benchmark evaluation |
| Live admission | Full pytest must pass for the unchanged source snapshot before transport; failure or edits block calls | live gate |
| Test isolation | No real model/network experiment inside pytest; mocks and project-owned loopback HTTP only | conftest, live gate |

Before a repair, add an observable failing behavioral test. Then change implementation and run the relevant tests. Run the entire suite before any live experiment. Keep positive controls so that disabling a detector/validator cannot masquerade as fixing its false positives.

The live gate runs the full suite itself before the first model request in a process. Subsequent requests require identical source/config/test contents. An edit after admission stops the process's model calls; restart after completing the edit. No trusted pass-file or environment skip exists. Gate logs are local artifacts, not reusable admission credentials.

The current Jinja/LangChain checkouts and environments are optional for ordinary offline development, so real-checkout integration tests can skip when absent. Their orchestration correctness is also tested with deterministic mocks without those dependencies. A future LangChain-specific live runner must additionally require the actual pair prerequisites and passing integration checks; generic pytest success with skipped external fixtures is not evidence of pair readiness.

For a clean checkout, install the locked Python environment with `uv sync --locked`,
then run `uv run --no-sync pytest`. The Java boundary tests require Linux, a JDK
with `jdk.compiler`, and `cc`; they compile and execute the pinned two-case
[OWASP fixture](../tests/fixtures/java_command/README.md) in pytest temporary
directories. They do not require downloading `data/raw/BenchmarkJava`. Historical
review files linked by the documentation are tracked individually; bulk experiment
artifacts and real model credentials are not test prerequisites. Launcher tests
copy the scripts unchanged and load fake credentials only from a temporary project.

No automatic retry, provider fallback, broad benchmark run, or claimed safety proof is authorized merely by passing tests. Experiment configuration still defines the request budget and dataset role. HTTP errors/empty model choices are failures, not SAFE votes.

## Semantic contract v1 — 2026-09-26

以下是后续修复的规范与验收标准，不是当前实现已经满足的声明。适用范围是候选绑定、Python 命令/权限分析、证据准入与 ReAct/仲裁；不要求实现通用 Python 解释器。与历史测试期望冲突时，必须指出违反的契约编号，增加正反对照，再明确更新旧测试；不得仅为保持历史成绩而保留错误行为。

本文是这些规则的唯一规范入口。后续修复在现有测试和模块中落地，不要求每次生成 artifacts 下的 Markdown 报告。不以 hp001/hp003 标签、测试数量或开发矩阵变绿作为正确性定义。

### C1. 先定义判定对象，再解释状态

每个实质判决必须绑定：仓库与源码摘要、候选位置、待判定性质、覆盖范围、输入与环境前提。缺少的信息不得从期望标签、案例 ID、文件名关键词或模型猜测补齐。现有 `ValidationSubject` 是绑定载体；本契约不规定立即引入新的类或重构全部序列化格式。

- 待判定性质必须足够具体。例如“输入可作为 shell 语法进入这个调用”与“这个 chmod 调用的 mode 含 others-write 位”是不同性质；后者不等于完整的权限漏洞可利用性。
- `Candidate.property_id` / `ValidationSubject.property_id` 承载机器可核对的性质，并属于候选身份。已适配的权限证明只匹配 `chmod-mode-others-write`，eval 输入见证只匹配 `dynamic-evaluation`，命令证据只匹配 `command-execution`；不从候选 ID、文件名或期望标签推断它们。字段缺失时可展示工具的局部事实，但不能把它升级成这三类候选证明。性质声明本身不证明来源、可达性或消费语义；这些仍必须在分析中核验。
- 位模式和 eval 工具在产生证明前核对源码身份、实际位置及适用输入前提，消费端重复核对性质绑定。不能引用同函数另一处调用的结果作为该行的证明。局部事实不属于候选时，不能作为充分 supporting 证据；真实同范围反证仍不受 citation 角色影响。
- `VULNERABLE/SAFE/ABSTAIN` 是对已声明性质的预测；`CONFIRMED/REFUTED/UNRESOLVED` 是验证器对其明确证明范围的结论。静态证明可以证明有界性质，不能仅靠重命名状态升级为真实 exploit witness。
- 验证器证明范围必须足以支持候选性质才能用于实质判决。范围更窄的结果只是局部事实；`scope_note` 文字不能弥补实际的范围错配。
- 整函数候选包含调用方及其实际调用链中相关的执行与副作用。某行候选只覆盖声明的该执行位置及影响它的前置计算、副作用；同文件其他独立汇点不自动属于它。函数头行号仅可作为现有数据格式的定位方式，不能代替范围语义；带切片偏移和装饰器的定位须有测试。
- “图上相邻”“被检索到”“helper 名字相似”都不证明调用可达。实际展开的 helper 汇点要保留调用来源；helper 单独分析得到的返回值状态不能冒充调用方执行事实。
- 无候选身份的合成单测可以测试局部函数，但不能证明生产入口允许缺失身份的实质判决。

### C2. 分开保存值、执行可能性和副作用

分析必须在逻辑上区分下列信息，不允许用同一个 UNKNOWN 或一个字符串状态替代全部信息：

| 维度 | 必须区分的情况 |
| --- | --- |
| 值 | 已知值/结构、已证明的输入来源、未知值；未知值不等于攻击者可控，也不等于已净化 |
| 执行 | 可继续的路径、确定正常终止的路径、确定抛异常的路径、未解析的继续/异常路径 |
| 副作用 | 已解析且相关、已证明对目标性质无影响、可能相关但未解析 |
| 覆盖 | 声明范围已覆盖、仍有相关缺口；必须保留缺口的来源和受影响范围 |

- 已知解包长度全部不匹配：不得生成其后正常执行路径上的汇点。若异常被外层捕获，须沿已支持的异常路径继续；未支持的异常处理保持未解析，不能断言整个程序不可达。
- 部分备选解包成功、部分失败：必须保留成功分支的后续分析，失败分支终止或进入异常处理。不能因一个失败分支删掉成功分支，也不能把失败分支当成成功。该已知有限分支组合属于必须支持的验收范围。
- 未知解包可以产生未知绑定，但不能据此证明可达性、清除已有副作用缺口，或假定自定义迭代器纯净。未知操作影响不到特定事实须有不影响证明；仅仅“返回值未使用”不够。
- 确定不可达的表达式不执行其副作用；可能执行而未解析的表达式，必须记录相关缺口。已有独立危险路径的证据不因另一条无关路径未解析而丢失。
- 未解析操作位于危险汇点之前、可能改变其值/绑定/可达性时，不能把后续猜测的危险汇点当成完整证据链。

### C3. 条件表达式与 helper 摘要服从同一副作用规则

不能因为一个节点处于 `if` 条件中，就豁免其中的副作用。短路首项和后项、三元表达式的条件和两个结果分支、比较操作数、海象右值、函数调用的实参与函数体，均按 Python 求值顺序处理。对不支持的可执行子树，可选择保守记录缺口；不得静默跳过后再宣称安全。

权限分析必须考虑可能执行的 chmod、os/函数绑定变化、目标别名与其他相关权限操作。仅搜索字面 `os.chmod` 不足以证明任意未知调用无副作用。纯布尔输入上的条件不是副作用；普通函数调用是否纯净则需要已验证摘要或明确的分析前提。lambda 的未调用函数体等延迟执行部分不能作为已执行操作收集。

摘要必须注明函数身份与源码适用版本、输入/类型前提、正常返回关系、可能异常、对参数/别名/全局状态的副作用，以及是否调用相关汇点。任何未证明的字段保持未知；前提不满足就不能套用摘要。

`_download_artifact_from_uri` 不得统一假设“原样保留 shell 字符”，也不得统一假设“返回干净路径”或“绝不执行命令”。只有已核验的具体分派和条件才能支持摘要；本地目录、远程下载及插件分派分别处理。用未知返回字符串替代函数体，不能顺带擦除该调用可能有的副作用。

权限 mode 验证只证明其声明的 mode 性质。存在相关未解析副作用时不得 REFUTED；可达的 0777 不能被另一目标的 0750 抵消；先宽后窄不能自动消除时间窗口。若候选只询问某个 chmod 的位模式，应明确限定该调用，不能给整个函数出具安全结论。

### C4. 命令性质按路径与上下文合并

`SANITIZED` 表示在已解析的具体消费上下文中满足防护条件，不能从“出现 shlex.quote”直接推导。嵌套 shell、后续拼接、容器别名修改或未知消费方式都要重新检查。非 shell argv 的安全证明与 shell 参数转义是不同证据。

| 范围内的路径证据 | 允许的候选结论 |
| --- | --- |
| 至少一条完整、候选绑定的危险路径，前提满足且没有同范围证明冲突 | 可支持 VULNERABLE；其他独立安全路径不抵消它 |
| 所有相关路径均证明不发生目标弱点，且没有相关未解析副作用 | 可支持 SAFE |
| 一条路径安全，另一条相关路径未解析 | ABSTAIN，除非另有覆盖该缺口的有效证明 |
| 只有 MAY_REACH、裸字符串未知、sink 列表或 UNSANITIZED helper 返回值 | 不足以单独支持实质命令判决 |
| 只有 NOT_ESTABLISHED / UNAVAILABLE | 表示没有建立所需事实，不等于证明安全或漏洞 |
| 已知不可达的危险语句 | 不得支持 VULNERABLE；SAFE 还需覆盖声明的其余范围 |
| 同一源码、范围、前提下出现不能相容的充分证明 | 保留冲突并 ABSTAIN；不得按引用选择或状态优先级掩盖冲突 |

UNSANITIZED 的局部值状态不自动等于表中“完整危险路径”。需建立来源、转换、目标消费方式和路径前提；独立危险路径也不能靠未知前置转换凭空成立。不同路径的安全/危险事实不是证明冲突：整函数 SAFE 会被任一有效危险路径否定，而单条安全路径不会。

同一执行状态下重复检查的纯平台条件必须保持关联；中间可能改变条件值时不能强行关联。不得生成现实中不可能的真假组合。评测没有声明 POSIX-only 时不能删掉 Windows 路径；但“已证明不经 shell 且排除了其他相关解释器执行”可以在明确的 shell 注入范围内作为否定证据，不能永远把非 shell 路径等同未知。`shell=False` 字样或 NOT_ESTABLISHED 状态本身不构成该证明。

### C5. 准入由事实与范围决定，不能由调用或引用技巧决定

- 所有有效、已投递且候选绑定的相关观察都进入准入检查。blocked/error、被抑制或截断的 payload 不提供充分证明，也不能满足完整取证要求；初始源码片段是上下文，不是自动生成的验证证明。
- 保持相关事实不变时，添加/删除只重复已知 sink 的静态扫描、添加无关读取、调整独立工具调用顺序、换用同一 observation 的 citation 别名，不得改变准入结果。若工具带来了新事实则不要求结果不变。
- 省略引用或将不利观察放进 counter/unresolved，不能解除它对候选结论的约束。counter 的角色是“反对预测标签”，不是忽略事实的开关。
- 实质结论必须引用足够的 supporting 证据；省略充分正向证据可以使结论被拒，但不能让一个原本证据不足的结论获准。安全证明范围不足时，不能用另一次无关成功工具调用补足。
- 已有危险证据只有在独立性、路径和范围得到说明时才能克服其他未知事实。确定证明间的冲突不能由“引用了 UNSANITIZED 所以优先放行”解决。
- 同一 source_digest、候选和前提下应使用同一准入规则，与 E1–E5、专家名字、模型置信度及多数票数无关。多数票只聚合已准入结论；多个专家复述同一缺口不增加证据强度，也不算独立证明。

### C6. 收尾改变终止方式，不改变证据门槛

| 情况 | 目标行为 |
| --- | --- |
| 证据充分且任务要求完成 | 可以产生实质选票；其余身份、引用和范围校验仍执行 |
| 无成功、完整、已投递的相关工具观察 | 不允许实质选票，任何步骤都一样 |
| 至少一次工具尝试后自愿 ABSTAIN | 可终止；失败尝试保留，但不算验证器完成 |
| 最终预算耗尽，模型仍提交证据不足的实质结论 | 运行时以 ABSTAIN 收尾，明确记录 proposed label、拒绝原因和预算终止；不伪装成模型自愿弃权 |
| 必需验证器未完成 | 记录 validation incomplete；允许终止为运行时弃权，但不能把该任务当成验证成功，也不能满足依赖它的证据前提 |
| 零工具尝试且现有 Vote schema 不允许成票 | 返回显式未完成执行记录/失败，不伪造一次调用或成功选票 |
| 未知引用、身份漂移、非法协议、传输错误、内部异常 | 显式错误；不得作为一般证据不足吞掉 |

模型拒绝配合时的有界弃权必须经过身份和引用合法性检查；原始输出及全部用量保留。预算耗尽不得增加请求上限、虚构工具观察或清空不利证据。2026-09-27 已验证零成功观察下顽固 VULNERABLE 走 `no_successful_observation` 拒绝并最终运行时弃权；这不代表任务完成状态与依赖传播已经符合本表，见下方覆盖核验。

每个专家只有一张最终选票；ABSTAIN 不是 SAFE。早停只对已声明仲裁规则和可比较的固定选票续列保证标签不变，不能据此推断改变调度后真实模型响应也相同。路由器选择取证动作，不产出证据或额外选票。

### Acceptance matrix — 必须按类别验收

以下每行是测试类别，不是一条测试的配额。用参数化、有限组合枚举和端到端正反对照覆盖；不新增网络依赖。S 表示允许支持 SAFE，V 表示允许支持 VULNERABLE，U 表示必须保留未解析/不能给出指定实质结论；S/V 都受 C1 的具体性质范围约束。

| ID | 输入类别与对照 | 必须观察到的结果 | 主要测试位置（tests/） |
| --- | --- | --- | --- |
| T01 | 整函数：危险 helper+安全 caller；安全 helper+危险 caller；双方安全 | 前两者禁 S，完整危险链可 V；双方完整安全可 S | test_hp003_semantic_and_verdict_contract.py, test_review_followup.py |
| T02 | 同文件不同候选行、切片偏移、装饰器、无关 helper | 正确绑定范围，不误借或误删相关事实 | test_scoped_entry_evidence.py, test_evidence_subject.py |
| T03 | chmod 位于 and/or 首项/后项、三元条件/分支、比较、海象、调用参数 | 可能执行的危险操作被收集或明确 U，不能 REFUTED | test_semantic_diagnostics.py |
| T04 | 同组语法中的确定死分支、未调用 lambda；纯布尔守卫；有已验证纯摘要的调用 | 不虚构危险执行；完整安全对照保持 S；无摘要调用不豁免 | test_semantic_diagnostics.py |
| T05 | helper 原地修改参数、别名、全局 os/函数绑定；未使用返回值 | 保留副作用或 U，不得用 unused-return 理由支持 S | test_hp003_semantic_and_verdict_contract.py |
| T06 | 解包：全成功、全失败、成功+失败、成功+未知；嵌套解包；支持/不支持的异常处理 | 成功路径保留；失败路径不生成正常后继汇点；未知不升级为证明 | test_semantic_diagnostics.py, test_review_exception_edges.py |
| T07 | 已知不透明纯字符串 vs 已证明输入来源；摘要前提成立/不成立 | 未知不等于 raw attacker input；失配摘要不提供安全证明 | test_review_command_inputs.py, test_hp003_semantic_and_verdict_contract.py |
| T08 | 正常参数转义、嵌套 shell、转义后追加 raw 内容、argv 解释器消费 | 只在正确消费上下文给 S，危险链给 V，未解析给 U | test_review_context_and_commands.py, test_validation_tools.py |
| T09 | 同一平台条件两次检查、平台前提有/无、中间状态变化 | 保留条件关联或显式 U；禁止擅自限定平台/合并出虚假路径 | test_hp003_semantic_and_verdict_contract.py |
| T10 | 0777 后0750、两个不同目标、条件副作用；单一明确0750/0777模式性质 | 不跨目标或时间窗口抵消；局部模式证明不提升成整体安全 | test_semantic_diagnostics.py |
| T11 | 相关不利证据：引用/省略/counter；静态扫描增删；无关读取；独立调用重排 | 不能通过呈现方式绕过准入；缺少正向支持仍可拒绝 | test_evidence_validation.py, test_hp003_semantic_and_verdict_contract.py |
| T12 | 安全路径+危险路径 vs 同范围矛盾证明；独立危险链+其他未知 vs 未知前置转换 | 按 C4 分别 V、U；不能用统一状态优先级混淆 | test_review_evidence_precedence.py |
| T13 | 正确/错误 subject、摘要、前提、citation；完整/截断/抑制/blocked/error | 只有完整且范围匹配的证据可支持证明，无身份漏洞 | test_evidence_subject.py, test_evidence_validation.py |
| T14 | 正常/收尾阶段 × 零尝试/失败尝试/完整成功/截断成功 × V/S/U | 按 C6 终止，预算不改变证据准入；每条路径用量准确 | test_react_engine.py, test_agent_budget_units.py |
| T15 | 必需验证器完成/未完成；非法引用/身份；自愿/运行时弃权 | 不把未完成标成验证成功；不吞协议错误；保留原因与原输出 | test_hp003_semantic_and_verdict_contract.py, test_agentic_workflow.py |
| T16 | 一个/多个专家复述弱证据，重复任务，同一固定票序列完整/早停 | 弱证据不能由票数升级；每专家一票；符合限定的早停不变量 | test_agentic_workflow.py, test_quorum_probe_workflow.py |

### Implementation ownership and completion criteria

| 边界 | 现有主要模块 | 不应承担的工作 |
| --- | --- | --- |
| 值、路径、执行效果 | src/cv_agent/tools/analysis/commands.py; tools/validation/permissions.py | 不决定专家投票，不借期望标签补语义 |
| 工具证据封装与范围 | src/cv_agent/tools/validation/commands.py; domain/evidence.py; tools/identity.py | 不把局部 helper/模式事实提升为整体证明 |
| 准入 | src/cv_agent/agents/evidence_policy.py | 不重新解析源码补分析器缺失事实，不用调用历史技巧替代证明 |
| 终止与观察投递 | src/cv_agent/agents/react.py; tools/registry.py | 不因预算降低证据要求，不伪造验证成功 |
| 调度、投票与统计 | src/cv_agent/agents/workflow.py; domain/review.py; evaluation/ | 不把多数票变成语义证明，不把失败/弃权移出分母 |

修复顺序：先固定 C1/C2 的范围与事实表示，再按 C3/C4 修分析规则，然后按 C5/C6 统一准入与收尾，最后验证调度组合。可保留现有模块，不以大规模重构作为前置条件；禁止新增彼此独立的重复准入规则。

一类问题的完成条件：对应矩阵类别已枚举且关键正反对照通过；真实分析工具到准入的链路有测试（不能全部手造 JSON）；不支持的情况保留明确缺口；已支持的安全/危险正例不被统一 ABSTAIN 掩盖；相关测试与完整离线套件通过。旧测试改期望须标明契约编号及改变原因。复现一个反例并增加一条测试，不足以宣布整类修复完成。

验收说明只需列出契约编号、测试命令/结果、仍未覆盖的类别及能力变化。不得把本节矩阵标成已覆盖，除非逐项检查实际测试。真实实验是后续单独验证覆盖率/成本的阶段，不是上述语义验收的替代品；历史成绩与新契约结果必须区分版本。

### Coverage audit — 2026-09-27

本节矩阵与 B1–B3 复现描述记录修复前快照；后续实现进度见文末，不把历史反例描述当作当前验收状态。

本次仅核验上述 T01–T16，不修改检测实现，不调用真实模型。状态定义：**主链已验**表示已有真实工具/运行链正反对照，不表示该类所有组合已穷尽；**部分**表示只有局部断言、缺少组合或端到端证据；**阻断**表示已复现与契约相反的结果。测试通过与契约通过分开记录。

| ID | 状态 | 已核验的证据与剩余边界 |
| --- | --- | --- |
| T01 | 主链已验 | `test_function_head_safety_must_retain_reachable_helper_sink`、`test_both_safe_helper_and_caller_support_safe`、`test_helper_sanitized_status_cannot_mask_caller_unsanitized_sink` 使用真实命令工具和准入；覆盖直接已展开 helper，不代表不透明调用安全（B1）。 |
| T02 | 部分 | `test_line_scoped_candidates_bind_their_own_sink_line` 检查两行 sink，偏移部分只断言 `_candidate_local_line == 3`；`test_unexecuted_helper_cannot_pollute_the_candidate` 检查工具事实。尚需偏移/装饰器的真实解析→工具→准入链，不能把行号换算当成整链验证。 |
| T03 | 主链已验 | `test_permission_condition_positions_with_chmod_stay_unresolved`、lambda/比较回归及 `test_permission_statement_calls_preserve_effects_and_block_safe_vote` 覆盖条件、实参和语句位置；仅涵盖显式枚举的表达式，不能声称任意 Python 对象协议无副作用。 |
| T04 | 部分 | `test_permission_statement_effect_controls` 覆盖死分支、延迟 lambda、os.makedirs 现有摘要的 S/V 对照；摘要身份/类型/版本前提及复杂关联死分支尚未成矩阵。 |
| T05 | 阻断 | 已展开 helper、容器别名测试通常只断言“不是 SANITIZED”；未解析调用返回值未使用时仍可获 SAFE，见 B1。权限模块修复不能算作命令模块的副作用覆盖。 |
| T06 | 部分 | 单目标 Choice 成功/失败/未知、嵌套和旧值合并已有测试；循环目标及多目标赋值仍走单次 assign（L1）。`test_review_exception_edges` 等 flow 测试属于污点分析，不能替代命令解释器异常语义验证。未知迭代的安全边界归 B1。 |
| T07 | 部分 | `test_boolean_entry_condition_selects_branch_but_does_not_invent_download_semantics` 区分返回值，`test_declared_input_parameter_starts_only_a_may_flow_trace` 限制污点证明强度；但前者期望 download 未建模时仍 SANITIZED，尚未覆盖调用副作用（B1）。下载分派摘要未实现，保持能力限制。 |
| T08 | 主链已验 | `test_secondary_shell_after_quoting_cannot_be_sanitized`、`test_numeric_argv_does_not_sanitize_executable_standard_input`、validation tools 的 quoted/unquoted 对照及 `test_non_shell_code_execution_keeps_matching_taint_evidence` 覆盖关键消费上下文；不等于所有解释器/平台已支持。 |
| T09 | 阻断 | 显式入口布尔参数及身份绑定已有测试；没有重复条件关联的端到端保障，未赋值改变的同一 flag 可生成不可能危险路径并获准，见 B2。 |
| T10 | 部分 | 先宽后窄、多目标、条件/调用副作用和直接模式对照存在；“位模式证明”与“整体漏洞证明”的范围适配仍需核对，不能仅凭相同 subject 或 scope_note 认定覆盖。 |
| T11 | 主链已验 | 静态扫描增删、AMBIGUOUS/SANITIZED 引用/省略/counter、无关读取和独立工具重排已有准入对照。冲突证明是否相容另归 T12。 |
| T12 | 部分 | `test_deterministic_proof_overrides_incomplete_command_analysis` 和 typed 冲突测试覆盖具体证明；`test_sanitized_trace_still_allows_safe_and_unsanitized_vulnerable` 手造同候选同 sink 的两种状态但未标不同路径，仍允许 V。不足以证明能区分“不同路径”与“同范围证明矛盾”，需 V1。 |
| T13 | 部分 | `test_confirmation_requires_exact_candidate_and_source_subject`、fixture 注册绑定、截断/抑制/citation 拒绝有测试；这些不能外推为所有静态工具具有同样的 digest/前提/范围校验，需 V1 的生产入口对照。 |
| T14 | 主链已验 | ReAct 修正/收尾、`test_finalization_without_successful_observation_ends_as_runtime_abstain`、预算 payload 和 usage 测试覆盖主要终止链。未声称状态笛卡尔积已穷尽；零尝试仍受 Vote schema 限制。 |
| T15 | 阻断 | `test_incomplete_validation_task_demoted_with_validator_uncompleted_record` 只测单专家终止及 rationale；工作流仍将其列入 completed 并放行依赖，跨专家提示未传递 validation-incomplete 标志，见 B3。 |
| T16 | 主链已验 | `test_repeated_tasks_do_not_give_one_expert_multiple_quorum_votes`、E4/E5 工作流正反例及 `test_early_exit_matches_full_review_across_labels_and_confidence_threshold` 的 9³ 固定票组合；并不证明多专家证据独立或真实模型调度改变后输出不变。依赖失效仍受 B3 阻断。 |

#### 已复现的冻结阻断项（限定为三类机制）

**B1 — 命令分析中未解析执行效果可以消失（C2/C3，P1）。** 在 `def entry(value):` 中先执行 `mutate(value)` 或 `a, b = value`，随后执行 `os.system('echo ' + shlex.quote(value))`：当前分析为 SANITIZED、issues 为空，真实命令工具→整函数准入接受 SAFE。前者的未知函数可能自行执行命令，后者的迭代协议可能有副作用；转义后续参数不能证明它们无影响。已有 `test_unrelated_destructuring_allows_analysis_to_proceed_safely` 正在保留过强结论。修复目标是保留相关调用/迭代效果缺口，并使工具封装与 SAFE 准入消费它；有明确类型和纯净摘要的路径保留安全正例。不要把所有返回值标 raw，也不要把所有独立危险见证一起删掉。

**B2 — 条件关联丢失制造不存在的危险执行（C2/C4，P1）。** 以下例子当前得到 UNSANITIZED、issues 为空，并通过 VULNERABLE 准入：

```python
def entry(value, flag):
    if flag:
        cmd = 'echo ' + shlex.quote(value)
    else:
        cmd = value
    if flag:
        os.system(cmd)
```

在纯布尔 flag 的前提下，实际执行到 sink 时必定采用安全构造；如果不接受该类型前提，也应明确未知，不能凭不相容的路径生成充分危险证据。修复目标是保留路径约束/绑定关联，或在丢失关联时阻止相应实质证明；保持真实可达危险分支的正例。重复平台条件是同一机制，不另开 hp003 特例。

**B3 — 终止被当成依赖验证完成（C6，P1）。** 用现有 `_permission_index_and_candidate(guard='enabled', literal_body=True)` 与 `_permission_models` 的 scan-mode→authz-mode 计划，将 scan 脚本改成 6 次 read_span 加 2 次合法 ABSTAIN，不执行 validate_permission_mode。实际 scan 以“Assigned validator ... did not complete”运行时弃权，authz 仍启动（2 次请求）；提示放入 `Completed dependencies`，且跨专家内容不包含未完成原因。此复现证明错误依赖放行和状态丢失，未证明 authz 的独立检查结果本身错误。修复目标是结构化区分任务终止、验证器已执行及证据充分性；依赖策略显式检查所需状态，失败传播有界终止，不靠解析 rationale，不把 blocked 依赖反复重调度。完成但 UNRESOLVED 与根本未运行必须分开。

复现 B1/B2 使用现有 `test_review_followup.inspect_and_trace` 生成真实工具观察，把 subject.entry_line 设为 1，再用同文件 `vote` 检查 SAFE/VULNERABLE；没有模拟模型语义或手造 sink_facts。B3 使用 ScriptedChatModel，未发送真实请求。以上是当前树的行为核验，不声称这些机制都是上一轮修改才引入。

#### 能力限制与验证欠账

- **L1（P2）：循环/多目标解包。** `pair = (1, value) if flag else (1,)` 后分别用 `for a,b in [pair]: os.system(b)` 和 `copy = a,b = pair; os.system(b)`，当前均为 AMBIGUOUS、unresolved destructuring issue、无 sink。两项已测行为是保守漏检，不是已发现的错误 SAFE。若暂缓实现，必须补“未知不获实质结论”的工具→准入测试并明确未满足 T06；不能宣布 T06 完成。
- **L2：摘要和平台覆盖。** 下载分派、一般对象协议、任意 helper 语义和跨平台非 shell 证明不在本轮能力扩展范围。安全地 UNRESOLVED 可保留；被当成无副作用则归 B1，不能以不支持为由豁免。
- **V1（冻结前验证）：证明范围与冲突。** 用真实工具/fixture 给 T02 的偏移和装饰器补整链验证；对 T10/T12/T13 分别构造局部性质 vs 整体性质、不同路径 vs 同范围矛盾、相同路径但不同 digest/输入前提的准入正反对照。现有合成测试不足，暂不宣称已发现每个组合都存在实现错误；发现失败时归入范围/准入边界修复，不能只改期望。

#### 本轮证据与停止条件

本次重新运行以下 16 个相关测试文件：**511 passed in 13.09s**。全量 **1330 passed in 34.04s** 是上一轮实现修复后的记录，本次没有改代码，也没有重新执行全量或真实矩阵。

```bash
uv run --no-sync pytest tests/test_hp003_semantic_and_verdict_contract.py tests/test_semantic_diagnostics.py tests/test_review_followup.py tests/test_scoped_entry_evidence.py tests/test_evidence_subject.py tests/test_review_command_inputs.py tests/test_review_context_and_commands.py tests/test_validation_tools.py tests/test_evidence_validation.py tests/test_review_evidence_precedence.py tests/test_react_engine.py tests/test_agent_budget_units.py tests/test_agentic_workflow.py tests/test_planner_dependencies.py tests/test_retrieval_and_consensus.py tests/test_quorum_probe_workflow.py
```

下一轮收尾顺序：B1/B2 分析事实 → B3 调度状态 → V1 整链验证 → L1 明确实现或保守边界测试 → 全量离线 → 冻结快照。该轮只针对这些已列出的机制和矩阵类别，不扩展新漏洞类型或追求开发集成绩。B1–B3 的反例与正对照通过、V1 无未处理的实质判决错误、L1/L2 不越权给证明后，才进入有预算的小规模真实验证；允许诚实弃权与覆盖率下降。不能用“511/1330 都绿”覆盖本次已复现的契约冲突。

#### Implementation checkpoint — 2026-09-27

最新离线全量 **1758 passed in 32.20s，exit=0**（提示词同步后最终回归；上次 1758 passed），没有真实模型调用。此记录是阶段验收，不是冻结完成声明。

- **B1 调用、迭代与写入反例已修复**：未解析调用及未知迭代保留执行效果缺口，不能支持整函数 SAFE；布尔运算、比较和一元运算按求值顺序访问操作数。未知对象属性写入、模块别名写入、带未解析调用的字典键写入保留缺口；新建 builtin 字典及其别名的普通键写入是正例。确定短路的死调用不污染安全对照。未知操作之前的独立危险汇点仍保留；解析完整的纯 helper 保留安全能力。后续读取协议修复见下文，不能由这些用例宣称任意对象副作用均已覆盖。
- **B2 函数内条件与循环关联已修复**：普通名称条件及 not、赋值/返回位置的条件表达式按路径执行后续语句；纯 and/or/not 组合按有界布尔路径分析。保留值绑定和条件假设，中途改写条件不会强行沿用旧真值。有界循环的正常退出、break/continue、else 和嵌套循环 else 的外层退出保留实际后继，不在循环出口提前合并值。真实工具→准入覆盖同条件、取反、重绑定和复合条件的安全/危险对照。调用间进度见下文；其他复杂条件与对象协议保留未解析；后续 T09 的声明场景、关联条件与重绑定验收见文末，不声称实现通用求解器。
- **B3 依赖状态已修复**：`ValidationTaskExecution.validator_completed` 与 `AgenticVerdict.blocked_tasks` 明确区分任务终止、验证器完成和依赖阻塞。未执行验证器阻塞直接/传递依赖，独立任务继续并全额记账；实际完成但 UNRESOLVED 的验证器仍可满足调度依赖。旧序列化快照仅迁移新增字段，原判决与用量不变。
- **V1 身份与冲突主链已修复**：命令工具核对索引的实际 source digest、仓库与入口，再附带 subject；生产候选不得使用缺失 subject 的命令证明，亦不能跨候选、digest 和入口前提借用证明。旧合成正例补齐声明身份，真实工具正例使用索引实际 digest，不恢复缺失身份放行。整体安全与整体危险两份冲突的命令证明要求弃权，单次分析中不同安全/危险路径仍可支持 VULNERABLE。后续偏移、函数头及装饰器准入组合已按文末 T02 核验；未建模装饰器保留未解析。
- **L1 已列反例已修复**：循环目标与链式多目标赋值按 RHS 同一备选执行解包，已知失败备选终止，成功备选保留汇点。真实工具→准入的成功/全失败对照已通过。L2 的一般对象协议仍为开放边界，不引入下载摘要或 POSIX 特例。
- **B2 调用间已列反例已修复**：helper 需要未确定输入真值时，调用方保留相应分支并沿各自状态分析返回值和后续语句，不提前混合互斥返回值。约束按实际参数值和命名绑定传递，覆盖位置/关键字参数、条件取反、调用前后改写、内联调用和 helper 自身危险汇点保留；`not` 的值关联不退化成共享 UNKNOWN。仍未声称任意比较约束、对象真值协议和任意 helper 语义均已支持。
- **B1 读取及协议操作已列反例已修复**：未知属性/下标读取、整数转换、quote 参数、比较、加法、一元操作与格式化不会因返回值未使用而消去相关效果缺口；格式化中的实参和格式说明按顺序访问。已知 tuple/string 读取与纯文本输入操作保留正例，先于缺口的独立危险汇点继续保留。原 request.args 正例缺少 getter 纯净前提，现保留为拒绝对照，数字 argv 规则改用明确声明的纯文本输入验证，不添加任意框架对象的纯净摘要。
- **C2/B2 原语终止与表达式关联**：已知非法整数转换、越界和不兼容原语操作按 KnownPathFailure 终止该路径，不生成其后危险汇点；正常转换保留正例。嵌在调用参数里的条件表达式也沿调用方约束分叉。未建模的比较关系明确未解析，不能通过提前合并制造虚假危险路径；已知常量比较仍正常分析。没有声称支持一般 Python 约束求解。
- **V1 切片范围检查已修复**：工具核对候选行是否落在实际索引文本内，输出 source_line_count；消费端同样拒绝越界位置，不能借用原观察或重跑工具来绕过。正常函数头和准确汇点行在切片偏移下均有真实工具→准入正例。
- **V1 函数头范围已修复**：命令工具输出解析得到的 function_header_lines，准入使用实际函数头而非固定本地行 1 识别整函数范围。有前导 import/空行、切片偏移的安全/危险正反例通过；未建模装饰器仍不得支持实质判决。
- **C4/C5 命令证明义务已收紧**：静态命令匹配、权限守卫模式或源码读取不能替代对应标签的命令证明。新增真实工具反例覆盖静态扫描单独引用、守卫不能反驳命令危险；旧的“只引源码即可放行”合成断言按 C4/C5 改为拒绝，并保留充分命令证明的正例。错误反馈继续明确 supporting 与 counter/unresolved 的区别。
- **V1 权限性质及位置借用已修复**：真实权限工具曾将另一行 chmod(0777) 的证明绑定给不可达命令候选；现在输出局部性质并仅为明确匹配的 property_id 附加候选证明。行候选选取该行 chmod，不同目标/行、切片偏移有安全和危险正对照；完整源码身份与行范围不符时阻止工具运行。调用方/扫描器/规划及专家上下文保留性质声明，旧开发数据配置不自动改成更窄的性质。
- **V1 eval 同类证明借用与场景参数已修复**：eval 探针只为对应性质及已见证位置绑定确认结果；函数头可覆盖实际执行链，其他行不能借用其见证。实际探测接收 entry_boolean_arguments，不再忽略候选 False 而沿函数默认 True 执行。适用性质、正常汇点、整函数和切片偏移保持确认正例，局部事实不丢失。
- **C1 消费端检查统一**：已匹配的权限/eval 证明、肯定安全证据和具体验证反证共用性质绑定判据；旧记录仅有 subject、没有对应性质声明不能直接支持实质判决。其他动态分析的既有未验证预测规则没有被自动改为必须有具体执行见证；这部分不能与 CONFIRMED 混称。
- **C5 命名规则已修复**：候选 ID 与路径里的 command 关键词不再决定命令准入，明确 property_id 优先；保留性质声明和工具事实判据，增加中性 ID/路径对照。
- **V1 命令性质兼容路径已修复**：实际工具只有在 property_id 为 command-execution 时才绑定候选；消费端不接受无性质或不同性质的 SANITIZED/UNSANITIZED 证明，旧观察再次盖 subject 也不能绕过。16 个真实工具对照覆盖两种标签、四种性质声明、中性/command 命名及旧 stamp。旧命令正例补齐声明，原断言保留；其他性质的测试保留完整 command 轨迹，但不把它引用为自身的支持证明。
- **C1/T07 已声明命令来源已接入解释器**：command_construction 将 input_parameters 传入 analyze_command；声明的文本来源生成 raw 片段，其他入口参数保留 UNKNOWN（包括类型和执行效果），entry_boolean_arguments 再施加固定布尔场景。缺失参数名产生明确 issue。低层无候选诊断仍可作符号字符串分析，但不提供候选证明。
- **T07 实际工具验收**：直接调用/helper 两种形式各比较 value、other、空来源集合以及转义；仅声明 other 不能令 value 支持 VULNERABLE，未知对象也不能通过 quote 自动获得 SAFE。补充覆盖来源被未知值/字面值覆写、无输入的安全常量、未知真值效果、固定 True/False 场景及非法声明。旧危险/安全正例明确声明自身的数据和控制参数，断言未放宽。新增 17 项，整链与全量通过。
- **C1/C3 权限布尔场景已修复**：entry_boolean_arguments 接入权限求值，条件、短路、三元和比较使用当前绑定；普通赋值及海象更新绑定，未知分支分别执行后合并，异常处理不沿用正常路径独有的值。固定 False 下不可执行的 chmod 不再输出确认；只有危险汇点且被关闭时保持无事实的 UNRESOLVED，有安全 else 时可 REFUTED，True 危险正例仍 CONFIRMED。无法确定的重绑定参与条件时产生明确缺口。新增 31 项真实工具回归与正对照；初始 16 项中 14 项修前失败，全量现通过。此结论只覆盖有界权限场景，不扩张为任意 Python 控制流证明。
- **C1/T07 eval 来源声明已接入探针**：候选绑定的请求注入必须要求首个 request/req 参数在 input_parameters 中，并检查声明名称确实存在；不再将名称本身当作外部控制证明。无候选的本地诊断保留原先明确的 request 注入假设，不能成为候选证明。工具输出记录来源与布尔场景。直接调用/helper 的 8 个反例修前 CONFIRMED、修后 UNRESOLVED；正确声明的正例继续确认。另覆盖 req 别名、常量覆写、固定真假场景和来源发现→实际工具→工作流；共新增 20 项，全量通过。C1 迁移：纯源码发现不再自动确认外部控制；项目自有正例显式声明 request，断言未弱化。工具说明及其嵌入 planner 的哈希只因新增此前提说明而更新，已通过去除此句复原旧哈希核对。
- **V1 当前 advisory 配置已声明性质**：三个活动配置目标分别为 temporary-directory-race、authorization-boundary、command-execution。前者仍要求临时目录权限暴露所导致的竞态/下游影响，后者授权性质仍要求主体、动作、资源及预期归属关系，不等于局部 chmod 位模式或 guard 存在。原标签、矩阵、预算、输入场景、claim_eligible=false 和预声明弃权均保留。缺少 property_id 的历史配置可以读取，但 build_pair_input 在索引前拒绝开启新候选运行。新增配置→候选→真实权限工具→准入正反例：0777/0750 的局部性质可分别判定，均不能借给竞态性质。配置迁移测试去除三个字段后须复原原始字节哈希；历史文件未改写。
- **V1 自动发现性质缺项已修复**：scanner 的全部规则都声明 property_id，权限规则明确对应 chmod-mode-others-write，其余规则使用各自性质。五类新增真实发现→read_span→准入反例（数据库、模板、授权、动态属性、进程控制）修前允许仅凭源码读取提交 VULNERABLE，修后因缺少性质证明被拒，ABSTAIN 保持允许。另将既有精确 subject 证明的准入正反例扩展至这五类：匹配证明可确认，候选/源码/位置/性质失配不能借用。新增 10 项，全量 1590 通过；没有新增这些类别的语义分析能力，不声称仅设置性质就提高检出率。
- **C1 公共入口已拒绝缺失性质**：AgenticPipeline.run 在 graph/model 执行前检查 property_id。None、空串、纯空白 × E1–E5 的 15 项回归修前均失败，修后明确 ValueError 且请求数为零。既有 eval 工作流/调度正例补齐原有 eval 性质，LangChain 开发入口明确为 template-traversal；不依赖候选 ID 或标签推断性质。
- **C5/T16 旧弱票演示已迁移**：scripted 的 cross-file 命令与授权案例保留原先静态 VULNERABLE 提议，准入拒绝后才提交 ABSTAIN，纠正请求完整计数。E1/E3/E4/E5 均不能用这些弱票产生实质判决，旧“降低误报”比例不再伪报为收益。fast-path smoke 改为已有真实 eval 探针正例，显式断言候选绑定 CONFIRMED、两票 fast、未调用 authz。只更新这两项诊断快照，原 synthetic 基线与 schema 快照保留。此结果不声称穷尽所有弱证据组合。
- **V1 PythonPair/micro/Luna 入口已适配**：PythonPair 配置及构造器显式传递 template-traversal / sandbox-attr-format-escape；缺失性质在索引前报错。LangChain 完整包入口在创建 pair 时声明性质，不再事后改候选。micro 四个 eval 案例和 Luna 两个案例声明 dynamic-evaluation 与 request 输入；实际探针在真正可达输入的正例确认，在常量和未支持的清洗路径维持 UNRESOLVED。两个配置新增字段去除后须还原原始字节哈希，原标签和矩阵未变。
- **C1 模板 fixture 性质范围已校验**：注册的 pair/fixture 身份决定其固定证明范围，pair.property_id 与 candidate.property_id 都须匹配；独立 LangChain preflight 适配器同样检查 template-traversal。8 个反例修前可把模板事实绑定成其他性质，修后明确拒绝；已有 CONFIRMED/REFUTED 的匹配正例仍通过。本轮共新增 17 项，全量 1622 通过，没有真实模型调用。
- **V1 OWASP 入口已声明性质并隔离结果标签**：loader 接收显式 property_ids；缺项/空白/覆盖错配在源码读取前拒绝。无声明仅保留给读取/检索用途，不能进入公共工作流。通用 CLI 要求 --property-id；development、ten-trial、retrieval-validation、preparation 和诊断显式读取 configs/datasets/owasp_properties.json 中原 66 个开发任务的独立声明。冻结 truth manifest、案例选择和标签未改。实际离线工作流对照同时修改 CSV category/CWE/vulnerable，候选、subject 性质及全部模型请求保持一致；运行时不从这些结果字段或案例名推断目标。
- **C1/T10 Java 进程边界事实不再冒充命令注入证明**：真实 fixture 只验证受控 token 在当前 payload/helper stubs 下是否到达进程边界，其明确性质为 java-fixture-token-reachability；到达不等于 shell 注入，单次未到达不等于所有输入安全。命令注入候选得到 UNRESOLVED，保留 local_validation_status 与进程观察；实际 fixture→注册工具→准入链拒绝据此 VULNERABLE/SAFE，ABSTAIN 可用。明确询问 token 实验的原正反例仍有 CONFIRMED/REFUTED。原 OWASP 命令注入任务未缩小，不能仅靠此 fixture 达成旧十格验收。本轮新增 10 项，全量 1632 通过。
- **T02/T13 Java 实际入口绑定已修复一组确定反例**：fixture 固定执行 doPost；构建时现在核对注册源码路径、仓库、实际签名与方法头位置，并重新解析入口及实际编译的四个 helper，与索引文档（含元数据）逐项比较。doGet、错行、错仓库、缺少入口文档、入口文本/helper 文本/调用元数据错配共 7 项修前失败，修后拒绝；原真实 token 正反例仍通过。相关 14 项通过，全量 1639 通过。这里验证的是方法文档一致性；没有证明方法外的字段初始化、imports、资源与旧索引快照一致，不将其写成完整原始文件身份保证。
- **C1/C5/T16 动态 eval 弱票链已修复**：删除 dynamic-evaluation 对通用匹配证明要求的例外；MAY_REACH、sink 或 sanitizer pattern 不能单独支持实质标签。真实 eval 探针的 CONFIRMED 仍能支持 scan；taint 原始 VULNERABLE 提议由准入拒绝，再用额外一次请求提交 ABSTAIN，原提议、纠正与用量均保留。C01 的 E4/E5 均为三票 slow/ABSTAIN，不再报告两票早停收益。新增六项标签×自报验证状态对照：修前 UNRESOLVED/VULNERABLE 实际放行，其余组合已拒绝但错误类别不同；修后统一因缺少匹配证明拒绝，ABSTAIN 仍可用。旧 eval sanitizer 流断言保留并加强，但不再等同于完整 SAFE 证明。路由/计费用例以合法弃权保留原预算与调用数断言；真实命令工具提供两票 VULNERABLE 早停和恢复任务后两票 SAFE 早停的正对照。仅更新 agentic_smoke 行为快照，不改 synthetic/schema 等其他快照。
- **C1/T02/T13 Java 完整源文件绑定已修复**：五项反例修前均失败：方法文本不变时，入口字段、import、helper 字段及资源分派的变化仍可通过 fixture 构建，字段不同的文件甚至产生相同 subject digest。Java 方法文档现在携带完整文件 source_sha256，候选身份包含该哈希；已有构建时重新解析比较因而能拒绝旧索引。两个运行资源限定为已登记的上游哈希，不为未登记分派提供实验结果。新增重新索引正例：无害字段更新后身份改变，匹配的新索引仍能运行真实 Java 实验并保持 REFUTED。其他适配器未提供完整文件哈希时不改变旧摘要；解析快照仅新增该字段，已核对去除此字段后全部旧内容相同。范围仍是该有界 fixture 的源码和固定资源，不扩张为完整 Java 应用/环境的漏洞证明。
- **C3/T04 makedirs 摘要前提已收紧**：先前把未知 Name、整数和 None 路径都视为无权限副作用；调用位于 chmod 前后共 8 个反例修前都获得 REFUTED。现在仅为已知 builtin str/bytes 常量或其已知绑定应用现有 stdlib-os 摘要，未知 PathLike 进入正常未解析调用通道；真实运行对照证明 __fspath__ 可执行用户代码（在任何文件写入前主动抛错）。正常返回值建模为 None，不再把该调用的真假当作未知：此正例修前 UNRESOLVED、修后仅保留 false 分支的 0750。字符串/字节串与赋值绑定 × 0750/0777 共六个正例继续通过，原摘要对照明确改用普通字符串路径。新增 16 项，全量 1667 通过。该摘要仍受既有 stdlib 绑定与有界正常执行前提约束，不证明任意文件系统成功或整体权限漏洞；不将 T04 全类别标为完成。
- **C3/T04 装饰器名称豁免已删除**：此前 cache_return_value_per_process、functools.cache/lru_cache 和 lru_cache（含无参调用形式）只按拼写被认定保持函数体，未验证绑定、源码或参数协议。8 种拼写 × 0750/0777 共 16 项真实工具→准入反例修前均得到实质状态；修后 UNRESOLVED、无绑定证明，两种实质标签均被拒。真实 functools.cache 对照还确认参数 __hash__ 会在函数体外执行。当前没有装饰器语义摘要，装饰入口保留明确未解析，不声称其函数体就是实际调用效果；原两个 cache 名称放行断言按 C3 迁移，普通函数的 0750/0777 正例保留。相关 82 项通过，未调真实模型。
- **C2/C3/T04 未知对象隐式协议已保留缺口**：未知入口值的 truth、比较以及普通属性读取不再默认为纯操作。三种操作 × chmod 前后共六项反例修前均 REFUTED，修后 UNRESOLVED 且不附候选证明；实际 Python 对照分别验证 __bool__、__eq__、property 会执行用户代码。显式布尔场景、已知字符串比较和常量死分支保留正例；循环/表达式绑定中的未知对象不能因最终值一致清除副作用缺口。旧“裸变量/平台属性天然纯净”期望按 C3 收紧；重复工具/收尾机制测试仅换用明确 False 守卫，原实质判决、预算和用量断言保留。本轮净增 14 项，全量 1698 通过。
- **阶段状态与结束边界**：B1–B3 已列反例、已列命令/权限路径修复以及本轮 Java 方法错配回归均已通过；这只支持各自已枚举范围。Java fixture 完整源文件绑定与 T16 上述弱票链已修复，但不据此宣称所有性质和弱证据组合已穷尽，T01–T16 的表列主链现已逐项核对，证据和边界见下表，不由总测试数推定任意语义组合正确。下载摘要、通用对象协议和平台能力扩展不作为顺手新增实现。离线契约验收不自动授权冻结或真实大矩阵。

旧测试迁移依据：C2/C3 的未知调用/迭代不得当纯操作；C4/C5 的同范围矛盾证明不得按引用选择放行；C6 的依赖完成状态必须结构化。历史模型回复重放会按当前工具可用性进入 final-only 阶段，保留原提议标签、拒绝原因与用量断言，不假称完整复刻历史预算环境。

#### 当前矩阵主链复核（替代历史状态；本轮契约修复验收完成）

| 类别 | 本轮直接核验的证据 | 状态边界 |
| --- | --- | --- |
| T01 | `test_function_head_safety_must_retain_reachable_helper_sink`、`test_helper_sanitized_status_cannot_mask_caller_unsanitized_sink` 拒绝错误 SAFE；`test_both_safe_helper_and_caller_support_safe` 允许 SAFE；`test_conditional_helper_return_does_not_erase_its_own_dangerous_sink` 用真实工具允许 helper 危险路径 V 并拒 S | 主链已验，未以单独局部 helper 状态代替调用方证明。 |
| T02 | `test_candidate_outside_source_slice_cannot_borrow_command_proof` 有正常函数头/准确汇点正例与越界拒绝；`test_parsed_function_header_defines_whole_function_scope` 覆盖前导文本、偏移、装饰器及两种标签；Java 原始文件身份回归见上文 | 主链已验；未调用 helper 的原对照主要断工具事实，不将其单独算成整链覆盖。 |
| T03 | `test_permission_condition_positions_with_chmod_stay_unresolved` 及 statement/call 位置对照保留危险事实或明确缺口 | 已核验列举位置；其他语法组合不能由这些测试自动外推。 |
| T04 | makedirs 类型前提、装饰器名称豁免和未知对象协议三组反例已修复；固定布尔场景、已知常量、死分支、未调用 lambda 的正例保留 | 主链已验；未知对象不能再被称为纯布尔输入。其他类别仍按原 T01–T16 要求继续复核。 |
| T05 | `test_helper_effect_gaps_are_enforced_at_real_admission` 覆盖 helper 参数写入、别名写入、os.system 修改与 global os 重绑定，均拒绝 S；独立危险汇点位于 helper 之前时仍可 V。已有 unused-return、未知读取/写入与 owned-dict 正例共同覆盖副作用边界 | 主链已验；未实现的 helper 效果保留缺口，不因返回值未使用而消失。 |
| T06 | `test_unpack_coverage_reaches_candidate_admission` 将单目标全成功/全失败、成功+失败、成功+未知、嵌套解包、未支持 try 及安全常量接到实际准入；已有 loop/chain 真正工具到准入正反例保留 | 主链已验；Try 仍显式未解析，不宣称异常处理能力已扩展。 |
| T07 | `test_command_source_declaration_controls_actual_entry_values` 的直接/helper、正确/错来源/空来源与 quoted/unquoted 对照及 `test_declared_sources_do_not_erase_unknown_effects_or_fixed_scenarios` 验证覆写、常量、固定布尔场景 | 主链已验；没有添加下载摘要，也不把未知对象升级为纯文本来源。 |
| T08 | `test_shell_consumption_context_is_enforced_at_real_admission` 覆盖正常 quote、quote 后追加 raw、二次 shell、普通非 shell 与数值 argv；已有 stdin/executable 上下文和按候选汇点选取的真实工具准入测试 | 主链已验；普通 argv 的 NOT_ESTABLISHED 只支持弃权。初稿将 echo argv 期望成 SAFE 缺少充分证明，已更正为明确 U，并保留有 numeric_argv 证明的 S 正例；未改实现以强行获得通用 argv 安全结论。 |
| T09 | `test_platform_wrapping_requires_declared_scenario_and_tracks_rebinding` 覆盖平台参数未声明/False/True及两次检查间取反；真实工具到准入禁止默认 POSIX，固定场景能保留安全正例。已有重复条件、not、复合条件及 helper 条件关联覆盖符号路径 | 主链已验；外部平台函数未解析时仍可明确 U，不声称建成一般平台求解器。 |
| T10 | `test_permission_proof_selects_declared_call_not_another_mode` 验证不同目标/行与偏移的 V/S 正例及错借拒绝；`test_configured_race_property_cannot_borrow_literal_permission_proof` 从实际配置构造候选，再验证局部 0777/0750 不能成为竞态性质证明；模式序列测试保留先宽后窄/多目标 U | 主链已验；局部位模式与完整权限漏洞保持区分，不以先宽后窄证明没有暴露窗口。 |
| T11 | `test_real_command_adverse_evidence_survives_citation_and_scan_choices` 使用真实 SANITIZED/AMBIGUOUS 观察，比较 supporting/counter/省略、静态扫描有无及顺序；既有角色别名冲突和支持证明正例保留 | 主链已验；没有把修改引用角色当成修改事实。 |
| T12 | `test_real_safe_and_unsafe_paths_are_not_conflicting_whole_scope_proofs` 允许不同路径中完整危险链；helper/未知效果顺序对照保留独立危险事实。`test_same_scope_conflicting_command_proofs_require_abstention` 显式注入同身份矛盾证明并检查 V/S 均拒绝 | 主链已验；冲突输入使用合成观察测试消费端，不伪称正常确定性分析器应生成两份矛盾证明。 |
| T13 | `test_real_permission_proof_requires_complete_successful_delivery` 将真实 0750/0777 证明与 complete/truncated/suppressed/blocked/error 逐项比较，两种实质标签仅完整证明获准；源码/候选/位置/性质/场景错配及 Java 全文件身份测试保留 | 主链已验；投递状态对照显式变更真实观察的封装状态，不伪称为一次真实传输故障。 |
| T14 | `test_evidence_floor_survives_finalization_and_accounts_every_request` 比较 2/4 步、正常/blocked 读取及 V/S/U；无充分证明均诚实弃权，逐请求与 tokens 对账。已有完整证明成票、零尝试显式失败、末步关闭工具的正反例保留 | 主链已验；预算不能放宽证据准入，零工具尝试不伪造成票。 |
| T15 | `test_incomplete_validator_blocks_dependent_task_without_fabricating_calls` 覆盖直接与传递阻塞；实际完成但 UNRESOLVED 的权限检查满足调度依赖；未知引用与身份错误终止、原始提议与运行时弃权的区别均有测试 | 主链已验；未完成任务不会被写成验证完成，协议错误不当一般弃权吞掉。 |
| T16 | 命令/授权弱票脚本与真实 eval MAY_REACH 弱票均不能凑 quorum；重复任务只有每专家最终一票；真实命令 V/S 早停正例及 9³ 固定票/置信度组合与完整仲裁一致 | 主链已验；不声称多专家观察独立，不把固定票序列结论外推成真实模型重调度结果不变。 |

本轮 T05–T08 补强 20 项真实工具→准入测试；未修改分析器或准入实现。新增用例填补底层状态断言与实际判决之间的覆盖缺口，不作为新增检出能力或泛化收益。

T09–T12 本轮新增 18 项实际工具到准入对照，无分析器/门禁实现变化；T13–T16 已按上表完成主链复核，不用前十二项代替整体验收。

T13–T16 本轮补强 22 项投递/收尾组合。最终收尾已同步专家 mandate 与当前证明契约，并更新 `docs/CURRENT_STATUS.md`；旧状态原文保留在历史区，不作为当前验收证据。Planner 提示词字节快照已核验：仅还原三个专家 mandate 即复原旧哈希，工具定义及候选身份哈希不变。同步后全量 1758 passed in 32.20s，exit=0，git diff --check 无错误。本轮约定的 C1–C6/T01–T16 修复与离线验收完成，当前没有已复现而未关闭的缺陷；不承诺任意程序或输入不存在未知问题，不将能力边界、历史模型成绩或开发集测试当作泛化证明。没有新真实模型调用、没有改写原始实验 artifacts、没有提交或清理用户原有工作树。
