# 当前状态（2026-10-02）

## 静态交付迭代、调度修复与全源码组件验收

用户授权继续“实验—修复—再实验—扩展”后，先完成 8 项再扩到剩余 28 项的公开静态交付链，共 **36 次请求、42,322 reported tokens**。真实 CLI review／verify／view、完整包复制、分享件、源码漂移／证据损坏／既有输出／小摘要控制及逐请求记账全部通过。首个验收脚本曾错误地把准确调用片段当成整函数片段，已保留零请求失败并用 4 项离线回归修正。

随后对完整 `src` 尝试单次审阅，触发原 **200,000 AST 节点上限**，保留 PARTIAL 结果，不算全量通过。严格组件扩展也因分析阻塞停止；全源码诊断定位到 **9 个静态调度误拒绝**：门禁把 `compile`／`str`／`Path` 等参数构造计成第二个待判定操作。已改为核对同一行不同的已登记操作，真正多操作仍拒绝，原验证器仍接收完整片段并保留未知效果。v1 和执行见证实现没有改变。

新增调度回归初始 **4 failed／6 passed**，修后连同相邻控制 **22 passed**，补齐两个导入别名对照后调度回归 **12 passed**。新的实际实验进程执行完整门禁 **2964 passed in 431.69s**，通过后才读取密钥；6 个自有无害控制实际调用 **6 次、8,214 reported tokens**，输出 SUPPORTED／REFUTED／4 UNKNOWN，身份、引用、状态及调用后包复核全部匹配。两轮共新增 **42 次请求、50,536 reported tokens**，各自保持独立版本和账本，未自动重试或复用旧 pass 回执。

修复后，同一严格组件政策完成 **12/12 组件、239/239 文件、59/59 候选分析，0 阻塞、0 分析失败**；当前源码为 **1,837,775 bytes／281,525 AST nodes**，原包和完整复制包全部复核。先前 9 个阻塞的源码字节、候选和操作位置逐项不变，现在完成静态检查，性质仍 UNKNOWN；全源码 59 项也均 UNKNOWN，不能把分析完成说成证明了 59 项或整个应用安全。

见 [迭代与数值分析](../audit/static_dispatch_repair_20261002/verification.md)、[新快照真实验收](../audit/static_dispatch_repair_20261002/result.json) 和 [最终同源复核](../audit/static_dispatch_repair_20261002/final-result.json)。这是自有源码按组件的静态链扩展；跨组件上下文未准入，单次全 `src` 通过未宣称，完整 E1–E5 自动攻击／见证矩阵未放行。目标源码执行为 0，原 G-A=NO、生产 R17、独立项目质量／人工价值门槛和 14 项命名 mode 能力边界保留。旧快照的门禁、包和发行 ZIP 属于各自历史版本，不作为当前实现的通行凭据；新修复留在共享工作区。

## 36 个开发控制的真实模型批次

用户批准扩展后，已完成现有 36 个自有合成权限控制的单次静态证据消费实验。源码按目录排序后复制到中性路径，逐项核验源码摘要、唯一 chmod 操作与完整静态包；提示只包含绑定源码和观察，不含开发参考标签或控制目录名。实际进程重新执行完整门禁 **2948 passed in 433.63s**，通过后才读取密钥，经原 `OpenAICompatibleChatModel` 顺序调用，未重试或使用旁路。

本批 **36 次请求、36 次返回、42,267 reported tokens**，全部返回 `deepseek-flash`，在预登记 36 次／120,000 tokens 上限内。36 项输出协议、候选身份和引用均通过，账本无缺失用量或冲突；模型对静态观察的状态匹配为 **36/36**，错误强提议为 0。输出为 **5 SUPPORTED／5 REFUTED／26 UNKNOWN**。与封存的开发参考答案比较仍为 **22/36（61.1%）**：预期 SUPPORTED 和 REFUTED 各有 7 项继续 UNKNOWN，14 个命名 mode 覆盖缺口没有因模型接入消失。

见 [逐请求对账和双重评分](../audit/live_controls36_20261002/result.json) 与 [批次核验说明](../audit/live_controls36_20261002/verification.md)。本批说明这些开发控制的引用协议和受限静态证据消费流程通过，不是全系统 E1–E5 实验闭环、held-out 检出率或人工收益验收；目标源码执行次数为 0，生产 R17 未启用，原 G-A=NO 不变。历史 72 次请求账本与此前 5 次试跑分别保留，未将不同协议合并成绩。

## 引用协议修复与真实试跑 v2

用户要求修复后，模型输入改为单一 `observation_ref` 引用格式，明确只能复制 `available_evidence_refs`，工具内部 `citation_id/evidence_ids` 从模型展示投影中移除，完整私有记录保留。校验器继续拒绝不合格引用，并保存具体拒绝原因和原始提议；旧第二条回复离线重放仍被拒绝，没有回写成成功。

新增 7 项离线回归和正控通过；实际 v2 实验进程重新执行完整门禁 **2948 passed in 426.61s**。只运行原先未执行的第 3／4／5 项，实际返回 **UNKNOWN／SUPPORTED／REFUTED**，3 项候选身份、引用和有限性质均匹配，新增 **3 次请求、5,726 reported tokens**，引用错误与错误强提议均为 0。两轮合计 **5 次请求、9,485 reported tokens**，未超原 5 次／30,000 上限。

[引用修复及试跑验收](../audit/live_static_pilot_20261001/result_v2.json) 逐项绑定新旧账本、完整门禁和原始回复。v1 的失败继续保留，两轮采用不同提示及输入子集，不能合并宣称‘同一协议五项全通过’或因果提升；这是受限静态证据消费闭环验证，仍不是独立项目检出率或人工价值测量。生产 R17、目标执行和原 G-A=NO 保持原状态。

## 用户追加真实模型静态证据试跑

用户要求开始小规模真实实验后，已用原 `OpenAICompatibleChatModel` 完成一次受限静态证据消费试跑。实际实验进程先重新运行完整门禁，**2941 passed in 427.49s**，通过后才读取密钥；没有使用此前的 pass 回执或绕过门禁。

预登记上限为 5 次请求、30,000 reported tokens，输入是项目自身 3 个静态候选及 2 个自有字面 mode 对照，模型没有工具调用权限。实际发送 **2 次请求，3,759 reported tokens**，两次返回模型均为 `deepseek-flash`。第一项 UNKNOWN 与静态依据一致并通过输出协议；第二项同样返回 UNKNOWN，但引用了工具内部源码事实 ID，未使用本轮允许的原始观察引用 ID，因而未被接受。按停止规则保留失败并停止，剩余 3 项没有运行，不重试或修改准入规则。

[试跑结果与逐请求核对](../audit/live_static_pilot_20261001/result.json) 保存了原始事件、全部用量及 namespace 诊断路径。第二项不是已观察到的漏洞误判，也不是完整五项验收通过；提示同时包含两种引用名称，对模型的可消费性仍需离线澄清。该运行仅为开发诊断，不代表独立项目检出率或人工收益；生产 R17、执行见证、K5–K8 和原 G-A=NO 均未改变。原 M0/E-iter 的 72 次请求账本保持其历史范围，不把本次追加试跑混入旧结论。

## 10 月 1 日恢复反馈：显式 v2 静态试用版

已逐页读取 [31 页恢复反馈](reports/cv_agent_design_review_and_recovery_2026-10-01.pdf)，按 F01–F22/R00–R17/V01–V60 区分实证缺陷、待核验假设和新功能。恢复实现包括封存字节与精确操作、共享静态准入、完整私有记录、独立摘要、守恒阶段计数、公开 copy 重验证、不替换目录提交和 Linux 有限静态子进程。v1 仍是默认，v2 须显式选择。

先前“验收完成”对应下面的 9 月 30 日工程快照。10 月 1 日第一轮全量为 **15 failed / 2904 passed**；失败日志保留，公开 DTO 校验保持严格，研究脚本改用独立中性输入视图。随后故障控制还复现并修复了证据回读失败、异常后继续分析、输出阶段诊断和记录计数不一致。patch1 完整套件的 **2940 passed in 427.22s** 已作为 [上一修订验证回执](../audit/product_recovery_20261001/final-validation.json) 保留。末次核查还复现了返回 DTO 的上下文回执可变问题；现使用已有不可变 `ScopeAdmission`，序列化形状不变，修后受影响控制 37 passed。patch2 最终第三轮完整测试 **2941 passed in 422.98s**，harness PASS，423 份源码和测试的验证前后指纹一致。见 [最终同源回执](../audit/product_recovery_20261001/final-validation-patch2.json)、[恢复核验记录](../audit/product_recovery_20261001/verification.md) 与 [60 项验收矩阵](../audit/product_recovery_20261001/acceptance.json)。

patch2 的 100／500／1000 个自有常量源码文件单次测量全部完成，墙钟为 4.02／18.66／44.47 秒，峰值 RSS 为 53,727,232／97,116,160／149,364,736 bytes。记录独立保存且包含完整复核重放；这是两个审计脚本及发行准备同机并行的描述性工程测量，早于第三轮完整 pytest，不能把与前修订的时差归因为 DTO 改动。负载更正另有回执，原数据保留；不是任意仓库性能保证。45 份历史报告及源码产物、73 份历史配置和脚本的机械字节比较均保持一致。

[产品指南](reference/PRODUCT_REVIEW.md) 给出精确运行与本地定位方式，[发行安装说明](../audit/product_recovery_20261001/release-final-patch2/install.md) 给出锁定离线安装。patch2 重新运行的 36 个中性工程控制仍为 22/36 精确匹配和 0 错误强状态，只反映这些夹具；14 个已知命名 mode 构造仍 UNKNOWN。实际用户失败命令、授权项目上的独立质量、新人工审阅者定位和 A/B 审阅收益未提供或未测，当前定位是 **工程试用版**，未宣称真实价值验收完成。模型、目标执行、scratch/native 扩展继续关闭；原 G-A=NO、GP3/GP4 未测量。

## 9 月 30 日设计审查：当时静态产品工程验收记录

已逐页核对用户提供的设计审查 PDF，并按实际 `4dba622` 基线复现、修复和验收。新增独立 `product_triage_v1`：显式本地 Python 源码可通过 `cv-agent review` 生成 JSON 和人工报告，不需要模型或目标执行。`doctor` 显示能力和缺项；性质、运行、任务等待状态分开，原始验证器状态保留。

共享修复包括嵌套别名隔离、slow/fast 对全部已交付证据重新准入、已知密钥的传输错误脱敏，以及 16 步图业务上限。产品另外提供四层身份、顺序不变的证据归并、守恒证书预算、付费上下文 span 扩展、半写日志审计和取消后的部分产物。原 E 配置、检索及历史实验原样保留；共享完整性修复版本和兼容夹具迁移单独记录。

最终完整离线测试 **2684 passed in 414.20s**，harness **PASS**；启用能力组 **126 passed**，七个真实 CLI 演示全部通过。额外拒绝式传输监测测得 HTTP、socket、live gate 尝试均为 0。A01–A34 中默认产品必需的 31 项通过；A27–A29 作为未启用条件能力保留在分母，未冒充通过。本轮新增真实模型请求为 **0**。

[产品指南](reference/PRODUCT_REVIEW.md)、[逐项核验记录](../audit/design_review_20260930/verification.md)、[任务记录](../audit/design_review_20260930/tasks.json) 和 [验收矩阵](../audit/design_review_20260930/acceptance.json) 提供实现、日志及证据路径。初始两项失败和修后第一轮兼容夹具失败均留档；最终套件没有 skip/xfail。

GP0/GP1 仅表示这条静态产品路径的工程验收。私有 scratch/native build 仍未启用（T10/T11，GP2）；T14 已冻结前瞻增量协议，真实授权样本、人工复核价值与模型净收益仍 **未测量**（GP3/GP4）。原 **G-A=NO**，原累计 **72 请求 / 447,812 reported tokens** 不变。改动留在本地工作区，尚未提交。

## 收尾：K2 完成，G-A 正式判定为 NO

- **E-iter 已运行一次**：四格最终均为 ABSTAIN / UNRESOLVED，共 26 次请求、166,482 reported tokens，返回的模型 ID 全部为 `deepseek-flash`。hp003 两格又一次选了 `enable_mlserver=false`（F3）；entry-00390 两格止于隔离下的临时目录创建（F4）。模型拿到 UNRESOLVED 之后没有换场景再试。详见 [E-iter 结果](../.hermes/plans/2026-09-30-E-iter-results.md)。
- **K2 已完成（`af7024d`）**：见证运行时迁到 `runtime/witness/`，核心包不再导入 evaluation 层。迁移后两个真实快照的脚本化配对与迁移前逐项相同：a 为 `CONFIRMED / EXPANDED_OBSERVED`，b 为 `UNRESOLVED / LITERAL_OBSERVED`，manifest 中只有 `python_executable` 变化。完整测试 **2562 passed**，harness **PASS**。详见 [K2 结果](../.hermes/plans/2026-09-30-K2-results.md)。
- **G-A = NO**：B-a 在 M0 阶段 1（F1）和唯一一次重跑阶段 2（F3）中都没有成功，3b 合格的外部样本对为 0。K5–K8 不启动。现有见证定位为对少量已选定候选做有界确认的工具。详见 [G-A 判定](../.hermes/plans/2026-09-30-G-A-decision.md) 和 [定位报告](../.hermes/plans/2026-09-30-positioning-report.md)。
- **用量**：真实模型累计 72 次请求、447,812 reported tokens，上限为 210 次请求、250 万 tokens。所有结果 `claim_eligible=false`。
- **数据治理**：架构方补记了自己对 held-out 评测侧元数据的查看；VulnGym v4 在命令注入相关结论等方面不再视为盲测，见 [架构方披露](../.hermes/plans/2026-09-30-architect-exposure-disclosure.md)。仓库根目录新增 `.ignore`，ripgrep 默认搜索跳过 held-out 输入文件及其快照副本。

## 追加探索 E-iter：离线验收完成（运行前状态，保留历史）

用户追加授权 E-iter ≤40 请求后已恢复实施，保留此前 S4 内容搜索事件披露；继续禁止任何进一步 held-out 内容使用。K1 已提交 **d93a7d2**。紧凑投递、四格 runner、严格 Click callback 适配及 K3/K4 离线部分已经验收；最终完整套件 **2556 passed in 407.96s**，harness PASS，实际四格预检通过且 hp003 初始请求与阶段 2 逐字相同。E-iter 尚未发真实请求，累计仍为 **46 请求 / 281,330 tokens**。本次探索的结果只补充定位，不改变 M0 原重跑或 G-A。

K3 从头复建两版 Python 3.12 环境；旧/新各 141 包版本和 977 项目标源码绑定逐项一致，原四个读取授权未扩大，七个未接受读取提案保留。用新环境实际脚本复现 a 的 CONFIRMED 与 b 的 UNRESOLVED。K4 脚本 E4 的两票共享同一次见证，记为 2 票 / 1 次原始观察；固定侧弃权。外部 3b 冻结前 15 条后，只有 Pillow 符合源码路径标准，但缺精确版本的 native `_imaging`，环境标准未满足；0 个合格外部对，不运行模型。详见 [K3](../.hermes/plans/2026-09-30-K3-results.md)、[K4](../.hermes/plans/2026-09-30-K4-results.md)、[3b](../.hermes/plans/2026-09-29-phase3b-results.md) 和 [E-iter 预登记](../.hermes/plans/2026-09-30-E-iter-preregistration.md)。

3a 真实脚本两版都在临时目录创建处被现有只读文件系统隔离阻止，未到进程边界，不能确认。E-iter 按用户要求保留3a两格并明确基础设施上限；M0原3a运行的前置条件仍未满足。M0 B-a唯一重跑失败，G-A第一个条件已不满足，正式判定留在M0/K2收尾；K5–K8不启动，探索结果不能修改门槛。具体协议见 [E-iter追加计划](../.hermes/plans/2026-09-29-E-iter-execution-plan.md)。以下停止记录和当时状态保留为历史。

## 模型提出场景：阶段 2 完成，K1 实施触发新 S4 停止

K1 实施中，子代理源码导航搜索误包含受保护 held-out 配置，打印四行 commit 字段，超出此前仅机械哈希/归档的解除范围。未输出标签/场景，也未用于模型、检测或选样；按 M0 §0 已停止实施并锁定共享账本。K1 未提交改动和中断的脚本产物保留，尚未完整验收；K2/K3/K4 和后续迁移未完成，G-A 尚未正式判定。具体事件、边界和恢复条件见 [新 S4 报告](../.hermes/plans/2026-09-29-STOP-S4-content-search.md)。下面的“继续”描述是此次停止前的执行分支。

阶段 2 的唯一 B 重跑已完成，执行源码为 **d23e59c**：14 次请求、90,153 reported tokens，返回模型 ID 全部为 deepseek-flash，新进程完整门禁 **2427 passed in 270.88s**。两格最终均 ABSTAIN / UNRESOLVED。各完成两次准备和一次真实见证，完整运行结果投递，没有重复执行；两格提出 enable_mlserver=false，走 scoring_server/uvicorn 分支，在 `recorder_prefix_not_established` 处不能闭合。B-a 复核为 **F3，伴随局部 F6**，没有基础设施故障证据；固定侧没有 CONFIRMED 或已准入 VULNERABLE。三份原始 VULNERABLE 提案均被证据准入拒绝，仍完整归档。

累计用量为 **46 请求 / 281,330 reported tokens**，未触发硬停。按 M0 的单次重跑失败分支，后续 3a、3b 只做离线能力检查，不追加模型请求或第二轮提示修复。继续 K1、K3、K4 离线验收、近迁移与外部准备，然后 M0 汇总和 K2。G-A 留到这些工作完成后按原标准判定，K5–K8 尚未启动。具体账本、场景原文、运行结果和失败边界见 [阶段 2 报告](../.hermes/plans/2026-09-29-phase2-results.md) 与 [完整审计](../.hermes/plans/2026-09-29-phase2-summary.json)。下列阶段 1、S4 和准备记录保留其当时状态。

见证工具现在接收结构化 `scenario_hypothesis`，支持注入参数、开关、条件与值前提、构造数据和预置文件。每条前提要求值、攻击者输入/部署配置/环境条件分类和理由。原候选身份保持不变，执行 subject 与场景来源单独绑定；工具掌握探针、良性对照和全部运行时核验。普通工具与注册有界见证 fixture 的未分类场景均拒绝执行，仍只允许 CONFIRMED / UNRESOLVED。

严格无场景 subject、入口/advisory 提示的脚本模型真实对照已复现 2c：hp003_a **VULNERABLE / CONFIRMED / EXPANDED_OBSERVED**，hp003_b **ABSTAIN / UNRESOLVED / LITERAL_OBSERVED**。两版原始四组场景字段为空，各自 977 个源码绑定、良性对照及全部运行时义务核对通过，具体输入一致；17 项改名仓库控制也通过。模型可见结果保留所有前提值和分类，完整理由与证据保存在私有产物，源码帧仅展示仓库相对路径。

剩余执行计划的 G1–G6 已获授权，基线提交为 **221373f**，阶段 1 执行提交为 **d6f6af1**。固定 E1、`deepseek-flash`，A 保留数据集场景、B 由模型提出场景，四格各运行一次，**全部 ABSTAIN**；实际用量 **32 次请求 / 191,177 reported tokens**，32 次响应的模型 ID 全部匹配，无缺失 usage。新进程完整门禁 **2398 passed in 249.93s**；此前阶段 0 完整测试 **2398 passed in 252.85s**，harness **PASS**。实际 B 初始请求无预写场景提示，相同预算下 A/B 源码前缀长度分别为 2439/3113 字符。

B-a 缺失入口和构造参数，未执行见证；主因复核为 **F1**，本地观察/收尾预算耗尽是 **F6** 伴随因素，不能把部分准备接收解释为 F3 的错误场景运行。B-b 执行两次真实见证，均 **UNRESOLVED / LITERAL_OBSERVED**；两次投递都因观察预算被截断，相同调用因执行/投递状态未区分而重复执行。四格均没有 SAFE、CONFIRMED 或最终 VULNERABLE。这些问题已记录，阶段 2 的通用修复尚未实施。

阶段 1 完成后的授权审计发现：通用门禁指纹和源码快照机械读取/复制了 held-out 配置，与执行计划 §0 的读取禁令冲突。没有将其内容用于检测、prompt 或 held-out 运行，但按 **S4** 停止后续修复、模型请求及联网选样，共享账本已记录停止状态。阶段 2–3b 未执行，待用户明确解决机械哈希/归档的授权冲突；不更改门禁或删除历史产物。详见 [阶段 1](../.hermes/plans/2026-09-29-phase1-results.md)、[S4 停止报告](../.hermes/plans/2026-09-29-STOP-S4.md) 和 [停止时汇总](../.hermes/plans/2026-09-29-remaining-work-final-report.md)。所有结果保持 `claim_eligible=false`，尚未证明自主确认、新样本迁移或 held-out 泛化。只有 repository_url/commit 的端到端输入仍需要独立的候选发现和环境准备。

用户现已交付 [K1–K8 架构文档](../.hermes/plans/2026-09-29-remaining-architecture.md)，与 M0 联合执行。K1/K2/K3/K4 的离线开发和条件 K5 已获授权，仍须按阶段依赖执行；K4 真实运行、K6/K7 模型预算和 K8 冻结签字尚未追加。**G-A 待判定**，当前 B 重跑和外部迁移都未执行，不能提前判失败或启动 K5。用户披露已查看 held-out 汇总分布，这仅是设计来源记录，未由执行者重新核验，也不进入 detector 输入。只读兼容性审计和当前授权、准备/执行语义、固定版 S1、共享见证计数约束见 [联合交接状态](../.hermes/plans/2026-09-29-architecture-handoff-state.md)。本次没有代码、测试、模型或网络运行，S4 仍未解除。

**随后用户明确要求完成剩余工作，S4 现已解除**：仅允许现有门禁、指纹和源码归档机械哈希/复制配置，不用于检测、prompt 或评测。共享账本保留停止和解除记录，32 请求 / 191,177 tokens 不重置。当前进入 M0 阶段 2 的一次通用协议修复，修后只重跑 B 两格，最多 30 请求；此前四格不重跑。具体边界见 [S4 解除记录](../.hermes/plans/2026-09-29-S4-resolution.md)。

阶段 2 通用修复与离线验证已完成：准备字段及填写位置显式化，必需验证器及时恢复，schema 明确布尔/文本类型，成功执行与投递状态分开，相同已执行调用在截断后也不重跑。完整测试 **2427 passed in 269.24s**，harness **PASS**；脚本真实快照正反控保持 a CONFIRMED / b UNRESOLVED，各一次见证、977 项源码绑定。B 实际请求预检通过，模型重跑尚未启动。详见 [阶段 2](../.hermes/plans/2026-09-29-phase2-results.md)。

## 候选执行见证：第 1 步完成（此前状态，保留历史）

已将有界真实执行见证注册为 agent 工具 `run_bounded_execution_witness`。系统从候选 subject 和绑定源码生成入口、调用参数、前提及源码库存；模型只能补缺失构造参数和受限文件布局。探针、良性对照、核验义务与隔离配置由系统掌握，契约只允许候选级 CONFIRMED；准备响应不算完成验证，字面量观测不产生 SAFE。

代码 **3039867**；完整离线测试 **2296 passed**，harness **PASS**。通过标准 E1 agent 工作流和脚本模型，在同一输入下完成两个真实快照的离线验收：hp003_a 的展开见证获准并输出 **VULNERABLE / CONFIRMED**；hp003_b 保留 **ABSTAIN / UNRESOLVED / LITERAL_OBSERVED**。两版均完成所有运行时义务及良性对照，输入一致性机器核对为 true，没有内部桩、真实模型请求或新增安装。

确认前提是调用方能提供一个已存在、名字带 shell 元字符的本地目录，并满足声明的 Linux / LOCAL / enable_mlserver 场景；远程可达性尚未建立。当前只有脚本模型补充 `config={}` 后的工具闭环；真实模型单臂运行和新开发样本泛化尚未执行，`claim_eligible=false`。详细证据及限制见 [第 1 步报告](../.hermes/plans/2026-09-29-witness-system-step1-results.md)。

## 证明契约返工与修后六格（2026-09-27 晚间，历史记录）

审查报告指出的八项缺口及随后独立发现的 loopback 错性质证明、强弱 fixture 混合调度问题均已修复。完整离线测试 **1905 passed**，原审查用例 **10 passed**，harness PASS。新的六格运行 `artifacts/jev_v3_comparison/545892d6559f439a94ef307cc021cac3/summary.json` 在固定专家策略下完成 hp003_a/b × E4_JEV_V3、E4_RULE_V1、E4；**六格全部弃权、零运行失败**。规则臂两格均为 **零 planner 请求**，Jev 两次 API 请求返回四个决策；真实用量 155 请求、1,343,687 reported tokens。逐请求审计、修复清单与源码快照差异见 `artifacts/proof_routing_repair/handoff.md`。

弃权是候选证据不足：两份源码的命令观察均为 `AMBIGUOUS`，未解析 `_get_root_uri_and_artifact_path`，下载仓库/插件分派和相关副作用也未建立完整证明。必做任务均执行完成，没有依赖阻塞。修后实现可以诚实拒绝证据不足的 V/S 判决，但尚无该宽范围候选的实质判决覆盖；旧 30-cell 成绩不能用于宣称当前检出率或上线就绪。hp001 竞态、hp002 完整授权边界、hp003 下载链证明仍是能力缺口，开发样本 `claim_eligible=false`。

## 历史完整矩阵：2026-09-27 18:03–18:07（新加坡时间）

当时版本重跑全部 30-cell：`artifacts/python_heldout_pair_matrix_v4/9f59cdbd664b48fdb03175159c5fe4fb`。DeepSeek Flash，真实请求前完整离线门禁 **1828 passed in 41.03s**。结果 **29 正确、1 弃权、0 误判、0 执行失败**；唯一弃权为 hp001_a/E5，`acceptance.passed=false`、`operational_ready=false`。283 请求/283 响应，2,008,214 reported tokens，无缺失用量。

相对当时的完整基线 `fixture_all_pairs_full_after_prompt_2026_09_27`（30/30 正确、292 请求、2,084,142 tokens），本轮请求下降 3.1%、reported tokens 下降 3.6%，同时少一个正确实质判决。E1–E4 各 6/6 正确，E5 5/6；E4 请求 117→136，E5 127→104。E5 在 hp002_a/b、hp003_a/b 四项实际早停，hp001 两项走完整审查。该批 hp003 为 10/10；这不是修后源码的成绩。

hp001_a/E5 的 scan 已通过 fixture 得到 CONFIRMED；taint 和 authz 弃权，只有一张实质票。authz 的原始请求中已投递 fixture 结果，但本次未据此形成第二张实质票。基线中 authz 使用同类证据投了 VULNERABLE。该项走 slow 路径，不能把弃权直接归因于 E5 早停，也不能仅由单轮差异断言某一项代码改动造成了回归。

两轮模型配置、样本源码身份及系统集合相同，项目代码和候选前提不同；不是单变量消融。30 项都使用可信注册 fixture，仍属开发回归，`claim_eligible=false`。本轮未调用 Jev；Jev active 的独立对照与整单回退问题见 [Jev 运行记录](reference/JEV_ROUTING.md)。详细前后比较保存在本轮目录的 `comparison.md` 和 `comparison.json`；没有重试弃权项或覆盖原始结果。

后续完整流程审查发现额外的证明契约风险：hp001 fixture 实际检查 AST 中的 chmod 模式却声明竞态性质，hp002 fixture 依赖源码字符串形状而没有完整授权控制流证明，hp003 fixture 的状态还受 expected_role 过滤。因而上文 hp001 弃权不能仅归因为“专家未利用充分证据”；应先核清 fixture 的证明范围。实现细节、流程图、已确认事实和调整优先级见 [当前项目流程与诊断](reference/PROJECT_FLOW_AND_DIAGNOSIS.md)。本次为代码审查发现，未修改历史统计或检测实现。

## 当日更早的诊断记录（以下保留历史原文）

以下进度早于已配置 hp003 场景、fixture 接入和后续返工；其中“最近一次”“尚未添加”“仍无完整证明”等相对时间表述只对应当时的源码。当前状态以本页开头的第 1 步见证接入记录及其原始证据为准。

当前处于上线前迭代，**尚未达到上线条件**。此前 C1–C6/T01–T16 离线契约复核减少了错误证据放行，但不代表功能完整性和真实代码覆盖率完成验收。

最近一次有限真实验证：`artifacts/hp003_contract_verification_2026-09-27/run_1`，DeepSeek Flash，hp003 正反版本 × E3/E4/E5 共六格全部弃权，零执行失败；115 次请求、974,641 reported tokens，原始事件逐格对账一致，acceptance=false。该运行在本次多跳修复之前，不能作为修复后的成绩。

当前已确认的产品问题：

- 命令检查 max_hops 原来只区分零/非零，始终只纳入入口直接邻居。本次已实现访问范围内的按层展开；离线真实源码两版本在深度 1/2/3/4 分别纳入 7/23/56/84 个 helper。二层分析从缺失 `_get_root_uri_and_artifact_path` 推进到不支持 `os.path.exists`，仍无完整汇点证明。
- 多跳诊断已与源码可用集合分离：只展开解释器实际分析过的 helper，确定死分支的图邻居不生成无关缺口。两份真实 hp003 源码离线对照中，深度 2 输出从 9,469 降到 1,372 字节，深度 4 从 33,336 降到 1,372 字节，候选状态、issues 与 sink_facts 完全相同；这是序列化内容大小，不冒充真实 token 节省或覆盖率改善。
- 分析器缺少路径解析、库对象和环境字典的必要语义。不能把 unknown 返回值摘要当作无副作用证明，也不能用读取源码替代完整调用链证据。
- 真实轨迹有七次 helper 单独检查因接口要求候选入口而被拒、十三次观察预算耗尽拒绝、二十三条截断标记（这些类别有重叠）。多跳带来的输出增长仍需检查，不能只增加检索量。
- 四个多专家 cell 的 authz 合计花费 27 次请求、226,428 tokens，没有建立命令性质证据。适用性调度和固定研究协议的变更须区分，不能偷偷改变 E3–E5 后继续沿用旧对比。

环境前提核验：MLflow 的 `artifact_repository_registry.py` 在注册内置 repository 后调用 `register_entrypoints()`，插件注册会覆写 `_registry[scheme]`。因此 `file:`/本地路径不自动证明分派给 LocalArtifactRepository；任何下载摘要都需要绑定实际分派或显式、可核验的插件环境前提。文件存在性不能用分析机当前文件系统代替目标环境。尚未添加这类摘要，也未缩小原 hp003 任务范围。

工具现保留嵌套未解析调用的实际 source_path、局部行号与调用符号，并给出 definition_not_admitted / available_definition_not_expanded / unmodeled_call / unresolved_binding 诊断。这些只表示索引定义的可用性，不证明运行时绑定，更不能升级为漏洞或安全证据；原 issues 和候选证明要求保留。其他非调用语义缺口仍由 issues 报告，不声称已结构化全部失败原因。

已补充有界词法路径语义：明确的 posixpath/ntpath basename、dirname、normpath、join 接受已知 builtin 字符串抽象；常量精确求值，POSIX join 的后置绝对分量可覆盖先前路径值（参数副作用仍先求值）。动态结果为未知字符串，不继承未经证明的攻击字符或先前 shell 转义；转换后重新 quote 可在完整已解析消费上下文支持安全。未知 PathLike、自定义绑定以及平台未声明的 os.path 不应用摘要。该能力不涉及文件系统访问，也尚未解决 hp003 的 exists、repository 分派和环境对象链。

文件存在性摘要已加入：标准 os.path/posixpath/ntpath.exists 在 builtin 字符串抽象上产生环境布尔读，不访问分析机文件系统。两个正常布尔结果分别解释；每次读取独立，保存的同一结果保持关联。汇点记录 environment_requirements，依赖未证明外部状态的 UNSANITIZED 降为 AMBIGUOUS；此前独立危险汇点不受后来条件污染。所有相关路径安全时可以支持安全结论。未知 PathLike 仍不应用摘要。该模型不提供文件存在性见证、不假定文件系统稳定，也不解决插件分派。两份真实 hp003 源码离线检查均越过 exists，首个报告缺口为 urllib.parse.urlparse，候选仍 AMBIGUOUS、零汇点；未新增真实模型运行。

真实路径诊断已运行：`artifacts/mlflow_path_diagnosis_2026-09-27/run_1` 使用目标仓库锁文件和独立环境，在清空凭据、网络限制及只读文件隔离下导入两份真实 checkout。环境元数据问题与首次随机设备权限错误均保留原始失败记录；`a3_result.json`、`b2_result.json` 均捕获真实 serve 到 Popen 边界。当前实际本地分派为 LocalArtifactRepository，已存在目录中的 `$()` 原样穿过下载转换。漏洞版生成未引用的路径，修复版生成单引号保护路径。没有替换下载或 get_cmd，只截获 Popen，未执行 shell/模型服务；源文件哈希和 checkout 干净状态复核通过。依赖、构建记录、探针和输入配置保留。该结果证明一个 POSIX/local 场景中的真实命令构造差异，不证明任意插件/远程路径或修复版整体安全，也尚未接入生产证据准入。

下一阶段采用混合证明路线：以真实源码受控执行补齐具体危险路径见证，静态分析与明确覆盖范围用于安全结论；不以完整解释所有框架代码作为获得第一条有效证据的前提。仍需完成 shell 消费验证、候选/环境/源码绑定、注册工具和预算记账，再验证专家适用性、独立样本及运行可靠性。开发样本继续 `claim_eligible=false`，不以测试数量、零误判或旧矩阵作为上线证明。

## 历史记录的使用范围

下方保留原状态页供追溯。其中 1272 项测试、旧运行统计及“因果确认”“彻底消除”等表述均属于旧版报告，不作为当前源码的验收或研究结论；本轮未重跑或重新审计这些历史模型运行。当前实现与验证范围以本页开头和测试契约为准，原始 artifacts 未改写。

<details>
<summary>展开 2026-09-26 原状态记录</summary>

# 当前状态（2026-09-26）

离线测试全量通过（**1272 项通过**）。在 9 月 25 日 hp003 诊断基础之上，完成了三项针对性修复并补充正反例验证：
1. **统一候选作用域并禁止 helper 状态替代调用方证据**：函数级候选（`local_line == 1`）统领全函数体内所有汇点，任何一条存在 `UNSANITIZED` 即不可判定为 SAFE；彻底移除 helper 安全状态回退逻辑，禁止安全 helper 掩盖调用方未处理的危险执行汇点。
2. **闭环候选绑定命令检查准入门槛**：基于完整 trace 的候选绑定观察进行强制准入检查，消除通过在最终 JSON 中故意省略 `inspect_command_construction` 引用（仅引用静态正则匹配）来绕过 `AMBIGUOUS`/`UNAVAILABLE` 拦截的漏洞。
3. **结构化预算状态收尾**：由 registry 统一维护 `scope.budget_exhausted` 与 `metadata["budget_exhausted"]`，ReAct 引擎在文本或 JSON 工具无法投递预算诊断（包括 status 为 `error` 的分支）时立即切换至收尾阶段，关闭工具 definitions 并有界退出，消除重复请求死锁。

在 DeepSeek API 充值后重新运行了受控验证：
- **18-Cell 受控复现（3 轮 × 6 cells）**：正确 7，**错误分类（误判）0**，弃权 8，执行失败 3。
- **30-Cell 完整开发矩阵（`be2c56243e6f46f18f81020609d5ca24`）**：
  ```text
  正确分类: 23 / 30
  错误分类:  0 / 30 (误判率 0.0%)
  弃权:      6 / 30
  执行失败:  1 / 30
  ```
  `hp001`（10/10）与 `hp002`（10/10）全量保持正确，零回归；历史频发的 `hp003_b` 误判全部被准确拦截并按协议转为合法弃权。

## 能做什么

本次修复后的完整离线测试为 **1272 项通过**。

- E1–E5 的检索、规划、ReAct 工具循环、专家调度、投票和日志记账可以运行。
- Python/Java/JS/TS/Go 源码适配器、图检索、静态分析和部分受控动态夹具已有离线验证。
- 独立 VulnGym 全量源码发现 runner 支持浅检出缓存、动态 worktree 清理和带代码指纹核验的断点恢复（durable partial progress）。
- 每次真实运行保留来源、事件、结果、usage、summary 和验收；首次模型请求需要当前源码的完整 pytest 通过。
- 库、实验生命周期、数据集协议、启动入口和确定性基线已有明确模块归属。

这些能力还不能证明真实项目漏洞检出率、跨项目泛化或静态安全证明的完整性。

## 最近真实矩阵

依据第五轮运行 `artifacts/python_heldout_pair_matrix_v4/d626f151882d42e68c44265307f265f1/` 的 `summary.json`、`usage.json` 和 `acceptance.json`：

| 系统 | 正确实质判断 / 6 | 弃权 | 执行失败 | 严格召回 | API 请求 |
| --- | --- | --- | --- | --- | --- |
| E1 | 4 | 2 | 0 | 66.7% | 35 |
| E2 | 6 | 0 | 0 | 100% | 38 |
| E3 | 6 | 0 | 0 | 100% | 41 |
| E4 | 6 | 0 | 0 | 100% | 112 |
| E5 | 6 | 0 | 0 | 100% | 116 |

总计 28 项正确实质判断、2 项原协议预声明弃权、0 执行失败；342 次请求、2,518,438 reported tokens。实质判断中没有观察到误判，总体覆盖率 93.3%，不能删除弃权分母宣称整体准确率100%。54 张专家选票中，7 张 CONFIRMED、8 张 REFUTED 均来自有界 chmod 性质检查，39 张 UNRESOLVED；这些不是完整应用 exploit 复现。

E4 固定票前缀回放六项标签一致，但没有触发早停；E5 请求数高于 E4，没有证明早停收益。五轮总计 1,787 请求、12,803,897 reported tokens，历史运行均保留。

更早的十项门禁 `a9b918176b034efe9c9ad484a25c5d06` 曾通过，但当时完整矩阵未通过；现在第五轮完整矩阵通过。一次成功运行仍不是稳定性证明。

9 月 25 日再次运行完整矩阵（`c5c2ba30977f40ef9f2fe1d178ae0340`）：24 完成、3 弃权、**3 执行失败**，另有 1 项误判（hp003_b E3 判 VULNERABLE，应为 SAFE），验收 `passed=false`。三项失败全部是 hp003，直接原因相同：planner 在一次读取用掉大部分观察预算后，后续调用得到空 payload，于是重复请求同一路径直到 8 步上限。这与第五轮**不是受控对比**——两次运行的源码快照有 77 个文件不同（含 20 个 src 文件），因此不能把差异归因于任何单一改动。历史 7 轮中 6 轮未通过，弃权数在 2～15 之间波动，单次运行的差异不足以支撑归因。空 payload 的问题已按第 8 项修复。

### 四臂对照（9 月 25–26 日，同一份工作树）

由于与第五轮的对比不成立，改为在同一工作树上构造对照臂。四个臂的源码差异仅限下列改动，配置、数据与协议完全相同：

| 运行 | chmod 修复 | 重复守卫 | 预算修复 | 证据门槛修复 | 正确 | 弃权 | 失败 | 误判 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `c5c2ba30977f40ef9f2fe1d178ae0340` | ✓ | ✓ | ✗ | ✗ | 23/30 | 3 | 3 | 1 |
| `3bb9fcac7af741c6b72ebafb10e14bb8` | ✓ | ✓ | ✓ | ✗ | 25/30 | 4 | 0 | 1 |
| `b6d43e260b734d95bae15de350dc400e` | ✗ | ✗ | ✓ | ✗ | 15/30 | 14 | 1 | 0 |
| `be2c56243e6f46f18f81020609d5ca24` | ✓ | ✓ | ✓ | ✓ | 23/30 | 6 | 1 | **0** |

- **chmod 修复得到因果确认**：去掉它，hp001 的 **10 个 cell 全部弃权**（a、b 两侧 E1–E5），即最初报告的权限证据死锁被按需复现；保留它，10 个 cell 全部正确。这是确定性的、整组的效应，不是波动。
- **预算修复与结构化收尾**：把 3 个执行失败降为 0～1 个，registry 增加结构化 `budget_exhausted` 状态，无论是文本工具还是 JSON 工具（返回 error），在预算耗尽时均能立即关闭 tools 并让模型有界收尾。
- **证据门槛修复彻底消除误判**：修复前（Arm 1 / Arm 2）hp003_b 必定在 E1 或 E3 发生 VULNERABLE 误判；修复后（`be2c5624`），函数级候选作用域得到统一，删除了 helper 状态的错误回退，且基于完整 trace 闭环了 `inspect_command_construction` 的准入门槛。全矩阵 **0 误判**，同时 `hp001`（10/10）和 `hp002`（10/10）全量保持正确，零回归。
- 已修复（部分）：解构赋值接收非元组值时，不再让整个分析中止，而是把解包出的名字绑定为 unknown；`unknown` 无法到达 SANITIZED，因此不放宽安全性。同时把 `UNAVAILABLE` 判定改为以「未解析调用」本身为依据，而不是要求额外存在 issue（后者只是代理信号，修复后会失效）。测试 1256 项通过。
- **但 hp003 仍不可判定，且原因已定位**：`serve` 有 **四个**可达 helper 含不受支持的构造——`prepare_env`（FunctionDef）、`_set_mlflow_config_env`（属性/容器修改）、`_download_artifact_from_uri`（Try）、`Environment.execute`（NamedExpr）。这些 helper 与命令路径无关，却各自触发「helper 分析失败 ⇒ 整个候选 AMBIGUOUS」的保守升级，于是 `shlex.quote` 修复被挡在后面。扩大解释器覆盖面（逐个支持 Try、NamedExpr、属性修改……）在真实代码里没有自然边界；放宽升级规则则与既有安全测试冲突：`test_helper_failure_cannot_support_safe_vote` 里的 helper 自身会执行命令，必须继续被判为不可 SAFE。

三个漏洞/修复对均已用于反复检查和修复，所有相关配置保持 `claim_eligible=false`。应将其用于开发回归；研究结论需要冻结协议后独立的新样本及预先确定的重复运行计划。

## 语义修复与剩余问题

9 月 22 日通过失败测试和完整实验定位后，已完成以下有界修复；未覆盖语义仍保持不确定：

1. 已修复：正常分支汇合与受支持 Try 的后续语句完整收集；不同终止路径、绑定改写、异常类型副作用和 handler 内未证实可达的权限操作保持 UNRESOLVED。消除漏扫后过强 REFUTED，同时恢复有支持依据的 chmod 模式判断；仍非完整异常路径分析。
2. 已修复：直接传入 `['bash', '-c', value]` 不再被普通 argv 规则清除污点；绝对路径和 executable 覆盖也保留可能流。单次赋值、仅用于受支持 subprocess 参数的局部普通 argv 可保留结构，避免与直接传参不一致；容器修改、逃逸、重赋值仍保守处理。不是通用解释器或别名分析。
3. 已修复：显式证据角色冲突会被拒绝并指出引用/字段，包含同观察别名；角色冲突与独立证据错误一起反馈。候选已观察到的权限检查不再能通过引用选择绕过门槛。
   局部鉴权分析也补充直接 lookup→delete 的资源、参数与比较事实，不将主体参数名或未知上游策略视作具体授权证明。
4. 将 `get_cmd` 这样的构造函数指定为 sink，工具找不到执行 sink，可能返回 NOT_ESTABLISHED；这不等于输入无法流向外层 Popen。
5. 下载变换及 shell 上下文仍有未解析语义；相关 AMBIGUOUS/UNRESOLVED 和合理弃权应保留。
6. 已修复：非恒定分支的条件表达式形状不再改变 chmod 有界判断。此前只有 `if enabled` 这类简单条件能完成模式判断，`if is_in_databricks_runtime() and get_repl_id() is not None:`（GHSA-4x5p-f36r-mxxr 的实际形状）会因条件内部的调用与短路表达式被追加额外限制，整体退回 UNRESOLVED，进而使权限证据门槛同时禁止 VULNERABLE 与 SAFE，三专家只能 ABSTAIN。现在条件内部的表达式形状问题由「crosses a nonconstant branch」统一表达，模式序列仍按原有契约判断；每个收集到的调用同时记录其所属分支条件（`branch_conditions`），使 CONFIRMED/REFUTED 的适用范围可追溯到具体路径。测试中的 `os.chmod` 本身仍保留绑定与参数个数限制。
7. 一个专家子任务内不再重复执行完全相同的工具调用。同一 scope 面对同一份冻结索引，重复调用的结果不会改变；重复会被记录为 blocked 观察并指向已有的 citation，而不是再次消耗预算。该拒绝与其他 blocked 观察一样计入工具观察预算并写入 journal，不同专家子任务使用各自的 scope，仍会各自执行被指派的验证器。
8. 已修复：工具观察预算耗尽后，模型不再收到空的工具消息。此前「observation budget exhausted」这条说明本身也要占用预算，于是被自己报告的预算抑制成空 payload；模型把它读成「工具什么都没返回」，于是重复请求同一路径直到 8 步上限。现在无法投递的调用会收到 Harness 诊断正文（JSON 工具保持可解析的 payload），该诊断不计入它所报告的预算。预算检查先于重复检查，因此耗尽的子任务总能得到解释。

`VULNERABLE/SAFE/ABSTAIN` 是预测；`CONFIRMED/REFUTED/UNRESOLVED` 是候选绑定证据状态。静态 MAY_REACH 或声明输入条件不能提升成具体 exploit witness。

## 下一次行为修复的顺序

接下来改善 sink 参数诊断，并继续扩展权限路径与 shell 上下文的失败测试。随后冻结配置、记录所有重复运行，分别报告运行完整性、检测质量、覆盖率和成本。独立真实运行的成本差异仍需重复测量，不能直接归因于早停。

</details>
