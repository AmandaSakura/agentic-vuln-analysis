# M0 阶段 4：开发期结果与结论边界

本报告续写 [M0 计划](2026-09-29-remaining-work-plan.md) 的阶段 4，保留 [2026-09-29 的 S4 停止时报告](2026-09-29-remaining-work-final-report.md) 作为历史记录。所有样本均为 `dataset_role=development`、`claim_eligible=false`。A 的场景来自数据集，B 的场景由真实模型提出；`developer_scripted` 只检查工具在明确给定场景下的能力，不计入真实模型成功率。补充实验 E-iter 与 M0 原阶段分开记账，也不重置其门槛。

## M0 原阶段

阶段 0 的无请求预检核对了 B 的空场景 subject、实际初始请求及两快照输入绑定。阶段 1 的四格在同一模型 `deepseek-flash` 下完成；阶段 2 只对 B 做一次预登记的通用协议修复与确认性重跑。表中“准备”表示 `witness_attempted=false`；底层 `raw_status` 与最终准入判定分别列出，不能互换。

| 阶段 / 格子 | 条件、场景来源 | 物理见证 | 底层 raw_status / 投递 | 最终判定 | 请求 / reported tokens |
| --- | --- | --- | --- | --- | ---: |
| 1 / hp003_a | A，dataset | 0，准备未完成 | 准备 UNRESOLVED | ABSTAIN / UNRESOLVED | 8 / 48,350 |
| 1 / hp003_b | A，dataset | 0，准备未完成 | 准备 UNRESOLVED | ABSTAIN / UNRESOLVED | 8 / 48,202 |
| 1 / hp003_a | B，model | 0，准备未完成 | 准备 UNRESOLVED | ABSTAIN / UNRESOLVED | 8 / 46,712 |
| 1 / hp003_b | B，model | 2 | LITERAL_OBSERVED 两次；投递均截断、无可用 proof | ABSTAIN / UNRESOLVED | 8 / 47,913 |
| 2 / hp003_a | B，model | 1 | UNRESOLVED，`recorder_prefix_not_established`；完整投递 | ABSTAIN / UNRESOLVED | 8 / 51,842 |
| 2 / hp003_b | B，model | 1 | UNRESOLVED，同一前缀缺口；完整投递 | ABSTAIN / UNRESOLVED | 6 / 38,311 |
| 3a / entry-00390 a、b | B，离线 developer_scripted | 各 1 次尝试，未到进程边界 | UNRESOLVED，`target_or_isolation_error`；TempDir 写入被隔离拒绝 | 均 ABSTAIN；原阶段 API 跳过 | 0 / 0 |
| 3b / 固定前 15 条公告 | 无场景选样，离线 | 0 | 0 对完成环境准入；无见证 raw_status | 未运行模型 | 0 / 0 |

阶段 1 的 B-a 主因是 **F1**：一次字符串布尔值被 schema 拒绝后，正确类型的场景仍缺 3 个入口值和 2 个构造值；工具只接受了部分准备数据，模型没有补齐，局部 8 步/8192 观察预算也限制了收尾。A-a 把数据集已给场景又作为替换假设提交而被拒，也没有完成冒烟正例。阶段 2 修复了通用缺字段协议、继续准备指引、严格字段类型及“已执行但投递失败”的重复执行记忆；不替模型填写值，不改变九项运行义务或证据门槛。重跑时 B-a、B-b 均真正执行一次且完整投递，但模型选择 `enable_mlserver=false` 的 scoring-server/uvicorn 分支，实际命令不含探针路径，故 B-a 为 **F3，局部 F6 伴随**。两次准备响应不能算执行，后续未再做 M0 第二轮确认性重跑。详细原始场景、分类、请求和工具时序见[阶段 1](2026-09-29-phase1-results.md)、[阶段 2](2026-09-29-phase2-results.md)及各自的机器摘要。

3a 的无场景 Click 入口可按精确绑定直接调用 callback，但不执行公开 CLI parser；没有证据证明 parser 的转换或远程调用权限。正确开发脚本也因只读隔离下的临时目录创建失败，未到 `environment.py:1014` 的实际进程边界。按登记前置条件，不发 M0 的 3a 模型请求。3b 按发布时间固定检查 15 条 Reviewed/PyPI/CWE-78/77 公告，绝不从第 16 条补选。唯一源码路径合格的 Pillow 暂定候选在两份精确源码的受限 Python 3.12 导入预检中均缺匹配的 native `_imaging`；当前 K3 的 metadata-only 准备不能满足环境标准 6，因此完全合格对数为 0，v7、脚本见证和 3b 模型请求均为 0。这是本轮环境能力缺口，不证明该源码无法构建或该漏洞安全。见[3a 记录](2026-09-30-phase3a-offline-results.md)、[3b 记录](2026-09-29-phase3b-results.md)和[逐条选样审核](2026-09-30-phase3b-selection-audit.md)。

## 追加探索性 E-iter：不改写原阶段

E-iter 是用户另行授权、一次预登记的四格补充定位实验，使用 B 的空场景输入和通用紧凑投递；它**不是** M0 阶段 2 的第二次重跑，也不补算 3a 原阶段跳过的运行。四格各进行一次物理见证，最终均为 ABSTAIN / UNRESOLVED，没有已准入的 VULNERABLE、producer CONFIRMED 或固定侧可靠性警报。

| E-iter 格子 | 模型提出场景后的实际缺口 | 最终判定 | 请求 / reported tokens |
| --- | --- | --- | ---: |
| hp003_a | 一次实际 UNRESOLVED；选了 false 分支，`recorder_prefix_not_established` | ABSTAIN | 6 / 36,234 |
| hp003_b | 一次实际 UNRESOLVED；同一 false 分支和前缀缺口 | ABSTAIN | 7 / 44,985 |
| entry-00390 a | 一次实际 UNRESOLVED；TempDir 创建失败，尚未到进程边界 | ABSTAIN | 7 / 45,465 |
| entry-00390 b | 一次实际 UNRESOLVED；同一隔离/临时目录缺口 | ABSTAIN | 6 / 39,798 |

四格合计 **26 请求 / 166,482 reported tokens**，全部原始返回 ID 为 `deepseek-flash`，usage 与请求账本一致，没有解析失败；运行硬停为空。hp003 两格的完整实际观察各花 968 个可见预算单位，CLI 两格各 861，均完整投递。模型没有在收到实际 U 后迭代成另一场景。两份原始 VULNERABLE/UNRESOLVED 提案被证据准入拒绝，不是最终 V 票，也不是假确认。E-iter 仍未得到自主正例，亦不能单独识别局部预算对模型选择错误分支的因果作用。原始账本及复核见[独立审计](../../artifacts/remaining_work_20260929/E_iter_independent_audit.json)；单独的 E-iter 文字报告将归档为 `2026-09-30-E-iter-results.md`。

## 用量、离线工程与门槛

| 真实模型范围 | 请求 | reported tokens | 授权上限 |
| --- | ---: | ---: | --- |
| M0 阶段 1 | 32 | 191,177 | 60 请求 |
| M0 阶段 2 | 14 | 90,153 | 30 请求 |
| E-iter（另列，仍计入全局） | 26 | 166,482 | 40 请求 |
| **累计** | **72** | **447,812** | **210 请求 / 2,500,000 tokens** |

阶段 0 的 2351 项完整测试与 harness 通过；阶段 2 真正请求前的完整门禁为 2427 项通过。K1 将范围说明改为基于实测状态，并仅向模型投递一次可逆的分类前提清单；准备状态明确“未执行”，运行时 U 不会把未核验前提说成已核验。K1 完整套件 2438 项与 harness 通过，真实开发配对的脚本结果仍为 a `CONFIRMED/EXPANDED_OBSERVED`、b `UNRESOLVED/LITERAL_OBSERVED`，两侧均核对 977 项源码绑定。紧凑观察的可信引用、原始完整产物和分类均保留；它不放宽 proof 准入。见[K1 结果](2026-09-29-k1-results.md)。

K3 从新目录构建两套源绑定 Python 3.12 环境，141 个包版本和 977 项源码绑定与旧环境逐项相同；沿用原四个身份绑定只读叶文件授权，没有自动接受新的准入建议。K3 脚本配对仍 a 确认、b 未决；见[K3 结果](2026-09-30-K3-results.md)。K4 的离线 E4 验收中，a 的 scan 与 taint 两张实质票引用**同一次**确认见证：共享票 2、独立观察 1，最终 VULNERABLE；b 为 ABSTAIN，零实质票。E5 仅回放同一票序列计算反事实节省，未独立执行第二套见证，也不等于两次独立证明；见[K4 结果](2026-09-30-K4-results.md)。这些全是 `developer_scripted`，不得与真实模型统计相加。

E-iter 前，完整手动门禁 **2556 passed / 407.96 秒**、harness **PASS**；真正请求时在提交 `8f05292` 上重新跑出的完整门禁为 **2556 passed / 390.51 秒**。E-iter 后若有代码改动，其完整套件应按最终源码另记，不能沿用这次真实请求前的通过记录。K2 的运行时分层仍待本报告之后完成，必须在没有真实运行重叠时迁移并复测；[架构计划](2026-09-29-remaining-architecture.md)的 G-A 正式判定排在 M0 与 K2 之后。

### 只属于离线 CONFIRMED 的分类前提

本轮真实模型**没有**任何 CONFIRMED。离线 hp003_a 确认控制（阶段 2/K4 的原始脚本场景相同；K1/K3 配对沿用该开发控制）的前提按运行时绑定的分类如下。`model_uri` 表示有界调用者可给出的本地输入，不证明外网攻击者有权限；分类只是来源说明，不代替真实值、分支和源码核验。

| 分类 | 声明的前提与值 |
| --- | --- |
| 攻击者可控输入 | `input_parameter=model_uri`，本地调用者提供已存在的目录名。 |
| 部署配置 | `config={}`；`enable_mlserver=true`；`self._env_manager != em.LOCAL=false`；`host=127.0.0.1`；`port=5000`；`timeout=null`；`self._nworkers=1`；`model_config=null`；`synchronous=false`。 |
| 环境条件 | `sys.platform.startswith('linux')=true`；`is_windows()=false`；`os.path.exists(artifact_uri)=true`；`MLServerDefaultModelName="mlflow-model"`；`MLServerMLflowRuntime="mlserver_mlflow.MLflowRuntime"`。 |

E-iter 离线序列另有一个更短的 hp003_a 确认控制：`input_parameter=model_uri` 为攻击者输入；部署配置为 `config={}`、`env_manager="local"`、`enable_mlserver=true`、`host="127.0.0.1"`、`port=5000`、`timeout=null`；它没有额外分类的文件或环境条件。此序列先运行 false 分支 U，再以脚本给定 true 分支 C，说明工具可区分两个物理场景，**没有证明真实模型能自己迭代到 true**。完整 rationale、值与结果在[阶段 2 离线摘要](2026-09-29-phase2-offline-summary.json)、[K4 机器摘要](2026-09-30-K4-summary.json)和[E-iter 离线摘要](2026-09-30-E-iter-offline-summary.json)；最终报告不将本地分类误称远程权限证明。

## 结论边界

| 问题 | 本次可以说 | 本次不能说 |
| --- | --- | --- |
| 无场景标注的自主确认 | M0 B-a 在阶段 1 未执行，阶段 2 执行一次但走错误分支；E-iter 补充一格仍为 U。原 M0 成功条件明确失败。 | 不能用开发脚本的 C 替代真实模型成功，不能称具备无场景泛化召回。 |
| 已标注场景 A | 两格均因替换数据集前提及缺数据而未执行，最终弃权。 | 不能称 A 冒烟成功或用同提示推断模型找到分支。 |
| 见证可靠性与 b 侧 | 本轮所有真实 b 格均无 SAFE、无 producer CONFIRMED、无已准入 V；字面量及运行时 U 均未被当作安全证据。 | 有限的开发对照不能证明全域零误报、整函数 SAFE 或其他场景都可靠。 |
| 跨入口与新仓库迁移 | Click callback 有源绑定直接调用能力；K3 可从零准备两套既有开发环境。3a 实际止于 TempDir，3b 的唯一源码合格者止于 native 导入。 | 不能称无需改动便迁移到 CLI 公开解析路径或新仓库，不能报告外部新样本模型成绩。 |
| 运行时确认的范围 | 离线 C 只证明特定分类前提下的具体本地调用和命令展开；remote authority 一直未建立。 | 不能称远程命令注入已证实，也不能把静态 may-flow 或模型理由当作运行时事实。 |
| E4/E5 票数 | 两张实质票可合法引用同一已投递验证器观察；计数明确为 2 票/1 观察。 | 不能将票数当作两份独立见证，或把 E5 回放当作实际成本实验。 |
| held-out 与评测 | 没有运行 held-out 测试或把其标注、场景放入 detector/prompt。用户提供的两个统计口径分别是 146 条 repo+commit 输入与 361 条汇总、其中 TypeScript 295/Python 36/命令相关至多 1；这两个分母不同，汇总未经本轮独立核验。 | 不能相除、合并或声称 held-out 成绩；不能从开发、公告预选或 E-iter 结果估计召回与误报率。 |

S4 授权历史必须随结论保留：先前门禁/归档对受保护配置的机械哈希与复制被单独披露并获继续授权；随后一次过宽的源码导航搜索又意外显示四个 held-out 配置的 `commit` 字段，已按[内容搜索事件](2026-09-29-STOP-S4-content-search.md)单独停下和披露，用户再明确要求继续。没有标签或场景内容进入该输出，已报告未用于推理、代码、选样、detector 或 prompt；这不是“从未读取任何受保护字段”的声明。此后继续禁止读取受保护内容，3b 仅比对已提交的仓库 URL 排除清单。

按[架构计划的合取门槛 G-A](2026-09-29-remaining-architecture.md)，既需原 M0 B-a 自主成功，也需 3b 至少一对迁移成功。两项在现有事实下都不成立，所以 **K2 完成后的正式 G-A 预计为 NO；K5–K8 暂不启动**。K2 尚未完成，不把这一预测伪装成已经进行的正式门槛判定。若最终仍为 NO，应按架构计划将现有见证定位为少量候选的有界确认工具，并单列环境构建、入口可达性、模型选场景、隔离临时目录和本地调用权限这些扩展代价。不能以 E-iter 或额外开发脚本救回原 M0 成功条件。

## 收尾更新（2026-09-30，追加）

本节在上文之后追加，不改写上文。

- **K2 已完成**：见证运行时迁到 `runtime/witness/`，核心包不再导入 evaluation 层。用迁移后重建的上下文重跑两个真实快照的脚本化配对：a 为 `CONFIRMED / EXPANDED_OBSERVED`，b 为 `UNRESOLVED / LITERAL_OBSERVED`，两侧的绑定字段与迁移前记录逐项相同。详见 [K2 结果](2026-09-30-K2-results.md)。
- **G-A 已正式判定为 NO**：B-a 和 3b 两个条件都不满足，K5–K8 不启动。见 [G-A 判定](2026-09-30-G-A-decision.md) 和 [定位报告](2026-09-30-positioning-report.md)。
- **更正**：上文"用户提供的两个统计口径"一句，这些数字实际来自架构方的查询；架构方当时还看过 13 条 held-out 命令注入类条目的元数据。见 [架构方披露](2026-09-30-architect-exposure-disclosure.md)。
- **预防措施**：仓库根目录新增 `.ignore`，ripgrep 默认搜索跳过 held-out 输入文件及其快照副本。门禁指纹和源码归档不读这个文件，行为不变。
