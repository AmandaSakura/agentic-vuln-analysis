# Jev V2：独立验证工具决策

V2 参考 mu 的窄问题、独立策略、shadow 模式和决策账本。检索后通过受限的 `read_span` 取得候选源码，一次原生 `/v1/systemone` 请求批量询问 scan、taint、authz 各自应先使用哪个验证工具。删除 V1 的“整个计划是否足够”问题，也不再把所有选择绑成全有或全无。

Jev 只选择取证动作；专家仍需调用工具、独立判断，并完成 E4 仲裁。它的概率不是验证证据，也不产生额外选票。

## 配置和启动

在项目根目录的 `.env.experiments` 填入：

```dotenv
JEV_API_KEY=你的TypeSafe密钥
```

该文件已被 Git 忽略；可提交模板为 [环境变量示例](../../.env.experiments.example)。原有 `CV_AGENT_PROVIDER`、对应的 DeepSeek/Gemini 模型与密钥仍用于专家和 LLM 深审，不要删掉。

从项目根目录执行：

```bash
bash scripts/jev_pilot.sh
```

新 checkout 还需先按项目说明安装锁定环境并准备 advisory 源码快照。启动脚本无参数，读取本地环境文件后直接执行 `cv_agent.evaluation.runners.run_jev_routing_pilot`。当前 [V2 配置](../../configs/experiments/jev_routing_v2_pilot.json) 固定模型 `jev-1.13.0`，默认 `mode=shadow`。V1 配置和实验源码快照保留，不覆盖历史结果。

模式含义：`off` 不调用 Jev、不额外读取源码，也不需要 Jev key；`shadow` 调用并记录建议，但使用原 LLM 规划器，保持其输入及观察预算；`active` 应用通过策略的逐项选择。shadow 有额外调用开销，用于观察，不用于宣称省钱。修改 V2 配置中的 mode 后需启动新进程。

hp003 的单独 active 对照由 `bash scripts/hp003_jev_active.sh` 启动，读取 [hp003 active 配置](../../configs/experiments/hp003_jev_active.json)：hp003_a/b 各先 E4_JEV、再 E4，共 4 项。Jev 优先规划，现有策略无法接纳其计划时使用 LLM 规划器；专家仍使用配置中的 DeepSeek/Gemini。阈值 0.85、原专家规则和候选证据准入保持一致，两组使用同样的源码、场景及注册 fixture。普通 E3/E4/E5 入口继续作为无 Jev 的对照，旧 hp001 shadow 配置独立保留。

该 hp003 批次已于 2026-09-27 完成，脚本中的执行命令现已注释，并保留两次运行 ID 作为执行记录。需要重新执行时，明确取消其中一条命令的注释；当前脚本不会自动重复已完成实验。

默认使用已有开发案例 `hp001_a`、`hp001_b`，每例按 E4_JEV、E3、E4 的顺序执行，共 6 项，串行执行。先跑新方案，接口失败即停止，避免先消耗基线请求。总上限 120 次模型请求、1800 秒的请求准入时间窗口；进行中的请求仍受各自 HTTP timeout 限制。遇到接口错误或预算耗尽就停止，不自动重试、不扩大矩阵。Jev 和专家请求共同计入预算。

所有真实请求都经过 `OpenAICompatibleChatModel` 的完整 pytest 门禁。缺少 Jev key 时提前报错；离线 pytest 使用假密钥和模拟 HTTP，不读取 `.env.experiments`。

## 分流边界

- 每个决策独立检查 `probabilities[choice] >= min_choice_probability`；门槛仍为 0.85，未经本领域校准。provider 的 `confidence` 单独记录，不当作所选项概率。
- 每道题都有 `unknown` 选项。在 active 模式下，明确选择生成该专家的验证任务；不明确的专家保留原本自主选择工具的 ReAct 流程，不跳过专家。
- 没有任何可用选择、计划违反权限/命令检查约束，或部分 fixture 计划无法覆盖所有依赖时，进入原 LLM 规划器。所有提议仍保留供审查。
- 源码读取错误、截断或无可用验证器时，直接进入 LLM 规划，不消耗 Jev 请求。
- API 错误、缺失答案、未知选项、非法概率属于执行失败，不伪装成低置信度决策，也不自动切换后端。
- 路由读取额度由 `max_source_observation_tokens` 显式配置，默认 4096；hp003 active 使用 6144，以完整读取较长的候选函数。额度必须小于原有 8192 总规划观察预算；active 模式的后续 LLM 规划共享剩余额度，不能重置已用预算。shadow 不扣减基线规划预算，但额外读取仍完整计入用量。
- 此版本不减少专家人数、不让 Jev 输出 SAFE/VULNERABLE。能否节省规划请求以及是否影响检测质量，必须实测。

## 结果

每次写入新的 `artifacts/jev_routing_pilot/<run-id>/`，保留 `metadata.json`、`events.jsonl`、`results.json`、`usage.json` 和 `summary.json`。完整失败、弃权及未运行单元保留在分母内。

`routing_decision` 事件在专家执行前持久化，专家之后失败也不丢失调度记录。`verdict.routing` 保存 spec_version、mode、state_digest、延迟、原始回答、用量、proposed_plan 和实际 plan。每个 decision 同时保存所选概率、provider confidence、门槛、accepted、applied、最终 action 及未接受原因。accepted 仅表示逐项过门槛，applied 表示程序采用该调度，工具是否真的成功执行仍需查 task_executions 和工具日志。

`verdict.planner` 仅表示真正执行过的 LLM 规划。路由与规划请求、工具观察均计入总数。原始响应在解析前记账，Jev 的 input/output tokens 相加得到 total；失败解析也保留已报告用量，不重复计数。

`summary.json` 分系统、分角色统计 usage，并报告 E3/E4 与 E4_JEV 的配对结果。未配置价格时货币费用为未知，不把 token 数当作费用。这组数据已用于开发，固定标记 `dataset_role=development` 和 `claim_eligible=false`，不构成独立泛化或降本证明。规则分流基线已在下述 V3 六格中加入；仍需在独立样本上校准及评估。

## V1 运行与 V2 策略回放

V1 真实运行 `927d7003cedd415eb6a83495d6b4a3b4` 的 6 项均弃权：E3 15 次请求，E4 49 次，E4_JEV 51 次。Jev 两次均成功，整体 route confidence 为 0.13、0.39，触发了整计划深审。

把同次运行的局部回答代入 V2 逐项门槛，仅作离线策略回放：

| 案例 | scan 所选概率 | taint 所选概率 | authz 所选概率 | 局部策略结果 |
| --- | --- | --- | --- | --- |
| hp001_a | 1.00 | 0.82 | 1.00 | 保留 scan/authz 提议，taint 自主取证 |
| hp001_b | 1.00 | 0.79 | 0.99 | 保留 scan/authz 提议，taint 自主取证 |

新问题的措辞已改变，这段回放不是 V2 模型实测，也没有执行这些反事实计划，不能推算节省或准确率。

V2 后续已在 2026-09-25 真实运行两次 shadow 对照：`2bdb4e8b621748c0b167ad668a11c597` 六项均弃权；`8e750201dc044578a354e362d61763a5` 六项均完成并匹配预期标签。两次均返回 `jev-1.13.0`，每个 E4_JEV cell 一次路由请求，所有决策 `applied=false`。这些记录证明接口和 shadow 记录链路工作，不证明 Jev 接管规划后的质量或节省；两次运行的结果差异不归因于 Jev。

## 2026-09-27 hp003 active 对照

首轮 `a2e6a57f88794517ad82ff190535577d` 的四项均正确，但 4096 路由源码额度截断了两个候选函数，Jev 调用为零；这轮 93 请求、737131 reported tokens，不能当作 Jev 接管结果。

将 hp003 源码额度显式设为 6144（仍从原 8192 总规划观察额度中扣除）后，完整门禁 1828 passed in 41.38s。新运行 `6b16f651a0904ca194f1af29c86b7366` 四项均正确、无失败或最终弃权：

| 组别（hp003_a/b 合计） | 全部请求 | LLM planner 请求 | Jev 请求 | reported tokens |
| --- | --- | --- | --- | --- |
| E4_JEV active | 49 | 6 | 2 | 390514 |
| 普通 E4 | 45 | 6 | 0 | 347400 |

两次 Jev 响应均为 `jev-1.13.0`。scan 的命令检查选择概率为 0.94/0.95，通过 0.85 门槛；taint 选择 trace_dataflow 的概率均为 0.51，未通过门槛；authz 均为 unknown。原策略要求该类候选的 taint 专家执行 inspect_command_construction，因此两次均将整份计划交回 LLM，所有决策 `applied=false`。这轮证明先调用 Jev、策略拒绝后调用 LLM 的路径已通，但没有成功跳过 LLM 规划，也未观察到请求或 token 节省。未修改准入、门槛或必需验证任务来使计划获准。

新运行 94 请求、94 响应、737914 reported tokens；两轮合计 187 请求、1475045 reported tokens，货币费用未知。所有四项同时使用注册 fixture 和命令分析器，结论限于开发回归场景。原始目录均位于 `artifacts/jev_routing_pilot/`，快照及历史结果未覆盖。后续若要减少整单回退，需要单独评估怎样在保留必需 taint 检查和依赖的前提下组合局部决策；本轮未执行第三次模型实验。

## 2026-09-27 proof routing V3 返工与三臂六格

首次 V3 六格 `f9eadcf1d6334cbf9972e1bfcd021472` 的规则臂实际发起 7 次 LLM planner 请求，原 `routing=null`，因此不是有效的纯规则对照；旧静态下载摘要还会错误放行判决。原始结果保留，但原交接归因撤回。

修复证明范围、规则构造、case 绑定、组合 DAG 与局部补规划后，重新运行 `545892d6559f439a94ef307cc021cac3`。固定专家、禁用 fixture，hp003_a/b 各按 E4_JEV_V3 → E4_RULE_V1 → E4 运行一次。六格 **全部弃权、零运行失败**，`inspect_command_construction` 为 `AMBIGUOUS`，未解析 `_get_root_uri_and_artifact_path`；不能把弃权算成正确实质标签。规则臂两格均为 **0 planner 请求**，Jev 两次请求返回四个决策，两次 `trace_dataflow` 入计划并执行。

| 两样本合计 | 全部请求 | planner 请求 | Jev 请求 | reported tokens | 实质判决 |
| --- | ---: | ---: | ---: | ---: | ---: |
| E4_JEV_V3 | 48 | 0 | 2 | 388,827 | 0/2 |
| E4_RULE_V1 | 45 | 0 | 0 | 386,460 | 0/2 |
| E4 | 62 | 8 | 0 | 568,400 | 0/2 |

总量 155 请求、1,343,687 reported tokens；费用未配置。该单次开发样本结果证明新规则臂和 Jev 选择确实按来源执行，但未显示 Jev 带来判决收益。详细更正、正反例与逐请求账本见 `artifacts/proof_routing_repair/handoff.md`。

## 参考及未照搬的行为

参考 mu 固定版本 `8252cc6ed561e45ff658c9c89f134b9e90499bc8` 的 [逐项 choice 策略](https://github.com/AmandaSakura/mu/blob/8252cc6ed561e45ff658c9c89f134b9e90499bc8/packages/kyrn-judge/src/policy.ts)、[决策模式与账本](https://github.com/AmandaSakura/mu/blob/8252cc6ed561e45ff658c9c89f134b9e90499bc8/packages/kyrn-judge/src/decision.ts)、[窄任务路由](https://github.com/AmandaSakura/mu/blob/8252cc6ed561e45ff658c9c89f134b9e90499bc8/packages/kyrn-judge/src/decisions/swarm-routing.ts) 及 [收益回顾](https://github.com/AmandaSakura/mu/blob/8252cc6ed561e45ff658c9c89f134b9e90499bc8/kyrn/docs/08-jev-retrospective.md)。本项目继续要求 API/日志失败显式报错、完整记录用量，不照搬 fail-open、吞日志错误或缺失 usage 视零的行为。

接口依据：[TypeSafe OpenAPI](https://api.typesafe.ai/openapi.json)。实施范围见 [接入计划](JEV_IMPLEMENTATION_PLAN.md)。
