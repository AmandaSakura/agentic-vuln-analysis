# 项目审查：2026-09-19

> 历史审查：以下描述的是当时的 301-test 版本。其问题已分批修复；当前版本、剩余缺口和最新复查见
> [当前状态](PROJECT_STATUS_2026-09-19.md)及[本轮审查结果](CURRENT_REVIEW_RESULT_2026-09-19.md)。

**结论：项目已经具备可运行的研究原型，但验证器存在可复现的错误确认，尚不能把 typed CONFIRMED 当作可靠的候选漏洞验证。当前最需要修的是证据语义和归属，而不是先扩大 API 调用。**

此次审查未修改实现、既有测试或历史实验结果，未请求模型 API，未操作共享代理。新增离线反例脚本与本报告。运行已有上下文审计脚本重新生成了 `artifacts/development_context_audit_with_bm25.json`，源码 profiling 生成了新目录。

## 检查范围与实测

审查覆盖候选生成、Python 调用图、跨语言适配入口、检索和上下文截断、ReAct 证据校验、动态任务调度、全量/提前退出裁决、验证器、Python probe、fixture 隔离、模型协议、开发评估、held-out 清单、LangChain 差分复现，以及关键实验产物。也检查了旧确定性实验与新 live 系统的用途区别。没有对所有第三方源码做形式化验证，也没有重新执行全部历史模型实验。

| 检查 | 本次结果 | 能说明什么 |
| --- | --- | --- |
| `uv run --no-sync pytest` | 301 passed，9.42 秒 | 既有测试通过；包括本机已准备好的 LangChain 差分测试 |
| `uv run --no-sync cv-agent harness-check` | PASS | 声明的系统契约内部一致，不是算法正确性认证 |
| 66 案例上下文审计 | 原 E2 0/66；E3 66/66；增强 BM25 66/66 | 图优于弱文本的上下文保留结果可复现，但强文本也全保留 |
| 三个开发仓库解析 | 2,489 文件，328 候选，0 个报告的解析错误 | 解析可运行，不能推出图边或数据流正确 |
| 六类调用账本重算 | 361 请求、1,367,529 token、10 invalid、1 usage 缺失 | 与已有六类账本一致，但它遗漏另一个已有诊断产物 |
| 两个 LangChain checkout | 当前工作区干净；差分测试通过 | 当前样本的差分行为真实存在 |

新增反例：`artifacts/project_review_2026-09-19/reproduce_findings.py`。
原始结果：`artifacts/project_review_2026-09-19/reproductions.json`。
源码解析新产物：`artifacts/development_source_profile/e26691c27aef400b8c66ace8eb0c8b65/`。

复跑反例（项目根目录）：

```sh
uv run --no-sync python artifacts/project_review_2026-09-19/reproduce_findings.py
```

反例中的模型传输、跨候选 fixture 执行及错误 benign 输出使用 mock，以隔离所审查的协议/证据归属/判定逻辑；其余反例直接调用现有解析器与验证器。没有执行不受信任的仓库代码。产物目录被现有 `.gitignore` 忽略，交接时需要单独保留。

## 按优先级排序的发现

### R1 / P1：污点分析把不可达代码和无注入语义的调用确认为漏洞

位置：`src/cv_agent/python_flow.py:107`、`:132`；`src/cv_agent/validation_tools.py:1037`。

已复现两个独立问题：

```python
def endpoint(request):
    return "safe"
    eval(request.args["x"])
```

```python
def endpoint(request):
    subprocess.run(["/bin/echo", request.args["x"]], shell=False)
```

两者 `trace_dataflow` 都返回 `CONFIRMED`。第一例的访问器不在 `return` 后终止路径。第二例仅依据第一个实参包含污点，不区分固定可执行文件的 argv 与 shell 命令文本。输入进入 echo 参数并不构成 shell 注入。

这是验证器的实际误报，不能只用“静态检查不是动态 exploit”解释：第一例连可达的数据流都不存在。应实现控制流终止与特定 sink 的危险参数语义；无法建立的部分保留 `UNRESOLVED`，并另行报告 may-taint 事实。

复现键：`unreachable_eval_is_confirmed`、`shell_false_echo_is_confirmed`。

### R2 / P1：授权验证仅凭通用动词和没有匹配到 guard 就确认漏洞

位置：`src/cv_agent/validation_tools.py:1156`、`:1292`。

已复现：函数创建局部字典，调用 `local_cache.update({"last_seen": 1})`，返回 `"ok"`，仍被判为 `CONFIRMED` 的授权问题。`update` 命中敏感操作词，没有 guard 就确认；没有证明受保护资源、主体、权限需求或未授权访问。

这会让无关的 authz 专家贡献错误的物质票，并可能与其他错误票组成 quorum。guard 缺失的模式发现应为 `UNRESOLVED`；确认需要绑定具体主体、动作、资源及可复现的授权失败。

复现键：`local_dict_update_authz_confirmed`。

### R3 / P1：差分验证器把安全重构当成原版本漏洞证据

位置：`src/cv_agent/validation_tools.py:1367`。

已复现：旧函数 `return eval("1 + 1")`，新函数 `return 2`。两者均不接受攻击者输入，但 sink 数量下降使 `compare_vulnerable_and_fixed` 返回 `CONFIRMED`。新增 guard 的判断同样主要依赖关键词数量与行序。

“检测到了疑似修复差异”与“确认旧版候选漏洞”不是同一结论。当前状态会被 `validate_conclusion` 接受为 VULNERABLE 的确认依据。应把模式差异保留为普通证据，并要求同一攻击在旧版成功、新版阻断及正常控制成功后，才赋予相应漏洞验证状态。

复现键：`safe_constant_refactor_confirmed`。

### R4 / P1：证据只校验引用存在，没有完整绑定候选及攻击目标

位置：`src/cv_agent/validation_tools.py:953`、`:1397`、`:1427`；`src/cv_agent/react_engine.py:82`。

`probe_python_eval` 已绑定候选入口，这是正确修复；但 `trace_dataflow` 可从任意 admitted span 开始，fixture/loopback 处理器直接丢弃 scope。最终校验只检查被引用工具的状态相符。

已复现：安全候选与另一个有 eval 的 helper 同在 admitted 集合时，从 helper 起跑的 `CONFIRMED` 能通过安全候选的最终结论校验。另一个 repository/case 的已注册 fixture 结果也能被引用并通过校验。fixture 反例 mock 了执行函数，仅测试注册、调用与证据归属边界。

该问题在检索混入无关函数、批量注册多个 fixture 后尤其明显。应让观察携带 repository/commit/candidate/entry/attack 的结构化 subject identity；最终确认需要 subject 相符。需要从 helper 分析时，应显式保留并验证候选到 helper 的可达链。

复现键：`unrelated_helper_evidence_accepted`、`unrelated_fixture_accepted`。

### R5 / P1：已解析的外部导入仍回退到裸函数名，生成错误调用边

位置：`src/cv_agent/python_ast.py:238`；`src/cv_agent/retrieval.py:617`。

已复现：`a.py` 中 `from external import calculate`，仓库仅有 `b.py` 定义同名 `calculate`。解析器同时发出 `external.calculate` 和 `calculate`；索引把后者连接到 `b.py`。若 `b.py` 对输入 eval，污点验证器会沿不存在的调用边确认漏洞。

这影响项目的核心检索比较，并污染依赖该图的验证器。唯一裸名称不代表已知限定符可以被忽略。应保留调用的解析来源/限定符，已知外部目标找不到时保持未解析，而非连接仓库内同名目标。

复现键：`external_import_false_graph_edge`、`false_graph_edge_confirmed`。

### R6 / P1：Python probe 丢失模块级绑定，可能把普通函数调用当成 builtin eval

位置：`src/cv_agent/python_ast.py:280`；`src/cv_agent/python_probe.py:166`。

已复现：模块先声明 `eval = lambda value: value`，入口再调用 `eval(request.args["x"])`。运行语义只是返回字符串，但 probe 报告 `CONFIRMED`。

现有逻辑处理了参数/局部赋值和部分 import shadowing，却没有保留模块赋值。输出列出“unshadowed eval”的假设，并不等于验证了这个假设。需要携带模块绑定信息；不能确定 builtin 身份时应返回 `UNRESOLVED`。作为对照，本次 `from external import harmless as eval` 返回 `UNRESOLVED`，未把已修复的 import 情况误报成新问题。

复现键：`module_shadowed_eval_confirmed`；对照 `aliased_harmless_eval_probe`。

### R7 / P1（开跑前）：LangChain detector 配置直接暴露版本标签

位置：`configs/langchain_pair_eval.json:14`、`:23`；`src/cv_agent/agentic_workflow.py:47`。

所谓“无 ground-truth 泄漏”的 detector cases 使用 `_vulnerable`、`_fixed` ID，checkout 目录也有相同含义。当前 prompt 投影会发送 `candidate_id`。若新 runner 沿用这些 case ID 构造候选，模型可以不分析源码就获知标签。

目前未发现消费这个配置的评估 runner，因此不能说历史 LangChain Agent 结果已被污染；它尚未运行。应在实现 runner 前改用中性 ID，并只在 evaluator 侧保留映射，检查最终模型消息而不只是检查 labels 是否单独存文件。

### R8 / P2：已报告 usage 在非空 choices 的解析失败分支中丢失

位置：`src/cv_agent/model_runtime.py:278`、`:301`。

目前只有空 choices 分支记录 `model_invalid_response` 及 usage。已复现：响应有 choices、包含 `total_tokens=30`，但 tool arguments 不是合法 JSON；最终只有 `model_start` 与 `model_error`，账本记 0 reported tokens、1 usage unknown。

应先记录服务端响应及 usage，再解析内容；任意内容/工具/结构解析失败都应保留已知消耗，防止遗漏或重复计数。此结论来自 mock 响应，未消耗真实 API token。

复现键：`malformed_tool_arguments_drop_reported_usage`。

### R9 / P2：全局调用账本漏掉原始响应诊断

位置：`scripts/summarize_live_usage.py:11`。

六类目录重算与账本完全一致。然而 `artifacts/transport_raw_diagnostic/a2f2198a5013451f9eae5b01aad0b266/raw_response.json` 还保存了一个 HTTP 200 响应，usage 为 prompt 3,691 + completion 306 = 3,997。这个目录不在汇总中，也没有使用事件 journal。

因此，仅把这个已知遗漏加回后，至少是 **362 次请求、1,371,526 个已报告 token**，仍有原先 1 次 usage 缺失。此数不是对所有历史目录的全项目完整账单保证。建议所有 live 入口共用 journal，统一按请求身份去重汇总。

### R10 / P2：LangChain 正常控制失败也能通过差分汇总

位置：`scripts/langchain_template_probe.py:52`；`scripts/reproduce_langchain_template_pair.py:137`。

worker 在输出不等于 `Hello World` 时仍发 `status=BENIGN_OK`，另设 `success=False`；orchestrator 只检查 status。已注入 mock benign 输出 `WRONG/success=False`，汇总仍为 `verified_differential_security=True`、`benign_control_preserved=True`。

当前真实两版本的正常输出确实正确，不是在否定已有复现；这是未来回归可能被错误放行。应验证 `success is True` 和预期输出，并精确检查修复阻断的异常原因。另建议为 subprocess 加 timeout，并在提交号校验之外拒绝脏 checkout 或保存内容身份；当前 checkout 干净，不构成此次实测错误。

复现键：`broken_benign_control_accepted`。

### R11 / P2：交接文档把未经证明的安全审核解释写成已确认根因

位置：`docs/HANDOFF_2026-09-19.md:59`；`scripts/probe_raw_proxy_response.py:40`。

本地 pinned 代理源码支持“非 Claude 分支删除 maxOutputTokens”和“候选转换为 choices”的代码判断。但所谓 raw diagnostic 调用的是 OpenAI-compatible `/v1/chat/completions`，保存的是代理转换后的成功响应，含 1 个 choice；不是失败请求的 Google 原生响应。

没有候选输出或只有 reasoning tokens，不能唯一归因于安全审核，更不能证明是推理中的漏洞关键词触发。文档应区分观察、代码机制和待验证假设。缺少重试是可用性限制，但不能先把失败标为已确认 safety drop，再以重试当作已证实的修复。明确的 provider 拒绝与可重试的暂态错误应区分。

## 架构与实验逻辑的判断

**做得扎实的部分。** 新 live 系统有真实模型/工具循环、类型边界、错误记录、任务依赖和累计专家票。重复子任务不会给一个专家多张票。full/fast 对固定的三专家票采用同一多数规则；两票同向后第三票不能翻转多数，这个逻辑成立。工具有 admitted-path 与输出预算约束，fixture 有专门的隔离与资源限制。开发集、oracle 诊断与最终研究结论有明确区分。失败、弃权与未执行项保留在总体分母中的方向也正确。

**尚未实现的链路。** LangChain reproducer 是独立脚本，未注册到 Agent 的 fixture/validator；仓库中没有读取 `langchain_pair_eval.json` 的运行器。现有 `RecordedTools` 默认仅调用 `full_agent_tools(index)`，未配置该配对的 fixture 或 fixed index。因此“配置已准备好”不代表 Agent 已可端到端获得同样的差分验证证据。

**发现能力有限。** `StaticScanner` 仅三条规则，不能发现该模板入口。Python 文档以函数切片为主，模块级行为和绑定缺失；非 Python flow 仍有行级近似。解析无错误不代表上述语义成立。oracle-seeded 配对评估只能衡量指定入口后的分析，不是全仓自动漏洞召回。

**检索结论需要强基线。** 本次重新验证了原文本 0/66、图 66/66、增强 BM25 66/66。已有 8 例 live 对照的 7/8 与 8/8 可以描述为探索性预测结果，不能据此外推可靠提升，也不能当作漏洞复现率。

**多专家并非自动提升准确率。** 扫描、污点、授权的适用范围不同；与候选无关的专家应弃权。共享索引的错误可以同时影响多位专家。R1–R6 表明 typed 状态本身并不保证证据可信。E3→E4 还同时加入 planner、更多调用和验证，因此是组合差异，不是纯粹专家数或 quorum 的效果。

**E4/E5 的实测边界。** 固定票的不可逆多数有逻辑保证，但分别运行的 live E4/E5 会重新规划和生成票，不能预设结果相同。已有 E4 前缀 replay 是合理的固定轨迹调度诊断；独立调用的延迟和成本应另行报告，不能把二者混用。

**Held-out 尚未成立。** 当前是正例输入准备，缺乏验证过的成对负例、无泄漏的检测到标签匹配、仓库/advisory 分组不确定性和全链路实测。LangChain 已被开发性检查；若据此修改规则/提示，应生成排除相关仓库/advisory 的新 held-out 清单，保留旧版审计记录。

**测试质量。** 既有测试对 wiring、类型、预算和先前回归有价值，但对“安全程序不应被验证器确认为漏洞”的反例不足。301 passed 不能概括为 offline robust。优先补 R1–R6 的语义负例，比继续增加形状/字段断言更有价值。LangChain 两项测试还依赖 ignored 的本地 checkout/env，在另一台机器可能直接 skip。

**工程维护。** 核心有合理的模块划分；验证工具文件约 1,500 行，旧确定性 experts 也约 1,500 行；新实验脚本大量采用宽泛 dict 与紧凑编码，错误更易藏在状态/账本边界。README 的“预算仅来自 harness”也应与脚本自行选择 byte cap、请求限额的现实分别说明。状态文档仍写 299 tests，handoff 写 301，说明文档口径未完全同步。

## 建议的实施顺序

1. 先阻止错误确认：修 R1–R6；把启发式发现与候选验证的状态/subject 分开，补语义负例。
2. 修复 LangChain 中性身份和 benign 判定，注册受控差分验证工具，完成无标签泄漏的最小评估 runner。
3. 统一所有 API 入口的响应/usage 记录；为有证据支持的暂态错误设计有界重试，每个实际请求都计入预算与账本。
4. 跑小规模配对评估，同时核对预测、typed evidence、负例、失败率与成本。不要只看最终 label。
5. 冻结方法和分割，再开展更大开发矩阵与 held-out。图检索采用增强 BM25 对照，full/fast 分清固定轨迹与独立运行。

目前可以把项目描述为“具有真实 ReAct 与开发评测的漏洞分析研究原型”；不能描述为“验证器已可靠、真实项目漏洞检测已完成验证”或用当前结果支撑泛化提升百分比。
