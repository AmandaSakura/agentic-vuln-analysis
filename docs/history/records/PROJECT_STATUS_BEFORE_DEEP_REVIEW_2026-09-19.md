# 项目当前状态（2026-09-19，整体复查后）

项目是已跑通小规模真实评估的漏洞分析研究原型，尚未完成全仓自动发现及独立测试集验证。
本页是当前口径；旧版状态保存在 `PROJECT_STATUS_BEFORE_CURRENT_REVIEW_2026-09-19.md`。

**最新十项验收：未通过，未推全量。** 并发 2，10 项耗时 169 秒：7 项标签匹配、1 项弃权、
2 项上游 OTHER 拦截；验证状态仍为 UNRESOLVED。56 次请求，修正并发用量重复统计后为
296,132 tokens；修复后完整 pytest **380 passed in 10.24s**。
详见 [十项试验及后续方案](TEN_TRIAL_PROTOCOL_2026-09-19.md)，其中离线更正报告取代原用量汇总。

**实验已按用户要求停止：** 开发矩阵运行约 19.7 分钟，44 项弃权、1 项中断、285 项未运行；
331 次请求、619,489 个已上报 token，1 次中断请求用量未知。进程已退出，未重启。

**实验启动记录：** 修复后的真实配对运行 `615ca84226fd4c08b701575dc54dcb6e`
两侧均完成，6 次请求、15,698 tokens。完整 330 项开发矩阵已启动，运行目录
`artifacts/development_benchmark/87818baabbba4552b31c02af055ac938/`；启动门禁
377 项通过，已记录真实请求和首个试验结果。详见 [启动记录](EXPERIMENT_START_2026-09-19.md)。
下方“尚未重新实测”的描述属于启动前状态，以本更新及运行产物为准。

## 当前验证结果

- 最新完整离线测试：**377 passed in 9.64s**；Harness 契约检查 PASS。
- 后续 bug 修复：生成器调用不再被当成函数体已经执行；新增 4 个误确认回归用例和 2 个正向控制，详见修复报告 R7。
- 最新成功的真实 E1 配对实验：`artifacts/langchain_agent_eval/b24820ebdb2848f1a1854f01bf89db6a/`。
  漏洞侧 `VULNERABLE / CONFIRMED`，修复侧 `SAFE / REFUTED`；6 次请求、15,769 个上报 token，
  六条原始响应均已自动关联。本次成功发生在整体复查修复之前，保留其当时源码和提示词证据。
- 整体复查发现并修复两个 Python 探针错误确认，以及分析范围传递、测试集隔离、覆盖率报告和
  代理拦截分类的问题。详见 [本轮审查与修复](CURRENT_REVIEW_RESULT_2026-09-19.md)。
- 本轮修复没有模型 API 调用。更新后的模型可见范围已通过离线 Agent 流程验证，尚未做新一轮真实模型评估。

## 已具备的能力

- 模型/工具 ReAct 循环、LangGraph 规划与 E1–E5 调度、证据归属检查、预算和失败记录。
- 静态线索与具体验证分离；不支持的语义保留 `UNRESOLVED`，不能据无发现证明安全。
- LangChain 真实配对前置检查和候选绑定 fixture；正常控制、属性遍历、dunder 遍历均有真实差分证据。
- 本机代理日志自动关联、明确拦截原因分类、失败用量保留；共享运行器要求完整 pytest 门禁。
- 明确的 `analysis_scope` 进入模型上下文并计入预算，同时绑定验证证据；检索 query 和评估 metadata 保持私有。

## 尚未解决的缺口

1. **全仓自动发现**：扫描器仍只有三条静态规则，不能命中本例模板格式化 sink。
   本轮重新分析两个真实 checkout，各产生 7 个候选，精确参考 sink 命中均为 0。
   预设入口的 E1 配对结果不能当作全仓召回率。
2. **完整开发评估**：66 个 OWASP 案例 × E1–E5 的 330 个计划试验未完成。
   既有小样本检索和多专家结果仍属于探索性开发证据，不支持总体提升百分比。
3. **独立评估**：当前有效准备清单为 `configs/vulngym_heldout_inputs_v2.json`，
   含 19 个仓库、174 个 advisory、379 条正例记录、157 个源码提交；尚无 held-out 模型评估，
   独立验证的配对修复负例为 0。原 v1 清单包含开发使用过的 LangChain，不能继续作为有效独立划分。
4. **服务稳定性及输出预算**：已捕获过真实上游过滤拦截，但未修复 Google 端的间歇性行为。
   当前代理会删除 Gemini 请求的 `maxOutputTokens`，客户端配置值不是已执行的上游输出限制。
5. **分析边界**：Python probe 是受限函数切片解释器；静态图和数据流有近似及不支持的语义。
   当前测试覆盖的行为通过不等于所有代码正确，也不等于任意项目漏洞都能检测。

## 下一阶段顺序

1. 对自动候选生成增加经过正反例验证的语义覆盖，并继续把候选发现与漏洞确认分开。
2. 冻结方法、模型、检索强基线和有效数据划分，再做有界开发实验。
3. 补独立配对负例和检测到参考标签的匹配，再开展按仓库/advisory 分组的 held-out 评估。

不得用历史失败的反复重跑替代稳定性验证，不得把既有 oracle 入口实验改称自动发现。

## 复核入口

```sh
uv run --no-sync pytest
uv run --no-sync cv-agent harness-check
uv run --no-sync python scripts/profile_langchain_scanner_coverage.py
uv run --no-sync python scripts/summarize_live_usage.py
```

以上命令不调用模型。v2 划分已冻结；`scripts/prepare_heldout_inputs.py` 再次运行会拒绝覆盖。
历史实验细节见 `LANGCHAIN_AGENT_RESULT_2026-09-19.md`、`DEVELOPMENT_PILOT_2026-09-19.md`，
代理诊断见 `PROXY_LOGGING_INTEGRATION_2026-09-19.md`。旧实验和旧测试数量属于当时版本，不能替代当前验收。
