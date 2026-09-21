# 项目当前状态：full development matrix 后（2026-09-19）

## 后续功能补齐：Python 全仓发现与独立评分

当前源码已在历史 full matrix 之后继续更新。新增 source-only Python repository discovery、
有预算的小规模 E3/E5 运行器、独立输入清单准入和 evaluator-only 精确位置评分；修复了
AST 扫描的注释/字符串误命中、导入别名漏检、嵌套 span 重复以及多行字符串缩进问题。
补齐授权路由候选发现，并改进专家读源码权限、依赖证据隔离、具体证据冲突检查和重复投票检查。

- 新增功能的最终完整离线测试：**452 passed in 20.51s**；harness-check PASS。
- 开发/独立输入 pilot 已完成 **8 + 2 = 10 cells**，均返回判定，66 requests、153,562 tokens；
  它们是流程检查，不是十个已验证正确的分类。随后补齐的动态属性访问和进程控制规则只完成
  离线复核，LangChain 3/3、NLTK 1/1 参考位置均能发现，未追加 API 调用。配置、操作和实际运行记录见
  [Python repository pipeline](PYTHON_REPOSITORY_PIPELINE_2026-09-19.md)。
- 下方 330-cell 结果和原 ten-trial gate 属于上一版源码。它们是保留的历史结果，
  **不能为当前源码自动准入全量实验**，也不能证明新改动已经改善误报率。

## 历史完整开发矩阵

当前是具备真实开发矩阵运行、候选绑定证据和部分执行验证能力的研究原型。它已经完成本轮 330-cell OWASP BenchmarkJava development matrix，但仍不能称为“无 bug 的完整漏洞验证系统”，也不能把 development 结果当成 held-out 或真实项目泛化结论。

最新完整结果见 [Full development matrix result](FULL_DEVELOPMENT_MATRIX_RESULT_2026-09-19.md)。旧状态保存在 `PROJECT_STATUS_BEFORE_DEEP_REVIEW_2026-09-19.md` 等历史文档。

## 最新验收

- 完整离线 pytest：**410 passed in 21.69s**；`cv-agent harness-check` PASS。
- 当前源码/配置的十项真实验收通过：
  `artifacts/development_benchmark/a4643644fd3a40dab01f15cbba68b4ca/`。
  10/10 cells completed，`acceptance.json` 为 `passed: true`、`issues: []`。
- 已完成 330-cell full development matrix：
  `artifacts/development_benchmark/523853f48f434210960ede9948d5cce9/`。
  330/330 cells reached terminal status：319 completed、10 abstained、1 failed。
- 唯一 failed 是 `BenchmarkTest00954/E2` 的 Gemini 上游 `OTHER` 空响应。同一格单独复跑
  `artifacts/development_benchmark/single_rerun_8c3e7b6d399c45c2a9505ea76f30d14d/`
  已 completed，因此记录为 transient upstream failure，不改写正式 full run。
- full run 使用 `gemini-3.8-flash-high(low)`、`max_tokens=6000`、`thinking_mode=disabled`、
  timeout 180s、concurrency 1。2,054 次请求中 native diagnostics 为 2,053 个
  `upstream_response` 和 1 个 `upstream_blocked`；输出上限 2,054/2,054 matched。

## 本轮修复范围

- 实现并接入 Java 命令边界 fixture。固定 cmdi 开发对：`BenchmarkTest00827` 返回
  `SAFE/REFUTED`，`BenchmarkTest02244` 返回 `VULNERABLE/CONFIRMED`。
- ten-trial 和 full runner 共享同一套 registered fixture tools。
- acceptance 复验允许 `local:`/`text:`/`graph:`/`hybrid:` 检索 evidence 作为 initial evidence。
- planner 子任务只暴露对应 expert 的 assigned validator，避免 scan 反复调用不相关 validator。
- planner prompt 改为候选身份和 retrieved-evidence index，避免把完整代码片段放进 planner 首轮上下文。
- planner/expert final JSON 加长度边界，避免 reasoning token 抢占输出预算后截断 JSON。
- live 配置提高到 `max_tokens=6000`、timeout 180s，并将长跑切到 `gemini-3.8-flash-high(low)` 与 concurrency 1。

这些修复没有向实验逻辑加入自动 retry 或 fallback。

## Full matrix 结果摘要

| System | TP | FP | TN | FN | Abstain | Failed | Coverage | Strict recall | Population FPR | Requests |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| E1 | 29 | 15 | 17 | 3 | 2 | 0 | 0.9697 | 0.8788 | 0.4545 | 288 |
| E2 | 27 | 13 | 18 | 5 | 2 | 1 | 0.9545 | 0.8182 | 0.3939 | 288 |
| E3 | 27 | 2 | 31 | 6 | 0 | 0 | 1.0000 | 0.8182 | 0.0606 | 165 |
| E4 | 26 | 5 | 28 | 5 | 2 | 0 | 0.9697 | 0.7879 | 0.1515 | 781 |
| E5 | 26 | 5 | 28 | 3 | 4 | 0 | 0.9394 | 0.7879 | 0.1515 | 532 |

Paired summary：E2→E3 右侧胜 13、左侧胜 1；E3→E4 左侧胜 5、右侧胜 1；E4→E5 双方各胜 2、62 ties。详见 full result 文档和 run 目录中的 `summary.json`。

## 仍需保持的边界

- 这仍是 OWASP BenchmarkJava development matrix，不是 independent held-out result。
- 除固定 cmdi pair 外，其他类别没有对应动态执行 fixture；多数结论是预测或静态/数据流证据，不等价于“已真实利用/已真实修复”。
- 唯一 failed cell 已诊断为 transient upstream block，但正式 full run 仍保留这个 failure，不用单格复跑覆盖主结果。
- 若要扩大动态验证范围，需要为 crypto/hash/ldapi/pathtraver/sqli/xpathi 等类别补对应 validator。
- 当前有效隔离清单为 `configs/vulngym_heldout_inputs_v3.json`；NLTK 已用于修改扫描器，
  因此与 LangChain 一同排除。v3 保留 18 个仓库、173 个 advisory、378 条正例和 156 个源码提交。
  不得把开发样本结果称为独立效果。

## 离线复核命令

```sh
uv run --no-sync pytest
uv run --no-sync cv-agent harness-check
uv run --no-sync python scripts/audit_project_readiness.py
uv run --no-sync python scripts/profile_langchain_scanner_coverage.py
uv run --no-sync python scripts/summarize_live_usage.py
```

实际实验必须经过完整 pytest 和 ten-trial 准入检查；不提供绕过参数。API 密钥只从本地 runtime 环境读取，不写入文档或对话。
