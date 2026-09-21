# 项目进度与实测结果（2026-09-19）

项目已从四个手写用例的演示，推进到有固定数据清单、真实 API 对照、工具证据和失败记录的开发评测。完整研究验证尚未完成：330 个开发试验未全跑，独立真实项目测试集未执行，也没有经过验证的修复版负例。

## 审查后的测试契约与修复

- 新增 `AGENTS.md` 与 `docs/TEST_CONTRACT.md`，约束候选证据、静态分析、数据分割、预算与离线测试边界；修复方案位于 `docs/superpowers/plans/2026-09-19-test-contract-and-repair.md`。
- 真实模型入口先执行完整 pytest；失败或当前进程启动后源码/配置/测试改变时禁止调用。原始响应诊断也走同一入口，无旁路和自动重试。
- 新增语义反例覆盖不可达 eval、安全 argv、字典 update、常量重构、外部同名误连、模块/导入重绑定、跨候选证据、异常 usage、门禁失效和差分正常控制错误。
- 静态污点、guard、源码差分工具不再返回漏洞确认；仍保留可检查的 flow/guard/diff 事实。真实 bounded input probe 正例继续确认，并绑定候选和源码摘要。
- LangChain detector ID 改为中性名称，checkout 路径为 runner-private；严格检查正常输出和预期阻断原因，并限制子进程时间、拒绝脏 checkout。
- 本轮没有真实 API 请求。历史记录保持原样；其中旧静态工具的 `CONFIRMED` 不能用作当前语义下的确认统计。
- LangChain Agent runner 和已绑定的真实配对验证工具仍未接入；修复配置不等于完成端到端评估。

## 已修复

- 结果标签是字符串，移除错误的 `.value` 访问；接收完整 JSON 代码围栏，专家身份校验进入纠错循环。
- 明确区分模型预测与验证器证据。`SAFE` 预测不能自动变成已证伪，静态工具无发现不能作为安全证明；证据不足保留 `ABSTAIN/UNRESOLVED`。
- 在既有八步上限内预留最终输出步骤，避免不断调用工具却不交付结果。仍然拒绝缺失必要验证器或伪造证据的结论。
- Python probe 绑定候选入口，防止从检索到的内部函数起跑、绕过入口检查与参数绑定。
- 修正 Python/Java/JavaScript 候选行号；支持 JS 文档 ID 的字节偏移后缀。
- 每次模型请求、工具调用、失败和结果即时落盘。失败消耗不再记成零；空响应中提供的 usage 也计入账本。
- 恢复三个开发源码目录损坏的 Git 元数据，保持原源码不变，核实精确提交及干净工作区。旧指针已本地备份。

## 数据与检索

- 冻结 OWASP BenchmarkJava 的 **66 个案例**：11 类，每类 3 正例、3 负例；E1–E5 共 **330 个计划试验**。模型不接收参考标签。
- 离线检查发现原文本检索在 66 个案例中均未保留直接调用目标；图检索全部保留。这提示原文本基线过弱。
- 新增显式命名的源码元信息 BM25 基线，结合源码路径与定义信息；在同一检查中也保留 66/66 的直接调用目标。这衡量上下文保留，不是漏洞正确率。
- 三个真实开发仓库共解析 **2,489 个支持格式文件**，无报告的解析错误。静态扫描输出 328 个候选，包含测试与生成代码；候选数不代表漏洞数。
- VulnGym 预备清单排除开发仓库及共享 advisory，得到 **20 个仓库、175 个 advisory、382 条正例记录、158 个源码提交**。探测端只收到仓库与提交；参考位置单独留给评估端。**已验证修复负例为 0，未执行 held-out 模型评测。**

## 已完成的真实 API 小批次

| 批次 | 完成情况 | 能支持的结论 |
| --- | --- | --- |
| 四类 OWASP 正负例，共 8 案例 × 2 检索变体 | 16/16 完成；文本 7/8，图 8/8；58 次请求 | 两组共享 BM25、源码元信息及预算；图组少错一个 SQL 负例，仅是探索性开发结果 |
| 两个 Python 手写案例 × E3/E4/E5 | 6/6 完成；55 次请求 | 有漏洞案例收到 typed validator 的 CONFIRMED；安全案例仍 UNRESOLVED，不能说已证明安全 |
| 命令注入正负例 × E3/E4/E5 | 5/6 完成；56 次请求 | 一个 E5 试验遇到空 choices；单独后续批次该正例完成（12 次请求），不覆盖原失败 |
| 三个真实仓库各一候选 × E3/E4 | 3/6 完成；36 次请求 | Google 的两组、jlowin 的 E4 完成；Prefect 两组和 jlowin E3 失败。没有真值标签，不计算准确率 |
| 省略 thinking 参数的真实源码复查 | 1/4 完成；31 次请求 | 只有 jlowin E4 完成；其余三组仍有空 choices，参数调整未解决稳定性问题 |

四类对照的所有票仍为 `UNRESOLVED`：上表 7/8 与 8/8 是预测标签对照参考标签，不能解读为 15 次漏洞复现。样本只有八个，不能支持总体提升、跨仓库泛化或简历中的历史提升百分比。

E4 的已记录执行前缀可以离线重放 E5 提前停止规则，并核对标签与省去的后续请求。这是固定轨迹下的反事实调度比较，不等于独立运行 E5 的实际延迟或成本；报告中分别记录。

## 仍存在的 API 问题

本地代理返回的模型 ID 为 `gemini-3.8-flash`，请求使用别名 `gemini-3.8-flash-high`。部分请求返回 usage，但 `choices` 为空，实际完成 token 全部或部分为 reasoning。

四次固定首请求诊断中，传 `thinking: disabled` 的两次失败，省略参数的两次成功。但独立完整复查中，省略参数仍出现空响应，**不能把该参数当成已确认根因或修复**。两种配置及失败轨迹均保留，没有自动重试、暗中切换模型或将错误转成安全结论。继续扩大真实项目调用前，应先解决这一服务兼容性问题。

## 产物定位

以下路径均相对于项目根目录；完整原始轨迹在各运行目录的 `events.jsonl`，配置与源码快照位于同目录。历史产物保留当时行为，不因后续修复被覆盖。

- 四类对照：`artifacts/retrieval_validation_matrix/a8b023219f2c401aad4ac032136e3809/`
- Python 工具证据：`artifacts/python_evidence_check/1f93076e43564a038df80f99998def2a/`
- E3/E4/E5 图检索试跑：`artifacts/development_benchmark/76dc1343e5f14d1fa157e290e1662847/`
- E5 独立后续试跑：`artifacts/development_benchmark/80f6a8c4661e4d479f0ae8dd12af68b7/`
- 真实源码原配置：`artifacts/real_source_smoke/d1891dbaa76244d7a4dc76888c9e4dbc/`
- 真实源码省略 thinking 的独立复查：`artifacts/real_source_smoke/dbe2396af5074336b5942a10e9cd3a0e/`
- 四次传输诊断：`artifacts/transport_probe/57023a997a8f42c88f8d2b95449fc7d6/`
- 传输 Token 限制探测：`artifacts/transport_token_probe/00c658ca7df6425ab8669f6059045b4b/`
- 真实源码离线解析：`artifacts/development_source_profile/65819d7726274bbba731e7d29004b99f/summary.json`
- 检索保留审计：`artifacts/development_context_audit_with_bm25.json`
- 独立测试集准备：`configs/vulngym_heldout_inputs.json` 与 `artifacts/vulngym_heldout_preparation/`
- 请求与 token 汇总：`artifacts/live_usage_audit.json`；包含历史失败及诊断，不能作为单个算法的成本。服务计价未知，金额留空，未上报 usage 的请求单列。

原六类目录累计 361 次请求、1,367,529 个已上报 token。审查后把遗漏的原始代理诊断加入总账，合计 **362 次请求、1,371,526 个已上报 token**，仍有 1 次 usage 缺失；这次修复没有新增 API 消耗。汇总器同时支持未来 micro-benchmark 和 journaled raw diagnostic，避免 raw 文件与 journal 双重计费。

## 验证与复现

在 `/home/joker/AAA_NUS_SEM2/cv_agent` 中执行：

```sh
uv run --no-sync pytest
uv run --no-sync python scripts/inspect_development_context.py
uv run --no-sync python scripts/profile_development_sources.py
uv run --no-sync python scripts/summarize_live_usage.py
```

完整验收结果见 `docs/TEST_REPAIR_RESULT_2026-09-19.md`。上述命令均不调用模型 API；301 passed 是修复前的基线，不能作为修复后代码的准入凭据。

要复跑有界四类对照，先加载已有本地凭据，再单独运行：

```sh
source /home/joker/.config/cliproxyapi/client.env
export ANTIGRAVITY_API_KEY="$OPENAI_API_KEY"
uv run --no-sync python scripts/run_retrieval_validation_matrix.py
```

该配置上限 80 次请求、1,200 秒准入时间，输出到新的独立目录。未默认启动 330 试验全量矩阵。下一阶段应依次完成 API 稳定性诊断、独立验证修复负例、标签无泄漏的真实项目候选匹配，以及按仓库/advisory 分组的评估。
