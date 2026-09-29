# 模型提出场景：离线验收与四格实验

本轮完成可复用的场景接口和离线验收。真实模型请求为零。脚本模型提供的正确假设只验证执行、核验与准入协议，不证明模型能自主发现场景，也不支持 held-out 成绩。

## 场景与证明的边界

`WitnessScenarioHypothesis` 包含注入参数、布尔参数、条件与值前提、构造参数、预置文件。每项要求 `value`、`classification` 和非空 `rationale`。分类为攻击者输入、部署配置或环境条件；它声明所需权限，不证明远程攻击者实际拥有这些权限。

原候选 subject 保持不变。模型场景生成单独的执行 subject；完整产物绑定两者、场景来源、场景摘要、真实源码与实际测量。模型不得替换已有数据集场景，不得同时提供未分类的旧补充字段，也不能设置源码、探针、对照、录制器、隔离或判决。

系统仍负责源码与入口匹配、实际输入/开关/构造输入/文件测量、值与分支核验、真实 Popen 身份、preexec、良性对照及 shell 重放。全部义务闭合后才允许附带这些前提的 `CONFIRMED`。错误场景、缺观测和字面量结果保持 `UNRESOLVED`，不输出安全证明。

普通工具和注册有界见证 fixture 都要求分类记录。旧数据集 subject 需由可信执行上下文提供 `dataset_scenario`；该记录必须精确描述原前提，不自动补构造数据。无分类的旧调用拒绝执行。独立低层诊断仍可读取历史人工清单，但不能通过这些公开适配器提供未分类的候选确认。

模型收到所有前提的值与分类及完整核验摘要；理由、两个完整 subject 和原始事件保存在私有产物中。较大的值使用明确标注的内容摘要，避免重复完整输入。模型可见源码帧使用仓库相对路径；目标 checkout、commit 路径和完整身份仍保存在产物中。原有观察预算与证据准入规则保持。

## 离线结果

独立的改名 fixture 使用 `LaunchPad.dispatch(location, activated)`、不同配置常量和 `widget launch` 命令，涵盖必要文件、正确场景、错误开关/条件/参数/文件、六处缺分类、缺理由、转义对照及标签扰动。17 项控制通过实际工具和脚本工作流，正例确认，反例未确认。

真实 hp003 两个快照在构造输入前删除四组场景字段；检索与提示只保留入口和披露过来源的 advisory 摘要，移除旧标题中的 `enable_mlserver=True` 注释及人工汇点标记。脚本通过标准工具调用提出完整分类假设。

| 开发快照 | 标准工作流判决 | 工具状态 | 原始观测 |
| --- | --- | --- | --- |
| hp003_a | VULNERABLE | CONFIRMED | EXPANDED_OBSERVED |
| hp003_b | ABSTAIN | UNRESOLVED | LITERAL_OBSERVED |

两版原 subject 的四组场景字段均为空；各自 977 个源码文件摘要在运行后重新核验，checkout 保持干净。两版共用同一具体探针与良性输入，值、分支、源码、进程及 preexec 义务全部闭合。最终模型可见内容分别 4,681 / 4,693 字节，无截断或抑制。每版三次脚本响应、一次准备和一次实际见证；真实模型请求与 reported token usage 均为零。

初次真实对照的执行本身得到相同原始观测，但 9,247 字节的重复记录超过标准交付预算，准入诚实弃权。该中间运行和失败审计记录保留在 `artifacts/witness_scenario_development_2026_09_29/paired/`；最终验收在新的 `paired_entry_only/`，未覆盖原始产物。注册 fixture 入口的相同交付问题也使用同一报告函数解决；没有增加预算。

最终完整 `uv run --no-sync pytest`：**2351 passed in 242.57s**；harness **PASS**，`git diff --check` 通过。完整日志保存在本地 `artifacts/witness_scenario_development_2026_09_29/full_pytest_final.log`。首次全量的三项文档布局/链接失败及修后检查记录也保留。最终机器核对的可版本化摘要在 [见证审计](../../.hermes/plans/2026-09-29-witness-scenarios-audit.json)，包括相同具体输入和两版完整证据。新分类要求的回归先复现未分类确认，再迁移既有正例的分类上下文；原语义断言保留。工具定义摘要只因场景 schema 和说明而改变，原候选身份与 planner 摘要保持。

## 待授权的真实模型实验

[witness_scenario_2x2.json](../../configs/experiments/witness_scenario_2x2.json) 声明 hp003_a/b × A/B 共四格，用户后续授权改为固定 E1 和 `deepseek-flash`，串行执行，共享最多 60 次实际请求及 3,600 秒预算。A 保留数据集前提并附完整可信分类；B 的 subject、检索和提示均不带场景标注，由真实模型提出假设。两条件的入口与 advisory 文本一致，人工汇点标记均不提供。阶段 0 的追加控制与新验收记录见 [阶段 0](../../.hermes/plans/2026-09-29-phase0-results.md)。

请求通过 `OpenAICompatibleChatModel` 和其当前源码完整 pytest 门禁。每个实际请求与原始响应、解析失败、provider reported usage 都进入逐请求日志。失败停止批次，无重试或替代模型。来源、见证状态、最终选票、失败和用量按 A/B 分开报告；不汇总成检出率，也不以最终选票失败掩盖已经完成的见证观察。

默认命令仅验证配置并输出准备记录，不读取 API 凭据或执行模型/目标：

```bash
uv run --no-sync python -m cv_agent.evaluation.runners.run_witness_scenario_matrix
```

后续执行计划已授权本配置及阶段预算，启动 `--live` 仍须工作树干净并通过新进程的完整 pytest 门禁。最初接口验收没有真实模型调用；实际阶段结果另行登记。

## 泛化阶段的停止边界

本接口消除了必须由数据集先写场景这一依赖，没有增加新的框架专用语义。当前执行器仍支持绑定的类方法入口、调用方提供已有本地目录的 shell 见证；它不证明远程可达，也不自动提供任意仓库的入口、依赖环境或任意漏洞类别的执行探针。

真实 B 结果尚未获得。第 3 步先等待 B 的自主场景发现结果，再对新的开发样本按无场景标注方式运行。仅有 repository_url/commit 的 held-out 端到端输入还要求独立的候选发现与执行环境准备；本次带入口和 advisory 的开发控制不能替代这项验证，所有产物继续 `claim_eligible=false`。
