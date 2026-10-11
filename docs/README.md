# 文档导航

日常阅读只需要这里的四份说明。源码入口和安装方式见 [项目 README](../README.md)。

| 想了解什么 | 文档 |
| --- | --- |
| 项目完成程度、最近结果、已知问题 | [当前状态](CURRENT_STATUS.md) |
| 核心代码在哪里、各层负责什么 | [架构与阅读路线](ARCHITECTURE.md) |
| 怎样运行、配置、统计和解释实验 | [实验指南](EXPERIMENTS.md) |
| 修改代码与证据逻辑必须满足什么 | [测试契约](TEST_CONTRACT.md) |

## 10 月 1 日恢复反馈与当前实现

[恢复反馈 PDF](reports/cv_agent_design_review_and_recovery_2026-10-01.pdf) 的 31 页已逐页核对。显式 v2 的实现、安装、有限支持范围和逐项验收见 [产品指南](reference/PRODUCT_REVIEW.md)、[恢复核验](../audit/product_recovery_20261001/verification.md) 及 [F/R/V 矩阵](../audit/product_recovery_20261001/acceptance.json)。默认仍为 v1；真实用户任务与人工净收益尚未测量。

## 恢复前技术报告（2026-10-01）

[完整技术报告 PDF](reports/cv_agent_technical_report_2026-10-01.pdf) 和 [LaTeX 源码与构建说明](reports/cv_agent_technical_report_2026-10-01/README.md) 保留恢复前的离线静态 v1 产品、研究架构、证据与身份逻辑、任务和预算、历史用量及当时验收边界。该 PDF 未覆盖之后的 v2 恢复改动，不能作为当前发行物的验收回执；原文件及图表完整保留。

## 修复前技术报告（2026-09-30）

[完整技术报告 PDF](reports/cv_agent_technical_report_2026-09-30.pdf) 和 [LaTeX 源码](reports/cv_agent_technical_report_2026-09-30.tex) 记录修复前 `4dba622` 基线的架构、数据模型、检索、任务调度、证据准入、执行见证与验收结果。用户随后提供的 [设计审查 PDF](reports/cv_agent_design_review_and_repair_plan_2026-09-30.pdf) 已按实际源码完成启用静态范围的核验与修复；修后产品入口及逐项验收以 [产品指南](reference/PRODUCT_REVIEW.md) 和其审计记录为准，原 G-A 保持 NO。

## 参考设计

- [离线产品审查入口](reference/PRODUCT_REVIEW.md)：无需模型的本地 Python 审查、性质状态、能力预检、预算、显式上下文和产物。

- [模型提出场景的见证接口](reference/MODEL_PROPOSED_WITNESS_SCENARIOS.md)：分类前提、离线正反控与待授权的 A/B 四格实验。
- [完整流程与当前问题定位](reference/PROJECT_FLOW_AND_DIAGNOSIS.md)：当前入口、E1–E5、Jev、证据链和最新全矩阵的逐环节分析。
- [Jev 接入计划](reference/JEV_IMPLEMENTATION_PLAN.md)：类型化规划分流与离线验证。
- [Jev 配置与运行](reference/JEV_ROUTING.md)：填写密钥、执行 6 项开发对照、理解分流与成本记录。
- [hp003 Jev active 对照计划](reference/HP003_JEV_ACTIVE_PLAN.md)：四项实验的接线、验证和采用情况审计。

- [Harness 说明](reference/HARNESS.md)：主要解释早期确定性 V 系列约束；当前 E 系列的实际预算、策略和协议以 `src/cv_agent/harness/` 与运行配置为准。
- [完整系统目标规格](reference/FULL_SYSTEM_SPEC.md)：记录设计目标，不能据此认为所有要求已实现或验证。当前完成程度以本目录的状态说明为准。

## 历史资料

[历史索引](history/README.md) 收纳旧审查、实验结果、交接、重构记录、执行计划和补丁。正文保留，迁移时只调整相对链接。历史文中的代码路径、命令、测试数量和“当前/最新”均描述写作时的状态。

```text
docs/
├── README.md             # 从这里开始
├── CURRENT_STATUS.md     # 当前状态
├── ARCHITECTURE.md       # 代码结构
├── EXPERIMENTS.md        # 实验操作与解释
├── TEST_CONTRACT.md      # 修改与验证规则
├── reference/            # 参考设计
├── reports/              # LaTeX 技术报告和用户提供的审查 PDF
└── history/
    ├── README.md         # 历史索引
    ├── records/          # 审查、结果和交接记录
    ├── plans/            # 历史执行计划
    └── patches/          # 历史外部组件补丁
```
