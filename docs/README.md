# 文档导航

日常阅读只需要这里的四份说明。源码入口和安装方式见 [项目 README](../README.md)。

| 想了解什么 | 文档 |
| --- | --- |
| 项目完成程度、最近结果、已知问题 | [当前状态](CURRENT_STATUS.md) |
| 核心代码在哪里、各层负责什么 | [架构与阅读路线](ARCHITECTURE.md) |
| 怎样运行、配置、统计和解释实验 | [实验指南](EXPERIMENTS.md) |
| 修改代码与证据逻辑必须满足什么 | [测试契约](TEST_CONTRACT.md) |

## 参考设计

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
└── history/
    ├── README.md         # 历史索引
    ├── records/          # 审查、结果和交接记录
    ├── plans/            # 历史执行计划
    └── patches/          # 历史外部组件补丁
```
