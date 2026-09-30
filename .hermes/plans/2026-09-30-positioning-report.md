# 有界执行见证的定位报告（G-A = NO 之后）

[G-A 正式判定](2026-09-30-G-A-decision.md) 为 NO。按 [剩余架构](2026-09-29-remaining-architecture.md) §4，K5–K8 不启动。本报告根据已记录的实测结果，给出现有见证能力的定位、使用前提和扩展代价。所有结果都是 `dataset_role=development`、`claim_eligible=false`。

## 1. 定位

`run_bounded_execution_witness` 定位为**对少量已选定候选做有界确认的工具**，不作为"从仓库加提交号自动检测"的主干。

- **它能回答的问题**：在一组给定的、已分类的场景前提下，这个具体候选的真实代码能否把受控输入作为 shell 语法交给命令边界。
- **它的输出只有两种**：`CONFIRMED`，或带具体缺口的 `UNRESOLVED`。字面量观测（`LITERAL_OBSERVED`）不产生 SAFE，也不产生 REFUTED。
- **场景由谁提供**：本轮验证过的做法是由数据集或开发者提供分类场景。由模型自主提出场景，在本轮真实运行里没有成功过（见 §4）。

## 2. 已验证的能力

| 能力 | 证据 | 记录 |
| --- | --- | --- |
| 给定场景下的候选级确认 | hp003_a 为 `CONFIRMED / EXPANDED_OBSERVED`，hp003_b 为 `UNRESOLVED / LITERAL_OBSERVED`；977 项源码绑定、九项运行时义务、良性对照全部闭合。2c、K1、K3、K2 之后多次复现，结果一致 | [2c](2026-09-28-witness-stage2c-results.md)、[K1](2026-09-29-k1-results.md)、[K3](2026-09-30-K3-results.md)、[K2](2026-09-30-K2-results.md) |
| 系统生成调用清单 | 入口、参数、前提和源码库存由系统从源码生成；外部只补缺失的构造参数和文件 | [第 1 步](2026-09-29-witness-system-step1-results.md) |
| 接入多专家工作流 | E4 中 scan 和 taint 两张实质票引用同一次确认见证，记为共享票 2、独立观察 1；b 侧 ABSTAIN | [K4](2026-09-30-K4-results.md) |
| 修复版侧的可靠性 | M0 和 E-iter 的全部真实 b 格：没有 SAFE、没有 producer CONFIRMED、没有已准入的 VULNERABLE | [收尾报告](2026-09-30-remaining-work-final-report.md) |
| 环境可复现 | 从零重建两套 Python 3.12 环境：141 个包的版本、977 项源码绑定与旧环境逐项相同；只读准入仍为原来的 4 个叶子文件 | [K3](2026-09-30-K3-results.md) |
| 运行时分层 | 见证运行时迁到 `runtime/witness/`，核心包不再导入 evaluation 层；迁移前后两个快照的绑定字段全部相同 | [K2](2026-09-30-K2-results.md) |

## 3. 使用前提

同时满足以下条件时，这个工具才有可能给出 `CONFIRMED`：

1. 候选性质是 `command-execution`，sink 是进程创建，并且捕获到的 argv 属于已识别的 shell 形状。
2. 入口可以直接调用：普通函数、方法，或按精确绑定调用的 Click callback。公开 CLI 解析器不在覆盖范围内。
3. 目标环境能在 hash 锁定下构建。目标包只装 dist-info、从 checkout 导入；需要从源码编译的原生扩展不在覆盖范围内。
4. 到达 sink 之前的执行路径不需要可写的临时目录。当前隔离策略拒绝一切文件系统写入。
5. 有一份带分类的场景：注入参数、开关、条件和值前提、构造数据、预置文件。
6. 资源配置按实测基线推导；只读准入只放行单个叶子文件，并逐条写明理由。

## 4. 扩展代价（按实测证据）

| 代价 | 实测现象 | 记录 |
| --- | --- | --- |
| 模型自主选择场景 | M0 B-a：阶段 1 为 F1（没有执行见证），阶段 2 为 F3（选了 `enable_mlserver=false`，走 scoring_server 分支）。E-iter 的 hp003 两格又一次走了同一分支；模型拿到 UNRESOLVED 后也没有换一个场景再试 | [阶段 1](2026-09-29-phase1-results.md)、[阶段 2](2026-09-29-phase2-results.md)、[E-iter](2026-09-30-E-iter-results.md) |
| 隔离下的临时目录 | 3a 和 E-iter 的 entry-00390 两格都在 MLflow TempDir 创建时失败（`No usable temporary directory`），没有走到进程边界，属于 F4 | [3a](2026-09-30-phase3a-offline-results.md) |
| 原生扩展环境 | 3b 冻结的 15 条公告里，唯一符合源码标准的候选（Pillow）在受限导入预检中缺少对应版本的 native `_imaging`，合格外部样本对为 0 | [3b](2026-09-29-phase3b-results.md) |
| 入口可达性 | Click 入口只能直接调用 callback，公开解析器的输入转换和调用权限都没有被证明 | [3a](2026-09-30-phase3a-offline-results.md) |
| 调用权限的范围 | 所有 CONFIRMED 的前提都是"本地调用者能提供一个已存在的目录名"；远程调用权限从未建立 | [收尾报告](2026-09-30-remaining-work-final-report.md) |
| 运行成本 | 每次配对见证墙钟约 15–16 秒，每个 worker 约 8 秒 CPU，RSS 峰值约 170 MiB；每个目标需要一套独立 venv（hp003 为 141 个包）；每个真实模型格子约 6–8 次请求、3.6–5.2 万 reported tokens | [2c](2026-09-28-witness-stage2c-results.md)、[E-iter](2026-09-30-E-iter-results.md) |

## 5. 不能得出的结论

- 不能说系统能从"仓库加提交号"或只凭 advisory 摘要自主检出漏洞。
- 不能报告 held-out 上的召回率或误报率。VulnGym v4 在命令注入等方面已不是盲测，见 [架构方披露](2026-09-30-architect-exposure-disclosure.md)。
- 不能说修复版整体安全，也不能说远程命令注入已被证实。
- 不能把 developer_scripted 的确认计入真实模型的成功率，也不能用 E-iter 改写 G-A。

## 6. 若要重新启动扩展（需用户决定并重新登记）

以下每一项都需要新的预登记，也不会追溯改变 G-A：

1. **隔离内的私有临时目录**：在运行时根目录下提供一个只属于 worker 的可写目录，写入范围固定并记录在产物里。这是通用的隔离改动，要有正反控，确保其他位置仍然不可写。
2. **原生扩展的源码构建**：扩展 K3 的环境准备，允许在隔离外按 hash 锁定编译目标自身的原生扩展，并记录构建产物的身份。
3. **场景提出研究**：在更大的观察预算下，或换用其他模型，研究模型能否在拿到 UNRESOLVED 之后改提第二个场景。需要先登记重复次数和成功标准。
4. **新鲜评测集（K8）**：只在前面的扩展有正面结果之后才值得做；样本冻结日期、选样脚本和样本量需要用户签字。
