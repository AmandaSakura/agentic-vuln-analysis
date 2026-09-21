# 代码审查修复验收（2026-09-20）

本轮修复 `CODE_REVIEW_2026-09-20.md` 的六组问题，新增 **55 项回归与正反对照**。先记录失败，再修改实现；未放宽历史实验标签、未重写历史产物、未调用模型 API。

## 修复结果

| 审查问题 | 当前行为 | 实现位置 |
| --- | --- | --- |
| 权限伪确认 | try/循环等未支持路径、短路未执行调用、局部 os 绑定及别名属性修改不再产生确认；直接可达的 0o777/0o750 正反控制仍成立 | `src/cv_agent/validation_tools.py` |
| helper 返回值不准确 | 赋值覆盖、别名、有限字面量循环按执行顺序处理；return 后停止；只分析实际返回值，未知路径不保留旧 SANITIZED 状态 | `src/cv_agent/command_analysis.py` |
| 调用方与 sink 脱节 | 将实际实参绑定到 helper，跟踪返回值、解包和调用方后续修改，最终检查传给 shell 的参数；普通 argv 不当成 shell 字符串 | 同上 |
| shell 引号上下文丢失 | 保留常量及插值片段；仅在普通 shell 参数词元位置认可 quote；双引号包裹、格式转换、动态命令名和二次 shell 解释为 AMBIGUOUS | 同上 |
| 反证引用导致硬性否决 | 区分支持、反对、未决引用；披露静态反证不再触发支持证据检查；反证也不能被挪作 SAFE 或具体验证的支持证据 | `src/cv_agent/react_engine.py` |
| 结果保存丢行 | 计划外行保留并标记，验收在保存前后得到相同异常；summary 单列额外行；重复单元不再撑大分母或按覆盖顺序决定指标 | `scripts/run_python_heldout_pair_matrix.py` |

额外覆盖了未知调用或异常表达式导致权限路径终止、嵌套定义默认参数执行、异步 helper 未 await、引用角色对污点/静态检查的影响，以及实际常量/转义实参传入 helper 的行为。

原命令工具测试中的 caller 也已修正为传递 helper 所声明的参数；此前部分追加内容的样例声明了 suffix/replacement，但 caller 没有传递它们。现在正反控制具有合法调用关系，原有预期未被放宽。

## 验证

- 修复前首批新回归：**27 failed, 10 passed**。后续补充边界也先分别记录失败，再修复。
- 最终完整测试：`uv run --no-sync pytest` → **615 passed in 22.54s**。
- `uv run --no-sync cv-agent harness-check` → **PASS**。
- `git diff --check` → 通过。
- 模型 API 请求：**0**。

复跑原审查脚本后的新证据：

- [完整工具结果和执行对照](../../../artifacts/code_review_20260920_g6p44cr_/offline_reproductions.json)
- [复跑脚本](../../../artifacts/code_review_20260920_g6p44cr_/reproduce.py)
- [本轮相关源码哈希](../../../artifacts/code_review_20260920_g6p44cr_/source_sha256.txt)

主要反例的当前结果：

| 反例 | 修复前 | 修复后 |
| --- | --- | --- |
| try-return、短路未执行、调用前局部绑定失效 | CONFIRMED | UNRESOLVED |
| 循环追加原始输入 | SANITIZED | UNSANITIZED |
| return 后不可达赋值、已覆盖的旧原始值 | UNSANITIZED | SANITIZED |
| caller 追加原始输入 | SANITIZED | UNSANITIZED |
| quote 外再包双引号 | SANITIZED | AMBIGUOUS，不能作为 SAFE 的肯定支持 |
| 将静态反证列入 counter 引用 | 拒绝结论 | 允许有独立支持证据的结论 |
| 30 条计划行加 1 条额外行 | 保存为 30 条 | 保存为 31 条，额外行仍被验收拒绝 |

## 支持范围

这是明确限定语义的静态分析，不是任意 Python 程序或 shell 的安全性证明。命令解释器支持直线赋值、常量分支、最多 16 个元素的字面量循环，并有语句和调用深度上限；动态分支、未知调用/变换、属性或容器修改等未支持结构返回不确定结果。普通 argv 与已支持的 POSIX shell 调用分开处理，未知 shell 配置保持不确定。

权限结果仅验证受支持候选路径中的字面量模式序列，不证明跨进程竞态可利用性。命令工具始终保持 `validation_status=UNRESOLVED`，不会把静态字符串分析升级为具体漏洞确认。

这些修复可能使此前过度确定的真实样本变为弃权，需要在下一次不超过 10 项的版本化 gate 中如实观察。当前完成的是代码修复与离线验收；没有据此宣称真实模型实验已通过。
