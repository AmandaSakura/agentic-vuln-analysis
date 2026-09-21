# 最近修复的代码审查（2026-09-20）

**后续状态：** 本报告六组问题现已修复，并新增 55 项回归与正反对照；完整测试为 **615 passed in 22.54s**。原反例已复跑，具体行为、支持范围和证据见 [修复验收记录](CODE_REVIEW_FIX_2026-09-20.md)。下文保留修复前审查内容，位置指向当时版本。

审查范围：`validation_tools.py` 的权限与命令构造分析、`react_engine.py` 的证据裁决、held-out pair 的验收与结果保存。没有对整个仓库作无缺陷保证。

结论：上一轮修复处理了原有回归样例，但仍有六组已离线复现的问题；暂不建议据此推全实验。这些反例暴露实现缺陷，不代表已经证明历史实验中的具体标签错误。

本次现有完整测试为 **560 passed in 25.26s**，`harness-check` 为 **PASS**，`git diff --check` 通过。下面的十个失败场景不在现有回归覆盖内；现有测试通过不能覆盖它们。本次仅新增审查报告和诊断产物，没有修改生产实现或原有测试，没有模型 API 调用。

证据目录：[`artifacts/code_review_20260920_h0m169a9`](../artifacts/code_review_20260920_h0m169a9/)。

- [完整输入、工具输出、实际执行结果和裁决结果](../artifacts/code_review_20260920_h0m169a9/offline_reproductions.json)
- [可复跑诊断脚本](../artifacts/code_review_20260920_h0m169a9/reproduce.py)

在项目根目录执行：

```bash
uv run --no-sync python artifacts/code_review_20260920_h0m169a9/reproduce.py
```

诊断只执行自有合成函数。权限操作用记录调用的 stub 替代，调用方的 `Popen` 用记录参数的 stub 替代；引号上下文反例仅运行固定的 Bash `printf` 标记命令，无网络与文件修改。

## 1. P1：权限确认仍忽略部分不可达路径和函数局部绑定

位置：`src/cv_agent/validation_tools.py:507-514`、`:517-529`。

三个反例都返回带有当前 candidate subject 的 `CONFIRMED`，而实际 stub 调用数为零：

```python
def check(path, replacement):
    try:
        return path
    finally:
        pass
    os.chmod(path, 0o777)
```

```python
def check(path, replacement):
    False and os.chmod(path, 0o777)
```

```python
def check(path, replacement):
    os.chmod(path, 0o777)
    os = replacement
```

第一例的 `try` 不含 chmod，被直接跳过，退出状态没有传播到后续语句；第二例把短路表达式中的 AST 调用当成已执行；第三例没有预先分析整个函数的局部名字绑定，实际在调用前发生 `UnboundLocalError`。

修复要求：支持的控制流必须传播终止状态，表达式必须保留短路执行语义，局部符号表必须先于顺序分析建立；不支持的执行语义返回 `UNRESOLVED`，不能确认或反驳。保留直接可达 `0o777 → CONFIRMED`、`0o750 → REFUTED` 控制。本次两个控制均通过。

证据名称：`permission_try_return`、`permission_short_circuit`、`permission_local_binding_after_call`。

## 2. P1：命令分析还不是基于可达返回值的数据流分析

位置：`src/cv_agent/validation_tools.py:783-829`、`:1736-1742`。

以下 helper 实际返回 `worker clean; printf REVIEW_MARKER`，工具却返回 `SANITIZED`：

```python
def get_cmd(model_uri, suffix):
    cmd = f"worker {shlex.quote(model_uri)}"
    for value in [suffix]:
        cmd += value
    return cmd, {}
```

实现只处理函数体顶层的少量语句，`for` 中的修改被忽略，先前的转义状态继续存活。此错误输出会使 `validate_conclusion` 接受 `SAFE/UNRESOLVED`，拒绝引用它的 `VULNERABLE/UNRESOLVED`。

反方向也存在误报：

- 安全 `return` 后增加永远不会执行的未转义 `cmd` 赋值，结果变成 `UNSANITIZED`。
- 先赋原始字符串、再完全覆盖为正确转义字符串并返回，结果仍是 `UNSANITIZED`。

原因是 `return` 后继续收集，且最终状态汇总所有历史赋值，任意旧 `UNSANITIZED` 都压过实际返回值。

修复要求：跟踪可达路径上实际返回的值；终止后停止分析；覆盖赋值应替换旧状态。循环、try/with 等可能修改命令的结构必须有状态转移或明确产生不确定结果，不能保留全链路转义判断。保留直接正确转义与直接未转义控制。

证据名称：`command_loop_append`、`command_dead_code`、`command_overwritten_raw_value`。

## 3. P1：helper 的转义状态没有绑定到调用方实际执行的命令

位置：`src/cv_agent/validation_tools.py:1750-1761`。

正确转义的 helper 不变，仅将调用方改成：

```python
def serve(model_uri, suffix):
    command, command_env = mlserver.get_cmd(model_uri)
    command += suffix
    return subprocess.Popen(["bash", "-c", command])
```

工具仍返回 `SANITIZED`。记录参数的 Popen stub 实际收到 `['bash', '-c', 'worker clean; printf REVIEW_MARKER']`。结论校验接受 SAFE，拒绝引用该命令观察的 VULNERABLE。

原因是只检查存在 sink 和被检索 helper 的状态，没有连接 helper 返回值、调用方的后续变换与最终 sink 参数。这与上一项 helper 内部控制流遗漏是两个独立边界。

修复要求：把返回值绑定到调用方变量并追踪到具体 sink 参数；核实 shell 调用方式。在完成该绑定之前，helper 的转义只能作为局部事实，不足以宣称候选完整命令已转义。

证据名称：`command_caller_append`。

## 4. P1：忽略 shell 引号上下文，错误信任 shlex.quote

位置：`src/cv_agent/validation_tools.py:630-644`、`:670-687`。

```python
def get_cmd(model_uri):
    cmd = f'printf "%s" "{shlex.quote(model_uri)}"'
    return cmd, {}
```

输入为固定的 `$(printf REVIEW_MARKER)`。工具返回 `SANITIZED`，但 Bash 实际输出 `'REVIEW_MARKER'`，而非包含 `$(` 的原始输入：命令替换已发生。`shlex.quote` 产生的单引号位于外层双引号中，不能提供这里所假设的保护。

实现分析 f-string 时丢掉常量片段，只看插值是否调用 quote，因此丢失了决定转义是否有效的 shell 上下文。该错误同样被裁决层接受为 SAFE 的肯定反证。

修复要求：只在已支持且核实的 shell 词元位置承认转义；嵌套引号、二次解释等没有建模的组合返回不确定结果。加入双引号包裹反例与正确裸词元转义控制，不能仅按函数名判定消毒有效。

证据名称：`command_double_quote_context`。

## 5. P2：如实引用静态反证仍会导致漏洞结论被拒绝

位置：`src/cv_agent/react_engine.py:226-233`，以及 `:153-166` 的引用合并。

同一条 VULNERABLE 结论引用源码中的后续原始追加，并解释 helper 只保护了之前的输入：不填写 `counter_observation_ids` 时通过；把 helper 的 SANITIZED 观察放入 `counter_observation_ids` 后被拒绝。

原因是支持、反对和未决引用被合并为同一个集合；静态反证被当成不可反驳的结论约束。只限制为“被引用的观察”修复了全局否决的一部分，却使如实披露反证的结论受到惩罚。它不需要模型调用就能复现。

修复要求：保留证据角色和作用范围；静态 SANITIZED 观察不能仅因出现在反证列表就硬性否决有后续证据的结论。保留同 candidate、同 source、同验证范围的具体 CONFIRMED/REFUTED 冲突约束，不可用删除所有冲突检查替代修复。

证据名称：`counter_citation_absent`、`counter_citation_present`。

## 6. P2：汇总保存仍丢弃计划外结果行

位置：`scripts/run_python_heldout_pair_matrix.py:87-112`。

给合法 30 行添加一个计划外的 failed 行后，`rows_with_truth` 将 31 行缩减成 30 行。直接验收原始行会报告 `Unexpected held-out result cells`；验收保存后的 enriched 行却没有问题。

当前运行器最终验收使用原始内存 rows，因此本次反例**没有绕过在线运行器的验收**。缺陷在于 `results.json` 和后续 summary 丢失记录，离线复核可能与原验收不一致；重复行修复没有覆盖计划外行。

修复要求：保存全部原始行，并显式标记计划外单元；指标按合法计划单元计算，同时报告额外记录。回归应断言原始与持久化记录的完整性，并验证正常、重复、缺失和额外行。

证据名称：`unexpected_row_disappears_from_results`。

## 建议的修复与验收顺序

1. 把以上十个失败场景加入行为回归，同时保留安全与不安全正反控制。
2. 先修权限执行与绑定语义，再修命令 helper 返回值、调用方 sink 绑定和 shell 转义上下文。
3. 修复证据引用角色和原始结果持久化，避免不可靠局部证据支配裁决或保存时丢行。
4. 完整离线 pytest、harness-check 通过后，按既有约定运行不超过 10 项的版本化 gate；结果与新代码快照一并审核，再决定完整矩阵。

这次审查不支持“已经没有 bug”的结论。可验收目标应是上述反例修复、支持语义范围明确、未支持路径不产生伪确认，以及实验记录可重放。
