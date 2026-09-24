# 离线语义问题定位（2026-09-22）

本轮仅增加行为测试，未修改检测实现，未加载凭据或调用真实模型。
修改前完整离线测试通过（741 项；历史重构记录的 729 项不是当前数量）。新增 `tests/test_semantic_diagnostics.py`
共 23 个案例，单独运行得到 14 项通过、9 项失败；失败不标记 xfail，保留为修复验收条件。
新增后完整测试结果：**755 passed, 9 failed in 26.29s**，失败全部来自新增诊断案例。

复现命令（项目根目录）：

```bash
uv run --no-sync pytest -o addopts='' -q tests/test_semantic_diagnostics.py --tb=short
```

## 1. 权限检查漏掉后续 chmod，产生过强否定证据

最小示例：

```python
def entry(path, enabled):
    if enabled:
        os.chmod(path, 0o750)
    os.chmod(path, 0o777)
```

工具实际只收集分支中的 0o750，输出带候选绑定的 REFUTED。
末尾无条件 0o777 不能被此前分支排除，因此至少不能给出 REFUTED；
测试允许未支持的控制流保持 UNRESOLVED，不要求提升为漏洞确认。

另两项失败分别是 `chmod(0o750)` 后接 `if enabled: pass` 或
`try: pass / finally: pass`，再执行 `chmod(0o777)`。
直接安全/不安全 chmod、return 后死代码、恒假分支四项对照全部通过。

定位：`src/cv_agent/tools/validation/permissions.py` 的 `collect_statements`
遇到非恒定分支或 Try 后停止扫描；`_permission_mode_assessment` 又允许这些
issue 进入 `bounded_control_issues`，用不完整的调用集合生成 REFUTED。
修复必须区分真实路径终止与分析不完整，不能把扫描不到当成不存在。

## 2. 显式 shell 解释器被当成普通 argv

`subprocess.run(["bash", "-c", value])` 和对应的 `sh` / `Popen` 组合，
在 value 来源为 `request.args['value']` 时，实际返回 NOT_ESTABLISHED，
预期应保留 MAY_REACH。四项失败；相同命令先赋给变量再调用，四项通过。

定位：`src/cv_agent/tools/analysis/python_flow.py` 的 `record` 对
`shell=False` 且首元素为常量的直接列表统一清除 taint，未区分解释器 `-c`。
没有运行任何 shell 命令；测试只分析源码。MAY_REACH 也不是 exploit witness。

## 3. 普通 argv 存入变量后丢失结构信息

`command = ["echo", value]; subprocess.run(command)` 被标记 MAY_REACH，
直接传入同一列表则为 NOT_ESTABLISHED；Popen 同样如此，共两项失败。
这里检查的是 shell 命令注入流，不代表普通程序参数在所有场景下都安全。
固定 `bash -c "echo fixed"` 的四种写法全部通过负控。

定位：同一分析器的赋值环境仅保留名称是否带污点，丢失 argv 的程序与参数结构；
普通 argv 排除规则又只识别调用位置的列表/元组字面量。

优先修复第 1 项，再同时处理第 2、3 项，避免仅改一种写法导致另一种退化。
修复时保留全部正负对照，完成完整离线测试后再考虑真实模型实验。

## 后续修复（2026-09-22）

用户授权修复后修改了两个分析器：

- 权限收集在非恒定分支后尚有未访问语句时记录不完整扫描；未支持的 Try
  从有界 issue 白名单移除。上述三例现在均为 UNRESOLVED，且不绑定确认/否定 subject。
  单纯安全/不安全 chmod 与死代码对照保持原行为。
- 命令分析保留显式 shell/解释器 argv 的污点，包括绝对路径；指定 executable
  或传入未知关键字展开时，不使用普通 argv 排除规则。
- 仅为函数体内单次赋值、后续引用全部直接作为受支持 subprocess argv 的局部
  列表/元组保留结构信息。修改、重赋值、别名逃逸、未知函数调用均不套用该排除。
  shell=True 或动态 shell 参数也不清除可能流。

增加 10 个边界案例，修复前其中绝对 shell 路径、元组变量关键字传参、executable
覆盖三项也失败；其余覆盖重赋值、分支、直接/别名修改、未知调用及 shell 参数。
修复后 33 项诊断案例与相关历史测试共 **167 项通过**。
首次完整检查中所有行为测试通过，仅新增文档目录与导航违反布局约束（772 passed,
2 failed）；已将计划移入现有 history/plans 并补齐索引，不修改测试约束。
最终完整离线测试：**774 passed in 26.52s**；`git diff --check` 通过。

这些是有界静态语义修复，并非完整权限路径分析或通用 shell/解释器分析。
没有重新运行真实模型矩阵，历史结果与 claim_eligible 保持原样。
