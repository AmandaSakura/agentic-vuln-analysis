# Java 执行验证器实施结果

## 当前结果

已实现固定开发对 `BenchmarkTest00827` / `BenchmarkTest02244` 的候选绑定 Java 命令边界
验证器，并接入 ten-trial runner。

- `BenchmarkTest02244`：真实 Java `doPost` 路径经 `ThingFactory` / `thing.properties`
  到 `ProcessBuilder(["sh", "-c", "echo " + bar])`；本地 `LD_PRELOAD` recorder 在
  `exec` 边界截获 argv，受控 token 到达 shell `-c` 参数，返回 `CONFIRMED`。
- `BenchmarkTest00827`：真实 Java `doPost` 路径执行 List 插入、删除、取值后进入
  `Runtime.exec(cmd, argsEnv, cwd)`；fixture 使用安全的 `/usr/bin/env` 作为命令边界
  观察程序，确认受控 token 没有到达进程边界，返回 `REFUTED`。
- `run_fixture_test` 现在带 `ValidationSubject`，必须匹配候选路径、行号和索引源码摘要；
  旧源码、helper、resource 或 recorder 摘要变化会使 fixture 返回 `UNRESOLVED`。
- 普通 Python fixture 仍保留 Landlock/seccomp/resource limits；Java fixture 显式走
  `isolated=False, resource_limited=False`，依靠 subprocess timeout、最小环境和边界
  recorder 控制，不继承普通 fixture 的 JVM 不兼容内存限制。
- `validation/` 已纳入 live gate source fingerprint，验证 harness 变化会使十项验收失效。

最新验证：

```sh
uv run --no-sync pytest
# 410 passed in 21.69s

uv run --no-sync cv-agent harness-check
# status: PASS
```

最新 current-source ten-trial：

```text
artifacts/development_benchmark/a4643644fd3a40dab01f15cbba68b4ca
passed: true
issues: []
```

该批次是 2 个固定 cmdi 案例 × E1-E5 = 10 cells。随后 full development matrix 已完成：
`artifacts/development_benchmark/523853f48f434210960ede9948d5cce9/`；完整结果见
`docs/FULL_DEVELOPMENT_MATRIX_RESULT_2026-09-19.md`。

## 原问题

十项试验中的 Java 工具只有静态检查和可能的数据流，没有已注册的执行验证器。
因此正确模型标签与 CONFIRMED/REFUTED 是两个不同结果。本轮已经修复了验收和实验准入，
但没有用标签、源码正则或伪造 fixture 补足动态证据。

## 已交付范围

先实现固定开发对 `BenchmarkTest00827` / `BenchmarkTest02244` 的 Linux 命令注入
验证，保持 doPost 入口和候选源内容绑定。该阶段只是两种声明探针的开发验证，
不宣称覆盖 11 类漏洞、330 项矩阵或任意 Java 程序。

具体代码单元：

- `validation/java-command-harness/`：固定依赖的 native `exec` recorder。`ProcessBuilder`
  shell 路径在 exec 边界记录参数并阻断，不在宿主机执行待分析命令。
- `src/cv_agent/java_fixture.py`：加载当前提交的构建产物、验证源码及运行依赖摘要，
  编译候选和 minimal servlet harness，转换为 `FixtureOutcome`。未知案例、源码错配、超时、
  构建失败都返回 `UNRESOLVED`。
- `tests/test_java_fixture.py`：候选/源码/资源错配、提前 return、输入覆盖、参数位置变化、
  环境变量与 shell 参数区别、候选绑定和真实可达正反例的回归测试。

## 必须建模的实际语义

正例通过 `ThingFactory.createThing()`、反射和 `thing.properties` 选择实现，最后向
`ProcessBuilder` 传递 shell 的 `-c` 参数。不能把未知 helper 一律当成输入原样传递。
负例使用 List 的插入/删除/取值，取出的值位于 `Runtime.exec` 的环境参数，而非命令参数；
不能仅凭字符串出现于 `exec` 调用就确认命令注入。

运行身份必须包含候选路径/行号、源码摘要、helper 与资源摘要、依赖锁、JVM 版本和 OS 分支。
模型只看到中性候选、限定分析范围及脱敏行为记录；不暴露正负标签或依据结果选择路径。

## 扩量边界

十项成功只说明固定 cmdi 开发对就绪。330-cell full matrix 已完成，但仍包含 crypto/hash/ldapi 等其他
类别；这些类别没有对应动态验证 fixture。full matrix 应按 development prediction matrix 解读，
不能把所有类别称为已执行验证的漏洞结论。
