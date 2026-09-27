# 见证器停点 2 调整（rev2）

承接 `2026-09-27-bounded-execution-witness-design-rev1.md`（已在 1c6fb6f 实现）。本文件只调整停点 2 的顺序和两项证明义务的实现方式；rev1 的其余约束不变。本任务不发任何模型请求。

## 结论

同意在执行两快照见证之前补两项证明义务，但有三处修改：

1. **先做一次两快照诊断运行（2a），再补义务（2b）。** 现在的见证器已经会如实返回 `UNRESOLVED` 并附缺口列表，先跑一次不产生任何判决风险，却能暴露真实运行里的阻断点：依赖、导入、模型目录是否合法、`serve` 能否真正到达 `Popen`。如果 `serve` 在前面就失败了，预先做好的 preexec/条件义务就白做了。
2. **缺口不止两项。** `_assumption_gaps` 对 `entry_value_assumptions` 中不在 `call_kwargs` 里的项也会记缺口。hp003 有这些：`self._nworkers`、`MLServerDefaultModelName`、`MLServerMLflowRuntime`。这些同样需要运行时核验，否则 2b 做完仍然闭合不了。
3. **义务的实现方式必须通用，并且不执行字符串表达式**（见下文）。

## 2a：环境准备和诊断运行（需要网络安装依赖；不进 pytest）

- 两个快照各建一个 venv，使用 Python ≥ 3.12（下文要用 `sys.monitoring`）。如果 mlflow 在这两个 commit 上不支持该版本，停下报告，不要降级实现。
- 记录 `pip freeze`、包 hash 和 Python 版本；目标 mlflow 只从 checkout 通过 `PYTHONPATH` 加载。
- 用同一份清单各运行一次见证，保存完整产物。预期结果是 `UNRESOLVED`，要报告实际的缺口列表，以及运行到了哪一步（是否到达 `Popen`、首个事件是什么）。
- **停下，交付缺口列表。** 2b 只处理这里实际出现的缺口。

## 2b：通用证明义务（只做 2a 实际暴露的项；合成 fixture 正反控，进 pytest）

### 条件前提：观测分支结果，不求值表达式

- **不要**用 `eval` 执行 `entry_condition_assumptions` 里的表达式文本：会有副作用，求值时所在的帧也不对（例如 `os.path.exists(artifact_uri)` 属于 `_get_root_uri_and_artifact_path` 的帧，并不在 `serve` 里）。
- 做法：
  1. 在已准入且 SHA256 已核对的源码里，按 AST 找出测试表达式文本与假设完全一致的 `if`/三元节点。找不到或有歧义时记缺口。
  2. 只对这些 code object 开启 `sys.monitoring` 局部事件（LINE/BRANCH），在实际运行中观测每个节点走了哪个分支。
  3. 所有被执行到的出现处，都必须与声明的真值一致；节点一次都没执行到的，保留缺口；任一不一致，整次运行记 `UNRESOLVED`，并记录实际值。
- 平台类事实（`sys.platform`、`os.name`）另外在 worker 里记录，作为环境记录，不替代分支观测。

### 值假设：只读字典，不触发描述符

- `self.<attr>`：在入口帧取 `f_locals["self"]`，只查 `type(self).__dict__`/`self.__dict__` 的原始值，不调用 `getattr`，避免触发 property。拿不到就记缺口。
- 裸名常量：只有当它在已准入源码的**唯一一个**模块里有模块级赋值时，才在导入后读 `module.__dict__`。多处定义或没有定义时记缺口。
- 与声明值不相等就记 `UNRESOLVED`。

### `preexec_fn`：在隔离子进程里实跑一次

- 当前要求 `preexec_fn is None` 是正确的保守做法。放宽的条件只有一个：证明这次运行中 `preexec_fn` 会正常返回，且不会替换或终止进程。
- 做法：在审计钩子拦下 `Popen` 事件时取出 `preexec_fn` 对象；中止 `Popen` 之后，仍在同一个 seccomp worker 里 fork 一个子进程，子进程安装"全记录、命令类事件一律拒绝"的钩子，然后调用 `preexec_fn()`，用退出码和事件记录回报结果。
- 通过的条件：正常返回；没有 `os.exec*`/`os.system`/`posix_spawn`/`subprocess.Popen`/`os._exit`/`sys.exit` 事件，也没有抛出异常。`ctypes.dlopen` 等事件可以出现，但要记录。
- 自己 fork 出来的这个子进程要打标记，不能被当作目标代码的 `os.fork` 事件。
- **不能**按函数名或 hp003 的源码放行。
- 正反控要覆盖这些情况：
  - 正常返回（正例）；
  - 抛异常；
  - 调用 `os.execv`；
  - 调用 `os._exit`；
  - 调用 `subprocess.run`；
  - 吞掉异常后返回（正例，同 hp003 形状，但用合成代码）。

### 通用约束

- 义务未满足时一律 `UNRESOLVED`，缺口名要具体。
- 每项都要有正控和反控，现有断言不得放宽。
- 做完跑完整 `uv run --no-sync pytest` 和 harness-check，然后提交。

## 2c：重跑两快照诊断

- 使用同一份清单和同一套环境；交付结果、缺口列表和差分（`witness_differential.json`）。**停下。**

## 止损线

2c 之后如果 hp003_a 仍然没有得到 `CONFIRMED`，而且新缺口还是 mlflow 专有的语义，就不要继续往见证器里加义务，停下来和用户讨论是否换样本或换路线。hp003_b 预期是 `UNRESOLVED`（rev1 规定字面量观察不产生 SAFE），这不算失败。
