# 无 strace 的单轮见证诊断与 v5 交付

## 结论与停点

按本轮授权，两份固定快照各运行一次。关闭 strace 及配套的 open 尝试记录后，**两版都在约 6 秒内到达经过认证、绑定到候选源码的 `subprocess.Popen`**，没有 CPU 超限或墙钟超时。当前输入下隔离环境不再阻断命令边界。此结果支持插桩开销的解释；同时关闭了两种记录，不能单独量化 strace 与 open 审计各自的贡献。

隔离 Bash 重放中，a 的命令替换探针展开，b 的探针按字面量保留。**两版候选结论仍为 UNRESOLVED**，没有 CONFIRMED、REFUTED 或 SAFE；尚未实现的假设核验和 preexec 核验没有被跳过。

本轮目标运行已经结束。没有追加运行、扩建隔离策略、安装依赖/工具或调用模型。未实现新的证明义务，也未运行良性目标对照。后续路线由用户在此停点决定。

## 1. v5 的三个条件

- `configs/datasets/advisory_pairs_v5.json` 与 v4 的唯一 JSON 差分为 `pairs[2].entry_value_assumptions["self._nworkers"]: null → 1`，两份 hp003 快照共用这一声明。
- `configs/datasets/advisory_pairs_v5.md` 说明构造源码为 `workers or 1`、清单使用默认 workers，以及历史六格结果继续归属 v4。v4 保持原始字节，SHA256 为 `6b26bb871650211f5087174e663c4f870ea61fc1a38cb4e9d6c81627f9847896`。
- 新回归递归检查唯一键差分，并实际加载原 gate、matrix、pilot runner，确认它们仍为 v4。数据加载器和诊断清单准备器新增显式 dataset 参数，默认仍是 v4；本轮准备清单时显式选择 v5。原实验配置没有改动。

v5 仍为开发数据，`claim_eligible=false`。声明修正没有自动核验 `_nworkers` 的运行值，因而其未核验缺口仍存在；这是核验能力尚未实现，不是本轮观察到值不匹配。

两份清单与上一轮 heavy 清单比较，只有上述值声明及包含该声明的派生 `analysis_scope` 改变。源码、调用数据、解释器和资源配置完全相同。

## 2. 通用诊断改动

新增 `--no-strace --dump-stacks`。Landlock、seccomp、命令审计、候选帧和源码绑定检查继续执行；原四项精确只读准入在无 strace 时也传入 worker。没有新增 procfs/sysfs 准入，也不再从无 trace 的运行推断读取拒绝清单。

在隔离完成后调用 `faulthandler.dump_traceback_later`，定时点为父进程绝对墙钟截止时间之前 3 秒。所有线程的 Python 栈通过独立管道传回，JSON 结果不与原始栈混写；最多保存 64,000 字节，超额继续排空并标记截断。没有新增文件写权限。本轮目标均在 27 秒定时点之前完成，因此空栈是正常结果。合成超时用例验证了实际线程栈回传。

新增关闭管道反例先复现 EOF 后仍反复 select 的父进程空转，再以 EOF 标记修复。回归同时覆盖快速 Popen、无 trace 的精确只读准入及禁止写入/读取邻居文件、过期准入、默认候选正控和 160 KB 栈输出不破坏 JSON。

## 3. 固定输入与原策略

| 项目 | 本轮取值 |
| --- | --- |
| nonce | `e775150be75644bddf7642a38cd8ed86` |
| 模型路径 | `/home/joker/AAA_NUS_SEM3/cv_agent/artifacts/bounded_execution_witness_stage2/shared_runtime/model$(printf e775150be75644bddf7642a38cd8ed86)` |
| 调用 | `PyFuncBackend(config={}, env_manager="local").serve`，`enable_mlserver=true`，其余参数沿用无标签模板 |
| heavy_target | CPU soft/hard 15/20 秒，AS 2 GiB，64 FD，文件大小 1 MB，worker 墙钟 30 秒 |
| 原只读准入 | `/dev/urandom`、`/etc/passwd`、`/etc/ssl/openssl.cnf`、UTC 时区数据的规范叶文件 |
| 准入清单 SHA256 | `4b047c4a25af05852c50e0030fcd9561326c692f1ceae15d75e07bab41faa942` |

差分程序及附加断言确认 `same_concrete_input=true`、同一准入数据/摘要和同一资源配置。两个目标均用已安装的 Python 3.12.12 venv，从相应固定 checkout 导入，没有下载/注册表函数的桩。控制目录按原协议准备，但诊断模式没有运行良性目标对照；目录存在不能算对照成功。

## 4. 实际观测

| 指标 | hp003_a | hp003_b |
| --- | --- | --- |
| 固定 commit | `d1312edfca36c7acae0d064ef6a094eded88e14f` | `202fac4c83ccc8544c087c142b80196d0e60695c` |
| 总诊断墙钟 | 6.144 秒 | 5.316 秒 |
| 目标自身 CPU | 5.89 秒 | 5.58 秒 |
| 首个认证命令事件 | `subprocess.Popen` | `subprocess.Popen` |
| candidate/emitter | `PyFuncBackend.serve`，`backend.py:311` | 同一函数与行号 |
| Bash 重放 | nonce 展开 | 完整 `$(printf …)` 字面量保留 |
| 候选状态 | UNRESOLVED | UNRESOLVED |

两版 serve 文件 SHA256 相同：`709861cdbfcc51f27f8e377d65babc058d17fff368af0c29d3dd93c7e2927065`；函数首行 229。候选帧和发出事件的帧一致，`in_checkout=true`，`loaded_source_gaps=[]`。真实 subprocess 代码对象认证、seccomp 自检和审计钩子自检均通过，worker 退出码 0，实际可执行文件核对为 Bash。没有继承污染 shell 的环境变量。

a 捕获的第三个 argv 为 `exec mlserver start <模型路径>`；b 为 `exec mlserver start '<模型路径>'`。独立隔离 Bash 重放均退出 0：a recorder 收到 `start` 和末尾为 `model` 加 nonce 的路径，b recorder 收到 `start` 和完整原模型路径。被测目标的命令在进程创建边界被拦截，**目标自身并未启动 Bash**；这里报告的是捕获 argv 的独立重放结果。重放没有继承捕获的环境变量，保持原 fixture 限额和 5 秒墙钟。

目标 own CPU 由回收前的进程统计获取，tracer 为 null。RSS 峰值分别为 174,156/174,976 KiB；虚拟内存观察峰值为 1,183,200/1,183,160 KiB。FD 观察峰值均为 7，存在读取 proc FD 的 EACCES 测量缺口，因此只能称观察下界。

## 5. 剩余证明义务

两版均剩相同的八项缺口：

1. `entry_value_assumption_unverified:self._nworkers`
2. `entry_value_assumption_unverified:MLServerDefaultModelName`
3. `entry_value_assumption_unverified:MLServerMLflowRuntime`
4. `entry_condition_assumption_unverified:sys.platform.startswith('linux')`
5. `entry_condition_assumption_unverified:is_windows()`
6. `entry_condition_assumption_unverified:self._env_manager != em.LOCAL`
7. `entry_condition_assumption_unverified:os.path.exists(artifact_uri)`
8. `preexec_not_verified`

这些是保守核验缺口，不能说全部假设在运行时失败。当前 `preexec_fn` 未被证明为 None，也没有在隔离子进程中单独验证。a 的展开观测尚未闭合候选见证，b 的一次字面量观测不能证明整函数安全。未运行良性对照，不能声称 C3 已完成；本轮结果不计入原六格、TP/TN 或三臂效果比较。

## 6. 验证、保存与交付

定向回归 **20 项通过**。最终完整 `uv run --no-sync pytest`：**2138 passed in 178.79s**；`uv run --no-sync cv-agent harness-check`：**PASS**。

首轮完整测试曾在原 CPU 测试中出现 1 失败：测试专用 1 秒软 CPU 限制在 bootstrap/import 阶段耗尽，没有进入其要验证的 invoke 忙循环。将该用例的显式 profile 改为 2/4 秒后，仍要求 invoke、真实内核 SIGXCPU 来源及分离 CPU 统计；默认 fixture 与 heavy_target 未改变。修复后完整测试通过，EOF 回归加入后再次完整通过。历史失败日志保留。

原始文件保存在 `artifacts/bounded_execution_witness_stack_diagnostic/`：两份 manifest、两份诊断 JSON/log、差分 JSON、输入核对、pytest 和 harness 日志；没有生成 strace 文件。版本控制文件 `.hermes/plans/2026-09-28-witness-stack-diagnostic-summary.json` 完整保存两份 manifest、两份原始诊断、机器差分及原始产物摘要。计划、v5 说明和回归随代码提交，避免只依赖未跟踪文件。

实际诊断入口是 `cv_agent.evaluation.diagnostics.run_bounded_witness_diagnostic`，分别使用 `manifest_v5_a.json` / `manifest_v5_b.json`、上述共享目录与 nonce、原 `read_grants_final.json`，参数均为 `--no-strace --dump-stacks`。两次输出各保留一份，未重跑。
