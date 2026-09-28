# 资源诊断结果与两轮停点

## 结论

当前复现已确认 **CPU 限额中断来自内核**，没有证据把它归因于 MLflow 语义。将诊断 CPU 软/硬限制分为 5/10 秒后，两版在 import 阶段都收到 `SIGXCPU`，`si_code=128 (SI_KERNEL)`、`si_pid=0`，输出专门缺口 `cpu_limit_exceeded`。目标自身 CPU 与 tracer 自身 CPU 已分开计量。这个结果直接支持上一轮 `(5,5)` 硬 CPU 限制造成 SIGKILL 的解释；历史日志没有保留发送者信息，因此不是对历史信号发送者的独立追溯记录。

第二轮使用显式 `heavy_target` 后，两版均越过导入和构造，运行器进入 **invoke** 阶段，但 30 秒墙钟到期，父进程终止进程组。没有交付完整、认证的首个命令事件，没有得到 candidate_frame/argv，也没有重放。两版仍为 **UNRESOLVED**。`invoke` 是调用方在调用方法前写出的阶段，不能冒充被调用函数的认证帧或 Popen 见证。

本轮只做两组目标诊断：CPU 来源核对和 heavy 配置各一组。已停止；不再增加目标运行、资源值或 Landlock/seccomp/strace 功能。没有网络访问、依赖下载、模型请求、数据集修改或新增 procfs/sysfs 准入。

## 1. 最便宜的导入基线

使用现有 UV Python 3.12.12 venv、对应固定 checkout、GNU time 的 `-v` 和 Python 的 `-X importtime`。没有项目资源限制、Landlock、seccomp 或 strace。测量 supervisor 和目标放在同一个 user/net namespace，UID 保持 1000，网络接口只有隔离的 lo；没有联网安装任何包。

| 指标 | a | b |
| --- | --- | --- |
| GNU time user CPU | 3.60 s | 3.59 s |
| GNU time system CPU | 0.47 s | 0.47 s |
| 合计 CPU | 4.07 s | 4.06 s |
| 峰值 RSS | 170,576 KiB | 170,344 KiB |
| 采样 VmPeak | 1,026,912 KiB | 1,026,904 KiB |
| FD 观察峰值 | 6 | 6 |
| 退出状态 | 0 | 0 |
| 实际模块从指定 checkout 导入 | 是 | 是 |

第一份直接 GNU time 记录也成功导入，CPU 4.11 s、RSS 170,256 KiB；当时跨 user namespace 的 FD 观察触发 PermissionError，观察脚本失败。该 time/stdout/importtime 原始日志完整保留，正式基线由通用 supervisor 重新测量。正式基线也保留一次瞬时 FD PermissionError，其他采样继续成功；FD 值为观察下界，不声称精确最大值。

两次正式基线的地址空间约 1.05 GB、FD 观察峰值 6，没有显示原 AS 1.5 GB 或 FD 64 已超限。RSS 是物理驻留量，不能直接代替 RLIMIT_AS 的虚拟地址空间基线。

日志和命令：`artifacts/bounded_execution_witness_resource_diagnostics/baseline_{a,b}_measured.{json,time.log,importtime.log,stdout.log}`。所有实际 source 路径、模块 SHA256、Python prefix、namespace、命令、环境和日志摘要已复制进受版本控制的同目录 `2026-09-28-witness-resource-diagnostics-summary.json`。

## 2. 默认配置不变；新配置显式声明

| 配置 | CPU soft/hard | 地址空间 | FD | 文件大小 | worker 墙钟 |
| --- | --- | --- | --- | --- | --- |
| fixture_default | 5 / 5 s | 1,500,000,000 B | 64 | 1,000,000 B | 12 s |
| cpu_diagnostic | 5 / 10 s | 1,500,000,000 B | 64 | 1,000,000 B | 20 s |
| heavy_target | 15 / 20 s | 2,147,483,648 B (2 GiB) | 64 | 1,000,000 B | 30 s |

heavy 的选择：正式导入 CPU 最大值 ×3 向上取到 15 s，硬限制再加 5 s；VmPeak ×2 向上取到 2 GiB；FD 使用 `max(64, 4×观察峰值+8)=64`；墙钟使用 `max(30s, 4×导入墙钟)=30s`。没有根据结果标签选择配置。

`WitnessManifest.resource_profile` 完整序列化各项数值。默认配置固定校验，不允许以默认名字悄悄扩大值；新名字必须有限、正数，且 CPU soft<hard。新配置仅可用于诊断，不放宽候选证明。Bash replay 保留原 fixture 限额和 5 秒重放墙钟。`fixtures.py` 未修改。

## 3. CPU 限额归因

| 快照 | 目标 SELF user+system（信号报告时） | tracer own CPU（退出后回收前） | 信号 | 最后阶段 |
| --- | --- | --- | --- | --- |
| a | 3.099054 + 2.303760 = 5.402814 s | 2.88 s | 内核 SIGXCPU | import |
| b | 2.930464 + 2.312614 = 5.243078 s | 2.88 s | 内核 SIGXCPU | import |

可信 waiter 在线程继承 seccomp/Landlock 后启动，通过 `sigwaitinfo` 得到来源。用户调用 `os.kill(SIGXCPU)` 的反例得到 `si_code=0`，不记 CPU 超限。监控线程仍需取得 GIL；不能声称任意长 C 扩展都能在硬限制前回传。

Linux 在发出 CPU 软限额信号后会把软限额递增，本次 live `getrlimit` 变为 `(6,10)`。产物同时记录最初实际施加的 `(5,10)` 和信号后的 getter 值，没有把内核递增误判为配置漂移。内核常量和行为用本机 `/usr/include/asm-generic/siginfo.h`、`/usr/share/man/man2/getrlimit.2.gz` 及合成正反例核对，没有联网查文档。

## 4. heavy 结果与止损

| 快照 | 最后阶段 | 实际终止方/原因 | 目标 CPU 最后采样 | tracer own 最终 CPU | 首个认证命令事件 |
| --- | --- | --- | --- | --- | --- |
| a | invoke | 父进程，wall_timeout | 14.14 s（不完整） | 10.94 s | 未交付 |
| b | invoke | 父进程，wall_timeout | 14.28 s（不完整） | 11.07 s | 未交付 |

目标采样 VM 峰值约 1,109,450 KiB、FD 峰值仍为 6，未显示它们触及 heavy 限额。目标采样在终止前，不能当精确最终 CPU。tracer 的 own CPU 由 waitid WNOWAIT 后、Popen.wait 回收前的 proc stat 得到，分辨率 0.01 s。旧 `RUSAGE_CHILDREN` 字段保留兼容，但父进程同时杀死 tracer/目标时可能遗漏未被 tracer 回收的目标，不能当完整合计，更不能当目标或 tracer own CPU。

invoke 阶段已在构造函数正常返回之后写出，说明不再被导入或构造挡住。末段 trace 中继续读取已绑定的 MLflow 源文件，这与见证器的源码核验开销一致；缺少完整事件回传，不能据此宣称实际到达某个 Popen 行号。源码核对/trace 的开销是后续调查线索，不是本轮继续扩建或重跑的授权。

剩余 6 个 procfs/sysfs 读取全部继续拒绝并保留缺口；它们没有阻止运行器越过构造阶段，但没有给出对整个候选性质无影响的证明。原 7 项假设仍未核验。若下一步改用 bwrap，安装所需 sudo apt/网络必须单独确认；本轮没有安装或启动新隔离工具。

## 5. 数据集确认点：仅提案，未实施

构造步骤已经通过。按照用户“到构造函数再正式确认”的停点，现提交可审阅提案：复制 `configs/datasets/advisory_pairs_v4.json` 为 `advisory_pairs_v5.json`，只把 hp003 两快照共用的 `entry_value_assumptions["self._nworkers"]` 从 null 改成 1。共有一处 JSON 声明；构造源码两版都为 `workers or 1`，当前清单使用默认 workers。

- v4 和旧六格结果保持原样，旧运行继续归属 v4。
- v5 仍 `claim_eligible=false`，其他配置不变。
- 不会自动清除值核验义务，也不把源码推导当新运行时 `__dict__` 核验。
- 具体差分：`2026-09-28-advisory-v5-nworkers-proposal.diff`。**未创建实际 v5 配置，未修改 v4。**

## 6. 回归与交付

新增真实 CPU 软限制、用户信号反例、超时来源、未回收 tracer 统计、FD/地址空间采样、默认预算和新配置类型检查。最后审查还发现并修复两个父进程问题：非零退出后已写出的命令记录不能升级证明；清理时进程组消失只能忽略 ESRCH，不能丢失超时结果。均有真实合成进程的修前失败日志。非零退出测试首次出现过测试名称错误，纠正后重新捕获了真实的错误 CONFIRMED，不把名称错误当行为复现。

标签翻转测试保留完整状态、输入、来源和实际限额比较；仅正常化新增的 PID/CPU 等易变观察数据。没有删除候选证明断言或默认正控。

完整最终 `uv run --no-sync pytest`：**2127 passed in 135.91s**，日志 `final_verified_pytest.log`；`uv run --no-sync cv-agent harness-check`：**PASS**，日志 `final_harness_check.log`。没有模型请求，未绕过模型 gate。
