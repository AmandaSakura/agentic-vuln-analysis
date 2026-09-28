# 隔离读取诊断：本轮停点报告

## 结论

已经实现通用的读取尝试/实际拒绝记录，并在现有 UV 环境上对两个固定快照做了 5 轮、共 10 次诊断。所有轮次的具体输入完全相同；每轮两版本的准入策略也相同。最终两版都是 **UNRESOLVED**，最后可靠观察的阶段都是 **import**，随后进程收到 **SIGKILL**。指定的目标构造与 `serve` 调用尚未开始，没有首个命令事件，没有 Bash 重放，没有候选确认。

本轮停止在这里：没有实现条件、值或 preexec 证明义务，没有修改数据集或 `_nworkers` 声明，没有发模型请求，没有下载或安装依赖。为核对诊断机制，只读查阅了文末的官方文档；目标进程仍保持禁网。

## 通用实现

- Python `open` audit 记录访问尝试、阶段、线程和不读源码的栈信息。仅保留最后 32 条并记录总数/截断标志；原生库打开以 syscall 日志补足。
- 父进程在隔离外使用本机 `/usr/bin/strace` 记录 `open/openat/openat2`，以成功的 `landlock_restrict_self` 为边界，并追踪线程继承。处理转义路径、相对路径和 unfinished/resumed；不完整记录保留明确缺口。
- 只有实际隔离后只读打开返回 EACCES、路径在准入外且父进程只读打开成功，才记 `isolation_read_denied:<canonical_path>`。其他拒绝记 `read_access_denied`；ENOENT、写打开和伪造 audit 不产生读取隔离证据。宿主核对只打开/关闭，不读取文件内容。
- 新增准入只接受带理由和身份的叶子文件：普通文件 SHA256、字符设备 major/minor。目录、过期身份和非诊断使用均拒绝。身份在父进程及 worker 中核对；这是诊断身份检查，不是并发替换条件下的原子文件绑定证明。
- trace 私有新建、禁止覆盖，启动失败不能消费旧日志。日志与结果都有容量限制；超时/启动异常清理整个启动进程组。诊断 worker 先回传阶段，因信号终止也能保留最后阶段。
- 所有诊断状态固定为 UNRESOLVED，不进入原候选 TP/TN；没有目标内部 mock。

一次运行只能观察实际执行过的读取。致命导入失败后的访问尚未发生，所以使用了有界的逐项核对、同输入重跑会话，没有自动放开未知路径。

## 实际推进

| 轮次 | 两版共同准入增量 | 两版共同观测 | 阶段 |
| --- | --- | --- | --- |
| 0 | 无 | `/dev/urandom` 拒绝；`NotImplementedError` | import |
| 1 | `/dev/urandom` | `/etc/passwd`、`/run/systemd/userdb/` 拒绝；无法确定 home 目录 | import |
| 2 | 再加 `/etc/passwd` | 一次暴露 8 个系统读取路径，随后 SIGKILL；当时尚无阶段进度回传 | 未回传最终阶段 |
| 3 | 再加 OpenSSL 配置及误选的本地时区文件 | SIGKILL；阶段记录确认仍为 import | import |
| 4 | 保留 OpenSSL 配置，纠正为实际请求的 UTC 文件 | 剩余 6 个读取拒绝，SIGKILL；无命令事件 | import |

第 3 轮曾把 `/etc/localtime` 准入为时区数据，实际指向 Asia/Singapore；复核发现被请求的是 `/usr/share/zoneinfo/UTC`。第 4 轮移除了前一条，换成正确的 UTC 叶子文件。旧策略和产物完整保留，没有给予时区目录权限。

### 11 个观察到的拒绝路径及决定

| 规范路径 | 最终决定 | 理由 |
| --- | --- | --- |
| `/dev/urandom` | 只读准入 | 依赖导入需要 OS 熵；字符设备 1:9 |
| `/etc/passwd` | 只读准入 | 原生 UID→home 查询，普通文件摘要绑定 |
| `/etc/ssl/openssl.cnf` | 只读准入 | 依赖的本地 OpenSSL 初始化配置；禁网保持 |
| `/usr/share/zoneinfo/Etc/UTC` | 只读准入 | 实际请求 `/usr/share/zoneinfo/UTC` 的规范叶子；摘要绑定 |
| `/run/systemd/userdb` | 继续拒绝 | 目录；准入 passwd 后最终没有尝试此回退 |
| `/sys/devices/system/cpu` | 继续拒绝 | 目录，不能扩大整个目录读取权限 |
| `/sys/devices/system/cpu/online` | 继续拒绝 | CPU 检测；尚未证明是到达入口的必需读取 |
| `/proc/stat` | 继续拒绝 | 动态系统状态；尚未证明必要性 |
| `/proc/cpuinfo` | 继续拒绝 | CPU 检测；尚未证明必要性 |
| `/proc/sys/vm/overcommit_memory` | 继续拒绝 | 内存策略探测；尚未证明必要性 |
| `/sys/kernel/mm/transparent_hugepage/enabled` | 继续拒绝 | 内存策略探测；尚未证明必要性 |

最终仍记录这些实际缺口，没有把“似乎可以忽略”当作已证明无影响。四条最终准入的路径、理由、文件摘要/设备身份在同目录的 `2026-09-28-isolation-read-diagnostics-summary.json` 中完整保存。

## 最终状态与资源观察

| 快照 | 状态 | 最后阶段 | 首个命令事件 | 入口 Popen | 墙钟时间 | 子进程 CPU 合计 |
| --- | --- | --- | --- | --- | --- | --- |
| a：`d1312edfca36c7acae0d064ef6a094eded88e14f` | UNRESOLVED | import | 无 | 未到达 | 9.01 s | 8.22 s |
| b：`202fac4c83ccc8544c087c142b80196d0e60695c` | UNRESOLVED | import | 无 | 未到达 | 8.67 s | 8.16 s |

两版最终缺口：原先 7 项未核验假设；表中 6 个最终读取拒绝；`isolation_trace_process_killed`；`worker_terminated:SIGKILL`。进程 CPU 合计包含 tracer 与目标，不能单独定位目标资源消耗或证明 SIGKILL 的来源。原有 CPU 5 s、地址空间 1,500,000,000 bytes、worker 墙钟 12 s 预算均未放宽；下一次继续时应先测清终止原因，不能据此推断注册表、preexec 或 serve 语义。

`self._nworkers=None` 与构造函数的静态冲突保持记录，但本轮没有运行到指定的构造步骤，因此没有宣称完成运行时值核验。数据集修订/义务范围仍待用户决定。

## 输入、产物与验证

- 两份原 manifest 的 SHA256 保持为 `c34dab97789b47b6190163553ab5e133e27652358871e9986f74b352f2eed9c8` / `69d5b30279b1574243c8dfa3b7c182359b42d03e84e40a72a516c96b1ef3eb30`；源 checkout 工作树均干净。
- 同一个 nonce `e775150be75644bddf7642a38cd8ed86`、同一个受控目录及前提文件摘要贯穿所有轮次。两个模型/对照目录与前次诊断一致。最终差分 `same_concrete_input=true`；会话摘要另行断言所有轮次同输入、每轮两版同实际准入列表和策略摘要。
- 最终策略 SHA256：`4b047c4a25af05852c50e0030fcd9561326c692f1ceae15d75e07bab41faa942`。
- 完整日志：`artifacts/bounded_execution_witness_stage2_read_admission/round{0..4}_{a,b}.json` 及各自 `.strace.log`、`read_grants_round*.json`、`read_grants_final.json`、`witness_differential_final.json`。跟踪日志 SHA、大小和观测摘要已复制进受版本控制的会话 JSON。
- 新增 42 项离线回归：29 项 trace 解析/边界/原生线程对照，13 项真实隔离读取/文件准入/旧日志/信号终止对照。修改前的失败日志也保留。
- 最终完整 `uv run --no-sync pytest`：**2044 passed in 120.07s**，日志 `verified_pytest.log`；`uv run --no-sync cv-agent harness-check`：**PASS**，日志 `verified_harness.log`。

## 文档依据

Python audit 的 `open` 事件提供访问参数，不能替代实际 syscall 返回码，见 [Python audit events](https://docs.python.org/3.12/library/audit_events.html)。Landlock 的文件读取权限、继承及已有描述符约束，见 [Linux 6.6 Landlock 文档](https://docs.kernel.org/6.6/userspace-api/landlock.html)。本机的拒绝、线程跟踪与准入结果另由合成测试和实际诊断日志核对。
