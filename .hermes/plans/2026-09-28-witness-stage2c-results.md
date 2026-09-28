# B 路线 2b/2c 结果与停点

## 结论

2b 已先通过完整门禁并提交为 **e67f36a**，随后执行唯一一组 2c。两份固定快照各进行一次 verification 调用，每次包含一次真实 probe 入口和一次真实 benign-control 入口。没有目标重跑、模型请求、依赖安装或新隔离准入。

| 快照 | 候选状态 | raw_status | 核验缺口 | 完整见证耗时 |
| --- | --- | --- | --- | --- |
| hp003_a | **CONFIRMED** | **EXPANDED_OBSERVED** | 无 | 16.177 秒 |
| hp003_b | **UNRESOLVED** | **LITERAL_OBSERVED** | 无 | 15.303 秒 |

九项义务均闭合：3 项值、4 项条件、preexec 实跑和良性对照。a 是在声明输入/环境下绑定到具体候选与源码的展开见证；b 的字面量观测不产生 REFUTED 或 SAFE，也不证明其他输入/路径不存在危险行为。

本轮已经停止。调用清单由人工根据 advisory 提供，因此结果是**人工提供场景后的工具验证**，不能报告为自动检测系统检出、六格模型成绩、TP/TN 改善或 held-out 泛化。`claim_eligible=false` 保留；清单由谁生成留到之后讨论。

## 固定输入、资源与次数

重用上一轮两份 v5 manifest 的原始字节，SHA256 分别为：

- a：`bead6f13ec5624cb46329a4233d7fef9678229fd5a5faf4498ed02203cb85db6`
- b：`916b5df70450a7330d3c9b98d650fe35c1f05b625f1d8499ec6cd51f06cc3786`

同一 nonce `e775150be75644bddf7642a38cd8ed86`、同一模型/控制路径、构造和调用参数、原有四项精确只读准入、Python 3.12.12 venv 和原值不变的 heavy_target。CPU soft/hard 15/20 秒、AS 2 GiB、FD 64、文件大小 1 MB、worker 墙钟 30 秒。v4/v5 与原实验配置没有改动。

差分程序和独立只读审计均确认 `same_concrete_input=true`、`same_read_policy=true`、`same_resource_profile=true`。准入清单 SHA256 仍为 `4b047c4a25af05852c50e0030fcd9561326c692f1ceae15d75e07bab41faa942`。

实际共四次 serve 入口执行、四个独立 preexec 测量子进程及四次隔离 Bash 重放。没有修改或 mock `_download_artifact_from_uri`、注册表分派、get_cmd 或其他目标内部函数。目标 Popen 在进程创建边界被中止；捕获 argv 的 shell 行为由另一隔离进程重放，不冒称目标自身启动了 Bash。

## 帧、源码与观测

四个真实命令事件均为认证的 `subprocess.Popen`，candidate/emitter 帧一致：`PyFuncBackend.serve`、函数首行 229、`mlflow/pyfunc/backend.py:311`。serve 完整文件 SHA256 为 `709861cdbfcc51f27f8e377d65babc058d17fff368af0c29d3dd93c7e2927065`。解释器与 manifest 匹配，seccomp 和审计自检通过，worker 退出码 0，加载源码与并发命令缺口均为空。

| 义务 | 四次运行的真实结果 |
| --- | --- |
| `self._nworkers` | 入口原始 instance 字典读到整数 1 |
| `MLServerDefaultModelName` | 唯一模块级定义，原始 module 字典读到 `mlflow-model` |
| `MLServerMLflowRuntime` | 唯一模块级定义，读到 `mlserver_mlflow.MLflowRuntime` |
| `sys.platform.startswith('linux')` | backend.py:252 的实际分支为 True |
| `self._env_manager != em.LOCAL` | backend.py:296 的实际分支为 False |
| `os.path.exists(artifact_uri)` | artifact_utils.py:70 的实际分支为 True |
| `is_windows()` | backend.py:284/308、artifact_utils.py:71 的三次观察均为 False |
| preexec | 真实对象在同一隔离 worker 的 fork 子进程中正常返回、退出码 0、自检通过、无禁止事件、新加载源码核对无缺口 |
| benign control | 两版均得到 `['start', 完整对照路径]`，无展开、重放退出 0 |

四项条件在六个实际执行到的出现处各记录一次，所有观察都符合声明。表达式匹配采用**规范化完整 AST**，只规范化引号/冗余括号，并支持完整测试外层 not 的测量真值反转；不是逐字文本或子串匹配，没有表达式 eval。tool ID 4 正常注册，局部 LINE/BRANCH 记录包含源码摘要与实际跳转偏移。

每次 preexec 记录四个允许事件：观测自检、builtins.id 自检，以及 `ctypes.dlopen('libc.so.6')` 和 `ctypes.dlsym(..., 'prctl')`。没有按这些名称放行；实际正常返回与完整消息才是通过依据。probe/control 的 preexec 耗时分别为 a 0.447/0.421 秒、b 0.426/0.444 秒，禁止事件与源码缺口均为空。

a 的 probe recorder 收到尾部为 `model` 加 nonce 的路径，原 `$(printf nonce)` 已展开。b 收到含完整 `$(printf nonce)` 的原模型路径。两版 benign recorder 都收到同一控制路径 `modelb066b2443182e1002f4432ec`。四次 replay 均成功。

原 JSON 的 `details.assumption_gaps` 是沿用字段，保存**运行前**的七项核验清单；当前结论依据 `result.gaps` 和各事件 `assumption_verification.gaps`，本轮全部为空。完整记录仍保留初始清单及后续核验事实，避免覆盖历史信息。

## 成本与边界

| 自身 CPU（进程统计，0.01 秒分辨率） | a | b |
| --- | --- | --- |
| probe worker | 8.04 秒 | 7.74 秒 |
| control worker | 7.66 秒 | 7.43 秒 |
| CLI 聚合子进程 CPU | 17.737 秒 | 17.267 秒 |

聚合值包括两个 worker、重放和已回收后代，不能当成一个目标的 CPU。没有 strace/tracer。四次运行均在 27 秒栈定时点之前完成，栈输出为 0 字节。FD 观察峰值 7–8，带有 proc FD 权限测量缺口，只能当观察下界。

性质只覆盖声明的本地已存在、含 shell 元字符路径，LOCAL、enable_mlserver、Linux 环境下的具体输入。其他 URI 类别、其他 env_manager、其他路径与输入不由本轮观测证明。Python audit/profile/monitoring 不完全覆盖裸 native/ctypes 进程调用或刻意篡改解释器/继承管道；这些覆盖限制没有因为状态 CONFIRMED 而消失。审计是观测，隔离仍由 seccomp/Landlock 提供。

## 验证、修复与保存

2b 新增 89 项离线测试，覆盖四类义务的正反控、来源/范围失配、监控占用与篡改、良性对照失败、退出包装调用、线程隐藏尝试、缺失正常返回和实际 preexec 延迟导入。完整最终测试：**2227 passed in 195.16s**；harness：**PASS**。

整合中修复了三个具体边界：在审计回调内测 preexec 会抑制 profile/trace；preexec 新导入源码也必须绑定；捕获 Popen 所产生的合成异常上下文会改变 preexec 行为并导致假 CONFIRMED。后者在提交前由正反控真实复现，移到异常处理结束后测量，再重新完整测试。没有用函数名、标签或 MLflow 特定源码放行。

原始输出保存于 `artifacts/bounded_execution_witness_stage2bc/witness_a.json`、`witness_b.json` 和 `witness_differential.json`，未覆盖旧诊断。受版本控制的 `.hermes/plans/2026-09-28-witness-stage2c-summary.json` 完整保存两份原始 manifest、两份原始见证、差分、输入核对和日志摘要。2b 代码提交与 2c 数据提交分开，目标运行只发生在完整测试和代码提交之后。
