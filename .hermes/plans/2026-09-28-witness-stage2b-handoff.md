# 见证器 2b 完成与 2c 门禁

## 完成范围

实现本轮批准的三类通用核验及真实良性目标对照；新增显式 `verify_obligations=True` / CLI `--verify-obligations`。旧 observation-only diagnostic 模式继续保持 UNRESOLVED，不自动运行对照或产生证明。现有 v4 实验配置、v5、默认 fixture 与 heavy_target 资源值均未修改。

- **值**：真实入口帧读取 instance 原始字典，规避 property、自定义属性访问、元类描述符、任意比较/哈希协议。裸名需要在全部 SHA 绑定源码中有唯一无条件模块级赋值，实际值来自来源核对后的模块字典；失配与源码漂移保持缺口。
- **条件**：从已核对源码 AST 匹配完整表达式，规范化引号/冗余括号，并支持完整测试外层 `not` 的真值反转。没有 eval。专用 sys.monitoring tool ID 4；PY_START 发现真实入口和懒加载 helper，只有相关已绑定代码开启局部 LINE/BRANCH。逐个记录实际分支边、真假与次数；未观察、歧义、任一失配或监控被占用/改变均为缺口。平台信息单独记录，不能代替分支观察。
- **preexec**：在真实 Popen 的两个可信 subprocess 帧中取得相同对象，中止 Popen 后，在同一隔离 worker 中 fork 标记子进程并真实调用。完整正常返回记录、退出码 0、观测自检及没有危险尝试缺一不可。新导入的 checkout 源码也在子进程里核对。None 使用原有严格实参核对。
- **良性对照**：verification 模式总是运行真实对照入口，使用与 probe 相同的源码、资源、准入与核验；随后独立 Bash 重放必须得到清单里的固定参数及完整对照路径。对照失败不能被 probe 的展开掩盖。

只有 probe 与 control 全部边界/义务闭合，且探针实测展开，才返回 CONFIRMED/EXPANDED_OBSERVED；字面量始终 UNRESOLVED/LITERAL_OBSERVED。任何义务缺口均保持 UNRESOLVED。原候选范围未缩小，没有样本专用函数放行或目标内部桩。

## 关键反例与修复

os._exit/sys.exit 没有 Python 审计事件。子进程补充 profile/trace 观测；捕获后吞掉的 exit、exec、subprocess/fork 尝试仍拒绝。进程退出但缺少正常返回消息永远不能通过。新的线程及修改/规避观测的入口保守拒绝。

整合时审计回调会抑制 profile/trace，fork 会继承这一状态。现在通过内部捕获信号中止 Popen，退出回调后再核验。最后还用正反控复现了**合成捕获异常上下文造成假 CONFIRMED**：preexec 读 sys.exception() 时继承工具自己的异常。核验已移到异常处理结束后的 finally，恢复中性上下文；原正控与对应反控都通过。

另两项行为复现已经修复：preexec 延迟导入未声明源码仍确认；CodeType 在绑定核对之前对注入常量调用目标哈希。均有修前失败与正常来源正控。

## 验证与提交前状态

新增 **89 项**离线测试（值 21、分支 28、preexec 23、整链 12、CLI/差分 5）。原见证器定向回归全部通过。

最终完整 `uv run --no-sync pytest`：**2227 passed in 195.16s**。`uv run --no-sync cv-agent harness-check`：**PASS**。前一次完整 2223 passed 在异常上下文反例加入前，仅为历史通过记录；最终结果使用修复后的版本。

日志保存在 `artifacts/bounded_execution_witness_stage2bc/`，包括整合初始失败、审查反例、最终定向与完整日志。当前尚未运行实际 hp003 目标；先提交 2b，再进行用户批准的唯一一组 2c。

## 2c 输入与限制

继续使用上一轮原样的 v5 manifests（SHA 与字节内容均已核对）、现有 Python 3.12 venv、同一模型目录/nonce、原四项精确只读准入及 heavy_target。无 strace，保留超时栈；没有联网安装或项目模型请求。每个快照一次 verification 调用，包含 probe 和 benign control 各一个目标进程。原产物不覆盖。

这是 Python 审计/profile/monitoring 的有界测量；审计钩子不是隔离工具。裸 native/ctypes 进程调用、刻意篡改解释器观察状态/伪造继承管道等不在其完整覆盖声明内。允许并记录普通 ctypes 加载，不按 libc/prctl 或目标函数名放行。源绑定和隔离自检不等同于通用沙箱安全保证。

调用清单仍由人工根据 advisory 提供。2c 即使确认，也只代表该清单和环境下工具验证成功，不能报告为自动检测系统检出、TP/TN 改善或 held-out 泛化；`claim_eligible=false` 保留。2c 后停下，清单来源问题由用户之后决定。
