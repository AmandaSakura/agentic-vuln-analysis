# 系统生成见证清单：第 1 步离线验收

第 1 步离线验收完成：注册工具、确定性生成清单、结构化补充数据、离线脚本模型验收。没有真实模型请求、联网安装或新 advisory / held-out 运行。

## 实现与边界

- 注册 `run_bounded_execution_witness`，通过现有候选级 `FixtureProofScope` 消费，契约只支持 `CONFIRMED`。字面量观察保留 `LITERAL_OBSERVED / UNRESOLVED`。
- 系统从冻结索引和实际源码生成入口、签名参数、构造参数提议、值及条件前提和完整源码绑定。模型只可填写工具报告的缺失构造参数、受限的相对路径文本文件布局。
- nonce、探针、良性对照、录制命令、运行时核验义务、解释器、隔离准入与资源配置均由工具或可信调用配置掌握。调用参数和源码身份不能由模型覆盖；禁止标签、stub、mock 和运行策略字段。
- `env_manager="local"` 等输入提议来自已绑定源码和 subject 前提，仍需实际运行核验，生成成功不等于证明成立。当前 hp003 唯一补充构造字段为 `config={}`。
- Bash 录制器从真实绑定的命令边界推导，要求受支持的直接可执行命令与固定字面参数形状；不使用 hp003 命令名规则或旧人工清单。良性对照必须匹配同一命令前缀。
- 准备响应可以提示缺字段，但 `witness_attempted=false`，不能满足必做验证或解锁依赖任务。实际执行后才标记尝试完成。
- 支持无装饰器的方法头整函数候选；其他行候选不能借用该函数此前的命令事件。`src/` 导入布局由可信配置绑定。
- 常规静态工具的 `admitted_paths` 与模型上下文预算不变。真实执行所需源码库存单独绑定整个固定快照，存于工具产物中，模型只接收简短核验结果。

## 离线控制

合成 fixture 覆盖来源错误、过期源码、目录越界、stub / 标签 / nonce 字段、构造参数覆写、缺失数据、标签翻转、危险与字面量命令、命令前缀错配、后续行错借证明、准备响应误算完成及实际 `src/` 包布局。

脚本模型发现完整清单已经执行时应直接收尾。新增反例修前因为重复调用被拒而错误弃权；修后仅一次工具调用。生成器的输入提议不取代运行时正反控。

提示词及工具定义字节快照按本次新增说明与 schema 更新。仅逆转这两类新增内容可恢复旧哈希，候选身份哈希保持不变，核对记录保存在摘要中。旧 wall-timeout 测试的 2 秒预算在完整运行时耗于 strace 导入；仅该测试改为 6 秒，目标仍睡眠 30 秒，全部原断言保留。生产默认及 heavy_target 配置未改。

## 验收与提交

代码先提交为 **3039867**，随后执行配对验收。最终完整 `uv run --no-sync pytest`：**2296 passed in 211.58s**；`uv run --no-sync cv-agent harness-check`：**PASS**。本轮净新增 69 项测试。首次完整测试的两个失败和新增脚本模型反例的修前失败日志也保存于摘要，不覆盖历史运行。

| 快照 | 工具状态 | 原始观测 | 正常 agent 工作流判决 | 未闭合核验 |
| --- | --- | --- | --- | --- |
| hp003_a | CONFIRMED | EXPANDED_OBSERVED | VULNERABLE | 0 |
| hp003_b | UNRESOLVED | LITERAL_OBSERVED | ABSTAIN | 0 |

实际使用 `E1_LOCAL_SINGLE`、标准 `ToolRegistry`、完整 ReAct 投递和证据准入；模型为 `ScriptedChatModel`。每个版本 3 次脚本响应、2 次工具调用：先获得缺失 `config` 的准备响应，再补 `config={}` 执行，最后引用测量结果。共 6 次脚本响应，**真实模型请求 0、用量 0**。模型消息中的候选和仓库 ID 都是 `neutral-entry`，机器核对消息没有 hp003 案例标识。

两个快照各一次验证调用，每次包含真实探针及良性对照，因此实际有 4 个入口 worker、4 个 preexec 测量子进程、4 次独立 Bash 重放。都在真实 `PyFuncBackend.serve` 帧下捕获 `backend.py:311` 的 Popen，核对源码 SHA256、自检、正常退出、运行时值和条件、preexec 正常返回及良性字面量对照。没有替换任何 mlflow 内部函数。

机器核对 `same_concrete_input=true`：探针 / 对照 nonce 和绝对路径、构造 / 调用实参、前提文件内容摘要、资源配置及只读准入都相同。两边仅脚本补充 `config={}` 和空文件布局；入口、参数、977 项 Python 源码绑定均自动生成。977 项文件摘要在运行后再次核对，两个目标 checkout 仍干净。

沿用原 heavy_target（CPU 15/20 秒、地址空间 2 GiB、64 fd、1 MB 输出文件、30 秒墙钟）及四项已批准只读文件；没有 strace、依赖安装或新增准入。工具投递分别为 5389 / 5401 字节，均未截断或抑制，未增加预算。

原始 `details.assumption_gaps` 保留生成阶段的 7 条待核验义务；该字段不是运行结束后的未闭合列表。实际探针和对照的 `assumption_verification.gaps`、source/preexec 缺口及最终 `result.gaps` 均为空，完整原文保留，未删去这份初始义务清单。

完整清单、生成来源、原始事件、脚本请求、正常工作流判决、证明范围、全部测试日志摘要及机器核对程序已存入 [可追溯摘要](2026-09-29-witness-system-step1-summary.json)。批量工作产物在 `artifacts/witness_system_step1/paired_acceptance/`，可用如下命令在新的输出目录复现：

```bash
uv run --no-sync python -m cv_agent.evaluation.diagnostics.scripted_witness_acceptance \
  configs/profiles/witness_system_step1_offline.json \
  artifacts/witness_system_step1/paired_acceptance_new
```

旧六格配置仍指向 v4；本次新离线诊断显式选择 v5。所有结果保持 `claim_eligible=false`。

## 范围限制与停点

确认要求攻击者可提供一个**已经存在、目录名带 shell 元字符的本地目录**，并满足 subject 的 Linux / LOCAL / enable_mlserver 等声明场景。远程可达性和远程任意命令注入均未建立。

仍保留原生调用及观测通道篡改等既有覆盖限制；单次字面量观察不证明候选安全。生成器支持位置参数数据，但位置专用前提的运行时值绑定目前可能留下未定缺口，不影响 hp003；未知参数及未支持调用形状同样保持未定。

本轮模型行为为离线脚本，`config={}` 与空文件布局是脚本数据；没有人工完整调用清单或被测代码 wrapper。第 2 步真实模型单臂端到端以及第 3 步新开发样本泛化尚未执行，停在此处等用户决定。
