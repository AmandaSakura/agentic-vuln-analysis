# 阶段 2：一次通用协议修复与 B 重跑

本阶段按 M0 §4 的 F1 分支执行。阶段 1 的 B-a 没有执行见证：严格布尔值修正后仍缺调用与构造数据，随后观察/收尾预算耗尽。原始四格和自动 F3 诊断保留，人工复核为 F1、F6 伴随因素。用户已解除机械指纹/归档读取造成的 S4，见 [授权解除](2026-09-29-S4-resolution.md)。

## 重跑前登记

仅 B 两格各运行一次，不重跑 A 或阶段 1。相同 E1、DeepSeek Flash、入口和 advisory 摘要；移除数据集场景。模型独立提出、修正并分类每条场景前提，不提供样本值或分支答案。阶段最多 30 请求、3600 秒，累计仍最多 210 请求 / 2,500,000 reported tokens；已发生的 32 请求 / 191,177 tokens 计入总账。

| 格子 | 成功 / 可接受 | 警报 |
| --- | --- | --- |
| B-hp003_a | 模型场景实际得到 CONFIRMED，最终 VULNERABLE | 不成功如实报告，不追加第二轮重跑 |
| B-hp003_b | ABSTAIN / UNRESOLVED，其他不带确认的结果按原标准审计 | 任何 producer CONFIRMED 或最终 VULNERABLE → S1 立即停 |

任何 SAFE 必须核对完整证据，字面量或未知不能提供安全结论。F1–F6 沿用 [阶段 1 登记](2026-09-29-phase1-results.md)，区别准备接收、真实执行与完整投递；本地观察/步骤预算与实验请求总上限分开记。

## 本轮通用修复范围

- 共用的准备协议：生产者声明尚未执行与可补齐字段及填写位置，必需验证器及时提示继续准备；模型继续选择值与分类，未知语义和绑定失败不能伪造成可执行场景。
- 调用执行与投递状态分开：成功生产的相同调用即使投递被截断，也记住已执行，不重新运行。不同参数和新任务仍正常执行；缓存不保存或重放确认证据，截断继续不具备证明资格。
- 逐请求审计依据实际执行判 F3，不把接收部分准备数据当作错误场景的运行时证据。历史审计不改写。

预算、证据准入、九项义务、系统探针、良性对照、隔离默认值不放宽；K1 输出通用化和 K4 字段变更留在本阶段重跑之后，保持此次实验条件清楚。

## 验证与实际结果

首次完整套件为 2426 passed / 1 failed；唯一失败是旧的 `test_small_budget_cannot_be_borrowed_from_a_later_expert_subtask` 仍预期相同静态检查再次执行后产生 error。按本轮执行记忆修复，相同调用应被 blocked，因此迁移该测试，生产实现未回退。保留原有 RuntimeError、总预算 400、首任务上限 200、第一次及第二次投递截断和两次 scan 观察合计不超过 200 的断言；新增第二次无 validation/proof、两个请求 scope 都为 200、实际静态生产者仅调用一次的核验。C5 要求截断和 blocked 观察不能提供证明，C6 要求未完成验证不得解锁后续任务或借用其预算；记住已执行调用不改变这两个门槛。迁移后定向 planner / registry / ReAct 正反控 **55 passed in 13.63s**，完整套件仍须按最终源码重新运行。

最终完整 `uv run --no-sync pytest` 为 **2427 passed in 269.24s**，harness **PASS**；首轮失败日志保留。新增协议与执行记忆控制分别为 16、10 项，包含真实合成仓库的展开/引用、准备不提供证明、错误绑定、可信元数据、同批终态关闭恢复提示、截断不重复执行以及完整证据正常准入。布尔与文本前提的 schema 现在公开实际强制的类型，不给出目标取值。

真实开发快照的 developer_scripted 正反控仍为 a **VULNERABLE / CONFIRMED / EXPANDED_OBSERVED**、b **ABSTAIN / UNRESOLVED / LITERAL_OBSERVED**，各只执行一次，全部 977 项源码绑定和运行义务核对闭合；每格 3 次脚本回复，观察预算分别为 6248、6261，未扩大 8192 上限。详情见 [离线汇总](2026-09-29-phase2-offline-summary.json)，不将这些脚本结果作为自主模型成功。

B 实际初始请求预检通过，两格初始请求哈希相同，源码前缀各 3113 字符，无场景字段、无场景参考记录、源码外场景标记为空。实际工具定义摘要 `3a1bf3b6ba2b8f21650db8cdd9043dc98a5717fb455db14593677b131c19f477`；详情见 [预检](2026-09-29-phase2-preflight.json)。包边界快照复原旧 mandate、描述和前提类型引用即可得到旧哈希；候选身份摘要保持不变。差异只来自真实类型声明与通用准备/恢复指引，未加入样本路径、名字或参数值。

## 真实模型实际结果

实际运行使用已提交的 `d23e59c9d13bdd5e304f96f6628287d3f222c7c7`，目录为 `artifacts/witness_scenario_matrix/d735d835e8af451cbd8b260de12e2f4c`。自带完整门禁为 **2427 passed in 270.88s**；本阶段 14 次请求 / 14 个原始响应 / 14 个解析成功回复，**90153 reported tokens**。全部原始响应的 `model` 字段均为 `deepseek-flash`，没有缺失 usage、用量冲突、孤立响应或重复请求。14 份原始 usage 与耐久授权账本逐条相同。最终两格均 ABSTAIN / UNRESOLVED，没有 producer CONFIRMED、已准入 VULNERABLE 或 SAFE。`hard_stop=null`。

| 格子 | 请求 | input / output / total tokens | 工具调用 | 准备 / 实际见证 | 格子耗时 | 见证工具耗时 | 已准入结果 |
| --- | ---: | --- | ---: | --- | ---: | ---: | --- |
| B-hp003_a | 8 | 50494 / 1348 / 51842 | 7 | 2 / 1 | 29.690 s | 14.548877 s | ABSTAIN / UNRESOLVED |
| B-hp003_b | 6 | 37172 / 1139 / 38311 | 6 | 2 / 1 | 27.969 s | 14.667903 s | ABSTAIN / UNRESOLVED |

两格均从空参数见证调用进入 `propose_scenario` 准备状态，提交 input_parameter 后进入 `complete_call_data`，再补齐分类数据进行一次真实执行。前两次回复的 `witness_attempted=false`，最后一次为 true；不能把接收准备数据计为运行。最后实际见证分别投递 3708、3704 个观察 token，均 `status=ok`、`validation_status=UNRESOLVED`、未截断、未抑制。两个运行产物确认各执行一次，没有重复执行。

### 逐请求原始用量

下表按实际发生顺序列出全部请求；所有行的原始返回模型均为 `deepseek-flash`。完整原始 usage 对象、provider response ID、开始/接收时间和逐请求授权账本记录保存在 [summary](2026-09-29-phase2-summary.json) 的 `requests_in_actual_order`；包含 `prompt_tokens_details.cached_tokens` 与所有 cache 字段，未丢弃任何 reported usage 字段。

| 格子 | request_id | prompt | completion | total | cache hit / miss |
| --- | --- | ---: | ---: | ---: | --- |
| hp003_a | `36b7f7dcbf374c91955f90a360eaa04c` | 4712 | 137 | 4849 | 128 / 4584 |
| hp003_a | `e2299055601b40758f063fed858ae909` | 5351 | 69 | 5420 | 4736 / 615 |
| hp003_a | `877424b954fc497bb34e0acf317fc29b` | 5798 | 145 | 5943 | 5376 / 422 |
| hp003_a | `ac0956929ed346308c26931c337a810d` | 6654 | 372 | 7026 | 5760 / 894 |
| hp003_a | `dd9bb10d8dab4e6ab707bb86a1bf0640` | 8206 | 146 | 8352 | 6912 / 1294 |
| hp003_a | `13bf6ea6bbc14bc29e757aba4da8864c` | 6186 | 173 | 6359 | 768 / 5418 |
| hp003_a | `6ec2df3c9dcd45649ed89da5accea1b3` | 6624 | 155 | 6779 | 6272 / 352 |
| hp003_a | `474df647281445a7be109defe7b4a389` | 6963 | 151 | 7114 | 6656 / 307 |
| hp003_b | `d816ba2737e8426ebb3703ce1c8f27a8` | 4712 | 139 | 4851 | 4480 / 232 |
| hp003_b | `4326f02a07d348e79d5987122f431840` | 5574 | 144 | 5718 | 4736 / 838 |
| hp003_b | `f72ddb3aa0744972801b02f8a21d26e3` | 6425 | 390 | 6815 | 5632 / 793 |
| hp003_b | `6b2a918c3a9d48bd84583b0d623e47d4` | 7994 | 107 | 8101 | 6784 / 1210 |
| hp003_b | `f186cedd3d6347f2a9fa62b87fb89355` | 6048 | 187 | 6235 | 2176 / 3872 |
| hp003_b | `932666a730c64b02ac2c48e349fcf0b8` | 6419 | 172 | 6591 | 6144 / 275 |

阶段 1 与 2 累计为 **46 requests / 281330 reported tokens**，accounted tokens 同为 281330；没有未结的未知用量保留。阶段上限 30、累计上限 210 / 2500000 均未耗尽。两格 8192 的局部观察预算均耗尽，和全局请求上限分开报告。

### 模型原始场景与分类

以下四份为模型原始 `scenario_hypothesis`，保留所有值、分类和理由，不把模型关于 default 的文字当作已验证事实。四次的外层 `constructor_parameters` 与 `precondition_files` 都是空对象；除此以外还有两次不带假设的空参数初始调用。原始省略的 maps 保持省略，不在本节补成数据集前提。

**hp003_a，request `877424b954fc497bb34e0acf317fc29b`，原始 event 18**

```json
{
  "input_parameter": {
    "value": "model_uri",
    "classification": "attacker_controlled_input",
    "rationale": "serve() takes model_uri from the caller and passes it to _download_artifact_from_uri and then into server_implementation.get_cmd, which builds the scoring-server command line."
  }
}
```

**hp003_a，request `ac0956929ed346308c26931c337a810d`，原始 event 23**

```json
{
  "constructor_parameters": {
    "config": {
      "classification": "deployment_configuration",
      "rationale": "PyFuncBackend constructor config is supplied by the deployment, not the request.",
      "value": "None"
    },
    "env_manager": {
      "classification": "deployment_configuration",
      "rationale": "env_manager selects the environment manager and is a deployment setting.",
      "value": "local"
    }
  },
  "entry_value_assumptions": {
    "enable_mlserver": {
      "classification": "deployment_configuration",
      "rationale": "enable_mlserver selects mlserver vs scoring_server and is a deployment flag.",
      "value": false
    },
    "host": {
      "classification": "deployment_configuration",
      "rationale": "Bind host is a deployment setting.",
      "value": "127.0.0.1"
    },
    "port": {
      "classification": "deployment_configuration",
      "rationale": "Bind port is a deployment setting.",
      "value": "5000"
    },
    "timeout": {
      "classification": "deployment_configuration",
      "rationale": "Server timeout is a deployment setting.",
      "value": "60"
    }
  },
  "input_parameter": {
    "classification": "attacker_controlled_input",
    "rationale": "serve() takes model_uri from the caller and passes it to _download_artifact_from_uri and then into server_implementation.get_cmd, which builds the scoring-server command line.",
    "value": "model_uri"
  }
}
```

**hp003_b，request `4326f02a07d348e79d5987122f431840`，原始 event 54**

```json
{
  "input_parameter": {
    "value": "model_uri",
    "classification": "attacker_controlled_input",
    "rationale": "serve() takes model_uri from the caller and passes it to _download_artifact_from_uri and then into server_implementation.get_cmd, which builds the shell command string."
  }
}
```

**hp003_b，request `f72ddb3aa0744972801b02f8a21d26e3`，原始 event 59**

```json
{
  "constructor_parameters": {
    "config": {
      "classification": "deployment_configuration",
      "rationale": "PyFuncBackend constructor config dict; default None in typical serving deployments.",
      "value": null
    },
    "env_manager": {
      "classification": "deployment_configuration",
      "rationale": "PyFuncBackend env_manager selects environment handling; default 'local' for serving.",
      "value": "local"
    }
  },
  "entry_value_assumptions": {
    "enable_mlserver": {
      "classification": "deployment_configuration",
      "rationale": "Flag selecting mlserver vs scoring_server implementation; default False.",
      "value": false
    },
    "host": {
      "classification": "deployment_configuration",
      "rationale": "Bind host for the local scoring server; default 127.0.0.1.",
      "value": "127.0.0.1"
    },
    "port": {
      "classification": "deployment_configuration",
      "rationale": "Bind port for the local scoring server; default 5000.",
      "value": "5000"
    },
    "timeout": {
      "classification": "deployment_configuration",
      "rationale": "Server startup timeout in seconds; default 60.",
      "value": "60"
    }
  },
  "input_parameter": {
    "classification": "attacker_controlled_input",
    "rationale": "serve() takes model_uri from the caller and passes it to _download_artifact_from_uri and then into server_implementation.get_cmd, which builds the shell command string.",
    "value": "model_uri"
  }
}
```

input_parameter 均声明为 `attacker_controlled_input`；其余实际提交的 host、port、timeout、enable_mlserver、config、env_manager 均声明为 `deployment_configuration`。未提交额外环境条件或预先文件。a 的 config 是字符串 **"None"**，b 是 JSON **null**，不能混写。两格都把 enable_mlserver 置为布尔 **false**，env_manager 为 "local"；原始 Boolean/condition maps 为空，开关通过 `entry_value_assumptions` 提交。工具核验了这些值对应实际执行，但权限分类本身不证明远程控制或部署普遍性。

### 实际执行、对照与投递

两格发出的 argv 都是 `["bash", "-c", "exec uvicorn --host 127.0.0.1 --port 5000 --workers 1 mlflow.pyfunc.scoring_server.app:app"]`。实际走的是 scoring_server 分支，命令中没有 probe 目录路径。不能采用模型随后声称“unquoted model_uri-derived path 已进入命令”的解释；实际事件没有建立该 shell 值传播。两格 raw status 都为 UNRESOLVED，唯一运行时缺口为 `recorder_prefix_not_established`。该缺口是见证范围未闭合，不能重命名成隔离、超时或资源失败。

实际发出事件的 candidate/emitter frame 均为 `mlflow/pyfunc/backend.py:311` / `PyFuncBackend.serve`，源码 SHA256 为 `709861cdbfcc51f27f8e377d65babc058d17fff368af0c29d3dd93c7e2927065`。probe 的真实 Popen、source checks、声明值/分支、seccomp/hook self-test 和 preexec normal return 均已核验。工具在 recorder 前缀检查处提前返回：没有 control event、probe replay 或 control replay。观察里的空 control 摘要并非执行过的良性对照；九项义务未闭合，因此只能 U，不能 SAFE/REFUTED。完整 raw result、实际 probe event、original/execution subject 与 hashes 均保存于 summary 的 `runtime_results`，原产物未修改。

| 格子 | 运行产物 | manifest SHA256 | scenario SHA256 |
| --- | --- | --- | --- |
| hp003_a | `artifacts/witness_scenario_matrix/d735d835e8af451cbd8b260de12e2f4c/shared-runtime-witness-artifact-zcnw6igu/witness-result.json` | `61818ae9e4ed6dce77ca7cc969118b7fefaaab3cb2c86f8862a336950ea0fe2f` | `169fa1aa3fc8b70e60aebcb2a7e872d11639794d0bdf255475f06c6aadf66c14` |
| hp003_b | `artifacts/witness_scenario_matrix/d735d835e8af451cbd8b260de12e2f4c/shared-runtime-witness-artifact-_uc5rxad/witness-result.json` | `32e835dd08e5366661b19db10aebc8cfb8153b172b6c2c1ee499b48f559b1669` | `93bbbe4f39adf3ec3f836d036a3624a15e02a10a82c3eb341446fd0acf2ba075` |

### 工具时序与预算

每行耗时是 tool_start 到 tool_result；准备耗时包括清单检查，但不计为执行见证。

| 格子 / citation | 工具与阶段 | elapsed s | token charge | 结果 |
| --- | --- | ---: | ---: | --- |
| hp003_a / `scan/tool:1` | inspect_command_construction | 0.459820 | 1173 | ok / UNRESOLVED |
| hp003_a / `scan/tool:2` | run_static_check | 0.005028 | 460 | ok / UNRESOLVED |
| hp003_a / `scan/tool:3` | run_bounded_execution_witness / 准备 | 2.565343 | 950 | ok / UNRESOLVED |
| hp003_a / `scan/tool:4` | run_bounded_execution_witness / 准备 | 2.973259 | 1798 | ok / UNRESOLVED |
| hp003_a / `scan/tool:5` | run_bounded_execution_witness / 执行 | 9.010275 | 3708 | ok / UNRESOLVED |
| hp003_a / `scan/tool:6` | search_symbols | 0.012201 | 103 | ok / 截断 |
| hp003_a / `scan/tool:7` | search_symbols | 0.004005 | 0 | blocked / 截断 |
| hp003_b / `scan/tool:1` | run_bounded_execution_witness / 准备 | 2.870656 | 950 | ok / UNRESOLVED |
| hp003_b / `scan/tool:2` | inspect_command_construction | 0.489067 | 1173 | ok / UNRESOLVED |
| hp003_b / `scan/tool:3` | run_bounded_execution_witness / 准备 | 2.799358 | 1798 | ok / UNRESOLVED |
| hp003_b / `scan/tool:4` | run_bounded_execution_witness / 执行 | 8.997889 | 3704 | ok / UNRESOLVED |
| hp003_b / `scan/tool:5` | read_span | 0.004186 | 567 | ok / 截断 |
| hp003_b / `scan/tool:6` | search_symbols | 0.004033 | 0 | blocked / 截断 |

B-a：1173 inspection + 460 static + 950 preparation + 1798 preparation + 3708 runtime = 8089；下一次 search 只投递 103 后耗尽 8192，再下一次 blocked。B-b：950 preparation + 1173 inspection + 1798 preparation + 3704 runtime = 7625；read_span 只投递 567 后耗尽 8192，随后 search blocked。完整 U 已在预算耗尽前送达；本轮不属于成功见证被截断，也没有证据缓存重新准入。

### 原始结论、准入和 F1–F6 复核

B-a 提交过两份 VULNERABLE / UNRESOLVED 原始结论：第一份将 scan/tool:5 同时放进 supporting 与 unresolved，并依赖静态 sink；第二份修正角色后仍没有充分命令证据。B-b 提交过一份 VULNERABLE / UNRESOLVED，声称输入路径进入未引用的命令并依赖截断 read_span；同样被准入拒绝。它们都是模型提案，不是已准入 ballot 或最终判决；三份提案及原始反馈全文保存在 summary 的 `rejected_material_proposals`。不能笼统写“没有出现 VULNERABLE”，也不能把证据拒绝计为 schema 拒绝。两格最终分别以 0.4、0.3 confidence 提交并获准 ABSTAIN / UNRESOLVED；固定侧没有 producer CONF 或已准入 V，运行硬停记录为空。

| 格子 | 原始提案被拒 | 自动诊断 | 人工复核 |
| --- | ---: | --- | --- |
| B-a | 2 次 V/U | F3、F6 | **F3，局部 F6 伴随**：完整场景实际执行但进入 scoring_server/uvicorn，recorder 前缀未建立，未得到正例所要求的 CONF。不是阶段 1 的准备未完成 F1。 |
| B-b | 1 次 V/U | F3、F6 | **预登记的固定侧 ABSTAIN/U 达标**。保留分支选择、prefix 缺口和局部预算事实；不能由固定侧 U 单独推断场景错误，也未检验 mlserver 修复分支。 |

两格都完成准备协议并执行一次，F1 不是主因；schema rejection 为零，不满足 F2。无基础设施缺口，不支持 F4；没有 CONF，不存在 F5。F6 指本地观察/收尾约束，不是 30 请求或累计 210 请求耗尽。自动 request_audit 原文件和逐条事实保留，本报告增加人工接受标准解释。

### M0 后续分支

B-a 的唯一授权重跑仍未达到 CONFIRMED / VULNERABLE。按 M0 §4 的“重跑失败”分支，**3a、3b 后续只做离线部分，不发模型请求**；当前没有“失败已明确与样本无关且已修好”的例外证据，不追加第二轮模型重跑或样本提示。局部预算与场景分支失败按模型能力事实记录，不能据此再做针对本样本的修复。K4 等已授权离线工程另行验收，不构成追加真实请求授权。

developer_scripted 正反控与真实模型结果分开：脚本证明工具在指定场景下可以闭合，真实模型现在能够走完准备并收到完整运行结果，但本轮未自主得到正例确认。不支持自主泛化、held-out 召回或整函数安全结论。

完整账本、场景原文、运行结果与复核见 [phase2 summary](2026-09-29-phase2-summary.json)；原始 `events.jsonl`、`request_audit.json` 和 `summary.json` 的路径及 SHA256 也已登记，历史阶段 1 产物保持不变。
