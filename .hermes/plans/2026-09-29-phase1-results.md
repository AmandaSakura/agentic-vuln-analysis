# 阶段 1：DeepSeek 无场景发现对照

本报告的判定标准在任何真实模型请求前登记。阶段 0 的基线提交为 `221373f`（2351 项完整测试通过，harness PASS）。执行模型固定为 `deepseek-flash`，所有实际返回模型 ID 均须匹配，缺失或不匹配按 S2 停止。

## 预先登记的判定标准（执行计划 §3.2 原文）

| 格子 | 成功 | 可接受 | 警报 |
| --- | --- | --- | --- |
| A-hp003_a（数据集场景） | 见证 `CONFIRMED`，判定 VULNERABLE | — | 其他结果：记录原因，属于协议问题 |
| A-hp003_b | ABSTAIN / UNRESOLVED | 其他不带确认证据的结论 | 判 VULNERABLE，或出现 `CONFIRMED` |
| **B-hp003_a（模型场景）** | **模型自己提出场景，见证 `CONFIRMED`，判定 VULNERABLE** | — | — |
| B-hp003_b | ABSTAIN / UNRESOLVED | 同 A-b | 同 A-b |

- b 格出现 `CONFIRMED` 或 VULNERABLE，就是**可靠性警报 → 硬停**（第 8 节 S1）。
- 任何格子判出 SAFE 时，检查它的证据链。没有合格证据的 SAFE 记为缺陷，走第 7 节修复。

## 预先登记的失败分类

| 代码 | 含义 |
| --- | --- |
| F1 | 没有调用见证工具，或没走完工具协议 |
| F2 | 场景假设多次被 schema 拒绝 |
| F3 | 场景假设被接受但是错的，见证结果为 UNRESOLVED，列出具体缺口 |
| F4 | 见证基础设施出错：超时、隔离、资源 |
| F5 | 见证已 `CONFIRMED`，但 agent 最终判定不是 VULNERABLE（证据接纳链的问题） |
| F6 | 预算用尽 |

多因素失败保留全部证据，不用任意单一归类删掉其他因素。F2 的“多次”按至少两份不同参数的 schema 拒绝记录；重复调用阻断单独记录，不当作新的 schema 实验。F6 需有明确预算/步骤终止记录。F4 的语义前提不成立不能冒充资源故障。

## 执行范围和硬上限

`dataset_role=development`，`claim_eligible=false`。固定 E1、同一模型、同一 advisory 摘要和入口标记。A 为 dataset，B 为 model；此前 developer_scripted 数据仅为离线能力验收，不与本阶段合并。

本阶段最多 60 次请求、3600 秒；全计划累计最多 210 次请求、2,500,000 reported tokens。每个格子只启动一次，任何重跑只可走已授权的阶段 2。首次模型请求前所有代码提交并通过新进程完整 pytest 门禁，每次请求前工作树和提交身份复核。模型 ID、修复版确认或累计配额触发硬停时保留已发生请求、原始响应及用量。

## 预检需要披露的差异

去掉场景说明后，相同总上下文预算下 B 可以容纳更长的源码前缀；该长度差异会随实际预检记录披露。要求的是每个条件内部两快照的相同输入规则与身份隔离，不把模型在 B 中自主选择的假设强制复用到另一快照。

## 实际结果

阶段 1 已按登记顺序完成一次四格运行，进程正常退出。实际代码提交为 `d6f6af1803bfa3bc5e142e55ec82023649d1ff9e`；独立 live gate 完整测试 **2398 passed / 249.93 秒**。32 次实际请求、32 份已解析回复，全部原始返回模型 ID 为 `deepseek-flash`；reported tokens 为 **191,177**。运行中的 guard 没有触发停点；事后权限审计发现 **S4：机械读取和复制保护输入**，后续工作已经停止。没有 SAFE、VULNERABLE 或任何生产见证 CONFIRMED。

四格最终均为 ABSTAIN / UNRESOLVED。A 两格和 B-a 未执行见证；B-b 实际执行两次见证，底层均为 `LITERAL_OBSERVED / UNRESOLVED`，但投递因剩余 token 预算不足被截断。B-a 的结果按独立复核归为 **F1：协议未完成**，F6 仅指本地观察/8 步预算收尾；全局 60 请求上限没有耗尽。

| 格子 | 场景来源 | 最终判定 / 验证 | API 请求 | reported tokens | 工具调用 | 实际见证执行 | 格子耗时秒 | 见证工具总耗时秒 |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| A-hp003_a | dataset | ABSTAIN / UNRESOLVED | 8 | 48,350 | 6 | 0 | 16.031 | 0.464543 |
| A-hp003_b | dataset | ABSTAIN / UNRESOLVED | 8 | 48,202 | 6 | 0 | 15.913 | 0.453059 |
| B-hp003_a | model | ABSTAIN / UNRESOLVED | 8 | 46,712 | 6 | 0 | 18.572 | 2.824974 |
| B-hp003_b | model | ABSTAIN / UNRESOLVED | 8 | 47,913 | 8 | 2 | 53.094 | 35.604250 |

来源分开计费：dataset 16 请求 / 96,552 tokens；model 16 请求 / 94,625 tokens。developer_scripted 在本阶段为 0，不与系统结果合并。逐次请求与全部原始 usage 字段保存在 [阶段 1 summary JSON](2026-09-29-phase1-summary.json) 的 `request_ledger`；未报告用量、usage 冲突、孤立回复、重复请求 ID、未归属工具和未配对工具起点均为 0。

## 工具序列与分类复核

- **A-hp003_a**：`run_bounded_execution_witness` → `inspect_command_construction` → `search_symbols` → `search_symbols` → `search_symbols` → `search_symbols`。
- **A-hp003_b**：`run_bounded_execution_witness` → `inspect_command_construction` → `search_symbols` → `search_symbols` → `search_symbols` → `search_symbols`。
- **B-hp003_a**：`run_bounded_execution_witness` → `inspect_command_construction` → `run_bounded_execution_witness` → `search_symbols` → `search_symbols` → `search_symbols`。
- **B-hp003_b**：`run_bounded_execution_witness` → `inspect_command_construction` → `run_bounded_execution_witness` → `run_bounded_execution_witness` → `run_bounded_execution_witness` → `run_bounded_execution_witness` → `run_static_check` → `probe_python_eval`。

A 两格均把已有数据集场景重新放入 `scenario_hypothesis`，违反该输入分支的协议，得到 `dataset_scenario_cannot_be_replaced`。它们随后转入静态分析和查询，没有完成构造参数补充和实际见证。两者都是 F1，并在本地收尾出现 F6。A-a 没有满足登记的成功条件；A-b 的弃权符合可接受范围，但没有测到见证正反差分。

**B-a：主因 F1，贡献因素 F6。** 第一份假设把布尔值写成字符串 `"true"`，schema 拒绝一次；第二份改为严格布尔值，schema 接受，但仍缺入口 `port`、`host`、`timeout` 和构造 `config`、`env_manager`。工具仅返回准备响应 `witness_attempted=false`，没有完整 manifest、worker、进程边界事件或见证产物。模型没有补齐这些数据，而转去查询源码。schema / static / preparation 分别消耗 457 / 1173 / 1759 观察 token（合计 3389），后续查询消耗 4446、357（截断），再下一次被阻断；本地上限 8192 token、8 次模型响应用尽。

原始自动审计把“schema 接受且 UNRESOLVED”当成 F3，给出 F3 + F1 + F6。该原始 artifact 保留；本报告和 companion JSON 显式附加独立复核结果。**准备阶段缺字段不证明运行时场景错误，因此这里不作 F3。** 只有一次 schema 拒绝，不满足预先登记 F2 的“至少两次”；没有超时、隔离或资源故障，不作 F4；没有确认，不作 F5。

B-b 有两次不同参数的 schema 拒绝（字符串布尔值；混用未分类构造参数与场景），达到 F2 的记录条件。补齐后的真实执行均为局部字面量观察；投递两次被截断后再转到静态 / eval 工具，最后以本地预算未完成验证的弃权收尾。这里把 schema、真实执行和投递缺口分别保存，不把字面量观测算作 SAFE。

## B-b 底层测量与投递不一致

| citation | 实际执行耗时秒 | producer 状态 / raw_status | producer 最终 gaps | 投递状态 / validation_status | 截断原因 |
| --- | ---: | --- | --- | --- | --- |
| `scan/tool:5` | 16.961274 | UNRESOLVED / LITERAL_OBSERVED | `[]` | error / null | token_budget |
| `scan/tool:6` | 15.816779 | UNRESOLVED / LITERAL_OBSERVED | `[]` | error / null | token_budget |

两次记录均在真实候选帧 `PyFuncBackend.serve` 中发出，直接 emitter 为 `mlflow/pyfunc/backend.py:311`，与登记关键操作一致。绑定文件 SHA256 为 `709861cdbfcc51f27f8e377d65babc058d17fff368af0c29d3dd93c7e2927065`。实际探针命令含被引用的路径；独立 Bash 重放保留字面量路径；良性对照正常、无展开。两次 producer 最终 gaps 均为空，guard 私有 telemetry 为 UNRESOLVED。完整探针、对照、preexec / source / 前提核验原文保留在每个见证 artifact，summary JSON 附实际事件和重放记录。

投递 JSON 大小为 4652 字节，未超 8192 字节上限；剩余 **token** 预算不足，产生 `{"observation_truncated":true,"original_size":4652,"reason":"token_budget"}`。消费端因此移除 `validation_status` 与 `fixture_proof`，不得据此支持实质判决或声称验证完成。

两个完整调用的参数相同，manifest digest 和 scenario digest 也相同，但发生两次真实执行。当前 `ToolRegistry` 只在 `finalized.status == "ok"` 后保存 `answered_calls`；第一次 producer 测量成功返回 UNRESOLVED 后因投递截断变成 error，所以第二次相同调用没有被阻断。**这是独立于样本标签的工具循环语义缺陷，违反 TEST_CONTRACT “同一专家任务不重复执行相同调用”。** 它没有产生假 CONFIRMED，不能把截断标记当证明；后续允许的通用修复应同时覆盖执行记忆与投递状态的区分，保持正常不同参数 / 不同任务执行的正控。

- scan/tool:5 原始见证产物：`artifacts/witness_scenario_matrix/90428b956f2b44e885c6e4461958dab5/shared-runtime-witness-artifact-3q5a2mml/witness-result.json`；artifact SHA256 `3de47419b76a8df345590b5e5373a09f4ce441cad59350c5046a1244101c4900`。
- scan/tool:6 原始见证产物：`artifacts/witness_scenario_matrix/90428b956f2b44e885c6e4461958dab5/shared-runtime-witness-artifact-olr0jzc9/witness-result.json`；artifact SHA256 `f13e904fac8026fcdfff605c75192b78009d039662252761dccdcd25ae27a758`。

## B 场景假设原文

以下按实际工具调用顺序照录 `scenario_hypothesis`，包括所有分类、原始类型和 rationale；拒绝的假设也保留。外层构造参数是否误放在未分类补充位置，在 summary JSON 的完整 `tool_timeline.call.arguments` 中保存。每一项均来自真实模型，不是 developer_scripted。

### B 假设 1：hp003_a

request ID：`5206a9b914454eac803757a355ef4356`；事件索引 84。

```json
{
  "input_parameter": {
    "value": "model_uri",
    "classification": "attacker_controlled_input",
    "rationale": "serve() takes model_uri from caller; advisory claims command injection via model URI in mlserver/scoring server command"
  },
  "entry_condition_assumptions": {
    "enable_mlserver": {
      "value": "true",
      "classification": "deployment_configuration",
      "rationale": "mlserver path selected by enable_mlserver flag"
    }
  }
}
```

### B 假设 2：hp003_a

request ID：`23929579b0e94a44ab1ec09b353821cf`；事件索引 91。

```json
{
  "entry_boolean_arguments": {
    "enable_mlserver": {
      "classification": "deployment_configuration",
      "rationale": "mlserver path selected by enable_mlserver flag",
      "value": true
    }
  },
  "input_parameter": {
    "classification": "attacker_controlled_input",
    "rationale": "serve() takes model_uri from caller; advisory claims command injection via model URI in server command",
    "value": "model_uri"
  }
}
```

### B 假设 3：hp003_b

request ID：`844c920a43b4402f8ab8dc8052a69655`；事件索引 123。

```json
{
  "input_parameter": {
    "value": "model_uri",
    "classification": "attacker_controlled_input",
    "rationale": "serve() takes model_uri from caller; advisory claims command injection via model URI in mlserver get_cmd"
  },
  "entry_condition_assumptions": {
    "enable_mlserver": {
      "value": "true",
      "classification": "deployment_configuration",
      "rationale": "mlserver path selected when enable_mlserver is true"
    }
  }
}
```

### B 假设 4：hp003_b

request ID：`718a0e0d9cd94940a3639747eecf7e1c`；事件索引 130。

```json
{
  "entry_boolean_arguments": {
    "enable_mlserver": {
      "classification": "deployment_configuration",
      "rationale": "mlserver path selected when enable_mlserver is true",
      "value": true
    }
  },
  "input_parameter": {
    "classification": "attacker_controlled_input",
    "rationale": "serve() takes model_uri from caller; advisory claims command injection via model URI in mlserver get_cmd",
    "value": "model_uri"
  }
}
```

### B 假设 5：hp003_b

request ID：`8bd529a64ad8443ebfd6f9fa8658f380`；事件索引 135。

```json
{
  "entry_boolean_arguments": {
    "enable_mlserver": {
      "classification": "deployment_configuration",
      "rationale": "mlserver path selected when enable_mlserver is true",
      "value": true
    }
  },
  "entry_value_assumptions": {
    "host": {
      "classification": "deployment_configuration",
      "rationale": "bind host",
      "value": "127.0.0.1"
    },
    "port": {
      "classification": "deployment_configuration",
      "rationale": "bind port",
      "value": "5000"
    },
    "timeout": {
      "classification": "deployment_configuration",
      "rationale": "server timeout",
      "value": "60"
    }
  },
  "input_parameter": {
    "classification": "attacker_controlled_input",
    "rationale": "serve() takes model_uri from caller; advisory claims command injection via model URI in mlserver get_cmd",
    "value": "model_uri"
  }
}
```

### B 假设 6：hp003_b

request ID：`660ba5c44e8c448ebf369cd1e2094ff4`；事件索引 140。

```json
{
  "constructor_parameters": {
    "config": {
      "classification": "deployment_configuration",
      "rationale": "backend config object",
      "value": null
    },
    "env_manager": {
      "classification": "deployment_configuration",
      "rationale": "env manager selection",
      "value": "local"
    }
  },
  "entry_boolean_arguments": {
    "enable_mlserver": {
      "classification": "deployment_configuration",
      "rationale": "mlserver path selected when enable_mlserver is true",
      "value": true
    }
  },
  "entry_value_assumptions": {
    "host": {
      "classification": "deployment_configuration",
      "rationale": "bind host",
      "value": "127.0.0.1"
    },
    "port": {
      "classification": "deployment_configuration",
      "rationale": "bind port",
      "value": "5000"
    },
    "timeout": {
      "classification": "deployment_configuration",
      "rationale": "server timeout",
      "value": "60"
    }
  },
  "input_parameter": {
    "classification": "attacker_controlled_input",
    "rationale": "serve() takes model_uri from caller; advisory claims command injection via model URI in mlserver get_cmd",
    "value": "model_uri"
  }
}
```

### B 假设 7：hp003_b

request ID：`ab71249afa984e41a9bbfcff2d838152`；事件索引 145。

```json
{
  "constructor_parameters": {
    "config": {
      "classification": "deployment_configuration",
      "rationale": "backend config object",
      "value": null
    },
    "env_manager": {
      "classification": "deployment_configuration",
      "rationale": "env manager selection",
      "value": "local"
    }
  },
  "entry_boolean_arguments": {
    "enable_mlserver": {
      "classification": "deployment_configuration",
      "rationale": "mlserver path selected when enable_mlserver is true",
      "value": true
    }
  },
  "entry_value_assumptions": {
    "host": {
      "classification": "deployment_configuration",
      "rationale": "bind host",
      "value": "127.0.0.1"
    },
    "port": {
      "classification": "deployment_configuration",
      "rationale": "bind port",
      "value": "5000"
    },
    "timeout": {
      "classification": "deployment_configuration",
      "rationale": "server timeout",
      "value": "60"
    }
  },
  "input_parameter": {
    "classification": "attacker_controlled_input",
    "rationale": "serve() takes model_uri from caller; advisory claims command injection via model URI in mlserver get_cmd",
    "value": "model_uri"
  }
}
```

## 逐请求账本

| 序号 | 格子 | request ID | prompt | completion | cached hit | cached miss | total |
| ---: | --- | --- | ---: | ---: | ---: | ---: | ---: |
| 1 | A-hp003_a | `e383a423c4244d60b27e287bde9eb198` | 4308 | 427 | 0 | 4308 | 4735 |
| 2 | A-hp003_a | `fef9825eff0c4f879b160c2429666ee9` | 5607 | 150 | 4224 | 1383 | 5757 |
| 3 | A-hp003_a | `ec5eb6c123a94e5fb287ca08117ed29a` | 7020 | 112 | 5632 | 1388 | 7132 |
| 4 | A-hp003_a | `2e59b7d4b60140e4bbd192a6964343c6` | 5388 | 164 | 768 | 4620 | 5552 |
| 5 | A-hp003_a | `a3160ce9d10f4da59d65c5df3e553f7d` | 5676 | 172 | 5504 | 172 | 5848 |
| 6 | A-hp003_a | `c28abf9b7e2a489aaea1596f796ad2b5` | 5972 | 173 | 5760 | 212 | 6145 |
| 7 | A-hp003_a | `8204b7d3b1ce402f8004151a2cfe66d3` | 6269 | 173 | 6016 | 253 | 6442 |
| 8 | A-hp003_a | `b48440aba5a94a3589ff41a582cde38a` | 6566 | 173 | 6400 | 166 | 6739 |
| 9 | A-hp003_b | `d66bbf0776ca4fbf9bf14c1595744f03` | 4308 | 427 | 4096 | 212 | 4735 |
| 10 | A-hp003_b | `2fdfc62516d249eabd74101ee2575599` | 5607 | 140 | 5376 | 231 | 5747 |
| 11 | A-hp003_b | `97ef74169ba44c60983d71bcee1386bb` | 7010 | 111 | 5632 | 1378 | 7121 |
| 12 | A-hp003_b | `7513a167aebc4fb390ed3e2da22dfb89` | 5377 | 168 | 3456 | 1921 | 5545 |
| 13 | A-hp003_b | `0fe6b2bf4764483799610c55d46e9f9e` | 5669 | 164 | 5504 | 165 | 5833 |
| 14 | A-hp003_b | `ef53946f59554303bf9f7b80c9e7153b` | 5957 | 164 | 5760 | 197 | 6121 |
| 15 | A-hp003_b | `73728eb508b947d9be9124bcd7bcb04a` | 6245 | 162 | 6016 | 229 | 6407 |
| 16 | A-hp003_b | `b9e244438bfa4f66b649eeb4cb7ce86e` | 6531 | 162 | 6272 | 259 | 6693 |
| 17 | B-hp003_a | `5206a9b914454eac803757a355ef4356` | 4292 | 256 | 2688 | 1604 | 4548 |
| 18 | B-hp003_a | `23929579b0e94a44ab1ec09b353821cf` | 5012 | 240 | 4224 | 788 | 5252 |
| 19 | B-hp003_a | `da7679d896414f8486f024fd03ba894b` | 6800 | 144 | 5248 | 1552 | 6944 |
| 20 | B-hp003_a | `cec66c84cd02429fb2d9bc9d6944f5e1` | 5249 | 168 | 768 | 4481 | 5417 |
| 21 | B-hp003_a | `9b1b92f146b2437bae2001fa844a5962` | 5541 | 168 | 5376 | 165 | 5709 |
| 22 | B-hp003_a | `e2ea5245f08245028aa53e3b52d66af8` | 5833 | 162 | 5632 | 201 | 5995 |
| 23 | B-hp003_a | `6a06505dd86f40b1871d1ca830e36100` | 6119 | 162 | 5888 | 231 | 6281 |
| 24 | B-hp003_a | `a9dd8c74af97403f8d437aab269018a5` | 6405 | 161 | 6144 | 261 | 6566 |
| 25 | B-hp003_b | `844c920a43b4402f8ab8dc8052a69655` | 4292 | 256 | 4096 | 196 | 4548 |
| 26 | B-hp003_b | `718a0e0d9cd94940a3639747eecf7e1c` | 5013 | 188 | 4224 | 789 | 5201 |
| 27 | B-hp003_b | `8bd529a64ad8443ebfd6f9fa8658f380` | 5703 | 293 | 5120 | 583 | 5996 |
| 28 | B-hp003_b | `660ba5c44e8c448ebf369cd1e2094ff4` | 6110 | 334 | 5888 | 222 | 6444 |
| 29 | B-hp003_b | `ab71249afa984e41a9bbfcff2d838152` | 6508 | 341 | 6272 | 236 | 6849 |
| 30 | B-hp003_b | `3183c2a4e2ad41c5876c658366515434` | 6913 | 130 | 6656 | 257 | 7043 |
| 31 | B-hp003_b | `bcf8980c45f24b96823e5eba5f09c8a6` | 5592 | 173 | 2304 | 3288 | 5765 |
| 32 | B-hp003_b | `366c132649744da8a9e43dab8ab50264` | 5889 | 178 | 5632 | 257 | 6067 |

## 预检差异、产物与后续分支

- A-hp003_a：初始 source 前缀 2439 字符；初始请求 SHA256 `4a4e4ccd171a853a403d250a0fe4444f9df54025a18b0df6fe397776fde21258`。
- A-hp003_b：初始 source 前缀 2439 字符；初始请求 SHA256 `4a4e4ccd171a853a403d250a0fe4444f9df54025a18b0df6fe397776fde21258`。
- B-hp003_a：初始 source 前缀 3113 字符；初始请求 SHA256 `ee4d5442f0b37ad53f4279beb505e4d9327af9772f7aabc985b5bb3ceaece45f`。
- B-hp003_b：初始 source 前缀 3113 字符；初始请求 SHA256 `ee4d5442f0b37ad53f4279beb505e4d9327af9772f7aabc985b5bb3ceaece45f`。

B 的场景标记在绑定源码之外均为 0；A / B 共享同一工具定义、入口、advisory 主干和 E1 arm。A 的场景说明占用上下文预算，使 A source 前缀短于 B；这个预先披露的差异未在事后隐藏。不同 B 侧的模型假设并不强制相同；B-b 后来使用的 `config=null`、`env_manager="local"`、字符串 port/timeout 也不替换 B-a 未完成的真实轨迹。

原始运行目录：`artifacts/witness_scenario_matrix/90428b956f2b44e885c6e4461958dab5`，其中 `events.jsonl`、`results.json`、`request_audit.json` 分别保存完整事件、结果和原始自动审计。本次独立 gate 日志为 `artifacts/pytest_gate/0268ffd92bd448c9bdf9cb221db97fee/pytest.log`。本报告 companion 为 [phase1-summary.json](2026-09-29-phase1-summary.json)。历史和原始 artifact 未改写。

B-a 的独立复核主因 F1 在技术分支上符合阶段 2 的一轮通用修复条件，但事后发现的 **S4 硬停优先**。没有开始修复、B 重跑、近迁移或外部样本联网选样。账面剩余 178 请求 / 2,308,823 reported tokens 不构成硬停后的继续授权。

本阶段不能声称模型已在无场景标注的漏洞版自主获得 CONFIRMED，也不能据修复版两次字面量测量声称安全。没有把保护输入作为 detector 数据或 held-out 模型任务运行；但指纹和源码快照已经机械读取保护输入，不能再声明“未读取 held-out 输入”。所有模型结果仍保持 development / claim_eligible=false。

## 事后权限审计：S4 硬停

执行计划 §0 明确不授权“读取或运行 vulngym held-out 输入及其标签”。代码审计显示 `fingerprint_files` 递归纳入 `configs`，`source_fingerprint` 对所有这些文件执行 `read_bytes()`；`runtime/admission.py` 的模块导入即计算 `_loaded_fingerprint`。`snapshot_sources` 再次逐文件 `read_bytes()`，并把字节写入 `run/source/`。因此这不是仅统计文件名：已经发生保护输入的机械字节读取和复制。

本次审计仅使用已获授权的实现源码、运行 metadata 中的文件名和快照文件的 stat 信息，没有打开保护输入的内容。以下复制目标的存在和大小，加上源码中的读写路径，足以证明 S4；不需要读取任何标签或分析输入内容。

| 原路径 | 已生成快照路径 | 文件大小 bytes |
| --- | --- | ---: |
| `configs/datasets/vulngym_heldout_inputs.json` | `artifacts/witness_scenario_matrix/90428b956f2b44e885c6e4461958dab5/source/configs/datasets/vulngym_heldout_inputs.json` | 21573 |
| `configs/datasets/vulngym_heldout_inputs_v2.json` | `artifacts/witness_scenario_matrix/90428b956f2b44e885c6e4461958dab5/source/configs/datasets/vulngym_heldout_inputs_v2.json` | 21518 |
| `configs/datasets/vulngym_heldout_inputs_v3.json` | `artifacts/witness_scenario_matrix/90428b956f2b44e885c6e4461958dab5/source/configs/datasets/vulngym_heldout_inputs_v3.json` | 21393 |
| `configs/datasets/vulngym_heldout_inputs_v4.json` | `artifacts/witness_scenario_matrix/90428b956f2b44e885c6e4461958dab5/source/configs/datasets/vulngym_heldout_inputs_v4.json` | 19964 |

机械指纹/复制与 detector 使用必须分开：本阶段的模型任务仍只有 hp003 的四个 development 格子；没有观察到把这些保护输入送进 detector、作为选样依据或运行 held-out 模型任务。但“不被 detector 消费”不能替代字面授权边界，也不能消除已发生的读取。文件名元数据没有发现 label-named held-out 快照；这里不据此外推所有进程都未接触标签。

完整 gate 和源码保存原本获准执行，但其现有实现跨过了明示禁止的保护输入读取边界。不能自行把禁令改解释为“只禁止语义消费”，也不能在事后继续修复并发模型请求。运行结束时 `hard_stop=null` 的账本另存为 `artifacts/remaining_work_20260929/authorization_ledger_at_phase1_completion.json`；原始运行汇总不变。共享授权账本现在追加了事后 S4，companion JSON 也另记 `post_run_authorization_stop=S4`。所有后续阶段停止，等待用户决定该读取边界或修复范围；本次新增事实不证明 held-out 检出能力，也不支持 held-out 成绩。
