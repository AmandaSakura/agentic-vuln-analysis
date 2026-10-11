# 离线源码审查：v1 默认入口与 v2 恢复试用版

2026-10-01 的恢复工作增加显式 `product_triage_v2`，默认仍为 v1。v2 将完整私有证据保存与分享摘要分开，以精确 AST 操作身份区分同一行的调用。它是有界静态试用版；实际用户失败、独立人工质量和审阅净收益尚未测量，原 G-A=NO、GP2 未启用、GP3/GP4 未测量。

## v2：安装与本地复核

固定发行物及离线命令见 [恢复发行安装说明](../../audit/product_recovery_20261001/release-final-patch2/install.md)。验收平台是 Linux x86-64、Python 3.13.5；元数据要求 Python ≥3.12，其他解释器和平台尚未做发行验收。安装依赖由现有已安装文件按 RECORD 哈希核对后重新封装，清单明确记录本地 wheel 哈希，不声称与上游 wheel 容器相同。发行物省略 evaluation、测试、研究 workflow 和模型 transport，保留静态导入所需的共享工具定义和 Pydantic/Tree-sitter 依赖。

Git 仓库保存源码、安装说明和验收回执；发行 ZIP、wheelhouse 和运行产物保留在本地。仅从 GitHub 克隆时，按仓库 README 使用 `uv sync --locked` 安装源码环境，再通过 `uv run --no-sync cv-agent ...` 运行下列命令。

使用完整发行包安装后，可从仓库外运行：

```bash
cv-agent doctor /path/to/authorized/source
cv-agent review /path/to/authorized/source --output /path/to/new-run --profile product_triage_v2 --summary-bytes 8192
cv-agent verify /path/to/new-run
cv-agent view /path/to/new-run --candidate-id operation-ID --source-root /path/to/authorized/source
```

`candidate_id` 从 `result.json` 取得。`view` 先验证完整私有包，再核对当前源码字节身份和准确操作，才显示本地片段；源码变化返回 `SOURCE_DRIFT`。`verify` 从封存字节重建 AST、绑定元数据和完整操作清单，核对文件、记录、subject、上下文及性质归并，并重放已登记静态分析。它验证使用者自有包的一致性，不认证任意外部生产者来源。每次复核的静态重放另耗 CPU；只读 verify/view 尚不使用 review 的子进程资源上限。

完整运行包含 `result.json`、`report.md`、`share.json`、`manifest.json` 和私有 `.private/`。私有目录 0700、证据文件 0600；其中包含获准源码、原始观察、上下文和错误信息。复制整个目录会复制这些私有材料。分享时选择 `share.json`；它固定 `NOT_VERIFIABLE`，只给未决表达及本地结论是否可访问的提示。哈希和摘要不取得独立强结论资格。源码路径及行列仍是可见元数据。

`--summary-bytes` 只约束分享件 finding 正文的序列化 UTF-8 字节，固定元数据明确豁免；不是整个 JSON 文件大小上限。摘要缩到 1 byte 时，本地完整证据及其有限性质状态保持不变，分享件可以省略全部候选。v2 不接受旧的 `--observation-bytes`，以免混淆两种预算。

| v2 阶段 | 状态与分母 |
| --- | --- |
| 源码 | 已枚举、已读、已解析、读取/解析错误；提前停止时 `inventory_complete=false`，没有枚举的仓库余量未知 |
| 候选分析 | `NOT_STARTED / COMPLETED / BLOCKED / FAILED`；四项之和等于候选总数 |
| 记录保存 | `NOT_ATTEMPTED / COMPLETE / FAILED`；失败记录不能提供强状态 |
| 本地复核 | `VERIFIED / INCOMPLETE / UNAVAILABLE`；完整记录与静态准入都必需 |
| 性质 | `SUPPORTED / REFUTED / UNKNOWN / CONFLICT`；冲突有充分证据，但不算无冲突解决 |

完成分析可以留下 UNKNOWN。内置报告显示最多 10 项优先队列，完整分母留在 JSON；每项给出事实、前提、具体缺项、责任方、必要输入、再分析步骤和完成条件。分析器内部异常或材料保存故障会停止后续工具，保留此前已经完整登记的事实；取消同样停止后续分析。进程被资源边界强制终止或最终输出失败时，只报告阶段错误和未经复核的耐久进度引用，计数为 null；不把未知写成零。

### v2 的支持范围与边界

强性质仅在已有静态契约覆盖时成立。权限检查支持准确调用处的字面整数 mode 和已建模绑定；`mode = 0o600; os.chmod(path, mode)` 目前仍 UNKNOWN。命令和 eval 保留已有解释器范围；同一行存在多个已登记操作、需要行级绑定的非权限检查时，v2 明确阻塞该精确操作检查，不能借邻近调用的结论。普通参数构造（如 `str`、`Path`、`compile`）本身不算第二个登记操作；原验证器仍分析完整片段和嵌套表达式的副作用，未支持语义仍 UNKNOWN。其他 AST 候选是审阅线索。应用安全、公共可达性和远程权限都未评估。

每个文件先封存字节，再从同一份内容解码、解析和提取片段；这是逐文件版本封存，不保证活跃工作树在全仓时刻上原子一致。身份分别记录源码、语义引擎/资源政策、获准视图和展示政策，改变摘要预算只改变展示身份。v1 历史候选 ID 和索引摘要算法保留；v2 ID 单独版本化，含路径、起止行、UTF-8 字节列、节点/规则版本和字节摘要。

Linux review 的固定静态子进程有 120 秒墙钟、120 秒 CPU、1 GiB 地址空间上限；输入还有 1000 文件、10 MiB 源码、200000 AST 节点、1000 个分析候选和 64 MiB 原记录上限。单份工具观察独立限制为 2 MiB。这些是试用政策上限，RSS 实测不是地址空间上限的证明，1000 候选也不承诺一定能在时限内完成。子进程只运行项目静态实现，源码不会被导入执行。

已有目录、并发创建目录和符号链接不能被发布替换。文件及嵌套目录同步后，通过 Linux `renameat2(RENAME_NOREPLACE)` 提交，再同步父目录；不支持该原语时明确失败。提交后的 `completion.json` 是非权威时间诊断，不能修改证据 manifest。未提交的私有临时目录保留为故障材料，不能称为成功完整包。

工程控制、实际日志与逐项 F/R/V 状态见 [恢复核验记录](../../audit/product_recovery_20261001/verification.md) 和 [恢复验收矩阵](../../audit/product_recovery_20261001/acceptance.json)。36 个其他 agent 设计的中性控制仅为工程夹具：22 个精确状态匹配、0 个错误强状态，14 个命名 mode 构造仍未覆盖；参考没有为 UNKNOWN 改写。它们不代表独立人工质量、held-out 检出率或 FPR。人工评估的前瞻约束见 [恢复试用协议](../../audit/product_recovery_20261001/recovery-protocol.json)。

## 默认 v1 与历史语义

这条路径接受使用者明确选择的本地 Python 源码目录，完成快照、索引、候选发现、适用静态检查和结果导出。默认不需要 API key，不导入目标源码，不启动模型、planner、Jev、多专家、quorum、早停或执行见证。

```bash
uv run --no-sync cv-agent doctor /path/to/authorized/source
uv run --no-sync cv-agent review /path/to/authorized/source --output /path/to/new-review-run
```

输出目录必须尚不存在。成功、零候选、解析失败、能力阻塞、局部预算耗尽及分析阶段取消均可生成 `result.json` 和 `report.md`。完成返回 0；部分、阻塞、失败或取消返回 2。配置参数或输出目录本身不能使用时，CLI 输出结构化错误，不覆盖既有目录。

## 性质与运行状态

性质状态是 `SUPPORTED / REFUTED / UNKNOWN / CONFLICT`，运行状态是 `COMPLETED / PARTIAL / BLOCKED / FAILED / CANCELLED`。任务控制态还区分 `WAITING_INPUT`；它是显式业务输入等待，不是语义证明。完成的静态检查可以留下 UNKNOWN。取消保存已经登记的证据，并停止后续工具。

| 结果 | 含义 |
| --- | --- |
| SUPPORTED | 完整、匹配的观察支持明确声明的有界性质 |
| REFUTED | 完整、匹配的观察否定同一有界性质 |
| UNKNOWN | 只有线索、未知语义、局部事实或未完成/未投递的证书 |
| CONFLICT | 同身份、同前提、同完整范围的充分证明互相矛盾 |

所有 finding 固定 `application_security=NOT_ASSESSED`。权限位性质的否定不表示整个应用安全；本地静态事实不建立公共入口可达性或远程调用权限。原研究标签 `VULNERABLE/SAFE/ABSTAIN` 和验证器状态 `CONFIRMED/REFUTED/UNRESOLVED` 保留原语义。

| 能力 | 默认支持范围 |
| --- | --- |
| Python 候选发现 | AST 中确定性语法线索；注释和伪状态不是证明 |
| 权限 mode 检查 | 现有 `validate_permission_mode` 的候选行、绑定及有界模式解释 |
| 命令构造检查 | 现有 `inspect_command_construction` 和共享准入函数；未建立输入控制或语义时 UNKNOWN |
| Python eval 检查 | 现有有界 AST 模型；不导入、运行目标模块 |
| 其他性质 | 静态线索和人工复核缺项，UNKNOWN |
| 模型说明、目标执行、私有 scratch、native build | 未启用；不阻塞默认静态路径 |

源码清单保留解析失败文件的分母和原始字节摘要。源码符号可被解析，不表示任意 Python 语义被完整解释。默认排除 `.git`、虚拟环境、依赖/构建目录，以及 `data`、`artifacts`、`audit`、`.hermes`；项目自身受保护的数据、运行和评价输入目录不能作为产品根。

## 数据流与权威边界

```mermaid
flowchart LR
  A[显式本地源码根] --> B[能力预检]
  B --> C[字节快照与 AST 索引]
  C --> D[确定性候选]
  D --> E[适用静态工具]
  E --> F[原始生产者观察]
  F --> G[完整证书投递与字节预算]
  G --> H[全局确定性归并]
  H --> I[JSON 与人工报告原子提交]
```

`application/service.py` 调用已有工具。presentation 只渲染 `ReviewResult`，不重新分析源码或增加证明。产品没有模型最终 JSON 这一必经环节。

原始生产者 ID 标识一次调用；引用别名和角色数不增加生产者。充分观察不会被后来的无关 UNKNOWN 覆盖。部分或不匹配的局部安全事实不能否定另一份完整支持。复杂范围包含关系不做自然语言推断，只接受规范字段精确匹配。

命令工具仍保存原始 `validation_status=UNRESOLVED`；已有静态准入函数建立的有限结论单独投影到 `accepted_static_status`，没有重命名成执行见证。完整证书缺失、截断或隐藏时不能据私有结果形成强性质状态。

## 身份与上下文

| 字段 | 输入与版本 |
| --- | --- |
| `source_digest` | `source-bytes-v1`：排序的根相对 Python 文件路径和完整原始字节 SHA-256；不可读项明确为 null |
| `analysis_contract_digest` | `analysis-contract-v1`：profile、性质契约、规则、预算/排除政策、相关分析代码摘要、Python 和实际 parser/Pydantic 版本 |
| `execution_digest` | 默认 null；仅显式可信环境 manifest 才能构造 `approved-execution-v1` |
| `retrieval_view_revision` | `retrieval-view-v1`：规范文件路径及准入行区间 |

原 `ValidationSubject.source_digest` 仍采用既有索引 JSON 摘要算法，没有静默替换。产品证据另外绑定字节身份和分析契约身份。改变源码或分析实现使相应产品身份失效；单纯扩大获准视图不改变源码身份。规范 JSON 拒绝非有限数，路径拒绝绝对路径、父目录跳转和非规范形式。

默认静态索引明确准入完整支持文件；内部索引不是模型上下文投递。需要限定初始分析范围和显式扩展时，可使用 `--context-grants grants.json --context-bytes 8192`：

```json
{
  "version": "source-grants-v1",
  "initial": [
    {"path": "entry.py", "start_line": 1, "end_line": 4, "reason": "selected entry"}
  ],
  "extensions": [
    {"path": "helper.py", "start_line": 1, "end_line": 2, "reason": "explicit helper context"}
  ]
}
```

扩展只接受已有授权清单内的源文件，并重新核对字节摘要。完整扩展封装的 UTF-8 字节计费成功后才准入；预算拒绝不改变视图。路径相同不能免费读取另一个行区间，重复投递也计费。原 E1–E5 的检索边界及任务均分政策没有为此改变。可见 helper 不等于已经证明它是运行时 callee。

## 预算、日志与产物

默认全局工具观察预算为 8192 字节，可用 `--observation-bytes` 显式设置。共享池不会按任务平均切分；分配接口支持为必需证书预留已验证的最小尺寸并事前拒绝不可行计划。当前产品静态检查没有“必须证明成功”的义务，保留独立诊断空间，超出投递预算形成 PARTIAL 和缺项。字节是序列化 UTF-8 大小，不是 provider reported tokens。

证书缓存保留不可变生产者 bytes。每次重投递都增加投递字节，保持原生产者 ID；它不调用生产者或增加物理执行数。产品静态工具的 `physical_executions=0`；工具调用单独计数。

公共 JSON/报告省略源码文本和凭据值，业务 reason 中有标签的秘密作展示脱敏。原始工具观察及内部异常位于 `.private/observations.jsonl`，文件权限 0600、目录 0700；证据引用和内容 SHA-256 可追溯到该私有账本。脱敏不修改原源码摘要。文件名、源码位置和明确声明的范围本身仍属于报告信息。

JSON 与 Markdown 用同一临时目录原子提交。`accounting` 区分准备、分析、模型、门禁及产物准备耗时；默认 gate/model 时间为零。`.private/completion.json` 另外记录包括提交在内的输出墙钟，避免把最终序列化之后的时间伪装成 JSON 内的精确自测时间。

`runtime/journal.py::audit_journal` 对已有事件做只读恢复审计：未结束行、损坏记录、无响应请求和未知用量都明确列出；未知不是零，它不退款或自动重发。原真实模型入口、进程内完整 pytest 门禁及实验账本仍保留。

## 验证与研究边界

实现和任务验收见 [逐项源码核查记录](../../audit/design_review_20260930/verification.md)、[验收矩阵](../../audit/design_review_20260930/acceptance.json) 和 [实施计划](../../.hermes/plans/2026-09-30-design-review-repair.md)。完整 pytest 与新产品真实 CLI 分别验收；可选 checkout 测试的 skip 不能用来发布 scratch/native 能力。

原 G-A 仍为 NO。GP0/GP1 是这条新静态交付路径的工程门槛；GP2 条件执行能力仍未启用；GP3 的人工价值和 GP4 的模型净增量没有测量。新的 [增量评估协议](../../.hermes/plans/2026-09-30-product-increment-preregistration.json) 已冻结为前瞻方案，未提供样本、人工评估或模型预算时不执行，不拿单测数量替代用户价值。
