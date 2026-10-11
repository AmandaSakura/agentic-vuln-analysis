# 2026-09-30：设计审查逐项源码核验与修复

审查输入为 `docs/reports/cv_agent_design_review_and_repair_plan_2026-09-30.pdf`。已读全部 32 个物理页面及 `docs/TEST_CONTRACT.md`。实际源码 HEAD 为 `4dba622db459d4487bc8493b9af3a6a5f40a3387`，与报告一致；保留进入本任务前的汇总 JSON 修订、技术报告及用户审查 PDF。没有真实模型调用、网络实验、第三方目标执行、安装或历史实验重写。

## 已核实的共享问题

| 假设 | 实际复现 | 修复与限制 |
| --- | --- | --- |
| H01 | 两张既有实质票之后出现同 subject 的充分相反观察，最终仍接受旧票；两种顺序均复现 | `global-evidence-v2` 在 slow/fast 裁决前重新准入全部既有实质票。任务原提案、观察及费用保留，协议错误不吞掉。 |
| H02 | 已交付冲突也能进入原 fast | 该既有冲突已修；尚未执行的未来观察仍不属于 E5 固定票保证，新产品关闭早停。 |
| H03 | 5 项嵌套别名修改回归均失败 | Candidate、CodeDocument、ValidationSubject、ToolObservation 的公开容器封存和读视图隔离；原 JSON 形状与摘要算法保留。 |
| H08 | URLError 文本含 fake API key 时，异常和 `model_error` 事件暴露它 | 已知密钥在传输错误及事件中脱敏；正常和 HTTP 错误路径原控制保留。 |
| H09 | 最大合法图可运行，但未显式设业务限额；注入无进展超过冻结上限 | 配置图限额 16，最大八任务和有限循环退出分别验证；不是任意增加框架默认值。 |

H01 真正的语义失败日志是 `T06_before_verified.log`；前两份设置错误日志不是缺陷证据。H08 真正的失败日志是 `T12_verified_before_redaction.log`。日志位于 `artifacts/design_review_repair_20260930/`，所有初始失败都保留。

H04：原索引身份、见证库存和执行环境原本承担不同职责，不能说原代码只有一个摘要。新增产品四层身份及证据绑定，并保留旧算法。H05：原代码已累加任务 trace 和费用，最后一个模型判断仍可弃权；新产品按全部事实归并，未把旧判断换成隐式多数。H06：原 E 路径按已准入文档收费重新读取，不是无计费的文件越界；新产品提供有行区间的单独准入。H07：原请求锁、用量预留和恢复账本已有控制；保留并补测并发、失败和半写日志，没有为了假设必须成立而改坏已覆盖逻辑。

## 产品与任务卡

新增 `product_triage_v1`：本地源码→能力预检→字节快照/索引→确定性候选→静态工具→完整证书投递→全局性质归并→原子 JSON/报告。真实 CLI 测试显式拒绝导入 evaluation 包，并使用没有 API key 的子进程。目标源码中有导入即抛错的控制，证实只解析未执行。

T00–T09 及 T12 的默认静态路径实现见 `tasks.json` 和 `docs/reference/PRODUCT_REVIEW.md`。旧 E 配置、检索、witness 必需义务及任务均分政策保留；H01/H03/H08 和图业务限额在共享边界修复。T08 在产品中使用守恒共享池，2500+1000+1000+1000 的完整 JSON 证书封装在 8192 内通过；重投递增加 bytes，不增加生产者执行数。

任务控制区分 FINISHED+UNKNOWN、WAITING_INPUT、BLOCKED 和 FAILED。静态独立任务不等待未启用执行能力，真正数据依赖等待完成协议。显式补项能恢复依赖，重复错误输入在固定上限收尾。内部异常保存私有日志引用；非有限生产者 JSON 在规范化之前拒绝。分析阶段取消保留既有证明且不会启动后续工具。

上下文扩展只进入已授权字节清单，按完整封装收费，超预算不会把新 span 留在准入视图。公开产物不输出源码文本或凭据值；原始工具内容、错误及交付状态保存在权限为 0600 的私有账本，内容 hash 和 producer 引用可追溯。

## 初始失败与最终验收

初始完整套件为 **2560 passed, 2 failed in 478.78s**。两项已复查：新增报告目录与原严格文档目录清单冲突；清理测试的 2 秒在 traced import 阶段耗尽，未到 30 秒调用睡眠。文档清单只增加授权的 reports；清理夹具采用已有 wall-timeout 控制的 6 秒预算，SIGKILL、UNRESOLVED、worker_timeout、invoke、wall_timeout 和 tracer accounting 断言全保留。生产默认资源和隔离不变。

T13 完整套件、实际 CLI 演示、harness 和 A01–A34 的最终结果记录在 `acceptance.json`。本文会在这些验收完成后追加实际结果；初始绿色局部日志不代替完整套件。

修后第一轮完整套件为 **2682 passed, 1 failed in 414.94s**，日志为 `final_full_pytest_attempt1.log`。失败来自已有 applicable quorum 单测：内部状态没有 evidence，实质 ballot 也没有任何 trace。全局准入不能为了这种裸票跳过证据检查。该夹具已迁移为实际调用现有命令静态工具的有界观察，原“两票胜出、一票弃权、固定策略仍调度 authz”的断言全部保留。最终核对同时用失败回归修正了新产品归并器对生产者 helper references 的保留；规范化只消除 citation 和引用顺序，不丢掉准入使用的字段。随后对最终源码重新执行完整套件。

## 条件任务与未测量项目

T10/T11 的私有 scratch/native build 依照报告的条件分支保持 **UNSUPPORTED / NOT_ENABLED**。A27–A29 仍在矩阵里，没有删除、冒充通过或把 skip 当能力验收。默认静态产品不等待它们，GP2 未提供。

T14 已冻结前瞻协议 `.hermes/plans/2026-09-30-product-increment-preregistration.json`。真实授权样本、人工 paired review 和新模型预算没有提供，因此 GP3/GP4 **NOT_MEASURED**；没有所谓模型净增量成绩。原 **G-A=NO**、72 次请求/447812 reported tokens 及污染披露均保留。

## 最终实际结果（2026-10-01，新加坡时间）

- 完整 `uv run --no-sync pytest`：**2684 passed in 414.20s**，退出 0，没有 skip/xfail。
- 启用能力集合：**126 passed in 3.96s**；旧身份、证据准入、预算、调度及特征化控制包含于完整套件。
- `uv run --no-sync cv-agent harness-check`：**PASS**，退出 0。
- 七个新产物目录的真实 console CLI 演示全部通过；另一次调用公共 `cv_agent.cli:main` 的拒绝式 spy 测得 HTTP/socket/live gate 尝试均为 **0**，不导入 evaluation 或目标模块。
- 默认静态产品对应 **31/31 必需 A 项通过**；**3 条件 A 项未启用/未运行**，明确保留。GP0 PASS、GP1 PASS_FOR_ENABLED_STATIC_PROFILE；GP2 NOT_ENABLED、GP3/GP4 NOT_MEASURED。
- 原用户审查 PDF、技术报告 PDF/LaTeX、先前完成的 final-summary JSON 修订的 SHA-256 均未变化。docs/README 仅追加导航及明确报告基线。

完整逐卡 receipt、测试命令、退出码、失败和通过日志 SHA-256、兼容说明、剩余条件分别在 `tasks.json`、`acceptance.json`、`final-source-manifest.json` 中。修改尚未提交，不宣称工作区干净或整个项目研究目标已达成。
