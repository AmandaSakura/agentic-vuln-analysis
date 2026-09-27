# B 方案修订版（rev1）：有界执行见证 — 可交付执行

基于 `2026-09-27-bounded-execution-witness-design.md`。原设计的总体方向、隔离分层（审计钩子只观测，不当沙箱）和两阶段 Bash 重放保留；本文件只列**拍板结论**和**必须修改/补充的点**，执行者以本文件为准，冲突处以本文件覆盖原设计。

执行前必读：`AGENTS.md`、`docs/TEST_CONTRACT.md`。本任务不发任何模型请求。

---

## 0. 先提交现有工作（执行者第一步）

- 在当前分支 `fix/candidate-evidence-review-loop` 提交现有改动与未跟踪的 `src/`、`tests/`、`configs/`、`docs/`、`scripts/` 文件，遵守 `.gitignore`，不改历史产物。
- `.hermes/` 是否入库由用户决定；未获明确同意前不提交。
- 提交前跑完整 `uv run --no-sync pytest`，失败则停下报告，不提交。

## 1. 范围拍板（接受“第一版修复版只给局部字面量见证”，并收紧为下列规则）

| 观测 | 候选级 `validation_status` | 记录方式 |
| --- | --- | --- |
| 危险见证成立（见 §2 全部条件） | `CONFIRMED` | `FixtureProofScope(coverage="candidate", method="bounded_execution", supported_statuses=(CONFIRMED,))` |
| 字面量保留 | **`UNRESOLVED`** | `raw_status="LITERAL_OBSERVED"`，只作局部测量 |
| 其他任何情况（未到达边界、首事件非目标、钩子/沙箱自检失败、依赖或来源不符） | `UNRESOLVED` | `raw_status` + 缺口列表 |

- **不产生 `REFUTED`。** 原设计写的是"REFUTED 限定为一次调用的局部观测"，这里改掉：现有消费端（`evidence_policy.fixture_can_support_candidate`）会把 `REFUTED` 当作候选级反证，局部含义会在下游丢失。用 `supported_statuses=(CONFIRMED,)` 在类型层面堵住，不靠文档约定。
- 原整函数候选的 SAFE 本版不做，保持 `UNRESOLVED`。
- 两个快照的差异（a 触发、b 不触发）可以作为**诊断性差分**单独报告（例如 `witness_differential.json`），不写入原候选 TP/TN，也不注册为工具输出。

## 2. 危险见证的成立条件（原设计缺少调用点绑定，必须补）

`CONFIRMED` 要求以下条件**全部**满足：

1. **绑定候选。** 命令事件发生时，审计钩子遍历调用栈，栈中必须有候选入口帧：`co_filename` 的真实路径位于已核对的 checkout 内，文件 SHA256 与 subject 记录一致，函数为 `PyFuncBackend.serve`。导入阶段或入口帧之外（其他线程、atexit 等）的事件一律不计入，只记录。
2. **记录发出位置。** 记下直接发出事件的源码帧（文件、行号、文件 SHA256）。事件在 `serve` 帧之下即可成立（整函数候选的性质是“存在危险路径”）；是否落在 `critical_operation` 声明的 `backend.py:311-317` 另行标注，不作为 V 的前提。
3. **argv 含本次运行的随机探针**，而且是在 argv 里，不能只出现在 env 里。
4. **Bash 重放发生展开**，同时同形良性对照（不含元字符、nonce 不同）正常、无展开。
5. 钩子自检、seccomp 自检、导入来源核对全部通过（见 §3）。

**首事件处理。** 保留“首个命令事件后中止”的做法，但按帧区分：
- 入口帧之前的事件：记录，并在钩子里抛异常。导入阶段就中止的，记缺口 `import_time_command_event`。
- 入口帧之下的首个事件：按上面条件 1–4 判定。不含探针的，记缺口 `preempted_by_unrelated_command_event`，不得判 SAFE。

## 3. 隔离与来源（在原设计上补这些具体要求）

- **后备阻断。** worker 进程在导入目标之前加载 seccomp，拒绝 `execve`/`execveat`；复用 `src/cv_agent/tools/validation/fixtures.py` 现有的 seccomp 机制，不要拒绝 `clone`，否则线程会坏掉。加载后必须自检：尝试 `os.execv("/bin/true", ...)`，必须得到 `EPERM`，否则整次运行记 `UNRESOLVED`。
- **钩子自检。** 在导入目标之前，触发一个自定义审计事件，确认钩子被调用。
- **来源。** 目标 mlflow 通过 `PYTHONPATH` 指向固定 checkout，导入后核对 `mlflow.__file__` 及相关模块的 `__file__` 都在 checkout 内，并和 subject 的摘要一致。site-packages 里不得有 mlflow。
- **依赖。** 每个快照一个 venv，在沙箱外、有网络的准备步骤中安装，保存 `pip freeze` 和各包 hash。见证运行时禁网络。两版依赖不一致时记录差异。
- **严禁打桩目标内部。** 唯一允许的拦截点是进程创建边界（钩子加 seccomp）。不得 monkeypatch `_download_artifact_from_uri`、`_get_root_uri_and_artifact_path`、`get_artifact_repository`、任何 `ArtifactRepository`，也不得修改 `get_cmd`。B 路线的意义就在于真实执行注册表分派；中途失败（例如缺 MLmodel 文件）就记缺口，不要绕过去。清单校验器必须拒绝任何声明了额外 stub 的清单。
- **Bash 重放环境。** 使用 `bash --norc --noprofile`，env 用最小白名单，不继承捕获的 env。捕获 env 中若有 `BASH_ENV`、`ENV`、`SHELLOPTS`、`BASH_FUNC_*`，只记录，不带入。只接受 `['bash'|'sh'|绝对路径, '-c', S]` 这类形状；`shell=True` 按等价形状规范化，其他形状一律 `UNRESOLVED`。

## 4. 清单卫生（防止 oracle 泄漏）

- 调用清单只来自 advisory 文本（入口、输入参数、前置条件）和公开的构造方式。两个快照使用**同一份**清单和同一个探针模板，每次运行的 nonce 随机生成。
- 清单里不得出现 `revision_role`、case ID 到标签的映射，也不得包含对修复位置的提示。
- 文件系统前置条件（名字含元字符、真实存在的模型目录及其内容）由清单声明，由见证器在临时目录中生成，并记录内容摘要。

## 5. 离线正反控（合成 fixture，进 pytest，不依赖 mlflow）

原设计的四组保留：直接拼接、`shlex.quote`、helper 先执行命令、引用后改 argv。再加以下几组：

| 用例 | 期望 |
| --- | --- |
| 命令事件发生在导入阶段 / 入口帧之外的线程 | 不计入；`UNRESOLVED` 并带对应缺口 |
| 探针只出现在 env，不在 argv | 非 V，`UNRESOLVED` |
| 良性对照也"展开"或重放失败 | `UNRESOLVED` |
| 钩子未安装 / seccomp 自检失败 / `__file__` 来源不符 | `UNRESOLVED` |
| 清单声明内部 stub | 清单校验拒绝 |
| 同源码、翻转 `revision_role` | 输出字节级一致（C2） |
| 字面量保留的情况 | 候选级必须是 `UNRESOLVED`，永不出现 `REFUTED`/SAFE；消费端 `fixture_can_support_candidate` 对它返回 False |
| helper 先执行、且含探针并展开 | `CONFIRMED`，并记录发出位置不在 311 |

每个用例都要有正控，对应断言不得放宽。改完后跑完整 `uv run --no-sync pytest` 和 `uv run --no-sync cv-agent harness-check`。

## 6. 停点

1. **停点 1：** §0 提交完成，加上 §5 全部通过。交付变更摘要、测试日志和新增用例清单，**然后停下，等用户确认**。
2. **停点 2（用户确认后才做）：** 准备两个 venv，用同一份清单对 hp003_a/b 各运行一次见证。这是开发诊断，不进 pytest，`claim_eligible=false`，不请求模型。交付每次运行的完整产物（原设计列出的字段，外加 §2 的帧绑定记录和 §3 的自检结果）以及缺口列表。**然后停下。**
3. 是否发起 hp003 的单臂模型请求由用户另行决定；三臂对比继续暂停。

## 7. 本版明确不做

原候选 SAFE；静态注册表建模（A 路线）；推广 `hp003_callsite.py` 的手写 wrapper；Jev 或路由实验；任何模型 API 请求。
