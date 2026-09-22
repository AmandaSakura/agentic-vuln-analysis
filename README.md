# cv-agent

**代码漏洞候选点审查与全流程挖掘的多智能体（Multi-Agent）系统。**

本项目针对传统静态代码分析工具（SAST）**误报率极高**、以及大语言模型（LLM）直接通库扫描**幻觉严重且 Token 成本巨大**的双重痛点，提出了一套 **“全仓静态粗筛 ➔ 上下文检索增强 ➔ 规划器任务拆解 ➔ 多专家协同分析 ➔ 法定人数表决（Quorum）”** 的两阶段漏斗型代码安全审计架构。

---

## 💡 核心设计思想

1. **两阶段漏斗式过滤（Two-Stage Funnel）**
   - **粗筛（广度）**：不直接将整个仓库的成千上万行代码粗暴塞给大模型，而是先由轻量确定性扫描器（AST 语法树分析与规则匹配）在全仓快速建立索引，定位所有潜在的危险 Sink 点与 API 路由入口，自动产出候选点清单（`Candidate Inventory`）。
   - **精审（深度）**：将粗筛提取出的可疑靶点，逐个交由多专家 Agent 专家团进行深度上下文追踪与实证验证，解决“这个位置在真实运行时到底能不能被攻击者利用”的核心问题。

2. **多专家协同与职责分离（Specialist Separation of Concerns）**
   - 复杂的漏洞验证需要跨代码层面的综合研判。我们将代码审查职责解耦为三个具备独立工具集和 Mandate 的专家智能体：
     - **🔍 扫描专家 (`scan`)**：核实 AST 结构语法特征、外部调用链可达性与局部沙箱探针验证；
     - **🌊 污点专家 (`taint`)**：深挖从 Source 输入端到 Sink 危险端的数据流流动、参数传递与清洗过滤（Sanitizers）；
     - **🛡️ 鉴权专家 (`authz`)**：核对访问控制、身份认证、租户边界隔离与路由守卫（Guards）。

3. **法定人数多数仲裁机制（Quorum Adjudication）**
   - 避免单个 Agent 的主观幻觉或偶发误判。每个专家在各自独立的 ReAct 工具循环中收集证据，最终投出结构化选票（`AgentExpertVote`：`VULNERABLE` / `SAFE` / `ABSTAIN`，包含置信度与引用的证据 ID）。
   - 引入受分布式共识启发的 Quorum 机制：既保证多数人达成一致时的可靠性（E4 完整表决），又支持在主要专家意见高度一致时提前截断（E5 早停），在保障准确率的同时大幅削减大模型 API 成本。

---

## 🏗️ 架构与完整工作流

```text
                    ┌────────────────────────┐
                    │      代码仓库源码      │
                    └───────────┬────────────┘
                                │
                  [阶段一：全仓遍历与静态粗筛]
                                │ (StaticScanner / AST 规则 / 路由发现)
                                ▼
                    ┌────────────────────────┐
                    │   可疑候选点清单        │
                    │  (Candidate Inventory) │
                    └───────────┬────────────┘
                                │
                  [阶段二：Code-RAG 上下文检索]
                                │ (Call Graph / 跨文件 AST / BM25)
                                ▼
                    ┌────────────────────────┐
                    │  规划器 (Planner) 任务拆解 │
                    └───────────┬────────────┘
                                │
               ┌────────────────┼────────────────┐
               ▼                ▼                ▼
        🔍 扫描专家 (`scan`)   🌊 污点专家 (`taint`)  🛡️ 鉴权专家 (`authz`)
        - 跨文件调用链追踪      - Source-to-Sink 数据流 - 路由与身份边界
        - 局部沙箱探针验证      - 参数清洗/过滤分析     - 鉴权逻辑有效性
        - 投出 Scan 选票        - 投出 Taint 选票       - 投出 Authz 选票
               └────────────────┼────────────────┘
                                │
                                ▼
                    ┌────────────────────────┐
                    │   法定人数仲裁 (Quorum) │ (E4 全量表决 / E5 早停裁定)
                    └───────────┬────────────┘
                                │
                                ▼
                    ┌────────────────────────┐
                    │ 最终判定 / 证据链 / 账本│
                    └────────────────────────┘
```

---

## 📊 系统演进路线（E1–E5 & V1–V5）

仓库当前的主力系统为 **E1–E5**，同时保留了 V1–V5 确定性基线用于对照消融实验：

| 系统 | 检索增强 (Code-RAG) | 调度与专家团 | 仲裁决策机制 |
| :--- | :--- | :--- | :--- |
| **E1** | 本地代码切片（Local Context） | 单一扫描专家 (`scan`) | 单票裁定 |
| **E2** | 全局 BM25 文本检索 | 单一扫描专家 (`scan`) | 单票裁定 |
| **E3** | 基于 AST 与跨文件调用图检索 | 单一扫描专家 (`scan`) | 单票裁定 |
| **E4** | 基于 AST 与跨文件调用图检索 | 规划器 + 三专家协同 (`scan`, `taint`, `authz`) | **完整多数表决**（收集全部选票后多数裁定） |
| **E5** | 基于 AST 与跨文件调用图检索 | 规划器 + 三专家协同 (`scan`, `taint`, `authz`) | **高置信度早停表决**（前两票一致且高置信时提前截断） |

---

## 🚀 快速上手与使用方式

### 模式 1：全仓端到端自动扫描与审查（Discovery ➔ Review）
针对一个完整的代码仓库，自动完成“全仓粗筛 -> 提取候选 -> 专家团会诊审查”：
```bash
# 执行 Python 仓库端到端 Pilot 扫描与多专家审查
uv run --no-sync python -m cv_agent.evaluation.runners.run_python_repository_pilot
```

### 模式 2：针对单点候选位置进行靶向精审（Candidate Review）
当从 CI/CD 流程、传统 SAST 报警（如 Semgrep / CodeQL）获取到明确可疑位置，或在基准测试集中进行单点复测时：
```bash
# 针对具体的测试 Case ID 启动真实模型多专家审查
bash scripts/deepseek.sh agentic-live-owasp --case-id BenchmarkTest0001 --system E5_GRAPH_FAST_SLOW
```

### 模式 3：离线本地无凭据验证（开发与回归自测）
不需要任何外部大模型 API Key，使用内置脚本化模型验证全流程连通性与逻辑完整性：
```bash
uv run --no-sync pytest                     # 全量离线单元与回归测试
uv run --no-sync cv-agent harness-check      # 检查实验契约与工具链
uv run --no-sync cv-agent synthetic          # 运行确定性双样本连通性检查
uv run --no-sync cv-agent agentic-smoke     # 验证 LangGraph 专家与工具调用连通性
uv run --no-sync cv-agent agentic-eval      # 验证多专家 Quorum 表决与误报消除逻辑
```

### 模式 4：真实模型基准实验与门禁
```bash
bash scripts/heldout_gate.sh                # 10 项核心开发门禁（调用真实模型）
bash scripts/heldout_matrix.sh              # 30 项完整评测矩阵（调用真实模型）
```
> **说明**：真实请求会通过 `OpenAICompatibleChatModel`，并在发起真实调用前执行完整离线测试阻断门禁。提供商和凭据由被 Git 忽略的 `.env.experiments` 配置（模板见 `.env.experiments.example`）。

---

## 📂 代码分层与核心模块

| 目录 / 文件 | 职责说明 |
| :--- | :--- |
| `src/cv_agent/agents/scanner.py` | **前端静态扫描器**：基于 AST 与正则规则粗筛，生成初筛候选点（支持命令执行、动态求值、SQL、模板、鉴权路由等 7 类规则） |
| `src/cv_agent/agents/discovery.py`| **仓库级自动发现**：递归遍历源码库，生成全仓 `Candidate Inventory` |
| `src/cv_agent/agents/` | **多智能体核心**：ReAct 循环引擎（`react`）、动态任务规划（`planning`）、Quorum 投票仲裁（`voting`）、工作流调度（`workflow`） |
| `src/cv_agent/retrieval/` | **Code-RAG 检索层**：跨文件调用图检索、符号索引、BM25 文本检索与上下文预算裁剪 |
| `src/cv_agent/tools/` | **工具注册与分析**：AST 结构查询、静态数据流、权限检查、命令拼接检查与局部隔离探针 |
| `src/cv_agent/code_adapters/` | **多语言源码解析**：Python、Java、JS/TS、Go 语法树解析与符号加载 |
| `src/cv_agent/domain/` | **核心领域契约**：`Candidate`、`Evidence`、`AgentExpertVote`、`Verdict` 等类型定义 |
| `src/cv_agent/runtime/` | **底层运行时**：大模型协议传输、完整测试门禁、请求追踪与 Token 预算记账 |
| `src/cv_agent/evaluation/` | **实验与评测体系**：数据集协议、端到端评测执行流、统计指标与门禁控制 |
| `src/cv_agent/baselines/` | **历史基线**：保留的原 V1–V5 确定性基线系统 |

---

## 📖 进阶阅读与文档导航

1. [当前状态](docs/CURRENT_STATUS.md)：已完成工作、实验结果和已知边界说明。
2. [架构与阅读路线](docs/ARCHITECTURE.md)：沿数据流阅读核心实现。
3. [端到端系统规格定义](docs/reference/FULL_SYSTEM_SPEC.md)：系统最初的设计规范与契约。
4. [实验指南](docs/EXPERIMENTS.md)：配置、入口、原始日志与验收口径。
5. [测试契约](docs/TEST_CONTRACT.md)：修改分析器、证据链或运行逻辑前必读。
6. [历史重构记录](docs/history/records/REFACTOR_2026-09-21.md)：模块化重构、逐批测试与兼容性记录。

完整阅读路线见 [文档导航](docs/README.md) 与 [配置导航](configs/README.md)。
