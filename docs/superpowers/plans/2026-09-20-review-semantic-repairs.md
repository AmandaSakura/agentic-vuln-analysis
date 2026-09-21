# Review Semantic Repairs Implementation Plan

**Goal:** 修复 CODE_REVIEW_2026-09-20.md 的六组缺陷，保留正反控制与原始实验记录。

**Architecture:** 权限验证仅解释明确可执行的受支持语句。命令分析用独立的有界 AST 值解释器保留字符串片段，从 helper 的实际返回值追踪至 caller 的 shell 参数；未知语义显式保持不确定。证据引用保留角色，汇总保留全部原始结果。

**Tech Stack:** Python 3.12、AST、Pydantic、pytest。

本轮在当前任务内直接实施，不提交现有混合工作区，不调用模型 API。

## 1. 行为回归

- [x] 新建 `tests/test_review_semantics.py`，加入报告中的权限三例、命令五例、反证引用和额外行；加入可达权限、正确转义、原始命令控制。
- [x] `uv run --no-sync pytest tests/test_review_semantics.py`，记录修复前失败。

## 2. 权限语义

- [x] 修改 `src/cv_agent/validation_tools.py`：函数预分析 os 的局部绑定；按短路表达式的执行次序收集；未支持控制流不得被当作透明语句跳过；保留有效字面量权限控制。
- [x] `uv run --no-sync pytest tests/test_review_semantics.py tests/test_validation_tools.py -k permission`。

## 3. 命令流与转义

- [x] 新建 `src/cv_agent/command_analysis.py`：用字符串片段、元组值、模块绑定表示解释状态；处理赋值覆盖、别名、有限字面量循环、return 终止；未支持语句明确终止精确解释。
- [x] 将 `validation_tools.py` 的命令工具接至该模块；helper 只报告可达返回值，caller 只报告实际传入受支持 shell sink 的值。
- [x] 字符串常量和已转义片段都保留到 sink，只有普通 shell 词元边界支持 quote；其他引号上下文为 AMBIGUOUS。
- [x] `uv run --no-sync pytest tests/test_review_semantics.py tests/test_validation_tools.py -k command`。

## 4. 裁决与持久化

- [x] 修改 `src/cv_agent/react_engine.py`，将用于支持结论的引用与 counter/unresolved 引用区分；同候选具体证据冲突约束不变。
- [x] 修改 `scripts/run_python_heldout_pair_matrix.py`：计划外行保留并标记，summary 明确列出额外行，指标分母仅使用计划单元。
- [x] `uv run --no-sync pytest tests/test_review_semantics.py tests/test_evidence_validation.py tests/test_python_heldout_pair_runner.py`。

## 5. 验收

- [x] `uv run --no-sync pytest`，必须完整通过。
- [x] `uv run --no-sync cv-agent harness-check` 和 `git diff --check`。
- [x] 更新审查文档的修复状态、支持范围及验证结果。原始反例证据和实验产物保持不变。
