# Code architecture

The core packages are grouped by responsibility. Their `__init__.py` files expose
the existing imports used by workflows, experiments and tests; implementation
modules import their dependencies directly. There are no dynamic module aliases
or duplicate legacy implementations.

## Where to change behavior

| Concern | Source |
| --- | --- |
| Experiment schemas and enums | `src/cv_agent/harness/models.py` |
| Active budgets, expert policies and command registration | `src/cv_agent/harness/defaults.py` |
| Contract consistency | `src/cv_agent/harness/validation.py` |
| Result acceptance | `src/cv_agent/harness/owasp_results.py`, `vulngym_results.py` |
| Source spans and parser output models | `src/cv_agent/code_adapters/models.py` |
| JavaScript/TypeScript and Go parsing | `src/cv_agent/code_adapters/javascript.py`, `go.py` |
| Fallback documents and repository traversal | `src/cv_agent/code_adapters/fallback.py`, `repository.py` |
| Python and Java AST parsing | `src/cv_agent/python_ast.py`, `java_ast.py` |
| Repository index, call graph and retrieval ranking | `src/cv_agent/retrieval/index.py` |
| Focused evidence and textual assignment dependencies | `src/cv_agent/retrieval/context.py`, `dependencies.py` |
| Context accounting and truncation | `src/cv_agent/retrieval/tokens.py` |
| Shared Java-like lexical primitives | `src/cv_agent/java_lexical.py` |
| Deterministic expert decisions | `src/cv_agent/experts/scan.py`, `taint.py`, `flow.py`, `authorization.py` |
| Typed validation inputs and registered fixture contracts | `src/cv_agent/validation_tools/models.py` |
| Static patterns, dataflow, permissions and commands | Corresponding modules in `src/cv_agent/validation_tools/` |
| Authorization and paired-source comparison | `src/cv_agent/validation_tools/authorization.py`, `comparison.py` |
| Isolated fixture processes and loopback HTTP | `src/cv_agent/validation_tools/fixtures.py` |
| Tool names, descriptions, capabilities and assembly | `src/cv_agent/validation_tools/registry.py` |
| Agent scheduling and model/tool loop | `src/cv_agent/agentic_workflow.py`, `react_engine.py` |
| Model transport and offline test admission | `src/cv_agent/model_runtime.py`, `live_gate.py` |

## Dependency boundaries

- `types.py` and the package model modules define shared data. They do not depend
  on workflow orchestration.
- Harness defaults instantiate typed models. Harness validators check those
  declarations; importing `cv_agent.harness` still validates the project contract.
- Language adapters produce code documents. Retrieval consumes documents and
  produces bounded evidence. Parsers do not invoke retrieval or experts.
- Retrieval and deterministic experts share lexical syntax through
  `java_lexical.py`. Source/sink rules and control-flow assumptions remain owned
  by each analyzer because their semantics differ.
- Validation handlers receive their repository index or fixture registry
  explicitly. `validation_tools/registry.py` assembles `AgentTool` definitions;
  analysis modules do not import the registry.
- `ToolRegistry` owns admission, serialized observation budgets and tool errors.
  `AgenticPipeline` owns scheduling and verdicts. Both planner and experts use
  the observation limit declared by the harness; resumed expert tasks retain
  their accumulated usage.

Keep concrete evidence bound to its candidate and source snapshot. Static
may-flow results remain unresolved. Moving code does not relax the
[test contract](TEST_CONTRACT.md), source scope, fixture isolation or live gate.

## Repository navigation

`src/cv_agent/` contains reusable implementation. `tests/` contains offline
behavioral checks. `scripts/` holds experiment and diagnostic entry points;
`configs/` holds their inputs. `data/`, `validation/` and `artifacts/` contain
datasets, fixture assets and experiment outputs respectively.

Use this guide for current source locations and [HARNESS.md](HARNESS.md) for
experiment rules. Dated review, handoff and result documents are historical
records; their file names and line numbers describe the checkout at that time.

## Verification

Run from the repository root:

```bash
uv run --no-sync pytest
uv run --no-sync cv-agent harness-check
uv run --no-sync cv-agent synthetic
uv run --no-sync cv-agent agentic-smoke
uv run --no-sync cv-agent agentic-eval
```

These commands use offline fixtures or scripted models. A wheel build checks
that nested packages are included:

```bash
uv build --wheel
```

Public consumers import from package roots. Tests that intentionally replace an
internal fixture runner patch `cv_agent.validation_tools.fixtures`, where the
runner is now defined, so isolation-failure and evidence-binding checks remain
effective.
