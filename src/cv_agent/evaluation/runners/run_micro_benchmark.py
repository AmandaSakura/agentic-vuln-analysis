#!/usr/bin/env python3
"""Micro-Benchmark for cv_agent: Controlled Live Evaluation with Antigravity API.

Evaluates 4 representative cases across 6 system variants:
- Baseline: Direct Single LLM Zero-shot (No tools, static analysis prompt)
- E1: Local Single Expert (No cross-file retrieval)
- E2: Text RAG Single Expert (Lexical BM25/TF-IDF)
- E3: Graph Code-RAG Single Expert (AST Caller-Callee graph)
- E4: Graph Multi-Expert Majority (Planner + Scan + Taint + Authz, full review)
- E5: Graph Multi-Expert Quorum-Fast (Planner + Scan + Taint + Authz, early exit)

Target API: Local Antigravity proxy (gemini-3.8-flash-high).
"""

from __future__ import annotations

from cv_agent.runtime.paths import PROJECT_ROOT

import json
import os
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import math
from uuid import uuid4
from pathlib import Path
from typing import Any

project_root = PROJECT_ROOT

from cv_agent.domain.chat import ChatMessage
from cv_agent.agents.workflow import AgenticPipeline
from cv_agent.harness import FULL_SYSTEM_HARNESS, AgentSystemVersion
from cv_agent.runtime.model import OpenAICompatibleChatModel
from cv_agent.code_adapters.python import parse_python_source
from cv_agent.retrieval import RepositoryIndex
from cv_agent.runtime.journal import Journal, RecordedTools, Trial, utc_now
from cv_agent.domain.types import Candidate, CodeDocument


def load_default_model_config(root=PROJECT_ROOT):
    """Read the existing micro-model settings only when an explicit run needs them."""
    return json.loads((root / "configs/models" / "micro_benchmark.json").read_text())


SYSTEMS = [
    ("Baseline_Direct_LLM", None),
    *[(system.value, system) for system in (
        AgentSystemVersion.E1_LOCAL_SINGLE, AgentSystemVersion.E2_TEXT_SINGLE,
        AgentSystemVersion.E3_GRAPH_SINGLE, AgentSystemVersion.E4_GRAPH_MULTI,
        AgentSystemVersion.E5_GRAPH_FAST,
    )],
]


def get_live_model(trial, role):
    # No credential is stored in source, configuration, or run metadata.
    return OpenAICompatibleChatModel(
        **load_default_model_config(project_root), api_key=os.environ["ANTIGRAVITY_API_KEY"],
        observer=trial.observe(role),
    )


@dataclass
class TestCase:
    case_id: str
    name: str
    ground_truth: str  # VULNERABLE or SAFE
    description: str
    files: dict[str, str]
    entry_path_prefix: str
    entry_line: int
    query: str


BENCHMARK_CASES: list[TestCase] = [
    TestCase(
        case_id="C01",
        name="direct_eval_injection",
        ground_truth="VULNERABLE",
        description="Direct taint propagation from request parameter to eval() across 2 files.",
        files={
            "api.py": (
                "from operations import calculate\n\n"
                "def endpoint(request):\n"
                "    payload = request.args['expression']\n"
                "    return calculate(payload)\n"
            ),
            "operations.py": (
                "def calculate(expression: str):\n"
                "    return eval(expression)\n"
            ),
        },
        entry_path_prefix="api.py::endpoint@",
        entry_line=3,
        query="eval expression endpoint",
    ),
    TestCase(
        case_id="C02",
        name="unused_argument_safe",
        ground_truth="SAFE",
        description="Untrusted user input passed to unused argument, constant passed to eval(). High FP trap for naive static scan.",
        files={
            "api.py": (
                "from operations import calculate\n\n"
                "def endpoint(request):\n"
                "    payload = request.args['expression']\n"
                '    return calculate("1 + 1", payload)\n'
            ),
            "operations.py": (
                "def calculate(expression: str, audit_tag: str):\n"
                "    return eval(expression)\n"
            ),
        },
        entry_path_prefix="api.py::endpoint@",
        entry_line=3,
        query="eval expression endpoint",
    ),
    TestCase(
        case_id="C03",
        name="multi_hop_sanitized_safe",
        ground_truth="SAFE",
        description="3-hop cross-file flow protected by explicit isalnum validation guard. Tests flow refutation.",
        files={
            "controller.py": (
                "from service import safe_execute\n\n"
                "def endpoint(request):\n"
                "    raw = request.args.get('formula')\n"
                "    return safe_execute(raw)\n"
            ),
            "service.py": (
                "from validator import is_valid_input\n"
                "from backend import run_calc\n\n"
                "def safe_execute(val: str):\n"
                "    if not is_valid_input(val):\n"
                "        return 'Invalid'\n"
                "    return run_calc(val)\n"
            ),
            "validator.py": (
                "def is_valid_input(text: str) -> bool:\n"
                "    return text.isalnum()\n"
            ),
            "backend.py": (
                "def run_calc(expr: str):\n"
                "    return eval(expr)\n"
            ),
        },
        entry_path_prefix="controller.py::endpoint@",
        entry_line=3,
        query="execute formula",
    ),
    TestCase(
        case_id="C04",
        name="deep_cross_file_injection",
        ground_truth="VULNERABLE",
        description="3-hop call chain across 4 files without lexical keyword overlap (no 'eval' or 'cmd' in caller names). Tests AST graph retrieval vs text retrieval.",
        files={
            "web.py": (
                "from dispatcher import dispatch_job\n\n"
                "def handle_request(request):\n"
                "    user_task = request.args['task']\n"
                "    return dispatch_job(user_task)\n"
            ),
            "dispatcher.py": (
                "from worker import execute_job\n\n"
                "def dispatch_job(task_info: str):\n"
                "    return execute_job(task_info)\n"
            ),
            "worker.py": (
                "from sink import run_dynamic\n\n"
                "def execute_job(job_payload: str):\n"
                "    return run_dynamic(job_payload)\n"
            ),
            "sink.py": (
                "def run_dynamic(code_str: str):\n"
                "    return eval(code_str)\n"
            ),
        },
        entry_path_prefix="web.py::handle_request@",
        entry_line=3,
        query="dispatch user task",
    ),
]


def build_case_harness(case: TestCase) -> tuple[RepositoryIndex, Candidate]:
    documents: list[CodeDocument] = []
    for path, source in case.files.items():
        spans = parse_python_source(case.case_id, path, source)
        for s in spans:
            documents.append(s.document)

    entry = next(
        doc for doc in documents if doc.path.startswith(case.entry_path_prefix)
    )
    candidate = Candidate(
        candidate_id=case.case_id,
        case_id=case.case_id,
        repository_id=case.case_id,
        path=entry.path,
        line=case.entry_line,
        query=case.query,
    )
    return RepositoryIndex(documents), candidate



class InvalidBaselineOutput(ValueError):
    pass


def parse_baseline(content):
    cleaned = (content or "").strip()
    if cleaned.startswith("```") and cleaned.endswith("```"):
        cleaned = cleaned.split("\n", 1)[1].rsplit("```", 1)[0]
    try:
        data = json.loads(cleaned)
        label = data["label"]
        confidence = data["confidence"]
        rationale = data["rationale"]
        if label not in {"VULNERABLE", "SAFE", "UNRESOLVED"}:
            raise ValueError("invalid label")
        if (type(confidence) not in {int, float} or not math.isfinite(confidence)
                or not 0 <= confidence <= 1):
            raise ValueError("confidence must be finite and in [0, 1]")
        if not isinstance(rationale, str):
            raise ValueError("rationale must be text")
    except (ValueError, TypeError, KeyError) as error:
        raise InvalidBaselineOutput(str(error)) from error
    return {"predicted_label": label, "confidence": confidence, "rationale": rationale,
            "path": "direct", "votes": []}


def run_baseline_direct_llm(case, trial):
    code_bundle = "\n\n".join(f"# File: {path}\n{code}" for path, code in case.files.items())
    # Do not supply ground truth, case descriptions, or case-specific answer rules.
    prompt = f"""Analyze whether attacker-controlled request data can cause arbitrary
code execution through Python eval, starting at {case.entry_path_prefix}.
Reason about parameter binding and validation. If evidence is insufficient,
return UNRESOLVED. Scope is code execution, not all possible security flaws.
Codebase:
{code_bundle}
Return JSON only with label (VULNERABLE, SAFE, or UNRESOLVED),
confidence (number between 0 and 1), and rationale (string)."""
    reply = get_live_model(trial, "baseline").complete(
        [ChatMessage(role="user", content=prompt)], [])
    return {**parse_baseline(reply.content), "raw_reply": reply.model_dump(mode="json")}


def run_agentic_system(case, system_ver, trial):
    index, candidate = build_case_harness(case)
    spec = FULL_SYSTEM_HARNESS.system_spec(system_ver)
    roles = set(spec.expert_order)
    if spec.planner_enabled:
        roles.add("planner")
    pipeline = AgenticPipeline(
        index=index, system=system_ver,
        models={role: get_live_model(trial, role) for role in sorted(roles)},
        tools=RecordedTools(index, trial),
    )
    verdict = pipeline.run(candidate)
    return {
        "predicted_label": verdict.label, "confidence": verdict.confidence,
        "path": verdict.path, "rationale": verdict.rationale,
        "votes": [vote.model_dump(mode="json") for vote in verdict.votes],
        "verdict": verdict.model_dump(mode="json"),
    }


def run_trial(case, system_name, system_ver, journal):
    trial = Trial(case.case_id, system_name, journal)
    start = time.perf_counter()
    result = {
        "case_id": case.case_id, "case_name": case.name, "system": system_name,
        "ground_truth": case.ground_truth, "predicted_label": None,
        "confidence": None, "path": None, "votes": [], "rationale": "",
    }
    trial.record({"event": "trial_start"})
    interruption = None
    try:
        outcome = (run_baseline_direct_llm(case, trial) if system_ver is None
                   else run_agentic_system(case, system_ver, trial))
        result.update(outcome)
        result["status"] = ("abstained" if result["predicted_label"] in
                            {"ABSTAIN", "UNRESOLVED"} else "completed")
    except (Exception, KeyboardInterrupt) as error:
        interruption = error if isinstance(error, KeyboardInterrupt) else None
        result.update(
            status="interrupted" if interruption is not None else "failed",
            error_type=type(error).__name__, error=str(error),
        )
    result.update(
        is_correct=result["status"] == "completed"
                   and result["predicted_label"] == case.ground_truth,
        model_calls=trial.model_calls, tool_calls=trial.tool_calls,
        latency_sec=round(time.perf_counter() - start, 3),
    )
    trial.record({"event": "trial_result", "result": result})
    if interruption is not None:
        raise interruption
    return result


def generate_markdown_report(results, out_path, metadata):
    lines = [
        "# cv_agent 微型 API 对照实验",
        "",
        f"开始时间：{metadata['started_at']}；请求模型：{metadata['config']['model']}",
        f"已记录 {len(results)}/{metadata['expected_trials']} 组；完整事件与证据见 events.jsonl。",
        "",
        "四个手写 Python 功能用例，不是独立抽样的真实仓库测试集；标签仅针对 eval 代码执行。",
        "直接模型获得全部源码；E1–E5 使用各自 Harness 的上下文、工具与证据约束。",
        "直接模型对比属于系统对比，不能单独归因于检索或多专家机制。",
        "E4/E5 是独立模型运行，不是共享专家轨迹回放；调用差异不必然由提前退出造成。",
        "观察到的请求次数包含失败请求；token 用量仅在服务端返回时可用，未知不按零处理。",
        "未决、失败和中断计入总体正确率分母，但不直接归为 FP/FN。",
        "",
        "| 用例 | 系统 | 状态 | 真值 | 预测 | 模型请求 | 工具调用 | 秒 |",
        "|---|---|---|---|---|---:|---:|---:|",
    ]
    for row in results:
        lines.append(
            f"| {row['case_id']} | {row['system']} | {row['status']} | "
            f"{row['ground_truth']} | {row['predicted_label'] or '—'} | "
            f"{row['model_calls']} | {row['tool_calls']} | {row['latency_sec']} |")
    lines.extend([
        "", "| 系统 | 正确/已记录 | FP | FN | 未决 | 失败 | 中断 | 平均模型请求 | 平均工具调用 | 平均秒 |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ])
    for system in sorted({row["system"] for row in results}):
        rows = [row for row in results if row["system"] == system]
        n = len(rows)
        fp = sum(row["status"] == "completed" and row["ground_truth"] == "SAFE"
                 and row["predicted_label"] == "VULNERABLE" for row in rows)
        fn = sum(row["status"] == "completed" and row["ground_truth"] == "VULNERABLE"
                 and row["predicted_label"] == "SAFE" for row in rows)
        counts = [sum(row["status"] == state for row in rows)
                  for state in ("abstained", "failed", "interrupted")]
        lines.append(
            f"| {system} | {sum(row['is_correct'] for row in rows)}/{n} | {fp} | {fn} | "
            f"{counts[0]} | {counts[1]} | {counts[2]} | "
            f"{sum(row['model_calls'] for row in rows)/n:.2f} | "
            f"{sum(row['tool_calls'] for row in rows)/n:.2f} | "
            f"{sum(row['latency_sec'] for row in rows)/n:.3f} |")
    lines.extend(["", "以上只报告已记录的观测值，不自动宣称组件优势或历史指标得到复现。",
                  "若进程被强制终止，以 events.jsonl 的 trial_start/model_start 和对应结束事件核对未完成工作。"])
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def save_summary(run_dir, metadata):
    # Journal is authoritative, including results written immediately before Ctrl-C.
    events = [json.loads(line) for line in (run_dir / "events.jsonl").read_text().splitlines()]
    results = [event["result"] for event in events if event["event"] == "trial_result"]
    target = run_dir / "results.json"
    temporary = run_dir / "results.json.tmp"
    temporary.write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(target)
    generate_markdown_report(results, run_dir / "report.md", metadata)


def main():
    # Fail before starting the matrix if the required credential is absent.
    if not os.environ.get("ANTIGRAVITY_API_KEY", "").strip():
        raise ValueError("Set ANTIGRAVITY_API_KEY before running the live benchmark")
    run_dir = project_root / "artifacts" / "micro_benchmark" / (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:8])
    run_dir.mkdir(parents=True)
    metadata = {
        "started_at": utc_now(), "config": load_default_model_config(project_root),
        "expected_trials": len(BENCHMARK_CASES) * len(SYSTEMS),
        "systems": [name for name, _ in SYSTEMS],
        "cases": [asdict(case) for case in BENCHMARK_CASES],
        "harness": FULL_SYSTEM_HARNESS.model_dump(mode="json"),
        "source_sha256": {
            str(path.relative_to(project_root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted((project_root / "src" / "cv_agent").rglob("*.py"))
        },
    }
    (run_dir / "metadata.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n")
    journal = Journal(run_dir / "events.jsonl")
    journal.write({"event": "run_start"})
    print(f"Run directory: {run_dir}", flush=True)
    try:
        for case in BENCHMARK_CASES:
            for name, version in SYSTEMS:
                print(f"Running {case.case_id} / {name}", flush=True)
                result = run_trial(case, name, version, journal)
                save_summary(run_dir, metadata)
                print(f"{result['status']}: {result['predicted_label']} "
                      f"requests={result['model_calls']} tools={result['tool_calls']}", flush=True)
    finally:
        save_summary(run_dir, metadata)


if __name__ == "__main__":
    main()
