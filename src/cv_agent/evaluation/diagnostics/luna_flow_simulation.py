"""Capture model requests and replay externally obtained Luna replies through the real graph.

This is a development-only orchestration simulation. It uses the existing scripted
runtime for replay, never claims a DeepSeek/live API result, and never reads a key.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from cv_agent.tools.registry import ToolRegistry
from cv_agent.domain.chat import ModelReply
from cv_agent.agents.workflow import AgenticPipeline
from cv_agent.harness import AgentSystemVersion, FULL_SYSTEM_HARNESS
from cv_agent.runtime.model import ScriptedChatModel
from cv_agent.code_adapters.python import parse_python_source
from cv_agent.retrieval import RepositoryIndex
from cv_agent.domain.types import Candidate
from cv_agent.tools.validation import full_agent_tools


def fixture(case_id: str):
    calls = {
        "C01": "return calculate(payload)",
        "C02": 'return calculate("1 + 1", payload)',
    }
    parameters = {
        "C01": "expression: str",
        "C02": "expression: str, audit_tag: str",
    }
    files = {
        "api.py": (
            "from operations import calculate\n\n"
            "def endpoint(request):\n"
            "    payload = request.args['expression']\n"
            f"    {calls[case_id]}\n"
        ),
        "operations.py": (
            f"def calculate({parameters[case_id]}):\n"
            "    return eval(expression)\n"
        ),
    }
    documents = [
        span.document for path, source in files.items()
        for span in parse_python_source("luna-flow-fixture", path, source)
    ]
    entry = next(doc for doc in documents if doc.path.startswith("api.py::endpoint@"))
    candidate = Candidate(
        candidate_id=case_id, case_id=case_id, repository_id="luna-flow-fixture",
        path=entry.path, line=3, query=entry.text,
    )
    return RepositoryIndex(documents), candidate


def packet(request):
    messages, tools = request
    return {
        "messages": [message.model_dump(mode="json", exclude_none=True) for message in messages],
        "tools": list(tools),
    }


def normalize_reply(raw):
    if "candidate_id" in raw or "expert" in raw:
        # The workflow itself asks for the final schema directly. Preserve that
        # response as model content even when the transport wrapper was omitted.
        return ModelReply(model_id="gpt-5.6-luna", content=json.dumps(raw, sort_keys=True))
    if set(raw) == {"final"}:
        return ModelReply(model_id="gpt-5.6-luna", content=json.dumps(raw["final"], sort_keys=True))
    if set(raw) == {"tool_calls"}:
        return ModelReply(model_id="gpt-5.6-luna", tool_calls=raw["tool_calls"])
    raise ValueError("reply must contain exactly final or tool_calls")


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", choices=("C01", "C02"), required=True)
    parser.add_argument("--session", type=Path, required=True)
    parser.add_argument("--system", choices=("E4", "E5"), default="E4")
    parser.add_argument("--reply", type=Path)
    parser.add_argument("--agent")
    args = parser.parse_args()
    args.session.mkdir(parents=True, exist_ok=True)
    history_path = args.session / "history.json"
    history = json.loads(history_path.read_text()) if history_path.exists() else []
    if args.reply:
        pending = json.loads((args.session / "pending.json").read_text())
        raw = json.loads(args.reply.read_text())
        reply = normalize_reply(raw)
        history.append({
            "role": pending["role"], "request": pending["request"],
            "raw_reply": raw, "reply": reply.model_dump(mode="json"),
            "agent": args.agent, "requested_model": "gpt-5.6-luna",
            "requested_effort": "max", "parent_history_inherited": False,
        })
        write_json(history_path, history)
    role_records = {
        role: [item for item in history if item["role"] == role]
        for role in ("planner", "scan", "taint", "authz")
    }
    models = {
        role: ScriptedChatModel([ModelReply.model_validate(item["reply"]) for item in records])
        for role, records in role_records.items()
    }
    index, candidate = fixture(args.case)
    pipeline = AgenticPipeline(
        index=index, system=AgentSystemVersion(args.system), models=models,
        tools=ToolRegistry(full_agent_tools(index), max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes),
    )
    verdict = None
    failure = None
    try:
        verdict = pipeline.run(candidate)
    except (RuntimeError, ValueError) as error:
        if str(error) != "scripted model has no reply remaining":
            failure = {"type": type(error).__name__, "message": str(error)}
    for role, model in models.items():
        for request, recorded in zip(model.requests, role_records[role]):
            if packet(request) != recorded["request"]:
                raise ValueError(f"replayed input changed for {role}; start a new clean simulation")
    if failure is not None:
        result = {"status": "failed", "case": args.case, "system": args.system,
                  "claim_eligible": False, "failure": failure}
        write_json(args.session / f"failure-{args.system}.json", result)
        print(json.dumps(result))
        return
    if verdict is not None:
        result = {
            "case_id": args.case, "system": args.system, "status": "complete",
            "model_reply_origin": "clean-context Codex Luna max subagents",
            "execution": "recorded replies replayed through AgenticPipeline and ToolRegistry",
            "claim_eligible": False, "dataset_role": "development",
            "verdict": verdict.model_dump(mode="json"),
        }
        write_json(args.session / f"result-{args.system}.json", result)
        print(json.dumps({
            "status": "complete", "case": args.case, "system": args.system,
            "label": verdict.label, "path": verdict.path,
            "model_calls": verdict.model_calls, "tool_calls": verdict.tool_calls,
        }))
        return
    for role, model in models.items():
        if len(model.requests) > len(role_records[role]):
            pending = {
                "case_id": args.case, "role": role,
                "role_request": len(model.requests), "request": packet(model.requests[-1]),
            }
            write_json(args.session / "pending.json", pending)
            print(json.dumps(pending, ensure_ascii=False))
            return
    raise RuntimeError("simulation stopped without a next request or verdict")


if __name__ == "__main__":
    main()
