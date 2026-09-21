"""Deterministic tool-driven workflow check, never a live-model measurement."""

from __future__ import annotations

import json

from .agent_tools import ToolRegistry
from .agent_types import ModelReply, ModelToolCall
from .agentic_workflow import AgenticPipeline
from .harness import AgentSystemVersion
from .model_runtime import ScriptedChatModel
from .python_ast import parse_python_source
from .retrieval import RepositoryIndex
from .types import Candidate
from .validation_tools import full_agent_tools


class _ObservedToolReply:
    """Test transport deriving its conclusion from the actual tool observation."""

    def __init__(self, role, path):
        self.role, self.path = role, path

    def __call__(self, messages, tools):
        name, key = {
            "scan": ("probe_python_eval", "source_path"),
            "taint": ("trace_dataflow", "source_path"),
            "authz": ("compare_route_and_service_guard", "route_path"),
        }[self.role]
        if messages[-1].role != "tool":
            return ModelReply(model_id="scripted-tool-driven", tool_calls=(
                ModelToolCall(call_id=self.role + "-1", name=name, arguments={key: self.path}),
            ))
        observation = json.loads(messages[-1].content)
        status = observation.get("validation_status", "UNRESOLVED")
        label = {"CONFIRMED": "VULNERABLE", "REFUTED": "SAFE", "UNRESOLVED": "ABSTAIN"}[status]
        if self.role == "taint" and json.loads(observation["content"]).get("flow_status") == "MAY_REACH":
            # A prediction based on static flow remains unvalidated.
            label = "VULNERABLE"
        return ModelReply(model_id="scripted-tool-driven", content=json.dumps({
            "expert": self.role, "label": label, "confidence": 0.9,
            "validation_status": status, "evidence_ids": [observation["citation_id"]],
            "rationale": "Development transport reports its own typed tool observation.",
        }))


def run_probe_case(case: str, system: AgentSystemVersion):
    call = {"C01": "calculate(payload, 'audit')", "C02": "calculate('1 + 1', payload)"}[case]
    files = {
        "api.py": "from operations import calculate\n\ndef endpoint(request):\n    payload = request.args['expression']\n    return " + call + "\n",
        "operations.py": "def calculate(expression: str, audit_tag: str):\n    return eval(expression)\n",
    }
    docs = [span.document for path, source in files.items()
            for span in parse_python_source("probe-smoke", path, source)]
    entry = next(doc for doc in docs if doc.path.startswith("api.py::endpoint@"))
    candidate = Candidate(candidate_id=case, case_id=case, repository_id="probe-smoke",
                          path=entry.path, line=3, query=entry.text)
    plan = {
        "candidate_id": case, "vulnerability_hypotheses": ["Python eval injection"],
        "subtasks": [
            {"task_id": role, "expert": role, "objective": objective,
             "allowed_validator": validator, "dependencies": [], "success_condition": objective}
            for role, validator, objective in (
                ("scan", "probe_python_eval", "Check two concrete inputs reaching eval in admitted code."),
                ("taint", "trace_dataflow", "Independently check parameter flow from input to eval."),
                ("authz", "compare_route_and_service_guard", "Assess whether permissions are applicable."),
            )
        ],
        "rationale": "Two applicable checks of injection and a separate authorization assessment.",
    }
    models = {}
    for role in ("scan", "taint", "authz"):
        responder = _ObservedToolReply(role, entry.path)
        models[role] = ScriptedChatModel([responder, responder])
    models["planner"] = ScriptedChatModel([
        ModelReply(model_id="scripted-plan", tool_calls=(
            ModelToolCall(call_id="planner-1", name="read_span", arguments={"path": entry.path}),
        )),
        ModelReply(model_id="scripted-plan", content=json.dumps(plan)),
    ])
    index = RepositoryIndex(docs)
    verdict = AgenticPipeline(index=index, system=system, models=models,
                             tools=ToolRegistry(full_agent_tools(index), max_output_bytes=1_000_000)).run(candidate)
    return verdict, models


def main():
    results = [
        {"case": case, "system": system.value, "verdict": run_probe_case(case, system)[0].model_dump(mode="json")}
        for case in ("C01", "C02")
        for system in (AgentSystemVersion.E4_GRAPH_MULTI, AgentSystemVersion.E5_GRAPH_FAST)
    ]
    print(json.dumps({"claim_eligible": False, "model_reply_origin": "deterministic tool-driven transport",
                      "dataset_role": "development", "results": results}, indent=2))


if __name__ == "__main__":
    main()
