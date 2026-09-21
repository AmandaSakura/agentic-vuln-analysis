from __future__ import annotations

import json

from cv_agent.tools.registry import ToolRegistry
from cv_agent.domain.chat import ModelReply, ModelToolCall
from cv_agent.agents.workflow import AgenticPipeline
from cv_agent.harness import FULL_SYSTEM_HARNESS, AgentSystemVersion
from cv_agent.runtime.model import ScriptedChatModel
from cv_agent.baselines.synthetic import cross_file_fixture
from cv_agent.tools.validation import full_agent_tools


def _tool_reply(role: str, name: str, arguments: dict[str, object]) -> ModelReply:
    return ModelReply(
        model_id=f"scripted-{role}",
        tool_calls=(
            ModelToolCall(
                call_id=f"{role}-tool-1",
                name=name,
                arguments=arguments,
            ),
        ),
    )


def _conclusion(
    expert: str,
    label: str,
    validation_status: str,
    evidence_ids: list[str],
) -> ModelReply:
    return ModelReply(
        model_id=f"scripted-{expert}",
        content=json.dumps(
            {
                "expert": expert,
                "label": label,
                "confidence": 0.9,
                "validation_status": validation_status,
                "evidence_ids": evidence_ids,
                "rationale": f"{expert} reached a scripted fixture conclusion.",
            }
        ),
    )


def run_agentic_smoke() -> dict[str, object]:
    index, candidate = cross_file_fixture()
    plan = {
        "candidate_id": candidate.candidate_id,
        "vulnerability_hypotheses": ["command injection"],
        "subtasks": [
            {
                "task_id": "find-command-sink",
                "objective": "Locate the cross-file command sink.",
                "expert": "scan",
                "allowed_validator": "run_static_check",
                "dependencies": [],
                "success_condition": "A command execution sink is located.",
            },
            {
                "task_id": "trace-request",
                "objective": "Trace request input into the command sink.",
                "expert": "taint",
                "allowed_validator": "trace_dataflow",
                "dependencies": ["find-command-sink"],
                "success_condition": "The unsanitized source-to-sink path is established.",
            },
        ],
        "rationale": "The entry delegates a request-derived command to another file.",
    }
    models = {
        "planner": ScriptedChatModel(
            [
                _tool_reply(
                    "planner",
                    "read_span",
                    {"path": "controller.py"},
                ),
                ModelReply(model_id="scripted-planner", content=json.dumps(plan)),
            ]
        ),
        "scan": ScriptedChatModel(
            [
                _tool_reply("scan", "run_static_check", {"path": "service.py"}),
                _conclusion(
                    "scan",
                    "VULNERABLE",
                    "UNRESOLVED",
                    ["scan/tool:1"],
                ),
            ]
        ),
        "taint": ScriptedChatModel(
            [
                _tool_reply("taint", "trace_dataflow", {"source_path": "controller.py"}),
                _conclusion(
                    "taint",
                    "VULNERABLE",
                    "UNRESOLVED",
                    ["taint/tool:1"],
                ),
            ]
        ),
        # The fast path must finish before this model is called.
        "authz": ScriptedChatModel([]),
    }
    tools = ToolRegistry(
        full_agent_tools(index),
        max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes,
    )
    verdict = AgenticPipeline(
        index=index,
        system=AgentSystemVersion.E5_GRAPH_FAST,
        models=models,
        tools=tools,
    ).run(candidate)
    if verdict.path != "fast" or len(verdict.votes) != 2:
        raise RuntimeError("agentic smoke fixture failed to exercise the two-vote fast path")
    if models["authz"].requests:
        raise RuntimeError("agentic smoke fixture called authz after a fast quorum")
    return {
        "harness_id": FULL_SYSTEM_HARNESS.harness_id,
        "runtime_mode": "scripted",
        "claim_eligible": False,
        "purpose": "wiring-only ReAct and LangGraph diagnostic",
        "verdict": verdict.model_dump(mode="json"),
    }
