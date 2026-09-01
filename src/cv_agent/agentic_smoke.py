from __future__ import annotations

import json

from .agent_tools import ToolRegistry, repository_tools
from .agent_types import ModelReply, ModelToolCall
from .agentic_workflow import AgenticPipeline
from .harness import FULL_SYSTEM_HARNESS, AgentSystemVersion
from .model_runtime import ScriptedChatModel
from .synthetic import cross_file_fixture


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
                "allowed_validator": "compare_vulnerable_and_fixed",
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
                    "get_callees",
                    {"path": "controller.py"},
                ),
                ModelReply(model_id="scripted-planner", content=json.dumps(plan)),
            ]
        ),
        "scan": ScriptedChatModel(
            [
                _tool_reply("scan", "read_span", {"path": "service.py"}),
                _conclusion(
                    "scan",
                    "VULNERABLE",
                    "CONFIRMED",
                    ["span:service.py"],
                ),
            ]
        ),
        "taint": ScriptedChatModel(
            [
                _tool_reply("taint", "read_span", {"path": "controller.py"}),
                _conclusion(
                    "taint",
                    "VULNERABLE",
                    "CONFIRMED",
                    ["span:controller.py", "span:service.py"],
                ),
            ]
        ),
        # The fast path must finish before this model is called.
        "authz": ScriptedChatModel([]),
    }
    tools = ToolRegistry(
        repository_tools(index),
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

