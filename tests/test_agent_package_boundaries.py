"""Canonical ownership and behavior contracts for the agent components."""

import hashlib
import importlib
import json

import pytest

from cv_agent.domain import chat, evidence, review
from cv_agent.tools import registry, repository, identity
from cv_agent.agents import workflow as agentic_workflow, react as react_engine
from cv_agent.harness import AgentSystemVersion
from cv_agent.runtime.model import ScriptedChatModel
from cv_agent.retrieval import RepositoryIndex
from cv_agent.domain.types import Candidate, CodeDocument
from cv_agent.tools.validation import full_agent_tools


CONTRACT_MODULES = {
    "chat": ("ModelToolCall", "ChatMessage", "ModelUsage", "ModelReply"),
    "evidence": ("ValidationStatus", "ValidationSubject", "ToolObservation", "ReActStep"),
    "review": (
        "AgentExpertConclusion", "AgentExpertVote", "ValidationSubtask", "ValidationPlan",
        "PlannerResult", "ValidationTaskExecution", "AgenticVerdict",
    ),
}


def _pipeline():
    index = RepositoryIndex([
        CodeDocument(
            repository_id="r", path="entry.py::entry@1-2",
            text="def entry(value):\n    return eval(value)\n",
            language="python", adapter_tier="ast", defines=("entry",),
        ),
    ])
    candidate = Candidate(
        candidate_id="c", case_id="c", repository_id="r", path="entry.py::entry@1-2",
        line=1, query="entry", input_parameters=("value",),
        analysis_scope="Review the supplied entry argument.",
    )
    tools = registry.ToolRegistry(full_agent_tools(index), max_output_bytes=10000)
    pipeline = agentic_workflow.AgenticPipeline(
        index=index, system=AgentSystemVersion.E4_GRAPH_MULTI,
        models={role: ScriptedChatModel([]) for role in ("planner", "scan", "taint", "authz")},
        tools=tools,
    )
    return pipeline, candidate, {"candidate": candidate, "evidence": index.local(candidate)}


@pytest.mark.parametrize("module,names", CONTRACT_MODULES.items())
def test_domain_contracts_are_defined_in_their_owning_modules(module, names):
    owner = importlib.import_module(f"cv_agent.domain.{module}")
    for name in names:
        contract = getattr(owner, name)
        assert contract.__module__ == owner.__name__
    assert react_engine.AgentExpertConclusion is review.AgentExpertConclusion


@pytest.mark.parametrize("module,names", [
    ("registry", ("AgentTool", "ToolExecutionScope", "ToolRegistry")),
    ("repository", ("SearchSymbolsInput", "ReadSpanInput", "GraphNeighborsInput", "repository_tools")),
    ("identity", ("repository_source_digest", "candidate_subject")),
])
def test_tools_are_defined_in_their_implementation_modules(module, names):
    owner = importlib.import_module(f"cv_agent.tools.{module}")
    for name in names:
        implementation = getattr(owner, name)
        assert implementation.__module__ == owner.__name__


def test_react_delegates_to_the_evidence_policy(monkeypatch):
    from cv_agent.agents import evidence_policy

    assert react_engine.validate_conclusion is evidence_policy.validate_conclusion
    assert evidence_policy.validate_conclusion.__module__ == evidence_policy.__name__
    observation = evidence.ToolObservation(
        tool="get_guards", status="ok", content='{"guards":[]}', citation_id="scan/tool:1",
    )
    trace = [evidence.ReActStep(
        step=1, model_id="offline", tool_call=chat.ModelToolCall(
            call_id="one", name="get_guards", arguments={"path": "entry.py"},
        ), observation=observation,
    )]
    conclusion = review.AgentExpertConclusion(
        expert="scan", label="SAFE", confidence=0.5, validation_status="UNRESOLVED",
        evidence_ids=("scan/tool:1",), rationale="Test policy dispatch.",
    )
    with pytest.raises(ValueError, match="affirmative counter-evidence"):
        react_engine.validate_conclusion(conclusion, trace, frozenset())
    received = []

    def affirmative(item, subject):
        received.append((item, subject))
        return True

    monkeypatch.setattr(evidence_policy, "_has_affirmative_safe_evidence", affirmative)
    react_engine.validate_conclusion(conclusion, trace, frozenset())
    assert received == [(observation, None)]


def test_subject_identity_uses_its_implementation_dependency(monkeypatch):
    from cv_agent.tools import identity

    pipeline, candidate, _ = _pipeline()
    received = []

    def source_digest(index):
        received.append(index)
        return "offline-source-identity"

    monkeypatch.setattr(identity, "repository_source_digest", source_digest)
    subject = identity.candidate_subject(pipeline.index, candidate)
    assert received == [pipeline.index]
    assert subject.source_digest == "offline-source-identity"
    assert subject.input_parameters == ("value",)
    assert subject.entry_path == candidate.path


def test_registry_uses_its_implementation_dependencies(monkeypatch):
    from cv_agent.tools import registry

    pipeline, candidate, _ = _pipeline()
    original = registry.context_text_token_count
    payloads = []

    def count(payload):
        payloads.append(payload)
        return original(payload)

    monkeypatch.setattr(registry, "context_text_token_count", count)
    scope = registry.ToolExecutionScope(
        admitted_paths=frozenset({candidate.path}), max_observation_tokens=10000,
    )
    observation = pipeline.tools.invoke(
        chat.ModelToolCall(call_id="one", name="read_span", arguments={"path": candidate.path}),
        allowed=("read_span",), scope=scope, citation_id="scan/tool:1",
    )
    assert observation.status == "ok"
    assert observation.content == pipeline.index.document(candidate.path).text
    assert scope.observed_tokens == original(pipeline.tools.prompt_payload(observation))
    assert pipeline.tools.prompt_payload(observation) in payloads
    assert all(tool.handler.__module__ == "cv_agent.tools.repository"
               for tool in repository.repository_tools(pipeline.index))


def test_planner_delegates_with_the_patched_workflow_harness(monkeypatch):
    from cv_agent.agents import planning

    pipeline, candidate, state = _pipeline()
    harness = agentic_workflow.FULL_SYSTEM_HARNESS.model_copy(update={"planner_max_subtasks": 1})
    monkeypatch.setattr(agentic_workflow, "FULL_SYSTEM_HARNESS", harness)
    received = []
    original_prompt = planning.render_planner_prompt
    original_validate = planning.validate_plan

    def prompt(**kwargs):
        received.append(("prompt", kwargs))
        return original_prompt(**kwargs)

    def validate(plan, **kwargs):
        received.append(("validate", kwargs))
        return original_validate(plan, **kwargs)

    monkeypatch.setattr(planning, "render_planner_prompt", prompt)
    monkeypatch.setattr(planning, "validate_plan", validate)
    text = pipeline._planner_prompt(state)
    capabilities = json.loads(text.split("\nPlanning capabilities: ")[1])
    assert capabilities["maximum_subtasks"] == 1
    plan = review.ValidationPlan(
        candidate_id=candidate.candidate_id, vulnerability_hypotheses=("entry argument reaches eval",),
        subtasks=tuple(review.ValidationSubtask(
            task_id=f"t{i}", expert="scan", allowed_validator="run_static_check",
            objective="Inspect the entry.", success_condition="Report observed evidence.",
        ) for i in (1, 2)), rationale="Check the candidate.",
    )
    with pytest.raises(ValueError, match="planner exceeded maximum_subtasks"):
        pipeline._validate_plan(plan, candidate, state["evidence"])
    assert [operation for operation, _ in received] == ["prompt", "validate"]
    for _, arguments in received:
        assert arguments["harness"] is harness
        assert arguments["system_spec"] is pipeline.system_spec
        assert arguments["tools"] is pipeline.tools
        assert arguments["candidate"] is candidate
        assert arguments["evidence"] is state["evidence"]


def test_planner_tool_definitions_and_subject_match_the_original_bytes():
    pipeline, candidate, state = _pipeline()
    payloads = {
        "planner": pipeline._planner_prompt(state),
        "definitions": json.dumps(pipeline.tools.definitions(pipeline.tools.names), sort_keys=True, separators=(",", ":")),
        "subject": json.dumps(identity.candidate_subject(pipeline.index, candidate).model_dump(mode="json"), sort_keys=True, separators=(",", ":")),
    }
    assert {name: hashlib.sha256(value.encode()).hexdigest() for name, value in payloads.items()} == {
        "planner": "8827da39c40da3ea5e6f71eecee5f3ec81f3df77136900908acd2da6a633d8fb",
        "definitions": "0231a28281e3addfba98a5ca92758c8ce5607ae3ee59b8aa117154cd021870bc",
        "subject": "013deb2bd166c2fdbd050f2fcc56df31d3e17966a527243e702bec5625ad437f",
    }
