import json

import pytest

from cv_agent.tools.registry import ToolExecutionScope, ToolRegistry
from cv_agent.tools.repository import repository_tools
from cv_agent.domain.chat import ModelReply, ModelToolCall
from cv_agent.agents.workflow import _bounded_context_prompt
from cv_agent.agents.workflow import AgenticPipeline
from cv_agent.harness import FULL_SYSTEM_HARNESS, AgentSystemVersion, RetrievalBudget, RetrievalMode
from cv_agent.retrieval import RepositoryIndex, context_text_token_count, prompt_token_upper_bound
from cv_agent.domain.types import Candidate, CodeDocument, Evidence
from cv_agent.runtime.model import ScriptedChatModel
from cv_agent.tools.validation import full_agent_tools


@pytest.mark.parametrize("text", ["Q" * 100000, "中文" * 50000])
def test_large_unbroken_source_cannot_bypass_serialized_agent_budget(text):
    candidate = Candidate(candidate_id="c", case_id="c", repository_id="r", path="p.py", line=1, query="")
    selected, payload, count = _bounded_context_prompt(candidate, [
        Evidence(evidence_id="local:p.py", path="p.py", text=text, retrieval="local", score=1),
    ], token_budget=512)
    assert count == prompt_token_upper_bound(payload) <= 512
    assert len(selected[0].text) < len(text)
    assert context_text_token_count(text) == 1  # Historical proxy unit stays separate.


def test_a_spent_observation_budget_answers_every_later_call_with_its_diagnostic():
    document = CodeDocument(repository_id="r", path="p.py", text="Q" * 100000)
    registry = ToolRegistry(repository_tools(RepositoryIndex([document])), max_output_bytes=200000)
    scope = ToolExecutionScope(frozenset({document.path}), 512)
    call = ModelToolCall(call_id="read", name="read_span", arguments={"path": document.path})
    registry.invoke(call, allowed=("read_span",), scope=scope, citation_id="tool:1")
    assert scope.remaining_tokens == 0

    # The budget check precedes the repeat check, so an exhausted task always learns
    # why nothing can be answered instead of receiving an empty tool message.
    for citation, arguments in (("tool:2", {"path": document.path}), ("tool:3", {"path": "p.py"})):
        observation = registry.invoke(
            call.model_copy(update={"arguments": arguments}),
            allowed=("read_span",), scope=scope, citation_id=citation,
        )
        assert observation.status == "blocked"
        assert observation.metadata["model_payload_suppressed"] is False
        assert observation.metadata["observation_token_count"] == 0
        assert "budget is spent" in observation.content
        assert registry.prompt_payload(observation)
    assert scope.observed_tokens <= scope.max_observation_tokens


def test_large_tool_observation_is_bounded_and_charged_as_serialized_bytes():
    document = CodeDocument(repository_id="r", path="p.py", text="Q" * 100000)
    registry = ToolRegistry(repository_tools(RepositoryIndex([document])), max_output_bytes=200000)
    scope = ToolExecutionScope(frozenset({document.path}), 512)
    call = ModelToolCall(call_id="read", name="read_span", arguments={"path": document.path})
    observation = registry.invoke(call, allowed=("read_span",), scope=scope, citation_id="tool:1")
    payload = registry.prompt_payload(observation)
    assert len(payload.encode("utf-8")) <= 512
    assert scope.observed_tokens == len(payload.encode("utf-8"))
    assert observation.metadata["observation_truncated"]
    assert json.loads(payload)["citation_id"] == "tool:1"
    blocked = registry.invoke(call, allowed=("read_span",), scope=scope)
    assert blocked.status == "blocked"


def test_batch_calls_exhaustion_accounting():
    document = CodeDocument(repository_id="r", path="p.py", text="Q" * 100000)
    registry = ToolRegistry(repository_tools(RepositoryIndex([document])), max_output_bytes=200000)
    scope = ToolExecutionScope(frozenset({document.path}), 512)

    # Batch of 3 calls in one model turn
    call1 = ModelToolCall(call_id="call-1", name="read_span", arguments={"path": document.path})
    call2 = ModelToolCall(call_id="call-2", name="read_span", arguments={"path": document.path})
    call3 = ModelToolCall(call_id="call-3", name="search_symbols", arguments={"query": "test"})

    obs1 = registry.invoke(call1, allowed=("read_span", "search_symbols"), scope=scope, citation_id="scan/tool:1")
    assert scope.budget_exhausted is True or scope.remaining_tokens == 0

    obs2 = registry.invoke(call2, allowed=("read_span", "search_symbols"), scope=scope, citation_id="scan/tool:2")
    obs3 = registry.invoke(call3, allowed=("read_span", "search_symbols"), scope=scope, citation_id="scan/tool:3")

    # All 3 have valid observations and citations
    assert obs1.citation_id == "scan/tool:1"
    assert obs2.citation_id == "scan/tool:2"
    assert obs3.citation_id == "scan/tool:3"

    # Calls 2 and 3 are blocked due to budget exhaustion, but are accounted for
    assert obs2.status == "blocked"
    assert obs3.status == "blocked"
    assert "budget is spent" in obs2.content
    assert "budget is spent" in obs3.content


def test_priority_admission_obeys_top_k_and_serialized_budget_with_skip_audit():
    entry = CodeDocument(
        repository_id="r", path="p.py::entry@1-2",
        text="def entry(x):\n    return one(x) + two(x)\n",
        defines=("entry",), calls=("one", "two"),
    )
    one = CodeDocument(
        repository_id="r", path="p.py::one@4-5",
        text="def one(x):\n    return x\n", defines=("one",),
    )
    two = CodeDocument(
        repository_id="r", path="p.py::two@7-8",
        text="def two(x):\n    return x\n", defines=("two",),
    )
    index = RepositoryIndex([entry, one, two])
    candidate = Candidate(
        candidate_id="entry", case_id="entry", repository_id="r",
        path=entry.path, line=1, query="one", property_id="command-execution",
    )
    budget = RetrievalBudget(
        top_k=1, base_context_tokens=512, augmentation_context_tokens=128,
        graph_hops=1,
    )
    evidence, records = index.retrieve_context_with_admission(
        candidate, mode=RetrievalMode.GRAPH, budget=budget,
    )
    assert len(evidence) == 2
    assert {record["status"] for record in records} == {"admitted", "skipped"}
    assert next(record for record in records if record["status"] == "skipped")["reason"] == "top_k_budget"

    events: list[dict] = []
    pipeline = object.__new__(AgenticPipeline)
    pipeline.index = index
    spec = FULL_SYSTEM_HARNESS.system_spec(AgentSystemVersion.E3_GRAPH_SINGLE)
    pipeline.system_spec = spec.model_copy(update={"budget": budget})
    pipeline.retrieval_observer = events.append
    state = pipeline._retrieve({"candidate": candidate})
    assert state["context_token_count"] <= budget.total_context_tokens
    assert len(state["evidence"]) <= budget.top_k + 1
    admitted = [record for record in state["admission_records"] if record.status == "admitted"]
    assert len(admitted) == 1
    assert 0 < admitted[0].serialized_token_cost <= state["context_token_count"]
    assert events[0]["admission_records"] == [
        record.model_dump(mode="json") for record in state["admission_records"]
    ]

    zero_context = budget.model_copy(update={"augmentation_context_tokens": 0})
    local_only, zero_records = index.retrieve_context_with_admission(
        candidate, mode=RetrievalMode.GRAPH, budget=zero_context,
    )
    assert [item.path for item in local_only] == [entry.path]
    assert any(record["reason"] == "augmentation_context_budget" for record in zero_records)

    scripted = ScriptedChatModel([
        ModelReply(model_id="scripted", tool_calls=(
            ModelToolCall(call_id="read", name="run_static_check", arguments={"path": entry.path}),
        )),
        ModelReply(model_id="scripted", content=json.dumps({
            "expert": "scan", "label": "ABSTAIN", "confidence": 0.0,
            "validation_status": "UNRESOLVED", "evidence_ids": ["scan/tool:1"],
            "rationale": "The local check does not establish the candidate property.",
        })),
    ])
    verdict = AgenticPipeline(
        index=index, system=AgentSystemVersion.E3_GRAPH_SINGLE,
        models={"scan": scripted},
        tools=ToolRegistry(
            full_agent_tools(index),
            max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes,
        ),
    ).run(candidate)
    assert verdict.label == "ABSTAIN"
    assert verdict.retrieval_admission is not None
    assert verdict.retrieval_admission.subject_digest == state["admission_subject_digest"]
    assert verdict.retrieval_admission.records
    assert verdict.model_dump(mode="json")["retrieval_admission"]["records"]
