import json

import pytest

from cv_agent.agent_tools import ToolExecutionScope, ToolRegistry, repository_tools
from cv_agent.agent_types import ModelToolCall
from cv_agent.agentic_workflow import _bounded_context_prompt
from cv_agent.retrieval import RepositoryIndex, context_text_token_count, prompt_token_upper_bound
from cv_agent.types import Candidate, CodeDocument, Evidence


@pytest.mark.parametrize("text", ["Q" * 100000, "中文" * 50000])
def test_large_unbroken_source_cannot_bypass_serialized_agent_budget(text):
    candidate = Candidate(candidate_id="c", case_id="c", repository_id="r", path="p.py", line=1, query="")
    selected, payload, count = _bounded_context_prompt(candidate, [
        Evidence(evidence_id="local:p.py", path="p.py", text=text, retrieval="local", score=1),
    ], token_budget=512)
    assert count == prompt_token_upper_bound(payload) <= 512
    assert len(selected[0].text) < len(text)
    assert context_text_token_count(text) == 1  # Historical proxy unit stays separate.


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
