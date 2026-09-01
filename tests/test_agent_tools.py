from cv_agent.agent_tools import (
    AgentTool,
    ReadSpanInput,
    ToolExecutionScope,
    ToolRegistry,
    repository_tools,
)
from cv_agent.agent_types import ModelToolCall, ToolObservation
from cv_agent.retrieval import RepositoryIndex, context_text_token_count
from cv_agent.types import CodeDocument, FrozenModel


def _index() -> RepositoryIndex:
    return RepositoryIndex(
        [
            CodeDocument(
                repository_id="repo",
                path="entry.py::entry@1-2",
                text="def entry(value):\n    return sink(value)\n",
                defines=("entry",),
                calls=("sink",),
            ),
            CodeDocument(
                repository_id="repo",
                path="sink.py::sink@1-2",
                text="def sink(value):\n    return eval(value)\n",
                defines=("sink",),
            ),
        ]
    )


def _scope(*paths: str, token_budget: int = 10_000) -> ToolExecutionScope:
    return ToolExecutionScope(
        admitted_paths=frozenset(paths),
        max_observation_tokens=token_budget,
    )


def test_repository_tools_read_and_traverse_typed_graph():
    index = _index()
    registry = ToolRegistry(repository_tools(index), max_output_bytes=10_000)
    scope = _scope("entry.py::entry@1-2", "sink.py::sink@1-2")

    read = registry.invoke(
        ModelToolCall(
            call_id="read-1",
            name="read_span",
            arguments={"path": "entry.py::entry@1-2"},
        ),
        allowed=("read_span",),
        scope=scope,
    )
    graph = registry.invoke(
        ModelToolCall(
            call_id="graph-1",
            name="get_callees",
            arguments={"path": "entry.py::entry@1-2"},
        ),
        allowed=("get_callees",),
        scope=scope,
    )

    assert read.status == "ok"
    assert "return sink" in read.content
    assert graph.status == "ok"
    assert graph.content == "sink.py::sink@1-2"


def test_tool_registry_blocks_tools_outside_expert_allowlist():
    registry = ToolRegistry(repository_tools(_index()), max_output_bytes=10_000)
    scope = _scope("entry.py::entry@1-2")

    observation = registry.invoke(
        ModelToolCall(
            call_id="blocked-1",
            name="read_span",
            arguments={"path": "entry.py::entry@1-2"},
        ),
        allowed=("search_symbols",),
        scope=scope,
    )

    assert observation.status == "blocked"


def test_tool_registry_truncates_observations_at_harness_limit():
    registry = ToolRegistry(repository_tools(_index()), max_output_bytes=40)
    scope = _scope("entry.py::entry@1-2")

    observation = registry.invoke(
        ModelToolCall(
            call_id="read-1",
            name="read_span",
            arguments={"path": "entry.py::entry@1-2"},
        ),
        allowed=("read_span",),
        scope=scope,
    )

    assert len(observation.content.encode("utf-8")) <= 40
    assert observation.content.endswith("[tool output truncated by Harness]")


def test_repository_tools_cannot_escape_retrieved_execution_scope():
    registry = ToolRegistry(repository_tools(_index()), max_output_bytes=10_000)
    scope = _scope("entry.py::entry@1-2")

    read = registry.invoke(
        ModelToolCall(
            call_id="read-hidden",
            name="read_span",
            arguments={"path": "sink.py::sink@1-2"},
        ),
        allowed=("read_span",),
        scope=scope,
    )
    graph = registry.invoke(
        ModelToolCall(
            call_id="graph-hidden",
            name="get_callees",
            arguments={"path": "entry.py::entry@1-2"},
        ),
        allowed=("get_callees",),
        scope=scope,
    )
    search = registry.invoke(
        ModelToolCall(
            call_id="search-hidden",
            name="search_symbols",
            arguments={"query": "eval", "top_k": 50},
        ),
        allowed=("search_symbols",),
        scope=scope,
    )

    assert read.status == "blocked"
    assert graph.content == "no resolved callees"
    assert "sink.py" not in graph.content
    assert "sink.py" not in search.content


def test_tool_observations_share_one_bounded_context_budget():
    registry = ToolRegistry(repository_tools(_index()), max_output_bytes=10_000)
    scope = _scope("entry.py::entry@1-2", token_budget=32)
    call = ModelToolCall(
        call_id="read-budgeted",
        name="read_span",
        arguments={"path": "entry.py::entry@1-2"},
    )

    first = registry.invoke(call, allowed=("read_span",), scope=scope)
    second = registry.invoke(call, allowed=("read_span",), scope=scope)

    assert first.status == "ok"
    assert 0 < first.metadata["observation_token_count"] <= 32
    assert first.metadata["observation_token_count"] == context_text_token_count(
        registry.prompt_payload(first)
    )
    assert first.metadata["observation_truncated"] is True
    assert scope.observed_tokens == first.metadata["observation_token_count"]
    assert second.status == "blocked"
    assert second.metadata["observation_token_count"] == 0


def test_model_tool_payload_excludes_audit_metadata_and_evidence_ids():
    secret = "ORACLE_GROUND_TRUTH_" * 1_000

    def handle(
        arguments: FrozenModel,
        scope: ToolExecutionScope,
    ) -> ToolObservation:
        del arguments, scope
        return ToolObservation(
            tool="audit_tool",
            status="ok",
            content="model-visible evidence",
            evidence_ids=(secret,),
            metadata={"hidden_oracle": secret},
        )

    registry = ToolRegistry(
        (
            AgentTool(
                name="audit_tool",
                description="Return evidence with audit-only annotations.",
                input_model=ReadSpanInput,
                handler=handle,
            ),
        ),
        max_output_bytes=10_000,
    )
    scope = _scope("entry.py::entry@1-2", token_budget=64)
    observation = registry.invoke(
        ModelToolCall(
            call_id="audit-only-fields",
            name="audit_tool",
            arguments={"path": "entry.py::entry@1-2"},
        ),
        allowed=("audit_tool",),
        scope=scope,
    )
    prompt_payload = registry.prompt_payload(observation)

    assert secret not in prompt_payload
    assert observation.metadata["hidden_oracle"] == secret
    assert observation.evidence_ids == (secret,)
    assert observation.metadata["observation_token_count"] == (
        context_text_token_count(prompt_payload)
    )
