import pytest


def test_confirmation_requires_exact_candidate_and_source_subject():
    from cv_agent.agent_types import (
        ValidationSubject, ToolObservation, AgentExpertConclusion, ReActStep, ModelToolCall,
    )
    from cv_agent.react_engine import validate_conclusion
    subject = ValidationSubject(candidate_id="one", repository_id="repo",
                                entry_path="entry.py", source_digest="source-a")
    vote = AgentExpertConclusion(expert="scan", label="VULNERABLE", confidence=.9,
        validation_status="CONFIRMED", evidence_ids=("tool:1",), rationale="bounded witness")
    def check(observed):
        observation = ToolObservation(tool="probe_python_eval", status="ok", content="witness",
            citation_id="tool:1", validation_status="CONFIRMED", subject=observed)
        trace = [ReActStep(step=1, model_id="offline", observation=observation,
                          tool_call=ModelToolCall(call_id="one", name=observation.tool, arguments={}))]
        validate_conclusion(vote, trace, frozenset(), subject=subject)
    check(subject)
    for wrong in (None, subject.model_copy(update={"candidate_id": "two"}),
                  subject.model_copy(update={"source_digest": "source-b"}),
                  subject.model_copy(update={"repository_id": "other"}),
                  subject.model_copy(update={"entry_path": "helper.py"})):
        with pytest.raises(ValueError, match="subject"):
            check(wrong)


@pytest.mark.parametrize("tool_name", ["run_fixture_test", "run_loopback_http_case"])
def test_mismatched_or_unbound_fixture_is_blocked_before_execution(monkeypatch, tool_name):
    from cv_agent.agent_types import ValidationSubject, ModelToolCall
    from cv_agent.agent_tools import ToolRegistry, ToolExecutionScope
    from cv_agent.types import CodeDocument
    from cv_agent.retrieval import RepositoryIndex
    from cv_agent.validation_tools import full_agent_tools, FixtureCase, LoopbackCase
    subject = ValidationSubject(candidate_id="one", repository_id="repo",
                                entry_path="entry.py", source_digest="source-a")
    def should_not_run(*args, **kwargs):
        pytest.fail("wrong-subject validator executed")
    monkeypatch.setattr("cv_agent.validation_tools.fixtures._run_fixture_case", should_not_run)
    monkeypatch.setattr("cv_agent.validation_tools.fixtures._run_loopback_case", should_not_run)
    index = RepositoryIndex([CodeDocument(repository_id="repo", path="entry.py", text="safe")])
    for bound in (None, subject.model_copy(update={"candidate_id": "two"})):
        options = ({"fixture_cases": (FixtureCase("test", should_not_run, subject=bound),)}
                   if tool_name == "run_fixture_test" else
                   {"loopback_cases": (LoopbackCase("test", should_not_run, subject=bound),)})
        registry = ToolRegistry(full_agent_tools(index, **options), max_output_bytes=10000)
        result = registry.invoke(ModelToolCall(call_id="one", name=tool_name, arguments={"case_id": "test"}),
            allowed=(tool_name,), scope=ToolExecutionScope(frozenset({"entry.py"}), 10000,
                                                          candidate_path="entry.py", subject=subject))
        assert result.status == "blocked"


def test_matching_registered_fixture_keeps_bound_confirmation(monkeypatch):
    from cv_agent.agent_tools import candidate_subject, ToolRegistry, ToolExecutionScope
    from cv_agent.agent_types import ModelToolCall
    from cv_agent.types import Candidate, CodeDocument
    from cv_agent.retrieval import RepositoryIndex
    from cv_agent.validation_tools import FixtureCase, FixtureOutcome, full_agent_tools
    document = CodeDocument(repository_id="repo", path="entry.py", text="version A")
    index = RepositoryIndex([document])
    candidate = Candidate(candidate_id="one", case_id="one", repository_id="repo", path=document.path, line=1, query="")
    subject = candidate_subject(index, candidate)
    calls = []
    def execute(case, timeout):
        calls.append(case.case_id)
        return FixtureOutcome(status="CONFIRMED", summary="registered bounded witness")
    monkeypatch.setattr("cv_agent.validation_tools.fixtures._run_fixture_case", execute)
    fixture = FixtureCase("one", lambda: None, subject=subject)
    registry = ToolRegistry(full_agent_tools(index, fixture_cases=(fixture,)), max_output_bytes=10000)
    observation = registry.invoke(ModelToolCall(call_id="one", name="run_fixture_test", arguments={"case_id": "one"}),
        allowed=("run_fixture_test",), scope=ToolExecutionScope(frozenset({document.path}), 10000,
                                                              candidate_path=document.path, subject=subject))
    assert calls == ["one"]
    assert observation.validation_status.value == "CONFIRMED"
    assert observation.subject == subject
    changed = RepositoryIndex([document.model_copy(update={"text": "version B"})])
    assert candidate_subject(changed, candidate).source_digest != subject.source_digest


def test_scope_rejects_inconsistent_subject_entry():
    from cv_agent.agent_types import ValidationSubject
    from cv_agent.agent_tools import ToolExecutionScope
    subject = ValidationSubject(candidate_id="one", repository_id="repo", entry_path="other.py", source_digest="one")
    with pytest.raises(ValueError, match="subject entry"):
        ToolExecutionScope(frozenset({"entry.py"}), 1000, candidate_path="entry.py", subject=subject)
