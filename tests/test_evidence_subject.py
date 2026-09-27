import pytest


@pytest.mark.parametrize("property_id", [
    "declared-target-property", "database-operation", "template-operation",
    "authorization-boundary", "dynamic-attribute-access", "process-control",
])
def test_confirmation_requires_exact_candidate_and_source_subject(property_id):
    from cv_agent.domain.evidence import FixtureProofScope, ValidationStatus, ValidationSubject, ToolObservation, ReActStep
    from cv_agent.domain.review import AgentExpertConclusion
    from cv_agent.domain.chat import ModelToolCall
    from cv_agent.agents.react import validate_conclusion
    subject = ValidationSubject(candidate_id="one", repository_id="repo",
                                entry_path="entry.py", source_digest="source-a", property_id=property_id)
    proof = FixtureProofScope(contract_id="bounded-identity-control", property_id=property_id,
                              coverage="candidate", method="bounded_execution",
                              supported_statuses=(ValidationStatus.CONFIRMED,))
    vote = AgentExpertConclusion(expert="scan", label="VULNERABLE", confidence=.9,
        validation_status="CONFIRMED", evidence_ids=("tool:1",), rationale="bounded witness")
    def check(observed):
        observation = ToolObservation(tool="run_fixture_test", status="ok", content="witness",
            citation_id="tool:1", validation_status="CONFIRMED", subject=observed,
            fixture_proof=proof)
        trace = [ReActStep(step=1, model_id="offline", observation=observation,
                          tool_call=ModelToolCall(call_id="one", name=observation.tool, arguments={}))]
        validate_conclusion(vote, trace, frozenset(), subject=subject)
    check(subject)
    for wrong in (None, subject.model_copy(update={"candidate_id": "two"}),
                  subject.model_copy(update={"source_digest": "source-b"}),
                  subject.model_copy(update={"repository_id": "other"}),
                  subject.model_copy(update={"entry_path": "helper.py"}),
                  subject.model_copy(update={"property_id": "other-property"})):
        with pytest.raises(ValueError, match="subject|property"):
            check(wrong)


@pytest.mark.parametrize("tool_name", ["run_fixture_test", "run_loopback_http_case"])
def test_mismatched_or_unbound_fixture_is_blocked_before_execution(monkeypatch, tool_name):
    from cv_agent.domain.evidence import ValidationSubject
    from cv_agent.domain.chat import ModelToolCall
    from cv_agent.tools.registry import ToolRegistry, ToolExecutionScope
    from cv_agent.domain.types import CodeDocument
    from cv_agent.retrieval import RepositoryIndex
    from cv_agent.tools.validation import full_agent_tools, FixtureCase, LoopbackCase
    subject = ValidationSubject(candidate_id="one", repository_id="repo",
                                entry_path="entry.py", source_digest="source-a")
    def should_not_run(*args, **kwargs):
        pytest.fail("wrong-subject validator executed")
    monkeypatch.setattr("cv_agent.tools.validation.fixtures._run_fixture_case", should_not_run)
    monkeypatch.setattr("cv_agent.tools.validation.fixtures._run_loopback_case", should_not_run)
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
    from cv_agent.tools.identity import candidate_subject
    from cv_agent.tools.registry import ToolRegistry, ToolExecutionScope
    from cv_agent.domain.chat import ModelToolCall
    from cv_agent.domain.types import Candidate, CodeDocument
    from cv_agent.retrieval import RepositoryIndex
    from cv_agent.tools.validation import FixtureCase, FixtureOutcome, full_agent_tools
    document = CodeDocument(repository_id="repo", path="entry.py", text="version A")
    index = RepositoryIndex([document])
    candidate = Candidate(candidate_id="one", case_id="one", repository_id="repo", path=document.path, line=1, query="", property_id="test-prop")
    subject = candidate_subject(index, candidate)
    calls = []
    def execute(case, timeout):
        calls.append(case.case_id)
        return FixtureOutcome(status="CONFIRMED", summary="registered bounded witness")
    monkeypatch.setattr("cv_agent.tools.validation.fixtures._run_fixture_case", execute)
    from cv_agent.domain.evidence import FixtureProofScope, ValidationStatus
    proof_scope = FixtureProofScope(
        contract_id="contract-one",
        property_id="test-prop",
        coverage="candidate",
        method="bounded_execution",
        supported_statuses=(ValidationStatus.CONFIRMED, ValidationStatus.REFUTED),
    )
    fixture = FixtureCase("one", lambda: None, subject=subject, proof_scope=proof_scope)
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
    from cv_agent.domain.evidence import ValidationSubject
    from cv_agent.tools.registry import ToolExecutionScope
    subject = ValidationSubject(candidate_id="one", repository_id="repo", entry_path="other.py", source_digest="one")
    with pytest.raises(ValueError, match="subject entry"):
        ToolExecutionScope(frozenset({"entry.py"}), 1000, candidate_path="entry.py", subject=subject)


@pytest.mark.parametrize('tool', ['validate_permission_mode', 'probe_python_eval'])
def test_legacy_validator_stamp_without_property_cannot_supply_candidate_proof(tool):
    from cv_agent.domain.evidence import ValidationSubject, ToolObservation, ReActStep
    from cv_agent.domain.review import AgentExpertConclusion
    from cv_agent.domain.chat import ModelToolCall
    from cv_agent.agents.evidence_policy import validate_conclusion

    subject = ValidationSubject(candidate_id='one', repository_id='r', entry_path='entry.py',
                                source_digest='source')
    observation = ToolObservation(tool=tool, status='ok', content='{}', citation_id='proof',
                                  subject=subject, validation_status='CONFIRMED')
    trace = [ReActStep(step=1, model_id='offline', observation=observation,
                      tool_call=ModelToolCall(call_id='proof', name=tool, arguments={}))]
    output = AgentExpertConclusion(expert='scan', label='VULNERABLE', confidence=.9,
                                   validation_status='CONFIRMED', evidence_ids=('proof',), rationale='Old stamp.')
    with pytest.raises(ValueError):
        validate_conclusion(output, trace, frozenset(), subject=subject)


@pytest.mark.parametrize('label,mode', [('SAFE', '0o750'), ('VULNERABLE', '0o777')])
@pytest.mark.parametrize('delivery', ['complete', 'truncated', 'suppressed', 'blocked', 'error'])
def test_real_permission_proof_requires_complete_successful_delivery(label, mode, delivery):
    from cv_agent.agents.evidence_policy import validate_conclusion
    from cv_agent.domain.chat import ModelToolCall
    from cv_agent.domain.evidence import ReActStep, ValidationSubject
    from cv_agent.domain.review import AgentExpertConclusion
    from cv_agent.domain.types import CodeDocument
    from cv_agent.retrieval import RepositoryIndex
    from cv_agent.tools.identity import repository_source_digest
    from cv_agent.tools.registry import ToolExecutionScope
    from cv_agent.tools.validation.permissions import permission_mode
    from cv_agent.tools.validation.models import PathInput
    document = CodeDocument(repository_id='r', path='entry.py',
                            text=f'def entry():\n    os.chmod("target", {mode})\n')
    index = RepositoryIndex([document])
    subject = ValidationSubject(candidate_id='c', repository_id='r', entry_path=document.path,
        entry_line=1, property_id='chmod-mode-others-write', source_digest=repository_source_digest(index))
    proof = permission_mode(index, PathInput(path=document.path), ToolExecutionScope(
        candidate_path=document.path, admitted_paths=frozenset({document.path}),
        subject=subject, max_observation_tokens=10000)).model_copy(update={'citation_id': 'proof'})
    assert proof.subject == subject
    assert proof.validation_status.value == ('REFUTED' if label == 'SAFE' else 'CONFIRMED')
    if delivery in {'blocked', 'error'}:
        proof = proof.model_copy(update={'status': delivery})
    elif delivery != 'complete':
        key = 'observation_truncated' if delivery == 'truncated' else 'model_payload_suppressed'
        proof = proof.model_copy(update={'metadata': {key: True}})
    trace = [ReActStep(step=1, model_id='offline', observation=proof,
                      tool_call=ModelToolCall(call_id='proof', name=proof.tool, arguments={}))]
    proposal = AgentExpertConclusion(expert='scan', label=label, confidence=.9,
        validation_status=proof.validation_status, evidence_ids=('proof',),
        supporting_observation_ids=('proof',), rationale='Bounded literal mode proof.')
    if delivery == 'complete':
        validate_conclusion(proposal, trace, frozenset(), subject=subject)
    else:
        with pytest.raises(ValueError):
            validate_conclusion(proposal, trace, frozenset(), subject=subject)
    abstain = proposal.model_copy(update={'label': 'ABSTAIN', 'validation_status': 'UNRESOLVED',
                                         'evidence_ids': (), 'supporting_observation_ids': ()})
    validate_conclusion(abstain, trace, frozenset(), subject=subject)
