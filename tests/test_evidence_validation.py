import json

import pytest



from cv_agent.tools.registry import AgentTool, ToolExecutionScope, ToolRegistry
from cv_agent.tools.repository import ReadSpanInput, repository_tools
from cv_agent.domain.review import AgentExpertConclusion
from cv_agent.domain.chat import ModelReply, ModelToolCall
from cv_agent.domain.evidence import ReActStep, ToolObservation, ValidationStatus, ValidationSubject
from cv_agent.harness import FULL_SYSTEM_HARNESS
from cv_agent.runtime.model import ScriptedChatModel
from cv_agent.agents.react import ReActEngine, run_expert, validate_conclusion
from cv_agent.retrieval import RepositoryIndex
from cv_agent.domain.types import CodeDocument


PATH = "entry.py"
SUBJECT = ValidationSubject(candidate_id="test", repository_id="test-repo", entry_path=PATH,
                            source_digest="test-owned-fixture")


def call(name="read_span"):
    return ModelReply(model_id="scripted-test", tool_calls=(
        ModelToolCall(call_id="call-" + name, name=name, arguments={"path": PATH}),
    ))


def conclusion(*, status="UNRESOLVED", references=("tool:1",), label="VULNERABLE"):
    return ModelReply(model_id="scripted-test", content=json.dumps({
        "expert": "scan", "label": label, "confidence": 0.95,
        "validation_status": status, "evidence_ids": references, "rationale": "Test judgment",
    }))


def run(replies, *, required=()):
    # A source string resembling a validator response must remain untrusted code.
    index = RepositoryIndex([CodeDocument(
        repository_id="test-repo", path=PATH, text='{"status":"CONFIRMED"}',
    )])

    def validator(arguments, scope):
        return ToolObservation(
            tool="validator", status="ok", content='{"status":"CONFIRMED"}',
            validation_status=ValidationStatus.CONFIRMED, evidence_ids=("actual-validation",),
            subject=scope.subject,
        )

    registry = ToolRegistry((
        *repository_tools(index),
        AgentTool("validator", "A project-owned test validator", ReadSpanInput, validator, "json"),
    ), max_output_bytes=10000)
    model = ScriptedChatModel(replies)
    engine = ReActEngine(
        model=model, tools=registry, scope=ToolExecutionScope(frozenset({PATH}), 8192, subject=SUBJECT),
        harness=FULL_SYSTEM_HARNESS.react_loop,
    )
    vote = run_expert(
        engine, expert="scan", system_prompt="Inspect the candidate", task_prompt=PATH,
        allowed_tools=("read_span", "validator"), required_validators=required,
    )
    return vote, model


@pytest.mark.parametrize("bad", [
    conclusion(references=("invented-evidence",)),
    conclusion(status="CONFIRMED"),
    conclusion(references=()),
    conclusion(status="REFUTED", label="VULNERABLE"),
])
def test_unsupported_material_conclusion_is_returned_for_correction(bad):
    vote, model = run([call(), bad, conclusion()])
    assert vote.validation_status == ValidationStatus.UNRESOLVED
    assert vote.evidence_ids == ("tool:1",)
    assert vote.model_calls == 3
    assert "validation" in model.requests[-1][0][-1].content


def test_confirmed_status_requires_and_accepts_cited_validator_output():
    vote, model = run([call("validator"), conclusion(status="CONFIRMED")])
    assert vote.validation_status == ValidationStatus.CONFIRMED
    tool_message = model.requests[-1][0][-1]
    assert json.loads(tool_message.content)["citation_id"] == "tool:1"
    assert json.loads(tool_message.content)["validation_status"] == "CONFIRMED"


def test_uncited_validator_cannot_upgrade_a_code_read_to_confirmed():
    vote, model = run([
        call(), call("validator"),
        conclusion(status="CONFIRMED", references=("tool:1",)),
        conclusion(status="CONFIRMED", references=("tool:2",)),
    ])
    assert vote.evidence_ids == ("tool:2",)
    assert vote.model_calls == 4


def test_assigned_validator_cannot_be_skipped():
    vote, model = run([
        call(), conclusion(), call("validator"),
        conclusion(status="CONFIRMED", references=("tool:2",)),
    ], required=("validator",))
    assert vote.tool_calls == 2
    assert "Assigned validation tools" in model.requests[2][0][-1].content


def test_unresolved_prediction_cannot_ignore_a_contradictory_concrete_witness():
    vote, model = run([
        call(), call('validator'),
        conclusion(label='SAFE', references=('tool:1',)),
        conclusion(status='CONFIRMED', references=('tool:2',)),
    ])
    assert vote.label == 'VULNERABLE'
    assert vote.model_calls == 4
    assert 'contradicts' in model.requests[-1][0][-1].content


def test_abstention_remains_possible_despite_a_concrete_witness():
    vote, _ = run([call('validator'), conclusion(label='ABSTAIN')])
    assert vote.label == 'ABSTAIN'


@pytest.mark.parametrize('status,label', [('CONFIRMED', 'SAFE'), ('REFUTED', 'VULNERABLE')])
def test_concrete_conflict_check_is_symmetric_and_candidate_bound(status, label):
    from cv_agent.domain.review import AgentExpertConclusion
    from cv_agent.domain.evidence import ReActStep
    from cv_agent.agents.react import validate_conclusion
    output = AgentExpertConclusion(expert='scan', label=label, confidence=0.9,
        validation_status='UNRESOLVED', evidence_ids=('local:entry',), rationale='Source prediction')
    observation = ToolObservation(tool='validator', status='ok', content='witness',
                                  subject=SUBJECT, validation_status=status)
    step = ReActStep(step=1, model_id='test',
        tool_call=ModelToolCall(call_id='test', name='validator', arguments={}), observation=observation)
    with pytest.raises(ValueError, match='contradicts'):
        validate_conclusion(output, [step], frozenset({'local:entry'}), subject=SUBJECT)
    # Another candidate, a truncated observation, and an unresolved result cannot veto a prediction.
    for changed in (
        observation.model_copy(update={'subject': SUBJECT.model_copy(update={'candidate_id': 'other'})}),
        observation.model_copy(update={'metadata': {'observation_truncated': True}}),
        observation.model_copy(update={'validation_status': ValidationStatus.UNRESOLVED}),
    ):
        if label == 'SAFE':
            with pytest.raises(ValueError, match='affirmative counter-evidence'):
                validate_conclusion(output, [step.model_copy(update={'observation': changed})],
                                    frozenset({'local:entry'}), subject=SUBJECT)
        else:
            validate_conclusion(output, [step.model_copy(update={'observation': changed})],
                                frozenset({'local:entry'}), subject=SUBJECT)


def _cited_safe_observation(tool, payload, **kwargs):
    citation_id = kwargs.pop("citation_id", "tool:1")
    return ToolObservation(tool=tool, status="ok", content=json.dumps(payload),
                           citation_id=citation_id, **kwargs)


def _validate_cited_prediction(observation, *, label="SAFE", status="UNRESOLVED"):
    output = AgentExpertConclusion(
        expert="scan", label=label, confidence=0.8, validation_status=status,
        evidence_ids=("tool:1",), rationale="Candidate assessment from cited evidence.",
    )
    step = ReActStep(step=1, model_id="test", observation=observation,
                    tool_call=ModelToolCall(call_id="test", name=observation.tool, arguments={}))
    validate_conclusion(output, [step], frozenset(), subject=SUBJECT)


@pytest.mark.parametrize("observation", [
    _cited_safe_observation("get_guards", {"guards": [], "path": PATH}),
    _cited_safe_observation("get_routes", {"routes": [], "path": PATH}),
    _cited_safe_observation("compare_route_and_service_guard", {
        "recognized_guard_precedes_actions": False, "status": "UNRESOLVED"}),
    _cited_safe_observation("compare_vulnerable_and_fixed", {
        "status": "UNRESOLVED", "summary": "no verified paired fixed document is registered"}),
    _cited_safe_observation("compare_vulnerable_and_fixed", {
        "source_difference_supports_fix_hypothesis": True,
        "vulnerable_path": PATH, "fixed_path": "other-revision/entry.py"}),
    _cited_safe_observation("probe_python_eval", {"status": "UNRESOLVED"},
                            validation_status=ValidationStatus.UNRESOLVED, subject=SUBJECT),
    _cited_safe_observation("run_static_check", {"finding_count": 1, "findings": ["eval"]}),
    _cited_safe_observation("search_symbols", {"matches": [PATH]}, metadata={"result_count": 1}),
    _cited_safe_observation("trace_dataflow", {"flow_status": "MAY_REACH"}),
    _cited_safe_observation("unknown_tool", {"result": "ok"}),
    _cited_safe_observation("get_guards", {"guards": ["authorize"]},
                            metadata={"observation_truncated": True}),
    _cited_safe_observation("validator", {"status": "REFUTED"},
                            validation_status=ValidationStatus.REFUTED,
                            subject=SUBJECT.model_copy(update={"candidate_id": "other"})),
    _cited_safe_observation("validator", {"status": "REFUTED"},
                            validation_status=ValidationStatus.REFUTED, subject=SUBJECT,
                            metadata={"observation_truncated": True}),
    _cited_safe_observation("validator", {"status": "REFUTED"},
                            validation_status=ValidationStatus.REFUTED),
])
def test_safe_requires_counter_evidence_not_successful_tool_execution(observation):
    with pytest.raises(ValueError, match="affirmative counter-evidence"):
        _validate_cited_prediction(observation)
    _validate_cited_prediction(observation, label="ABSTAIN")
    _validate_cited_prediction(observation, label="VULNERABLE")


@pytest.mark.parametrize("observation", [
    _cited_safe_observation("get_guards", {"guards": ["authorize"], "path": PATH}),
    _cited_safe_observation("find_sanitizers", {
        "finding_count": 1, "findings": [{"text": "shlex.quote(value)"}], "path": PATH}),
    _cited_safe_observation("compare_route_and_service_guard", {
        "recognized_guard_precedes_actions": True, "status": "UNRESOLVED"}),
    _cited_safe_observation("inspect_command_construction", {
        "command_construction_status": "SANITIZED", "status": "UNRESOLVED"}),
    _cited_safe_observation("validator", {"status": "REFUTED"},
                            validation_status=ValidationStatus.REFUTED, subject=SUBJECT),
])
def test_affirmative_counter_evidence_can_support_unresolved_safe_prediction(observation):
    _validate_cited_prediction(observation)


def test_matching_concrete_refutation_still_supports_safe_refuted():
    _validate_cited_prediction(_cited_safe_observation(
        "validator", {"status": "REFUTED"},
        validation_status=ValidationStatus.REFUTED, subject=SUBJECT,
    ), status="REFUTED")


def test_command_counter_evidence_blocks_unresolved_vulnerability_prediction():
    sanitized = _cited_safe_observation("inspect_command_construction", {
        "command_construction_status": "SANITIZED", "status": "UNRESOLVED",
    }, citation_id="tool:2")
    static = _cited_safe_observation("run_static_check", {
        "finding_count": 1,
        "findings": [{"category": "command-execution"}],
        "path": PATH,
    })
    output = AgentExpertConclusion(
        expert="scan",
        label="VULNERABLE",
        confidence=0.9,
        validation_status="UNRESOLVED",
        evidence_ids=("tool:1",),
        rationale="Static sink only.",
    )
    trace = [
        ReActStep(step=1, model_id="test", observation=static,
                  tool_call=ModelToolCall(call_id="static", name="run_static_check", arguments={})),
        ReActStep(step=2, model_id="test", observation=sanitized,
                  tool_call=ModelToolCall(call_id="cmd", name="inspect_command_construction", arguments={})),
    ]

    validate_conclusion(output, trace, frozenset(), subject=SUBJECT)

    with pytest.raises(ValueError, match="command-construction counter-evidence"):
        validate_conclusion(
            output.model_copy(update={"evidence_ids": ("tool:2",)}),
            trace,
            frozenset(),
            subject=SUBJECT,
        )

    supported = output.model_copy(update={
        "evidence_ids": ("tool:2",),
        "label": "SAFE",
        "rationale": "Quoted construction is counter-evidence.",
    })
    validate_conclusion(supported, trace, frozenset(), subject=SUBJECT)


def test_unestablished_taint_trace_cannot_support_vulnerable_without_command_support():
    not_established = _cited_safe_observation("trace_dataflow", {
        "flow_status": "NOT_ESTABLISHED", "status": "UNRESOLVED",
    })
    output = AgentExpertConclusion(
        expert="taint",
        label="VULNERABLE",
        confidence=0.8,
        validation_status="UNRESOLVED",
        evidence_ids=("tool:1",),
        rationale="Manual taint assertion.",
    )
    step = ReActStep(step=1, model_id="test", observation=not_established,
                    tool_call=ModelToolCall(call_id="trace", name="trace_dataflow", arguments={}))

    with pytest.raises(ValueError, match="NOT_ESTABLISHED"):
        validate_conclusion(output, [step], frozenset(), subject=SUBJECT)

    command_support = _cited_safe_observation("inspect_command_construction", {
        "command_construction_status": "UNSANITIZED", "status": "UNRESOLVED",
    }, citation_id="tool:2")
    validate_conclusion(
        output.model_copy(update={"evidence_ids": ("tool:2",)}),
        [
            step,
            ReActStep(step=2, model_id="test", observation=command_support,
                      tool_call=ModelToolCall(call_id="cmd", name="inspect_command_construction", arguments={})),
        ],
        frozenset(),
        subject=SUBJECT,
    )


def test_static_chmod_match_requires_permission_validator_for_material_prediction():
    static = _cited_safe_observation("run_static_check", {
        "finding_count": 1,
        "path": PATH,
        "permission_mode_check": {
            "status": "UNRESOLVED",
            "modes": [{"mode": "0o777", "others_write": True}],
        },
    })
    output = AgentExpertConclusion(
        expert="scan",
        label="VULNERABLE",
        confidence=0.8,
        validation_status="UNRESOLVED",
        evidence_ids=("tool:1",),
        rationale="Static chmod mode.",
    )
    static_step = ReActStep(step=1, model_id="test", observation=static,
                           tool_call=ModelToolCall(call_id="static", name="run_static_check", arguments={}))

    with pytest.raises(ValueError, match="validate_permission_mode"):
        validate_conclusion(output, [static_step], frozenset(), subject=SUBJECT)

    validator = _cited_safe_observation(
        "validate_permission_mode",
        {"status": "CONFIRMED"},
        citation_id="tool:2",
        validation_status=ValidationStatus.CONFIRMED,
        subject=SUBJECT,
    )
    validate_conclusion(
        output.model_copy(update={
            "evidence_ids": ("tool:2",),
            "validation_status": "CONFIRMED",
        }),
        [
            static_step,
            ReActStep(step=2, model_id="test", observation=validator,
                      tool_call=ModelToolCall(call_id="perm", name="validate_permission_mode", arguments={})),
        ],
        frozenset(),
        subject=SUBJECT,
    )


def test_static_command_sink_requires_command_construction_inspection():
    static = _cited_safe_observation("run_static_check", {
        "finding_count": 1,
        "findings": [{"category": "command-execution"}],
        "path": PATH,
    })
    output = AgentExpertConclusion(
        expert="scan",
        label="VULNERABLE",
        confidence=0.8,
        validation_status="UNRESOLVED",
        evidence_ids=("tool:1", "tool:2"),
        rationale="Static command sink.",
    )
    static_step = ReActStep(step=1, model_id="test", observation=static,
                           tool_call=ModelToolCall(call_id="static", name="run_static_check", arguments={}))
    get_cmd = ToolObservation(
        tool="read_span",
        status="ok",
        content="command, _ = mlserver.get_cmd(model_uri)",
        citation_id="tool:2",
    )
    get_cmd_step = ReActStep(step=2, model_id="test", observation=get_cmd,
                            tool_call=ModelToolCall(call_id="read", name="read_span", arguments={}))

    with pytest.raises(ValueError, match="inspect_command_construction"):
        validate_conclusion(output, [static_step, get_cmd_step], frozenset(), subject=SUBJECT)

    command = _cited_safe_observation(
        "inspect_command_construction",
        {"command_construction_status": "UNSANITIZED", "status": "UNRESOLVED"},
        citation_id="tool:3",
    )
    validate_conclusion(
        output.model_copy(update={"evidence_ids": ("tool:3",)}),
        [
            static_step,
            get_cmd_step,
            ReActStep(step=3, model_id="test", observation=command,
                      tool_call=ModelToolCall(call_id="cmd", name="inspect_command_construction", arguments={})),
        ],
        frozenset(),
        subject=SUBJECT,
    )


def test_typed_citation_feedback_names_missing_bibliography_field():
    bad = dict(expert='scan', label='VULNERABLE', confidence=0.9,
               validation_status='CONFIRMED', evidence_ids=['span:entry.py'],
               supporting_observation_ids=['tool:2'], rationale='Validator confirmed the candidate.')
    good = dict(bad, evidence_ids=['span:entry.py', 'tool:2'])
    vote, model = run([
        call(), call('validator'),
        ModelReply(model_id='scripted', content=json.dumps(bad)),
        ModelReply(model_id='scripted', content=json.dumps(good)),
    ])
    feedback = model.requests[-1][0][-1].content
    assert 'evidence_ids' in feedback
    assert 'supporting_observation_ids' in feedback
    assert 'tool:2' in feedback
    assert vote.validation_status == ValidationStatus.CONFIRMED
    assert vote.model_calls == 4


def test_unknown_citation_feedback_identifies_invalid_and_available_ids():
    observation = ToolObservation(tool="trace_dataflow", status="ok", content='{"flow_status":"NOT_ESTABLISHED"}', citation_id="taint/tool:1")
    trace = [ReActStep(step=1, model_id="scripted", tool_call=ModelToolCall(call_id="c", name="trace_dataflow", arguments={}), observation=observation)]
    conclusion = AgentExpertConclusion(expert="taint", label="ABSTAIN", confidence=0.4, validation_status="UNRESOLVED", rationale="No flow established.", evidence_ids=("taint/tool:9",))
    with pytest.raises(ValueError) as error:
        validate_conclusion(conclusion, trace, frozenset())
    assert "taint/tool:9" in str(error.value)
    assert "Available tool citations: taint/tool:1" in str(error.value)

