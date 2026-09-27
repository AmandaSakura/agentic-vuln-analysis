import json
from pathlib import Path

import pytest

from cv_agent.domain.evidence import ValidationStatus, ValidationSubject, FixtureProofScope
from cv_agent.domain.review import AgentExpertConclusion
from cv_agent.domain.chat import ModelToolCall
from cv_agent.domain.types import CodeDocument
from cv_agent.agents.evidence_policy import validate_conclusion, InsufficientEvidenceError
from cv_agent.retrieval import RepositoryIndex
from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.registry import ToolExecutionScope, ToolRegistry
from cv_agent.tools.validation import full_agent_tools, FixtureCase, FixtureOutcome
from cv_agent.harness import FULL_SYSTEM_HARNESS
from test_advisory_fixtures import (
    _hp001_pair,
    _hp002_pair,
    _pair,
    _write_case,
    _write_hp001_case,
    _write_hp002_case,
    _invoke_registered_fixture,
    VULNERABLE_MLSERVER,
    FIXED_MLSERVER,
)


def test_dead_chmod_pattern_cannot_confirm_directory_race(tmp_path):
    source = tmp_path / "vulnerable/mlflow/utils/file_utils.py"
    source.parent.mkdir(parents=True)
    source.write_text("""import atexit, os, shutil, tempfile
def get_or_create_tmp_dir():
    tmp_dir = tempfile.mkdtemp()
    if False:
        os.chmod(tmp_dir, 0o777)
    atexit.register(shutil.rmtree, tmp_dir, ignore_errors=True)
    return tmp_dir
""")
    pair = _hp001_pair()
    observation = _invoke_registered_fixture(tmp_path, pair, pair.cases[0])
    assert observation.status == "ok"
    assert observation.validation_status == ValidationStatus.UNRESOLVED
    assert observation.subject.property_id == "temporary-directory-race"


def test_dead_owner_guard_cannot_refute_authorization_boundary(tmp_path):
    _write_hp002_case(tmp_path, "fixed", guarded=True)
    path = tmp_path / "fixed/src/backend/base/langflow/services/database/models/api_key/crud.py"
    path.write_text(path.read_text().replace(
        "if api_key.user_id != user_id:",
        "if False and api_key.user_id != user_id:",
    ))
    pair = _hp002_pair()
    observation = _invoke_registered_fixture(tmp_path, pair, pair.cases[1])
    assert observation.status == "ok"
    assert observation.validation_status == ValidationStatus.UNRESOLVED
    assert observation.subject.property_id == "authorization-boundary"


def test_hp003_measurement_is_independent_of_expected_revision_role(tmp_path):
    _write_case(tmp_path, "vulnerable", VULNERABLE_MLSERVER)
    pair = _pair()
    case = pair.cases[0]
    original = _invoke_registered_fixture(tmp_path, pair, case)
    flipped = _invoke_registered_fixture(
        tmp_path, pair, case.model_copy(update={"revision_role": "fixed"}),
    )
    assert original.subject == flipped.subject
    assert original.validation_status == flipped.validation_status
    assert json.loads(original.content) == json.loads(flipped.content)


def test_hp001_counterexamples_and_local_scope(tmp_path):
    # Non-tmpdir target
    source = tmp_path / "vulnerable/mlflow/utils/file_utils.py"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("""import atexit, os, shutil, tempfile
def get_or_create_tmp_dir():
    tmp_dir = tempfile.mkdtemp()
    other_var = "/tmp/other"
    os.chmod(other_var, 0o777)
    atexit.register(shutil.rmtree, tmp_dir, ignore_errors=True)
    return tmp_dir
""")
    pair = _hp001_pair()
    obs = _invoke_registered_fixture(tmp_path, pair, pair.cases[0])
    assert obs.status == "ok"
    assert obs.validation_status == ValidationStatus.UNRESOLVED
    content = json.loads(obs.content)
    assert content["status"] == "UNRESOLVED"

    # Even on genuine 0o777 chmod, the fixture is declared coverage='local',
    # so candidate-level validation_status must remain UNRESOLVED while preserving local fact.
    source.write_text("""import atexit, os, shutil, tempfile
def get_or_create_tmp_dir():
    tmp_dir = tempfile.mkdtemp()
    os.chmod(tmp_dir, 0o777)
    atexit.register(shutil.rmtree, tmp_dir, ignore_errors=True)
    return tmp_dir
""")
    obs777 = _invoke_registered_fixture(tmp_path, pair, pair.cases[0])
    assert obs777.status == "ok"
    assert obs777.validation_status == ValidationStatus.UNRESOLVED
    content777 = json.loads(obs777.content)
    assert content777["status"] == "UNRESOLVED"
    assert "0o777" in content777["details"]["chmod_modes"]
    assert content777["raw_status"] == "CONFIRMED"


@pytest.mark.parametrize(
    "delete_call, rejection",
    [
        ("session.delete(api_key)", "raise HTTPException(status_code=403, detail=\"Cannot delete another user's API key\")"),
        ("await session.delete(api_key)", "raise ValueError(\"Cannot delete another user's API key\")"),
    ],
)
def test_hp002_counterexamples_and_local_scope(tmp_path, delete_call, rejection):
    # Guard after delete
    _write_hp002_case(tmp_path, "fixed", guarded=True)
    path = tmp_path / "fixed/src/backend/base/langflow/services/database/models/api_key/crud.py"
    orig = path.read_text()
    if delete_call.startswith("await "):
        assert "    session.delete(api_key)" in orig
        assert '    raise HTTPException(status_code=403, detail="Cannot delete another user\'s API key")' in orig
        orig = orig.replace("    session.delete(api_key)", f"    {delete_call}")
        orig = orig.replace(
            '    raise HTTPException(status_code=403, detail="Cannot delete another user\'s API key")',
            f"    {rejection}",
        )
        path.write_text(orig)
    # Move delete before the owner guard
    target = (
        '    if api_key.user_id != user_id:\n'
        f"        {rejection}\n"
        f"    {delete_call}"
    )
    replacement = (
        f"    {delete_call}\n"
        '    if api_key.user_id != user_id:\n'
        f"        {rejection}"
    )
    assert target in orig, "Expected guard pattern in original source"
    swapped = orig.replace(target, replacement)
    assert swapped != orig
    assert swapped.index(delete_call) < swapped.index("if api_key.user_id != user_id")
    path.write_text(swapped)
    pair = _hp002_pair()
    obs = _invoke_registered_fixture(tmp_path, pair, pair.cases[1])
    assert obs.status == "ok"
    # Even if strings were present, guard after delete ensures UNRESOLVED
    assert obs.validation_status == ValidationStatus.UNRESOLVED
    payload = json.loads(obs.content)
    assert payload["status"] == "UNRESOLVED"
    assert payload["details"]["guard_precedes_delete"] is False


def test_candidate_admission_rejects_local_fixture(tmp_path):
    _write_case(tmp_path, "vulnerable", VULNERABLE_MLSERVER)
    pair = _pair()
    case = pair.cases[0]
    observation = _invoke_registered_fixture(tmp_path, pair, case)
    assert observation.validation_status == ValidationStatus.UNRESOLVED
    assert observation.fixture_proof is not None
    assert observation.fixture_proof.coverage == "local"

    # Attempting to cite this local fixture as proof for candidate VULNERABLE must fail
    conclusion = AgentExpertConclusion(
        expert="scan",
        label="VULNERABLE",
        confidence=0.95,
        validation_status=ValidationStatus.CONFIRMED,
        evidence_ids=(observation.citation_id or "fixture:hp003_a",),
        supporting_observation_ids=(observation.citation_id or "fixture:hp003_a",),
        counter_observation_ids=(),
        unresolved_observation_ids=(),
        rationale="Probe observed expansion.",
    )
    step = ModelToolCall(
        call_id="call-1",
        name="run_fixture_test",
        arguments={"case_id": case.case_id},
    )
    from cv_agent.domain.evidence import ReActStep
    trace = [ReActStep(step=1, model_id="test", tool_call=step, observation=observation)]

    with pytest.raises((InsufficientEvidenceError, ValueError)):
        validate_conclusion(
            conclusion,
            trace,
            initial_evidence_ids=frozenset(),
            required_validators=(),
            subject=observation.subject,
        )


def test_positive_control_candidate_proof_accepted():
    # A genuine candidate-level proof scope is accepted
    subject = ValidationSubject(
        property_id="command-execution",
        candidate_id="c1",
        repository_id="r1",
        entry_path="app.py",
        source_digest="sha" * 16,
    )
    candidate_proof = FixtureProofScope(
        contract_id="contract_test",
        property_id="command-execution",
        coverage="candidate",
        method="bounded_execution",
        supported_statuses=(ValidationStatus.CONFIRMED, ValidationStatus.REFUTED),
    )
    obs = _invoke_registered_fixture_with_scope(subject, candidate_proof, ValidationStatus.CONFIRMED)
    assert obs.validation_status == ValidationStatus.CONFIRMED

    citation = obs.citation_id or "fixture:test"
    obs_with_citation = obs.model_copy(update={"citation_id": citation})
    conclusion = AgentExpertConclusion(
        expert="scan",
        label="VULNERABLE",
        confidence=0.95,
        validation_status=ValidationStatus.CONFIRMED,
        evidence_ids=(citation,),
        supporting_observation_ids=(citation,),
        counter_observation_ids=(),
        unresolved_observation_ids=(),
        rationale="Candidate test executed and confirmed.",
    )
    from cv_agent.domain.evidence import ReActStep
    call = ModelToolCall(call_id="call-1", name="run_fixture_test", arguments={"case_id": "test"})
    trace = [ReActStep(step=1, model_id="test", tool_call=call, observation=obs_with_citation)]
    # This must NOT raise:
    validate_conclusion(conclusion, trace, initial_evidence_ids=frozenset(), required_validators=(), subject=subject)


def _invoke_registered_fixture_with_scope(subject, proof_scope, outcome_status):
    case = FixtureCase(
        case_id="test",
        runner=lambda: FixtureOutcome(status=outcome_status, summary="outcome"),
        subject=subject,
        proof_scope=proof_scope,
    )
    registry = ToolRegistry(
        full_agent_tools(RepositoryIndex(documents=()), fixture_cases=(case,)),
        max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes,
    )
    return registry.invoke(
        ModelToolCall(call_id="fixture", name="run_fixture_test", arguments={"case_id": "test"}),
        allowed=("run_fixture_test",),
        scope=ToolExecutionScope(
            admitted_paths=frozenset({subject.entry_path}),
            max_observation_tokens=FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens,
            candidate_path=subject.entry_path,
            subject=subject,
        ),
    )


def test_mlflow_local_artifact_download_summary_counterexamples_and_control():
    from cv_agent.tools.analysis.commands import analyze_command, UnsupportedSemantics

    caller = CodeDocument(
        repository_id="r",
        path="mlflow/pyfunc/backend.py::entry@1-4",
        text="""def entry(model_uri):
    local_path = _download_artifact_from_uri(model_uri)
    subprocess.Popen(f"mlserver {local_path}", shell=True)
""",
        defines=("entry",),
        calls=("_download_artifact_from_uri", "subprocess.Popen"),
    )

    valid_helper = CodeDocument(
        repository_id="r",
        path="mlflow/tracking/artifact_utils.py::_download_artifact_from_uri@1-6",
        text="""def _download_artifact_from_uri(artifact_uri, output_path=None):
    repo = get_artifact_repository(artifact_uri)
    return repo.download_artifacts(artifact_uri, output_path)
""",
        defines=("_download_artifact_from_uri",),
        calls=("get_artifact_repository", "repo.download_artifacts"),
    )

    # 1. Missing assumption: without os.path.exists and is_windows assumptions, cannot resolve download and cannot prove sink
    no_assump = analyze_command(
        caller,
        helpers=(valid_helper,),
        entry_condition_assumptions={},
        input_parameters=("model_uri",),
    )
    assert not any(s.get("status") == "VULNERABLE" for s in no_assump.sinks)
    assert any(c.get("call") == "get_artifact_repository" for c in no_assump.unresolved_calls)

    # 2. Remote helper / different path cannot use local summary
    remote_helper = CodeDocument(
        repository_id="r",
        path="mlflow/tracking/remote_utils.py::_download_artifact_from_uri@1-6",
        text=valid_helper.text,
        defines=("_download_artifact_from_uri",),
        calls=("get_artifact_repository", "repo.download_artifacts"),
    )
    remote = analyze_command(
        caller,
        helpers=(remote_helper,),
        entry_condition_assumptions={"os.path.exists(artifact_uri)": True, "is_windows()": False},
        input_parameters=("model_uri",),
    )
    assert not any(s.get("status") == "VULNERABLE" for s in remote.sinks)
    assert any(c.get("call") == "get_artifact_repository" for c in remote.unresolved_calls)

    # The generic repository lookup and download implementation are not bound in
    # this source set, so the local-path assumptions cannot prove their behavior.
    analysis = analyze_command(
        caller,
        helpers=(valid_helper,),
        entry_condition_assumptions={"os.path.exists(artifact_uri)": True, "is_windows()": False},
        input_parameters=("model_uri",),
    )
    assert not any(s["status"] == "UNSANITIZED" for s in analysis.sinks)
    assert any(c.get("call") == "get_artifact_repository" for c in analysis.unresolved_calls)

    # A directly visible return relation is still a complete positive control.
    passthrough_helper = valid_helper.model_copy(update={
        "text": "def _download_artifact_from_uri(artifact_uri):\n    return artifact_uri\n",
        "calls": (),
    })
    passthrough = analyze_command(
        caller,
        helpers=(passthrough_helper,),
        entry_condition_assumptions={"os.path.exists(artifact_uri)": True, "is_windows()": False},
        input_parameters=("model_uri",),
    )
    assert any(s["status"] == "UNSANITIZED" for s in passthrough.sinks)
