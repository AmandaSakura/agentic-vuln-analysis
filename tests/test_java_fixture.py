"""Offline Java command-boundary witnesses; model labels are never fixture inputs."""

from __future__ import annotations

import json
import hashlib
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from cv_agent.tools.registry import ToolExecutionScope, ToolRegistry
from cv_agent.tools.identity import candidate_subject
from cv_agent.domain.chat import ModelToolCall
from cv_agent.domain.evidence import ValidationStatus
from cv_agent.evaluation.datasets.owasp_live import load_owasp_agentic_inputs, select_owasp_entry
from cv_agent.evaluation.protocols.development import require_verification_capability
from cv_agent.harness import FULL_SYSTEM_HARNESS
from cv_agent.evaluation.datasets.java_fixture import JavaCommandValidator, java_command_fixture_cases
from cv_agent.tools.validation import full_agent_tools


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = PROJECT_ROOT / "tests/fixtures/java_command"


@pytest.fixture(scope="module")
def java_project_root(tmp_path_factory):
    root = tmp_path_factory.mktemp("java-command-project")
    shutil.copytree(FIXTURE_ROOT / "BenchmarkJava", root / "data/raw/BenchmarkJava")
    harness = root / "validation/java-command-harness"
    harness.mkdir(parents=True)
    shutil.copy2(PROJECT_ROOT / "validation/java-command-harness/exec_recorder.c", harness)
    return root


def _owasp_pair(project_root):
    inputs = load_owasp_agentic_inputs(
        project_root / "data/raw",
        case_ids=("BenchmarkTest00827", "BenchmarkTest02244"),
        # The positive controls assert only this concrete token experiment,
        # never the broader OWASP command-injection labels.
        property_ids={case: "java-fixture-token-reachability"
                      for case in ("BenchmarkTest00827", "BenchmarkTest02244")},
    )
    return inputs, select_owasp_entry(inputs, "doPost")


def _invoke_fixture(registry, case_id, candidate, subject):
    return registry.invoke(
        ModelToolCall(
            call_id=f"{case_id}-fixture",
            name="run_fixture_test",
            arguments={"case_id": case_id},
        ),
        allowed=("run_fixture_test",),
        scope=ToolExecutionScope(
            admitted_paths=frozenset({candidate.path}),
            max_observation_tokens=FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens,
            candidate_path=candidate.path,
            subject=subject,
        ),
    )


def test_java_validator_has_a_concrete_build_entrypoint():
    assert callable(JavaCommandValidator.build)


def test_java_fixture_matches_the_pinned_source_manifest():
    manifest = json.loads((FIXTURE_ROOT / "manifest.json").read_text())
    files = {path.relative_to(FIXTURE_ROOT / "BenchmarkJava").as_posix():
             hashlib.sha256(path.read_bytes()).hexdigest()
             for path in (FIXTURE_ROOT / "BenchmarkJava").rglob('*') if path.is_file()}
    assert files == manifest["files"]


def test_java_command_fixture_confirms_and_refutes_real_owasp_pair(java_project_root):
    inputs, candidates = _owasp_pair(java_project_root)
    fixtures = java_command_fixture_cases(java_project_root, inputs.index, candidates)
    registry = ToolRegistry(
        full_agent_tools(inputs.index, fixture_cases=fixtures),
        max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes,
    )
    require_verification_capability(registry._tools.values())

    observations = {}
    for candidate in candidates:
        observations[candidate.case_id] = _invoke_fixture(
            registry,
            candidate.case_id,
            candidate,
            candidate_subject(inputs.index, candidate),
        )

    assert observations["BenchmarkTest02244"].validation_status == ValidationStatus.CONFIRMED
    assert observations["BenchmarkTest00827"].validation_status == ValidationStatus.REFUTED
    for case_id, observation in observations.items():
        assert observation.status == "ok", case_id
        payload = json.loads(observation.content)
        assert payload["details"]["process_boundary_count"] >= 1
        assert payload["details"]["stubbed_helpers"] == ["org/owasp/benchmark/helpers/Utils.java"]
        assert observation.subject == candidate_subject(
            inputs.index,
            next(candidate for candidate in candidates if candidate.case_id == case_id),
        )


def test_java_fixture_subject_mismatch_is_blocked_before_execution(java_project_root):
    inputs, candidates = _owasp_pair(java_project_root)
    safe, vulnerable = candidates
    fixtures = java_command_fixture_cases(java_project_root, inputs.index, candidates)
    registry = ToolRegistry(
        full_agent_tools(inputs.index, fixture_cases=fixtures),
        max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes,
    )

    observation = _invoke_fixture(
        registry,
        safe.case_id,
        vulnerable,
        candidate_subject(inputs.index, vulnerable),
    )

    assert observation.status == "blocked"
    assert observation.validation_status is None


def test_java_fixture_source_snapshot_mismatch_is_unresolved(java_project_root):
    inputs, candidates = _owasp_pair(java_project_root)
    validator = JavaCommandValidator.build(java_project_root, inputs.index, candidates[0])
    first = replace(validator.files[0], sha256="0" * 64)
    stale = replace(validator, files=(first, *validator.files[1:]))

    outcome = stale.run()

    assert outcome.status == ValidationStatus.UNRESOLVED
    assert validator.files[0].relative_path in outcome.details["mismatches"]


@pytest.mark.parametrize('case_id', ['BenchmarkTest00827', 'BenchmarkTest02244'])
def test_process_token_fact_cannot_confirm_or_refute_command_injection(java_project_root, case_id):
    inputs, candidates = _owasp_pair(java_project_root)
    candidate = next(item for item in candidates if item.case_id == case_id).model_copy(
        update={'property_id': 'command-execution'})
    validator = JavaCommandValidator.build(java_project_root, inputs.index, candidate)
    registry = ToolRegistry(full_agent_tools(inputs.index, fixture_cases=(validator.fixture_case(),)),
                            max_output_bytes=100000)
    subject = candidate_subject(inputs.index, candidate)
    observation = _invoke_fixture(registry, case_id, candidate, subject).model_copy(update={'citation_id': 'probe'})
    assert observation.validation_status == ValidationStatus.UNRESOLVED
    details = json.loads(observation.content)['details']
    assert details['property_id'] == 'java-fixture-token-reachability'
    assert details['local_validation_status'] in {'CONFIRMED', 'REFUTED'}
    assert details['process_boundary_count'] >= 1
    from cv_agent.agents.evidence_policy import validate_conclusion
    from cv_agent.domain.evidence import ReActStep
    from cv_agent.domain.review import AgentExpertConclusion
    trace = [ReActStep(step=1, model_id='offline', observation=observation,
        tool_call=ModelToolCall(call_id='probe', name='run_fixture_test', arguments={'case_id': case_id}))]
    for label in ('VULNERABLE', 'SAFE'):
        vote = AgentExpertConclusion(expert='scan', label=label, validation_status='UNRESOLVED', confidence=.9,
            evidence_ids=('probe',), supporting_observation_ids=('probe',), rationale='Local token observation.')
        with pytest.raises(ValueError):
            validate_conclusion(vote, trace, frozenset(), subject=subject)
    validate_conclusion(vote.model_copy(update={'label': 'ABSTAIN'}), trace, frozenset(), subject=subject)


@pytest.mark.parametrize('mismatch', ['method', 'line', 'repository', 'missing_document', 'entry_text', 'helper_text', 'entry_metadata'])
def test_java_fixture_rejects_execution_scope_and_index_mismatch(java_project_root, mismatch):
    from cv_agent.retrieval import RepositoryIndex
    inputs, candidates = _owasp_pair(java_project_root)
    candidate = candidates[0]
    index = inputs.index
    if mismatch == 'method':
        candidate = inputs.candidates[0]  # HarnessMain invokes doPost, not doGet.
    elif mismatch == 'line':
        candidate = candidate.model_copy(update={'line': candidate.line + 1})
    elif mismatch == 'repository':
        candidate = candidate.model_copy(update={'repository_id': 'different-repository'})
    else:
        documents = list(index.documents.values())
        target = (next(doc for doc in documents if 'helpers/Thing1.java::' in doc.path)
                  if mismatch == 'helper_text' else index.document(candidate.path))
        if mismatch == 'missing_document':
            documents = [doc for doc in documents if doc.path != target.path]
        else:
            update = {'calls': ()} if mismatch == 'entry_metadata' else {'text': target.text + '\n// stale index'}
            documents = [doc.model_copy(update=update) if doc.path == target.path else doc for doc in documents]
        index = RepositoryIndex(documents)
    with pytest.raises(ValueError, match='entry|scope|source|repository|index'):
        JavaCommandValidator.build(java_project_root, index, candidate)


@pytest.mark.parametrize('change', ['entry_field', 'entry_import', 'helper_field', 'resource'])
def test_java_fixture_rejects_changes_outside_indexed_methods(java_project_root, tmp_path, change):
    """C1/T13: identical method slices are not an identical execution snapshot."""
    root = tmp_path / 'project'
    shutil.copytree(java_project_root, root)
    inputs, candidates = _owasp_pair(root)
    candidate = candidates[0]
    if change == 'resource':
        path = root / 'data/raw/BenchmarkJava/src/main/resources/thing.properties'
        path.write_bytes(b'thing=Thing1')
    else:
        relative = (candidate.path.split('::')[0] if change != 'helper_field'
                    else 'org/owasp/benchmark/helpers/Thing1.java')
        path = root / 'data/raw/BenchmarkJava/src/main/java' / relative
        original = path.read_bytes()
        if change == 'entry_field':
            modified = original.replace(b'serialVersionUID = 1L', b'serialVersionUID = 2L')
        elif change == 'entry_import':
            modified = original.replace(b'import java.io.IOException;', b'import java.io.FileNotFoundException;')
        else:
            modified = original.replace(b'implements ThingInterface {', b'implements ThingInterface { static int snapshotMarker = 1;')
        assert modified != original
        path.write_bytes(modified)
    with pytest.raises(ValueError, match='source|snapshot|resource|index'):
        JavaCommandValidator.build(root, inputs.index, candidate)


def test_java_subject_digest_includes_file_content_outside_method():
    from cv_agent.code_adapters.java import parse_java_source
    from cv_agent.retrieval import RepositoryIndex
    from cv_agent.tools.identity import repository_source_digest
    source = 'class Example { static int mode = 1; void run() { } }'
    first = parse_java_source('r', 'Example.java', source).documents
    second = parse_java_source('r', 'Example.java', source.replace('mode = 1', 'mode = 2')).documents
    assert [doc.text for doc in first] == [doc.text for doc in second]
    assert repository_source_digest(RepositoryIndex(first)) != repository_source_digest(RepositoryIndex(second))


def test_java_fixture_accepts_reindexed_source_and_binds_new_full_file_identity(java_project_root, tmp_path):
    root = tmp_path / 'project'
    shutil.copytree(java_project_root, root)
    before, old_candidates = _owasp_pair(root)
    path = root / 'data/raw/BenchmarkJava/src/main/java' / old_candidates[0].path.split('::')[0]
    path.write_bytes(path.read_bytes().replace(b'serialVersionUID = 1L', b'serialVersionUID = 2L'))
    after, new_candidates = _owasp_pair(root)
    validator = JavaCommandValidator.build(root, after.index, new_candidates[0])
    assert validator.subject != candidate_subject(before.index, old_candidates[0])
    assert validator.subject == candidate_subject(after.index, new_candidates[0])
    # An updated, matching snapshot still runs the actual bounded experiment.
    assert validator.run().status == ValidationStatus.REFUTED
