"""A Popen call-site property stays separate from hp003's whole-function score."""

from pathlib import Path

import pytest

from cv_agent.evaluation.datasets.advisory_config import PythonHeldoutPairCell
from cv_agent.evaluation.datasets.advisory_tasks import build_tasks
from cv_agent.evaluation.datasets.composition import load_advisory_config
from cv_agent.evaluation.diagnostics.hp003_callsite import analyze_callsite
from cv_agent.evaluation.runners.run_jev_v3_comparison import JevV3ComparisonConfig
from cv_agent.code_adapters.python import parse_python_source
from cv_agent.harness import AgentSystemVersion
from cv_agent.retrieval import RepositoryIndex


@pytest.fixture(scope="module")
def hp003_cases():
    root = Path(__file__).resolve().parents[1]
    config = JevV3ComparisonConfig.model_validate_json(
        (root / "configs/experiments/jev_v3_hp003_comparison.json").read_text()
    )
    advisory = load_advisory_config(root, config.advisory_profile)
    payload = advisory.model_dump(mode="json", by_alias=True)
    payload["selected_cells"] = [
        PythonHeldoutPairCell(
            case_id=case_id, system=AgentSystemVersion.E4_GRAPH_MULTI,
        ).model_dump(mode="json")
        for case_id in config.case_ids
    ]
    payload["expected_abstentions"] = []
    advisory = type(advisory).model_validate(payload)
    tasks, _, _ = build_tasks(root, advisory, fixture_policy="disabled")
    return {candidate.case_id: (index, candidate) for _, _, index, candidate, _, _ in tasks}


def _helper(index):
    return next(
        document for path, document in index.documents.items()
        if path.startswith("mlflow/pyfunc/mlserver.py::get_cmd@")
    )


def test_real_hp003_callsite_pair_is_source_bound_and_separate(hp003_cases):
    vulnerable = analyze_callsite(*hp003_cases["hp003_a"])
    fixed = analyze_callsite(*hp003_cases["hp003_b"])

    assert vulnerable.status == "UNSANITIZED"
    assert vulnerable.callsite_label == "VULNERABLE"
    assert fixed.status == "SANITIZED"
    assert fixed.callsite_label == "SAFE"
    for result in (vulnerable, fixed):
        assert result.subject.property_id == "popen-shell-argument-injection"
        assert result.subject.entry_line == 311
        assert result.subject.entry_path.endswith("::PyFuncBackend.serve@229-327")
        assert result.counts_toward_original_metrics is False
        assert result.analysis_issues == ()
        assert result.document_sha256[result.subject.entry_path]
    assert vulnerable.subject.source_digest != fixed.subject.source_digest


def test_unreviewed_get_cmd_change_requires_a_new_source_audit(hp003_cases):
    index, candidate = hp003_cases["hp003_b"]
    original = _helper(index)
    assert "shlex.quote(model_uri)" in original.text
    mutated = original.model_copy(update={
        "text": original.text.replace("shlex.quote(model_uri)", "model_uri")
    })
    smaller_index = RepositoryIndex([index.document(candidate.path), mutated])
    result = analyze_callsite(smaller_index, candidate)
    assert result.status == "UNRESOLVED"
    assert result.callsite_label is None
    assert any("full repository module" in issue or "full module" in issue
               for issue in result.analysis_issues)


def test_unexpected_command_rewrite_is_not_declared_safe(hp003_cases):
    index, candidate = hp003_cases["hp003_b"]
    original = index.document(candidate.path)
    marker = '                command = ["bash", "-c", command]'
    assert marker in original.text
    mutated = original.model_copy(update={
        "text": original.text.replace(
            marker,
            '                command = command + local_path\n' + marker,
        )
    })
    smaller_index = RepositoryIndex([mutated, _helper(index)])
    result = analyze_callsite(smaller_index, candidate)
    assert result.status == "UNRESOLVED"
    assert result.callsite_label is None
    assert any("command assignment" in issue for issue in result.analysis_issues)


def test_helper_side_effect_change_requires_a_new_source_audit(hp003_cases):
    index, candidate = hp003_cases["hp003_b"]
    original = _helper(index)
    marker = '    cmd = f"mlserver start {shlex.quote(model_uri)}"'
    assert marker in original.text
    mutated = original.model_copy(update={
        "text": original.text.replace(marker, '    os.system(model_uri)\n' + marker)
    })
    smaller_index = RepositoryIndex([index.document(candidate.path), mutated])
    result = analyze_callsite(smaller_index, candidate)
    assert result.status == "UNRESOLVED"
    assert result.callsite_label is None
    assert any("full repository module" in issue or "full module" in issue
               for issue in result.analysis_issues)
    assert result.counts_toward_original_metrics is False


@pytest.mark.parametrize("old,new", [
    (
        '                command = ["bash", "-c", command]\n\n',
        '                command = ["bash", "-c", command]\n'
        '                command.__setitem__(2, "exec mlserver start " + local_path)\n',
    ),
    (
        '        local_path = _download_artifact_from_uri(model_uri)\n\n',
        '        local_path = _download_artifact_from_uri(model_uri)\n'
        '        mlserver.get_cmd = lambda path, *args: ("mlserver start " + path, {})\n',
    ),
])
def test_caller_side_mutation_cannot_keep_a_safe_callsite_claim(hp003_cases, old, new):
    index, candidate = hp003_cases["hp003_b"]
    original = index.document(candidate.path)
    assert old in original.text
    mutated = original.model_copy(update={"text": original.text.replace(old, new)})
    smaller_index = RepositoryIndex([mutated, _helper(index)])
    result = analyze_callsite(smaller_index, candidate)
    assert result.status == "UNRESOLVED"
    assert result.callsite_label is None


def test_helper_from_another_repository_cannot_supply_safe_proof(hp003_cases):
    vulnerable_index, candidate = hp003_cases["hp003_a"]
    fixed_index, _ = hp003_cases["hp003_b"]
    mixed_index = RepositoryIndex([
        vulnerable_index.document(candidate.path),
        _helper(fixed_index),
    ])
    result = analyze_callsite(mixed_index, candidate)
    assert result.status == "UNRESOLVED"
    assert result.callsite_label is None
    assert any("repository" in issue for issue in result.analysis_issues)


def test_module_level_quote_rebinding_cannot_keep_safe_callsite_claim(hp003_cases):
    index, candidate = hp003_cases["hp003_b"]
    module = next(
        document for path, document in index.documents.items()
        if path.startswith("mlflow/pyfunc/mlserver.py::<module>@")
    )
    mutated_text = module.text + "\nshlex.quote = lambda value: value\n"
    reparsed = parse_python_source(
        candidate.repository_id, "mlflow/pyfunc/mlserver.py", mutated_text,
    )
    mutated_module = module.model_copy(update={
        "text": mutated_text,
        "path": module.path.replace("@1-46", "@1-48"),
    })
    backend_module = next(
        document for path, document in index.documents.items()
        if path.startswith("mlflow/pyfunc/backend.py::<module>@")
    )
    smaller_index = RepositoryIndex([
        index.document(candidate.path), backend_module, mutated_module,
        *(span.document for span in reparsed if span.document.path.startswith(
            "mlflow/pyfunc/mlserver.py::get_cmd@"
        )),
    ])
    result = analyze_callsite(smaller_index, candidate)
    assert result.status == "UNRESOLVED"
    assert result.callsite_label is None
    assert any("full module source digest" in issue for issue in result.analysis_issues), result.analysis_issues


def test_backend_module_rebinding_cannot_keep_safe_callsite_claim(hp003_cases):
    index, candidate = hp003_cases["hp003_b"]
    backend_module = next(
        document for path, document in index.documents.items()
        if path.startswith("mlflow/pyfunc/backend.py::<module>@")
    )
    mlserver_module = next(
        document for path, document in index.documents.items()
        if path.startswith("mlflow/pyfunc/mlserver.py::<module>@")
    )
    changed = backend_module.model_copy(update={
        "text": backend_module.text + "\nmlserver.get_cmd = lambda path, *args: ('mlserver start ' + path, {})\n",
    })
    smaller_index = RepositoryIndex([
        index.document(candidate.path), _helper(index), changed, mlserver_module,
    ])
    result = analyze_callsite(smaller_index, candidate)
    assert result.status == "UNRESOLVED"
    assert result.callsite_label is None
    assert any("full module source digest" in issue for issue in result.analysis_issues)
