"""Behavioral regressions from the 2026-09-20 post-fix review."""
import importlib
import json
import sys
from pathlib import Path

import pytest

from cv_agent.agent_tools import ToolExecutionScope, repository_source_digest
from cv_agent.agent_types import (
    AgentExpertConclusion, ModelToolCall, ReActStep, ToolObservation, ValidationSubject,
)
from cv_agent.python_heldout_pair_acceptance import heldout_pair_acceptance_issues
from cv_agent.python_heldout_pair_config import (
    PythonHeldoutPairExperimentConfig, heldout_truth, planned_heldout_cells,
)
from cv_agent.react_engine import validate_conclusion
from cv_agent.retrieval import RepositoryIndex
from cv_agent.types import CodeDocument
from test_python_heldout_pair_config import config_dict
from test_validation_tools import _command_documents, _invoke, _registry


SAFE_HELPER = '''def get_cmd(model_uri):
    cmd = f"worker {shlex.quote(model_uri)}"
    return cmd, {}
'''


def inspect_command(helper_text=SAFE_HELPER, caller_text=None):
    caller, helper = _command_documents(helper_text)
    if caller_text is not None:
        caller = caller.model_copy(update={"text": caller_text})
    index = RepositoryIndex([caller, helper])
    scope = ToolExecutionScope(
        admitted_paths=frozenset({caller.path, helper.path}),
        candidate_path=caller.path, max_observation_tokens=20000,
    )
    result = _invoke(_registry(index), "inspect_command_construction",
                     {"source_path": caller.path}, scope)
    assert result.status == "ok"
    assert result.validation_status.value == "UNRESOLVED"
    return json.loads(result.content)


@pytest.mark.parametrize("body, expected", [
    ("os.chmod(path, 0o777)", "CONFIRMED"),
    ("os.chmod(path, 0o750)", "REFUTED"),
    ("try:\n        return path\n    finally:\n        pass\n    os.chmod(path, 0o777)", "UNRESOLVED"),
    ("False and os.chmod(path, 0o777)", "UNRESOLVED"),
    ("os.chmod(path, 0o777)\n    os = replacement", "UNRESOLVED"),
    ("assert False\n    os.chmod(path, 0o777)", "UNRESOLVED"),
    ("while True:\n        pass\n    os.chmod(path, 0o777)", "UNRESOLVED"),
    ("True and os.chmod(path, 0o777)", "CONFIRMED"),
    ("import os\n    os.chmod(path, 0o750)", "REFUTED"),
    ("if replacement:\n        os.chmod(path, 0o750)", "REFUTED"),
    ("if replacement:\n        os.chmod(path, 0o777)", "CONFIRMED"),
    ("os.chmod = replacement\n    os.chmod(path, 0o750)", "UNRESOLVED"),
    ("import os\n    if path:\n        if replacement:\n            os = replacement\n    os.chmod(path, 0o750)", "UNRESOLVED"),
    ("replacement()\n    os.chmod(path, 0o777)", "UNRESOLVED"),
    ("1 / 0\n    os.chmod(path, 0o777)", "UNRESOLVED"),
    ("os.chmod(path, 0o750)\n    def nested(arg=os.chmod(path, 0o777)):\n        pass", "UNRESOLVED"),
    ("import os\n    alias = os\n    alias.chmod = replacement\n    os.chmod(path, 0o750)", "UNRESOLVED"),
])
def test_review_permission_execution_and_binding(body, expected):
    source = f"def check(path, replacement):\n    {body}\n"
    document = CodeDocument(repository_id="review", path="permission.py::check@1-20", text=source)
    index = RepositoryIndex([document])
    subject = ValidationSubject(candidate_id="review", repository_id="review",
                                entry_path=document.path, source_digest=repository_source_digest(index))
    result = _invoke(_registry(index), "validate_permission_mode", {"path": document.path},
                     ToolExecutionScope(admitted_paths=frozenset({document.path}),
                                        candidate_path=document.path, subject=subject,
                                        max_observation_tokens=20000))
    assert result.validation_status.value == expected
    assert (result.subject is not None) == (expected != "UNRESOLVED")


@pytest.mark.parametrize("mode, expected", [("0o777", "CONFIRMED"), ("0o750", "REFUTED")])
def test_review_permission_validator_handles_known_cache_decorator(mode, expected):
    source = f"@cache_return_value_per_process\ndef check(path):\n    os.chmod(path, {mode})\n"
    document = CodeDocument(repository_id="review", path="permission.py::check@1-3", text=source)
    index = RepositoryIndex([document])
    subject = ValidationSubject(candidate_id="review", repository_id="review",
                                entry_path=document.path, source_digest=repository_source_digest(index))
    result = _invoke(_registry(index), "validate_permission_mode", {"path": document.path},
                     ToolExecutionScope(admitted_paths=frozenset({document.path}),
                                        candidate_path=document.path, subject=subject,
                                        max_observation_tokens=20000))
    assert result.validation_status.value == expected
    assert result.subject is not None


def test_review_permission_validator_keeps_unknown_decorator_unresolved():
    source = "@maybe_skip\ndef check(path):\n    os.chmod(path, 0o777)\n"
    document = CodeDocument(repository_id="review", path="permission.py::check@1-3", text=source)
    result = _invoke(_registry(RepositoryIndex([document])), "validate_permission_mode",
                     {"path": document.path},
                     ToolExecutionScope(admitted_paths=frozenset({document.path}),
                                        candidate_path=document.path,
                                        max_observation_tokens=20000))
    assert result.validation_status.value == "UNRESOLVED"


@pytest.mark.parametrize("body, expected", [
    ('cmd = f"worker {shlex.quote(model_uri)}"\n    return cmd, {}', "SANITIZED"),
    ('cmd = f"worker {model_uri}"\n    return cmd, {}', "UNSANITIZED"),
    ('cmd = f"worker {shlex.quote(model_uri)}"\n    for value in [suffix]:\n        cmd += value\n    return cmd, {}', "UNSANITIZED"),
    ('cmd = f"worker {shlex.quote(model_uri)}"\n    return cmd, {}\n    cmd = f"worker {model_uri}"', "SANITIZED"),
    ('cmd = f"worker {model_uri}"\n    cmd = f"worker {shlex.quote(model_uri)}"\n    return cmd, {}', "SANITIZED"),
    ('cmd = f"worker {shlex.quote(model_uri)}"\n    for value in suffix:\n        cmd += value\n    return cmd, {}', "AMBIGUOUS"),
    ('cmd = f"worker {shlex.quote(model_uri)}"\n    try:\n        cmd += suffix\n    finally:\n        pass\n    return cmd, {}', "AMBIGUOUS"),
    ('cmd = f"worker {shlex.quote(model_uri)}"\n    if False:\n        cmd += suffix\n    return cmd, {}', "SANITIZED"),
    ('cmd = f"worker {shlex.quote(model_uri)}"\n    shlex = replacement\n    return cmd, {}', "AMBIGUOUS"),
    ('shlex.quote = replacement\n    return f"worker {shlex.quote(model_uri)}", {}', "AMBIGUOUS"),
    ('def nested(arg=replacement(shlex)):\n        pass\n    return f"worker {shlex.quote(model_uri)}", {}', "AMBIGUOUS"),
])
def test_review_command_reachable_return_values(body, expected):
    payload = inspect_command(f"def get_cmd(model_uri, suffix, replacement):\n    {body}\n")
    assert payload["command_construction_status"] == expected


@pytest.mark.parametrize("expression, expected", [
    ('f\'worker {shlex.quote(model_uri)}\'', "SANITIZED"),
    ('f\'worker "{shlex.quote(model_uri)}"\'', "AMBIGUOUS"),
    ('\'worker "\' + shlex.quote(model_uri) + \'"\'', "AMBIGUOUS"),
    ('f\'worker prefix{shlex.quote(model_uri)}\'', "AMBIGUOUS"),
    ('f\'worker {shlex.quote(model_uri)}suffix\'', "AMBIGUOUS"),
    ('f\'worker {shlex.quote(model_uri)!r}\'', "AMBIGUOUS"),
    ('f\'worker {shlex.quote(model_uri):>30}\'', "AMBIGUOUS"),
    ('f\'bash -c {shlex.quote(model_uri)}\'', "AMBIGUOUS"),
    ('f\' {shlex.quote(model_uri)}\'', "AMBIGUOUS"),
    ('f\'exec {shlex.quote(model_uri)}\'', "AMBIGUOUS"),
])
def test_review_command_shell_quote_context(expression, expected):
    payload = inspect_command(f"def get_cmd(model_uri):\n    return {expression}, {{}}\n")
    assert payload["command_construction_status"] == expected


@pytest.mark.parametrize("body, expected", [
    ('command, env = mlserver.get_cmd(model_uri)\n    return subprocess.Popen(["bash", "-c", command])', "SANITIZED"),
    ('command, env = mlserver.get_cmd(model_uri)\n    command += suffix\n    return subprocess.Popen(["bash", "-c", command])', "UNSANITIZED"),
    ('command, env = mlserver.get_cmd(model_uri)\n    alias = command\n    alias += suffix\n    return subprocess.Popen(["bash", "-c", alias])', "UNSANITIZED"),
    ('command, env = mlserver.get_cmd(model_uri)\n    return subprocess.Popen(["bash", "-c", suffix])', "UNSANITIZED"),
    ('command, env = mlserver.get_cmd(model_uri)\n    return subprocess.Popen(["worker", suffix])', "NOT_ESTABLISHED"),
    ('command, env = mlserver.get_cmd(model_uri)\n    return subprocess.Popen(command, shell=True)', "SANITIZED"),
    ('command, env = mlserver.get_cmd(model_uri)\n    return subprocess.Popen(command, shell=enabled)', "AMBIGUOUS"),
])
def test_review_command_binds_to_actual_sink_argument(body, expected):
    caller = f"def serve(model_uri, suffix, enabled):\n    {body}\n"
    assert inspect_command(caller_text=caller)["command_construction_status"] == expected


@pytest.mark.parametrize("role", ["counter_observation_ids", "unresolved_observation_ids"])
def test_review_disclosed_static_counter_evidence_does_not_veto_supported_prediction(role):
    observations = [
        ToolObservation(tool="read_span", status="ok", content="command += suffix", citation_id="source"),
        ToolObservation(tool="inspect_command_construction", status="ok", citation_id="counter",
                        content=json.dumps({"command_construction_status": "SANITIZED"})),
    ]
    trace = [ReActStep(step=i, model_id="offline", observation=obs,
                      tool_call=ModelToolCall(call_id=str(i), name=obs.tool, arguments={}))
             for i, obs in enumerate(observations, 1)]
    output = AgentExpertConclusion(
        expert="scan", label="VULNERABLE", confidence=0.8, validation_status="UNRESOLVED",
        evidence_ids=("source",), supporting_observation_ids=("source",),
        rationale="The quoted helper output is subsequently extended with raw suffix.",
        **{role: ("counter",)},
    )
    validate_conclusion(output, trace, frozenset())

    # Merely listing that observation as counter-evidence cannot provide
    # affirmative support for a SAFE prediction either.
    with pytest.raises(ValueError, match="affirmative counter-evidence"):
        validate_conclusion(output.model_copy(update={"label": "SAFE"}), trace, frozenset())


def test_review_saved_results_preserve_unexpected_rows_without_counting_them(tmp_path):
    sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
    runner = importlib.import_module("run_python_heldout_pair_matrix")
    config = PythonHeldoutPairExperimentConfig.model_validate(config_dict())
    rows = [dict(case_id=case.case_id, system=system.value, pair_id=pair.pair_id,
                 revision_role=case.revision_role, status="completed",
                 predicted_label=heldout_truth(case.revision_role), model_calls=1,
                 tool_calls=0, latency_sec=0.1, verdict=None)
            for pair, case, system in planned_heldout_cells(config)]
    extra = {**rows[0], "case_id": "unexpected", "status": "failed", "predicted_label": None}
    original = rows + [extra]
    saved = runner.rows_with_truth(original, config)
    assert len(saved) == len(original)
    unexpected = [row for row in saved if row["case_id"] == "unexpected"]
    assert len(unexpected) == 1
    assert unexpected[0]["planned_cell"] is False
    assert all(unexpected[0][key] == value for key, value in extra.items())
    assert heldout_pair_acceptance_issues(saved, {"requests": len(original)}, config) == \
        heldout_pair_acceptance_issues(original, {"requests": len(original)}, config)
    summary = runner.summarize_pair_run(tmp_path, config, original, {"requests": len(original)})
    assert summary["systems"]["E1"]["total"] == 2
    assert summary["unexpected_rows"] == unexpected
    assert summary["usage"]["requests"] == len(original)


@pytest.mark.parametrize("argument, expected", [
    ('model_uri', "UNSANITIZED"),
    ('"literal"', "SANITIZED"),
    ('shlex.quote(model_uri)', "SANITIZED"),
])
def test_review_command_helper_uses_actual_argument_binding(argument, expected):
    helper = 'def get_cmd(model_uri):\n    return f"worker {model_uri}", {}\n'
    caller = (
        'def serve(model_uri):\n'
        f'    command, env = mlserver.get_cmd({argument})\n'
        '    return subprocess.Popen(["bash", "-c", command])\n'
    )
    assert inspect_command(helper, caller)["command_construction_status"] == expected


def test_review_command_ignores_unknown_non_command_assignments():
    helper = (
        'def get_cmd(model_uri):\n'
        '    cmd = f"worker {shlex.quote(model_uri)}"\n'
        '    cmd_env = os.environ.copy()\n'
        '    return cmd, cmd_env\n'
    )
    caller = (
        'def serve(model_uri):\n'
        '    local_path = download(model_uri)\n'
        '    command, env = mlserver.get_cmd(model_uri)\n'
        '    return subprocess.Popen(["bash", "-c", command])\n'
    )
    assert inspect_command(helper, caller)["command_construction_status"] == "SANITIZED"


def test_review_command_unknown_assignment_flowing_to_shell_stays_ambiguous():
    helper = (
        'def get_cmd(model_uri):\n'
        '    cmd = build_command(model_uri)\n'
        '    return cmd, {}\n'
    )
    assert inspect_command(helper)["command_construction_status"] == "AMBIGUOUS"


@pytest.mark.parametrize("admit_other", [False, True])
def test_review_command_dynamic_get_cmd_requires_all_possible_helpers(admit_other):
    caller = CodeDocument(
        repository_id="repo",
        path="backend.py::serve@1-8",
        text=(
            "def serve(model_uri, enabled):\n"
            "    local_path = download(model_uri)\n"
            "    server_implementation = mlserver if enabled else scoring_server\n"
            "    command, env = server_implementation.get_cmd(local_path)\n"
            "    command = \"exec \" + command\n"
            "    return subprocess.Popen([\"bash\", \"-c\", command])\n"
        ),
        defines=("serve",),
        calls=("mlflow.pyfunc.mlserver.get_cmd", "mlflow.pyfunc.scoring_server.get_cmd", "subprocess.Popen"),
        import_aliases={
            "mlserver": "mlflow.pyfunc.mlserver",
            "scoring_server": "mlflow.pyfunc.scoring_server",
        },
    )
    helper = CodeDocument(
        repository_id="repo",
        path="mlserver.py::get_cmd@1-4",
        text=SAFE_HELPER,
        defines=("mlflow.pyfunc.mlserver.get_cmd", "get_cmd"),
    )
    other = helper.model_copy(update={"path": "scoring_server.py::get_cmd@1-4", "defines": ("mlflow.pyfunc.scoring_server.get_cmd",)})
    documents = [caller, helper, *([other] if admit_other else [])]
    index = RepositoryIndex(documents)
    scope = ToolExecutionScope(
        admitted_paths=frozenset(document.path for document in documents),
        candidate_path=caller.path,
        max_observation_tokens=20000,
    )
    result = _invoke(_registry(index), "inspect_command_construction",
                     {"source_path": caller.path}, scope)
    payload = json.loads(result.content)
    assert payload["command_construction_status"] == ("SANITIZED" if admit_other else "AMBIGUOUS")


def test_command_diagnostic_names_unknown_transformation_before_sink():
    payload = inspect_command(
        'def get_cmd(model_uri):\n    return f"worker {model_uri}", {}\n',
        'def serve(model_uri):\n'
        '    local_path = download(model_uri)\n'
        '    command, env = mlserver.get_cmd(local_path)\n'
        '    return subprocess.Popen(["bash", "-c", command])\n',
    )
    assert payload["command_construction_status"] == "AMBIGUOUS"
    assert {"call": "download", "line": 2} in payload["unresolved_calls"]


def test_review_explicit_counter_role_cannot_supply_typed_validation():
    subject = ValidationSubject(candidate_id="review", repository_id="review",
                                entry_path="entry", source_digest="snapshot")
    observation = ToolObservation(tool="validator", status="ok", content="refuted",
                                  citation_id="counter", subject=subject, validation_status="REFUTED")
    step = ReActStep(step=1, model_id="offline", observation=observation,
                    tool_call=ModelToolCall(call_id="1", name="validator", arguments={}))
    output = AgentExpertConclusion(expert="scan", label="SAFE", confidence=0.9,
                                   validation_status="REFUTED", evidence_ids=("counter",),
                                   counter_observation_ids=("counter",), rationale="Counter only.")
    with pytest.raises(ValueError, match="matching cited validator"):
        validate_conclusion(output, [step], frozenset(), subject=subject)


@pytest.mark.parametrize("tool, payload", [
    ("trace_dataflow", {"flow_status": "NOT_ESTABLISHED"}),
    ("run_static_check", {"permission_mode_check": {"status": "UNRESOLVED"}}),
    ("run_static_check", {"findings": [{"category": "command-execution"}], "callee": "get_cmd"}),
])
def test_review_counter_citations_do_not_create_support_requirements(tool, payload):
    observation = ToolObservation(tool=tool, status="ok", content=json.dumps(payload), citation_id="counter")
    step = ReActStep(step=1, model_id="offline", observation=observation,
                    tool_call=ModelToolCall(call_id="1", name=tool, arguments={}))
    output = AgentExpertConclusion(expert="scan", label="VULNERABLE", confidence=0.8,
                                   validation_status="UNRESOLVED", evidence_ids=("source",),
                                   counter_observation_ids=("counter",), rationale="Supported by source; static counter-signal is inconclusive.")
    validate_conclusion(output, [step], frozenset({"source"}))


def test_review_async_helper_call_is_not_a_synchronous_command_return():
    assert inspect_command(SAFE_HELPER.replace("def get_cmd", "async def get_cmd"))["command_construction_status"] == "AMBIGUOUS"


def test_review_duplicate_rows_do_not_inflate_summary_denominator(tmp_path):
    sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
    runner = importlib.import_module("run_python_heldout_pair_matrix")
    config = PythonHeldoutPairExperimentConfig.model_validate(config_dict())
    row = dict(case_id="hp001_a", system="E1", status="completed", predicted_label="VULNERABLE",
               model_calls=1, tool_calls=0, latency_sec=0.1, verdict=None)
    summary = runner.summarize_pair_run(tmp_path, config, [row, row.copy()], {"requests": 2})
    assert summary["systems"]["E1"]["total"] == 2
    assert summary["systems"]["E1"]["failed"] == 1
    assert summary["duplicate_cells"] == [{"case_id": "hp001_a", "system": "E1", "rows": 2}]
