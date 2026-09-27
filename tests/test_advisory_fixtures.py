from __future__ import annotations

import json
from pathlib import Path

import pytest

from cv_agent.domain.chat import ModelToolCall
from cv_agent.domain.evidence import ValidationStatus
from cv_agent.evaluation.datasets.advisory_config import PythonHeldoutPair, PythonHeldoutPairCase
from cv_agent.evaluation.datasets.advisory_fixtures import HP003_PAIR_ID, advisory_fixture_cases
from cv_agent.evaluation.datasets.advisory_source import build_pair_input
from cv_agent.harness import FULL_SYSTEM_HARNESS
from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.registry import ToolExecutionScope, ToolRegistry
from cv_agent.tools.validation import full_agent_tools


BACKEND_SOURCE = '''
import subprocess

class _Env:
    LOCAL = "local"

em = _Env()

class PyFuncBackend:
    def __init__(self):
        self._env_manager = em.LOCAL
        self._nworkers = None

    def serve(self, model_uri, port, host, timeout, enable_mlserver, synchronous=True):
        local_path = _download_artifact_from_uri(model_uri)
        server_implementation = mlserver if enable_mlserver else scoring_server
        command, command_env = server_implementation.get_cmd(
            local_path, port, host, timeout, self._nworkers
        )
        if not is_windows():
            command = "exec " + command
        if self._env_manager != em.LOCAL:
            return self.prepare_env(local_path).execute(command, command_env)
        else:
            if not is_windows():
                command = ["bash", "-c", command]
            return subprocess.Popen(command, env=command_env)
'''


VULNERABLE_MLSERVER = '''
import logging
import os

_logger = logging.getLogger(__name__)
MLServerDefaultModelName = "mlflow-model"

def get_cmd(model_uri: str, port=None, host=None, timeout=None, nworkers=None):
    cmd = f"mlserver start {model_uri}"
    cmd_env = os.environ.copy()
    return cmd, cmd_env
'''


FIXED_MLSERVER = '''
import logging
import os
import shlex

_logger = logging.getLogger(__name__)
MLServerDefaultModelName = "mlflow-model"

def get_cmd(model_uri: str, port=None, host=None, timeout=None, nworkers=None):
    cmd = f"mlserver start {shlex.quote(model_uri)}"
    cmd_env = os.environ.copy()
    return cmd, cmd_env
'''


def _write_case(root: Path, checkout: str, mlserver_source: str) -> None:
    base = root / checkout / "mlflow/pyfunc"
    base.mkdir(parents=True)
    (base / "backend.py").write_text(BACKEND_SOURCE)
    (base / "mlserver.py").write_text(mlserver_source)


def _case(case_id: str, role: str, checkout: str) -> PythonHeldoutPairCase:
    return PythonHeldoutPairCase.model_validate({
        "case_id": case_id,
        "revision_role": role,
        "commit": "0" * 40,
        "checkout": checkout,
        "file_path": "mlflow/pyfunc/backend.py",
        "line_hint": 22,
    })


def _pair() -> PythonHeldoutPair:
    return PythonHeldoutPair.model_validate({
        "pair_id": HP003_PAIR_ID,
        "entry_id": "entry-00389",
        "repository_url": "https://github.com/mlflow/mlflow",
        "advisory": "GHSA-RVHJ-8CHJ-8V3C",
        "source_link": "https://github.com/advisories/GHSA-rvhj-8chj-8v3c",
        "vuln_ids": ["CVE-2026-0596"],
        "source_root": ".",
        "vulnerability_title": "MLflow model serving command injection",
        "source_scope": "mlserver command construction",
        "analysis_scope": "Assess enable_mlserver=True command execution only.",
        "entry_point": {"code": "def serve(", "file": "mlflow/pyfunc/backend.py", "line": 13},
        "critical_operation": {"code": "subprocess.Popen(command)", "file": "mlflow/pyfunc/backend.py", "line": 26},
        "cases": [
            _case("hp003_a", "vulnerable", "vulnerable").model_dump(),
            _case("hp003_b", "fixed", "fixed").model_dump(),
        ],
        "input_parameters": ["model_uri"],
        "entry_boolean_arguments": {"enable_mlserver": True},
        "property_id": "command-execution",
    })


@pytest.mark.parametrize(
    ("case_index", "expected_status", "expected_flag"),
    [
        (0, ValidationStatus.CONFIRMED, "expanded_probe_observed"),
        (1, ValidationStatus.REFUTED, "literal_probe_observed"),
    ],
)
def test_hp003_mlserver_fixture_distinguishes_shell_consumption(tmp_path, case_index, expected_status, expected_flag):
    _write_case(tmp_path, "vulnerable", VULNERABLE_MLSERVER)
    _write_case(tmp_path, "fixed", FIXED_MLSERVER)
    pair = _pair()
    case = pair.cases[case_index]
    index, candidate, source_sha256 = build_pair_input(tmp_path, pair, case)
    cases = advisory_fixture_cases(tmp_path, pair, case, index, candidate, source_sha256)
    registry = ToolRegistry(
        full_agent_tools(index, fixture_cases=cases),
        max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes,
    )

    observation = registry.invoke(
        ModelToolCall(
            call_id="fixture",
            name="run_fixture_test",
            arguments={"case_id": case.case_id},
        ),
        allowed=("run_fixture_test",),
        scope=ToolExecutionScope(
            admitted_paths=frozenset({candidate.path}),
            max_observation_tokens=FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens,
            candidate_path=candidate.path,
            subject=candidate_subject(index, candidate),
        ),
    )

    assert observation.status == "ok"
    # Under the proof scope contract (C1/C3/C4), this bounded shell probe has coverage='local',
    # so candidate-level validation_status is demoted to UNRESOLVED while preserving the raw measurement.
    assert observation.validation_status == ValidationStatus.UNRESOLVED
    assert observation.subject == candidate_subject(index, candidate)
    assert f"fixture:{case.case_id}" in observation.evidence_ids
    assert f'"{expected_flag}":true' in observation.content
    content_payload = json.loads(observation.content)
    assert content_payload["raw_status"] == expected_status.value


def test_hp003_fixture_not_registered_for_other_pair(tmp_path):
    _write_case(tmp_path, "vulnerable", VULNERABLE_MLSERVER)
    _write_case(tmp_path, "fixed", FIXED_MLSERVER)
    pair = _pair().model_copy(update={"pair_id": "hp003_other"})
    case = pair.cases[0]
    index, candidate, source_sha256 = build_pair_input(tmp_path, pair, case)

    assert advisory_fixture_cases(tmp_path, pair, case, index, candidate, source_sha256) == ()


def _invoke_registered_fixture(root: Path, pair: PythonHeldoutPair, case: PythonHeldoutPairCase):
    index, candidate, source_sha256 = build_pair_input(root, pair, case)
    cases = advisory_fixture_cases(root, pair, case, index, candidate, source_sha256)
    registry = ToolRegistry(
        full_agent_tools(index, fixture_cases=cases),
        max_output_bytes=FULL_SYSTEM_HARNESS.validation.max_output_bytes,
    )
    return registry.invoke(
        ModelToolCall(call_id="fixture", name="run_fixture_test", arguments={"case_id": case.case_id}),
        allowed=("run_fixture_test",),
        scope=ToolExecutionScope(
            admitted_paths=frozenset({candidate.path}),
            max_observation_tokens=FULL_SYSTEM_HARNESS.react_loop.max_tool_observation_tokens,
            candidate_path=candidate.path,
            subject=candidate_subject(index, candidate),
        ),
    )


def _hp001_pair() -> PythonHeldoutPair:
    return PythonHeldoutPair.model_validate({
        "pair_id": "hp001_entry_00101_ghsa_4x5p_f36r_mxxr",
        "entry_id": "entry-00101",
        "repository_url": "https://github.com/mlflow/mlflow",
        "advisory": "GHSA-4X5P-F36R-MXXR",
        "source_link": "https://github.com/advisories/GHSA-4x5p-f36r-mxxr",
        "vuln_ids": ["CVE-2025-10279"],
        "source_root": ".",
        "vulnerability_title": "MLflow tmpdir race",
        "source_scope": "temporary directory chmod",
        "analysis_scope": "Assess get_or_create_tmp_dir chmod mode only.",
        "entry_point": {"code": "def get_or_create_tmp_dir(", "file": "mlflow/utils/file_utils.py", "line": 3},
        "critical_operation": {"code": "os.chmod(tmp_dir, mode)", "file": "mlflow/utils/file_utils.py", "line": 9},
        "cases": [
            {"case_id": "hp001_a", "revision_role": "vulnerable", "commit": "0" * 40,
             "checkout": "vulnerable", "file_path": "mlflow/utils/file_utils.py", "line_hint": 3},
            {"case_id": "hp001_b", "revision_role": "fixed", "commit": "0" * 40,
             "checkout": "fixed", "file_path": "mlflow/utils/file_utils.py", "line_hint": 3},
        ],
        "property_id": "temporary-directory-race",
    })


def _write_hp001_case(root: Path, checkout: str, mode: str) -> None:
    path = root / checkout / "mlflow/utils/file_utils.py"
    path.parent.mkdir(parents=True)
    path.write_text(f'''
def cache_return_value_per_process(fn):
    return fn

@cache_return_value_per_process
def get_or_create_tmp_dir():
    if False:
        tmp_dir = "/tmp/mlflow"
        os.makedirs(tmp_dir, exist_ok=True)
    else:
        tmp_dir = tempfile.mkdtemp()
        os.chmod(tmp_dir, {mode})
        atexit.register(shutil.rmtree, tmp_dir, ignore_errors=True)
    return tmp_dir
''')


@pytest.mark.parametrize(
    ("case_index", "expected_status", "expected_mode"),
    [(0, ValidationStatus.CONFIRMED, "0o777"), (1, ValidationStatus.REFUTED, "0o750")],
)
def test_hp001_tmpdir_fixture_types_chmod_race_property(tmp_path, case_index, expected_status, expected_mode):
    _write_hp001_case(tmp_path, "vulnerable", "0o777")
    _write_hp001_case(tmp_path, "fixed", "0o750")
    pair = _hp001_pair()
    observation = _invoke_registered_fixture(tmp_path, pair, pair.cases[case_index])

    assert observation.status == "ok"
    # Under the proof scope contract (C1/C3/C4), local pattern check has coverage='local',
    # demoted to UNRESOLVED for the candidate while keeping raw mode in content.
    assert observation.validation_status == ValidationStatus.UNRESOLVED
    assert expected_mode in observation.content
    content_payload = json.loads(observation.content)
    assert content_payload["raw_status"] == expected_status.value


def _hp002_pair() -> PythonHeldoutPair:
    return PythonHeldoutPair.model_validate({
        "pair_id": "hp002_entry_00317_ghsa_rf6x_r45m_xv3w",
        "entry_id": "entry-00317",
        "repository_url": "https://github.com/langflow-ai/langflow",
        "advisory": "GHSA-RF6X-R45M-XV3W",
        "source_link": "https://github.com/advisories/GHSA-rf6x-r45m-xv3w",
        "vuln_ids": ["CVE-2026-33053"],
        "source_root": ".",
        "python_import_root": "src/backend/base",
        "vulnerability_title": "Langflow API key IDOR",
        "source_scope": "delete API key authorization",
        "analysis_scope": "Assess delete_api_key ownership boundary only.",
        "entry_point": {"code": "@router.delete", "file": "src/backend/base/langflow/api/v1/api_key.py", "line": 1},
        "critical_operation": {"code": "session.get(ApiKey, api_key_id)", "file": "src/backend/base/langflow/services/database/models/api_key/crud.py", "line": 1},
        "cases": [
            {"case_id": "hp002_a", "revision_role": "vulnerable", "commit": "0" * 40,
             "checkout": "vulnerable", "file_path": "src/backend/base/langflow/services/database/models/api_key/crud.py", "line_hint": 1},
            {"case_id": "hp002_b", "revision_role": "fixed", "commit": "0" * 40,
             "checkout": "fixed", "file_path": "src/backend/base/langflow/services/database/models/api_key/crud.py", "line_hint": 1},
        ],
        "property_id": "authorization-boundary",
    })


def _write_hp002_case(root: Path, checkout: str, *, guarded: bool) -> None:
    service = root / checkout / "src/backend/base/langflow/services/database/models/api_key/crud.py"
    route = root / checkout / "src/backend/base/langflow/api/v1/api_key.py"
    service.parent.mkdir(parents=True, exist_ok=True)
    route.parent.mkdir(parents=True, exist_ok=True)
    if guarded:
        service.write_text('''
async def delete_api_key(session, api_key_id, user_id):
    api_key = session.get(ApiKey, api_key_id)
    if api_key.user_id != user_id:
        raise HTTPException(status_code=403, detail="Cannot delete another user's API key")
    session.delete(api_key)
''')
        route.write_text('''
@router.delete("/{api_key_id}")
async def delete_api_key_route(api_key_id, db, current_user):
    delete_api_key(db, api_key_id, current_user.id)
    return {"detail": "API Key deleted"}
''')
    else:
        service.write_text('''
async def delete_api_key(session, api_key_id):
    api_key = session.get(ApiKey, api_key_id)
    session.delete(api_key)
''')
        route.write_text('''
@router.delete("/{api_key_id}")
async def delete_api_key_route(api_key_id, db):
    delete_api_key(db, api_key_id)
    return {"detail": "API Key deleted"}
''')


@pytest.mark.parametrize(
    ("case_index", "expected_status", "guarded"),
    [(0, ValidationStatus.CONFIRMED, False), (1, ValidationStatus.REFUTED, True)],
)
def test_hp002_authz_fixture_types_route_to_service_boundary(tmp_path, case_index, expected_status, guarded):
    _write_hp002_case(tmp_path, "vulnerable", guarded=False)
    _write_hp002_case(tmp_path, "fixed", guarded=True)
    pair = _hp002_pair()
    observation = _invoke_registered_fixture(tmp_path, pair, pair.cases[case_index])

    assert guarded is (case_index == 1)
    assert observation.status == "ok"
    # Local pattern check has coverage='local', so candidate status is UNRESOLVED.
    assert observation.validation_status == ValidationStatus.UNRESOLVED
    assert '"property_id":"authorization-boundary"' in observation.content
    content_payload = json.loads(observation.content)
    assert content_payload["raw_status"] == expected_status.value


def test_final_claim_task_plan_does_not_register_development_fixtures(monkeypatch, tmp_path):
    from cv_agent.domain.types import Candidate, CodeDocument
    from cv_agent.evaluation.datasets import advisory_tasks
    from cv_agent.evaluation.datasets.advisory_config import PythonHeldoutPairExperimentConfig
    from cv_agent.retrieval import RepositoryIndex
    from test_python_heldout_pair_config import config_dict

    data = config_dict()
    data["dataset_role"] = "final-test"
    data["claim_eligible"] = True
    data["selected_cells"] = [{"case_id": "hp001_a", "system": "E1"}]
    data["limits"]["max_requests"] = 1
    config = PythonHeldoutPairExperimentConfig.model_validate(data)
    index = RepositoryIndex([CodeDocument(repository_id="hp001_a", path="example.py::entry@1-2", text="def entry():\n    pass\n")])
    candidate = Candidate(
        candidate_id="hp001_a",
        case_id="hp001_a",
        repository_id="hp001_a",
        path="example.py::entry@1-2",
        line=1,
        query="example",
        property_id="dynamic-evaluation",
    )

    monkeypatch.setattr(advisory_tasks, "require_clean_checkout", lambda checkout, commit: None)
    monkeypatch.setattr(advisory_tasks, "build_pair_input", lambda *args, **kwargs: (index, candidate, {"example.py": "digest"}))
    monkeypatch.setattr(advisory_tasks, "case_identity", lambda *args, **kwargs: {"case_id": "hp001_a"})

    def forbidden_fixture_registration(*args, **kwargs):
        raise AssertionError("final-test task construction must not register development fixtures")

    monkeypatch.setattr(advisory_tasks, "advisory_fixture_cases", forbidden_fixture_registration)

    tasks, subjects, identities, fixture_registry = advisory_tasks.build_task_plan(tmp_path, config)

    assert len(tasks) == 1
    assert fixture_registry == {}
    registered_tools = tasks[0][4]
    fixture_tool = next(tool for tool in registered_tools if tool.name == "run_fixture_test")
    assert fixture_tool.available is False
    assert subjects["hp001_a"].property_id == "dynamic-evaluation"
    assert identities == {"hp001_a": {"case_id": "hp001_a"}}
