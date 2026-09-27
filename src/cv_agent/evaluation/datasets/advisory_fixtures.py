from __future__ import annotations

import ast
import hashlib
import platform
import subprocess
import sys
from pathlib import Path

from cv_agent.domain.evidence import FixtureProofScope, ValidationStatus
from cv_agent.domain.types import Candidate
from cv_agent.evaluation.datasets.advisory_config import PythonHeldoutPair, PythonHeldoutPairCase
from cv_agent.retrieval import RepositoryIndex
from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.validation import FixtureCase, FixtureOutcome

HP003_PAIR_ID = "hp003_entry_00389_ghsa_rvhj_8chj_8v3c"
HP003_PROPERTY_ID = "command-execution"
HP003_BACKEND = "mlflow/pyfunc/backend.py"
HP003_MLSERVER = "mlflow/pyfunc/mlserver.py"
HP003_PROBE_EXPR = "$(printf${IFS}CV_AGENT_PROBE)"
HP003_PROBE_EXPANDED = "CV_AGENT_PROBE"
HP003_TIMEOUT_SECONDS = 20.0

HP001_PAIR_ID = "hp001_entry_00101_ghsa_4x5p_f36r_mxxr"
HP001_PROPERTY_ID = "temporary-directory-race"
HP001_FILE = "mlflow/utils/file_utils.py"

HP002_PAIR_ID = "hp002_entry_00317_ghsa_rf6x_r45m_xv3w"
HP002_PROPERTY_ID = "authorization-boundary"
HP002_SERVICE = "src/backend/base/langflow/services/database/models/api_key/crud.py"
HP002_ROUTE = "src/backend/base/langflow/api/v1/api_key.py"


def advisory_fixture_cases(
    root: Path,
    pair: PythonHeldoutPair,
    case: PythonHeldoutPairCase,
    index: RepositoryIndex,
    candidate: Candidate,
    source_sha256: dict[str, str],
) -> tuple[FixtureCase, ...]:
    if pair.pair_id == HP001_PAIR_ID:
        return _hp001_fixture_cases(root, pair, case, index, candidate, source_sha256)
    if pair.pair_id == HP002_PAIR_ID:
        return _hp002_fixture_cases(root, pair, case, index, candidate, source_sha256)
    if pair.pair_id != HP003_PAIR_ID:
        return ()
    if (
        pair.property_id != HP003_PROPERTY_ID
        or candidate.property_id != HP003_PROPERTY_ID
        or tuple(pair.input_parameters) != ("model_uri",)
        or pair.entry_boolean_arguments.get("enable_mlserver") is not True
        or case.file_path != HP003_BACKEND
    ):
        raise ValueError("hp003 fixture registration does not match the declared command candidate")
    if HP003_BACKEND not in source_sha256 or HP003_MLSERVER not in source_sha256:
        raise ValueError("hp003 fixture requires backend.py and mlserver.py source digests")
    checkout = root / case.checkout
    subject = candidate_subject(index, candidate)
    backend_digest = source_sha256[HP003_BACKEND]
    mlserver_digest = source_sha256[HP003_MLSERVER]
    runtime_root = _prepare_hp003_runtime(root, case.case_id, subject.source_digest)
    shell = Path("/bin/bash").resolve(strict=True)
    executable_paths = (shell, _dynamic_loader(), runtime_root / "bin/mlserver")
    read_roots = tuple(
        path for path in (
            checkout,
            runtime_root,
            Path(sys.prefix),
            Path(sys.base_prefix),
            Path("/usr/lib"),
            Path("/lib"),
            Path("/lib64"),
            Path("/etc/ld.so.cache"),
            Path("/dev/null"),
            Path("/dev/urandom"),
        )
        if path.exists()
    )

    proof_scope = FixtureProofScope(
        contract_id="hp003_mlserver_shell_probe_local",
        property_id=HP003_PROPERTY_ID,
        coverage="local",
        method="bounded_execution",
        supported_statuses=(ValidationStatus.CONFIRMED, ValidationStatus.REFUTED),
    )

    def runner() -> FixtureOutcome:
        return _run_hp003_mlserver_fixture(
            checkout=checkout,
            expected_backend_digest=backend_digest,
            expected_mlserver_digest=mlserver_digest,
            runtime_root=runtime_root,
            shell=shell,
        )

    return (
        FixtureCase(
            case.case_id,
            runner,
            timeout_seconds=HP003_TIMEOUT_SECONDS,
            read_roots=read_roots,
            executable_paths=executable_paths,
            subject=subject,
            proof_scope=proof_scope,
        ),
    )


def _hp001_fixture_cases(
    root: Path,
    pair: PythonHeldoutPair,
    case: PythonHeldoutPairCase,
    index: RepositoryIndex,
    candidate: Candidate,
    source_sha256: dict[str, str],
) -> tuple[FixtureCase, ...]:
    if (
        pair.property_id != HP001_PROPERTY_ID
        or candidate.property_id != HP001_PROPERTY_ID
        or case.file_path != HP001_FILE
        or HP001_FILE not in source_sha256
    ):
        raise ValueError("hp001 fixture registration does not match the declared temporary-directory candidate")
    checkout = root / case.checkout
    subject = candidate_subject(index, candidate)
    file_digest = source_sha256[HP001_FILE]
    proof_scope = FixtureProofScope(
        contract_id="hp001_tmpdir_chmod_local",
        property_id=HP001_PROPERTY_ID,
        coverage="local",
        method="source_pattern",
        supported_statuses=(ValidationStatus.CONFIRMED, ValidationStatus.REFUTED),
    )

    def runner() -> FixtureOutcome:
        return _run_hp001_tmpdir_fixture(checkout=checkout, expected_digest=file_digest)

    return (
        FixtureCase(
            case.case_id,
            runner,
            timeout_seconds=10.0,
            read_roots=(checkout,),
            subject=subject,
            proof_scope=proof_scope,
        ),
    )


def _hp002_fixture_cases(
    root: Path,
    pair: PythonHeldoutPair,
    case: PythonHeldoutPairCase,
    index: RepositoryIndex,
    candidate: Candidate,
    source_sha256: dict[str, str],
) -> tuple[FixtureCase, ...]:
    if (
        pair.property_id != HP002_PROPERTY_ID
        or candidate.property_id != HP002_PROPERTY_ID
        or case.file_path != HP002_SERVICE
        or HP002_SERVICE not in source_sha256
        or HP002_ROUTE not in source_sha256
    ):
        raise ValueError("hp002 fixture registration does not match the declared authorization candidate")
    checkout = root / case.checkout
    subject = candidate_subject(index, candidate)
    service_digest = source_sha256[HP002_SERVICE]
    route_digest = source_sha256[HP002_ROUTE]
    proof_scope = FixtureProofScope(
        contract_id="hp002_authz_local",
        property_id=HP002_PROPERTY_ID,
        coverage="local",
        method="source_pattern",
        supported_statuses=(ValidationStatus.CONFIRMED, ValidationStatus.REFUTED),
    )

    def runner() -> FixtureOutcome:
        return _run_hp002_authz_fixture(
            checkout=checkout,
            expected_service_digest=service_digest,
            expected_route_digest=route_digest,
        )

    return (
        FixtureCase(
            case.case_id,
            runner,
            timeout_seconds=10.0,
            read_roots=(checkout,),
            subject=subject,
            proof_scope=proof_scope,
        ),
    )


def _prepare_hp003_runtime(root: Path, case_id: str, source_digest: str) -> Path:
    runtime_root = root / "artifacts/fixture_runtime/hp003_mlserver_shell" / f"{case_id}-{source_digest[:16]}"
    bin_dir = runtime_root / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    recorder = bin_dir / "mlserver"
    content = "#!/bin/bash\nprintf '%s\\n' \"$@\"\n"
    if not recorder.exists() or recorder.read_text() != content:
        recorder.write_text(content)
    recorder.chmod(0o755)
    (runtime_root / f"model{HP003_PROBE_EXPR}").mkdir(exist_ok=True)
    return runtime_root


def _dynamic_loader() -> Path:
    loaders = {
        "x86_64": Path("/lib64/ld-linux-x86-64.so.2"),
        "aarch64": Path("/lib/ld-linux-aarch64.so.1"),
    }
    loader = loaders.get(platform.machine())
    if loader is None:
        raise RuntimeError("hp003 fixture executable grant requires a supported Linux architecture")
    return loader.resolve(strict=True)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run_hp001_tmpdir_fixture(*, checkout: Path, expected_digest: str) -> FixtureOutcome:
    source_path = checkout / HP001_FILE
    if not source_path.is_file() or _sha256(source_path) != expected_digest:
        return FixtureOutcome(
            status=ValidationStatus.UNRESOLVED,
            summary="hp001 fixture source snapshot changed before execution",
            details={"mismatches": [HP001_FILE]},
        )
    source = source_path.read_text()
    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        return FixtureOutcome(
            status=ValidationStatus.UNRESOLVED,
            summary="hp001 fixture could not parse file_utils.py",
            details={"error": f"SyntaxError: {error}"},
        )
    function = _find_function(tree, "get_or_create_tmp_dir")
    if function is None:
        return FixtureOutcome(
            status=ValidationStatus.UNRESOLVED,
            summary="hp001 fixture did not find get_or_create_tmp_dir",
        )
    chmod_modes: list[int] = []
    saw_tmp_mkdtemp = False
    saw_atexit_cleanup = False
    for node in ast.walk(function):
        text = ast.unparse(node)
        if isinstance(node, ast.Call) and text.startswith("tempfile.mkdtemp("):
            saw_tmp_mkdtemp = True
        if isinstance(node, ast.Call) and text.startswith("atexit.register(") and "shutil.rmtree" in text:
            saw_atexit_cleanup = True
        if not isinstance(node, ast.Call):
            continue
        if not _call_name_matches(node.func, "os.chmod") or len(node.args) < 2:
            continue
        target = ast.unparse(node.args[0])
        mode = _literal_int(node.args[1])
        if target == "tmp_dir" and mode is not None:
            chmod_modes.append(mode)
    details = {
        "property_id": HP001_PROPERTY_ID,
        "chmod_modes": [oct(mode) for mode in chmod_modes],
        "saw_tempfile_mkdtemp": saw_tmp_mkdtemp,
        "saw_atexit_cleanup": saw_atexit_cleanup,
        "scope": "get_or_create_tmp_dir local tempfile branch chmod mode",
    }
    if len(chmod_modes) != 1 or not saw_tmp_mkdtemp or not saw_atexit_cleanup:
        return FixtureOutcome(
            status=ValidationStatus.UNRESOLVED,
            summary="hp001 fixture source shape is outside its bounded proof contract",
            details=details,
        )
    mode = chmod_modes[0]
    if mode & 0o002:
        return FixtureOutcome(
            status=ValidationStatus.CONFIRMED,
            summary="get_or_create_tmp_dir widens a mkdtemp directory to others-writable permissions",
            details=details,
        )
    return FixtureOutcome(
        status=ValidationStatus.REFUTED,
        summary="get_or_create_tmp_dir keeps the mkdtemp directory non-others-writable",
        details=details,
    )


def _run_hp002_authz_fixture(
    *, checkout: Path, expected_service_digest: str, expected_route_digest: str,
) -> FixtureOutcome:
    service_path = checkout / HP002_SERVICE
    route_path = checkout / HP002_ROUTE
    mismatches = []
    for label, path, expected in (
        (HP002_SERVICE, service_path, expected_service_digest),
        (HP002_ROUTE, route_path, expected_route_digest),
    ):
        if not path.is_file() or _sha256(path) != expected:
            mismatches.append(label)
    if mismatches:
        return FixtureOutcome(
            status=ValidationStatus.UNRESOLVED,
            summary="hp002 fixture source snapshot changed before execution",
            details={"mismatches": mismatches},
        )
    try:
        service_tree = ast.parse(service_path.read_text())
        route_tree = ast.parse(route_path.read_text())
    except SyntaxError as error:
        return FixtureOutcome(
            status=ValidationStatus.UNRESOLVED,
            summary="hp002 fixture could not parse authorization source",
            details={"error": f"SyntaxError: {error}"},
        )
    service = _find_function(service_tree, "delete_api_key")
    route = _find_function(route_tree, "delete_api_key_route")
    if service is None or route is None:
        return FixtureOutcome(
            status=ValidationStatus.UNRESOLVED,
            summary="hp002 fixture did not find service and route functions",
            details={"service_found": service is not None, "route_found": route is not None},
        )
    service_params = [arg.arg for arg in service.args.args]
    route_params = [arg.arg for arg in route.args.args]
    service_text = ast.unparse(service)
    route_text = ast.unparse(route)
    has_lookup = "session.get(ApiKey, api_key_id)" in service_text
    has_delete = "session.delete(api_key)" in service_text
    has_owner_guard = "api_key.user_id != user_id" in service_text
    route_has_current_user = "current_user" in route_params
    route_passes_user = "delete_api_key(db, api_key_id, current_user.id)" in route_text
    route_dependency_login_only = "dependencies=[Depends(auth_utils.get_current_active_user)]" in route_text
    guard_line = None
    delete_line = None
    for stmt in service.body:
        text = ast.unparse(stmt)
        if "api_key.user_id != user_id" in text and guard_line is None:
            guard_line = stmt.lineno
        if "session.delete(" in text and delete_line is None:
            delete_line = stmt.lineno
    guard_precedes_delete = (
        guard_line is not None
        and delete_line is not None
        and guard_line < delete_line
    )
    details = {
        "property_id": HP002_PROPERTY_ID,
        "service_parameters": service_params,
        "route_parameters": route_params,
        "has_lookup_by_api_key_id": has_lookup,
        "has_delete": has_delete,
        "has_owner_guard": has_owner_guard,
        "guard_precedes_delete": guard_precedes_delete,
        "route_has_current_user": route_has_current_user,
        "route_passes_current_user_id": route_passes_user,
        "route_dependency_login_only": route_dependency_login_only,
        "scope": "delete_api_key route-to-service ownership boundary",
    }
    if not has_lookup or not has_delete:
        return FixtureOutcome(
            status=ValidationStatus.UNRESOLVED,
            summary="hp002 fixture source shape is outside its bounded proof contract",
            details=details,
        )
    if not has_owner_guard and not route_has_current_user and not route_passes_user:
        return FixtureOutcome(
            status=ValidationStatus.CONFIRMED,
            summary="delete_api_key deletes by api_key_id without binding the record to the current user",
            details=details,
        )
    if has_owner_guard and route_has_current_user and route_passes_user and guard_precedes_delete:
        return FixtureOutcome(
            status=ValidationStatus.REFUTED,
            summary="delete_api_key checks api_key.user_id against the route current_user before deletion",
            details=details,
        )
    return FixtureOutcome(
        status=ValidationStatus.UNRESOLVED,
        summary="hp002 fixture saw partial authorization facts that do not prove or refute the boundary",
        details=details,
    )


def _find_function(tree: ast.AST, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    matches = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    ]
    return matches[0] if len(matches) == 1 else None


def _call_name_matches(node: ast.AST, qualified: str) -> bool:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.insert(0, current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.insert(0, current.id)
    return ".".join(parts) == qualified


def _literal_int(node: ast.AST) -> int | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return node.value
    return None


def _run_hp003_mlserver_fixture(
    *,
    checkout: Path,
    expected_backend_digest: str,
    expected_mlserver_digest: str,
    runtime_root: Path,
    shell: Path,
) -> FixtureOutcome:
    backend = checkout / HP003_BACKEND
    mlserver = checkout / HP003_MLSERVER
    mismatches = []
    for label, path, expected in (
        (HP003_BACKEND, backend, expected_backend_digest),
        (HP003_MLSERVER, mlserver, expected_mlserver_digest),
    ):
        if not path.is_file() or _sha256(path) != expected:
            mismatches.append(label)
    if mismatches:
        return FixtureOutcome(
            status=ValidationStatus.UNRESOLVED,
            summary="hp003 fixture source snapshot changed before execution",
            details={"mismatches": mismatches},
        )
    backend_text = backend.read_text()
    mlserver_text = mlserver.read_text()
    backend_error = _validate_backend_shape(backend_text)
    mlserver_error = _validate_mlserver_shape(mlserver_text)
    if backend_error or mlserver_error:
        return FixtureOutcome(
            status=ValidationStatus.UNRESOLVED,
            summary="hp003 fixture source shape is outside its bounded proof contract",
            details={"backend_error": backend_error, "mlserver_error": mlserver_error},
        )
    probe_path = runtime_root / f"model{HP003_PROBE_EXPR}"
    if not probe_path.exists():
        return FixtureOutcome(
            status=ValidationStatus.UNRESOLVED,
            summary="hp003 fixture runtime probe path is missing",
        )
    try:
        command = _mlserver_command_from_source(mlserver_text, str(probe_path))
        result = subprocess.run(
            [str(shell), "--noprofile", "--norc", "-c", "exec " + command],
            cwd=runtime_root,
            env={"PATH": str(runtime_root / "bin"), "LC_ALL": "C", "LANG": "C"},
            capture_output=True,
            timeout=5,
        )
    except Exception as error:
        return FixtureOutcome(
            status=ValidationStatus.UNRESOLVED,
            summary="hp003 fixture failed before shell-consumption evidence",
            details={"error": f"{type(error).__name__}: {error}"},
        )
    stdout = result.stdout.decode("utf-8", errors="replace")
    stderr = result.stderr.decode("utf-8", errors="replace")
    literal = f"model{HP003_PROBE_EXPR}"
    expanded = f"model{HP003_PROBE_EXPANDED}"
    literal_observed = literal in stdout
    expanded_observed = expanded in stdout
    details = {
        "property_id": HP003_PROPERTY_ID,
        "scope": "POSIX local env_manager=local, enable_mlserver=True, existing local model directory",
        "returncode": result.returncode,
        "stdout_lines": stdout.splitlines(),
        "stderr": stderr[:500],
        "command_prefix": command.split(str(runtime_root), 1)[0],
        "literal_probe_observed": literal_observed,
        "expanded_probe_observed": expanded_observed,
    }
    if result.returncode == 0 and expanded_observed and not literal_observed:
        return FixtureOutcome(
            status=ValidationStatus.CONFIRMED,
            summary="POSIX bash expanded the unquoted model_uri while serving through mlserver",
            details=details,
        )
    if result.returncode == 0 and literal_observed and not expanded_observed:
        return FixtureOutcome(
            status=ValidationStatus.REFUTED,
            summary="shlex.quote preserved the model_uri shell syntax as a literal mlserver argument",
            details=details,
        )
    return FixtureOutcome(
        status=ValidationStatus.UNRESOLVED,
        summary="hp003 fixture shell-consumption probe did not unambiguously confirm expansion or literal preservation",
        details=details,
    )


def _mlserver_command_from_source(source: str, model_uri: str) -> str:
    namespace = {"__name__": "cv_agent_hp003_mlserver_fixture"}
    exec(compile(source, HP003_MLSERVER, "exec"), namespace)
    get_cmd = namespace.get("get_cmd")
    if not callable(get_cmd):
        raise RuntimeError("mlserver.py did not define get_cmd")
    command, command_env = get_cmd(model_uri, port=5000, host="127.0.0.1", timeout=30, nworkers=None)
    if not isinstance(command, str) or not isinstance(command_env, dict):
        raise RuntimeError("mlserver.get_cmd returned an unsupported shape")
    if not command.startswith("mlserver start "):
        raise RuntimeError("mlserver.get_cmd did not build the expected mlserver start command")
    return command


def _validate_mlserver_shape(source: str) -> str | None:
    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        return f"SyntaxError: {error}"
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "get_cmd"]
    if len(functions) != 1:
        return "expected one get_cmd function"
    function = functions[0]
    command_assignments = [
        node for node in ast.walk(function)
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "cmd" for target in node.targets)
        and isinstance(node.value, ast.JoinedStr)
        and "mlserver start" in ast.unparse(node.value)
    ]
    if len(command_assignments) != 1:
        return "expected one f-string assignment building mlserver start command"
    returns = [node for node in ast.walk(function) if isinstance(node, ast.Return)]
    if not returns or not any("cmd" in ast.unparse(node.value) and "cmd_env" in ast.unparse(node.value) for node in returns if node.value is not None):
        return "expected get_cmd to return cmd and cmd_env"
    return None


def _validate_backend_shape(source: str) -> str | None:
    required_fragments = (
        "local_path = _download_artifact_from_uri(model_uri)",
        "server_implementation = mlserver if enable_mlserver else scoring_server",
        "server_implementation.get_cmd(",
        "command = \"exec \" + command",
        "if self._env_manager != em.LOCAL:",
        "command = [\"bash\", \"-c\", command]",
        "subprocess.Popen(",
    )
    normalized = "\n".join(line.rstrip() for line in source.splitlines())
    missing = [fragment for fragment in required_fragments if fragment not in normalized]
    if missing:
        return "missing required fragments: " + "; ".join(missing)
    try:
        ast.parse(source)
    except SyntaxError as error:
        return f"SyntaxError: {error}"
    return None
