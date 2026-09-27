"""Source-bound, sink-only hp003 shell-argument diagnostic.

This intentionally treats the download result as an arbitrary builtin string.
It says nothing about commands executed by download helpers or by MLServer after
Popen. Its subject is distinct from the original whole-function candidate.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
import sys
import textwrap
from pathlib import Path
from typing import Any, Literal

from cv_agent.domain.evidence import ValidationSubject
from cv_agent.domain.types import Candidate, CodeDocument, FrozenModel
from cv_agent.retrieval import RepositoryIndex
from cv_agent.tools.analysis.commands import analyze_command
from cv_agent.tools.identity import repository_source_digest


CALLSITE_PROPERTY = "popen-shell-argument-injection"
_SERVE_PATH = re.compile(r"^mlflow/pyfunc/backend\.py::PyFuncBackend\.serve@(\d+)-(\d+)$")
_MLSERVER_PATH = re.compile(r"^mlflow/pyfunc/mlserver\.py::get_cmd@\d+-\d+$")
_POpen_LINE = 311
# This one-off diagnostic reconstructs a narrow command slice. Pin its caller
# source so an unmodeled intervening mutation cannot disappear from that slice.
# Both frozen hp003 revisions have this same serve document text.
_AUDITED_SERVE_DOCUMENT_SHA256 = "26a8c747e1eb52605cdf32610aac9b8eead2d15c1e8c948d9769d252df44e479"
_AUDITED_MODULE_SHA256 = {
    "mlflow/pyfunc/backend.py": {
        "709861cdbfcc51f27f8e377d65babc058d17fff368af0c29d3dd93c7e2927065",
    },
    "mlflow/pyfunc/mlserver.py": {
        "92d434b575c1f1c6bad6e0bcc1ded6a228160f80697c40d6551755db74b7993b",
        "8aab28c8f1c9f95395c7669022aeca5fa3113d5b3433d46566b62e7cf429e776",
    },
}


class CallsiteResult(FrozenModel):
    subject: ValidationSubject
    status: Literal["SANITIZED", "UNSANITIZED", "UNRESOLVED"]
    callsite_label: Literal["SAFE", "VULNERABLE"] | None
    analysis_issues: tuple[str, ...] = ()
    sink_facts: tuple[dict[str, Any], ...] = ()
    out_of_scope_sinks: tuple[dict[str, Any], ...] = ()
    document_sha256: dict[str, str]
    proof_method: Literal["bounded_static_source_slice"] = "bounded_static_source_slice"
    counts_toward_original_metrics: Literal[False] = False


def _same_ast(node: ast.AST, statement: str) -> bool:
    expected = ast.parse(statement).body[0]
    return ast.dump(node, include_attributes=False) == ast.dump(expected, include_attributes=False)


def _binds(node: ast.AST, name: str) -> bool:
    targets: list[ast.AST] = []
    if isinstance(node, ast.Assign):
        targets.extend(node.targets)
    elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
        targets.append(node.target)
    return any(
        isinstance(part, ast.Name) and part.id == name
        for target in targets for part in ast.walk(target)
    )


def _inside_branch(function: ast.FunctionDef, node: ast.AST, test: str, branch: str) -> bool:
    wanted = ast.parse(test, mode="eval").body
    for condition in ast.walk(function):
        if not isinstance(condition, ast.If):
            continue
        if ast.dump(condition.test, include_attributes=False) != ast.dump(wanted, include_attributes=False):
            continue
        statements = condition.body if branch == "body" else condition.orelse
        if any(part is node for statement in statements for part in ast.walk(statement)):
            return True
    return False


def _serve_shape_issues(document: CodeDocument, candidate: Candidate) -> list[str]:
    issues: list[str] = []
    match = _SERVE_PATH.fullmatch(document.path)
    if match is None or document.path != candidate.path:
        return ["candidate is not the indexed PyFuncBackend.serve span"]
    if hashlib.sha256(document.text.encode()).hexdigest() != _AUDITED_SERVE_DOCUMENT_SHA256:
        issues.append("serve source digest differs from the audited call-site slice")
    if document.import_aliases.get("mlserver") != "mlflow.pyfunc.mlserver":
        issues.append("mlserver import binding is not canonical")
    if document.import_aliases.get("subprocess") != "subprocess":
        issues.append("subprocess import binding is not canonical")
    if {"mlserver", "subprocess"} & set(document.module_rebindings):
        issues.append("module command binding may be rebound")
    assumptions = candidate.entry_condition_assumptions
    if (
        candidate.entry_boolean_arguments.get("enable_mlserver") is not True
        or assumptions.get("is_windows()") is not False
        or assumptions.get("sys.platform.startswith('linux')") is not True
        or assumptions.get("self._env_manager != em.LOCAL") is not False
    ):
        issues.append("call-site scenario does not establish the POSIX MLServer local branch")
    try:
        tree = ast.parse(textwrap.dedent(document.text))
    except SyntaxError:
        return [*issues, "serve source is not parseable Python"]
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "serve"]
    if len(functions) != 1:
        return [*issues, "serve function is not uniquely present"]
    function = functions[0]
    if any(
        isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
        and node.id in {"mlserver", "subprocess"}
        for node in ast.walk(function)
    ):
        issues.append("call-site module binding is locally rebound")
    assignments = [node for node in ast.walk(function) if _binds(node, "command")]
    expected = (
        "command, command_env = server_implementation.get_cmd(local_path, port, host, timeout, self._nworkers)",
        "command = 'exec ' + command",
        "command = ['bash', '-c', command]",
    )
    assignments.sort(key=lambda node: node.lineno)
    if len(assignments) != 3 or any(
        not _same_ast(node, source) for node, source in zip(assignments, expected)
    ):
        issues.append("command assignment chain differs from the audited call site")
    else:
        get_cmd, prefix, bash_argv = assignments
        if not (get_cmd.lineno < prefix.lineno < bash_argv.lineno):
            issues.append("command assignment order is not established")
        if not _inside_branch(function, prefix, "not is_windows()", "body"):
            issues.append("exec prefix is not guarded by the POSIX branch")
        if not _inside_branch(function, bash_argv, "not is_windows()", "body"):
            issues.append("bash -c argv is not guarded by the POSIX branch")
    ordinary_assignments = [node for node in ast.walk(function) if isinstance(node, ast.Assign)]
    for name, source in (
        ("local_path", "local_path = _download_artifact_from_uri(model_uri)"),
        ("server_implementation", "server_implementation = mlserver if enable_mlserver else scoring_server"),
    ):
        matches = [node for node in ordinary_assignments if _binds(node, name)]
        if len(matches) != 1 or not _same_ast(matches[0], source):
            issues.append(f"{name} binding differs from the audited call site")
    popens = [
        node for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "subprocess"
        and node.func.attr == "Popen"
    ]
    if len(popens) != 1:
        issues.append("subprocess.Popen is not unique")
    else:
        popen = popens[0]
        absolute_line = int(match.group(1)) + popen.lineno - 1
        if absolute_line != _POpen_LINE:
            issues.append("Popen source line is not the declared call site")
        if (
            len(popen.args) != 1
            or not isinstance(popen.args[0], ast.Name)
            or popen.args[0].id != "command"
            or any(keyword.arg in {"shell", "executable"} for keyword in popen.keywords)
        ):
            issues.append("Popen command consumption differs from the audited call site")
        if not _inside_branch(function, popen, "self._env_manager != em.LOCAL", "orelse"):
            issues.append("Popen is not in the declared local-environment branch")
        if assignments and popen.lineno <= max(item.lineno for item in assignments):
            issues.append("Popen is not after command construction")
    return issues


def _helper_issue(document: CodeDocument | None) -> str | None:
    if document is None:
        return "MLServer get_cmd definition is not indexed"
    try:
        tree = ast.parse(document.text)
    except SyntaxError:
        return "get_cmd source is not parseable Python"
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "get_cmd"]
    if len(functions) != 1:
        return "get_cmd function is not uniquely present"
    if any(isinstance(node, ast.Name) and node.id == "shlex" for node in ast.walk(functions[0])):
        if document.import_aliases.get("shlex") != "shlex" or "shlex" in document.module_rebindings:
            return "shlex quote binding is not canonical"
        if any(
            isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store) and node.id == "shlex"
            for node in ast.walk(functions[0])
        ):
            return "shlex quote binding is locally rebound"
    parameters = functions[0].args.args
    if not parameters or parameters[0].arg != "model_uri" or not isinstance(parameters[0].annotation, ast.Name) or parameters[0].annotation.id != "str":
        return "get_cmd does not declare a builtin string model_uri"
    return None


def _literal(value: Any, name: str) -> str:
    if value is None or type(value) in {str, int, bool}:
        return repr(value)
    raise ValueError(f"unsupported call-site value assumption: {name}")


def analyze_callsite(index: RepositoryIndex, candidate: Candidate) -> CallsiteResult:
    """Analyze only shell parsing of the declared Popen command argument."""
    subject = ValidationSubject(
        property_id=CALLSITE_PROPERTY,
        input_parameters=("local_path",),
        entry_boolean_arguments={"enable_mlserver": True},
        entry_condition_assumptions={
            key: candidate.entry_condition_assumptions[key]
            for key in (
                "is_windows()", "sys.platform.startswith('linux')",
                "self._env_manager != em.LOCAL",
            ) if key in candidate.entry_condition_assumptions
        },
        entry_value_assumptions={**candidate.entry_value_assumptions, "local_path_type": "builtins.str"},
        candidate_id=f"{candidate.candidate_id}:popen-shell-argument",
        repository_id=candidate.repository_id,
        entry_path=candidate.path,
        entry_line=_POpen_LINE,
        source_digest=repository_source_digest(index),
        analysis_scope=(
            "Only POSIX bash interpretation of the command argument at this "
            "subprocess.Popen call; upstream download execution, repository "
            "dispatch, and MLServer runtime behavior are outside this subject."
        ),
    )
    serve = index.document(candidate.path)
    helpers = [document for path, document in index.documents.items() if _MLSERVER_PATH.fullmatch(path)]
    helper = helpers[0] if len(helpers) == 1 else None
    module_documents = {
        file_path: [
            document for path, document in index.documents.items()
            if path.startswith(file_path + "::<module>@")
        ]
        for file_path in _AUDITED_MODULE_SHA256
    }
    hashes = {
        document.path: hashlib.sha256(document.text.encode()).hexdigest()
        for document in (serve, helper) if document is not None
    }
    issues = ["original candidate property is not command-execution"] if candidate.property_id != "command-execution" else []
    if serve is not None and serve.repository_id != candidate.repository_id:
        issues.append("serve repository identity differs from the candidate")
    if helper is not None and helper.repository_id != candidate.repository_id:
        issues.append("get_cmd repository identity differs from the candidate")
    for file_path, documents in module_documents.items():
        if len(documents) != 1:
            issues.append(f"full repository module is not uniquely indexed: {file_path}")
            continue
        module = documents[0]
        hashes[module.path] = hashlib.sha256(module.text.encode()).hexdigest()
        if module.repository_id != candidate.repository_id:
            issues.append(f"full module repository identity differs from the candidate: {file_path}")
        if hashes[module.path] not in _AUDITED_MODULE_SHA256[file_path]:
            issues.append(f"full module source digest is not an audited snapshot: {file_path}")
        relevant_slice = serve if file_path.endswith("backend.py") else helper
        if relevant_slice is not None and relevant_slice.text not in module.text:
            issues.append(f"indexed function slice differs from its full module: {file_path}")
    issues.extend(_serve_shape_issues(serve, candidate) if serve is not None else ["candidate source span is missing"])
    helper_problem = _helper_issue(helper)
    if helper_problem is not None:
        issues.append(helper_problem)
    if issues:
        return CallsiteResult(
            subject=subject, status="UNRESOLVED", callsite_label=None,
            analysis_issues=tuple(issues), document_sha256=hashes,
        )
    assumptions = candidate.entry_value_assumptions
    try:
        args = ", ".join(_literal(assumptions[key], key) for key in (
            "port", "host", "timeout", "self._nworkers",
        ))
    except KeyError as error:
        return CallsiteResult(
            subject=subject, status="UNRESOLVED", callsite_label=None,
            analysis_issues=(f"missing call-site value assumption: {error.args[0]}",),
            document_sha256=hashes,
        )
    except ValueError as error:
        return CallsiteResult(
            subject=subject, status="UNRESOLVED", callsite_label=None,
            analysis_issues=(str(error),), document_sha256=hashes,
        )
    wrapper = CodeDocument(
        repository_id=candidate.repository_id,
        path=f"{candidate.path}::popen_argument_slice",
        language="python",
        text=(
            "def callsite(local_path):\n"
            "    import subprocess\n"
            f"    command, command_env = get_cmd(local_path, {args})\n"
            "    command = 'exec ' + command\n"
            "    command = ['bash', '-c', command]\n"
            "    subprocess.Popen(command, env=command_env)\n"
        ),
        defines=("callsite",),
        calls=("get_cmd", "subprocess.Popen"),
    )
    analysis = analyze_command(
        wrapper,
        helpers=(helper,),
        input_parameters=("local_path",),
        entry_value_assumptions={
            key: assumptions[key]
            for key in ("MLServerDefaultModelName", "MLServerMLflowRuntime")
            if key in assumptions
        },
    )
    callsite_sinks = [
        fact for fact in analysis.sinks
        if fact["path"] == wrapper.path and fact["call"] == "subprocess.Popen"
    ]
    other_sinks = tuple(fact for fact in analysis.sinks if fact not in callsite_sinks)
    if analysis.issues or len(callsite_sinks) != 1 or callsite_sinks[0]["status"] not in {"SANITIZED", "UNSANITIZED"}:
        return CallsiteResult(
            subject=subject, status="UNRESOLVED", callsite_label=None,
            analysis_issues=tuple(analysis.issues or ["Popen argument status is not established"]),
            sink_facts=tuple(callsite_sinks), out_of_scope_sinks=other_sinks,
            document_sha256=hashes,
        )
    status = callsite_sinks[0]["status"]
    return CallsiteResult(
        subject=subject, status=status,
        callsite_label="SAFE" if status == "SANITIZED" else "VULNERABLE",
        sink_facts=tuple(callsite_sinks), out_of_scope_sinks=other_sinks,
        document_sha256=hashes,
    )


def run_pair(root: Path) -> dict:
    """Save both separate call-site subjects without changing benchmark rows."""
    from cv_agent.evaluation.datasets.advisory_config import PythonHeldoutPairCell
    from cv_agent.evaluation.datasets.advisory_tasks import build_tasks
    from cv_agent.evaluation.datasets.composition import load_advisory_config
    from cv_agent.evaluation.runners.run_jev_v3_comparison import JevV3ComparisonConfig
    from cv_agent.harness import AgentSystemVersion
    from cv_agent.runtime.admission import source_fingerprint

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
    cases = {
        candidate.case_id: analyze_callsite(index, candidate).model_dump(mode="json")
        for _, _, index, candidate, _, _ in tasks
    }
    result = {
        "source_fingerprint": source_fingerprint(root),
        "claim_eligible": False,
        "counts_toward_original_metrics": False,
        "scope": "Popen shell-argument interpretation only; download execution excluded",
        "cases": cases,
    }
    output = root / "artifacts/hp003_offline_gap_progression/callsite.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    return result


if __name__ == "__main__":
    if len(sys.argv) != 1:
        raise SystemExit("Usage: python -m cv_agent.evaluation.diagnostics.hp003_callsite")
    from cv_agent.runtime.paths import PROJECT_ROOT

    results = run_pair(PROJECT_ROOT)
    for case_id, case in sorted(results["cases"].items()):
        print(case_id, case["status"], case["callsite_label"])
