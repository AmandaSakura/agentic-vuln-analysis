"""Offline regressions for permission completeness and command argv semantics."""

import json

import pytest

from cv_agent.domain.evidence import ValidationSubject
from cv_agent.domain.types import CodeDocument
from cv_agent.retrieval import RepositoryIndex
from cv_agent.tools.identity import repository_source_digest
from cv_agent.tools.registry import ToolExecutionScope
from test_taint_regressions import trace
from test_validation_tools import _invoke, _registry


def permission_result(body):
    document = CodeDocument(
        repository_id="diagnostic",
        path="permission.py::entry@1-20",
        text="def entry(path, enabled):\n    " + body + "\n",
    )
    index = RepositoryIndex([document])
    subject = ValidationSubject(
        candidate_id="diagnostic", repository_id="diagnostic",
        entry_path=document.path, source_digest=repository_source_digest(index),
    )
    result = _invoke(
        _registry(index), "validate_permission_mode", {"path": document.path},
        ToolExecutionScope(
            admitted_paths=frozenset({document.path}), candidate_path=document.path,
            subject=subject, max_observation_tokens=20000,
        ),
    )
    assert result.status == "ok"
    return result


@pytest.mark.parametrize("prefix", [
    "if enabled:\n        os.chmod(path, 0o750)",
    "os.chmod(path, 0o750)\n    if enabled:\n        pass",
    "os.chmod(path, 0o750)\n    try:\n        pass\n    finally:\n        pass",
], ids=["branch-narrow-mode", "branch-pass", "try-finally-pass"])
def test_permission_does_not_refute_unconditional_later_world_write(prefix):
    result = permission_result(prefix + "\n    os.chmod(path, 0o777)")
    # In all cases the final chmod is reachable and unconditional. Unsupported
    # control flow may remain unresolved, but cannot justify a safety refutation.
    assert result.validation_status.value != "REFUTED", json.loads(result.content)
    if result.validation_status.value == "UNRESOLVED":
        assert result.subject is None
        assert json.loads(result.content)["issues"]


@pytest.mark.parametrize("body, expected", [
    ("os.chmod(path, 0o777)", "CONFIRMED"),
    ("os.chmod(path, 0o750)", "REFUTED"),
    ("os.chmod(path, 0o750)\n    return\n    os.chmod(path, 0o777)", "REFUTED"),
    ("os.chmod(path, 0o750)\n    if False:\n        os.chmod(path, 0o777)", "REFUTED"),
], ids=["unsafe", "safe", "dead-after-return", "dead-branch"])
def test_permission_diagnostic_controls(body, expected):
    result = permission_result(body)
    assert result.validation_status.value == expected
    assert result.subject is not None


@pytest.mark.parametrize("body, expected", [
    ("if enabled:\n        os.chmod(path, 0o750)\n    os.chmod(path, 0o777)", "CONFIRMED"),
    ("os.chmod(path, 0o750)\n    if enabled:\n        pass\n    os.chmod(path, 0o777)", "CONFIRMED"),
    ("os.chmod(path, 0o750)\n    try:\n        pass\n    finally:\n        pass\n    os.chmod(path, 0o777)", "CONFIRMED"),
    ("try:\n        os.chmod(path, 0o750)\n    finally:\n        os.chmod(path, 0o777)", "CONFIRMED"),
    ("if enabled:\n        try:\n            root = get_root()\n        except Exception:\n            root = os.path.join('/tmp', 'local')\n        path = os.path.join(root, 'cache')\n        os.makedirs(path, exist_ok=True)\n    else:\n        path = tempfile.mkdtemp()\n        os.chmod(path, 0o777)\n        atexit.register(shutil.rmtree, path, ignore_errors=True)\n    return path", "CONFIRMED"),
    ("if enabled:\n        try:\n            root = get_root()\n        except Exception:\n            root = os.path.join('/tmp', 'local')\n        path = os.path.join(root, 'cache')\n        os.makedirs(path, exist_ok=True)\n    else:\n        path = tempfile.mkdtemp()\n        os.chmod(path, 0o750)\n        atexit.register(shutil.rmtree, path, ignore_errors=True)\n    return path", "REFUTED"),
    ("if enabled:\n        return\n    os.chmod(path, 0o777)", "UNRESOLVED"),
    ("os.chmod(path, 0o750)\n    try:\n        return\n    finally:\n        os.chmod(path, 0o777)", "UNRESOLVED"),
    ("os.chmod(path, 0o750)\n    try:\n        os = replacement\n    except Exception:\n        pass\n    os.chmod(path, 0o777)", "UNRESOLVED"),
    ("if enabled:\n        os.chmod(path, 0o777)\n    else:\n        os.chmod(path, 0o750)\n    return path", "UNRESOLVED"),
    ("try:\n        pass\n    except replace_bindings():\n        pass\n    os.chmod(path, 0o750)", "UNRESOLVED"),
    ("try:\n        pass\n    except Exception:\n        os.chmod(path, 0o777)", "UNRESOLVED"),
    ("try:\n        os.chmod(path, 0o750)\n    except Exception:\n        os.chmod(path, 0o777)", "UNRESOLVED"),
    ("if os.chmod(path, 0o777):\n        pass\n    os.chmod(path, 0o750)", "UNRESOLVED"),
    ("if os.chmod(path, 0o777) or enabled:\n        pass\n    os.chmod(path, 0o750)", "UNRESOLVED"),
])
def test_permission_complete_structured_control_flow(body, expected):
    result = permission_result(body)
    assert result.validation_status.value == expected, json.loads(result.content)
    assert (result.subject is not None) == (expected != "UNRESOLVED")


@pytest.mark.parametrize("api", ["run", "Popen"])
@pytest.mark.parametrize("assigned", [False, True], ids=["inline", "assigned"])
@pytest.mark.parametrize("argv, expected", [
    ('["bash", "-c", value]', "MAY_REACH"),
    ('["sh", "-c", value]', "MAY_REACH"),
    ('["python3.12", "-c", value]', "MAY_REACH"),
    ('["python.exe", "-c", value]', "MAY_REACH"),
    ('["env", "bash", "-c", value]', "MAY_REACH"),
    ('["env", "-i", "python3.12", "-c", value]', "MAY_REACH"),
    ('["/usr/bin/env", "sh", "-c", value]', "MAY_REACH"),
    ('["sudo", "bash", "-c", value]', "MAY_REACH"),
    ('["echo", value]', "NOT_ESTABLISHED"),
    ('["git", "commit", "-m", value]', "NOT_ESTABLISHED"),
    ('["env", "git", "status", value]', "NOT_ESTABLISHED"),
    ('["env", "FOO=bar", "echo", value]', "NOT_ESTABLISHED"),
    ('["bash", "-c", "echo fixed"]', "NOT_ESTABLISHED"),
], ids=["bash-command", "sh-command", "python312-command", "python-exe-command",
        "env-bash", "env-i-python", "usr-bin-env-sh", "sudo-bash",
        "ordinary-argv", "git-argv", "env-git", "env-echo", "constant-command"])
def test_command_flow_preserves_argv_semantics(api, assigned, argv, expected):
    setup = f"    command = {argv}\n" if assigned else ""
    argument = "command" if assigned else argv
    result = trace({"entry.py": (
        "import subprocess\n\ndef entry(request):\n"
        "    value = request.args['value']\n"
        + setup + f"    return subprocess.{api}({argument})\n"
    )})
    assert result["status"] == "UNRESOLVED"
    assert result["flow_status"] == expected, result


@pytest.mark.parametrize("body, expected", [
    ('return subprocess.run(args=["/bin/bash", "-c", value])', "MAY_REACH"),
    ('command = ("echo", value)\n    return subprocess.run(args=command)', "NOT_ESTABLISHED"),
    ('command = ["echo", value]\n    command = ["bash", "-c", value]\n    return subprocess.run(command)', "MAY_REACH"),
    ('command = ["echo", value]\n    if request.args["flag"]:\n        command = ["bash", "-c", value]\n    return subprocess.run(command)', "MAY_REACH"),
    ('command = ["echo", value]\n    command[0] = "bash"\n    return subprocess.run(command)', "MAY_REACH"),
    ('command = ["echo", value]\n    alias = command\n    alias[0] = "bash"\n    return subprocess.run(command)', "MAY_REACH"),
    ('command = ["echo", value]\n    mutate(command)\n    return subprocess.run(command)', "MAY_REACH"),
    ('command = ["echo", value]\n    return subprocess.run(command, shell=True)', "MAY_REACH"),
    ('return subprocess.run(["echo", "-c", value], executable="bash")', "MAY_REACH"),
    ('command = ["echo", value]\n    return subprocess.run(command, shell=request.args["flag"])', "MAY_REACH"),
], ids=["absolute-shell-keyword", "tuple-keyword", "reassign", "branch-reassign",
        "mutation", "alias-mutation", "escape", "shell-true", "executable-override", "unknown-shell"])
def test_command_argv_structure_boundaries(body, expected):
    result = trace({"entry.py": (
        "import subprocess\n\ndef entry(request):\n"
        "    value = request.args['value']\n    " + body + "\n"
    )})
    assert result["status"] == "UNRESOLVED"
    assert result["flow_status"] == expected, result
