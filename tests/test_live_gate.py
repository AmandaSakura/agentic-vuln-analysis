from pathlib import Path
from types import SimpleNamespace

import pytest


def test_concurrent_first_callers_share_one_in_progress_test_run(gate, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    started, release, second_started = Event(), Event(), Event()
    calls = []
    def run(*args, **kwargs):
        calls.append(1)
        started.set()
        assert release.wait(2)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(gate.subprocess, 'run', run)
    def second():
        second_started.set()
        gate.require_passing_tests()
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(gate.require_passing_tests)
        assert started.wait(2)
        other = pool.submit(second)
        assert second_started.wait(2)
        release.set()
        first.result()
        other.result()
    assert calls == [1]


@pytest.fixture
def gate(tmp_path, monkeypatch):
    from cv_agent import live_gate
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src/code.py").write_text("value = 1\n")
    (tmp_path / "tests/test_code.py").write_text("def test_value(): pass\n")
    monkeypatch.setattr(live_gate, "PROJECT_ROOT", tmp_path)
    monkeypatch.setattr(live_gate, "_approved_fingerprint", None)
    monkeypatch.setattr(live_gate, "_attempted", False)
    monkeypatch.setattr(live_gate, "_loaded_fingerprint", live_gate.source_fingerprint(tmp_path))
    return live_gate


def test_failed_pytest_blocks_admission(gate, monkeypatch):
    calls = []
    def failed(*args, **kwargs):
        calls.append(1)
        return SimpleNamespace(returncode=1)
    monkeypatch.setattr(gate.subprocess, "run", failed)
    with pytest.raises(RuntimeError, match="pytest"):
        gate.require_passing_tests()
    assert gate._approved_fingerprint is None
    with pytest.raises(RuntimeError, match="pytest"):
        gate.require_passing_tests()
    assert len(calls) == 1


def test_success_is_reused_only_in_unchanged_process(gate, monkeypatch):
    calls = []
    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(gate.subprocess, "run", run)
    monkeypatch.setenv("PYTEST_ADDOPTS", "-k does_not_exist")
    gate.require_passing_tests()
    gate.require_passing_tests()
    assert len(calls) == 1
    assert calls[0][0] == ["uv", "run", "--no-sync", "pytest"]
    assert "PYTEST_ADDOPTS" not in calls[0][1]["env"]
    (gate.PROJECT_ROOT / "src/code.py").write_text("value = 2\n")
    with pytest.raises(RuntimeError, match="changed"):
        gate.require_passing_tests()
    assert len(calls) == 1


def test_edit_during_pytest_invalidates_pass(gate, monkeypatch):
    def run(*args, **kwargs):
        (gate.PROJECT_ROOT / "tests/new_test.py").write_text("def test_new(): pass\n")
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(gate.subprocess, "run", run)
    with pytest.raises(RuntimeError, match="changed"):
        gate.require_passing_tests()
    assert gate._approved_fingerprint is None


def test_config_addition_deletion_and_content_changes_invalidate_identity(gate):
    original = gate.source_fingerprint(gate.PROJECT_ROOT)
    config = gate.PROJECT_ROOT / "configs"
    config.mkdir()
    file = config / "run.json"
    file.write_text('{"requests": 1}')
    added = gate.source_fingerprint(gate.PROJECT_ROOT)
    assert added != original
    file.write_text('{"requests": 2}')
    assert gate.source_fingerprint(gate.PROJECT_ROOT) != added
    file.unlink()
    assert gate.source_fingerprint(gate.PROJECT_ROOT) == original


def test_validation_harness_changes_invalidate_identity(gate):
    original = gate.source_fingerprint(gate.PROJECT_ROOT)
    harness = gate.PROJECT_ROOT / "validation" / "java-command-harness"
    harness.mkdir(parents=True)
    source = harness / "exec_recorder.c"
    source.write_text("int value = 1;\n")
    changed = gate.source_fingerprint(gate.PROJECT_ROOT)
    assert changed != original
    source.write_text("int value = 2;\n")
    assert gate.source_fingerprint(gate.PROJECT_ROOT) != changed
    source.unlink()
    assert gate.source_fingerprint(gate.PROJECT_ROOT) == original


def test_gate_rejection_happens_before_model_start_or_http(monkeypatch):
    from cv_agent import model_runtime
    events = []
    def reject():
        raise RuntimeError("pytest failed")
    monkeypatch.setattr(model_runtime, "require_passing_tests", reject, raising=False)
    model = model_runtime.OpenAICompatibleChatModel(base_url="http://localhost/v1", model="offline",
        api_key=None, temperature=0, timeout_seconds=1, observer=events.append)
    with pytest.raises(RuntimeError, match="pytest failed"):
        model.complete([], [])
    assert events == []


def test_no_experiment_script_implements_an_ungated_model_http_transport():
    import ast
    root = Path(__file__).parents[1]
    for path in (root / "scripts").glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert ast.unparse(node.func) not in {
                    "urllib.request.urlopen", "requests.post", "httpx.post",
                }, f"Use the gated model runtime instead: {path.name}:{node.lineno}"


def test_suite_default_http_transport_cannot_reach_proxy():
    import urllib.request
    with pytest.raises(AssertionError, match="pytest forbids"):
        urllib.request.urlopen("http://127.0.0.1:8317/v1/chat/completions")


def test_pytest_timeout_does_not_grant_approval(gate, monkeypatch):
    def timeout(*args, **kwargs):
        raise gate.subprocess.TimeoutExpired(args[0], 300)
    monkeypatch.setattr(gate.subprocess, "run", timeout)
    with pytest.raises(gate.subprocess.TimeoutExpired):
        gate.require_passing_tests()
    assert gate._approved_fingerprint is None


def test_gate_isolates_provider_selection_without_changing_parent(gate, monkeypatch):
    import os
    names = {'CV_AGENT_PROVIDER': 'deepseek', 'DEEPSEEK_MODEL': 'offline-model',
             'GEMINI_MODEL': 'offline-proxy', 'DEEPSEEK_API_KEY': 'fake-secret'}
    for name, value in names.items():
        monkeypatch.setenv(name, value)
    def run(command, **kwargs):
        assert not set(names).intersection(kwargs['env'])
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(gate.subprocess, 'run', run)
    gate.require_passing_tests()
    assert all(os.environ[name] == value for name, value in names.items())
