import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace


ROOT = Path(__file__).parents[1]


def test_runtime_import_does_not_read_experiment_configuration(tmp_path):
    code = """
import importlib
from pathlib import Path
import sys
sys.path.insert(0, sys.argv[1])
original = Path.read_text
def guarded_read(path, *args, **kwargs):
    if 'configs' in path.parts or path.name.startswith('.env'):
        raise AssertionError('runtime imported experiment configuration')
    return original(path, *args, **kwargs)
Path.read_text = guarded_read
for name in ('cv_agent.runtime.journal', 'cv_agent.runtime.budget',
             'cv_agent.evaluation.execution', 'cv_agent.runtime.snapshots'):
    importlib.import_module(name)
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(ROOT / "src")],
        cwd=tmp_path,
        env={"PATH": os.environ["PATH"]},
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_source_snapshot_uses_explicit_root_and_preserves_bytes(tmp_path):
    from cv_agent.runtime.snapshots import snapshot_sources

    root = tmp_path / "subject"
    (root / "src").mkdir(parents=True)
    (root / "configs").mkdir()
    sources = {
        "src/example.py": b"value = '\xc3\xa9'\r\n",
        "configs/model.json": b'{"model": "offline"}\n',
    }
    for relative, content in sources.items():
        (root / relative).write_bytes(content)
    (root / ".env.experiments").write_text("not a source file")
    output = tmp_path / "run"

    hashes = snapshot_sources(root, output)

    assert hashes == {
        relative: hashlib.sha256(content).hexdigest()
        for relative, content in sources.items()
    }
    for relative, content in sources.items():
        assert (output / "source" / relative).read_bytes() == content
    assert not (output / "source/.env.experiments").exists()


def test_candidate_execution_uses_explicit_model_and_retrieval_settings(tmp_path, monkeypatch):
    from cv_agent.domain.review import AgenticVerdict
    from cv_agent.domain.chat import ModelUsage
    from cv_agent.harness import AgentSystemVersion
    from cv_agent.evaluation import execution
    from cv_agent.runtime.budget import Budget
    from cv_agent.runtime.journal import Journal

    monkeypatch.delenv("ANTIGRAVITY_API_KEY", raising=False)
    candidate = SimpleNamespace(case_id="one")
    index = object()
    model_arguments = []
    pipeline_arguments = []
    verdict = AgenticVerdict(
        runtime_mode="scripted", label="ABSTAIN", confidence=0.2,
        path="single", rationale="Insufficient evidence", votes=(),
        model_calls=1, tool_calls=1, usage=ModelUsage(),
        retrieval_context_token_count=0, tool_observation_token_count=0,
        context_token_count=0,
    )

    def model(**kwargs):
        model_arguments.append(kwargs)
        return SimpleNamespace(observer=kwargs["observer"])

    class Pipeline:
        def __init__(self, **kwargs):
            pipeline_arguments.append(kwargs)
            self.models = kwargs["models"]

        def run(self, received_candidate):
            assert received_candidate is candidate
            self.models["scan"].observer({"event": "model_start"})
            self.models["scan"].observer({"event": "model_reply"})
            return verdict

    monkeypatch.setattr(execution, "OpenAICompatibleChatModel", model)
    monkeypatch.setattr(execution, "AgenticPipeline", Pipeline)
    journal = Journal(tmp_path / "events.jsonl")
    row = execution.run_candidate(
        index, candidate, AgentSystemVersion.E3_GRAPH_SINGLE,
        journal, Budget(8, 60), model_config={"model": "offline-model"},
        api_key="offline-key", registered_tools=(), report_system="graph-check",
        graph_direction="both", graph_ranking="distance",
    )

    assert model_arguments[0]["model"] == "offline-model"
    assert model_arguments[0]["api_key"] == "offline-key"
    assert pipeline_arguments[0]["index"] is index
    assert pipeline_arguments[0]["graph_direction"] == "both"
    assert pipeline_arguments[0]["graph_ranking"] == "distance"
    assert pipeline_arguments[0]["tools"].names == ()
    assert row["system"] == "graph-check"
    assert row["status"] == "abstained"
    assert row["model_calls"] == 1
    assert row["tool_calls"] == 0
    assert row["verdict"] == verdict.model_dump(mode="json")
    events = [json.loads(line) for line in journal.path.read_text().splitlines()]
    assert [event["event"] for event in events] == [
        "trial_start", "model_start", "model_reply", "trial_result",
    ]
    assert events[-1]["result"] == row
    assert "offline-key" not in journal.path.read_text()


def test_micro_metadata_tracks_execution_code_after_package_extraction(tmp_path, monkeypatch):
    benchmark = importlib.import_module('cv_agent.evaluation.runners.run_micro_benchmark')
    (tmp_path / "configs/models").mkdir(parents=True)
    (tmp_path / "configs/models/micro_benchmark.json").write_text(json.dumps(benchmark.load_default_model_config()))
    execution = tmp_path / "src/cv_agent/evaluation/execution.py"
    execution.parent.mkdir(parents=True)
    execution.write_text("# extracted execution implementation\n")
    monkeypatch.setenv("ANTIGRAVITY_API_KEY", "offline")
    monkeypatch.setattr(benchmark, "project_root", tmp_path)
    monkeypatch.setattr(benchmark, "BENCHMARK_CASES", [])
    monkeypatch.setattr(benchmark, "SYSTEMS", [])

    benchmark.main()

    metadata_path = next((tmp_path / "artifacts/micro_benchmark").glob("*/metadata.json"))
    metadata = json.loads(metadata_path.read_text())
    assert metadata["source_sha256"]["src/cv_agent/evaluation/execution.py"] == (
        hashlib.sha256(execution.read_bytes()).hexdigest()
    )


def test_micro_provenance_records_implementation_without_a_script_wrapper(tmp_path, monkeypatch):
    benchmark = importlib.import_module('cv_agent.evaluation.runners.run_micro_benchmark')
    sources = {
        'src/cv_agent/evaluation/runners/run_micro_benchmark.py': '# canonical runner\n',
        'src/cv_agent/evaluation/execution.py': '# candidate executor\n',
    }
    for relative, content in sources.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    (tmp_path / 'configs/models').mkdir(parents=True)
    (tmp_path / 'configs/models/micro_benchmark.json').write_text('{"model": "offline"}')
    monkeypatch.setenv('ANTIGRAVITY_API_KEY', 'offline')
    monkeypatch.setattr(benchmark, 'project_root', tmp_path)
    monkeypatch.setattr(benchmark, '__file__', str(tmp_path/'src/cv_agent/evaluation/runners/run_micro_benchmark.py'))
    monkeypatch.setattr(benchmark, 'BENCHMARK_CASES', [])
    monkeypatch.setattr(benchmark, 'SYSTEMS', [])

    benchmark.main()

    metadata_path = next((tmp_path/'artifacts/micro_benchmark').glob('*/metadata.json'))
    hashes = json.loads(metadata_path.read_text())['source_sha256']
    assert hashes == {relative: hashlib.sha256(content.encode()).hexdigest()
                      for relative, content in sources.items()}
