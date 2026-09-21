import importlib.util
import json
from pathlib import Path
import sys

import pytest

from cv_agent.agent_types import ChatMessage, ModelReply, ModelToolCall
from cv_agent.agent_tools import ToolExecutionScope
from cv_agent.harness import AgentRuntimeMode
from cv_agent.model_runtime import OpenAICompatibleChatModel, trusted_runtime_mode


spec = importlib.util.spec_from_file_location(
    "micro_benchmark", Path(__file__).parents[1] / "scripts/run_micro_benchmark.py")
bench = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = bench
spec.loader.exec_module(bench)


@pytest.fixture
def journal(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTIGRAVITY_API_KEY", "test-credential-not-for-network")
    return bench.Journal(tmp_path / "events.jsonl")


def events(journal):
    return [json.loads(line) for line in journal.path.read_text().splitlines()]


def test_timeout_is_durable_failure_and_attempt_is_counted(journal, monkeypatch):
    def timeout(*args):
        raise TimeoutError("offline timeout")
    monkeypatch.setattr(OpenAICompatibleChatModel, "_complete", timeout)
    result = bench.run_trial(bench.BENCHMARK_CASES[0], "baseline", None, journal)
    assert result["status"] == "failed"
    assert result["error_type"] == "TimeoutError"
    assert result["model_calls"] == 1
    assert result["tool_calls"] == 0
    assert [event["event"] for event in events(journal)] == [
        "trial_start", "model_start", "model_error", "trial_result"]
    assert events(journal)[-1]["result"] == result


@pytest.mark.parametrize("content", [
    "not json", '[]', '{"label":"SAFE"}',
    '{"label":"OTHER","confidence":0.9,"rationale":"x"}',
    '{"label":"SAFE","confidence":NaN,"rationale":"x"}',
    '{"label":"SAFE","confidence":2,"rationale":"x"}',
    '{"label":"SAFE","confidence":true,"rationale":"x"}',
])
def test_invalid_output_is_failure_with_raw_reply(journal, monkeypatch, content):
    monkeypatch.setattr(OpenAICompatibleChatModel, "_complete", lambda *args:
                        ModelReply(model_id="offline-test", content=content))
    result = bench.run_trial(bench.BENCHMARK_CASES[0], "baseline", None, journal)
    assert result["status"] == "failed"
    assert result["error_type"] == "InvalidBaselineOutput"
    assert result["model_calls"] == 1
    assert events(journal)[2]["reply"]["content"] == content


def test_success_and_abstention_are_distinct(journal, monkeypatch):
    for label, expected in [("VULNERABLE", "completed"), ("UNRESOLVED", "abstained")]:
        monkeypatch.setattr(OpenAICompatibleChatModel, "_complete", lambda *args:
            ModelReply(model_id="offline-test", content=json.dumps(
                {"label": label, "confidence": 0.5, "rationale": "observed"})))
        result = bench.run_trial(bench.BENCHMARK_CASES[0], "baseline", None, journal)
        assert result["status"] == expected
        assert result["is_correct"] == (label == "VULNERABLE")
    assert "test-credential-not-for-network" not in journal.path.read_text()


def test_instrumented_model_retains_trusted_runtime(journal):
    model = bench.get_live_model(bench.Trial("C01", "E1", journal), "scan")
    assert trusted_runtime_mode(model) == AgentRuntimeMode.LIVE


def test_partial_agent_failure_preserves_actual_calls_and_tool_evidence(journal, monkeypatch):
    monkeypatch.setattr(OpenAICompatibleChatModel, "_complete", lambda *args:
                        ModelReply(model_id="offline-test", content="reply"))

    def fail_after_work(self, candidate):
        model = self.models["scan"]
        model.complete([ChatMessage(role="user", content="first")], [])
        model.complete([ChatMessage(role="user", content="second")], [])
        self.tools.invoke(
            ModelToolCall(call_id="call1", name="read_span", arguments={"path": candidate.path}),
            allowed=["read_span"],
            scope=ToolExecutionScope(frozenset([candidate.path]), 10000))
        raise RuntimeError("failure after work")

    monkeypatch.setattr(bench.AgenticPipeline, "run", fail_after_work)
    result = bench.run_trial(bench.BENCHMARK_CASES[0], "E1",
                            bench.AgentSystemVersion.E1_LOCAL_SINGLE, journal)
    assert result["status"] == "failed"
    assert result["model_calls"] == 2
    assert result["tool_calls"] == 1
    assert any(event["event"] == "tool_result" and event["observation"]["content"]
               for event in events(journal))


def test_agent_verdict_is_not_reduced_to_vote_summary(journal, monkeypatch):
    from cv_agent.agent_types import AgenticVerdict, ModelUsage
    verdict = AgenticVerdict(
        runtime_mode="scripted", label="VULNERABLE", confidence=0.9,
        path="single", rationale="test evidence", votes=(), model_calls=1, tool_calls=1,
        usage=ModelUsage(total_tokens=123), retrieval_context_token_count=10,
        tool_observation_token_count=5, context_token_count=15)
    monkeypatch.setattr(bench.AgenticPipeline, "run", lambda *args: verdict)
    result = bench.run_trial(bench.BENCHMARK_CASES[0], "E1",
                            bench.AgentSystemVersion.E1_LOCAL_SINGLE, journal)
    assert result["status"] == "completed"
    assert result["predicted_label"] == "VULNERABLE"
    assert result["verdict"] == verdict.model_dump(mode="json")
    assert events(journal)[-1]["result"]["verdict"] == result["verdict"]


def test_interrupt_preserves_partial_result_and_propagates(journal, monkeypatch):
    def interrupt(*args):
        raise KeyboardInterrupt()
    monkeypatch.setattr(OpenAICompatibleChatModel, "_complete", interrupt)
    with pytest.raises(KeyboardInterrupt):
        bench.run_trial(bench.BENCHMARK_CASES[0], "baseline", None, journal)
    result = events(journal)[-1]["result"]
    assert result["status"] == "interrupted"
    assert result["model_calls"] == 1


def test_main_continues_after_failure_and_checkpoints_before_next_trial(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTIGRAVITY_API_KEY", "offline")
    monkeypatch.setattr(bench, "project_root", tmp_path)
    monkeypatch.setattr(bench, "__file__", str(tmp_path / "script.py"))
    (tmp_path / "script.py").write_text("offline test")
    monkeypatch.setattr(bench, "BENCHMARK_CASES", bench.BENCHMARK_CASES[:2])
    monkeypatch.setattr(bench, "SYSTEMS", [("baseline", None)])
    calls = []

    def complete(*args):
        calls.append(1)
        if len(calls) == 1:
            raise TimeoutError("first trial failed")
        saved = list((tmp_path / "artifacts").glob("micro_benchmark/*/results.json"))
        assert len(saved) == 1
        assert json.loads(saved[0].read_text())[0]["status"] == "failed"
        return ModelReply(model_id="offline-test", content=
                          '{"label":"SAFE","confidence":0.8,"rationale":"constant"}')

    monkeypatch.setattr(OpenAICompatibleChatModel, "_complete", complete)
    bench.main()
    saved = next((tmp_path / "artifacts").glob("micro_benchmark/*/results.json"))
    assert [row["status"] for row in json.loads(saved.read_text())] == ["failed", "completed"]


def test_all_failure_report_has_no_predetermined_success(journal, monkeypatch):
    def timeout(*args):
        raise TimeoutError("offline timeout")
    monkeypatch.setattr(OpenAICompatibleChatModel, "_complete", timeout)
    bench.run_trial(bench.BENCHMARK_CASES[0], "baseline", None, journal)
    bench.save_summary(journal.path.parent, {
        "started_at": "test-time", "config": {"model": "offline-test"}, "expected_trials": 24})
    report = (journal.path.parent / "report.md").read_text()
    assert "1/24" in report
    assert "| baseline | 0/1 | 0 | 0 | 0 | 1 | 0 | 1.00" in report
    for unsupported in ["成功避免", "显著节省", "展现了图检索", "均独立给出了"]:
        assert unsupported not in report
