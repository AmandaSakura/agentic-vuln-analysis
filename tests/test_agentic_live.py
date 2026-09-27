from pathlib import Path

import pytest

from cv_agent.evaluation.datasets.owasp_live import load_owasp_agentic_inputs, run_agentic_owasp_live
from cv_agent.harness import FULL_SYSTEM_HARNESS


def _write_owasp_fixture(raw_root: Path) -> None:
    benchmark_root = raw_root / "BenchmarkJava"
    source_root = (
        benchmark_root
        / "src"
        / "main"
        / "java"
        / "org"
        / "owasp"
        / "benchmark"
        / "testcode"
    )
    source_root.mkdir(parents=True)
    (benchmark_root / "expectedresults-1.2beta.csv").write_text(
        "# test name, category, real vulnerability, cwe\n"
        "BenchmarkTest00001,cmdi,true,78\n",
        encoding="utf-8",
    )
    (source_root / "BenchmarkTest00001.java").write_text(
        """
        package org.owasp.benchmark.testcode;

        public class BenchmarkTest00001 {
            public void doGet(Object request, Object response) {
                doPost(request, response);
            }

            public void doPost(Object request, Object response) throws Exception {
                Runtime.getRuntime().exec("echo ok");
            }
        }
        """,
        encoding="utf-8",
    )


def test_owasp_agentic_loader_keeps_truth_out_of_candidate(tmp_path: Path):
    _write_owasp_fixture(tmp_path)

    inputs = load_owasp_agentic_inputs(
        tmp_path,
        case_ids=("BenchmarkTest00001",),
    )

    candidate = inputs.candidates[0]
    assert candidate.case_id == "BenchmarkTest00001"
    assert "BenchmarkTest00001.doGet" in candidate.path
    assert candidate.metadata == {}
    assert "true" not in candidate.query.casefold()
    assert inputs.labels["BenchmarkTest00001"].vulnerable is True


def test_owasp_agentic_loader_rejects_duplicate_cases(tmp_path: Path):
    _write_owasp_fixture(tmp_path)

    with pytest.raises(ValueError, match="duplicate OWASP case id"):
        load_owasp_agentic_inputs(
            tmp_path,
            case_ids=("BenchmarkTest00001", "BenchmarkTest00001"),
        )


def test_live_owasp_runner_requires_model_environment_before_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    _write_owasp_fixture(tmp_path)
    monkeypatch.delenv(FULL_SYSTEM_HARNESS.model.base_url_env, raising=False)
    monkeypatch.delenv(FULL_SYSTEM_HARNESS.model.model_env, raising=False)
    monkeypatch.delenv(FULL_SYSTEM_HARNESS.model.api_key_env, raising=False)

    with pytest.raises(ValueError, match="live model environment is incomplete"):
        run_agentic_owasp_live(
            tmp_path,
            case_ids=("BenchmarkTest00001",),
            system_ids=("E1",),
            property_id="command-execution",
        )


def test_owasp_declared_property_is_independent_of_all_evaluator_labels(tmp_path):
    from cv_agent.tools.identity import candidate_subject
    from cv_agent.evaluation.datasets.owasp_live import select_owasp_entry
    _write_owasp_fixture(tmp_path)
    properties = {'BenchmarkTest00001': 'command-execution'}
    first = load_owasp_agentic_inputs(tmp_path, case_ids=tuple(properties), property_ids=properties)
    labels = tmp_path / 'BenchmarkJava/expectedresults-1.2beta.csv'
    labels.write_text('# test name, category, real vulnerability, cwe\nBenchmarkTest00001,xss,false,79\n')
    second = load_owasp_agentic_inputs(tmp_path, case_ids=tuple(properties), property_ids=properties)
    assert first.candidates == second.candidates
    assert first.labels != second.labels
    # Check the actual model-facing packets as well as the candidate objects.
    import json
    from cv_agent.agents.workflow import AgenticPipeline
    from cv_agent.domain.chat import ModelReply, ModelToolCall
    from cv_agent.harness import AgentSystemVersion
    from cv_agent.runtime.model import ScriptedChatModel
    from cv_agent.tools.registry import ToolRegistry
    from cv_agent.tools.validation import full_agent_tools
    packets = []
    for inputs in (first, second):
        candidate = inputs.candidates[0]
        model = ScriptedChatModel([
            ModelReply(model_id='offline', tool_calls=(ModelToolCall(
                call_id='read', name='read_span', arguments={'path': candidate.path}),)),
            ModelReply(model_id='offline', content=json.dumps(dict(
                expert='scan', label='ABSTAIN', confidence=.5, validation_status='UNRESOLVED',
                evidence_ids=['scan/tool:1'], rationale='Source alone does not prove the property.'))),
        ])
        verdict = AgenticPipeline(index=inputs.index, system=AgentSystemVersion.E1_LOCAL_SINGLE,
            models={'scan': model}, tools=ToolRegistry(full_agent_tools(inputs.index), max_output_bytes=8192)).run(candidate)
        assert verdict.label == 'ABSTAIN'
        packets.append(model.requests)
    assert packets[0] == packets[1]
    for candidate in (*first.candidates, *select_owasp_entry(first, 'doPost')):
        assert candidate.property_id == 'command-execution'
        assert candidate_subject(first.index, candidate).property_id == 'command-execution'


@pytest.mark.parametrize('properties', [{}, {'BenchmarkTest00001': ''}, {'BenchmarkTest00001': '  '}, {'wrong-case': 'command-execution'}])
def test_owasp_incomplete_property_declaration_is_rejected(tmp_path, properties):
    with pytest.raises(ValueError, match='property'):
        load_owasp_agentic_inputs(tmp_path, case_ids=('BenchmarkTest00001',), property_ids=properties)


def test_reviewed_development_properties_are_separate_from_truth(tmp_path):
    import json
    from cv_agent.evaluation.datasets.owasp_live import development_owasp_properties
    folder = tmp_path / 'configs/datasets'
    folder.mkdir(parents=True)
    path = folder / 'owasp_properties.json'
    path.write_text(json.dumps({'example': 'command-execution'}))
    assert development_owasp_properties(tmp_path, ['example']) == {'example': 'command-execution'}
    with pytest.raises(ValueError, match='Missing OWASP property'):
        development_owasp_properties(tmp_path, ['missing'])
    path.write_text(json.dumps({'example': None}))
    with pytest.raises(ValueError, match='Invalid OWASP property'):
        development_owasp_properties(tmp_path, ['example'])


def test_cli_requires_an_explicit_owasp_property():
    from cv_agent.cli import build_parser
    args = ['agentic-live-owasp', '--case-id', 'BenchmarkTest00001', '--system', 'E1']
    with pytest.raises(SystemExit):
        build_parser().parse_args(args)
    assert build_parser().parse_args(args + ['--property-id', 'command-execution']).property_id == 'command-execution'


def test_development_property_declarations_cover_the_unchanged_case_population():
    import json
    from cv_agent.evaluation.datasets.owasp_live import development_owasp_properties
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / 'configs/datasets/development_manifest.json').read_text())
    declared = development_owasp_properties(root, manifest['case_ids'])
    assert set(declared) == set(manifest['case_ids'])
    assert len(declared) == 66
    assert set(declared.values()) == {
        'command-execution', 'unsafe-cryptography', 'weak-hash', 'ldap-injection',
        'path-traversal', 'insecure-cookie', 'sql-injection', 'trust-boundary',
        'weak-randomness', 'xpath-injection', 'cross-site-scripting',
    }
