import json
from pathlib import Path

from cv_agent.tools.registry import ToolExecutionScope
from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.analysis.commands import analyze_command, command_status
from cv_agent.harness import RetrievalBudget, RetrievalMode
from cv_agent.retrieval import RepositoryIndex
from cv_agent.domain.types import Candidate, CodeDocument
from test_validation_tools import _invoke, _registry
from cv_agent.evaluation.datasets.advisory_config import PythonHeldoutPairExperimentConfig
from cv_agent.evaluation.datasets.advisory_source import model_visible_analysis_scope


def test_direct_callees_precede_distant_lexical_matches_when_requested():
    entry = CodeDocument(repository_id="r", path="entry.py", text="def entry(): helper()", calls=("helper",))
    helper = CodeDocument(repository_id="r", path="helper.py", text="def helper(): distant()", defines=("helper",), calls=("distant",))
    distant = CodeDocument(repository_id="r", path="distant.py", text="query " * 50, defines=("distant",))
    index = RepositoryIndex([entry, helper, distant])
    candidate = Candidate(candidate_id="c", case_id="c", repository_id="r", path=entry.path, line=1, query="query")
    budget = RetrievalBudget(top_k=1, base_context_tokens=32, augmentation_context_tokens=64, graph_hops=2, graph_ranking="distance")
    evidence = index.retrieve_context(candidate, mode=RetrievalMode.GRAPH, budget=budget)
    assert [item.path for item in evidence] == [entry.path, helper.path]


def test_declared_input_parameter_starts_only_a_may_flow_trace():
    document = CodeDocument(repository_id="r", path="entry.py", text="def entry(value):\n    return eval(value)\n")
    index = RepositoryIndex([document])
    candidate = Candidate(candidate_id="c", case_id="c", repository_id="r", path=document.path, line=1, query="eval", input_parameters=("value",))
    subject = candidate_subject(index, candidate)
    scope = ToolExecutionScope(admitted_paths=frozenset({document.path}), candidate_path=document.path, subject=subject, max_observation_tokens=20000)
    observation = _invoke(_registry(index), "trace_dataflow", {"source_path": document.path}, scope)
    assert json.loads(observation.content)["flow_status"] == "MAY_REACH"
    assert observation.validation_status == "UNRESOLVED"
    assert subject.input_parameters == ("value",)
    unscoped = ToolExecutionScope(admitted_paths=scope.admitted_paths, candidate_path=document.path, max_observation_tokens=20000)
    result = _invoke(_registry(index), "trace_dataflow", {"source_path": document.path}, unscoped)
    assert json.loads(result.content)["flow_status"] == "NOT_ESTABLISHED"


def test_boolean_entry_condition_selects_branch_but_does_not_invent_download_semantics():
    document = CodeDocument(repository_id="r", path="entry.py", text=(
        "def entry(value, enabled):\n"
        "    data = download(value)\n"
        "    command = 'worker ' + shlex.quote(data) if enabled else data\n"
        "    return subprocess.Popen(command, shell=True)\n"
    ))
    assert command_status(analyze_command(document, entry_boolean_arguments={"enabled": True})) == "SANITIZED"
    assert command_status(analyze_command(document, entry_boolean_arguments={"enabled": False})) == "AMBIGUOUS"
    assert command_status(analyze_command(document)) == "AMBIGUOUS"


def test_scope_conditions_are_bound_to_validation_identity():
    document = CodeDocument(repository_id="r", path="entry.py", text="def entry(enabled): return enabled")
    index = RepositoryIndex([document])
    candidate = Candidate(candidate_id="c", case_id="c", repository_id="r", path=document.path, line=1, query="q")
    original = candidate_subject(index, candidate)
    constrained = candidate_subject(index, candidate.model_copy(update={"entry_boolean_arguments": {"enabled": True}}))
    declared = candidate_subject(index, candidate.model_copy(update={"input_parameters": ("enabled",)}))
    assert original != constrained
    assert original != declared


def test_v4_keeps_gate_cells_and_declares_same_scenario_on_both_revisions():
    root = Path(__file__).resolve().parents[1]
    for stem in ("python_heldout_pair_gate", "python_heldout_pairs"):
        old = PythonHeldoutPairExperimentConfig.model_validate_json((root / f"configs/history/{stem}_v3.json").read_text())
        new = PythonHeldoutPairExperimentConfig.model_validate_json((root / f"configs/history/{stem}_v4.json").read_text())
        assert new.graph_ranking == "distance"
        assert old.selected_cells == new.selected_cells
        assert old.expected_abstentions == new.expected_abstentions
        assert old.limits == new.limits
        for before, after in zip(old.pairs, new.pairs):
            assert before.cases == after.cases
            if after.pair_id.startswith("hp003_"):
                assert "enable_mlserver=True" in before.vulnerability_title
                assert after.entry_boolean_arguments == {"enable_mlserver": True}
                assert after.input_parameters == ("model_uri",)
                visible = model_visible_analysis_scope(after)
                assert '"enable_mlserver": true' in visible
                assert "CVE-" not in visible and "vulnerable" not in visible
