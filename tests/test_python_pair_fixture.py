import json

import pytest

from cv_agent.tools.registry import ToolExecutionScope
from cv_agent.tools.identity import candidate_subject
from cv_agent.harness import AgentSystemVersion, FULL_SYSTEM_HARNESS
from cv_agent.evaluation.datasets.python_pair_config import PythonPair, PythonPairCase
from cv_agent.evaluation.datasets.python_pair_fixture import PythonPairFixtureInput, build_pair_input, fixture_validation_status, pair_fixture_tool


def pair_and_case():
    pair = PythonPair.model_validate({
        "pair_id": "langchain_template_traversal",
        "fixture_id": "template_traversal",
        "repository_url": "https://github.com/example/project",
        "advisory": "GHSA-example",
        "cve": "CVE-2099-0001",
        "source_root": "pkg",
        "exclude_path_parts": ["tests", "__pycache__"],
        "entry_symbol": "Entry.entry",
        "source_scope": "example traversal only",
        "analysis_scope": "Assess only example traversal.",
        "cases": [
            {
                "case_id": "example_vulnerable",
                "revision_role": "vulnerable",
                "commit": "a" * 40,
                "checkout": "checkout",
                "file_path": "pkg/a.py",
                "line_hint": 2,
            },
            {
                "case_id": "example_fixed",
                "revision_role": "fixed",
                "commit": "b" * 40,
                "checkout": "checkout",
                "file_path": "pkg/a.py",
                "line_hint": 2,
            },
        ],
    })
    return pair, PythonPairCase.model_validate(pair.cases[0].model_dump())


def write_package(tmp_path):
    checkout = tmp_path / "checkout"
    (checkout / "pkg").mkdir(parents=True)
    (checkout / "pkg/a.py").write_text(
        "from pkg.b import helper\n\nclass Entry:\n    def entry(self, value):\n        return helper(value)\n"
    )
    (checkout / "pkg/b.py").write_text("def helper(value):\n    return value\n")
    (checkout / "pkg/tests").mkdir()
    (checkout / "pkg/tests/test_a.py").write_text("def helper(value):\n    return 'test'\n")
    return checkout


def langchain_observations():
    return {
        "benign": {"status": "BENIGN_OK", "success": True, "output": "Hello World"},
        "attribute_access": {"status": "EXPLOITED", "leaked_secret": True},
        "dunder_access": {"status": "EXPLOITED", "leaked_dunder": True},
    }


def test_full_package_index_binds_fixture_to_candidate_and_source(monkeypatch, tmp_path):
    checkout = write_package(tmp_path)
    pair, case = pair_and_case()
    monkeypatch.setattr("cv_agent.evaluation.datasets.python_pair_fixture.require_clean_checkout", lambda checkout, commit: None)
    index, candidate, source_hashes = build_pair_input(tmp_path, pair, case)
    assert "pkg/b.py" in json.dumps(sorted(index.documents))
    assert "pkg/tests/test_a.py" not in json.dumps(sorted(index.documents))
    neighbors = index.graph_neighbors(candidate.path, direction="forward")
    assert any("pkg/b.py::helper" in path for path in neighbors)
    assert source_hashes["pkg/a.py"]
    tool = pair_fixture_tool(tmp_path, pair, case, index, candidate, langchain_observations())
    subject = candidate_subject(index, candidate)
    scope = ToolExecutionScope(frozenset(index.documents), 4096, candidate_path=candidate.path, subject=subject)
    result = tool.handler(PythonPairFixtureInput(fixture_id="template_traversal"), scope)
    assert result.validation_status == "CONFIRMED"
    assert json.loads(result.content)["observations"]["benign"]["status"] == "BENIGN_OK"
    assert "a" * 40 not in candidate.model_dump_json()
    assert str(tmp_path) not in candidate.model_dump_json()
    changed = subject.model_copy(update={"candidate_id": "other"})
    scope = ToolExecutionScope(frozenset(index.documents), 4096, candidate_path=candidate.path, subject=changed)
    assert tool.handler(PythonPairFixtureInput(fixture_id="template_traversal"), scope).status == "blocked"
    (checkout / "pkg/a.py").write_text((checkout / "pkg/a.py").read_text() + "# changed\n")
    scope = ToolExecutionScope(frozenset(index.documents), 4096, candidate_path=candidate.path, subject=subject)
    with pytest.raises(ValueError, match="Source changed"):
        tool.handler(PythonPairFixtureInput(fixture_id="template_traversal"), scope)


def test_fixture_status_is_derived_from_strict_probe_invariants():
    assert fixture_validation_status(
        "langchain_template_traversal", "vulnerable", langchain_observations()
    ) == "CONFIRMED"
    arbitrary_error = {
        "benign": {"status": "BENIGN_OK"},
        "attribute_access": {"status": "BLOCKED", "error_type": "RuntimeError", "error_message": "anything"},
        "dunder_access": {"status": "BLOCKED", "error_type": "RuntimeError", "error_message": "anything"},
    }
    with pytest.raises(ValueError, match="invariants"):
        fixture_validation_status("langchain_template_traversal", "fixed", arbitrary_error)


def test_unknown_fixture_id_is_rejected(monkeypatch, tmp_path):
    write_package(tmp_path)
    pair, case = pair_and_case()
    monkeypatch.setattr("cv_agent.evaluation.datasets.python_pair_fixture.require_clean_checkout", lambda checkout, commit: None)
    index, candidate, _ = build_pair_input(tmp_path, pair, case)
    tool = pair_fixture_tool(tmp_path, pair, case, index, candidate, langchain_observations())
    subject = candidate_subject(index, candidate)
    scope = ToolExecutionScope(frozenset(index.documents), 4096, candidate_path=candidate.path, subject=subject)
    with pytest.raises(ValueError, match="Fixture id"):
        tool.handler(PythonPairFixtureInput(fixture_id="wrong_fixture"), scope)


def test_e2_and_e3_share_the_same_index_document_set(tmp_path):
    write_package(tmp_path)
    pair, case = pair_and_case()
    index, candidate, _ = build_pair_input(tmp_path, pair, case)
    e2 = FULL_SYSTEM_HARNESS.system_spec(AgentSystemVersion.E2_TEXT_SINGLE)
    e3 = FULL_SYSTEM_HARNESS.system_spec(AgentSystemVersion.E3_GRAPH_SINGLE)
    e2_paths = {item.path for item in index.retrieve_context(candidate, mode=e2.retrieval, budget=e2.budget)}
    e3_paths = {item.path for item in index.retrieve_context(candidate, mode=e3.retrieval, budget=e3.budget)}
    assert candidate.path in e2_paths
    assert candidate.path in e3_paths
    assert any("pkg/b.py::helper" in path for path in e3_paths)
