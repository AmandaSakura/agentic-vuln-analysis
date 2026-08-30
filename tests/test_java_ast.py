from pathlib import Path

from cv_agent.java_ast import load_java_repository, parse_java_source
from cv_agent.retrieval import RepositoryIndex
from cv_agent.types import Candidate


def test_java_ast_extracts_method_definitions_and_calls():
    source = """
        class Controller {
            void handle(String request) { Service.run(request); }
        }
    """
    result = parse_java_source("repo", "Controller.java", source)
    assert result.has_error is False
    assert len(result.documents) == 1
    document = result.documents[0]
    assert document.defines == ("Controller.handle", "handle")
    assert "Service.run" in document.calls


def test_call_graph_retrieves_cross_file_method(tmp_path: Path):
    (tmp_path / "Controller.java").write_text(
        "class Controller { void handle(String request) { Service.run(request); } }",
        encoding="utf-8",
    )
    (tmp_path / "Service.java").write_text(
        "class Service { static void run(String value) { Runtime.getRuntime().exec(value); } }",
        encoding="utf-8",
    )
    documents, errors = load_java_repository("repo", tmp_path)
    assert errors == []
    controller = next(document for document in documents if "Controller.handle" in document.defines)
    candidate = Candidate(
        candidate_id="controller-entry",
        case_id="controller-entry",
        repository_id="repo",
        path=controller.path,
        line=1,
        query="request handler",
    )
    evidence = RepositoryIndex(documents).graph_search(candidate)
    assert any("Service.run" in document.defines and f"graph:{document.path}" in {item.evidence_id for item in evidence} for document in documents)


def test_java_parser_reports_syntax_errors_without_dropping_valid_methods():
    result = parse_java_source("repo", "Broken.java", "class Broken { void ok() {} void nope( }")
    assert result.has_error is True
    assert any("Broken.ok" in document.defines for document in result.documents)
