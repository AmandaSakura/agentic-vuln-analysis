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
    assert {"Controller.handle", "handle"}.issubset(document.defines)
    assert "Controller.handle(String)" in document.defines
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


def test_java_ast_resolves_typed_receiver_without_unique_bare_name_shortcut(
    tmp_path: Path,
):
    (tmp_path / "Controller.java").write_text(
        """
        class Controller {
            void handle() {
                InitialDirContext idc = makeContext();
                idc.search("base", "filter", controls);
            }
        }
        """,
        encoding="utf-8",
    )
    (tmp_path / "LDAPManager.java").write_text(
        "class LDAPManager { void search(String value) {} }",
        encoding="utf-8",
    )
    documents, errors = load_java_repository("repo", tmp_path)
    assert errors == []
    controller = next(
        document for document in documents if "Controller.handle" in document.defines
    )
    assert "InitialDirContext.search" in controller.calls
    assert "search" not in controller.calls

    candidate = Candidate(
        candidate_id="controller-entry",
        case_id="controller-entry",
        repository_id="repo",
        path=controller.path,
        line=1,
        query=controller.text,
    )
    evidence_paths = {
        item.path for item in RepositoryIndex(documents).graph_search(candidate)
    }
    assert not any("LDAPManager.search" in path for path in evidence_paths)


def test_java_ast_resolves_project_helper_from_declared_receiver_type(tmp_path: Path):
    (tmp_path / "Controller.java").write_text(
        """
        class Controller {
            void handle() {
                SeparateClassRequest scr = new SeparateClassRequest(request);
                String value = scr.getTheValue("vector");
            }
        }
        """,
        encoding="utf-8",
    )
    (tmp_path / "SeparateClassRequest.java").write_text(
        'class SeparateClassRequest { String getTheValue(String key) { return "safe"; } }',
        encoding="utf-8",
    )
    documents, errors = load_java_repository("repo", tmp_path)
    assert errors == []
    controller = next(
        document for document in documents if "Controller.handle" in document.defines
    )
    assert "SeparateClassRequest.getTheValue" in controller.calls


def test_java_call_graph_expands_interface_dispatch_to_all_implementations(
    tmp_path: Path,
):
    (tmp_path / "Controller.java").write_text(
        """
        class Controller {
            void handle(ThingInterface thing) {
                String value = thing.doSomething("safe");
            }
        }
        """,
        encoding="utf-8",
    )
    (tmp_path / "ThingInterface.java").write_text(
        "interface ThingInterface { String doSomething(String value); }",
        encoding="utf-8",
    )
    for number in (1, 2):
        (tmp_path / f"Thing{number}.java").write_text(
            f"""
            class Thing{number} implements ThingInterface {{
                public String doSomething(String value) {{ return value; }}
            }}
            """,
            encoding="utf-8",
        )

    documents, errors = load_java_repository("repo", tmp_path)
    assert errors == []
    controller = next(
        document for document in documents if "Controller.handle" in document.defines
    )
    candidate = Candidate(
        candidate_id="controller-entry",
        case_id="controller-entry",
        repository_id="repo",
        path=controller.path,
        line=1,
        query=controller.text,
    )
    evidence_paths = {
        item.path
        for item in RepositoryIndex(documents).graph_search(candidate, top_k=8)
    }

    assert any("Thing1.doSomething" in path for path in evidence_paths)
    assert any("Thing2.doSomething" in path for path in evidence_paths)


def test_java_call_graph_uses_parameter_types_to_select_overload(tmp_path: Path):
    (tmp_path / "Controller.java").write_text(
        """
        class Controller {
            void handle(String value) { Helpers.run(value); }
        }
        """,
        encoding="utf-8",
    )
    (tmp_path / "Helpers.java").write_text(
        """
        class Helpers {
            static String run(String value) { return "string-overload"; }
            static String run(int value) { return "int-overload"; }
        }
        """,
        encoding="utf-8",
    )
    documents, errors = load_java_repository("repo", tmp_path)
    assert errors == []
    controller = next(
        document for document in documents if "Controller.handle" in document.defines
    )
    assert "Helpers.run(String)" in controller.calls
    candidate = Candidate(
        candidate_id="controller-entry",
        case_id="controller-entry",
        repository_id="repo",
        path=controller.path,
        line=1,
        query=controller.text,
    )
    evidence = RepositoryIndex(documents).graph_search(candidate, top_k=8)
    overloads = [item.text for item in evidence if "Helpers.run" in item.path]

    assert len(overloads) == 1
    assert "string-overload" in overloads[0]


def test_java_ast_resolves_method_on_new_object_receiver():
    result = parse_java_source(
        "repo",
        "Controller.java",
        """
        class Controller {
            void handle(String value) { new Helper().run(value); }
        }
        """,
    )
    document = next(
        item for item in result.documents if "Controller.handle" in item.defines
    )

    assert "Helper.run(String)" in document.calls


def test_java_call_graph_qualifies_nested_types_per_outer_class(tmp_path: Path):
    for outer in ("OuterOne", "OuterTwo"):
        (tmp_path / f"{outer}.java").write_text(
            f"""
            class {outer} {{
                String handle(String value) {{ return new Test().doSomething(value); }}
                class Test {{
                    String doSomething(String value) {{ return "{outer}"; }}
                }}
            }}
            """,
            encoding="utf-8",
        )
    documents, errors = load_java_repository("repo", tmp_path)
    assert errors == []
    entry = next(
        document for document in documents if "OuterOne.handle" in document.defines
    )
    assert "OuterOne.Test.doSomething(String)" in entry.calls
    candidate = Candidate(
        candidate_id="entry",
        case_id="entry",
        repository_id="repo",
        path=entry.path,
        line=1,
        query=entry.text,
    )
    evidence = RepositoryIndex(documents).graph_search(candidate, top_k=8)
    nested = [item for item in evidence if ".Test.doSomething" in item.path]

    assert len(nested) == 1
    assert "OuterOne.Test.doSomething" in nested[0].path


def test_java_parser_reports_syntax_errors_without_dropping_valid_methods():
    result = parse_java_source("repo", "Broken.java", "class Broken { void ok() {} void nope( }")
    assert result.has_error is True
    assert any("Broken.ok" in document.defines for document in result.documents)
