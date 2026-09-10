import pytest

from cv_agent.code_adapters import load_code_repository
from cv_agent.java_ast import load_java_repository
from cv_agent.python_ast import load_python_repository, parse_python_source
from cv_agent.retrieval import RepositoryIndex
from cv_agent.source_files import read_source_bytes


@pytest.mark.parametrize("loader,suffix,source", [
    (load_python_repository, ".py", "def marker():\n    return 'outside-marker'\n"),
    (load_code_repository, ".yaml", "key: outside-marker\n"),
    (load_java_repository, ".java", 'class Marker { String value() { return "outside-marker"; } }'),
])
def test_index_does_not_admit_external_file_symlinks(tmp_path, loader, suffix, source):
    subject = tmp_path / "subject"
    subject.mkdir()
    outside = tmp_path / ("outside" + suffix)
    outside.write_text(source)
    linked = subject / ("linked" + suffix)
    linked.symlink_to(outside)
    result = loader("test-repo", subject)
    documents, errors = (
        result if isinstance(result, tuple) else (result.documents, result.parse_error_paths)
    )
    assert not documents
    assert linked.name in errors


def test_source_reader_rejects_symlinked_parent_and_path_traversal(tmp_path):
    subject = tmp_path / "subject"
    subject.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "marker.py").write_text("outside")
    (subject / "linked").symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        read_source_bytes(subject, "linked/marker.py")
    with pytest.raises(ValueError):
        read_source_bytes(subject, "../outside/marker.py")
    (subject / "normal.py").write_text("inside")
    assert read_source_bytes(subject, "normal.py") == b"inside"


@pytest.mark.parametrize("statement,expression", [
    ("import pkg.service", "pkg.service.run_command(value)"),
    ("import pkg.service as svc", "svc.run_command(value)"),
    ("from pkg import service", "service.run_command(value)"),
])
def test_dotted_import_resolves_with_duplicate_bare_function_names(statement, expression):
    files = {
        "entry.py": f"{statement}\n\ndef entry(value):\n    return {expression}\n",
        "pkg/service.py": "def run_command(value):\n    return value\n",
        "other.py": "def run_command(value):\n    return value\n",
    }
    documents = [
        span.document for path, text in files.items()
        for span in parse_python_source("test-repo", path, text)
    ]
    entry = next(doc for doc in documents if doc.path.startswith("entry.py::"))
    index = RepositoryIndex(documents)
    assert index.graph_neighbors(entry.path, direction="forward") == (
        "pkg/service.py::run_command@1-2",
    )
