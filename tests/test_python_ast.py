from pathlib import Path

from cv_agent.python_ast import load_python_repository
from cv_agent.retrieval import RepositoryIndex
from cv_agent.types import Candidate


def test_python_ast_call_graph_retrieves_imported_function(tmp_path: Path):
    (tmp_path / "controller.py").write_text(
        "from service import run\n\ndef entry(request):\n    return run(request)\n",
        encoding="utf-8",
    )
    (tmp_path / "service.py").write_text(
        "def run(value):\n    return eval(value)\n",
        encoding="utf-8",
    )

    repository = load_python_repository("repo", tmp_path)
    assert repository.parse_error_paths == ()
    entry = repository.locate("controller.py", 3)
    target = repository.locate("service.py", 1)
    assert entry is not None
    assert target is not None
    assert "service.run" in entry.document.calls
    assert "service.run" in target.document.defines

    candidate = Candidate(
        candidate_id="entry",
        case_id="entry",
        repository_id="repo",
        path=entry.document.path,
        line=3,
        query=" ".join([*entry.document.defines, *entry.document.calls]),
    )
    local = RepositoryIndex(repository.documents).local(candidate)
    graph = RepositoryIndex(repository.documents).graph_search(candidate, top_k=8, max_hops=4)
    assert all(item.path != target.document.path for item in local)
    assert any(item.path == target.document.path for item in graph)


def test_python_ast_resolves_typed_self_field_to_concrete_override(tmp_path: Path):
    (tmp_path / "base_loader.py").write_text(
        """
class BaseLoader:
    def load(self, name):
        raise NotImplementedError
""",
        encoding="utf-8",
    )
    (tmp_path / "loader.py").write_text(
        """
from base_loader import BaseLoader

class Loader(BaseLoader):
    def load(self, name):
        return critical(name)

def critical(value):
    return eval(value)
""",
        encoding="utf-8",
    )
    (tmp_path / "web.py").write_text(
        """
from base_loader import BaseLoader

class Web:
    def __init__(self, loader: BaseLoader):
        self.loader = loader

    def entry(self, name):
        return self.loader.load(name)
""",
        encoding="utf-8",
    )

    repository = load_python_repository("repo", tmp_path)
    entry = repository.locate("web.py", 8)
    concrete = repository.locate("loader.py", 5)
    critical = repository.locate("loader.py", 8)
    assert entry is not None
    assert concrete is not None
    assert critical is not None
    assert "BaseLoader.load" in entry.document.calls
    assert "Web.load" not in entry.document.calls
    assert "BaseLoader.load" in concrete.document.defines

    candidate = Candidate(
        candidate_id="entry",
        case_id="entry",
        repository_id="repo",
        path=entry.document.path,
        line=8,
        query=" ".join([*entry.document.defines, *entry.document.calls]),
    )
    graph = RepositoryIndex(repository.documents).graph_search(
        candidate,
        top_k=8,
        max_hops=4,
    )
    paths = {item.path for item in graph}
    assert concrete.document.path in paths
    assert critical.document.path in paths


def test_python_span_locator_prefers_nested_function(tmp_path: Path):
    (tmp_path / "nested.py").write_text(
        "def outer():\n    def inner():\n        return 1\n    return inner()\n",
        encoding="utf-8",
    )
    repository = load_python_repository("repo", tmp_path)
    located = repository.locate("nested.py", 3)
    assert located is not None
    assert "inner" in located.document.defines


def test_python_span_includes_decorator_lines(tmp_path: Path):
    (tmp_path / "api.py").write_text(
        '@router.get("/items")\nasync def list_items():\n    return []\n',
        encoding="utf-8",
    )
    repository = load_python_repository("repo", tmp_path)
    located = repository.locate("api.py", 1)
    assert located is not None
    assert located.start_line == 1
    assert "list_items" in located.document.defines
    assert located.document.text.startswith("@router.get")
