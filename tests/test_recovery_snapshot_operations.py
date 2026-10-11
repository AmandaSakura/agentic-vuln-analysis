"""Owned source controls for R03/R04 and the R09 view/cache characterization."""
from dataclasses import FrozenInstanceError
import ast
import hashlib
import importlib
import json

import pytest

from cv_agent.agents.discovery import discover_python_repository
from cv_agent.application.context import ContextAdmissionError, ReadGrant, SourceReadView


def freeze(root, **kwargs):
    return importlib.import_module("cv_agent.application.source_snapshot").freeze_source_snapshot(root, **kwargs)


def operations(snapshot, discovery):
    return importlib.import_module("cv_agent.application.operations").discover_operations(snapshot, discovery)


def discover(root, snapshot):
    return discover_python_repository(root, "owned-source", snapshot=snapshot)


def test_historical_v1_same_line_collapse_is_characterized_not_rewritten(tmp_path):
    (tmp_path / "entry.py").write_text("import os\nos.chmod('first', 0o750); os.chmod('second', 0o777)\n")
    found = discover_python_repository(tmp_path, "owned-source")
    assert len(found.candidates) == 1  # Historic IDs intentionally remain v1.
    assert found.candidates[0].metadata["rule"] == "permission-mode"


def test_same_line_operations_receive_independent_exact_v2_ids(tmp_path):
    text = "import os\nos.chmod('first', 0o750); os.chmod('second', 0o777)\n"
    (tmp_path / "entry.py").write_text(text)
    snapshot = freeze(tmp_path)
    found = discover(tmp_path, snapshot)
    exact = operations(snapshot, found)
    assert len(exact) == 2
    assert len({candidate.candidate_id for candidate in exact}) == 2
    assert [c.metadata["source_snippet"] for c in exact] == ["os.chmod('first', 0o750)", "os.chmod('second', 0o777)"]
    assert all(c.property_id == "chmod-mode-others-write" for c in exact)
    assert all(c.metadata["evidence_kind"] == "static_candidate" for c in exact)
    locators = [c.metadata["operation_locator"] for c in exact]
    assert [locator["start_col_utf8"] for locator in locators] == [0, 26]
    assert all(locator["file_sha256"] == hashlib.sha256(text.encode()).hexdigest() for locator in locators)


@pytest.mark.parametrize("source", [
    "import os\ndef entry():\n    os.chmod('first', 0o750)\n",
    "import os\nclass C:\n    def entry(self):\n        os.chmod('first', 0o750)\n",
    "import os\n@decorate(os.chmod('first', 0o750))\ndef entry():\n    pass\n",
])
def test_module_function_and_decorated_spans_do_not_duplicate_operations(tmp_path, source):
    (tmp_path / "entry.py").write_text(source)
    snapshot = freeze(tmp_path)
    found = discover(tmp_path, snapshot)
    exact = operations(snapshot, found)
    assert len(exact) == 1
    assert "::<module>@" not in exact[0].path
    assert exact[0].metadata["source_snippet"] == "os.chmod('first', 0o750)"


def test_nested_operations_are_distinct_even_when_they_share_a_line(tmp_path):
    (tmp_path / "entry.py").write_text("eval(eval(value))\n")
    snapshot = freeze(tmp_path)
    found = discover(tmp_path, snapshot)
    exact = operations(snapshot, found)
    assert len(exact) == 2
    assert {c.metadata["source_snippet"] for c in exact} == {"eval(value)", "eval(eval(value))"}
    assert len({c.candidate_id for c in exact}) == 2


@pytest.mark.parametrize("encoding,ending", [("utf-8", "\n"), ("latin-1", "\r\n")])
def test_ast_utf8_columns_and_source_snippets_preserve_encoding_tabs_and_newlines(tmp_path, encoding, ending):
    prefix = "中文" if encoding == "utf-8" else "café"
    source = ending.join([f"# coding: {encoding}", "import os", "def entry():", f"\tlabel = '{prefix}'; os.chmod(", "\t\t'owned', 0o750)", ""])
    raw = source.encode(encoding)
    (tmp_path / "entry.py").write_bytes(raw)
    snapshot = freeze(tmp_path)
    sealed = snapshot.files["entry.py"]
    assert sealed.raw == raw and sealed.text == source
    found = discover(tmp_path, snapshot)
    candidate, = operations(snapshot, found)
    locator = candidate.metadata["operation_locator"]
    node = next(n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Call))
    assert (locator["start_line"], locator["end_line"], locator["start_col_utf8"], locator["end_col_utf8"]) == (node.lineno, node.end_lineno, node.col_offset, node.end_col_offset)
    assert locator["start_col_utf8"] == len(f"\tlabel = '{prefix}'; ".encode("utf-8"))
    assert candidate.metadata["source_snippet"] == ast.get_source_segment(source, node)
    assert ending in candidate.metadata["source_snippet"]


def test_snapshot_is_sealed_and_discovery_never_rereads_mutated_source(tmp_path, monkeypatch):
    source = "import os\nos.chmod('owned', 0o750)\n"
    (tmp_path / "entry.py").write_text(source)
    snapshot = freeze(tmp_path)
    (tmp_path / "entry.py").write_text("import os\nos.chmod('owned', 0o777)\n")
    monkeypatch.setattr("cv_agent.agents.discovery.read_source_bytes", lambda *args: pytest.fail("sealed discovery reread live bytes"))
    found = discover(tmp_path, snapshot)
    assert found.report["source_sha256"]["entry.py"] == hashlib.sha256(source.encode()).hexdigest()
    assert all("0o777" not in d.text for d in found.index.documents.values())
    assert operations(snapshot, found)[0].metadata["source_snippet"].endswith("0o750)")
    with pytest.raises(TypeError):
        snapshot.files["entry.py"] = snapshot.files["entry.py"]
    with pytest.raises(FrozenInstanceError):
        snapshot.files["entry.py"].raw = b"changed"


def test_live_drift_cannot_change_a_snapshot_bound_read_view(tmp_path):
    (tmp_path / "entry.py").write_text("eval('1')\n")
    snapshot = freeze(tmp_path)
    view = SourceReadView(tmp_path, snapshot.file_hashes, byte_budget=8192, snapshot=snapshot)
    view.admit(ReadGrant(path="entry.py", start_line=1, end_line=1, reason="owned stable source"))
    assert view.read("entry.py", 1, 1)["text"] == "eval('1')\n"
    previous = view.revision
    (tmp_path / "entry.py").write_text("eval('2')\n")
    with pytest.raises(ContextAdmissionError, match="snapshot"):
        view.read("entry.py", 1, 1)
    assert view.revision == previous
    assert snapshot.files["entry.py"].text == "eval('1')\n"


def test_snapshot_accounts_invalid_encoding_read_errors_and_exclusions(tmp_path):
    (tmp_path / "good.py").write_bytes(b"eval('1')\n")
    (tmp_path / "syntax.py").write_bytes(b"def broken(:\n")
    (tmp_path / "encoding.py").write_bytes(b"# coding: missing-owned-encoding\npass\n")
    (tmp_path / "linked.py").symlink_to(tmp_path / "good.py")
    for directory in (".venv", "data", "vendor"):
        (tmp_path / directory).mkdir()
        (tmp_path / directory / "ignored.py").write_text("eval(value)\n")
    snapshot = freeze(tmp_path, exclude_dirs=frozenset({"data"}))
    found = discover(tmp_path, snapshot)
    assert found.report["source_files"] == 4
    assert found.report["parsed_files"] == 1
    assert {row["path"] for row in found.report["parse_errors"]} == {"syntax.py", "encoding.py", "linked.py"}
    assert snapshot.file_hashes["linked.py"] is None
    assert snapshot.file_hashes["encoding.py"] == hashlib.sha256(snapshot.files["encoding.py"].raw).hexdigest()
    assert set(snapshot.files) == {"good.py", "syntax.py", "encoding.py", "linked.py"}
    assert snapshot.excluded_paths == (".venv", "data", "vendor")
    assert found.report["excluded_paths"] == [".venv", "data", "vendor"]


def test_snapshot_root_identity_and_matching_index_are_required(tmp_path):
    (tmp_path / "entry.py").write_text("eval('1')\n")
    snapshot = freeze(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(ValueError, match="root"):
        discover(other, snapshot)
    original = discover(tmp_path, snapshot)
    (tmp_path / "entry.py").write_text("eval('2')\n")
    changed = discover_python_repository(tmp_path, "owned-source")
    with pytest.raises(ValueError, match="snapshot"):
        operations(snapshot, changed)
    assert operations(snapshot, original)


def test_snapshot_mode_retains_identical_historical_v1_candidates_and_documents(tmp_path):
    (tmp_path / "entry.py").write_text("from subprocess import run as launch\nlaunch(['echo', 'owned'])\ndef entry(value):\n    return eval(value)\n")
    original = discover_python_repository(tmp_path, "owned-source")
    snapshot = freeze(tmp_path)
    sealed = discover(tmp_path, snapshot)
    assert sealed.candidates == original.candidates
    assert list(sealed.index.documents.values()) == list(original.index.documents.values())


def test_new_snapshot_changes_exact_operation_identity_without_rewriting_v1(tmp_path):
    (tmp_path / "entry.py").write_text("eval('1')\n")
    first = freeze(tmp_path)
    d1 = discover(tmp_path, first)
    (tmp_path / "entry.py").write_text("eval('2')\n")
    second = freeze(tmp_path)
    d2 = discover(tmp_path, second)
    assert d1.candidates[0].candidate_id == d2.candidates[0].candidate_id
    assert operations(first, d1)[0].candidate_id != operations(second, d2)[0].candidate_id


@pytest.mark.parametrize("name,limit,reason", [
    ("max_files", 1, "SOURCE_FILE_LIMIT"),
    ("max_source_bytes", 12, "SOURCE_BYTE_LIMIT"),
    ("max_ast_nodes", 4, "SOURCE_AST_LIMIT"),
])
def test_snapshot_resource_bounds_preserve_explicit_partial_inventory(tmp_path, name, limit, reason):
    (tmp_path / "a.py").write_text("eval('1')\n")
    (tmp_path / "b.py").write_text("eval('2')\n")
    snapshot = freeze(tmp_path, **{name: limit})
    assert snapshot.resource_reason == reason
    assert not snapshot.inventory_complete
    assert snapshot.enumerated_files == snapshot.read_files + snapshot.not_read_files
    if name == "max_source_bytes":
        assert snapshot.source_bytes <= limit
    if name == "max_ast_nodes":
        assert snapshot.ast_nodes <= limit
    found = discover(tmp_path, snapshot)
    assert found.report["inventory_complete"] is False
    assert found.report["resource_reason"] == reason
    assert found.report["source_files"] == found.report["parsed_files"] + len(found.report["parse_errors"])


def test_bounded_source_reader_rejects_large_file_before_unbounded_read(tmp_path):
    from cv_agent.code_adapters.source_files import SourceReadLimitError, read_source_bytes
    raw = b"x" * 100000
    (tmp_path / "large.py").write_bytes(raw)
    with pytest.raises(SourceReadLimitError):
        read_source_bytes(tmp_path, "large.py", max_bytes=16)
    assert read_source_bytes(tmp_path, "large.py") == raw


def test_snapshot_cancellation_marks_inventory_as_incomplete(tmp_path):
    (tmp_path / "a.py").write_text("eval('1')\n")
    snapshot = freeze(tmp_path, cancelled=lambda: True)
    assert not snapshot.inventory_complete
    assert snapshot.resource_reason == "CANCELLED"
    assert snapshot.enumerated_files == 0


def test_empty_snapshot_honors_cancellation_without_claiming_complete_inventory(tmp_path):
    active = freeze(tmp_path)
    assert active.inventory_complete and active.resource_reason is None
    stopped = freeze(tmp_path, cancelled=lambda: True)
    assert not stopped.inventory_complete
    assert stopped.resource_reason == "CANCELLED"
    assert stopped.enumerated_files == stopped.read_files == 0


@pytest.mark.parametrize("source,count", [
    ("def entry(arg: eval('1')) -> eval('2'):\n    pass\n", 2),
    ("def entry(*args: eval('1'), **kwargs: eval('2')):\n    pass\n", 2),
    ("def entry[T: eval('bound')](arg: eval('1')) -> eval('2'):\n    pass\n", 3),
    ("class Entry[T: eval('bound')]:\n    pass\n", 1),
    ("def entry(arg=eval('1')):\n    return eval('2')\n", 2),
])
def test_operation_inventory_includes_annotation_syntax_with_default_and_body_controls(tmp_path, source, count):
    (tmp_path / "entry.py").write_text(source)
    snapshot = freeze(tmp_path)
    found = discover(tmp_path, snapshot)
    exact = operations(snapshot, found)
    calls = [node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Call)]
    assert len(exact) == len(calls) == count
    assert {candidate.metadata["source_snippet"] for candidate in exact} == {ast.get_source_segment(source, node) for node in calls}
    assert all(candidate.metadata["evidence_kind"] == "static_candidate" for candidate in exact)


def test_actual_helper_grant_changes_next_tool_input_without_stale_result_cache(tmp_path):
    """R09 is NOT_REPRODUCED: new view uses new scope; repeats stay blocked."""
    from cv_agent.domain.chat import ModelToolCall
    from cv_agent.tools.identity import candidate_subject
    from cv_agent.tools.registry import ToolExecutionScope, ToolRegistry
    from cv_agent.tools.validation import full_agent_tools

    (tmp_path / "entry.py").write_text("import os\nfrom helper import build_cmd\ndef entry(value):\n    os.system(build_cmd(value))\n")
    (tmp_path / "helper.py").write_text("import shlex\ndef build_cmd(value):\n    return 'echo ' + shlex.quote(value)\n")
    snapshot = freeze(tmp_path)
    found = discover(tmp_path, snapshot)
    candidate, = found.candidates
    # This owned control explicitly declares its input; source discovery does not.
    candidate = candidate.model_copy(update={"input_parameters": ("value",)})
    subject = candidate_subject(found.index, candidate)
    view = SourceReadView(tmp_path, snapshot.file_hashes, byte_budget=8192, snapshot=snapshot)
    view.admit(ReadGrant(path="entry.py", start_line=3, end_line=4, reason="owned candidate"))
    registry = ToolRegistry([t for t in full_agent_tools(found.index) if t.name == "inspect_command_construction"], max_output_bytes=12000)

    def current_scope():
        admitted = []
        for path in found.index.documents:
            first, last = map(int, path.rsplit("@", 1)[1].split("-"))
            if view.covers(path.split("::", 1)[0], first, last):
                admitted.append(path)
        return ToolExecutionScope(admitted_paths=frozenset(admitted), candidate_path=candidate.path,
                                  subject=subject, max_observation_tokens=16000)

    call = ModelToolCall(call_id="owned-call", name="inspect_command_construction", arguments={"source_path": candidate.path, "max_hops": 2})
    before_scope = current_scope()
    before = registry.invoke(call, allowed=(call.name,), scope=before_scope)
    assert json.loads(before.content)["command_construction_status"] == "UNAVAILABLE"
    assert json.loads(before.content)["helpers"] == []
    old_revision = view.revision
    view.extend(ReadGrant(path="helper.py", start_line=2, end_line=3, reason="explicit owned helper"))
    after_scope = current_scope()
    assert view.revision != old_revision
    assert before_scope.admitted_paths < after_scope.admitted_paths
    after = registry.invoke(call, allowed=(call.name,), scope=after_scope)
    assert json.loads(after.content)["command_construction_status"] == "SANITIZED"
    assert json.loads(after.content)["helpers"]
    assert before.validation_status == after.validation_status == "UNRESOLVED"
    repeated = registry.invoke(call, allowed=(call.name,), scope=after_scope)
    assert repeated.status == "blocked"
    assert len(after_scope.answered_calls) == 1
