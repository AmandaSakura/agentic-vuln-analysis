"""Exact v2 chmod operation controls retain legacy line-level semantics."""
import ast
import hashlib
import json

import pytest

from cv_agent.domain.evidence import ValidationSubject
from cv_agent.domain.types import CodeDocument
from cv_agent.retrieval import RepositoryIndex
from cv_agent.tools.identity import repository_source_digest
from cv_agent.tools.registry import ToolExecutionScope
from cv_agent.tools.validation.models import PathInput
from cv_agent.tools.validation.permissions import _permission_mode_assessment, permission_mode


def locator(text, call, raw=None):
    return {"source_path": "entry.py", "start_line": call.lineno, "end_line": call.end_lineno,
        "start_col_utf8": call.col_offset, "end_col_utf8": call.end_col_offset,
        "node_kind": "Call", "rule_version": "static-operation-rules-v2",
        "file_sha256": hashlib.sha256(text.encode() if raw is None else raw).hexdigest(),
        "source_digest": "b" * 64}


def chmod_calls(text):
    return sorted((node for node in ast.walk(ast.parse(text)) if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute) and node.func.attr == "chmod"),
        key=lambda node: (node.lineno, node.col_offset))


def observe(document, operation=None, *, original_line=None, candidate="owned-operation"):
    index = RepositoryIndex([document])
    selected = ValidationSubject(candidate_id=candidate, repository_id="owned", entry_path=document.path,
        entry_line=original_line if original_line is not None else operation["start_line"] if operation else 1,
        source_digest=repository_source_digest(index), property_id="chmod-mode-others-write",
        analysis_scope="The literal mode at the selected owned AST operation.")
    scope = ToolExecutionScope(frozenset({document.path}), 8192, candidate_path=document.path,
        subject=selected, operation_locator=operation)
    observation = permission_mode(index, PathInput(path=document.path), scope)
    return selected, observation


def test_exact_operation_selects_one_chmod_on_shared_line():
    text = "import os\ndef owned(path):\n    os.chmod(path, 0o777); os.chmod(path, 0o600)\n"
    source = CodeDocument(repository_id="owned", path="entry.py", text=text,
                          source_sha256=hashlib.sha256(text.encode()).hexdigest())
    result = _permission_mode_assessment(source, call_line=3, operation_locator=locator(text, chmod_calls(text)[0]))
    assert result["status"] == "CONFIRMED"
    assert len(result["calls"]) == 1


def test_two_same_line_operations_receive_distinct_candidate_bound_mode_proofs():
    text = "import os\ndef owned(path):\n    os.chmod(path, 0o777); os.chmod(path, 0o600)\n"
    document = CodeDocument(repository_id="owned", path="entry.py", text=text,
        source_sha256=hashlib.sha256(text.encode()).hexdigest())
    results = []
    for position, call in enumerate(chmod_calls(text)):
        selected, observation = observe(document, locator(text, call), candidate=f"owned-operation/{position}")
        results.append(observation)
        assert observation.status == "ok" and observation.subject == selected
        payload = json.loads(observation.content)
        assert len(payload["calls"]) == 1
        assert set(payload["calls"][0]) == {"line", "target", "mode", "mode_text", "text", "branch_conditions"}
    assert [item.validation_status for item in results] == ["CONFIRMED", "REFUTED"]
    assert results[0].subject.candidate_id != results[1].subject.candidate_id


def test_legacy_line_scope_and_output_fields_are_preserved_without_locator():
    text = "import os\ndef owned(path):\n    os.chmod(path, 0o777); os.chmod(path, 0o600)\n"
    document = CodeDocument(repository_id="owned", path="entry.py", text=text)
    _, observed = observe(document, original_line=3)
    payload = json.loads(observed.content)
    assert observed.validation_status == "UNRESOLVED" and observed.subject is None
    assert len(payload["calls"]) == 2
    assert "operation_locator" not in payload
    assert set(payload["calls"][0]) == {"line", "target", "mode", "mode_text", "text", "branch_conditions"}


@pytest.mark.parametrize("field,value", [
    ("start_col_utf8", 5), ("end_col_utf8", 999), ("source_path", "other.py"),
    ("file_sha256", "f" * 64), ("start_line", 2), ("node_kind", "Expr"),
    ("rule_version", "unregistered-v9"), ("source_digest", "not-a-digest"),
])
def test_wrong_exact_locator_cannot_borrow_another_operation_proof(field, value):
    text = "import os\ndef owned(path):\n    os.chmod(path, 0o777)\n"
    document = CodeDocument(repository_id="owned", path="entry.py", text=text,
        source_sha256=hashlib.sha256(text.encode()).hexdigest())
    selected = locator(text, chmod_calls(text)[0])
    selected[field] = value
    _, observed = observe(document, selected, original_line=3)
    assert observed.status == "blocked" or observed.validation_status == "UNRESOLVED"
    assert observed.subject is None


@pytest.mark.parametrize("raw", [
    '# owned unicode\nimport os\ndef outer():\n    def inner(path):\n        café = "é"; os.chmod(path, 0o777); os.chmod(path, 0o600)\n'.encode(),
    b'import os\ndef outer():\n\tdef inner(path):\n\t\tlabel = "owned"; os.chmod(path, 0o777); os.chmod(path, 0o600)\n',
    b'import os\r\ndef outer():\r\n    def inner(path):\r\n        label = "owned"; os.chmod(path, 0o777); os.chmod(path, 0o600)\r\n',
    '# coding: latin-1\nimport os\ndef outer():\n    def inner(path):\n        café = "é"; os.chmod(path, 0o777); os.chmod(path, 0o600)\n'.encode("latin-1"),
])
def test_original_utf8_coordinates_survive_indented_function_slice_and_encoding(raw):
    import io
    import tokenize
    encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
    text = raw.decode(encoding)
    inner = next(node for node in ast.walk(ast.parse(text)) if isinstance(node, ast.FunctionDef) and node.name == "inner")
    slice_text = "".join(text.splitlines(keepends=True)[inner.lineno - 1:inner.end_lineno])
    document = CodeDocument(repository_id="owned", path=f"entry.py::outer.inner@{inner.lineno}-{inner.end_lineno}",
        text=slice_text, source_sha256=hashlib.sha256(raw).hexdigest())
    results = []
    for position, call in enumerate(chmod_calls(text)):
        selected, observed = observe(document, locator(text, call, raw), candidate=f"owned-encoded/{position}")
        assert observed.subject == selected and observed.status == "ok"
        payload = json.loads(observed.content)
        assert len(payload["calls"]) == 1
        assert payload["calls"][0]["line"] == call.lineno - inner.lineno + 1
        assert payload["calls"][0]["mode_text"] in {"0o777", "0o600"}
        results.append(observed.validation_status)
    assert results == ["CONFIRMED", "REFUTED"]


@pytest.mark.parametrize("before", [True, False])
def test_selecting_one_call_preserves_original_scope_unknown_effects(before):
    statements = ["    unknown_effect()\n", "    os.chmod(path, 0o600)\n"]
    if not before:
        statements.reverse()
    text = "import os\ndef owned(path):\n" + "".join(statements)
    document = CodeDocument(repository_id="owned", path="entry.py", text=text,
        source_sha256=hashlib.sha256(text.encode()).hexdigest())
    _, observed = observe(document, locator(text, chmod_calls(text)[0]))
    assert observed.validation_status == "UNRESOLVED" and observed.subject is None
    assert json.loads(observed.content)["issues"]


def test_exact_nonliteral_mode_and_related_prior_unknown_mode_stay_unknown():
    text = "import os\ndef owned(path, mode):\n    os.chmod(path, mode)\n    os.chmod(\n        path,\n        0o777,\n    )\n"
    # Keywords/trailing commas are ordinary AST coordinates; the collector
    # retains original relevant effects and selects only the exact mode call.
    document = CodeDocument(repository_id="owned", path="entry.py", text=text,
        source_sha256=hashlib.sha256(text.encode()).hexdigest())
    first, second = chmod_calls(text)
    _, unknown = observe(document, locator(text, first), candidate="owned-unknown")
    _, supported = observe(document, locator(text, second), candidate="owned-literal")
    assert unknown.validation_status == "UNRESOLVED" and unknown.subject is None
    assert supported.validation_status == "UNRESOLVED" and supported.subject is None


def test_multiline_literal_call_is_a_positive_control_without_an_unknown_prior_mode():
    text = "import os\ndef owned(path):\n    os.chmod(\n        path,\n        0o777,\n    )\n"
    document = CodeDocument(repository_id="owned", path="entry.py", text=text,
        source_sha256=hashlib.sha256(text.encode()).hexdigest())
    selected, supported = observe(document, locator(text, chmod_calls(text)[0]))
    assert supported.validation_status == "CONFIRMED" and supported.subject == selected
