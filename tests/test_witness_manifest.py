"""Subject-derived calls must use bound source and constrained data supplements."""
from __future__ import annotations

import hashlib
import math
import sys
import textwrap
from pathlib import Path

import pytest
from pydantic import ValidationError

from cv_agent.code_adapters.python import parse_python_source
from cv_agent.domain.evidence import ValidationSubject
from cv_agent.domain.types import CodeDocument
from cv_agent.retrieval import RepositoryIndex
from cv_agent.tools.identity import repository_source_digest


def _bound(tmp_path, source, *, values=None, booleans=None, conditions=None, extra=None):
    sources = {"sample.py": textwrap.dedent(source).lstrip(), **(extra or {})}
    documents = []
    entry = None
    for relative, text in sources.items():
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        spans = parse_python_source("neutral", relative, text)
        documents.extend(span.document.model_copy(update={"source_sha256": digest}) for span in spans)
        documents.append(CodeDocument(repository_id="neutral", path=f"{relative}::<module>@1-{len(text.splitlines())}",
                                      text=text, language="python", adapter_tier="ast", source_sha256=digest))
        if relative == "sample.py":
            entry = next(span.document for span in spans if "::Service.serve@" in span.document.path)
    index = RepositoryIndex(documents)
    assert entry is not None
    first = int(entry.path.split("@", 1)[1].split("-", 1)[0])
    subject = ValidationSubject(candidate_id="neutral", repository_id="neutral", property_id="command-execution",
                                entry_path=entry.path, entry_line=first, source_digest=repository_source_digest(index),
                                input_parameters=("model_uri",), entry_value_assumptions=values or {},
                                entry_boolean_arguments=booleans or {}, entry_condition_assumptions=conditions or {})
    return index, subject


def _build(tmp_path, index, subject, values=None, files=None):
    from cv_agent.tools.validation.witness_manifest import (
        WitnessExecutionContext, WitnessSupplement, build_witness_manifest,
    )
    return build_witness_manifest(index, subject, WitnessExecutionContext(checkout_root=tmp_path),
                                  WitnessSupplement(constructor_parameters=values or {}, precondition_files=files or {}))


PLAIN = '''
import subprocess
class Service:
    def serve(self, model_uri, port, enabled=False, timeout=None):
        subprocess.Popen(["bash", "-c", f"record {model_uri}"])
'''


def test_entry_and_call_kwargs_are_derived_without_a_template(tmp_path):
    index, subject = _bound(tmp_path, PLAIN, values={"port": 1234, "timeout": None}, booleans={"enabled": True})
    draft = _build(tmp_path, index, subject)
    assert draft.generated["entry_qualified"] is True
    assert draft.manifest is not None, draft.gaps
    manifest = draft.manifest
    assert manifest.module_name == "sample" and manifest.class_name == "Service" and manifest.method_name == "serve"
    assert manifest.call_kwargs == {"port": 1234, "timeout": None, "enabled": True}
    assert manifest.call_args == () and manifest.constructor_kwargs == {}
    assert manifest.probe_argument == "model_uri"
    assert manifest.recorder_command == "cv_witness_recorder"
    assert manifest.subject == subject
    assert manifest.entry_file_sha256 == hashlib.sha256((tmp_path / "sample.py").read_bytes()).hexdigest()
    assert draft.missing_constructor_parameters == ()


def test_required_call_argument_is_not_filled_by_model_or_default_guess(tmp_path):
    index, subject = _bound(tmp_path, PLAIN)
    draft = _build(tmp_path, index, subject)
    assert draft.manifest is None and draft.generated["entry_qualified"]
    assert "entry_argument_missing:port" in draft.gaps
    with pytest.raises(ValueError, match="constructor"):
        _build(tmp_path, index, subject, {"port": 1234})


def test_missing_constructor_config_is_explicit_then_only_missing_fields_can_be_supplied(tmp_path):
    source = PLAIN.replace('    def serve', '    def __init__(self, config):\n        self.config = config\n    def serve')
    index, subject = _bound(tmp_path, source, values={"port": 1234})
    draft = _build(tmp_path, index, subject)
    assert draft.manifest is None and draft.missing_constructor_parameters == ("config",)
    assert draft.generated["entry_qualified"] is True
    completed = _build(tmp_path, index, subject, {"config": {}}, {"metadata.json": "{}"})
    assert completed.manifest is not None, completed.gaps
    assert completed.manifest.constructor_kwargs == {"config": {}}
    assert completed.manifest.precondition_files == {"metadata.json": "{}"}
    with pytest.raises(ValueError, match="constructor"):
        _build(tmp_path, index, subject, {"config": {}, "unrequested": 1})


def test_non_sample_specific_self_assignment_maps_to_constructor_parameter(tmp_path):
    source = PLAIN.replace('    def serve', '    def __init__(self, threads, config):\n        self.pool_size = threads\n    def serve')
    index, subject = _bound(tmp_path, source, values={"port": 1234, "self.pool_size": 7})
    draft = _build(tmp_path, index, subject, {"config": {}})
    assert draft.manifest is not None, draft.gaps
    assert draft.manifest.constructor_kwargs == {"threads": 7, "config": {}}
    assert draft.manifest.subject.entry_value_assumptions["self.pool_size"] == 7
    with pytest.raises(ValueError, match="constructor"):
        _build(tmp_path, index, subject, {"threads": 8, "config": {}})


def test_primitive_or_default_is_generation_recipe_not_removed_obligation(tmp_path):
    source = PLAIN.replace('    def serve', '    def __init__(self, threads=1):\n        self.pool_size = threads or 1\n    def serve')
    index, subject = _bound(tmp_path, source, values={"port": 1234, "self.pool_size": 1})
    draft = _build(tmp_path, index, subject)
    assert draft.manifest is not None, draft.gaps
    assert "threads" not in draft.manifest.constructor_kwargs
    assert draft.manifest.subject.entry_value_assumptions["self.pool_size"] == 1


def test_condition_alias_constant_derivation_uses_its_actual_bound_module(tmp_path):
    source = 'from modes import selector as choice\n' + PLAIN.replace('    def serve', '    def __init__(self, manager, config):\n        self.manager = manager\n    def serve')
    index, subject = _bound(tmp_path, source, values={"port": 1234},
                           conditions={"self.manager != choice.CURRENT": False},
                           extra={"modes/__init__.py": "", "modes/selector.py": 'CURRENT = "embedded"\n',
                                  "unrelated.py": 'CURRENT = "wrong"\n'})
    draft = _build(tmp_path, index, subject, {"config": {}})
    assert draft.manifest is not None, draft.gaps
    assert draft.manifest.constructor_kwargs["manager"] == "embedded"
    assert draft.manifest.subject.entry_condition_assumptions == subject.entry_condition_assumptions


@pytest.mark.parametrize("mutation", [
    'choice = object()\n',
    'if True:\n    choice = object()\n',
])
def test_rebound_import_alias_cannot_choose_constructor_value(tmp_path, mutation):
    source = 'from modes import selector as choice\n' + mutation + PLAIN.replace('    def serve', '    def __init__(self, manager):\n        self.manager = manager\n    def serve')
    index, subject = _bound(tmp_path, source, values={"port": 1234}, conditions={"self.manager != choice.CURRENT": False},
                           extra={"modes/__init__.py": "", "modes/selector.py": 'CURRENT = "embedded"\n'})
    draft = _build(tmp_path, index, subject)
    assert draft.manifest is None and "manager" in draft.missing_constructor_parameters


@pytest.mark.parametrize("constant_source", [
    'CURRENT = compute()\n',
    'CURRENT = "embedded"\nCURRENT = "other"\n',
    'if True:\n    CURRENT = "embedded"\n',
])
def test_nonliteral_nonunique_or_conditional_constant_is_not_inferred(tmp_path, constant_source):
    source = 'import selector as choice\n' + PLAIN.replace('    def serve', '    def __init__(self, manager):\n        self.manager = manager\n    def serve')
    index, subject = _bound(tmp_path, source, values={"port": 1234}, conditions={"self.manager != choice.CURRENT": False},
                           extra={"selector.py": constant_source})
    draft = _build(tmp_path, index, subject)
    assert draft.manifest is None and draft.missing_constructor_parameters == ("manager",)


def test_positional_only_constructor_and_entry_parameters_follow_source_order(tmp_path):
    source = '''
class Service:
    def __init__(self, config, /):
        self.config = config
    def serve(self, port, /, model_uri):
        pass
'''
    index, subject = _bound(tmp_path, source, values={"port": 1234})
    draft = _build(tmp_path, index, subject, {"config": {}})
    assert draft.manifest is not None, draft.gaps
    assert draft.manifest.constructor_args == ({},) and draft.manifest.constructor_kwargs == {}
    assert draft.manifest.call_args == (1234,)


def test_variadic_constructor_required_binding_is_not_invented(tmp_path):
    source = PLAIN.replace('    def serve', '    def __init__(self, *args):\n        self.config = args[0]\n    def serve')
    index, subject = _bound(tmp_path, source, values={"port": 1234})
    draft = _build(tmp_path, index, subject)
    assert draft.manifest is None
    assert "constructor_variadic_unsupported" in draft.gaps


@pytest.mark.parametrize("alter", ["file", "digest", "line"])
def test_changed_source_or_subject_identity_is_not_qualified(tmp_path, alter):
    index, subject = _bound(tmp_path, PLAIN, values={"port": 1234})
    if alter == "file":
        (tmp_path / "sample.py").write_text(PLAIN + "\n# altered source\n")
    elif alter == "digest":
        subject = subject.model_copy(update={"source_digest": "0" * 64})
    else:
        subject = subject.model_copy(update={"entry_line": 1})
    draft = _build(tmp_path, index, subject)
    assert draft.manifest is None and draft.generated["entry_qualified"] is False
    assert draft.gaps


@pytest.mark.parametrize("payload", [
    {"constructor_parameters": {}, "precondition_files": {}, "stub": {}},
    {"constructor_parameters": {"config": {"nested": {"expected_label": "SAFE"}}}, "precondition_files": {}},
    {"constructor_parameters": {"config": {"source_modules": []}}, "precondition_files": {}},
    {"constructor_parameters": {"config": "CONFIRMED"}, "precondition_files": {}},
    {"constructor_parameters": {"config": math.nan}, "precondition_files": {}},
    {"constructor_parameters": {}, "precondition_files": {"../escape": "x"}},
    {"constructor_parameters": {}, "precondition_files": {"/absolute": "x"}},
    {"constructor_parameters": {}},
])
def test_strict_supplement_rejects_labels_sources_protocol_fields_and_missing_schema_keys(payload):
    from cv_agent.tools.validation.witness_manifest import WitnessSupplement
    with pytest.raises((ValidationError, ValueError)):
        WitnessSupplement.model_validate(payload)


def test_custom_json_protocol_is_not_run_or_coerced():
    from cv_agent.tools.validation.witness_manifest import WitnessSupplement
    class Hostile:
        def __iter__(self):
            raise AssertionError("iteration protocol executed")
        def __repr__(self):
            raise AssertionError("representation protocol executed")
    with pytest.raises((ValidationError, ValueError)):
        WitnessSupplement(constructor_parameters={"config": Hostile()}, precondition_files={})


def test_source_module_qualification_respects_trusted_import_root():
    from cv_agent.tools.validation.witness_manifest import qualify_source_module
    assert qualify_source_module("src/pkg/service.py", "src") == "pkg.service"
    assert qualify_source_module("src/pkg/__init__.py", "src") == "pkg"
    assert qualify_source_module("other/pkg/service.py", "src") is None
    assert qualify_source_module("src/pkg/bad-name.py", "src") is None


@pytest.mark.parametrize("shadow", ["module_function", "method_assignment", "package_export"])
def test_import_alias_shadowing_is_not_constructor_evidence(tmp_path, shadow):
    source = 'from modes import selector as choice\n' + PLAIN.replace('    def serve', '    def __init__(self, manager):\n        self.manager = manager\n    def serve')
    package = ""
    if shadow == "module_function":
        source = 'def choice():\n    return None\n' + source
    elif shadow == "method_assignment":
        source = source.replace('        subprocess.Popen', '        choice = object()\n        subprocess.Popen')
    else:
        package = 'selector = object()\n'
    index, subject = _bound(tmp_path, source, values={"port": 1234}, conditions={"self.manager != choice.CURRENT": False},
                           extra={"modes/__init__.py": package, "modes/selector.py": 'CURRENT = "embedded"\n'})
    draft = _build(tmp_path, index, subject)
    assert draft.manifest is None and draft.missing_constructor_parameters == ("manager",)


def test_uncalled_nested_constructor_assignment_is_not_an_input_recipe(tmp_path):
    source = PLAIN.replace('    def serve', '    def __init__(self, threads):\n        def uncalled():\n            self.pool_size = threads\n    def serve')
    index, subject = _bound(tmp_path, source, values={"port": 1234, "self.pool_size": 7})
    draft = _build(tmp_path, index, subject)
    assert draft.manifest is None and draft.missing_constructor_parameters == ("threads",)


def test_corrupt_entry_slice_cannot_borrow_matching_full_file_hash(tmp_path):
    index, subject = _bound(tmp_path, PLAIN, values={"port": 1234})
    changed = [doc.model_copy(update={"text": "def unrelated():\n    pass\n"}) if doc.path == subject.entry_path else doc
               for doc in index.documents.values()]
    index = RepositoryIndex(changed)
    subject = subject.model_copy(update={"source_digest": repository_source_digest(index)})
    draft = _build(tmp_path, index, subject)
    assert draft.manifest is None and draft.generated["entry_qualified"] is False
    assert "entry_index_text_mismatch" in draft.gaps


def test_missing_draft_preview_keeps_source_and_policy_identity_private(tmp_path):
    source = PLAIN.replace('    def serve', '    def __init__(self, config):\n        pass\n    def serve')
    index, subject = _bound(tmp_path, source, values={"port": 1234})
    subject = subject.model_copy(update={"candidate_id": "opaque-private-case-identity"})
    draft = _build(tmp_path, index, subject)
    import json
    preview = json.dumps(draft.generated)
    assert str(tmp_path) not in preview
    assert "opaque-private-case-identity" not in preview
    assert subject.source_digest not in preview
    assert "python_executable" not in preview and "resource_profile" not in preview
    assert draft.bound_fields["subject"] == subject


@pytest.mark.parametrize("files", [{"case_id": "opaque"}, {"metadata.txt": "SAFE"}])
def test_layout_mapping_cannot_carry_role_labels_or_case_metadata(files):
    from cv_agent.tools.validation.witness_manifest import WitnessSupplement
    with pytest.raises((ValidationError, ValueError)):
        WitnessSupplement(constructor_parameters={}, precondition_files=files)


@pytest.mark.parametrize("body_line", [True, False])
def test_function_witness_refuses_unbound_or_operation_specific_candidate_scope(tmp_path, body_line):
    index, subject = _bound(tmp_path, PLAIN, values={"port": 1234})
    subject = subject.model_copy(update={"entry_line": subject.entry_line + 1 if body_line else None})
    draft = _build(tmp_path, index, subject)
    assert draft.manifest is None and draft.generated["entry_qualified"] is False
    assert "candidate_scope_unbound" in draft.gaps


@pytest.mark.parametrize("decorated", ["class", "method"])
def test_decorated_entry_stays_unqualified_without_a_wrapper_model(tmp_path, decorated):
    source = 'def decorate(value):\n    return value\n' + PLAIN
    if decorated == "class":
        source = source.replace('class Service:', '@decorate\nclass Service:')
    else:
        source = source.replace('    def serve', '    @decorate\n    def serve')
    index, subject = _bound(tmp_path, source, values={"port": 1234})
    draft = _build(tmp_path, index, subject)
    assert draft.manifest is None and draft.generated["entry_qualified"] is False
    assert any(gap in draft.gaps for gap in ("entry_decorator_unsupported", "entry_ast_span_mismatch"))
