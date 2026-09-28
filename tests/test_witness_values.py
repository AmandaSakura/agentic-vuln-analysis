"""Offline dictionary-only controls for candidate runtime value assumptions."""
from __future__ import annotations

import hashlib
import importlib.util
import sys
import textwrap
from pathlib import Path

import pytest

from cv_agent.evaluation.diagnostics.bounded_execution_witness import SourceFileBinding
from test_bounded_execution_witness import _manifest


def _load(path: Path, module_name: str, monkeypatch: pytest.MonkeyPatch):
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    return module


def _setup(tmp_path: Path, source: str, assumptions: dict, monkeypatch: pytest.MonkeyPatch):
    from cv_agent.evaluation.diagnostics.witness_values import ValueAssumptionObserver

    manifest = _manifest(tmp_path, source)
    manifest = manifest.model_copy(update={
        "subject": manifest.subject.model_copy(update={"entry_value_assumptions": assumptions})
    })
    observer = ValueAssumptionObserver(manifest)
    module = _load(tmp_path / "sample.py", "sample", monkeypatch)
    module.__dict__["_observe"] = observer.observe_entry
    return manifest, observer, module


SOURCE = '''
import sys
SETTING = "literal"
class Service:
    def __init__(self):
        self.count = 1
    def serve(self, model_uri):
        _observe(sys._getframe())
'''


def test_actual_entry_dictionary_and_unique_module_constant_match(tmp_path, monkeypatch):
    _, observer, module = _setup(tmp_path, SOURCE, {"self.count": 1, "SETTING": "literal"}, monkeypatch)
    observer.verify_module_values()
    module.Service().serve("input")
    result = observer.result()
    assert result["gaps"] == []
    assert set(result["verified"]) == {"self.count", "SETTING"}
    self_fact = result["observations"]["self.count"][0]
    assert self_fact["actual"] == 1 and self_fact["point"] == "entry"
    constant_fact = result["observations"]["SETTING"][0]
    assert constant_fact["source_sha256"] == hashlib.sha256((tmp_path / "sample.py").read_bytes()).hexdigest()
    assert constant_fact["definition_line"] == 2


@pytest.mark.parametrize("assumptions, specific", [
    ({"self.count": 2}, "entry_value_assumption_mismatch:self.count"),
    ({"self.absent": 1}, "entry_value_assumption_missing:self.absent"),
    ({"MISSING": 1}, "entry_value_definition_missing:MISSING"),
    ({"self.count": True}, "entry_value_assumption_mismatch:self.count"),
])
def test_mismatch_missing_and_bool_int_do_not_match(tmp_path, monkeypatch, assumptions, specific):
    _, observer, module = _setup(tmp_path, SOURCE, assumptions, monkeypatch)
    observer.verify_module_values()
    module.Service().serve("input")
    result = observer.result()
    assert specific in result["gaps"]
    assert "entry_value_assumption_unverified:" + next(iter(assumptions)) in result["gaps"]
    assert not result["verified"]


def test_property_custom_dict_and_custom_getattribute_never_execute(tmp_path, monkeypatch):
    source = '''
import sys
hits = []
class Service:
    def __init__(self):
        object.__setattr__(self, "count", 1)
    @property
    def danger(self):
        hits.append("property")
        return 1
    def __getattribute__(self, name):
        if name != "serve":
            hits.append(name)
            raise AssertionError("attribute executed")
        return object.__getattribute__(self, name)
    def serve(self, model_uri):
        _observe(sys._getframe())
'''
    _, observer, module = _setup(tmp_path, source, {"self.count": 1, "self.danger": 1}, monkeypatch)
    module.Service().serve("input")
    result = observer.result()
    assert "self.count" in result["verified"]
    assert "entry_value_assumption_descriptor:self.danger" in result["gaps"]
    assert module.hits == []

    source = source.replace('    @property\n    def danger(self):', '    @property\n    def __dict__(self):')
    _, observer, module = _setup(tmp_path, source, {"self.count": 1}, monkeypatch)
    module.Service().serve("input")
    assert "entry_value_assumption_dictionary_unavailable:self.count" in observer.result()["gaps"]
    assert module.hits == []


def test_instance_descriptor_cannot_be_hidden_by_raw_dictionary_value(tmp_path, monkeypatch):
    source = '''
import sys
hits = []
class Service:
    @property
    def count(self):
        hits.append("property")
        return 2
    def serve(self, model_uri):
        _observe(sys._getframe())
'''
    _, observer, module = _setup(tmp_path, source, {"self.count": 1}, monkeypatch)
    instance = module.Service()
    instance.__dict__["count"] = 1
    instance.serve("input")
    assert "entry_value_assumption_descriptor:self.count" in observer.result()["gaps"]
    assert module.hits == []


@pytest.mark.parametrize("second_source", [
    'SETTING = "literal"\n',
    'SETTING: str = "literal"\n',
])
def test_same_name_in_another_admitted_module_is_nonunique(tmp_path, monkeypatch, second_source):
    from cv_agent.evaluation.diagnostics.witness_values import ValueAssumptionObserver

    manifest, _, module = _setup(tmp_path, SOURCE, {"SETTING": "literal"}, monkeypatch)
    other = tmp_path / "other.py"
    other.write_text(second_source)
    binding = SourceFileBinding(module_name="other", relative_path="other.py",
                                sha256=hashlib.sha256(other.read_bytes()).hexdigest())
    observer = ValueAssumptionObserver(manifest.model_copy(update={
        "source_modules": (*manifest.source_modules, binding)
    }))
    observer.verify_module_values()
    assert "entry_value_definition_nonunique:SETTING" in observer.result()["gaps"]


def test_imported_or_nested_name_is_not_a_module_assignment(tmp_path, monkeypatch):
    source = SOURCE.replace('SETTING = "literal"', '''
from os import name as IMPORTED
def helper():
    NESTED = "literal"
class Container:
    CLASS_ONLY = "literal"
''')
    _, observer, _ = _setup(tmp_path, source, {"IMPORTED": "posix", "NESTED": "literal", "CLASS_ONLY": "literal"}, monkeypatch)
    observer.verify_module_values()
    gaps = observer.result()["gaps"]
    for name in ("IMPORTED", "NESTED", "CLASS_ONLY"):
        assert f"entry_value_definition_missing:{name}" in gaps


@pytest.mark.parametrize("replacement", [
    'SETTING = "literal"\nSETTING = "literal"',
    'SETTING = "literal"\nif True:\n    SETTING = "literal"',
])
def test_repeated_or_conditional_module_assignment_is_ambiguous(tmp_path, monkeypatch, replacement):
    _, observer, _ = _setup(tmp_path, SOURCE.replace('SETTING = "literal"', replacement),
                           {"SETTING": "literal"}, monkeypatch)
    observer.verify_module_values()
    assert "entry_value_definition_nonunique:SETTING" in observer.result()["gaps"]


def test_module_mutation_is_reread_and_earlier_mismatch_is_sticky(tmp_path, monkeypatch):
    _, observer, module = _setup(tmp_path, SOURCE, {"SETTING": "literal"}, monkeypatch)
    observer.verify_module_values()
    assert not observer.result()["gaps"]
    module.__dict__["SETTING"] = "changed"
    observer.verify_module_values()
    module.__dict__["SETTING"] = "literal"
    observer.verify_module_values()
    assert "entry_value_assumption_mismatch:SETTING" in observer.result()["gaps"]
    assert "SETTING" not in observer.result()["verified"]
    assert [fact["actual"] for fact in observer.result()["observations"]["SETTING"]] == ["literal", "changed", "literal"]


def test_no_user_equality_or_representation_is_called(tmp_path, monkeypatch):
    source = SOURCE + '''
class Hostile:
    def __eq__(self, other):
        raise AssertionError("equality executed")
    def __repr__(self):
        raise AssertionError("representation executed")
'''
    _, observer, module = _setup(tmp_path, source, {"self.count": 1, "SETTING": "literal"}, monkeypatch)
    module.__dict__["SETTING"] = module.Hostile()
    instance = module.Service()
    instance.__dict__["count"] = module.Hostile()
    observer.verify_module_values()
    instance.serve("input")
    result = observer.result()
    assert "entry_value_assumption_unsupported_value:SETTING" in result["gaps"]
    assert "entry_value_assumption_unsupported_value:self.count" in result["gaps"]


def test_source_digest_and_module_origin_are_rechecked(tmp_path, monkeypatch):
    _, observer, module = _setup(tmp_path, SOURCE, {"SETTING": "literal", "self.count": 1}, monkeypatch)
    module.__dict__["__file__"] = str(tmp_path / "other.py")
    observer.verify_module_values()
    assert "entry_value_module_origin_mismatch:SETTING" in observer.result()["gaps"]
    module.__dict__["__file__"] = str(tmp_path / "sample.py")
    (tmp_path / "sample.py").write_text(SOURCE + "\n# changed after admission\n")
    observer.verify_module_values()
    module.Service().serve("input")
    gaps = observer.result()["gaps"]
    assert "entry_value_source_digest_mismatch:SETTING" in gaps
    assert "entry_value_entry_binding_mismatch:self.count" in gaps


def test_wrong_entry_frame_does_not_supply_instance_value(tmp_path, monkeypatch):
    source = SOURCE + '''
def unrelated(self):
    _observe(sys._getframe())
'''
    _, observer, module = _setup(tmp_path, source, {"self.count": 1}, monkeypatch)
    module.unrelated(module.Service())
    assert "entry_value_entry_binding_mismatch:self.count" in observer.result()["gaps"]


def test_entry_value_records_entry_before_later_mutation(tmp_path, monkeypatch):
    source = SOURCE.replace('_observe(sys._getframe())', '_observe(sys._getframe())\n        self.count = 99')
    _, observer, module = _setup(tmp_path, source, {"self.count": 1}, monkeypatch)
    instance = module.Service()
    instance.serve("input")
    assert instance.count == 99
    assert observer.result()["verified"] == ["self.count"]
    assert observer.result()["observations"]["self.count"][0]["actual"] == 1


def test_call_kwargs_only_verify_exact_json_values(tmp_path, monkeypatch):
    from cv_agent.evaluation.diagnostics.witness_values import ValueAssumptionObserver

    manifest, _, _ = _setup(tmp_path, SOURCE, {"timeout": None, "enabled": True}, monkeypatch)
    observer = ValueAssumptionObserver(manifest.model_copy(update={"call_kwargs": {"timeout": None, "enabled": 1}}))
    result = observer.result()
    assert result["verified"] == ["timeout"]
    assert "entry_value_assumption_mismatch:enabled" in result["gaps"]
    assert result["observations"]["timeout"][0]["point"] == "call_manifest"


def test_hostile_dictionary_keys_do_not_trigger_comparison(tmp_path, monkeypatch):
    source = SOURCE + '''
class HostileKey:
    def __hash__(self):
        return hash("count")
    def __eq__(self, other):
        raise AssertionError("dictionary key equality executed")
'''
    _, observer, module = _setup(tmp_path, source, {"self.count": 1}, monkeypatch)
    instance = module.Service()
    instance.__dict__.clear()
    instance.__dict__[module.HostileKey()] = 1
    instance.serve("input")
    assert "entry_value_assumption_dictionary_unavailable:self.count" in observer.result()["gaps"]


def test_hostile_module_name_metadata_is_not_compared(tmp_path, monkeypatch):
    source = SOURCE + '''
class HostileName:
    def __eq__(self, other):
        raise AssertionError("module name equality executed")
'''
    _, observer, module = _setup(tmp_path, source, {"SETTING": "literal"}, monkeypatch)
    module.__dict__["__name__"] = module.HostileName()
    observer.verify_module_values()
    assert "entry_value_module_origin_mismatch:SETTING" in observer.result()["gaps"]


def test_metaclass_dictionary_descriptors_are_never_invoked(tmp_path, monkeypatch):
    source = '''
import sys
hits = []
class Meta(type):
    @property
    def __dict__(cls):
        hits.append("class dictionary")
        raise AssertionError("metaclass dictionary descriptor executed")
    @property
    def __mro__(cls):
        hits.append("class mro")
        raise AssertionError("metaclass mro descriptor executed")
class Service(metaclass=Meta):
    def __init__(self):
        self.count = 1
    def serve(self, model_uri):
        _observe(sys._getframe())
'''
    _, observer, module = _setup(tmp_path, source, {"self.count": 1}, monkeypatch)
    module.Service().serve("input")
    assert observer.result()["gaps"] == []
    assert module.hits == []
