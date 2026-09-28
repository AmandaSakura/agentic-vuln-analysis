"""Observe declared values through trusted dictionaries without target protocols.

Source text identifies each eligible constant's module; its actual value always
comes from the loaded module dictionary. Instance facts are observed at the
candidate entry, before its body executes. No expression is evaluated here.
"""
from __future__ import annotations

import ast
import hashlib
import math
import re
import sys
import types
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cv_agent.evaluation.diagnostics.bounded_execution_witness import WitnessManifest

_SIMPLE_NAME = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")
_MISSING = object()
_CLASS_DICTIONARY = type.__dict__["__dict__"]
_CLASS_MRO = type.__dict__["__mro__"]


def _raw_mro(cls: type) -> tuple[type, ...]:
    return _CLASS_MRO.__get__(cls, type)


def _json_value(value: Any, *, depth: int = 0) -> tuple[bool, Any]:
    """Copy exact builtin JSON values without equality, repr or descriptors."""
    kind = type(value)
    if kind in (type(None), bool, int, str):
        return True, value
    if kind is float:
        return (True, value) if math.isfinite(value) else (False, None)
    if depth >= 16:
        return False, None
    if kind is list:
        if len(value) > 1024:
            return False, None
        copied = [_json_value(item, depth=depth + 1) for item in value]
        return (True, [item[1] for item in copied]) if all(item[0] for item in copied) else (False, None)
    if kind is dict:
        if len(value) > 1024 or any(type(key) is not str for key in value):
            return False, None
        copied = {key: _json_value(item, depth=depth + 1) for key, item in value.items()}
        return (True, {key: item[1] for key, item in copied.items()}) if all(item[0] for item in copied.values()) else (False, None)
    return False, None


def _same_json(actual: Any, expected: Any) -> bool:
    """Exact builtin types prevent bool/int and protocol-based matches."""
    if type(actual) is not type(expected):
        return False
    if type(actual) is list:
        return len(actual) == len(expected) and all(_same_json(a, b) for a, b in zip(actual, expected))
    if type(actual) is dict:
        return actual.keys() == expected.keys() and all(_same_json(actual[key], expected[key]) for key in actual)
    return actual == expected


def _class_dictionaries(instance: Any) -> tuple[dict[str, Any], ...]:
    # Calling type.__getattribute__ would still execute a metaclass property.
    # Invoke only type's builtin metadata descriptors directly instead.
    cls = type(instance)
    return tuple(_CLASS_DICTIONARY.__get__(base, type) for base in _raw_mro(cls))


def _raw_instance_value(instance: Any, name: str) -> tuple[Any, str | None]:
    dictionaries = _class_dictionaries(instance)
    class_value = next((dictionary[name] for dictionary in dictionaries if name in dictionary), _MISSING)
    if class_value is not _MISSING:
        descriptor_dictionaries = _class_dictionaries(class_value)
        if any("__get__" in dictionary for dictionary in descriptor_dictionaries):
            return _MISSING, "descriptor"
    descriptor = next((dictionary["__dict__"] for dictionary in dictionaries if "__dict__" in dictionary), _MISSING)
    if type(descriptor) is not types.GetSetDescriptorType:
        return _MISSING, "dictionary_unavailable"
    # Only Python's actual instance-dictionary descriptor is allowed. A target
    # property named __dict__ must never execute, even through object access.
    if descriptor.__name__ != "__dict__" or not any(base is descriptor.__objclass__ for base in _raw_mro(type(instance))):
        return _MISSING, "dictionary_unavailable"
    try:
        dictionary = descriptor.__get__(instance, type(instance))
    except (AttributeError, TypeError):
        return _MISSING, "dictionary_unavailable"
    if type(dictionary) is not dict or any(type(key) is not str for key in dictionary):
        return _MISSING, "dictionary_unavailable"
    value = dictionary.get(name, class_value)
    return (value, "missing") if value is _MISSING else (value, None)


def _assigned_names(target: ast.AST) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    if isinstance(target, (ast.Tuple, ast.List)):
        return set().union(*(_assigned_names(item) for item in target.elts)) if target.elts else set()
    return set()


def _module_assignments(tree: ast.Module, requested: set[str]) -> dict[str, list[ast.AST]]:
    """Count module-scope assignments; nested function/class bindings are excluded."""
    matches: dict[str, list[ast.AST]] = {name: [] for name in requested}

    def visit(node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            return
        targets = node.targets if isinstance(node, ast.Assign) else ([node.target] if isinstance(node, (ast.AnnAssign, ast.AugAssign)) else [])
        for name in set().union(*(_assigned_names(target) for target in targets)) if targets else set():
            if name in matches:
                matches[name].append(node)
        for child in ast.iter_child_nodes(node):
            visit(child)

    visit(tree)
    return matches


class ValueAssumptionObserver:
    """Collect sticky mismatches for the fixed snapshot's declared value facts."""

    def __init__(self, manifest: WitnessManifest):
        self.manifest = manifest
        self._expected = dict(manifest.subject.entry_value_assumptions)
        self._observations: dict[str, list[dict[str, Any]]] = {name: [] for name in self._expected}
        self._failures: dict[str, set[str]] = {name: set() for name in self._expected}
        self._passed: set[str] = set()
        self._self_names: dict[str, str] = {}
        self._bare_names: set[str] = set()
        self._definitions: dict[str, tuple[Any, Path, int]] = {}
        for name, expected in self._expected.items():
            if not _json_value(expected)[0]:
                self._fail(name, "unsupported_value")
            elif name in manifest.call_kwargs:
                self._record(name, manifest.call_kwargs[name], {"point": "call_manifest"})
            elif name.startswith("self.") and _SIMPLE_NAME.fullmatch(name[5:]):
                self._self_names[name] = name[5:]
            elif _SIMPLE_NAME.fullmatch(name):
                self._bare_names.add(name)
            else:
                self._fail(name, "unsupported_name")
        if self._bare_names:
            self._discover()

    def _fail(self, name: str, reason: str) -> None:
        self._failures[name].add(f"entry_value_assumption_{reason}:{name}")

    def _record(self, name: str, actual: Any, metadata: dict[str, Any]) -> None:
        safe, copied = _json_value(actual)
        record = dict(metadata)
        record["supported_value"] = safe
        if safe:
            record["actual"] = copied
        expected_safe, expected = _json_value(self._expected[name])
        record["matched"] = safe and expected_safe and _same_json(copied, expected)
        self._observations[name].append(record)
        if not safe or not expected_safe:
            self._fail(name, "unsupported_value")
        elif not record["matched"]:
            self._fail(name, "mismatch")
        else:
            self._passed.add(name)

    def _discover(self) -> None:
        matches: dict[str, list[tuple[Any, Path, ast.AST, bool]]] = {name: [] for name in self._bare_names}
        discovery_failed = False
        root = self.manifest.checkout_root.resolve()
        for binding in self.manifest.source_modules:
            path = root / binding.relative_path
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(root)
                raw = resolved.read_bytes()
                if hashlib.sha256(raw).hexdigest() != binding.sha256:
                    discovery_failed = True
                    continue
                source = raw.decode("utf-8")
            except (OSError, ValueError, UnicodeError):
                discovery_failed = True
                continue
            # Filtering follows digest verification and only saves AST work.
            requested = {name for name in self._bare_names if re.search(r"\b" + re.escape(name) + r"\b", source)}
            if not requested:
                continue
            try:
                tree = ast.parse(source, filename=str(resolved))
            except SyntaxError:
                discovery_failed = True
                continue
            direct_nodes = {id(node) for node in tree.body if isinstance(node, (ast.Assign, ast.AnnAssign))}
            for name, nodes in _module_assignments(tree, requested).items():
                for node in nodes:
                    matches[name].append((binding, resolved, node, id(node) in direct_nodes))
        if discovery_failed:
            for name in self._bare_names:
                self._failures[name].add(f"entry_value_source_discovery_incomplete:{name}")
            return
        for name, locations in matches.items():
            if not locations:
                self._failures[name].add(f"entry_value_definition_missing:{name}")
            elif len(locations) != 1:
                self._failures[name].add(f"entry_value_definition_nonunique:{name}")
            elif not locations[0][3]:
                self._failures[name].add(f"entry_value_definition_not_unconditional:{name}")
            else:
                binding, path, node, _ = locations[0]
                self._definitions[name] = (binding, path, node.lineno)

    def observe_entry(self, frame: types.FrameType) -> None:
        if not self._self_names:
            return
        bound = False
        if type(frame) is types.FrameType:
            expected_path = (self.manifest.checkout_root / self.manifest.entry_relative_path).resolve()
            try:
                globals_dictionary = frame.f_globals
                safe_globals = type(globals_dictionary) is dict and all(type(key) is str for key in globals_dictionary)
                module_name = globals_dictionary.get("__name__") if safe_globals else None
                bound = (Path(frame.f_code.co_filename).resolve() == expected_path
                         and frame.f_code.co_qualname == f"{self.manifest.class_name}.{self.manifest.method_name}"
                         and frame.f_code.co_firstlineno == self.manifest.entry_first_line
                         and type(module_name) is str and module_name == self.manifest.module_name
                         and hashlib.sha256(expected_path.read_bytes()).hexdigest() == self.manifest.entry_file_sha256)
            except OSError:
                bound = False
        if not bound:
            for name in self._self_names:
                self._failures[name].add(f"entry_value_entry_binding_mismatch:{name}")
            return
        instance = frame.f_locals.get("self", _MISSING)
        for name, attribute in self._self_names.items():
            if instance is _MISSING:
                self._fail(name, "missing")
                continue
            actual, reason = _raw_instance_value(instance, attribute)
            if reason:
                self._fail(name, reason)
                continue
            self._record(name, actual, {
                "point": "entry", "source_sha256": self.manifest.entry_file_sha256,
                "file": str(expected_path), "line": frame.f_lineno,
                "module_name": self.manifest.module_name,
            })

    def verify_module_values(self) -> None:
        for name, (binding, path, line) in self._definitions.items():
            try:
                if hashlib.sha256(path.read_bytes()).hexdigest() != binding.sha256:
                    self._failures[name].add(f"entry_value_source_digest_mismatch:{name}")
                    continue
            except OSError:
                self._failures[name].add(f"entry_value_source_unreadable:{name}")
                continue
            module = sys.modules.get(binding.module_name)
            if type(module) is not types.ModuleType:
                self._failures[name].add(f"entry_value_module_unavailable:{name}")
                continue
            dictionary = types.ModuleType.__dict__["__dict__"].__get__(module, types.ModuleType)
            if any(type(key) is not str for key in dictionary):
                self._failures[name].add(f"entry_value_module_dictionary_unavailable:{name}")
                continue
            module_file = dictionary.get("__file__")
            if type(module_file) is not str:
                self._failures[name].add(f"entry_value_module_origin_mismatch:{name}")
                continue
            try:
                origin_matches = Path(module_file).resolve(strict=True) == path
            except OSError:
                origin_matches = False
            module_name = dictionary.get("__name__")
            if not origin_matches or type(module_name) is not str or module_name != binding.module_name:
                self._failures[name].add(f"entry_value_module_origin_mismatch:{name}")
                continue
            actual = dictionary.get(name, _MISSING)
            if actual is _MISSING:
                self._fail(name, "missing")
                continue
            self._record(name, actual, {
                "point": "module_dictionary", "module_name": binding.module_name,
                "file": str(path), "source_sha256": binding.sha256,
                "definition_line": line,
            })

    def result(self) -> dict[str, Any]:
        verified = sorted(name for name in self._passed if not self._failures[name])
        gaps: list[str] = []
        for name in self._expected:
            if name not in verified:
                gaps.append(f"entry_value_assumption_unverified:{name}")
                gaps.extend(sorted(self._failures[name]))
        return {"gaps": gaps, "verified": verified, "observations": self._observations}
