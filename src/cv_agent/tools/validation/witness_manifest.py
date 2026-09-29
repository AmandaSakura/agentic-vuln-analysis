"""Generate a proposed witness call from a bound subject and data-only gaps.

Construction recipes select inputs; they do not discharge runtime assumptions.
Source identity, process policy and probe/control values never come from a model.
"""
from __future__ import annotations

import ast
import hashlib
import json
import math
import re
import tempfile
import tokenize
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any, Literal

from pydantic import field_validator, model_validator

from cv_agent.domain.evidence import ValidationSubject
from cv_agent.domain.types import FrozenModel
from cv_agent.evaluation.diagnostics.isolation_read_policy import IsolationReadGrant
from cv_agent.retrieval import RepositoryIndex
from cv_agent.runtime.witness_resources import WitnessResourceProfile
from cv_agent.runtime.witness_entry import source_entry
from cv_agent.tools.identity import repository_source_digest
from cv_agent.tools.validation.witness_scenario import WitnessScenarioHypothesis

if TYPE_CHECKING:
    from cv_agent.evaluation.diagnostics.bounded_execution_witness import SourceFileBinding, WitnessManifest

_NAME = re.compile(r"[A-Za-z_][A-Za-z_0-9]*\Z")
_SPAN = re.compile(r"(.+)::([A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)?)@([0-9]+)-([0-9]+)\Z")
_UNKNOWN = object()
_RESERVED = frozenset({
    "label", "labels", "status", "raw_status", "verdict", "vulnerable", "ground_truth", "truth",
    "case_id", "case_ids", "candidate_id", "repository_id", "stub", "stubs", "mock", "mocks",
    "monkeypatch", "subject", "source", "source_modules", "source_digest", "sha256", "checkout_root",
    "module_name", "class_name", "method_name", "entry_relative_path", "entry_first_line",
    "entry_file_sha256", "probe", "probe_argument", "probe_path", "probe_nonce", "probe_directory_prefix",
    "nonce", "control", "control_path", "control_nonce", "bash_path", "python_executable",
    "resource_profile", "read_grants", "runtime_root", "import_root", "security", "constructor_args", "call_args", "call_kwargs",
})
_LABELS = frozenset({"VULNERABLE", "SAFE", "ABSTAIN", "CONFIRMED", "REFUTED", "UNRESOLVED"})


def _json_data(value: Any, *, reject_metadata: bool, depth: int = 0) -> None:
    kind = type(value)
    if depth > 16:
        raise ValueError("JSON nesting exceeds supplement limit")
    if kind is str:
        if reject_metadata and value.upper() in _LABELS:
            raise ValueError("supplement cannot carry result labels or statuses")
        return
    if kind in (type(None), bool, int):
        return
    if kind is float and math.isfinite(value):
        return
    if kind is list:
        if len(value) > 1024:
            raise ValueError("JSON list exceeds supplement limit")
        for item in value:
            _json_data(item, reject_metadata=reject_metadata, depth=depth + 1)
        return
    if kind is dict:
        if len(value) > 1024 or any(type(key) is not str for key in value):
            raise ValueError("supplement dictionaries require bounded string keys")
        for key, item in value.items():
            normalized = key.lower().replace("-", "_").replace(" ", "_")
            if reject_metadata and (normalized in _RESERVED or normalized.startswith("expected_")):
                raise ValueError("supplement cannot carry labels, source identity, stubs or process policy")
            _json_data(item, reject_metadata=reject_metadata, depth=depth + 1)
        return
    raise ValueError("supplement values must be plain finite JSON data")


def _safe_relative(value: str) -> bool:
    if type(value) is not str:
        return False
    path = PurePosixPath(value)
    return bool(value and not path.is_absolute() and str(path) == value
                and all(part not in {".", ".."} for part in path.parts) and "\\" not in value)


class WitnessSupplement(FrozenModel):
    constructor_parameters: dict[str, Any]
    precondition_files: dict[str, str]
    scenario_hypothesis: WitnessScenarioHypothesis | None = None

    @field_validator("constructor_parameters", mode="before")
    @classmethod
    def validate_constructor(cls, value: Any) -> Any:
        if type(value) is not dict or any(type(key) is not str or not _NAME.fullmatch(key) for key in value):
            raise ValueError("constructor supplement must map simple parameter names to JSON values")
        _json_data(value, reject_metadata=True)
        return value

    @field_validator("precondition_files", mode="before")
    @classmethod
    def validate_files(cls, value: Any) -> Any:
        if type(value) is not dict or len(value) > 64:
            raise ValueError("precondition files must be a bounded text mapping")
        if any(not _safe_relative(name) or type(text) is not str for name, text in value.items()):
            raise ValueError("precondition files must be relative paths and literal text")
        _json_data(value, reject_metadata=True)
        if sum(len(text.encode("utf-8")) for text in value.values()) > 1_000_000:
            raise ValueError("precondition text exceeds layout limit")
        return value

    @model_validator(mode="after")
    def classified_data_only(self) -> WitnessSupplement:
        if self.scenario_hypothesis is not None and (self.constructor_parameters or self.precondition_files):
            raise ValueError("model scenarios cannot mix unclassified constructor or file supplements")
        return self


@dataclass(frozen=True)
class WitnessExecutionContext:
    checkout_root: Path
    python_executable: Path | None = None
    import_root: str = "."
    resource_profile: WitnessResourceProfile = field(default_factory=WitnessResourceProfile.fixture_default)
    read_grants: tuple[IsolationReadGrant, ...] = ()
    runtime_root: Path = field(default_factory=lambda: Path(tempfile.gettempdir()) / "cv-agent-witness")
    dataset_scenario: WitnessScenarioHypothesis | None = None
    response_mode: Literal["full", "compact"] = "full"

    def __post_init__(self) -> None:
        if type(self.response_mode) is not str or self.response_mode not in {"full", "compact"}:
            raise ValueError("witness response_mode must be full or compact")


@dataclass(frozen=True)
class ManifestDraft:
    manifest: WitnessManifest | None
    missing_constructor_parameters: tuple[str, ...]
    gaps: tuple[str, ...]
    generated: dict[str, Any]
    bound_fields: dict[str, Any] = field(default_factory=dict, repr=False)


def qualify_source_module(relative_path: str, import_root: str = ".") -> str | None:
    if not _safe_relative(relative_path) or not relative_path.endswith(".py"):
        return None
    path = PurePosixPath(relative_path)
    if import_root != ".":
        if not _safe_relative(import_root):
            return None
        try:
            path = path.relative_to(PurePosixPath(import_root))
        except ValueError:
            return None
    parts = list(path.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts) if parts and all(_NAME.fullmatch(part) for part in parts) else None


def _literal(node: ast.AST | None) -> Any:
    if isinstance(node, ast.Constant) and type(node.value) in (type(None), bool, int, float, str):
        try:
            _json_data(node.value, reject_metadata=False)
        except ValueError:
            return _UNKNOWN
        return node.value
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd)):
        value = _literal(node.operand)
        return (-value if isinstance(node.op, ast.USub) else value) if type(value) in (int, float) else _UNKNOWN
    if isinstance(node, ast.List):
        values = [_literal(item) for item in node.elts]
        return values if all(item is not _UNKNOWN for item in values) else _UNKNOWN
    if isinstance(node, ast.Dict):
        keys = [_literal(item) for item in node.keys]
        values = [_literal(item) for item in node.values]
        return dict(zip(keys, values)) if all(type(key) is str for key in keys) and all(value is not _UNKNOWN for value in values) else _UNKNOWN
    return _UNKNOWN


def _same(a: Any, b: Any) -> bool:
    return type(a) is type(b) and json.dumps(a, sort_keys=True, allow_nan=False) == json.dumps(b, sort_keys=True, allow_nan=False)


def _inventory(index: RepositoryIndex, subject: ValidationSubject, context: WitnessExecutionContext):
    from cv_agent.evaluation.diagnostics.bounded_execution_witness import SourceFileBinding
    root = context.checkout_root.resolve()
    groups: dict[str, list[Any]] = {}
    for document in index.documents.values():
        relative = document.path.split("::", 1)[0]
        if relative.endswith(".py"):
            groups.setdefault(relative, []).append(document)
    bindings: list[SourceFileBinding] = []
    trees: dict[str, ast.Module] = {}
    texts: dict[str, str] = {}
    gaps: list[str] = []
    seen: set[str] = set()
    for relative, documents in sorted(groups.items()):
        module = qualify_source_module(relative, context.import_root)
        if module is None:
            continue
        try:
            path = root / relative
            path.resolve(strict=True).relative_to(root)
            raw = path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            with tokenize.open(path) as stream:
                text = stream.read()
            tree = ast.parse(text, filename=relative)
        except (OSError, ValueError, UnicodeError, SyntaxError):
            gaps.append(f"source_inventory_unavailable:{relative}")
            continue
        full_documents = [doc for doc in documents if "::<module>@" in doc.path]
        if any(doc.repository_id != subject.repository_id for doc in documents):
            gaps.append(f"source_repository_mismatch:{relative}")
            continue
        if any(doc.source_sha256 is not None and doc.source_sha256 != digest for doc in documents):
            gaps.append(f"indexed_source_digest_mismatch:{relative}")
            continue
        if full_documents:
            if any(doc.text != text for doc in full_documents):
                gaps.append(f"indexed_source_text_mismatch:{relative}")
                continue
        elif not all(doc.source_sha256 == digest for doc in documents):
            gaps.append(f"indexed_full_source_identity_missing:{relative}")
            continue
        if module in seen:
            gaps.append(f"source_module_nonunique:{module}")
            continue
        seen.add(module)
        bindings.append(SourceFileBinding(module_name=module, relative_path=relative, sha256=digest))
        trees[module] = tree
        texts[relative] = text
    return tuple(bindings), trees, texts, gaps


def _module_stores(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    is_function = isinstance(tree, (ast.FunctionDef, ast.AsyncFunctionDef))
    direct_imports = {id(node) for node in getattr(tree, 'body', ())
                      if isinstance(node, (ast.Import, ast.ImportFrom))}
    def visit(node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            if hasattr(node, 'name'):
                names.add(node.name)
            return
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
        if isinstance(node, (ast.Import, ast.ImportFrom)) and (is_function or id(node) not in direct_imports):
            names.update(item.asname or item.name.split('.', 1)[0] for item in node.names)
        for child in ast.iter_child_nodes(node):
            visit(child)
    if is_function:
        for statement in tree.body:
            visit(statement)
    else:
        visit(tree)
    return names


def _literal_constant(expression: ast.AST, entry_tree: ast.Module, entry_module: str,
                      trees: dict[str, ast.Module], constructor: ast.FunctionDef | None,
                      method: ast.FunctionDef) -> Any:
    direct = _literal(expression)
    if direct is not _UNKNOWN:
        return direct
    if not isinstance(expression, ast.Attribute) or not isinstance(expression.value, ast.Name):
        return _UNKNOWN
    alias = expression.value.id
    if alias in _module_stores(entry_tree):
        return _UNKNOWN
    for function in (constructor, method):
        if function is not None:
            params = [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]
            if alias in {arg.arg for arg in params} or alias in _module_stores(function):
                return _UNKNOWN
    targets: list[str] = []
    for node in entry_tree.body:
        if isinstance(node, ast.Import):
            for item in node.names:
                if item.asname == alias or (item.asname is None and item.name == alias):
                    targets.append(item.name)
        elif isinstance(node, ast.ImportFrom):
            prefix = node.module or ""
            if node.level:
                package = entry_module.split(".")[:-1]
                if node.level > len(package) + 1:
                    continue
                prefix = ".".join([*package[:len(package) - node.level + 1], *([prefix] if prefix else [])])
            for item in node.names:
                if (item.asname or item.name) == alias and item.name != "*":
                    targets.append(".".join(part for part in (prefix, item.name) if part))
    if len(targets) != 1 or targets[0] not in trees:
        return _UNKNOWN
    package, _, child_name = targets[0].rpartition('.')
    if package in trees:
        parent = trees[package]
        if child_name in _module_stores(parent) or any(isinstance(node, ast.FunctionDef) and node.name == '__getattr__' for node in parent.body):
            return _UNKNOWN
    target = trees[targets[0]]
    assignments: list[ast.AST] = []
    def visit(node: ast.AST):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            if getattr(node, 'name', None) == expression.attr:
                assignments.append(node)
            return
        if isinstance(node, (ast.Import, ast.ImportFrom)) and any((item.asname or item.name.split('.', 1)[0]) == expression.attr for item in node.names):
            assignments.append(node)
        if isinstance(node, ast.Name) and node.id == expression.attr and isinstance(node.ctx, (ast.Store, ast.Del)):
            assignments.append(node)
        for child in ast.iter_child_nodes(node):
            visit(child)
    visit(target)
    direct_assignments = [node for node in target.body if
        (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
         and node.targets[0].id == expression.attr) or
        (isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == expression.attr)]
    if len(assignments) != 1 or len(direct_assignments) != 1:
        return _UNKNOWN
    return _literal(direct_assignments[0].value)


def _signature(function: ast.FunctionDef, *, constructor: bool, receiver: bool = True):
    positional = [*function.args.posonlyargs, *function.args.args]
    names = positional + list(function.args.kwonlyargs)
    if receiver and (not positional or positional[0].arg != "self"):
        return [], {}, set(), ["constructor_instance_signature_unsupported" if constructor else "entry_instance_signature_unsupported"]
    defaults = dict(zip((arg.arg for arg in positional[-len(function.args.defaults):]), function.args.defaults)) if function.args.defaults else {}
    defaults.update({arg.arg: value for arg, value in zip(function.args.kwonlyargs, function.args.kw_defaults) if value is not None})
    gaps = []
    if function.args.vararg:
        gaps.append("constructor_variadic_unsupported" if constructor else "entry_variadic_unsupported")
    if function.args.kwarg:
        key = function.args.kwarg.arg
        if any(isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id == key for node in ast.walk(function)):
            gaps.append("constructor_variadic_required_unsupported" if constructor else "entry_variadic_required_unsupported")
    offset = 1 if receiver else 0
    return [arg.arg for arg in names[offset:]], defaults, {arg.arg for arg in function.args.posonlyargs[offset:]}, gaps


def _constructor_recipe(constructor: ast.FunctionDef, method: ast.FunctionDef, tree: ast.Module,
                        module: str, trees: dict[str, ast.Module], subject: ValidationSubject,
                        names: list[str], defaults: dict[str, ast.AST]):
    mappings: dict[str, list[ast.AST]] = {}
    direct = {id(node) for node in constructor.body}
    def own_nodes(node: ast.AST):
        yield node
        for child in ast.iter_child_nodes(node):
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                yield from own_nodes(child)
    for node in own_nodes(constructor):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name) and target.value.id == "self":
                    mappings.setdefault(target.attr, []).append(node)
    requirements = {key[5:]: value for key, value in subject.entry_value_assumptions.items() if key.startswith("self.") and _NAME.fullmatch(key[5:])}
    for text, expected in subject.entry_condition_assumptions.items():
        try:
            expr = ast.parse(text, mode="eval").body
        except SyntaxError:
            continue
        if not isinstance(expr, ast.Compare) or len(expr.ops) != 1 or len(expr.comparators) != 1:
            continue
        if not ((isinstance(expr.ops[0], ast.NotEq) and expected is False) or
                (isinstance(expr.ops[0], ast.Eq) and expected is True)):
            continue
        left = expr.left
        if not isinstance(left, ast.Attribute) or not isinstance(left.value, ast.Name) or left.value.id != "self":
            continue
        value = _literal_constant(expr.comparators[0], tree, module, trees, constructor, method)
        if value is not _UNKNOWN:
            requirements.setdefault(left.attr, value)
    supplied: dict[str, Any] = {}
    recipes: list[dict[str, Any]] = []
    for attribute, expected in requirements.items():
        assignments = mappings.get(attribute, [])
        if len(assignments) != 1 or id(assignments[0]) not in direct:
            continue
        expression = assignments[0].value
        fallback = _UNKNOWN
        if isinstance(expression, ast.Name):
            parameter = expression.id
        elif (isinstance(expression, ast.BoolOp) and isinstance(expression.op, ast.Or) and len(expression.values) == 2
              and isinstance(expression.values[0], ast.Name)):
            parameter = expression.values[0].id
            fallback = _literal(expression.values[1])
            if fallback is _UNKNOWN:
                continue
        else:
            continue
        if parameter not in names:
            continue
        try:
            _json_data(expected, reject_metadata=False)
        except ValueError:
            continue
        default = _literal(defaults.get(parameter))
        omit = default is not _UNKNOWN and _same(default, expected)
        if fallback is not _UNKNOWN and not expected and not _same(expected, fallback):
            continue
        if parameter in supplied and not _same(supplied[parameter], expected):
            supplied.pop(parameter)
            continue
        if not omit:
            supplied[parameter] = expected
        recipes.append({"parameter": parameter, "attribute": attribute,
                        "kind": "primitive_or" if fallback is not _UNKNOWN else "direct_assignment",
                        "uses_source_default": omit, "runtime_verification_required": True})
    return supplied, recipes


def build_witness_manifest(index: RepositoryIndex, subject: ValidationSubject,
                           context: WitnessExecutionContext, supplement: WitnessSupplement, *,
                           scenario: WitnessScenarioHypothesis | None = None,
                           scenario_origin: str | None = None,
                           original_subject: ValidationSubject | None = None) -> ManifestDraft:
    from cv_agent.evaluation.diagnostics.bounded_execution_witness import WitnessManifest
    WitnessSupplement.model_validate(supplement.model_dump())
    generated: dict[str, Any] = {"entry_qualified": False, "input_profile": "existing_local_directory"}
    gaps: list[str] = []
    if subject.property_id != "command-execution":
        gaps.append("unsupported_witness_property")
    if subject.source_digest != repository_source_digest(index):
        gaps.append("subject_source_digest_mismatch")
    match = _SPAN.fullmatch(subject.entry_path)
    document = index.documents.get(subject.entry_path)
    if match is None or document is None or document.adapter_tier != "ast":
        gaps.append("entry_document_not_qualified")
    if gaps:
        return ManifestDraft(None, (), tuple(gaps), generated)
    bindings, trees, texts, source_gaps = _inventory(index, subject, context)
    gaps.extend(source_gaps)
    relative, qualified, first_text, last_text = match.groups()
    module = qualify_source_module(relative, context.import_root)
    first, last = int(first_text), int(last_text)
    if subject.entry_line != first:
        gaps.append("candidate_scope_unbound")
    if module not in trees or subject.entry_line is None or not first <= subject.entry_line <= last:
        gaps.append("entry_source_or_line_mismatch")
    if gaps:
        return ManifestDraft(None, (), tuple(gaps), generated)
    tree = trees[module]
    try:
        entry = source_entry(tree, qualified)
    except ValueError as error:
        return ManifestDraft(None, (), (str(error),), generated)
    cls, method = entry.class_node, entry.function
    class_name, method_name = (cls.name if cls is not None else None), method.name
    if entry.first_line != first or entry.last_line != last:
        gaps.append("entry_ast_span_mismatch")
    elif document.text != ''.join(texts[relative].splitlines(keepends=True)[first - 1:last]):
        gaps.append("entry_index_text_mismatch")
    if gaps:
        return ManifestDraft(None, (), tuple(gaps), generated)
    generated.update(entry_qualified=True, entry={"module_name": module, "class_name": class_name,
                     "method_name": method_name, "relative_path": relative, "first_line": first,
                     "invocation": entry.invocation})
    call_names, call_defaults, call_positional, call_gaps = _signature(
        method, constructor=False, receiver=cls is not None)
    gaps.extend(call_gaps)
    if len(subject.input_parameters) != 1 or subject.input_parameters[0] not in call_names:
        gaps.append("probe_input_parameter_not_unique")
        return ManifestDraft(None, (), tuple(gaps), generated)
    probe = subject.input_parameters[0]
    if probe in call_positional:
        gaps.append("probe_parameter_positional_only_unsupported")
    call_values: dict[str, Any] = {}
    for name, value in subject.entry_value_assumptions.items():
        if name in call_names and name != probe:
            try:
                _json_data(value, reject_metadata=False)
                call_values[name] = value
            except ValueError:
                gaps.append(f"entry_argument_unsupported_value:{name}")
    for name, value in subject.entry_boolean_arguments.items():
        if name not in call_names or name == probe:
            gaps.append(f"entry_boolean_parameter_missing:{name}")
        elif name in call_values and not _same(call_values[name], value):
            gaps.append(f"entry_argument_assumption_conflict:{name}")
        else:
            call_values[name] = value
    for name in call_names:
        if name != probe and name not in call_values and name not in call_defaults:
            gaps.append(f"entry_argument_missing:{name}")
    constructor_nodes = [node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "__init__"] if cls is not None else []
    ctor_names: list[str] = []
    ctor_defaults: dict[str, ast.AST] = {}
    ctor_positional: set[str] = set()
    ctor_values: dict[str, Any] = {}
    recipes: list[dict[str, Any]] = []
    if len(constructor_nodes) > 1:
        gaps.append("constructor_definition_nonunique")
    elif constructor_nodes:
        constructor = constructor_nodes[0]
        ctor_names, ctor_defaults, ctor_positional, ctor_gaps = _signature(constructor, constructor=True)
        gaps.extend(ctor_gaps)
        if constructor.decorator_list:
            gaps.append("constructor_decorator_unsupported")
        ctor_values, recipes = _constructor_recipe(constructor, method, tree, module, trees, subject, ctor_names, ctor_defaults)
    elif cls is not None and cls.bases:
        gaps.append("inherited_constructor_unsupported")
    missing = tuple(name for name in ctor_names if name not in ctor_values and name not in ctor_defaults)
    scenario_constructor = scenario.values("constructor_parameters") if scenario_origin == "model_proposed" else {}
    unexpected = set(scenario_constructor) - set(ctor_names)
    if unexpected:
        gaps.extend(f"scenario_constructor_parameter_missing:{name}" for name in sorted(unexpected))
    for name, value in scenario_constructor.items():
        if name in ctor_values and not _same(ctor_values[name], value):
            gaps.append(f"scenario_constructor_assumption_conflict:{name}")
        elif name in ctor_names:
            ctor_values[name] = value
    unexpected = set(supplement.constructor_parameters) - set(missing)
    if unexpected:
        raise ValueError("constructor supplement contains unrequested parameters")
    ctor_values.update(supplement.constructor_parameters)
    missing = tuple(name for name in missing if name not in ctor_values)
    gaps.extend(f"constructor_parameter_missing:{name}" for name in missing)
    generated.update(call_parameters=call_names, call_kwargs={name: value for name, value in call_values.items() if name not in call_positional},
                     constructor_parameters=ctor_names, constructor_kwargs={name: value for name, value in ctor_values.items() if name not in ctor_positional},
                     constructor_recipes=recipes, missing_constructor_parameters=list(missing))
    entry_binding = next(binding for binding in bindings if binding.module_name == module)
    bound = {"subject": subject, "checkout_root": context.checkout_root.resolve(), "module_name": module,
             "class_name": class_name, "method_name": method_name, "entry_invocation": entry.invocation, "entry_relative_path": relative,
             "entry_file_sha256": entry_binding.sha256, "entry_first_line": first, "source_modules": bindings,
             "import_root": context.import_root,
             "python_executable": context.python_executable, "resource_profile": context.resource_profile,
             "probe_argument": probe, "recorder_command": "cv_witness_recorder", "probe_directory_prefix": "model"}
    if scenario is not None:
        bound.update(original_subject=original_subject, scenario_hypothesis=scenario,
                     scenario_origin=scenario_origin)
    if gaps:
        return ManifestDraft(None, missing, tuple(dict.fromkeys(gaps)), generated, bound)
    def ordered_call(names, positional, values, defaults):
        args = []
        for name in names:
            if name in positional:
                if name in values:
                    args.append(values[name])
                elif defaults.get(name) is not None and _literal(defaults[name]) is not _UNKNOWN:
                    args.append(_literal(defaults[name]))
                else:
                    raise ValueError("positional-only defaults cannot be generated without literal data")
        return tuple(args), {name: value for name, value in values.items() if name not in positional}
    try:
        call_args, call_kwargs = ordered_call(call_names, call_positional, call_values, call_defaults)
        ctor_args, ctor_kwargs = ordered_call(ctor_names, ctor_positional, ctor_values, ctor_defaults)
        manifest = WitnessManifest(**bound, call_args=call_args, call_kwargs=call_kwargs,
                                   constructor_args=ctor_args, constructor_kwargs=ctor_kwargs,
                                   precondition_files=(scenario.values("precondition_files")
                                                       if scenario_origin == "model_proposed"
                                                       else supplement.precondition_files))
    except ValueError as error:
        return ManifestDraft(None, (), (f"manifest_call_shape_unsupported:{error}",), generated, bound)
    return ManifestDraft(manifest, (), (), generated, bound)
