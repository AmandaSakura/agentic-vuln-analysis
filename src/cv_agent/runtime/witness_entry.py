"""Qualify Python entries and their exact runtime function bindings.

The source-derived adapter permits one genuine Click command's direct callback.
It does not follow wrapper attributes or execute target descriptors.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from types import CodeType, FunctionType, MethodType, ModuleType
from typing import Any, Literal


EntryInvocation = Literal["instance_method", "function", "click_callback"]
_CLASS_DICTIONARY = type.__dict__["__dict__"]
_MODULE_DICTIONARY = ModuleType.__dict__["__dict__"]


@dataclass(frozen=True)
class SourceEntry:
    class_node: ast.ClassDef | None
    function: ast.FunctionDef
    invocation: EntryInvocation

    @property
    def qualified_name(self) -> str:
        return (f"{self.class_node.name}.{self.function.name}"
                if self.class_node is not None else self.function.name)

    @property
    def first_line(self) -> int:
        return min((node.lineno for node in self.function.decorator_list),
                   default=self.function.lineno)

    @property
    def last_line(self) -> int:
        return self.function.end_lineno


def source_entry(tree: ast.Module, symbol: str) -> SourceEntry:
    """Select a unique direct function or direct instance-method definition."""
    names = symbol.split(".")
    if len(names) == 1:
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name == names[0]]
        if len(functions) != 1:
            raise ValueError("entry_ast_span_mismatch")
        function = functions[0]
        return SourceEntry(None, function,
                           "click_callback" if function.decorator_list else "function")
    if len(names) != 2:
        raise ValueError("entry_ast_span_mismatch")
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)
               and node.name == names[0]]
    functions = [node for node in classes[0].body if isinstance(node, ast.FunctionDef)
                 and node.name == names[1]] if len(classes) == 1 else []
    if len(functions) != 1:
        raise ValueError("entry_ast_span_mismatch")
    if functions[0].decorator_list or classes[0].decorator_list:
        raise ValueError("entry_decorator_unsupported")
    return SourceEntry(classes[0], functions[0], "instance_method")


def compiler_constants(code: CodeType) -> bool:
    """Reject injected constants before CodeType equality or hashing."""
    def immutable(value: Any, depth: int) -> bool:
        if depth > 64:
            return False
        kind = type(value)
        if any(kind is builtin for builtin in (
                type(None), bool, int, float, complex, str, bytes, type(Ellipsis))):
            return True
        if kind is tuple or kind is frozenset:
            return all(immutable(item, depth + 1) for item in value)
        if kind is CodeType:
            return all(immutable(item, depth + 1) for item in value.co_consts)
        return False
    return type(code) is CodeType and all(immutable(item, 0) for item in code.co_consts)


def identical_code(actual: CodeType, expected: CodeType) -> bool:
    # Code equality covers bytecode, constants and name tables; location tables
    # bind a copy to the compiled source span rather than just its function name.
    return (compiler_constants(actual) and compiler_constants(expected)
            and actual == expected and actual.co_filename == expected.co_filename
            and actual.co_linetable == expected.co_linetable
            and actual.co_exceptiontable == expected.co_exceptiontable)


def _codes(code: CodeType):
    yield code
    for value in code.co_consts:
        if type(value) is CodeType:
            yield from _codes(value)


def source_entry_code(raw: bytes, filename: Path, symbol: str,
                      first_line: int) -> CodeType:
    """Compile the admitted bytes before any target module can rebind globals."""
    compiled = compile(raw, str(filename), "exec", dont_inherit=True, optimize=0)
    matches = [code for code in _codes(compiled)
               if code.co_qualname == symbol and code.co_firstlineno == first_line]
    if len(matches) != 1:
        raise ValueError("entry_source_code_nonunique")
    return matches[0]


def module_dictionary(module: Any) -> dict[str, Any]:
    if type(module) is not ModuleType:
        raise ValueError("entry_module_binding_unsupported")
    return _MODULE_DICTIONARY.__get__(module, ModuleType)


def class_dictionary(cls: Any):
    try:
        return _CLASS_DICTIONARY.__get__(cls, type)
    except TypeError as error:
        raise ValueError("entry_class_binding_unsupported") from error


def qualified_function(function: Any, globals_dictionary: dict[str, Any],
                       template: CodeType) -> FunctionType:
    if type(function) is not FunctionType:
        raise ValueError("entry_function_binding_unsupported")
    if function.__globals__ is not globals_dictionary:
        raise ValueError("entry_function_globals_mismatch")
    if not identical_code(function.__code__, template):
        raise ValueError("entry_function_code_mismatch")
    return function


def click_callback(command: Any, command_type: type,
                   globals_dictionary: dict[str, Any], template: CodeType) -> FunctionType:
    if type(command) is not command_type:
        raise ValueError("entry_click_command_type_mismatch")
    # Only the exact trusted Command type can reach this dictionary access.
    callback = object.__getattribute__(command, "__dict__").get("callback")
    return qualified_function(callback, globals_dictionary, template)


def bound_instance_method(target: Any, name: str, function: FunctionType) -> MethodType:
    bound = getattr(target, name)
    if (type(bound) is not MethodType or bound.__func__ is not function
            or bound.__self__ is not target):
        raise ValueError("entry_bound_method_mismatch")
    return bound
