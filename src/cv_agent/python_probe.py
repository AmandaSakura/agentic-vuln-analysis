"""Concrete input probes for a deliberately small Python function subset.

This interpreter never execs repository code, imports modules, or invokes host
callables. It is separate from the may-taint analysis in python_flow. Reaching
eval with two distinct injected expressions supports an input-control witness
under the recorded function-slice assumptions, not a full application exploit.
"""

from __future__ import annotations

import ast
import inspect
import textwrap
from dataclasses import dataclass

from .retrieval import RepositoryIndex


class UnsupportedProbe(ValueError):
    pass


@dataclass(frozen=True)
class _Request:
    pass


@dataclass(frozen=True)
class _InputMap:
    pass


class _Returned(Exception):
    def __init__(self, value):
        self.value = value


class _Witness(Exception):
    def __init__(self, path, line, trace):
        self.path, self.line, self.trace = path, line, tuple(trace)


class _Interpreter:
    def __init__(self, index, admitted, payload, sink_path, max_hops):
        self.index, self.admitted, self.payload = index, admitted, payload
        self.sink_path, self.max_hops = sink_path, max_hops
        self.steps = 0
        self.trace = []
        self.local_names = {}

    def tick(self):
        self.steps += 1
        if self.steps > 256:
            raise UnsupportedProbe("probe exceeded 256 interpreter steps")

    def function(self, path):
        if path not in self.admitted:
            raise UnsupportedProbe("callee is outside admitted code")
        doc = self.index.document(path)
        if doc is None or doc.language != "python" or doc.adapter_tier != "ast":
            raise UnsupportedProbe("probe requires Python AST function documents")
        if len(doc.text.encode("utf-8")) > 65_536:
            raise UnsupportedProbe("function exceeds probe source limit")
        tree = ast.parse(textwrap.dedent(doc.text))
        if len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef):
            raise UnsupportedProbe("probe supports one synchronous function per span")
        node = tree.body[0]
        if node.decorator_list or node.type_params or node.args.vararg or node.args.kwarg:
            raise UnsupportedProbe("decorators, generics and variadic parameters are unsupported")
        return doc, node

    def invoke(self, path, args, kwargs, depth=0):
        self.tick()
        if depth > self.max_hops:
            raise UnsupportedProbe("probe exceeded call depth")
        doc, node = self.function(path)
        parameters = []
        positional = [*node.args.posonlyargs, *node.args.args]
        defaults = [None] * (len(positional) - len(node.args.defaults)) + list(node.args.defaults)
        for arg, default in zip(positional, defaults):
            kind = inspect.Parameter.POSITIONAL_ONLY if arg in node.args.posonlyargs else inspect.Parameter.POSITIONAL_OR_KEYWORD
            parameters.append(inspect.Parameter(arg.arg, kind, default=self.default(default)))
        parameters.extend(
            inspect.Parameter(arg.arg, inspect.Parameter.KEYWORD_ONLY, default=self.default(default))
            for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults)
        )
        bound = inspect.Signature(parameters).bind(*args, **kwargs)
        bound.apply_defaults()
        environment = dict(bound.arguments)
        self.local_names[path] = {
            item.id for item in ast.walk(node) if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Store)
        }
        self.trace.append({"event": "enter", "path": path, "depth": depth})
        try:
            self.block(node.body, environment, doc, depth)
        except _Returned as result:
            return result.value
        return None

    @staticmethod
    def default(node):
        if node is None:
            return inspect.Parameter.empty
        if not isinstance(node, ast.Constant):
            raise UnsupportedProbe("only literal parameter defaults are supported")
        return node.value

    def block(self, statements, env, doc, depth):
        for node in statements:
            self.tick()
            if isinstance(node, ast.Return):
                raise _Returned(self.expression(node.value, env, doc, depth))
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(not isinstance(target, ast.Name) for target in targets) or node.value is None:
                    raise UnsupportedProbe("only assignments to local names are supported")
                value = self.expression(node.value, env, doc, depth)
                for target in targets:
                    env[target.id] = value
            elif isinstance(node, ast.Expr):
                self.expression(node.value, env, doc, depth)
            elif isinstance(node, ast.If):
                condition = self.expression(node.test, env, doc, depth)
                self.block(node.body if condition else node.orelse, env, doc, depth)
            elif not isinstance(node, ast.Pass):
                raise UnsupportedProbe(f"unsupported statement: {type(node).__name__}")

    def expression(self, node, env, doc, depth):
        self.tick()
        if node is None:
            return None
        if isinstance(node, ast.Constant) and type(node.value) in {str, int, bool, type(None)}:
            if isinstance(node.value, str) and len(node.value) > 4096:
                raise UnsupportedProbe("string exceeds probe value limit")
            return node.value
        if isinstance(node, ast.Name) and node.id in env:
            return env[node.id]
        if isinstance(node, ast.Attribute):
            receiver = self.expression(node.value, env, doc, depth)
            if isinstance(receiver, _Request) and node.attr in {"args", "query", "params", "headers", "cookies"}:
                return _InputMap()
        if isinstance(node, ast.Subscript):
            receiver = self.expression(node.value, env, doc, depth)
            key = self.expression(node.slice, env, doc, depth)
            if isinstance(receiver, _InputMap) and type(key) is str:
                self.trace.append({"event": "input", "path": doc.path, "line": node.lineno, "key": key})
                return self.payload
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub)):
            left, right = (self.expression(value, env, doc, depth) for value in (node.left, node.right))
            if type(left) is int and type(right) is int:
                return left + right if isinstance(node.op, ast.Add) else left - right
            if isinstance(node.op, ast.Add) and type(left) is str and type(right) is str and len(left) + len(right) <= 4096:
                return left + right
        if isinstance(node, ast.Compare) and len(node.ops) == 1 and isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
            left = self.expression(node.left, env, doc, depth)
            right = self.expression(node.comparators[0], env, doc, depth)
            return (left == right) if isinstance(node.ops[0], ast.Eq) else (left != right)
        if isinstance(node, ast.Call):
            if any(isinstance(arg, ast.Starred) for arg in node.args) or any(kw.arg is None for kw in node.keywords):
                raise UnsupportedProbe("argument expansion is unsupported")
            if len({kw.arg for kw in node.keywords}) != len(node.keywords):
                raise UnsupportedProbe("duplicate keyword arguments")
            name = ast.unparse(node.func)
            args = [self.expression(arg, env, doc, depth) for arg in node.args]
            kwargs = {kw.arg: self.expression(kw.value, env, doc, depth) for kw in node.keywords}
            if name.split(".")[0] in env or name.split(".")[0] in self.local_names.get(doc.path, set()):
                raise UnsupportedProbe("calls through local values are unsupported")
            if name in doc.defines:
                return self.invoke(doc.path, args, kwargs, depth + 1)
            targets = [
                target for path in self.index.graph_neighbors(doc.path, direction="forward")
                if (target := self.index.document(path)) is not None and name in target.defines
            ]
            if len(targets) == 1:
                return self.invoke(targets[0].path, args, kwargs, depth + 1)
            if targets or any(symbol.rsplit(".", 1)[-1] == name for symbol in doc.imports):
                raise UnsupportedProbe("ambiguous or unresolved imported call")
            if name == "eval" and name in doc.calls and len(args) == 1 and not kwargs and type(args[0]) is str:
                if args[0] == self.payload and (self.sink_path is None or doc.path == self.sink_path):
                    raise _Witness(doc.path, node.lineno, self.trace)
                # Interpret constant arithmetic without calling Python eval.
                return self.expression(ast.parse(args[0], mode="eval").body, {}, doc, depth)
            raise UnsupportedProbe(f"unsupported call: {name}")
        raise UnsupportedProbe(f"unsupported expression: {type(node).__name__}")


def probe_python_eval(index: RepositoryIndex, admitted: frozenset[str], source_path: str,
                      sink_path: str | None = None, max_hops: int = 4) -> dict:
    attempts = []
    witnesses = []
    for payload in ("(481516 + 2342)", "(271828 - 31415)"):
        interpreter = _Interpreter(index, admitted, payload, sink_path, max_hops)
        try:
            _, entry = interpreter.function(source_path)
            positional = [*entry.args.posonlyargs, *entry.args.args]
            if not positional or positional[0].arg not in {"request", "req"}:
                raise UnsupportedProbe("entry must accept request/req as its first parameter")
            interpreter.invoke(source_path, [_Request()], {})
            attempts.append({"input": payload, "outcome": "no witness"})
        except _Witness as witness:
            witnesses.append((witness.path, witness.line))
            attempts.append({"input": payload, "outcome": "input reached eval",
                             "sink_path": witness.path, "sink_line": witness.line,
                             "trace": witness.trace})
        except (UnsupportedProbe, SyntaxError, TypeError, ValueError, RecursionError) as error:
            attempts.append({"input": payload, "outcome": "unresolved", "reason": str(error)})
    confirmed = len(witnesses) == 2 and witnesses[0] == witnesses[1]
    return {
        "status": "CONFIRMED" if confirmed else "UNRESOLVED",
        "method": "bounded-concrete-input-probe",
        "scope": "admitted Python function slices; not a full application exploit",
        "assumptions": ["request fields model attacker-controlled strings", "unshadowed eval models the Python builtin"],
        "attempts": attempts,
        "summary": "Two different inputs reached the same eval argument." if confirmed else
                   "No two-input witness was established; this does not prove safety.",
    }
