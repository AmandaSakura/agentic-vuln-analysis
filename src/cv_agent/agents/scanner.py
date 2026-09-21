from __future__ import annotations

import re
import ast
from collections import defaultdict
from collections.abc import Iterable

from cv_agent.domain.types import Candidate, CodeDocument


class StaticScanner:
    """Small deterministic V0 candidate generator used before agent reasoning."""

    rules = {
        "command-execution": re.compile(r"subprocess\.|Runtime\.getRuntime\(\)\.exec|shell\s*=\s*True", re.IGNORECASE),
        "dynamic-evaluation": re.compile(r"(?<![\w.])(?:eval|exec)\s*\(", re.IGNORECASE),
        "database-operation": re.compile(r"\.(?:executeQuery|delete)\s*\(", re.IGNORECASE),
    }
    rule_names = (*rules, 'template-operation', 'authorization-boundary',
                  'dynamic-attribute-access', 'process-control')

    scopes = {
        'command-execution': 'Determine whether attacker-controlled input can change command execution semantics at this operation; safe argument passing alone is not command injection.',
        'dynamic-evaluation': 'Determine whether attacker-controlled input reaches dynamic code evaluation at this operation, accounting for bindings, reachability and sanitization.',
        'database-operation': 'Determine whether untrusted input can alter a database query or unauthorized data operation here; parameterized value binding alone is not injection.',
        'template-operation': 'Determine whether untrusted template content can access unintended attributes, objects or executable behavior through this operation; ordinary formatting alone is not a vulnerability.',
        'authorization-boundary': 'Determine the intended principal, action and resource or tenant boundary for this route, and whether a caller can bypass required enforcement. A public endpoint or absence of a recognized guard alone does not establish an authorization flaw.',
        'dynamic-attribute-access': 'Determine whether an attacker controls attribute names reaching reflection and can access or modify objects outside the intended boundary; inspect name restrictions, object scope and reachability. Dynamic reflection alone is not a vulnerability.',
        'process-control': 'Determine whether an external caller can reach process termination or signaling without required authorization or isolation. Authorized local shutdown and maintenance operations alone are not vulnerabilities.',
    }

    @staticmethod
    def _python_tree(document: CodeDocument) -> ast.AST:
        # Dedenting a method whose triple-quoted string contains column-zero
        # text leaves an invalid indented def. A wrapper preserves literal bytes.
        if document.text.startswith((' ', '\t')) and '::<module>@' not in document.path:
            return ast.increment_lineno(ast.parse('if True:\n' + document.text), -1)
        return ast.parse(document.text)

    @staticmethod
    def _python_calls(document: CodeDocument) -> dict[int, set[str]]:
        tree = StaticScanner._python_tree(document)
        aliases = dict(document.import_aliases)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for item in node.names:
                    aliases[item.asname or item.name.split('.')[0]] = item.name if item.asname else item.name.split('.')[0]
            elif isinstance(node, ast.ImportFrom) and node.module:
                for item in node.names:
                    aliases[item.asname or item.name] = f'{node.module}.{item.name}'
        found: dict[int, set[str]] = defaultdict(set)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    if (isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute)
                            and decorator.func.attr in {'get', 'post', 'put', 'patch', 'delete', 'route', 'api_route'}
                            and decorator.args and isinstance(decorator.args[0], ast.Constant)
                            and isinstance(decorator.args[0].value, str)):
                        found[decorator.lineno].add('authorization-boundary')
            if not isinstance(node, ast.Call):
                continue
            target = node.func
            parts = []
            while isinstance(target, ast.Attribute):
                parts.insert(0, target.attr)
                target = target.value
            if isinstance(target, ast.Name):
                parts.insert(0, aliases.get(target.id, target.id))
            symbol = '.'.join(parts)
            if symbol in {'eval', 'exec', 'builtins.eval', 'builtins.exec'}:
                found[node.lineno].add('dynamic-evaluation')
            if symbol in {'getattr', 'setattr', 'delattr', 'builtins.getattr', 'builtins.setattr', 'builtins.delattr'}:
                if len(node.args) >= 2 and not isinstance(node.args[1], ast.Constant):
                    found[node.lineno].add('dynamic-attribute-access')
            if symbol in {'os._exit', 'os.kill', 'os.killpg', 'sys.exit', 'signal.raise_signal'}:
                found[node.lineno].add('process-control')
            if symbol in {'os.system', 'os.popen'} or symbol in {
                f'subprocess.{name}' for name in
                ('run', 'Popen', 'call', 'check_call', 'check_output', 'getoutput', 'getstatusoutput')
            }:
                found[node.lineno].add('command-execution')
            if isinstance(node.func, ast.Attribute) and node.func.attr in {
                'execute', 'executemany', 'executescript', 'executeQuery', 'delete'
            }:
                found[node.lineno].add('database-operation')
        for line in StaticScanner._template_lines(document):
            found[line].add('template-operation')
        return found

    @staticmethod
    def _template_lines(document: CodeDocument) -> set[int]:
        if document.language != 'python' or document.adapter_tier != 'ast':
            return set()
        try:
            tree = StaticScanner._python_tree(document)
        except SyntaxError:
            return set()
        lines = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            target = node.func
            direct = isinstance(target, ast.Attribute) and target.attr in {
                'format', 'format_map', 'vformat', 'render', 'render_async', 'from_template'}
            # Dynamic formatter dispatch cannot be resolved here. It is only a
            # candidate heuristic, independent of repository names or sink labels.
            dispatch = isinstance(target, ast.Subscript) and any(
                word in ast.unparse(target.value).lower() for word in ('format', 'render', 'template'))
            if direct or dispatch:
                lines.add(node.lineno)
        return lines

    def scan(self, repository_id: str, documents: Iterable[CodeDocument]) -> list[Candidate]:
        candidates: list[Candidate] = []
        seen = set()
        # Prefer the smallest enclosing span when nested functions overlap.
        ordered = sorted(documents, key=lambda doc: (
            len(doc.text.splitlines()), '::<module>@' in doc.path, doc.path))
        for document in ordered:
            python_calls = (self._python_calls(document)
                            if document.language == 'python' and document.adapter_tier == 'ast'
                            else None)
            for line_number, line in enumerate(document.text.splitlines(), start=1):
                matches = (sorted(python_calls.get(line_number, ())) if python_calls is not None
                           else [name for name, pattern in self.rules.items() if pattern.search(line)])
                for rule_name in matches:
                    span = re.search(r"::.+@(\d+)(?:-\d+)?(?:#\d+-\d+)?$", document.path)
                    source_line = int(span.group(1)) + line_number - 1 if span else line_number
                    key = (document.path.split('::', 1)[0], source_line, rule_name)
                    if key in seen:
                        continue
                    seen.add(key)
                    candidate_id = f"{repository_id}:{document.path}:{source_line}:{rule_name}"
                    candidates.append(
                        Candidate(
                            candidate_id=candidate_id,
                            case_id=candidate_id,
                            repository_id=repository_id,
                            path=document.path,
                            line=source_line,
                            query=f"{rule_name} {line.strip()}",
                            analysis_scope=self.scopes[rule_name],
                            metadata={"rule": rule_name, "span_relative_line": line_number,
                                      "evidence_kind": "static_candidate"},
                        )
                    )
        return sorted(candidates, key=lambda c: (c.path.split('::', 1)[0], c.line, c.metadata['rule']))
