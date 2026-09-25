"""Static source, sink and guard patterns with scoped inspection tools."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, cast

from cv_agent.tools.registry import ToolExecutionScope
from cv_agent.domain.evidence import ToolObservation, ValidationStatus
from cv_agent.retrieval import RepositoryIndex
from cv_agent.domain.types import CodeDocument, FrozenModel
from cv_agent.tools.validation.models import FindReferencesInput, PathInput
from cv_agent.tools.validation.permissions import _chmod_permission_assessment
from cv_agent.tools.validation.scope import _admitted_document, _json_content, _scope_documents


@dataclass(frozen=True)
class PatternRule:
    category: str
    pattern: re.Pattern[str]


SOURCE_RULES = (
    PatternRule(
        "http-input",
        re.compile(
            r"\b(?:request|req)\.(?:args|query|body|params|headers|cookies)\b|"
            r"\brequest\.get(?:Header|Headers|Parameter|ParameterMap|ParameterValues|"
            r"Cookies?|QueryString)\s*\(|"
            r"\.getTheParameter\s*\(|"
            r"\br\.URL\.Query\s*\(|\bmux\.Vars\s*\(|\bctx\.Param\s*\(",
            re.IGNORECASE,
        ),
    ),
    PatternRule(
        "process-input",
        re.compile(r"\b(?:input\s*\(|sys\.argv\b|os\.environ\b|process\.env\b)"),
    ),
)


SINK_RULES = (
    PatternRule("code-execution", re.compile(r"(?<![\w.])(?:eval|exec)\s*\(")),
    PatternRule(
        "command-execution",
        re.compile(
            r"\b(?:os\.(?:system|popen)|subprocess\.(?:run|call|Popen|check_call|check_output|getoutput|getstatusoutput)|"
            r"child_process\.(?:exec|execSync|spawn)|exec\.Command|"
            r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\("
        ),
    ),
    PatternRule(
        "sql",
        re.compile(
            r"\.(?:execute|executeQuery|executeUpdate|executemany|"
            r"prepareStatement|prepareCall|query|raw)\s*\(",
            re.IGNORECASE,
        ),
    ),
    PatternRule(
        "ldap",
        re.compile(r"\.search\s*\(", re.IGNORECASE),
    ),
    PatternRule(
        "path-access",
        re.compile(r"\b(?:open|readFile|writeFile|os\.Open|os\.ReadFile)\s*\("),
    ),
    PatternRule(
        "outbound-request",
        re.compile(r"\b(?:requests\.(?:get|post)|fetch|http\.Get)\s*\("),
    ),
)


SANITIZER_RULES = (
    PatternRule(
        "shell-escaping",
        re.compile(r"\b(?:shlex\.quote|shellescape|escapeShellArg)\s*\("),
    ),
    PatternRule(
        "numeric-validation",
        re.compile(r"\b(?:int|parseInt|strconv\.(?:Atoi|ParseInt))\s*\("),
    ),
    PatternRule(
        "path-normalization",
        re.compile(r"\b(?:Path\.resolve|os\.path\.realpath|filepath\.Clean)\s*\("),
    ),
    PatternRule(
        "schema-validation",
        re.compile(r"\b(?:validate|parse_obj|model_validate|safeParse)\s*\("),
    ),
)


GUARD_PATTERN = re.compile(
    r"\b(?:authorize|authorization|authenticate|require_?permission|"
    r"check_?permission|has_?permission|require_?role|is_?admin|"
    r"UseGuards|enforce_policy|check_?tenant|assert_?owner)\b|"
    r"\b[A-Za-z_]\w*\.(?:user|owner|tenant|organization|project|account)_id\s*"
    r"(?:==|!=)\s*(?:current_)?(?:user|owner|tenant|organization|project|account)_id\b|"
    r"\b(?:current_)?(?:user|owner|tenant|organization|project|account)_id\s*"
    r"(?:==|!=)\s*[A-Za-z_]\w*\.(?:user|owner|tenant|organization|project|account)_id\b",
    re.IGNORECASE,
)


PRINCIPAL_PATTERN = re.compile(
    r"\b(?:request|req)\.user\b|\b(?:actor|principal|current_user|session_user|identity)\b",
    re.IGNORECASE,
)


RESOURCE_PATTERN = re.compile(
    r"\b(?:tenant|organization|project|account|user|resource|document)_id\b|"
    r"\b(?:req|request)\.params(?:\.[A-Za-z_]\w*|\[['\"][^'\"]+['\"]\])",
    re.IGNORECASE,
)


SENSITIVE_ACTION_PATTERN = re.compile(
    r"\b(?:delete|remove|update|write|admin|execute|run_command|transfer|invite|"
    r"set_role|change_role|read_secret)\b",
    re.IGNORECASE,
)


def _ignored_spans(document: CodeDocument) -> dict[int, list[tuple[int, int]]]:
    """Return line_number -> list of (start_col, end_col) spans for comments and strings."""
    from collections import defaultdict
    spans: dict[int, list[tuple[int, int]]] = defaultdict(list)
    text = document.text
    language = (document.language or "").lower()

    if language == "python":
        import io
        import tokenize
        try:
            for tok in tokenize.generate_tokens(io.StringIO(text).readline):
                if tok.type in (tokenize.COMMENT, tokenize.STRING):
                    sl, sc = tok.start
                    el, ec = tok.end
                    if sl == el:
                        spans[sl].append((sc, ec))
                    else:
                        lines = text.splitlines()
                        for l in range(sl, el + 1):
                            if l == sl:
                                spans[l].append((sc, len(lines[l - 1]) if l <= len(lines) else 0))
                            elif l == el:
                                spans[l].append((0, ec))
                            else:
                                spans[l].append((0, len(lines[l - 1]) if l <= len(lines) else 0))
            return spans
        except (tokenize.TokenError, IndentationError, SyntaxError):
            return spans

    # Use tree-sitter grammars already integrated in cv_agent for JS, TS, Java, Go
    tree_sitter_targets: tuple[str, ...] | None = None
    grammar = None
    if language in {"javascript", "typescript", "js", "ts", "jsx", "tsx"}:
        from cv_agent.code_adapters.javascript import JAVASCRIPT_LANGUAGE, TYPESCRIPT_LANGUAGE, TSX_LANGUAGE
        source_path = document.path.split("::", 1)[0]
        if language == "tsx" or source_path.endswith(".tsx"):
            grammar = TSX_LANGUAGE
        else:
            grammar = TYPESCRIPT_LANGUAGE if language in {"typescript", "ts"} else JAVASCRIPT_LANGUAGE
        tree_sitter_targets = ("comment", "string", "string_fragment", "regex")
    elif language == "java":
        from cv_agent.code_adapters.java import JAVA_LANGUAGE
        grammar = JAVA_LANGUAGE
        tree_sitter_targets = ("line_comment", "block_comment", "string_literal")
    elif language == "go":
        from cv_agent.code_adapters.go import GO_LANGUAGE
        grammar = GO_LANGUAGE
        tree_sitter_targets = ("comment", "interpreted_string_literal", "raw_string_literal")

    if grammar is not None and tree_sitter_targets is not None:
        from tree_sitter import Parser
        parser = Parser()
        parser.language = grammar
        tree = parser.parse(text.encode("utf-8"))
        lines = text.splitlines()

        def to_char_col(row: int, b_col: int) -> int:
            if row < len(lines):
                line_bytes = lines[row].encode("utf-8")
                return len(line_bytes[:b_col].decode("utf-8", errors="ignore"))
            return b_col

        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            if node.type in tree_sitter_targets:
                sr, sc = node.start_point
                er, ec = node.end_point
                if sr == er:
                    spans[sr + 1].append((to_char_col(sr, sc), to_char_col(er, ec)))
                else:
                    for r in range(sr, er + 1):
                        if r < len(lines):
                            if r == sr:
                                spans[r + 1].append((to_char_col(sr, sc), len(lines[r])))
                            elif r == er:
                                spans[r + 1].append((0, to_char_col(er, ec)))
                            else:
                                spans[r + 1].append((0, len(lines[r])))
            stack.extend(node.children)
        return spans

    # For shell, bash, ruby, yaml: mask only line comments starting with '#'
    if language in {"shell", "bash", "ruby", "yaml"}:
        for line_number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                spans[line_number].append((0, len(line)))
        return spans

    return spans


def _matching_lines(
    document: CodeDocument,
    rules: Iterable[PatternRule],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    ignored = _ignored_spans(document)
    for line_number, line in enumerate(document.text.splitlines(), start=1):
        line_ignored = ignored.get(line_number, [])
        for rule in rules:
            for match in rule.pattern.finditer(line):
                start, end = match.start(), match.end()
                if any(s_start <= start < s_end or s_start < end <= s_end for s_start, s_end in line_ignored):
                    continue
                findings.append(
                    {
                        "category": rule.category,
                        "line": line_number,
                        "match": match.group(0),
                        "text": line.strip(),
                    }
                )
    return findings


def references(
    index: RepositoryIndex,
    arguments: FrozenModel,
    scope: ToolExecutionScope,
) -> ToolObservation:
    value = cast(FindReferencesInput, arguments)
    matches = [
        {
            "calls": [call for call in document.calls if value.symbol in call],
            "defines": [
                definition
                for definition in document.defines
                if value.symbol in definition
            ],
            "path": document.path,
        }
        for document in _scope_documents(index, scope)
        if any(value.symbol in symbol for symbol in (*document.calls, *document.defines))
    ]
    return ToolObservation(
        tool="find_references",
        status="ok",
        content=_json_content({"references": matches, "symbol": value.symbol}),
        evidence_ids=tuple(f"reference:{item['path']}" for item in matches),
    )


def static_check(
    index: RepositoryIndex,
    arguments: FrozenModel,
    scope: ToolExecutionScope,
) -> ToolObservation:
    value = cast(PathInput, arguments)
    document, error = _admitted_document(index, value.path, scope, "run_static_check")
    if error is not None:
        return error
    item = cast(CodeDocument, document)
    findings = _matching_lines(item, SINK_RULES)
    permission = _chmod_permission_assessment(item)
    content = {
        "finding_count": len(findings),
        "findings": findings,
        "path": value.path,
    }
    if permission is not None:
        content["permission_mode_check"] = permission
    return ToolObservation(
        tool="run_static_check",
        status="ok",
        validation_status=ValidationStatus.UNRESOLVED,
        content=_json_content(content),
        evidence_ids=(f"static:{value.path}",),
    )


def pattern_tool(
    index: RepositoryIndex,
    tool_name: str,
    rules: Iterable[PatternRule],
) -> Callable[[FrozenModel, ToolExecutionScope], ToolObservation]:
    def handle(
        arguments: FrozenModel,
        scope: ToolExecutionScope,
    ) -> ToolObservation:
        value = cast(PathInput, arguments)
        document, error = _admitted_document(index, value.path, scope, tool_name)
        if error is not None:
            return error
        findings = _matching_lines(cast(CodeDocument, document), rules)
        sanitizer_flows: list[dict] = []
        if tool_name == "find_sanitizers" and findings and scope.subject is not None:
            from collections import Counter
            from cv_agent.tools.analysis.sanitizers import numeric_helper_flows
            from cv_agent.tools.identity import repository_source_digest
            entry = index.document(scope.subject.entry_path)
            if (entry is not None and entry.path in scope.admitted_paths
                    and value.path in index.graph_neighbors(entry.path, direction="forward")
                    and scope.subject.source_digest == repository_source_digest(index)):
                # Ambiguity belongs to the resolved call symbol, not a shared
                # short name belonging to otherwise distinct module definitions.
                neighbors = [index.document(path) for path in index.graph_neighbors(entry.path, direction="forward")]
                helper = cast(CodeDocument, document)
                counts = Counter(symbol for other in neighbors if other is not None for symbol in set(other.defines))
                sanitizer_flows = numeric_helper_flows(
                    entry, helper, scope.subject.entry_line,
                    ambiguous_symbols={symbol for symbol, count in counts.items() if count > 1},
                )
        return ToolObservation(
            tool=tool_name,
            status="ok",
            subject=scope.subject if sanitizer_flows else None,
            content=_json_content(
                {
                    "finding_count": len(findings),
                    "findings": findings,
                    "path": value.path,
                    "candidate_sanitizer_flows": sanitizer_flows,
                }
            ),
            evidence_ids=(f"{tool_name}:{value.path}",),
        )

    return handle
