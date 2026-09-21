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
            r"\b(?:os\.system|subprocess\.(?:run|call|Popen)|"
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


def _matching_lines(
    document: CodeDocument,
    rules: Iterable[PatternRule],
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line_number, line in enumerate(document.text.splitlines(), start=1):
        for rule in rules:
            for match in rule.pattern.finditer(line):
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
        return ToolObservation(
            tool=tool_name,
            status="ok",
            content=_json_content(
                {
                    "finding_count": len(findings),
                    "findings": findings,
                    "path": value.path,
                }
            ),
            evidence_ids=(f"{tool_name}:{value.path}",),
        )

    return handle
