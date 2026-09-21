from __future__ import annotations

import hashlib
import io
import json
import subprocess
import tokenize
from pathlib import Path
from typing import Any

from pydantic import Field

from cv_agent.tools.registry import AgentTool, ToolExecutionScope
from cv_agent.tools.identity import candidate_subject
from cv_agent.domain.evidence import ToolObservation, ValidationStatus
from cv_agent.code_adapters.python import parse_python_source
from cv_agent.evaluation.datasets.python_pair_config import PythonPair, PythonPairCase
from cv_agent.retrieval import RepositoryIndex
from cv_agent.code_adapters.source_files import read_source_bytes
from cv_agent.domain.types import Candidate, CodeDocument, FrozenModel


class PythonPairFixtureInput(FrozenModel):
    fixture_id: str = Field(pattern=r"^[a-z0-9_]+$")


def git_commit(checkout: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=checkout,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def require_clean_checkout(checkout: Path, expected_commit: str) -> None:
    if git_commit(checkout) != expected_commit:
        raise ValueError("Pair checkout commit changed")
    result = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=normal"],
        cwd=checkout,
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    if result.stdout.strip():
        raise ValueError("Pair checkout is not clean")


def build_package_index(
    root: Path,
    pair: PythonPair,
    case: PythonPairCase,
) -> tuple[RepositoryIndex, dict[str, str]]:
    checkout = root / case.checkout
    source_root = checkout / pair.source_root
    if not source_root.is_dir():
        raise FileNotFoundError(source_root)
    documents: list[CodeDocument] = []
    source_sha256: dict[str, str] = {}
    excluded = set(pair.exclude_path_parts) | {".git", ".venv", "venv", "node_modules", "vendor", "build", "dist"}
    for path in sorted(source_root.rglob("*.py")):
        relative_parts = path.relative_to(checkout).parts
        if set(relative_parts) & excluded:
            continue
        relative = path.relative_to(checkout).as_posix()
        try:
            raw = read_source_bytes(checkout, relative)
            source_sha256[relative] = hashlib.sha256(raw).hexdigest()
            encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
            text = raw.decode(encoding)
            spans = parse_python_source(case.case_id, relative, text)
        except (SyntaxError, UnicodeError, LookupError, OSError, ValueError):
            continue
        documents.extend(span.document for span in spans)
        documents.append(CodeDocument(
            repository_id=case.case_id,
            path=f"{relative}::<module>@1-{max(1, len(text.splitlines()))}",
            text=text,
            language="python",
            adapter_tier="ast",
        ))
    if not documents:
        raise ValueError("No Python documents indexed for pair case")
    return RepositoryIndex(documents), source_sha256


def build_pair_input(
    root: Path,
    pair: PythonPair,
    case: PythonPairCase,
) -> tuple[RepositoryIndex, Candidate, dict[str, str]]:
    index, source_sha256 = build_package_index(root, pair, case)
    entries = [
        document
        for document in index.documents.values()
        if document.path.startswith(f"{case.file_path}::")
        and pair.entry_symbol in document.defines
    ]
    if not entries:
        raise ValueError(f"Entry symbol not found in indexed package: {pair.entry_symbol}")
    entry = min(entries, key=lambda document: (
        0 if f"@{case.line_hint}-" in document.path else 1,
        abs(_start_line(document.path) - case.line_hint),
        document.path,
    ))
    candidate = Candidate(
        candidate_id=case.case_id,
        case_id=case.case_id,
        repository_id=case.case_id,
        path=entry.path,
        line=_start_line(entry.path),
        query=f"{pair.entry_symbol} {pair.source_scope}",
        analysis_scope=pair.analysis_scope,
    )
    return index, candidate, source_sha256


def _start_line(document_path: str) -> int:
    marker = document_path.rsplit("@", 1)[-1]
    return int(marker.split("-", 1)[0])


def sanitize_observations(observations: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "status",
        "success",
        "output",
        "leaked_secret",
        "leaked_dunder",
        "format_exposed",
        "error_type",
        "error_message",
    }
    return {
        scenario: {key: value for key, value in result.items() if key in allowed}
        for scenario, result in observations.items()
    }


def fixture_validation_status(pair_id: str, role: str, observations: dict[str, Any]) -> ValidationStatus:
    if pair_id == "langchain_template_traversal":
        benign = observations["benign"].get("status") == "BENIGN_OK"
        attr = observations["attribute_access"]
        dunder = observations["dunder_access"]
        exploited = (
            attr.get("status") == "EXPLOITED"
            and attr.get("leaked_secret") is True
            and dunder.get("status") == "EXPLOITED"
            and dunder.get("leaked_dunder") is True
        )
        blocked = (
            attr.get("status") == "BLOCKED"
            and attr.get("error_type") == "ValueError"
            and "Invalid variable name 'marker.secret' in f-string template" in attr.get("error_message", "")
            and dunder.get("status") == "BLOCKED"
            and dunder.get("error_type") == "ValueError"
            and "Invalid variable name 'marker.__class__.__name__' in f-string template" in dunder.get("error_message", "")
        )
    elif pair_id == "jinja_attr_format_escape":
        benign = observations["benign"].get("status") == "BENIGN_OK"
        attr = observations["attr_format"]
        exploited = attr.get("status") == "EXPLOITED" and attr.get("format_exposed") is True
        blocked = (
            attr.get("status") == "BLOCKED"
            and attr.get("error_type") in {"SecurityError", "UndefinedError", "TemplateRuntimeError", "Undefined"}
            and "format" in attr.get("error_message", "")
        )
    else:
        raise ValueError("Unknown pair id")
    if role == "vulnerable" and benign and exploited:
        return ValidationStatus.CONFIRMED
    if role == "fixed" and benign and blocked:
        return ValidationStatus.REFUTED
    raise ValueError("Current-run fixture invariants failed")


def pair_fixture_tool(
    root: Path,
    pair: PythonPair,
    case: PythonPairCase,
    index: RepositoryIndex,
    candidate: Candidate,
    observations: dict[str, Any],
) -> AgentTool:
    checkout = root / case.checkout
    source = checkout / case.file_path
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    subject = candidate_subject(index, candidate)
    sanitized = sanitize_observations(observations)
    validation_status = fixture_validation_status(pair.pair_id, case.revision_role, sanitized)

    def handler(args: PythonPairFixtureInput, scope: ToolExecutionScope) -> ToolObservation:
        if args.fixture_id != pair.fixture_id:
            raise ValueError("Fixture id is not registered for this candidate")
        if scope.subject != subject or scope.candidate_path != candidate.path:
            return ToolObservation(
                tool="run_fixture_test",
                status="blocked",
                content="Fixture is bound to another candidate.",
            )
        require_clean_checkout(checkout, case.commit)
        if hashlib.sha256(source.read_bytes()).hexdigest() != digest:
            raise ValueError("Source changed since pair validation")
        return ToolObservation(
            tool="run_fixture_test",
            status="ok",
            subject=subject,
            validation_status=validation_status,
            content=json.dumps({
                "execution": "current-run offline preflight; checkout revalidated",
                "fixture_id": pair.fixture_id,
                "scope": pair.source_scope,
                "observations": sanitized,
            }, sort_keys=True),
        )

    return AgentTool(
        "run_fixture_test",
        (
            f"Read executed {pair.fixture_id} fixture witnesses for this exact candidate. "
            "Includes benign control and advisory-scoped probes; no general safety claim."
        ),
        PythonPairFixtureInput,
        handler,
        content_type="json",
        validation_statuses=(ValidationStatus.CONFIRMED, ValidationStatus.REFUTED),
    )


def case_identity(root: Path, pair: PythonPair, case: PythonPairCase, source_sha256: dict[str, str]) -> dict[str, Any]:
    checkout = root / case.checkout
    return {
        "case_id": case.case_id,
        "pair_id": pair.pair_id,
        "revision_role": case.revision_role,
        "commit": git_commit(checkout),
        "configured_commit": case.commit,
        "checkout": case.checkout,
        "source_root": pair.source_root,
        "file_path": case.file_path,
        "entry_file_sha256": source_sha256[case.file_path],
        "source_sha256": source_sha256,
    }
