"""Positive-only admission contract for bounded execution witnesses."""

from __future__ import annotations

import ast
import hashlib
import io
import re
import tokenize
from functools import partial
from typing import Literal

from cv_agent.domain.evidence import FixtureProofScope, ValidationStatus, ValidationSubject
from cv_agent.domain.types import Candidate
from cv_agent.evaluation.diagnostics.bounded_execution_witness import (
    WitnessManifest,
    WitnessResult,
    run_witness,
)
from cv_agent.retrieval import RepositoryIndex
from cv_agent.tools.identity import candidate_subject, repository_source_digest
from cv_agent.tools.validation.models import FixtureCase, FixtureOutcome


class PositiveOnlyWitnessProofScope(FixtureProofScope):
    """A negative run cannot become a candidate-level REFUTED observation."""

    contract_id: Literal["bounded-execution-witness-v1"] = "bounded-execution-witness-v1"
    property_id: Literal["command-execution"] = "command-execution"
    coverage: Literal["candidate"] = "candidate"
    method: Literal["bounded_execution"] = "bounded_execution"
    supported_statuses: tuple[Literal[ValidationStatus.CONFIRMED]] = (
        ValidationStatus.CONFIRMED,
    )


def _fixture_outcome(manifest: WitnessManifest) -> FixtureOutcome:
    result: WitnessResult = run_witness(manifest)
    if result.status == ValidationStatus.REFUTED:
        raise ValueError("bounded execution witness cannot refute a candidate")
    if result.raw_status == "LITERAL_OBSERVED" and result.status != ValidationStatus.UNRESOLVED:
        raise ValueError("a literal observation cannot support a candidate verdict")
    if result.status == ValidationStatus.CONFIRMED and (
        result.raw_status != "EXPANDED_OBSERVED" or result.gaps
    ):
        raise ValueError("confirmed witness lacks a complete expansion record")
    return FixtureOutcome(
        status=result.status,
        summary="bounded execution witness",
        details={"witness": result.model_dump(mode="json"), "raw_status": result.raw_status},
    )


def bounded_witness_fixture_case(
    index: RepositoryIndex,
    candidate: Candidate,
    manifest: WitnessManifest,
) -> FixtureCase:
    """Register only a subject-bound positive witness with an immutable proof scope."""

    subject = candidate_subject(index, candidate)
    validate_witness_manifest(index, subject, manifest)
    return FixtureCase(
        case_id=candidate.case_id,
        runner=partial(_fixture_outcome, manifest),
        timeout_seconds=60.0,
        subject=subject,
        proof_scope=PositiveOnlyWitnessProofScope(),
        # The real target is isolated inside run_witness's fresh worker.
        isolated=False,
    )


def validate_witness_manifest(
    index: RepositoryIndex, subject: ValidationSubject, manifest: WitnessManifest,
) -> None:
    """Validate an execution manifest against the indexed candidate snapshot."""
    if manifest.subject != subject or subject.property_id != "command-execution":
        raise ValueError("witness subject does not match the indexed command candidate")
    if subject.source_digest != repository_source_digest(index):
        raise ValueError("witness subject differs from the indexed source digest")
    span = re.fullmatch(r"(.+)::([^@]+)@(\d+)-(\d+)", subject.entry_path)
    if span is None:
        raise ValueError("witness candidate needs an indexed Python method span")
    entry_path, symbol, start_text, end_text = span.groups()
    if (manifest.entry_relative_path != entry_path
            or symbol != f"{manifest.class_name}.{manifest.method_name}"):
        raise ValueError("witness entry method does not match the candidate span")
    document = index.document(subject.entry_path)
    if document is None or document.repository_id != subject.repository_id:
        raise ValueError("witness candidate entry is absent from the source index")
    checkout = manifest.checkout_root.resolve(strict=True)
    entry_file = (checkout / manifest.entry_relative_path).resolve(strict=True)
    if not entry_file.is_relative_to(checkout):
        raise ValueError("witness entry file escapes the fixed checkout")
    raw = entry_file.read_bytes()
    file_digest = hashlib.sha256(raw).hexdigest()
    if file_digest != manifest.entry_file_sha256:
        raise ValueError("witness entry file differs from the registered snapshot")
    if document.source_sha256 is not None and document.source_sha256 != file_digest:
        raise ValueError("witness entry file differs from the indexed file")
    encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
    text = raw.decode(encoding)
    first, last = int(start_text), int(end_text)
    indexed_text = "".join(text.splitlines(keepends=True)[first - 1:last])
    if document.text != indexed_text:
        raise ValueError("witness entry span differs from the indexed source")
    tree = ast.parse(text, filename=str(entry_file))
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)
               and node.name == manifest.class_name]
    if len(classes) != 1:
        raise ValueError("witness entry class is not unique in the source")
    methods = [node for node in classes[0].body if isinstance(node, ast.FunctionDef)
               and node.name == manifest.method_name]
    if len(methods) != 1:
        raise ValueError("witness entry method is not unique in the source")
    method = methods[0]
    method_start = min((item.lineno for item in method.decorator_list), default=method.lineno)
    if (method_start != first or method.end_lineno != last
            or method.lineno != manifest.entry_first_line
            or subject.entry_line is None or not first <= subject.entry_line <= last):
        raise ValueError("witness entry method location differs from the candidate span")
    if subject.entry_line != method.lineno or method.decorator_list:
        raise ValueError("bounded witness supports undecorated whole-method header candidates only")
    indexed_modules: dict[str, list] = {}
    for path, module_doc in index.documents.items():
        if module_doc.repository_id == subject.repository_id:
            indexed_modules.setdefault(path.split("::", 1)[0], []).append(module_doc)
    for binding in manifest.source_modules:
        module_file = (checkout / binding.relative_path).resolve(strict=True)
        if not module_file.is_relative_to(checkout):
            raise ValueError("witness source module escapes the fixed checkout")
        module_raw = module_file.read_bytes()
        if hashlib.sha256(module_raw).hexdigest() != binding.sha256:
            raise ValueError("witness source module differs from its manifest hash")
        module_encoding, _ = tokenize.detect_encoding(io.BytesIO(module_raw).readline)
        module_text = module_raw.decode(module_encoding)
        module_lines = module_text.splitlines(keepends=True)
        indexed = indexed_modules.get(binding.relative_path, [])
        if not indexed:
            raise ValueError("witness source module is absent from the source index")
        for module_doc in indexed:
            module_span = re.search(r"@(\d+)-(\d+)(?:#\d+-\d+)?$", module_doc.path)
            if module_span is None:
                expected_text = module_text
            else:
                module_first, module_last = map(int, module_span.groups())
                expected_text = "".join(module_lines[module_first - 1:module_last])
            if module_doc.text != expected_text:
                raise ValueError("witness source module differs from the indexed snapshot")
            if (module_doc.source_sha256 is not None
                    and module_doc.source_sha256 != binding.sha256):
                raise ValueError("witness source module file digest differs from the index")
