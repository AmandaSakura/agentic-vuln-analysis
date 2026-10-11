"""Narrow read-only product orchestration; no planner, provider or target import."""
from __future__ import annotations

import json
import re
from pathlib import Path
import time
import traceback
from uuid import uuid4

from cv_agent.agents.discovery import discover_python_repository
from cv_agent.agents.scanner import StaticScanner
from cv_agent.application.delivery import CertificateDelivery, DeliveryBudgetError, allocation_plan
from cv_agent.application.context import ContextManifest, ReadGrant, SourceReadView
from cv_agent.application.controller import ReviewTask, TaskController
from cv_agent.application.evidence import reduce_observations
from cv_agent.application.identity import analysis_implementation_digest, canonical_digest, source_digest, view_revision
from cv_agent.application.preflight import preflight, protected_project_root, PROPERTY_TO_TOOL, STATIC_TOOLS
from cv_agent.domain.chat import ModelToolCall
from cv_agent.domain.evidence import ToolObservation
from cv_agent.domain.product_result import (Diagnosis, IdentityBundle, ReviewAccounting, ReviewCounts,
    ReviewResult, property_contract)
from cv_agent.presentation.report import export_result
from cv_agent.tools.identity import candidate_subject
from cv_agent.tools.registry import ToolExecutionScope, ToolRegistry
from cv_agent.tools.validation import full_agent_tools


PRODUCT_EXCLUDED_DIRS = frozenset({"data", "artifacts", "audit", ".hermes"})
DEFAULT_OBSERVATION_BYTES = 8192
PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _protected_root(root: Path) -> bool:
    return protected_project_root(root)


def review_source(source_root: Path, *, language: str = "python",
                  observation_bytes: int = DEFAULT_OBSERVATION_BYTES,
                  context_manifest: dict | None = None, context_bytes: int = 8192,
                  private_sink=None) -> ReviewResult:
    start = time.monotonic()
    run_id = "review-" + uuid4().hex
    check = preflight(source_root, language=language)
    capabilities = list(check.capabilities)
    diagnoses = list(check.diagnoses)
    findings, receipts = [], []
    counts = ReviewCounts()
    hashes, spans = {}, []
    scope_receipts = ()
    source_view = None
    admitted_paths = frozenset()
    indexed_documents = 0
    calls = unprocessed = validated = 0
    state = "COMPLETED"
    was_cancelled = False
    delivery = CertificateDelivery(allocation_plan({}, total_bytes=observation_bytes,
        diagnostic_reserve=min(256, observation_bytes)))

    def diagnose(stage, reason, message, *, owner="analyzer", retry="never", candidate=None, failure=None):
        diagnoses.append(Diagnosis(stage=stage, reason_code=reason, message=message,
            owner=owner, retry_policy=retry, affected_candidate_ids=(candidate,) if candidate else (),
            experiment_failure_class=failure))

    if not check.ready:
        state = "BLOCKED"
    elif _protected_root(source_root):
        state = "BLOCKED"
        diagnose("input", "protected_source_root", "The selected root is a protected project data or run directory.",
                 owner="user", retry="after_input", failure="F1")
    elif language != "python":
        state = "BLOCKED"
        diagnose("preflight", "language_not_supported", "The enabled product source inventory supports Python only.",
                 owner="user", retry="after_input")
    manifest = None
    if context_manifest is not None:
        try:
            manifest = ContextManifest.model_validate(context_manifest)
        except ValueError:
            state = "BLOCKED"
            diagnose("input", "context_manifest_invalid", "The explicit context manifest is unavailable or invalid.",
                     owner="user", retry="after_input", failure="F1")
    preparation_end = time.monotonic()
    if state != "BLOCKED":
        try:
            discovery = discover_python_repository(source_root, "authorized-local-source",
                                                   exclude_dirs=PRODUCT_EXCLUDED_DIRS)
        except KeyboardInterrupt:
            was_cancelled = True
            state = "CANCELLED"
            diagnose("index", "review_cancelled", "Source inventory was cancelled before it committed analysis facts.",
                     owner="user", retry="manual")
        except Exception as error:
            state = "FAILED"
            diagnose("index", "index_internal_error", f"Source inventory failed: {type(error).__name__}.",
                     owner="runtime", retry="manual")
            if private_sink is not None:
                private_sink({"event": "index_internal_error", "error_type": type(error).__name__,
                              "private_traceback": traceback.format_exc()})
                diagnoses[-1] = diagnoses[-1].model_copy(update={"private_log_ref": ".private/observations.jsonl"})
        else:
            hashes = dict(discovery.report["source_sha256"])
            for error in discovery.report["parse_errors"]:
                hashes.setdefault(error["path"], None)
                diagnose("index", "source_parse_error", f"Could not parse {error['path']}: {error['error_type']}.")
            state = "PARTIAL" if discovery.report["parse_errors"] else "COMPLETED"
            # The product analyzes all explicitly indexed spans, without model retrieval.
            for path, document in sorted(discovery.index.documents.items()):
                file_path = path.split("::", 1)[0]
                if "::<module>@" in path:
                    spans.append((file_path, 1, max(1, len(document.text.splitlines()))))
            source_view = SourceReadView(source_root, hashes, byte_budget=context_bytes)
            initial = ([{"path": path, "start_line": first, "end_line": last,
                         "reason": "product source inventory: complete authorized Python file"}
                        for path, first, last in spans] if context_manifest is None
                       else manifest.initial)
            extensions = [] if context_manifest is None else manifest.extensions
            for is_extension, requests in ((False, initial), (True, extensions)):
                for request in requests:
                    try:
                        grant = ReadGrant.model_validate(request)
                        source_view.extend(grant) if is_extension else source_view.admit(grant)
                    except (ValueError, OSError) as error:
                        state = "PARTIAL"
                        diagnose("input", "context_grant_rejected", f"Explicit context request rejected: {type(error).__name__}.",
                                 owner="user", retry="after_input")
            def covered(path, document):
                span = re.search(r"@(\d+)-(\d+)$", path)
                first, last = (map(int, span.groups()) if span else (1, max(1, len(document.text.splitlines()))))
                return source_view.covers(path.split("::", 1)[0], first, last)
            admitted_paths = frozenset(path for path, document in discovery.index.documents.items() if covered(path, document))
            indexed_documents = len(discovery.index.documents)
            scope_receipts = source_view.receipts
            registry = ToolRegistry([tool for tool in full_agent_tools(discovery.index)
                                     if tool.name in STATIC_TOOLS], max_output_bytes=8192)
            for candidate in discovery.candidates:
                subject = candidate_subject(discovery.index, candidate)
                selected = PROPERTY_TO_TOOL.get(candidate.property_id, "run_static_check")
                capability = preflight(source_root, property_id=candidate.property_id,
                                       available_tools=frozenset(registry.available_names))
                capabilities.append(next(c for c in capability.capabilities if c.method == selected))
                observations = []
                if was_cancelled:
                    unprocessed += 1
                elif candidate.path not in admitted_paths:
                    unprocessed += 1
                    state = "PARTIAL"
                    diagnose("analysis", "candidate_span_not_admitted", "The complete candidate span is outside the explicit context grants.",
                             owner="user", retry="after_input", candidate=candidate.candidate_id)
                elif selected not in registry.available_names:
                    unprocessed += 1
                    state = "PARTIAL"
                    diagnose("validation", "validator_unavailable", "The requested static tool is unavailable.",
                             owner="environment", retry="after_environment_change", candidate=candidate.candidate_id)
                elif delivery.remaining_bytes < 256:
                    unprocessed += 1
                    state = "PARTIAL"
                    diagnose("validation", "observation_budget_exhausted", "No complete tool certificate can be admitted.",
                             candidate=candidate.candidate_id, failure="F6")
                else:
                    calls += 1
                    producer = f"{run_id}/static/{calls}"
                    arguments = ({"source_path": candidate.path, "max_hops": 2}
                                 if selected in {"inspect_command_construction", "probe_python_eval"}
                                 else {"path": candidate.path})
                    scope = ToolExecutionScope(admitted_paths=admitted_paths,
                        candidate_path=candidate.path, subject=subject, max_observation_tokens=8192)
                    task = ReviewTask(task_id=candidate.candidate_id)
                    control = TaskController((task,), {task.task_id: lambda _: registry.invoke(
                        ModelToolCall(call_id=producer, name=selected, arguments=arguments),
                        allowed=(selected,), scope=scope, citation_id=producer)})
                    try:
                        task_state = control.advance()[task.task_id]
                    except KeyboardInterrupt:
                        was_cancelled = True
                        unprocessed += 1
                        diagnose("runtime", "review_cancelled", "The review was cancelled; no later tools will start.",
                                 owner="user", retry="manual", candidate=candidate.candidate_id)
                        if private_sink is not None:
                            private_sink({"event": "task_cancelled", "producer_id": producer,
                                          "controller_events": control.events})
                        findings.append(reduce_observations(subject, ())[0])
                        continue
                    if task_state.diagnosis is not None:
                        diagnoses.append(task_state.diagnosis.model_copy(update={
                            "private_log_ref": ".private/observations.jsonl" if private_sink is not None else None}))
                    observed = task_state.observation or ToolObservation(tool=selected,
                        status="error", content="Task failed before producing an observation.")
                    # Includes identity, status, references and outer JSON, not just content bytes.
                    payload = json.dumps({"producer_id": producer, "observation": observed.model_dump(mode="json")},
                        sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
                    delivery.store(producer, payload, physical_execution=False)
                    original_observation = observed
                    try:
                        delivery.deliver(producer)
                    except DeliveryBudgetError:
                        unprocessed += 1
                        state = "PARTIAL"
                        observed = observed.model_copy(update={"metadata": {**observed.metadata,
                            "model_payload_suppressed": True}, "validation_status": None, "fixture_proof": None})
                        diagnose("validation", "observation_budget_exhausted", "Produced certificate exceeded the public delivery budget.",
                                 candidate=candidate.candidate_id, failure="F6")
                    else:
                        validated += int(selected != "run_static_check" and task_state.validator_completed)
                        if observed.status != "ok":
                            state = "PARTIAL"
                            diagnose("validation", "static_tool_failed", "Static tool returned a blocked or error observation.",
                                     candidate=candidate.candidate_id)
                    observations.append((producer, observed))
                    if private_sink is not None:
                        private_sink({"producer_id": producer, "observation": original_observation.model_dump(mode="json"),
                            "delivered": not observed.metadata.get("model_payload_suppressed"),
                            "controller_events": control.events})
                finding, evidence = reduce_observations(subject, observations)
                findings.append(finding)
                receipts.extend(evidence)
                if private_sink is not None and evidence:
                    receipts[-len(evidence):] = [item.model_copy(update={"artifact_ref": ".private/observations.jsonl"})
                                                 for item in evidence]
            counts = ReviewCounts(source_files=discovery.report["source_files"],
                parsed_files=discovery.report["parsed_files"], parse_errors=len(discovery.report["parse_errors"]),
                candidate_count=len(findings), validated_candidates=validated,
                sufficient_evidence_candidates=sum(f.property_state != "UNKNOWN" for f in findings),
                unprocessed_candidates=unprocessed, indexed_documents=indexed_documents,
                admitted_documents=len(admitted_paths))
    byte_identity = source_digest(hashes)
    analysis_identity = canonical_digest("analysis-contract-v1", {
        "profile": "product_triage_v1", "rules": StaticScanner.rule_names,
        "contracts": [property_contract(p).model_dump(mode="json") for p in sorted(PROPERTY_TO_TOOL)],
        "observation_bytes": observation_bytes, "context_bytes": context_bytes,
        "excluded_dirs": sorted(PRODUCT_EXCLUDED_DIRS), "tool_contract": "tool-contract-v1",
        "implementation_digest": analysis_implementation_digest(),
    })
    receipts = [item.model_copy(update={"source_identity": byte_identity,
                "analysis_contract_digest": analysis_identity}) for item in receipts]
    end = time.monotonic()
    return ReviewResult(run_id=run_id, run_state="CANCELLED" if was_cancelled else state, findings=tuple(findings),
        evidence_receipts=tuple(receipts), capabilities=tuple(capabilities), diagnoses=tuple(diagnoses),
        counts=counts, scope_admissions=scope_receipts, identity=IdentityBundle(source_digest=byte_identity,
            analysis_contract_digest=analysis_identity,
            retrieval_view_revision=source_view.revision if source_view is not None else view_revision(spans)),
        accounting=ReviewAccounting(tool_calls=calls, observation_bytes=delivery.used_bytes,
            context_bytes=source_view.used_bytes if source_view is not None else 0,
            preparation_seconds=preparation_end-start, analysis_seconds=end-preparation_end, total_seconds=end-start),
        artifacts={"result": "result.json", "report": "report.md",
                   **({"private_observations": ".private/observations.jsonl"} if private_sink is not None else {})})


def run_review(source_root: Path, output: Path, **options) -> ReviewResult:
    if output.exists() or output.is_symlink():
        raise FileExistsError("Output path already exists; select a new run directory")
    private_records = []
    result = review_source(source_root, private_sink=private_records.append, **options)
    return export_result(result, output, private_records=private_records)
