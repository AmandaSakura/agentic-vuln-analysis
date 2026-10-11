"""Versioned offline review projections; observations retain their original semantics."""
from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from cv_agent.domain.evidence import ValidationStatus, ValidationSubject
from cv_agent.domain.types import FrozenModel


PropertyState = Literal["SUPPORTED", "REFUTED", "UNKNOWN", "CONFLICT"]
RunState = Literal["COMPLETED", "PARTIAL", "BLOCKED", "FAILED", "CANCELLED"]
EvidenceMethod = Literal[
    "source_pattern", "source_read", "complete_static_analysis", "ast_model", "bounded_execution",
]


class PropertyContract(FrozenModel):
    version: Literal["property-contract-v1"] = "property-contract-v1"
    property_id: str = Field(min_length=1)
    predicate: str = Field(min_length=1)
    quantifier: Literal["existential", "universal", "bounded"]
    input_domain: tuple[str, ...]
    scope_kind: Literal["declared-candidate"] = "declared-candidate"
    supported_methods: tuple[EvidenceMethod, ...]
    not_covered: tuple[str, ...] = (
        "whole-application-security", "remote-authority", "public-entry-reachability",
    )


def property_contract(property_id: str) -> PropertyContract:
    definitions = {
        "chmod-mode-others-write": (
            "The selected chmod mode contains the others-write bit under the declared inputs.",
            "bounded", ("selected-statement", "resolved-mode", "declared-path-conditions"),
            ("complete_static_analysis", "bounded_execution"),
        ),
        "command-execution": (
            "Established controlled input can change shell syntax or executable selection at the declared command boundary.",
            "existential", ("declared-input-source", "declared-consumption-context", "candidate-scope"),
            ("complete_static_analysis", "bounded_execution"),
        ),
        "dynamic-evaluation": (
            "Established controlled input can change evaluated code semantics beyond value substitution in the declared bounded function model.",
            "existential", ("admitted-function-slices", "builtin-binding", "bounded-interpreter"),
            ("ast_model", "bounded_execution"),
        ),
        "authorization-boundary": (
            "The declared principal can bypass the specified action and resource authorization boundary under the declared policy.",
            "bounded", ("declared-policy", "principal", "resource", "action"),
            ("complete_static_analysis", "bounded_execution"),
        ),
    }
    if property_id in definitions:
        predicate, quantifier, domain, methods = definitions[property_id]
    else:
        predicate, quantifier, domain, methods = (
            "A source-derived review lead requiring a separately defined property contract.",
            "bounded", ("indexed-source",), ("source_pattern",),
        )
    return PropertyContract(property_id=property_id, predicate=predicate,
                            quantifier=quantifier, input_domain=domain, supported_methods=methods)


class IdentityBundle(FrozenModel):
    version: Literal["product-identity-v1"] = "product-identity-v1"
    source_algorithm: Literal["source-bytes-v1"] = "source-bytes-v1"
    source_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    analysis_contract_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    retrieval_view_revision: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class Diagnosis(FrozenModel):
    stage: Literal["input", "preflight", "index", "analysis", "validation", "reduction", "presentation", "runtime"]
    reason_code: str = Field(min_length=1)
    message: str = Field(min_length=1)
    owner: Literal["user", "environment", "runtime", "analyzer"]
    retry_policy: Literal["never", "after_input", "after_environment_change", "manual"]
    required_input: tuple[str, ...] = ()
    affected_candidate_ids: tuple[str, ...] = ()
    experiment_failure_class: Literal["F1", "F2", "F3", "F4", "F5", "F6"] | None = None
    private_log_ref: str | None = None


class CapabilityDecision(FrozenModel):
    language: str
    property_id: str | None = None
    method: str
    state: Literal["AVAILABLE", "UNSUPPORTED", "BLOCKED"]
    required: bool = False
    reason_code: str = Field(min_length=1)
    detail: str
    check_version: Literal["product-capability-v1"] = "product-capability-v1"


class EvidenceReceipt(FrozenModel):
    """Exported provenance for a runtime observation, not a replacement validator."""
    observation_id: str = Field(min_length=1)
    producer_id: str = Field(min_length=1)
    tool: str = Field(min_length=1)
    subject: ValidationSubject
    status: Literal["ok", "error", "blocked"]
    validation_status: ValidationStatus | None = None
    method: EvidenceMethod
    method_version: Literal["tool-contract-v1"] = "tool-contract-v1"
    accepted_static_status: Literal["CONFIRMED", "REFUTED"] | None = None
    coverage: Literal["candidate", "local"]
    delivered: bool
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    artifact_ref: str | None = None
    source_identity: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    analysis_contract_digest: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def static_projection_binding(self):
        if self.accepted_static_status is not None and not (
            self.tool == "inspect_command_construction"
            and self.method == "complete_static_analysis"
            and self.validation_status == ValidationStatus.UNRESOLVED
            and self.subject.property_id == "command-execution"
        ):
            raise ValueError("Static projection requires the registered command inspector")
        return self

    @property
    def proof_status(self) -> ValidationStatus | None:
        return (ValidationStatus(self.accepted_static_status)
                if self.accepted_static_status is not None else self.validation_status)

    def supplies_proof(self, subject: ValidationSubject, contract: PropertyContract) -> bool:
        return (
            self.subject == subject and self.status == "ok" and self.delivered
            and self.coverage == "candidate"
            and self.method not in {"source_pattern", "source_read"}
            and self.method in contract.supported_methods
            and self.proof_status in {ValidationStatus.CONFIRMED, ValidationStatus.REFUTED}
        )


class FindingView(FrozenModel):
    candidate_id: str
    subject: ValidationSubject
    contract: PropertyContract
    property_state: PropertyState = "UNKNOWN"
    evidence_refs: tuple[str, ...] = ()
    facts: tuple[str, ...] = ()
    missing_obligations: tuple[str, ...] = ()
    next_steps: tuple[str, ...] = ()
    application_security: Literal["NOT_ASSESSED"] = "NOT_ASSESSED"
    remote_authority_evaluated: Literal[False] = False
    public_entry_evaluated: Literal[False] = False

    @model_validator(mode="after")
    def property_binding(self):
        if self.subject.candidate_id != self.candidate_id:
            raise ValueError("Finding subject does not match its candidate")
        if self.subject.property_id != self.contract.property_id:
            raise ValueError("Finding property does not match its subject")
        if self.contract != property_contract(self.contract.property_id):
            raise ValueError("Finding property contract does not match the registered version")
        return self


class ReviewCounts(FrozenModel):
    source_files: int = Field(default=0, ge=0)
    parsed_files: int = Field(default=0, ge=0)
    parse_errors: int = Field(default=0, ge=0)
    candidate_count: int = Field(default=0, ge=0)
    validated_candidates: int = Field(default=0, ge=0)
    sufficient_evidence_candidates: int = Field(default=0, ge=0)
    unprocessed_candidates: int = Field(default=0, ge=0)
    indexed_documents: int = Field(default=0, ge=0)
    admitted_documents: int = Field(default=0, ge=0)


class ScopeAdmission(FrozenModel):
    admission_id: str
    path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    reason: str
    state: Literal["ADMITTED", "REJECTED"]
    reason_code: str
    delivered_bytes: int = Field(default=0, ge=0)


class ReviewAccounting(FrozenModel):
    model_requests: Literal[0] = 0
    reported_tokens: int | None = Field(default=None, ge=0)
    tool_calls: int = Field(default=0, ge=0)
    physical_executions: int = Field(default=0, ge=0)
    observation_bytes: int = Field(default=0, ge=0)
    context_bytes: int = Field(default=0, ge=0)
    preparation_seconds: float = Field(default=0, ge=0)
    gate_seconds: float = Field(default=0, ge=0)
    analysis_seconds: float = Field(default=0, ge=0)
    model_seconds: float = Field(default=0, ge=0)
    output_seconds: float = Field(default=0, ge=0)
    total_seconds: float = Field(default=0, ge=0)


class ReviewResult(FrozenModel):
    schema_version: Literal["product-review-v1"] = "product-review-v1"
    profile_id: Literal["product_triage_v1"] = "product_triage_v1"
    run_id: str = Field(min_length=1)
    run_state: RunState
    identity: IdentityBundle
    findings: tuple[FindingView, ...] = ()
    evidence_receipts: tuple[EvidenceReceipt, ...] = ()
    capabilities: tuple[CapabilityDecision, ...] = ()
    diagnoses: tuple[Diagnosis, ...] = ()
    scope_admissions: tuple[ScopeAdmission, ...] = ()
    counts: ReviewCounts = Field(default_factory=ReviewCounts)
    accounting: ReviewAccounting = Field(default_factory=ReviewAccounting)
    artifacts: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_evidence_references(self):
        receipts = {item.observation_id: item for item in self.evidence_receipts}
        if len(receipts) != len(self.evidence_receipts):
            raise ValueError("Duplicate evidence receipt reference")
        if len({item.candidate_id for item in self.findings}) != len(self.findings):
            raise ValueError("Duplicate finding candidate")
        if self.counts.candidate_count != len(self.findings):
            raise ValueError("Candidate denominator does not match the findings")
        if any(value > self.counts.candidate_count for value in (
            self.counts.validated_candidates, self.counts.unprocessed_candidates,
        )):
            raise ValueError("Candidate processing count exceeds its denominator")
        if self.counts.parsed_files + self.counts.parse_errors > self.counts.source_files:
            raise ValueError("Source denominator does not include all parsed/error files")
        if self.run_state == "COMPLETED" and (self.counts.parse_errors or self.counts.unprocessed_candidates):
            raise ValueError("Completed review cannot hide incomplete analysis")
        if self.run_state == "COMPLETED" and any(
            item.required and item.state != "AVAILABLE" for item in self.capabilities
        ):
            raise ValueError("Completed review cannot hide an unavailable required capability")
        for finding in self.findings:
            if set(finding.evidence_refs) - receipts.keys():
                raise ValueError("Finding has an unknown evidence reference")
            referenced = [receipts[key] for key in finding.evidence_refs]
            if any(item.subject != finding.subject for item in referenced):
                raise ValueError("Evidence receipt subject does not match finding subject")
            if any(item.source_identity != self.identity.source_digest
                   or item.analysis_contract_digest != self.identity.analysis_contract_digest for item in referenced):
                raise ValueError("Evidence receipt identity does not match the product source and analysis contract")
            proofs = {item.proof_status for item in referenced
                      if item.supplies_proof(finding.subject, finding.contract)}
            required = {
                "SUPPORTED": {ValidationStatus.CONFIRMED},
                "REFUTED": {ValidationStatus.REFUTED},
                "CONFLICT": {ValidationStatus.CONFIRMED, ValidationStatus.REFUTED},
                "UNKNOWN": set(),
            }[finding.property_state]
            if not required <= proofs:
                raise ValueError("Property state lacks complete matching proof receipts")
            if finding.property_state == "UNKNOWN" and proofs:
                raise ValueError("UNKNOWN cannot erase delivered complete property proofs")
            if finding.property_state in {"SUPPORTED", "REFUTED"} and len(proofs) > 1:
                raise ValueError("Conflicting proof receipts require CONFLICT")
        if self.counts.sufficient_evidence_candidates != sum(
            finding.property_state != "UNKNOWN" for finding in self.findings
        ):
            raise ValueError("Property proof count does not match the findings")
        return self
