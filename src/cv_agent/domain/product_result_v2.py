"""Explicit local-proof product schema; v1 delivery counters retain their meaning."""
from __future__ import annotations
from typing import Literal
from pydantic import Field, model_validator
from cv_agent.domain.types import FrozenModel, SnapshotModel
from cv_agent.domain.product_result import FindingView, Diagnosis, ScopeAdmission


class ResourceLimits(FrozenModel):
    version: Literal['product-resource-limits-v2'] = 'product-resource-limits-v2'
    max_files: int = Field(default=1000, ge=1, le=1000)
    max_source_bytes: int = Field(default=10*1024*1024, ge=1, le=10*1024*1024)
    max_candidates: int = Field(default=1000, ge=1, le=1000)
    max_ast_nodes: int = Field(default=200000, ge=1, le=200000)
    max_record_bytes: int = Field(default=64*1024*1024, ge=1, le=64*1024*1024)
    wall_seconds: float = Field(default=120, gt=0, le=120)
    cpu_seconds: int = Field(default=120, ge=1, le=120)
    memory_bytes: int = Field(default=1024*1024*1024, ge=64*1024*1024, le=1024*1024*1024)


class ProductIdentityV2(FrozenModel):
    version: Literal['product-identity-v2'] = 'product-identity-v2'
    source_digest: str = Field(pattern=r'^[0-9a-f]{64}$')
    semantic_engine_digest: str = Field(pattern=r'^[0-9a-f]{64}$')
    retrieval_view_revision: str = Field(pattern=r'^[0-9a-f]{64}$')
    delivery_policy_digest: str = Field(pattern=r'^[0-9a-f]{64}$')
    execution_digest: None = None


class ReviewAction(FrozenModel):
    kind: Literal['review-property','supply-input','review-lead','reconcile-conflict']
    owner: Literal['project-maintainer'] = 'project-maintainer'
    required_input: tuple[str, ...]
    reanalysis: str
    done_condition: str


class LocalFinding(FindingView, SnapshotModel):
    operation_locator: dict
    display_class: Literal['BOUNDED_PROPERTY','NEEDS_INPUT','REVIEW_LEAD']
    analysis_state: Literal['NOT_STARTED','COMPLETED','BLOCKED','FAILED']
    persistence_state: Literal['NOT_ATTEMPTED','COMPLETE','FAILED']
    local_verification: Literal['VERIFIED','INCOMPLETE','UNAVAILABLE']
    assumptions: tuple[str, ...] = ()
    review_action: ReviewAction
    record_refs: tuple[str, ...] = ()
    producer_ids: tuple[str, ...] = ()

    @model_validator(mode='after')
    def local_proof_boundary(self):
        if self.analysis_state=='NOT_STARTED'and self.persistence_state!='NOT_ATTEMPTED':
            raise ValueError('A candidate that never started cannot have persisted analysis evidence')
        if (self.persistence_state=='COMPLETE')!=(self.local_verification=='VERIFIED'):
            raise ValueError('Complete persistence and verified local records must agree')
        if self.persistence_state=='COMPLETE'and(not self.record_refs or not self.producer_ids):
            raise ValueError('Complete records require their original producer and local references')
        if self.property_state != 'UNKNOWN' and not (
            self.local_verification == 'VERIFIED' and self.persistence_state == 'COMPLETE'
            and self.record_refs and self.evidence_refs
        ):
            raise ValueError('A local strong state requires complete verified records')
        if self.persistence_state == 'FAILED' and self.property_state != 'UNKNOWN':
            raise ValueError('Incomplete material persistence cannot supply a one-sided proof')
        return self


class ReviewCountsV2(FrozenModel):
    source_files_enumerated: int = Field(default=0, ge=0)
    source_files_read: int = Field(default=0, ge=0)
    parsed_files: int = Field(default=0, ge=0)
    parse_errors: int = Field(default=0, ge=0)
    inventory_complete: bool = True
    candidate_total: int = Field(default=0, ge=0)
    analysis_not_started: int = Field(default=0, ge=0)
    analysis_completed: int = Field(default=0, ge=0)
    analysis_blocked: int = Field(default=0, ge=0)
    analysis_failed: int = Field(default=0, ge=0)
    evidence_persisted_candidates: int = Field(default=0, ge=0)
    has_sufficient_evidence: int = Field(default=0, ge=0)
    resolved_without_conflict: int = Field(default=0, ge=0)
    supported: int = Field(default=0, ge=0)
    refuted: int = Field(default=0, ge=0)
    unknown: int = Field(default=0, ge=0)
    conflict: int = Field(default=0, ge=0)

    @model_validator(mode='after')
    def conservation(self):
        if self.parsed_files+self.parse_errors!=self.source_files_enumerated:
            raise ValueError('Source parsing states do not conserve the enumerated inventory')
        if self.parsed_files>self.source_files_read or self.source_files_read>self.source_files_enumerated:
            raise ValueError('Parsed and read file counts exceed the source inventory')
        if self.candidate_total != (self.analysis_not_started+self.analysis_completed+
                self.analysis_blocked+self.analysis_failed):
            raise ValueError('Candidate analysis states do not conserve the denominator')
        if self.candidate_total != self.supported+self.refuted+self.unknown+self.conflict:
            raise ValueError('Property states do not conserve the denominator')
        if self.has_sufficient_evidence != self.supported+self.refuted+self.conflict:
            raise ValueError('Sufficient evidence count is inconsistent')
        if self.resolved_without_conflict != self.supported+self.refuted:
            raise ValueError('CONFLICT cannot be counted as resolved')
        if self.evidence_persisted_candidates > self.analysis_completed+self.analysis_failed+self.analysis_blocked:
            raise ValueError('Persisted candidates exceed analyzed candidates')
        return self


class ReviewResultV2(SnapshotModel):
    schema_version: Literal['product-review-v2'] = 'product-review-v2'
    profile_id: Literal['product_triage_v2'] = 'product_triage_v2'
    run_id: str
    run_state: Literal['COMPLETED','PARTIAL','BLOCKED','FAILED','CANCELLED']
    identity: ProductIdentityV2
    resource_limits: ResourceLimits
    findings: tuple[LocalFinding, ...] = ()
    counts: ReviewCountsV2
    diagnoses: tuple[Diagnosis, ...] = ()
    accounting: dict
    scope_admissions: tuple[ScopeAdmission, ...] = ()
    artifacts: dict
    local_verification_scope: Literal['USER_OWNED_SELF_GENERATED_PACKAGE'] = 'USER_OWNED_SELF_GENERATED_PACKAGE'

    @model_validator(mode='after')
    def consistency(self):
        if len(self.findings) != self.counts.candidate_total:
            raise ValueError('Finding and candidate denominators differ')
        if len({f.candidate_id for f in self.findings}) != len(self.findings):
            raise ValueError('Duplicate exact operation finding')
        if self.counts.evidence_persisted_candidates!=sum(f.persistence_state=='COMPLETE'for f in self.findings):
            raise ValueError('Persisted candidate count differs from the finding stages')
        for name in ('SUPPORTED','REFUTED','UNKNOWN','CONFLICT'):
            if sum(f.property_state == name for f in self.findings) != getattr(self.counts,name.lower()):
                raise ValueError('Finding property states differ from counters')
        for name in ('NOT_STARTED','COMPLETED','BLOCKED','FAILED'):
            if sum(f.analysis_state == name for f in self.findings) != getattr(self.counts,'analysis_'+name.lower()):
                raise ValueError('Finding analysis states differ from counters')
        if self.run_state == 'COMPLETED' and (not self.counts.inventory_complete or self.counts.parse_errors
                or self.counts.analysis_not_started or self.counts.analysis_blocked or self.counts.analysis_failed
                or any(f.persistence_state == 'FAILED' for f in self.findings)):
            raise ValueError('COMPLETED cannot hide unfinished work')
        if self.accounting.get('model_requests') != 0 or self.accounting.get('target_executions') != 0:
            raise ValueError('Static product cannot claim model/target execution')
        return self
