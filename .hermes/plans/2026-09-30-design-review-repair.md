# cv-agent Design Review Verification and Repair Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Verify the supplied document review against the repository, repair demonstrated contract violations, and deliver an independent offline product review path.

**Architecture:** Preserve candidate binding, typed observations, semantic admission, original E1–E5 profiles and historical experiments. Add a separate product_triage_v1 application with capability decisions, deterministic reduction and readable artifacts. Shared defects are fixed at their original boundary after a failing offline regression.

**Tech Stack:** Project uv; Python 3.13.5; Pydantic 2.13.5; LangGraph 1.2.11; existing adapters and tool registry; pytest.

---

The user has requested execution. Proceed inline in dependency order, without a separate execution-choice prompt. Optional execution sub-skills are not installed; these steps use existing read/test/edit tools. No model call, third-party target execution, automatic dependency installation or evaluator-label access is part of this work.

## Baseline preservation

- HEAD: 4dba622db459d4487bc8493b9af3a6a5f40a3387.
- Preserve the existing final-summary correction, docs/README.md, technical-report files and the user-supplied review PDF.
- Baseline receipt: audit/design_review_20260930/baseline.json.
- Collection and full-suite logs: artifacts/design_review_repair_20260930/.

## T00: source and issue mapping

**Files:** Read src/cv_agent/cli.py, agents/workflow.py, agents/evidence_policy.py, agents/plan_policy.py, agents/react.py, domain/types.py, domain/evidence.py, tools/identity.py, tools/registry.py and runtime model/admission/budget/journal modules. Create audit/design_review_20260930/{baseline.json,issue-map.md,tasks.json}.

- [x] Read all 32 physical PDF pages and docs/TEST_CONTRACT.md.
- [x] Record actual Git status, dependency versions and original dirty-file hashes.
- [x] Collect tests: uv run --no-sync pytest --collect-only -q; actual collection is 2562 cases.
- [x] Complete baseline uv run --no-sync pytest: 2560 passed, 2 failed in 478.78 seconds. Failures are retained in the baseline receipt and log.
- [x] Map D01–D14 and H01–H09 in audit/design_review_20260930/issue-map.md. Hypotheses remain pending behavioral checks.

## Ordered implementation units

Each unit gets a failing acceptance/regression test before implementation, positive controls, affected legacy checks, and an actual task receipt. Exact tests and implementation changes are recorded before that unit starts.

| Unit | Actual/new files | Acceptance behavior |
| --- | --- | --- |
| T01 | New domain/product_result.py | Versioned states and property contracts; valid round-trip; mismatched subjects and unsupported strong statements rejected. |
| T02 | New application/preflight.py | Static capability independent of model/witness; precise unavailable capabilities; no target execution. |
| T05 | domain/types.py, tools/identity.py, new tests/test_identity_snapshot.py | Sealed authority does not drift through nested aliases; source, analysis and view identities separate. |
| T03 | cli.py; new application/service.py and presentation/report.py | Real offline CLI writes consistent JSON/report for normal, zero-candidate, parse-error and partial inputs. |
| T06 | agents/evidence_policy.py, agents/workflow.py, new product reducer | Actually observed matching facts constrain final results; conflict handling order-independent; replicas add no proof. |
| T04 | Product diagnoses, doctor/controller tests | Environment, input and semantic gaps distinct; finite waiting/resume; no credential values exported. |
| T09 | Product context grants and existing safe source readers | Authorized span expansion charged; denied/out-of-range reads visible; E1–E5 budgets preserved. |
| T07 | Planning/workflow/ReAct and product controller | Independent static work survives optional blocking; required validation completion remains enforced; legal maximum plan finishes. |
| T08 | tools/registry.py, ReAct budget/delivery tests | Required certificates fit the shared cap; re-delivery billed without re-execution; clipping never proves. |
| T12 | Runtime budget/journal/model and recovery/redaction tests | Cancellation bounded; malformed responses retain usage; partial journals produce explicit audit errors. |
| T13 | New tests/test_application_smoke.py and acceptance receipt | Actual CLI and enabled A01–A34 requirements pass, plus complete offline suite and harness. |
| T10/T11 | Conditional isolation/environment code and owned benign fixtures | Verify existing limitations; default static product does not enable scratch or native building. Conditional work remains separately identified. |
| T14 | Independent product evaluation protocol | Freeze denominators and paired fields. Human/model measurements require real inputs and separately authorized experiments; never invent them. |

## Final verification and delivery

- [x] Preserve each regression failure before its repair.
- [x] Recheck legacy identity, admission, scheduling, budgets and characterization after shared changes.
- [x] Run complete uv run --no-sync pytest and cv-agent harness-check on final code: 2684 passed in 414.20s; PASS.
- [x] Run actual product CLI on owned benign fixtures from an empty output directory: seven cases passed plus zero HTTP/socket/gate transport spy.
- [x] Record task status, paths, before/after behavior, exact test commands/exit codes/logs, compatibility and gaps in audit/design_review_20260930/.
- [x] Preserve G-A = NO and historical request/token counts; T10/T11 remain not enabled, T14 measurement remains not run.

## T01 concrete contract and test steps

**Create:** src/cv_agent/domain/product_result.py and tests/test_product_contract.py. Existing E enums and JSON schemas remain unchanged.

The product contract contains PropertyContract, IdentityBundle, Diagnosis, CapabilityDecision, EvidenceReceipt, FindingView, ReviewCounts, ReviewAccounting and ReviewResult. Property predicates have an explicit version and quantifier. ReviewResult validates receipt identities and properties, complete delivery, supported proof methods, and required references. Its application-security field is fixed to NOT_ASSESSED. Strong property states require matching typed proof receipts; source patterns and incomplete receipts cannot supply them.

- [x] Create the acceptance tests below and run uv run --no-sync pytest tests/test_product_contract.py. Before implementation the missing product module caused collection failure, recorded as a functional gap.

```python
def test_unknown_round_trip_keeps_application_unassessed():
    result = example_result(property_state="UNKNOWN")
    assert ReviewResult.model_validate_json(result.model_dump_json()) == result
    assert result.findings[0].application_security == "NOT_ASSESSED"
    assert result.accounting.model_requests == 0

def test_strong_state_rejects_receipt_for_another_subject():
    data = example_result(property_state="SUPPORTED").model_dump(mode="json")
    data["evidence_receipts"][0]["subject"]["candidate_id"] = "other"
    with pytest.raises(ValueError, match="subject"):
        ReviewResult.model_validate(data)

def test_incomplete_or_pattern_receipt_cannot_support_property():
    data = example_result(property_state="SUPPORTED").model_dump(mode="json")
    data["evidence_receipts"][0]["method"] = "source_pattern"
    with pytest.raises(ValueError, match="proof"):
        ReviewResult.model_validate(data)
```

The actual test file supplies the complete benign fixture builder and parameterizes schema, state, property, delivery and scope mismatches. After tests fail, implement the declared models and reference validation; then re-run this file plus existing identity and refactor-characterization checks. Archive exact before/after command results in the T01 receipt.

T01 acceptance: missing-module collection failed before implementation; after implementation 49 product/subject/legacy-characterization checks passed. The complete final suite remains required after all repairs.

## T05 snapshot implementation

**Modify:** domain/types.py and domain/evidence.py. **Create:** tests/test_identity_snapshot.py. Preserve existing JSON schemas and indexed-source digest algorithm.

- [x] Regress mutation through an original nested premise, the public candidate/subject view, observation metadata and a model_copy update. The stored authority and original digest remain unchanged.
- [x] Add SnapshotModel as a FrozenModel subclass. Snapshot dictionary/list fields at construction and model_copy; public field reads return defensive copies with ordinary JSON container types. Use it for Candidate, CodeDocument, ValidationSubject and ToolObservation only.
- [x] Keep model_copy update semantics unchanged except alias isolation; explicit changed versions are still possible. This avoids replacing JSON dictionaries with subclasses that would break exact-type runtime checks.
- [x] Run uv run --no-sync pytest tests/test_identity_snapshot.py before and after; then source subject, semantic, tool, workflow and characterization controls.

```python
class SnapshotModel(FrozenModel):
    def model_post_init(self, context):
        self._seal_containers()

    def _seal_containers(self):
        for name in type(self).model_fields:
            value = self.__dict__.get(name)
            if isinstance(value, (dict, list)):
                object.__setattr__(self, name, deepcopy(value))

    def __getattribute__(self, name):
        value = super().__getattribute__(name)
        if name in type(self).model_fields and isinstance(value, (dict, list)):
            return deepcopy(value)
        return value

    def model_copy(self, *, update=None, deep=False):
        result = super().model_copy(update=update, deep=deep)
        result._seal_containers()
        return result
```

T05 reproduced five nested-alias failures; all five regressions and related source/subject/workflow/memory/characterization controls passed (91 tests). Existing JSON types, schemas and digest algorithm remain unchanged.

## T06 verified shared defect and correction

The actual behavioral log is artifacts/design_review_repair_20260930/T06_before_verified.log: 3 failures, 2 positive controls passed. Earlier setup-error logs are retained and are not defect evidence.

Modify agents/evidence_policy.py and agents/workflow.py. Revalidate final material ballots against all actually delivered matching observations before slow or fast adjudication. InsufficientEvidenceError demotes only final ballots with global-evidence-v2 provenance; protocol errors remain errors. Keep original task records, observations, costs and producer identity. Do not invent unexecuted future evidence or upgrade ABSTAIN.

Run tests/test_global_evidence_review.py and legacy evidence/workflow/quorum/characterization controls. The product reducer will reuse these proof-scope rules while dispensing with model quorum.
