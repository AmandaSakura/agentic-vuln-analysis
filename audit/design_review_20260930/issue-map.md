# Report-to-source verification map

Review source: docs/reports/cv_agent_design_review_and_repair_plan_2026-09-30.pdf (32 physical pages; 30 numbered body pages).

Baseline and existing dirty-file hashes are in baseline.json. Read-only observations below are not labeled reproduced defects until the corresponding behavioral regression runs.

## Design and delivery findings

| Report | Actual location | Verified current fact | Repair boundary |
| --- | --- | --- | --- |
| D01/D03/D13 | runtime/admission.py; tools/registry.py; evaluation/preparation/prepare_witness_environment.py | Full source pytest admission exists; static parsing and registered execution capabilities are separate. No unified product preflight exists. | New application capability/preflight, retain existing gate. |
| D02 | runtime/fixture_isolation.py; runtime/witness/isolation_policy.py | Existing execution profile denies writes. Historical TempDir failure is already documented. | Conditional owned-fixture capability; default product remains static. |
| D04/D05 | domain/validation_protocol.py; agents/plan_policy.py::required_tasks; agents/workflow.py::_blocked_tasks | Preparation is distinguished from completion; witness tasks precede command tasks in existing policy. | Product controller and genuine data dependencies; preserve required research obligations. |
| D06 | agents/workflow.py::_engine; tools/registry.py::_finalize | Per-task cumulative ceiling divides the expert budget by task count; physical de-duplication already exists. | Regression for feasible unequal certificates; separate re-delivery from execution. |
| D07/D12 | cli.py::build_parser/main; agents/discovery.py; evaluation/execution.py | CLI has research/diagnostic entrypoints; no local product review or doctor command. | Separate application/service and presentation export. |
| D08/D09 | agents/voting.py; agents/evidence_policy.py; agents/validator_accounting.py | Quorum and exact-subject admission exist; shared proofs are explicitly counted. | New deterministic property reducer; shared admission defects fixed in place. |
| D10 | retrieval/index.py; tools/repository.py::repository_tools | Existing E profiles admit document paths and bill serialized observations. No product span-grant extension interface. | Product-only explicit context extension; legacy frozen retrieval unchanged. |
| D11 | runtime/model.py::complete; runtime/admission.py | A process-bound full-suite gate exists; no saved pass-stamp bypass. | Offline product never loads provider; preserve gate. |
| D14 | evaluation/protocols/readiness.py; final-summary/G-A records | Claim readiness is distinct from operational readiness; G-A remains NO. | Independent product acceptance and prospective evaluation protocol. |

## H hypotheses and concrete regression plan

| Hypothesis | Actual symbols | Planned owned/offline check | Initial assessment |
| --- | --- | --- | --- |
| H01 | workflow::_adjudicate/_result; evidence_policy::validate_conclusion | Two valid typed proofs of one toy property, same subject and complete scope, opposite states, in both arrival orders; unrelated-subject positive control. | Final workflow currently combines ballots without a final global admission pass; regression pending. |
| H02 | workflow::_try_fast; voting::QuorumPolicy | Compare actually produced contradictory observation with a future unexecuted observation; product reducer must consume the former and default to no early-stop. | Existing guarantee covers fixed ballots, not hypothetical later facts; no claim of automatic full/fast semantic equivalence. |
| H03 | domain/types.py::FrozenModel; tools/identity.py::candidate_subject | Mutate nested premise through original container, candidate/subject alias and model_copy; sealed state/digest must not drift. | Frozen protects attributes only; nested-alias regression pending. |
| H04 | tools/identity.py::repository_source_digest; code_adapters; witness_manifest | Modify source/helper/import bytes versus retrieval selection; verify layer-specific identity and preserved legacy algorithm. | Legacy index hash and witness inventory are different on purpose; product source/view identity still missing. |
| H05 | workflow::_visible_executions/_run_named_expert | Earlier proof, irrelevant later UNKNOWN, then source read; verify facts retained and same-scope adverse proof still constrains final state. | Trace/cost aggregation exists; label remains last model conclusion. Test before changing. |
| H06 | tools/repository.py::read; tools/registry.py::_finalize | Small initial window versus billed read of admitted document; reject second unadmitted span and out-of-root source. | Legacy document-path policy permits billed re-read; no evidence yet of free file expansion. New product uses explicit spans. |
| H07 | runtime/budget.py; journal.py; evaluation/experiment_guard.py | Mock last-slot concurrency, cancellation, journal write failure and truncated tail; usage reservation remains unknown when response absent. | Locks/reservations exist; audit partial journal handling explicitly. |
| H08 | runtime/model.py::_record_response; tools/registry.py; product presentation | Fake state strings and instruction comments remain data; fake secrets redacted only in display, source digest unchanged. | Known API key response redaction exists; product public redaction is a new requirement. |
| H09 | workflow::run; installed langgraph/_internal/_config.py | Maximum eight-task scripted plan and an injected no-progress route; record real graph node count. | Locked LangGraph default recursion limit is 10007, not assumed 25; business-bound limit should be explicit and tested. |

## Scope

T10/T11 are conditional branches requiring an explicitly enabled owned-fixture execution profile and matching local resources. The static product does not need them. T14 can freeze an evaluation protocol here; real human or model increment measurement is not supplied by code unit tests. No historical G-A result, old API ledger or evaluator label is changed.

## Final verification

The hypothesis table above preserves the initial assessment. H01/H03/H08 were reproduced and fixed; H02's actually delivered conflict is fixed while its unexecuted-future limitation is retained. H09 now has an explicit measured business bound. H04/H05/H06/H07 have the distinctions, positive controls and product additions described in verification.md; they are not relabeled as previously reproduced defects. All enabled acceptance checks and 2684 full-suite tests passed. Conditional scratch/native and unmeasured human/model value remain explicit in acceptance.json.
