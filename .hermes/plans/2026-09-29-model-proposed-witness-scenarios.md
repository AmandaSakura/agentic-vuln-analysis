# Model-proposed witness scenarios implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking. These packages are not installed here; use the available collaboration agents to execute the already authorized offline work.

**Goal:** A scenario-empty candidate can receive a classified, model-proposed execution scenario, while source binding, probe/control generation and runtime proof remain owned by the system.

**Architecture:** Preserve the original candidate subject. Derive a separate execution subject from explicit classified hypotheses, and record both subjects and scenario provenance with every witness attempt. Reject attempts to replace dataset assumptions or mix classified hypotheses with unclassified supplements. Keep the witness positive-only and retain the existing exact-subject evidence admission rule.

**Tech Stack:** Python 3.12, Pydantic, existing AgenticPipeline, isolated witness workers, ScriptedChatModel, OpenAICompatibleChatModel and its full pytest gate.

## Task 1: Typed scenarios and witness binding

**Files:** Create `src/cv_agent/tools/validation/witness_scenario.py` and `tests/test_witness_scenario.py`; modify `witness_manifest.py`, `bounded_witness.py`, `registry.py` in the same validation directory, and `src/cv_agent/evaluation/diagnostics/bounded_execution_witness.py` for measured worker data checks.

- [x] Add structured scenario values with required `value`, `classification`, and nonempty `rationale`. Accepted classifications are `attacker_controlled_input`, `deployment_configuration`, and `environment_condition`.
- [x] Accept `scenario_hypothesis` in the existing tool supplement, covering the injected parameter, booleans, condition/value assumptions, constructor parameters, and relative precondition files. Model hypotheses require empty legacy supplement maps and a scenario-empty original subject.
- [x] Derive execution assumptions without changing candidate/source identity. Continue source inventory and manifest validation against the actual indexed contents. Models cannot supply a manifest, source identity, probes, controls, stubs, isolation policy, or outcomes.
- [x] Record original/execution subjects, classified premises, origin and canonical scenario digest in the artifact and observation. Add a trusted classified dataset scenario to the execution context for A; it describes the existing premises and does not silently fill missing constructor data.
- [x] Check actual worker argument and file values in addition to the existing source, branch, value, process, preexec and benign-control checks. Missing observations and mismatches stay UNRESOLVED.
- [x] Verify with `uv run --no-sync pytest tests/test_witness_scenario.py tests/test_witness_manifest.py tests/test_bounded_witness_tool.py`.

The concrete model call shape is:

```python
arguments = {
    "constructor_parameters": {},
    "precondition_files": {},
    "scenario_hypothesis": {
        "input_parameter": {
            "value": "location",
            "classification": "attacker_controlled_input",
            "rationale": "The bounded caller supplies this entry argument.",
        },
        "entry_boolean_arguments": {
            "activated": {
                "value": True,
                "classification": "deployment_configuration",
                "rationale": "Exercise the enabled serving configuration.",
            },
        },
        "entry_condition_assumptions": {},
        "entry_value_assumptions": {},
        "constructor_parameters": {},
        "precondition_files": {},
    },
}
```

## Task 2: Offline discovery controls and actual pair replay

**Files:** Create `tests/test_witness_scenario_generalization.py`; modify `src/cv_agent/evaluation/diagnostics/scripted_witness_acceptance.py` and `tests/test_scripted_witness_acceptance.py`; create `configs/profiles/witness_scenario_offline.json`.

- [x] Extend the scripted diagnostic with an explicit optional scenario proposal. The script supplies test hypotheses; final votes still read only delivered typed evidence.
- [x] Use neutral, renamed module/class/entry/parameter/configuration names for a second fixture family. Correct unquoted scenarios must confirm; quoted, wrong flag/condition/input scenarios must remain unresolved. Missing classification must prevent execution. Keep source/identity and label-flip controls.
- [x] Strip all four scenario fields before building the real-checkout B candidate. Supply a classified scripted scenario through the ordinary tool call, then reproduce `hp003_a = CONFIRMED/EXPANDED_OBSERVED` and `hp003_b = UNRESOLVED/LITERAL_OBSERVED` with the existing 2c environments, resource profile and read grants.
- [x] Keep all new output in a fresh directory. Report zero live requests and mark scripted scenarios as development controls, not autonomous scenario discovery.
- [x] Verify with `uv run --no-sync pytest tests/test_witness_scenario_generalization.py tests/test_scripted_witness_acceptance.py`, then execute the offline configuration using the existing diagnostic entrypoint.

## Task 3: Reviewable bounded 2×2 experiment

**Files:** Create `src/cv_agent/evaluation/runners/run_witness_scenario_matrix.py`, `configs/experiments/witness_scenario_2x2.json` and runner tests; modify `src/cv_agent/evaluation/datasets/advisory_source.py` for an explicit scene-removal option.

- [x] Prepare A/B × the two existing development source snapshots, with the same model and E1 arm. A keeps dataset premises; B removes all four scenario fields before subject and prompt construction. Remove editorial scenario annotations from retrieval text; retain a disclosed shared advisory summary and entry scope.
- [x] Use neutral detector identities. Keep evaluation labels, case aliases and interpreter paths out of model messages. Record scenario source separately and never pool A/B results into a recall number.
- [x] Enforce one shared budget of at most 60 actual requests. Use the normal model transport and full pytest gate. Preserve request events, failure records and every reported usage value; stop on transport failure without retry/fallback.
- [x] Provide a preparation mode that validates configuration and writes reviewable inputs without reading API credentials or making model requests. Live execution remains pending explicit user approval requested after all offline work.
- [x] Verify runner tests with offline mocks, including malformed-response accounting and aggregate request-limit controls.

## Task 4: Final verification and research boundaries

**Files:** Update `docs/CURRENT_STATUS.md` and write the new offline result/approval record.

- [x] Run `uv run --no-sync pytest` for the complete final source snapshot, plus the required harness check where applicable.
- [x] Check `git diff --check`, preserve historical artifacts, and report measured results and remaining supported scope.
- [x] State explicitly that no real-model B discovery or held-out generalization has yet been measured. Step 3 uses scenario-free inputs only after reviewing B results.
- [x] Ask for approval of the prepared four cells, named model and total request cap; do not issue real model requests before that approval.
