# System-Generated Witness Step 1 Implementation Plan

> **For agentic workers:** Execute only this authorized offline step. Stop after tests, one paired scripted-model acceptance run and committed evidence; steps 2 and 3 require later user direction.

**Goal:** Let an agent request the existing positive-only witness using a generated subject/source-bound manifest and restricted constructor/layout supplements.

**Architecture:** Trusted execution context binds checkout/import root/interpreter/resources/read grants. A deterministic AST builder owns entry, subject premises and probe input; the model supplies only still-missing constructor parameter values and relative precondition files. A registered positive-only validator executes the generic witness with a recorder selected from its authenticated argv, preserving the existing runtime obligations and benign control.

**Tech Stack:** Existing UV environments, AST/typed JSON, ToolRegistry, FixtureProofScope and the existing isolated witness. No live model, network installation or held-out sample.

## 1. Subject/source manifest builder

**Create:** `src/cv_agent/tools/validation/witness_manifest.py`, `tests/test_witness_manifest.py`.

- [ ] Add failing behavioral controls for source mismatch, ambiguous entry, wrong declarations, missing constructor data, caller-owned overrides/stubs/labels and import-constant ambiguity.
- [ ] Implement `WitnessExecutionContext`, strict `WitnessSupplement(constructor_parameters, precondition_files)`, `ManifestDraft` and `build_witness_manifest(index, subject, context, supplement)`.
- [ ] Derive class/method/module/location and source inventory from the frozen index plus SHA-checked files. No handwritten target wrapper or model-selected source identity.
- [ ] Bind one declared input to the tool's controlled existing local directory; derive call kwargs from declared booleans/values and the actual signature. Unsupported required call arguments keep explicit gaps.
- [ ] Constructor recipes use source assignments from self attributes to parameters and unique literal imports (including a False != equality premise). They are candidate input recipes, never proof; actual runtime observers remain mandatory. Unknown config remains a model requirement.
- [ ] Model input only fills discovered missing constructor parameter names and safe relative file content. Schema rejects protected source/probe/control/obligation/runtime fields, stubs and label metadata. Missing data yields explicit requirements without running the target.

## 2. Tool-owned recorder selection

**Modify:** `src/cv_agent/evaluation/diagnostics/bounded_execution_witness.py`. **Create:** `tests/test_witness_recorder_derivation.py`.

- [ ] Add real synthetic positive/negative controls before implementing `derive_recorder=True` in verification mode only.
- [ ] Derive a direct literal executable/fixed-argument prefix from the authenticated captured Bash command and exact tool-owned probe path. Require the original narrow command shape; shell control syntax/absolute executable/ambiguity remain gaps.
- [ ] Select recorder from measurement rather than model arguments or sample names. Require benign control to use the same measured prefix. Preserve all existing proof gates and default behavior.

## 3. Agent registration and proof consumption

**Create:** `src/cv_agent/tools/validation/bounded_witness.py`, `tests/test_bounded_witness_tool.py`.
**Modify:** `tools/validation/registry.py`, `tools/registry.py`, `harness/defaults.py`, `agents/evidence_policy.py`, `agents/plan_policy.py`, `agents/workflow.py`, and shared source qualification in `evaluation/diagnostics/witness_contract.py` if needed.

- [ ] Add behavioral tests for generated draft -> structured supplement -> real typed observation -> candidate conclusion, missing fields, wrong scope and literal-only refusal of SAFE.
- [ ] Register `run_bounded_execution_witness` with model schema limited to WitnessSupplement and trusted runtime contexts configured outside model calls. No context means unavailable; no automatic dependency/environment installation.
- [ ] Emit existing PositiveOnlyWitnessProofScope with candidate coverage, bounded_execution and supported_statuses=(CONFIRMED,). Only exact subject + complete delivered proof can support confirmation.
- [ ] Add scan validator/allowlist and deterministic requirement task when the configured service supports the exact subject. Retain other mandatory checks; do not pretend an incomplete dynamic draft is a registered complete fixture.
- [ ] Keep nonce/probe/control/security private and fresh per execution. Initial missing-field responses reveal no nonce. Save raw records outside the small model observation; projection stays complete enough for proof admission.
- [ ] Preserve duplicate-call refusal, source admission, truncation and source/subject mismatch gates. Update only genuinely changed schema/tool/mandate snapshots with provenance.

## 4. Offline acceptance and stop

**Create:** an offline evaluation entrypoint and tests for scripted model tool calls; durable result report in `.hermes/plans/`.

- [ ] Script model responses to supply missing config/layout through the same registered tool API, without reading label mappings. Positive/negative synthetic tests belong to pytest; heavy hp003 runs stay outside pytest and use existing environments.
- [ ] Run full `uv run --no-sync pytest` and harness; commit code before executing the paired acceptance.
- [ ] On v5 hp003_a/b, generate both manifests through the system builder (no prior manual template) and execute the registered tool once per snapshot with the same system-selected nonce/input/profile/read grants. Verify a CONFIRMED/expanded, b UNRESOLVED/literal.
- [ ] Check source/stub/parameter/missing-field/label-flip controls offline; labels cannot affect tool arguments, generated manifests or measured classification.
- [ ] Preserve raw observations, manifests, proof scope, generation provenance, requests (scripted only) and artifact digests; commit and stop. Do not run a live arm or pick new advisories.

## Reporting scope

Confirmation requires an attacker-controlled local directory whose name includes shell metacharacters to exist in this scenario. It is not proof of remote arbitrary command injection. Runtime/native/tampering exclusions remain. Step 1 demonstrates system-generated input plus tool verification; autonomous live detection and generalization remain future gates.
