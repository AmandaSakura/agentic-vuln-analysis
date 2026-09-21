# Evidence coverage repair and protocol v3

This is an offline repair after inspecting the DeepSeek v2 gate. No model API
requests were made during this repair. These inspected cases remain ineligible
for held-out improvement claims.

## Changes

- Python span parsing accepts a separate import-relative module path. The
  held-out pair config explicitly declares Langflow's `python_import_root` as
  `src/backend/base`. Source paths, source hashes and span line numbers retain
  repository coordinates. Qualified external calls do not gain suffix or
  bare-name fallbacks.
- Graph retrieval accepts an explicit direction in its budget. Legacy defaults
  remain forward; the new v3 gate and matrix configs request both directions.
  E3–E5 receive the same direction, top-k, hop limit and context budgets. E1/E2
  retain their local/text retrieval behavior. The provider launchers select v3
  through their existing Python entrypoints; v2 configs and historical artifacts
  are preserved. New gate/matrix runs have separate v3 output directories.
- Command interpretation no longer discards a possible `get_cmd` branch when
  its helper is unavailable. Missing branch semantics remain ambiguous. This
  fixes a demonstrated false SANITIZED report, with a positive control where
  both admitted helpers quote the argument correctly.
- Command tool results list unresolved call names and relative span line
  numbers. This is diagnostic context, not a claim that every listed call
  changes the shell argument.

No changes were made to voting thresholds, evidence acceptance, labels,
expected abstentions, source revisions, model settings or live request limits.

## Local source audit

Command: `uv run --no-sync python scripts/audit_heldout_evidence_v3.py`.
Output: `artifacts/heldout_evidence_v3_audit.json`.

Both Langflow snapshots now link the service to `delete_api_key_route` and admit
that route into the retrieved context. Observed lexical context counts are
5,348 and 5,374, below the configured 16,384 budget. These are local retrieval
accounting counts, not provider token usage. The pipeline separately applies
its existing model-input accounting limits.

Both MLflow snapshots remain AMBIGUOUS in this bounded analysis. The actual
unresolved calls are `mlflow.tracking.artifact_utils._download_artifact_from_uri`
and `mlflow.pyfunc.scoring_server.get_cmd`. The latter is a possible dynamic
callee absent from the admitted helper set; tuple unpacking cannot establish its
return shape. The former produces an unknown value when the unsafe helper is
analyzed alone. Quoting in the fixed helper does not justify discarding another
possible callee. Future live outcomes may therefore still abstain, including on
the fixed snapshot previously reported SAFE.

## Regression coverage

Tests cover exact import-root graph linking and an unrelated external function;
unchanged source coordinates and legacy behavior; caller admission only with an
explicit bidirectional budget; unchanged local context and budget enforcement;
v3 forwarding into the runner; unchanged v2/v3 cases, limits and abstention
expectations; invalid import roots; missing dynamic helpers and fully admitted
safe controls; named unknown command transformations.

The old command-branch test incorrectly expected SANITIZED with an unavailable
alternative. It now tests both missing and complete helper sets. The OWASP
metadata assertion now includes the explicit default graph direction.

Final full offline suite: `uv run --no-sync pytest` — **640 passed in 24.67s**.
