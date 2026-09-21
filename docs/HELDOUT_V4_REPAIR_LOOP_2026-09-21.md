# Held-out gate repair loop, 2026-09-21

The user authorized repeated offline regression, diagnosis, repair and bounded
live gate runs, retaining the full matrix for the user to launch. No full matrix
is run by this loop, and no acceptance conditions or expected abstentions change.

## First repair

The v3 ranking gave repository-path lexical matches precedence over direct
dependencies. Both MLflow command constructors existed in the index, but only
one entered the context. V4 explicitly ranks graph distance before lexical score
within the same top-k, hop and token budgets. This affects E3–E5 uniformly.

The original advisory scenario stated `enable_mlserver=True`. The neutral model
scope had dropped it, and the taint tool treated entry parameters as trusted
unless a request-source pattern occurred inside the span. V4 declares
`input_parameters=["model_uri"]` and `entry_boolean_arguments={"enable_mlserver":true}`
at the pair level, identically for both revisions. These declarations are visible
assumptions, not labels or validation witnesses; they are also part of the exact
validation subject identity. Unknown download semantics remain unknown. Declared
input flow produces at most MAY_REACH/UNRESOLVED, never typed confirmation.

The source-only audit is `scripts/audit_heldout_evidence_v4.py`; its output is
`artifacts/heldout_evidence_v4_audit.json`. Both command constructors and the
download function are retrieved. The vulnerable command remains AMBIGUOUS;
the quoted fixed command is SANITIZED on the analyzed scenario's POSIX shell
path. Both have a static MAY_REACH trace; this is not an exploit witness.

## First live v4 run

Run: `artifacts/python_heldout_pair_gate_v4/158d5dcbd0b44a3ab3a180c4834d6a9d`.
645 offline tests passed before transport. The gate did not pass:

- Langflow fixed E5 abstained. Its authorization tool counted the
  `@router.delete(...)` registration as a runtime deletion before the service
  ownership check. The actual service check was visible.
- MLflow vulnerable E5 and fixed E4 completed with expected labels.
- MLflow fixed E5 exhausted its ReAct steps: the expert's earlier subtask spent
  most of the shared 8,192 observation budget on full source reads; its later
  required dataflow tool could only return a truncation marker.

## Second repair

Authorization comparison excludes Python decorator expression lines from the
per-invocation sensitive-action list. Guarded and unguarded service controls
remain distinct, and the tool still reports UNRESOLVED rather than refutation.

Each expert's fixed observation budget now reserves a share for every planned
subtask. Unspent earlier shares carry forward, and already consumed tokens remain
charged. The total budget, validation requirements and ReAct step limit are
unchanged. The prompt reports available budget and asks for required validators
before optional reads. Regression tests verify reservation, carry-forward and
truncation without borrowing future shares.

Full offline regression after the second repair: **648 passed in 22.40 seconds**.

These runs are post-inspection engineering checks. Their SAFE predictions do not
constitute general application safety or untouched held-out research results.

## Subsequent iterations and final acceptance

- `725c18d7bc704a31bee3d015600514cf`: 9 completed, one MLflow vulnerable
  E5 abstention, no execution failures. The taint rationale treated absence of
  typed confirmation as requiring abstention despite the static MAY_REACH and
  selected-path interpolation evidence. Its mandate now distinguishes a
  prediction from typed validation, retains uncertainty about transformations,
  and still rejects isolated sink/helper evidence as insufficient.
- `6aa18cc57a2647cc941eeddfd631fcb9`: all three MLflow cells completed as
  expected; Langflow vulnerable E5 failed on an invented citation after repeating
  the same final JSON. The citation checker still rejects unknown and failed-call
  evidence. Its feedback now names the invalid IDs and lists available successful
  tool citations, without silently substituting an ID or changing the vote.
- `a9b918176b034efe9c9ad484a25c5d06`: **10/10 completed with expected labels,
  zero failed cells, zero abstained cells; acceptance passed=true, issues=[]**.
  Its automatic live-admission test run passed **649 tests in 24.56 seconds**.
  Usage: **156 requests, 156 responses, zero invalid responses, 1,087,675 reported
  tokens**, with no missing usage or usage-accounting conflicts.

Final inspection confirmed the current source fingerprint matches the successful
run and the full matrix shares its source cases, provider config, scope declarations
and retrieval settings. The matrix retains its original two declared MLflow E1
abstentions; these E1 cells are not in the ten-cell gate. Langflow and MLflow
material predictions remain UNRESOLVED rather than being promoted to typed
confirmation/refutation.

All four repair-loop gate runs together consumed **603 requests and 4,188,763
reported tokens**. Historical failures are preserved. No full matrix was started.

User launch command after this gate:

```bash
bash /home/joker/AAA_NUS_SEM3/cv_agent/scripts/heldout_matrix.sh
```
