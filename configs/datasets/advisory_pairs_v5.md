# Advisory dataset v5 — diagnostic declaration correction

The only JSON change from v4 is
`pairs[2].entry_value_assumptions["self._nworkers"]`: `null` → `1`.
This is the shared hp003 declaration for both fixed source snapshots.

`PyFuncBackend.__init__` defaults `workers` to `1` and assigns
`self._nworkers = workers or 1` (`mlflow/pyfunc/backend.py:95` in both
snapshots). The diagnostic call uses that default constructor argument, so
`1` is the actual runtime value. The old `null` declaration contradicted
that constructor. This correction does not establish command safety or
vulnerability and does not alter any other proof obligation.

v4 is preserved byte for byte. The old six-cell results remain results for
v4, including its original declaration; they must not be relabelled as v5.
Existing experiment profiles and runners continue to use v4. New offline
diagnostics explicitly select v5. The dataset remains development data with
`claim_eligible=false`; v5 does not authorize held-out claims or model calls.

This note is a sidecar because the strict dataset schema accepts no change
metadata, and the v5 JSON is required to differ at exactly one key.
