# Advisory dataset v6 — CLI near transfer

v6 appends only `hp004_entry_00390_ghsa_rvhj_8chj_8v3c` to v5. Historical v1–v4 standalone configurations and v4/v5 datasets are frozen by SHA256 tests. The new pair has no input, Boolean, condition or value premises. Its title removes the editorial branch annotation; it is development data with `claim_eligible=false`.

The declared entry is `mlflow/models/cli.py:24`, the decorator-inclusive `serve` function through line 106 (definition line 34). The declared operation is `mlflow/utils/environment.py:1014`. These locations come from the supplied development plan and are checked against the existing two checkouts; no protected held-out entry or label file is read.

The fix pair is verified locally: between `d1312edfca36c7acae0d064ef6a094eded88e14f` and `202fac4c83ccc8544c087c142b80196d0e60695c`, `mlflow/pyfunc/mlserver.py` adds `shlex` and changes `mlserver start {model_uri}` to quote that value. CLI, backend and environment source files are unchanged by this diff. This is an upstream value change on the CLI execution chain, not a claim that line 1014 itself changed.

The relevant call chain is `models.cli.serve` → `get_flavor_backend` → `PyFuncBackend.serve` → the selected server implementation's `get_cmd` → `prepare_env(...).execute` → `Environment.execute` → `_exec_cmd`. `get_flavor_backend` loads real `MLmodel` metadata and selects the Python-function backend; its constructor receives the loaded flavor and caller options. On the nonlocal branch the constructed command passes into `Environment.execute`, which joins activation commands and invokes the platform shell. The quoting change therefore applies before that shell receives the command. Environment preparation may emit an earlier unrelated process; the witness must not skip it.

On a local branch the same entry instead emits from `mlflow/pyfunc/backend.py:311`. A whole-entry dangerous-path confirmation there must report that actual emitter differs from the declared operation at environment.py:1014. Neither local success nor this static call-chain verification proves execution of the declared nonlocal operation.

The allowed adapter invokes the genuine Click callback directly. The public Click parser, its conversions and CLI validation are not executed. Actual source, callback globals/code/frame binding and all runtime obligations remain mandatory; the resulting observation only covers that concrete callback invocation under its reported premises.
