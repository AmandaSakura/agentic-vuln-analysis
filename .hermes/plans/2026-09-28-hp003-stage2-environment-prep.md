# hp003 stage 2 environment preparation (2026-09-28)

Scope: dependency preparation and import checks only. No witness or model request ran.

## Results

| Case | Fixed checkout | Interpreter | Dependency check | Import binding |
| --- | --- | --- | --- | --- |
| hp003_a | `d1312edfca36c7acae0d064ef6a094eded88e14f` | CPython 3.12.12 | 141 packages compatible | `mlflow` and `backend.py` from checkout |
| hp003_b | `202fac4c83ccc8544c087c142b80196d0e60695c` | CPython 3.12.12 | 141 packages compatible | `mlflow` and `backend.py` from checkout |

Outputs are under `data/diagnostics/hp003-stage2-a-py312/` and
`data/diagnostics/hp003-stage2-b-py312/`. Each contains the exact MLflow lock export
with artifact SHA256 hashes, the CV Agent extra dependency export, install and build
logs, `freeze.txt`, `check.log`, `import-check.json`, `metadata-install.json`,
`hashes.txt`, and a copy of `install_metadata_only.py`.

The source checkouts stayed clean (`git status --short` empty). Each venv has
`mlflow-3.8.2.dev0.dist-info` and **no** importable `site-packages/mlflow/`.
The metadata came from a wheel built offline from a byte-identical copy of the
corresponding checkout (`copy_verify.log` is empty after an rsync checksum check).
Only the wheel's `.dist-info` entries were extracted. The source import check
asserts `mlflow.__file__` and `mlflow.pyfunc.backend.__file__` resolve to the
specified fixed checkout. The witness module itself also imports successfully
in both venvs; this was an import check, not a witness invocation.

## Reproduction command shape

Run from `/home/joker/AAA_NUS_SEM3/cv_agent`. For each case, substitute its
checkout hash and output directory from the table above:

```bash
uvx --offline --from uv==0.9.8 uv export --frozen --offline --no-dev --extra mlserver --no-emit-workspace --project "$checkout" --output-file "$out/mlflow-requirements.txt"
uv export --frozen --offline --no-dev --no-emit-project --project . --no-emit-package annotated-types --no-emit-package anyio --no-emit-package certifi --no-emit-package charset-normalizer --no-emit-package h11 --no-emit-package idna --no-emit-package orjson --no-emit-package packaging --no-emit-package pydantic --no-emit-package pydantic-core --no-emit-package pyyaml --no-emit-package requests --no-emit-package typing-extensions --no-emit-package typing-inspection --no-emit-package urllib3 --output-file "$out/cv-agent-extra-requirements.txt"
uvx --offline --from uv==0.9.8 uv venv --python /home/joker/.local/share/uv/python/cpython-3.12.12-linux-x86_64-gnu/bin/python3.12 "$out/venv"
uvx --offline --from uv==0.9.8 uv pip install --python "$out/venv/bin/python" --no-deps --require-hashes -r "$out/mlflow-requirements.txt" -r "$out/cv-agent-extra-requirements.txt"
rsync -a --exclude='.git' "$checkout/" "$out/metadata-source/"
rsync -a --dry-run --checksum --itemize-changes --exclude='.git' "$checkout/" "$out/metadata-source/"
uvx --offline --from uv==0.9.8 uv build --wheel --offline --out-dir "$out/wheels" "$out/metadata-source"
"$out/venv/bin/python" -B "$out/install_metadata_only.py" "$out/wheels/mlflow-3.8.2.dev0-py3-none-any.whl" "$checkout"
uvx --offline --from uv==0.9.8 uv pip check --python "$out/venv/bin/python"
uvx --offline --from uv==0.9.8 uv pip freeze --python "$out/venv/bin/python"
```

The 15 omitted CV Agent packages are already pinned in each MLflow lock. Both
exports have no target `mlflow` package requirement, so `--no-deps` prevents
`mlserver-mlflow` from pulling a PyPI MLflow source package into site-packages.
The built wheel only supplies distribution metadata; its SHA256 is in
`hashes.txt` and `metadata-install.json`.

## Earlier Python 3.13 attempt

The original `data/diagnostics/hp003-stage2-a/` and `...-b/` remain for audit.
Both 3.13.5 venvs installed hashed dependencies but `uv pip check` found that
`mlserver==1.7.1` and `mlserver-mlflow==1.7.1` require Python `<3.13`.
They are not used for the stage 2 diagnosis. Their `check.log`, exports,
install logs, freeze, and hashes are preserved.
