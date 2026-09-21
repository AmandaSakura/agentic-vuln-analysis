"""Full offline regression admission for this checkout's live model transport."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
from threading import Lock
from uuid import uuid4

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def fingerprint_files(root: Path) -> list[Path]:
    files = [path for folder in ("src", "tests", "scripts", "configs", "validation")
             for path in (root / folder).rglob("*")
             if path.is_file() and "__pycache__" not in path.parts
             and path.suffix not in {".pyc", ".pyo"}]
    files.extend(root / name for name in ("pyproject.toml", "uv.lock", "AGENTS.md", "docs/TEST_CONTRACT.md")
                 if (root / name).is_file())
    return sorted(files)


def source_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    for path in fingerprint_files(root):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


_loaded_fingerprint = source_fingerprint(PROJECT_ROOT)
_approved_fingerprint: str | None = None
_attempted = False
_admission_lock = Lock()


def require_passing_tests() -> None:
    with _admission_lock:
        _require_passing_tests()


def _require_passing_tests() -> None:
    global _approved_fingerprint, _attempted
    current = source_fingerprint(PROJECT_ROOT)
    if current != _loaded_fingerprint:
        raise RuntimeError("Source/config/tests changed after process startup; restart before live API calls")
    if _approved_fingerprint == current:
        return
    if _attempted:
        raise RuntimeError("Full pytest did not pass in this process; restart before live API calls")
    _attempted = True
    directory = PROJECT_ROOT / "artifacts" / "pytest_gate" / uuid4().hex
    directory.mkdir(parents=True)
    log = directory / "pytest.log"
    environment = dict(os.environ)
    for name in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTEST_CURRENT_TEST",
                 "CV_AGENT_PROVIDER", "DEEPSEEK_MODEL", "GEMINI_MODEL"):
        environment.pop(name, None)
    # Tests use fake credentials only, even if the experiment loaded real ones.
    for name in tuple(environment):
        if any(token in name.upper() for token in ("API_KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")):
            environment.pop(name)
    environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    print(f"Live API gate: running full pytest; log: {log}", flush=True)
    with log.open("w") as stream:
        result = subprocess.run(["uv", "run", "--no-sync", "pytest"], cwd=PROJECT_ROOT,
                                env=environment, stdout=stream, stderr=subprocess.STDOUT,
                                timeout=300, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"Full pytest failed (exit {result.returncode}); live API blocked. See {log}")
    if source_fingerprint(PROJECT_ROOT) != current:
        raise RuntimeError("Source/config/tests changed during pytest; live API blocked")
    _approved_fingerprint = current


if __name__ == "__main__":
    require_passing_tests()
    print("Full pytest passed for this process/source snapshot; no API request was made.")
