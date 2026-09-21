"""Prepare pinned Jinja vulnerable/fixed checkouts for the paired matrix."""
from __future__ import annotations

from cv_agent.runtime.paths import PROJECT_ROOT

import subprocess
from pathlib import Path


VULN = PROJECT_ROOT / "data/diagnostics/jinja-vulnerable"
FIXED = PROJECT_ROOT / "data/diagnostics/jinja-fixed"
ENV = PROJECT_ROOT / "data/diagnostics/jinja-env"
REPO = "https://github.com/pallets/jinja.git"
VULN_COMMIT = "877f6e51be8e1765b06d911cfaa9033775f051d1"
FIX_COMMIT = "15206881c006c79667fe5154fe80c01c65410679"


def run(cmd: list[str], cwd: Path | None = None) -> None:
    subprocess.run(cmd, cwd=cwd, check=True)


def clone_checkout(target: Path, commit: str) -> None:
    if target.exists():
        run(["git", "fetch", "--all", "--tags"], cwd=target)
    else:
        run(["git", "clone", REPO, str(target)])
    run(["git", "checkout", commit], cwd=target)
    run(["git", "clean", "-fdx"], cwd=target)
    run(["git", "reset", "--hard", commit], cwd=target)


def main() -> None:
    VULN.parent.mkdir(parents=True, exist_ok=True)
    clone_checkout(VULN, VULN_COMMIT)
    clone_checkout(FIXED, FIX_COMMIT)
    run(["uv", "venv", str(ENV)])
    run(["uv", "pip", "install", "--python", str(ENV / "bin/python"), "markupsafe"])


if __name__ == "__main__":
    main()
