"""Compile the frozen report with installed XeLaTeX/BibTeX, without shell escape."""
from pathlib import Path
import shutil
import subprocess

REPORT = Path(__file__).resolve().parents[1]
ROOT = REPORT.parents[2]
BUILD = ROOT / "artifacts/technical_report_20261001/build"
OUTPUT = REPORT.parent / "cv_agent_technical_report_2026-10-01.pdf"


def run(command, name, *, cwd=REPORT):
    with (BUILD / name).open("w") as stream:
        result = subprocess.run(command, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError(f"Compilation failed; inspect {BUILD/name}")


def main():
    BUILD.mkdir(parents=True, exist_ok=True)
    tex = ["xelatex", "-no-shell-escape", "-interaction=nonstopmode", "-halt-on-error",
           f"-output-directory={BUILD}", "main.tex"]
    run(tex, "xelatex-pass1.stdout.log")
    shutil.copyfile(REPORT / "references.bib", BUILD / "references.bib")
    run(["bibtex", "main"], "bibtex.stdout.log", cwd=BUILD)
    for index in range(2, 5):
        run(tex, f"xelatex-pass{index}.stdout.log")
    shutil.copyfile(BUILD / "main.pdf", OUTPUT)
    print(OUTPUT)


if __name__ == "__main__":
    main()
