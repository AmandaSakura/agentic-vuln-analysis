"""Build a source-bound witness manifest from a neutral advisory call template."""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import tokenize
from pathlib import Path

from cv_agent.evaluation.datasets.advisory_source import build_pair_input
from cv_agent.evaluation.datasets.composition import load_advisory_config
from cv_agent.evaluation.diagnostics.bounded_execution_witness import WitnessManifest
from cv_agent.runtime.paths import PROJECT_ROOT
from cv_agent.tools.identity import candidate_subject


_SOURCE_IDENTITY_FIELDS = frozenset({
    "subject", "checkout_root", "entry_relative_path", "entry_file_sha256",
    "entry_first_line", "source_modules", "python_executable",
})
_DOTTED_MODULE = re.compile(r"[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)*\Z")


def _module_name(relative_path: str) -> str:
    parts = list(Path(relative_path).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _entry_first_line(path: Path, class_name: str, method_name: str) -> int:
    with tokenize.open(path) as stream:
        tree = ast.parse(stream.read(), filename=str(path))
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)
               and node.name == class_name]
    if len(classes) != 1:
        raise ValueError("template class is not unique in the fixed entry source")
    methods = [node for node in classes[0].body if isinstance(node, ast.FunctionDef)
               and node.name == method_name]
    if len(methods) != 1:
        raise ValueError("template method is not unique in the fixed entry source")
    return methods[0].lineno


def _fixed_checkout(checkout: Path, expected_commit: str) -> None:
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=checkout, text=True,
        capture_output=True, check=True,
    ).stdout.strip()
    if head != expected_commit:
        raise ValueError("checkout HEAD differs from the declared source commit")
    status = subprocess.run(
        ["git", "status", "--porcelain"], cwd=checkout, text=True,
        capture_output=True, check=True,
    ).stdout.strip()
    if status:
        raise ValueError("fixed source checkout has local modifications")


def prepare_manifest(
    profile_path: Path,
    template_path: Path,
    case_id: str,
    python_executable: Path,
) -> WitnessManifest:
    if not python_executable.is_absolute() or not python_executable.is_file():
        raise ValueError("witness interpreter must be an existing absolute venv executable")
    profile_relative = profile_path.resolve(strict=True).relative_to(PROJECT_ROOT).as_posix()
    config = load_advisory_config(PROJECT_ROOT, profile_relative)
    matches = [(pair, case) for pair in config.pairs for case in pair.cases
               if case.case_id == case_id]
    if len(matches) != 1:
        raise ValueError("case ID must select exactly one advisory source snapshot")
    pair, case = matches[0]
    template = json.loads(template_path.read_text())
    if not isinstance(template, dict) or _SOURCE_IDENTITY_FIELDS.intersection(template):
        raise ValueError("template may specify calls, never source identity or interpreter")
    checkout = (PROJECT_ROOT / case.checkout).resolve(strict=True)
    _fixed_checkout(checkout, case.commit)
    index, candidate, source_sha256 = build_pair_input(PROJECT_ROOT, pair, case)
    entry_path = case.file_path
    package_root = template["module_name"].split(".", 1)[0]
    source_modules = [
        {"module_name": _module_name(relative), "relative_path": relative,
         "sha256": digest}
        for relative, digest in sorted(source_sha256.items())
        if (relative.startswith(package_root + "/") and relative.endswith(".py")
            and _DOTTED_MODULE.fullmatch(_module_name(relative)))
    ]
    manifest = WitnessManifest.model_validate({
        **template,
        "subject": candidate_subject(index, candidate).model_dump(mode="json"),
        "checkout_root": str(checkout),
        "entry_relative_path": entry_path,
        "entry_file_sha256": source_sha256[entry_path],
        "entry_first_line": _entry_first_line(
            checkout / entry_path, template["class_name"], template["method_name"],
        ),
        "source_modules": source_modules,
        # Keep the venv/bin path: resolving its symlink would lose sys.prefix.
        "python_executable": str(python_executable),
    })
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("template", type=Path)
    parser.add_argument("case_id")
    parser.add_argument("python_executable", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    manifest = prepare_manifest(
        args.config, args.template, args.case_id, args.python_executable,
    )
    args.output.write_text(manifest.model_dump_json(indent=2) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
