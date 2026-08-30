from __future__ import annotations

import argparse
import json
from pathlib import Path

from .experiment import run_synthetic_experiment
from .java_ast import profile_owasp_java_ast
from .owasp import run_owasp_static_baseline
from .owasp_rag import run_owasp_rag_experiment
from .profile import profile_public_data
from .vulngym_subset import describe_vulngym_subjects, fetch_vulngym_subjects
from .vulngym_retrieval import run_vulngym_retrieval_experiment


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cv-agent")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("synthetic", help="run the deterministic two-case wiring experiment")
    profile = subparsers.add_parser("profile", help="report aggregate public-dataset metadata without row labels")
    profile.add_argument("--raw", type=Path, default=Path("data/raw"))
    baseline = subparsers.add_parser("owasp-baseline", help="run the source-only OWASP static sink baseline")
    baseline.add_argument("--raw", type=Path, default=Path("data/raw"))
    ast_profile = subparsers.add_parser("owasp-ast-profile", help="parse OWASP Java methods and calls with Tree-sitter")
    ast_profile.add_argument("--raw", type=Path, default=Path("data/raw"))
    rag = subparsers.add_parser("owasp-rag", help="run local/text/AST-call-graph retrieval ablations")
    rag.add_argument("--raw", type=Path, default=Path("data/raw"))
    vg_subset = subparsers.add_parser("vulngym-subset", help="describe the selected verified Python subjects")
    vg_subset.add_argument("--raw", type=Path, default=Path("data/raw"))
    vg_fetch = subparsers.add_parser("vulngym-fetch", help="fetch exact selected vulnerable commits")
    vg_fetch.add_argument("--data", type=Path, default=Path("data"))
    vg_retrieval = subparsers.add_parser("vulngym-retrieval", help="run oracle-seeded Python retrieval coverage")
    vg_retrieval.add_argument("--data", type=Path, default=Path("data"))
    return parser


def main() -> int:
    arguments = build_parser().parse_args()
    if arguments.command == "synthetic":
        print(json.dumps(run_synthetic_experiment(), indent=2, sort_keys=True))
        return 0
    if arguments.command == "profile":
        print(json.dumps(profile_public_data(arguments.raw), indent=2, sort_keys=True))
        return 0
    if arguments.command == "owasp-baseline":
        print(json.dumps(run_owasp_static_baseline(arguments.raw), indent=2, sort_keys=True))
        return 0
    if arguments.command == "owasp-ast-profile":
        print(json.dumps(profile_owasp_java_ast(arguments.raw), indent=2, sort_keys=True))
        return 0
    if arguments.command == "owasp-rag":
        print(json.dumps(run_owasp_rag_experiment(arguments.raw), indent=2, sort_keys=True))
        return 0
    if arguments.command == "vulngym-subset":
        print(json.dumps(describe_vulngym_subjects(arguments.raw), indent=2, sort_keys=True))
        return 0
    if arguments.command == "vulngym-fetch":
        print(json.dumps(fetch_vulngym_subjects(arguments.data), indent=2, sort_keys=True))
        return 0
    if arguments.command == "vulngym-retrieval":
        print(json.dumps(run_vulngym_retrieval_experiment(arguments.data), indent=2, sort_keys=True))
        return 0
    raise AssertionError(f"unhandled command: {arguments.command}")
