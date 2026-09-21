from __future__ import annotations

import argparse
import json
from pathlib import Path

from cv_agent.evaluation.datasets.owasp_live import run_agentic_owasp_live
from cv_agent.evaluation.smoke import run_agentic_smoke
from cv_agent.evaluation.scripted import run_agentic_scripted_eval
from cv_agent.baselines.synthetic_experiment import run_synthetic_experiment
from cv_agent.harness import AgentSystemVersion, command_policy, describe_project_harness
from cv_agent.code_adapters.java import profile_owasp_java_ast
from cv_agent.baselines.owasp import run_owasp_static_baseline
from cv_agent.baselines.owasp_rag import run_owasp_rag_experiment
from cv_agent.evaluation.datasets.profile import profile_public_data
from cv_agent.evaluation.datasets.vulngym_subset import describe_vulngym_subjects, fetch_vulngym_subjects
from cv_agent.evaluation.datasets.vulngym_retrieval import run_vulngym_retrieval_experiment


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cv-agent")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("harness-check", help="validate and print the project experiment contract")
    subparsers.add_parser("synthetic", help="run the deterministic two-case wiring experiment")
    subparsers.add_parser(
        "agentic-smoke",
        help="run the scripted model/tool/observation LangGraph wiring diagnostic",
    )
    subparsers.add_parser(
        "agentic-eval",
        help="run the scripted LangGraph/ReAct quorum false-positive diagnostic",
    )
    agentic_live = subparsers.add_parser(
        "agentic-live-owasp",
        help="run bounded live-model AgenticPipeline cases from OWASP BenchmarkJava",
    )
    agentic_live.add_argument("--raw", type=Path, default=Path("data/raw"))
    agentic_live.add_argument(
        "--case-id",
        action="append",
        required=True,
        help="explicit OWASP BenchmarkTest id to run; repeat for multiple cases",
    )
    agentic_live.add_argument(
        "--system",
        action="append",
        required=True,
        choices=[system.value for system in AgentSystemVersion],
        help="explicit agentic system id to run; repeat for multiple systems",
    )
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


def _emit(command: str, payload: dict[str, object]) -> int:
    policy = command_policy(command)
    output = {
        **payload,
        "command_policy": policy.model_dump(mode="json"),
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


def main() -> int:
    arguments = build_parser().parse_args()
    command_policy(arguments.command)
    if arguments.command == "harness-check":
        return _emit(arguments.command, describe_project_harness())
    if arguments.command == "synthetic":
        return _emit(arguments.command, run_synthetic_experiment())
    if arguments.command == "agentic-smoke":
        return _emit(arguments.command, run_agentic_smoke())
    if arguments.command == "agentic-eval":
        return _emit(arguments.command, run_agentic_scripted_eval())
    if arguments.command == "agentic-live-owasp":
        return _emit(
            arguments.command,
            run_agentic_owasp_live(
                arguments.raw,
                case_ids=arguments.case_id,
                system_ids=arguments.system,
            ),
        )
    if arguments.command == "profile":
        return _emit(arguments.command, profile_public_data(arguments.raw))
    if arguments.command == "owasp-baseline":
        return _emit(arguments.command, run_owasp_static_baseline(arguments.raw))
    if arguments.command == "owasp-ast-profile":
        return _emit(arguments.command, profile_owasp_java_ast(arguments.raw))
    if arguments.command == "owasp-rag":
        return _emit(arguments.command, run_owasp_rag_experiment(arguments.raw))
    if arguments.command == "vulngym-subset":
        return _emit(arguments.command, describe_vulngym_subjects(arguments.raw))
    if arguments.command == "vulngym-fetch":
        return _emit(arguments.command, fetch_vulngym_subjects(arguments.data))
    if arguments.command == "vulngym-retrieval":
        return _emit(arguments.command, run_vulngym_retrieval_experiment(arguments.data))
    raise AssertionError(f"unhandled command: {arguments.command}")
