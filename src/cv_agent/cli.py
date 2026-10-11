from __future__ import annotations

import argparse
import json
from pathlib import Path

from cv_agent.harness import AgentSystemVersion, command_policy, describe_project_harness


def build_parser(*, product_only: bool = False) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cv-agent")
    subparsers = parser.add_subparsers(dest="command", required=True)
    review = subparsers.add_parser("review", help="review explicitly selected local Python source offline")
    review.add_argument("source_root", type=Path)
    review.add_argument("--output", type=Path, required=True, help="new output directory for result.json and report.md")
    review.add_argument("--language", default="python")
    review.add_argument("--observation-bytes", type=int, default=None)
    review.add_argument("--profile", choices=("product_triage_v1", "product_triage_v2"), default="product_triage_v1")
    review.add_argument("--summary-bytes", type=int, default=None)
    review.add_argument("--context-grants", type=Path, help="explicit source-grants-v1 JSON manifest")
    review.add_argument("--context-bytes", type=int, default=8192)
    doctor = subparsers.add_parser("doctor", help="check local review capabilities without provider requests")
    doctor.add_argument("source_root", type=Path)
    doctor.add_argument("--language", default="python")
    doctor.add_argument("--property-id")
    verify = subparsers.add_parser("verify", help="verify a user-owned local v2 package without executing source")
    verify.add_argument("run_dir", type=Path)
    view = subparsers.add_parser("view", help="show an exact authorized local operation after verifying source identity")
    view.add_argument("run_dir", type=Path)
    view.add_argument("--candidate-id", required=True)
    view.add_argument("--source-root", type=Path, required=True)
    if product_only:
        return parser
    subparsers.add_parser("harness-check", help="validate and print the project experiment contract")
    readiness = subparsers.add_parser("readiness", help="audit a completed run artifact for operational and claim readiness")
    readiness.add_argument("run_dir", type=Path, help="completed experiment run directory")
    readiness.add_argument("--require-operational", action="store_true", help="exit nonzero unless the run is operationally ready")
    readiness.add_argument("--require-claim", action="store_true", help="exit nonzero unless the run is ready to support a final claim")
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
    agentic_live.add_argument("--property-id", required=True,
                              help="explicit proof obligation shared by the selected cases")
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


def main(*, product_only: bool = False) -> int:
    arguments = build_parser(product_only=product_only).parse_args()
    command_policy(arguments.command)
    if arguments.command in {"verify", "view"}:
        from cv_agent.application.service_v2 import verify_bundle, view_finding
        try:
            result = (verify_bundle(arguments.run_dir) if arguments.command == "verify" else
                view_finding(arguments.run_dir, arguments.candidate_id, arguments.source_root))
        except (ValueError, OSError) as error:
            print(json.dumps({"valid":False,"reason_code":str(error),"model_requests":0})); return 2
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result.get("valid", True) else 2
    if arguments.command == "review":
        from cv_agent.application.service import run_review, _protected_root
        context_manifest = None
        if arguments.context_grants is not None:
            try:
                if _protected_root(arguments.context_grants):
                    raise ValueError("Protected context input")
                context_manifest = json.loads(arguments.context_grants.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                context_manifest = {"invalid_manifest": True}
        try:
            if arguments.profile == "product_triage_v2":
                if arguments.language != "python":
                    print(json.dumps({"run_state":"BLOCKED","reason_code":"language_not_supported",
                        "model_requests":0,"target_executions":0})); return 2
                if arguments.observation_bytes is not None:
                    print(json.dumps({"run_state":"FAILED","reason_code":"ambiguous_v2_observation_budget",
                        "required_argument":"--summary-bytes","model_requests":0})); return 2
                from cv_agent.application.product_boundary import run_bounded_review
                envelope = run_bounded_review(arguments.source_root, arguments.output, options={
                    "summary_bytes":8192 if arguments.summary_bytes is None else arguments.summary_bytes,
                    "context_manifest":context_manifest, "context_bytes":arguments.context_bytes})
                payload = envelope.get("result") or envelope
                print(json.dumps(payload, ensure_ascii=False, indent=2))
                return 0 if payload["run_state"] == "COMPLETED" else 2
            if arguments.summary_bytes is not None:
                raise ValueError("summary bytes require explicit product_triage_v2")
            result = run_review(arguments.source_root, arguments.output, language=arguments.language,
                                observation_bytes=8192 if arguments.observation_bytes is None else arguments.observation_bytes, context_manifest=context_manifest,
                                context_bytes=arguments.context_bytes)
        except (FileExistsError, OSError, ValueError) as error:
            print(json.dumps({"run_state": "FAILED", "reason_code": "review_output_or_configuration_error",
                              "error_type": type(error).__name__, "model_requests": 0}, sort_keys=True))
            return 2
        print(result.model_dump_json(indent=2))
        return 0 if result.run_state == "COMPLETED" else 2
    if arguments.command == "doctor":
        from cv_agent.application.diagnostics import doctor
        result = doctor(arguments.source_root, language=arguments.language, property_id=arguments.property_id)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0 if result["ready"] else 2
    if arguments.command == "harness-check":
        return _emit(arguments.command, describe_project_harness())
    if arguments.command == "readiness":
        from cv_agent.evaluation.protocols.readiness import assess_run_readiness
        assessment = assess_run_readiness(arguments.run_dir)
        _emit(arguments.command, assessment)
        if arguments.require_claim and not assessment["claim_ready"]:
            return 2
        if arguments.require_operational and not assessment["operational_ready"]:
            return 2
        return 0
    if arguments.command == "synthetic":
        from cv_agent.baselines.synthetic_experiment import run_synthetic_experiment
        return _emit(arguments.command, run_synthetic_experiment())
    if arguments.command == "agentic-smoke":
        from cv_agent.evaluation.smoke import run_agentic_smoke
        return _emit(arguments.command, run_agentic_smoke())
    if arguments.command == "agentic-eval":
        from cv_agent.evaluation.scripted import run_agentic_scripted_eval
        return _emit(arguments.command, run_agentic_scripted_eval())
    if arguments.command == "agentic-live-owasp":
        from cv_agent.evaluation.datasets.owasp_live import run_agentic_owasp_live
        return _emit(
            arguments.command,
            run_agentic_owasp_live(
                arguments.raw,
                case_ids=arguments.case_id,
                system_ids=arguments.system,
                property_id=arguments.property_id,
            ),
        )
    if arguments.command == "profile":
        from cv_agent.evaluation.datasets.profile import profile_public_data
        return _emit(arguments.command, profile_public_data(arguments.raw))
    if arguments.command == "owasp-baseline":
        from cv_agent.baselines.owasp import run_owasp_static_baseline
        return _emit(arguments.command, run_owasp_static_baseline(arguments.raw))
    if arguments.command == "owasp-ast-profile":
        from cv_agent.code_adapters.java import profile_owasp_java_ast
        return _emit(arguments.command, profile_owasp_java_ast(arguments.raw))
    if arguments.command == "owasp-rag":
        from cv_agent.baselines.owasp_rag import run_owasp_rag_experiment
        return _emit(arguments.command, run_owasp_rag_experiment(arguments.raw))
    if arguments.command == "vulngym-subset":
        from cv_agent.evaluation.datasets.vulngym_subset import describe_vulngym_subjects
        return _emit(arguments.command, describe_vulngym_subjects(arguments.raw))
    if arguments.command == "vulngym-fetch":
        from cv_agent.evaluation.datasets.vulngym_subset import fetch_vulngym_subjects
        return _emit(arguments.command, fetch_vulngym_subjects(arguments.data))
    if arguments.command == "vulngym-retrieval":
        from cv_agent.evaluation.datasets.vulngym_retrieval import run_vulngym_retrieval_experiment
        return _emit(arguments.command, run_vulngym_retrieval_experiment(arguments.data))
    raise AssertionError(f"unhandled command: {arguments.command}")


def product_main() -> int:
    """The minimal installed product shares dispatch while exposing no research runner."""
    return main(product_only=True)
