from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping
from pathlib import Path

from .datasets import load_owasp_expected_results
from .harness import (
    OWASP_HARNESS,
    validate_owasp_result_payload,
    validate_project_harness,
)
from .java_ast import load_java_repository
from .metrics import TernaryEvaluation, evaluate_ternary
from .provenance import (
    assess_claim_eligibility,
    build_run_identity,
    find_project_root,
)
from .retrieval import RepositoryIndex
from .types import Candidate, CodeDocument, OwaspLabel, SystemVersion, VerdictLabel
from .workflow import AgentPipeline, PipelineConfig


EXPERIMENT_SYSTEMS = tuple(spec.system for spec in OWASP_HARNESS.systems)
PRIMARY_CATEGORIES = frozenset(OWASP_HARNESS.primary_scope)
SINK_EVIDENCE_ORIGINS = (
    "candidate_file",
    "other_benchmark_case",
    "shared_helper_or_framework",
)


def _entry_document(documents, class_name: str):
    expected = f"{class_name}.doGet"
    return next((document for document in documents if expected in document.defines), None)


def _sink_evidence_origin(evidence_id: str, candidate_path: str) -> str:
    evidence_path = evidence_id.partition(":")[2]
    evidence_source = evidence_path.split("::", 1)[0]
    candidate_source = candidate_path.split("::", 1)[0]
    if evidence_source == candidate_source:
        return "candidate_file"
    if Path(evidence_source).name.startswith("BenchmarkTest"):
        return "other_benchmark_case"
    return "shared_helper_or_framework"


def predict_owasp_rag(
    source_root: Path,
) -> tuple[dict[str, dict[str, VerdictLabel]], dict[str, object]]:
    """Run retrieval variants using Java source only; no labels enter this function."""

    validate_project_harness()
    source_files = sorted(source_root.rglob("BenchmarkTest*.java"))
    if not source_files:
        raise ValueError(f"no OWASP Benchmark Java cases found under {source_root}")

    repository_id = "OWASP:BenchmarkJava-1.2beta"
    corpus_source_files = sorted(source_root.rglob("*.java"))
    documents, corpus_parse_error_paths = load_java_repository(
        repository_id,
        source_root,
    )
    if not documents:
        raise ValueError(f"no Java methods found under {source_root}")
    documents_by_source: dict[str, list[CodeDocument]] = defaultdict(list)
    for document in documents:
        relative_path = document.path.split("::", 1)[0]
        documents_by_source[relative_path].append(document)
    index = RepositoryIndex(documents)

    predictions = {system.value: {} for system in EXPERIMENT_SYSTEMS}
    evidence_documents = {system.value: Counter() for system in EXPERIMENT_SYSTEMS}
    sink_evidence_origins = {
        system.value: Counter({origin: 0 for origin in SINK_EVIDENCE_ORIGINS})
        for system in EXPERIMENT_SYSTEMS
    }
    verdict_paths = {system.value: Counter() for system in EXPERIMENT_SYSTEMS}
    verdict_labels = {system.value: Counter() for system in EXPERIMENT_SYSTEMS}
    verdict_path_labels = {
        system.value: defaultdict(Counter) for system in EXPERIMENT_SYSTEMS
    }
    expert_calls = Counter({system.value: 0 for system in EXPERIMENT_SYSTEMS})
    expert_calls_by_name = {
        system.value: Counter({"scan": 0, "taint": 0, "authz": 0, "flow": 0})
        for system in EXPERIMENT_SYSTEMS
    }
    context_tokens = Counter({system.value: 0 for system in EXPERIMENT_SYSTEMS})
    max_context_tokens = Counter({system.value: 0 for system in EXPERIMENT_SYSTEMS})
    parse_error_cases = sorted(
        {
            Path(relative_path).stem
            for relative_path in corpus_parse_error_paths
            if Path(relative_path).stem.startswith("BenchmarkTest")
        }
    )
    missing_entry_cases: list[str] = []
    for source_file in source_files:
        case_id = source_file.stem
        relative_path = source_file.relative_to(source_root).as_posix()
        entry = _entry_document(documents_by_source.get(relative_path, ()), case_id)
        if entry is None:
            missing_entry_cases.append(case_id)
            for system in EXPERIMENT_SYSTEMS:
                predictions[system.value][case_id] = "ABSTAIN"
                verdict_paths[system.value]["missing_entry"] += 1
                verdict_labels[system.value]["ABSTAIN"] += 1
                verdict_path_labels[system.value]["missing_entry"]["ABSTAIN"] += 1
            continue

        candidate = Candidate(
            candidate_id=f"{case_id}:doGet",
            case_id=case_id,
            repository_id=repository_id,
            path=entry.path,
            line=int(entry.path.rsplit("@", 1)[-1]),
            query=entry.text,
        )
        for system in EXPERIMENT_SYSTEMS:
            verdict = AgentPipeline(index, PipelineConfig(system=system)).run(candidate)
            predictions[system.value][case_id] = verdict.label
            verdict_paths[system.value][verdict.path] += 1
            verdict_labels[system.value][verdict.label] += 1
            verdict_path_labels[system.value][verdict.path][verdict.label] += 1
            expert_calls[system.value] += len(verdict.votes)
            for vote in verdict.votes:
                expert_calls_by_name[system.value][vote.expert] += 1
            context_tokens[system.value] += verdict.context_token_count
            max_context_tokens[system.value] = max(
                max_context_tokens[system.value],
                verdict.context_token_count,
            )
            evidence_documents[system.value].update(
                {"retrieved": len(verdict.votes[0].evidence_ids)}
            )
            for evidence_id in verdict.votes[0].evidence_ids:
                sink_evidence_origins[system.value][
                    _sink_evidence_origin(evidence_id, candidate.path)
                ] += 1

    diagnostics: dict[str, object] = {
        "source_case_count": len(source_files),
        "corpus_source_file_count": len(corpus_source_files),
        "corpus_method_document_count": len(documents),
        "corpus_scope": "all BenchmarkJava main-source Java methods",
        "corpus_parse_error_count": len(corpus_parse_error_paths),
        "corpus_parse_error_paths": corpus_parse_error_paths,
        "parse_error_count": len(parse_error_cases),
        "parse_error_cases": parse_error_cases,
        "missing_entry_count": len(missing_entry_cases),
        "missing_entry_cases": missing_entry_cases,
        "matched_sink_evidence_count": {
            system: counts["retrieved"] for system, counts in evidence_documents.items()
        },
        "matched_sink_evidence_origin_count": {
            system: dict(sorted(counts.items()))
            for system, counts in sink_evidence_origins.items()
        },
        "verdict_path_count": {
            system: dict(sorted(counts.items())) for system, counts in verdict_paths.items()
        },
        "verdict_label_count": {
            system: dict(sorted(counts.items())) for system, counts in verdict_labels.items()
        },
        "verdict_path_by_label_count": {
            system: {
                path: dict(sorted(labels.items()))
                for path, labels in sorted(paths.items())
            }
            for system, paths in verdict_path_labels.items()
        },
        "expert_call_count": dict(sorted(expert_calls.items())),
        "expert_call_count_by_name": {
            system: dict(sorted(counts.items()))
            for system, counts in expert_calls_by_name.items()
        },
        "retrieval_contract": {
            spec.system.value: {
                "mode": spec.retrieval.value,
                **spec.budget.model_dump(mode="json"),
                "total_context_tokens": spec.budget.total_context_tokens,
            }
            for spec in OWASP_HARNESS.systems
        },
        "context_tokenizer": "deterministic word-or-punctuation units",
        "context_token_count": dict(sorted(context_tokens.items())),
        "max_context_token_count_per_case": dict(sorted(max_context_tokens.items())),
        "v5_vs_v4_expert_calls_saved": (
            expert_calls[SystemVersion.V4_GRAPH_MULTI.value]
            - expert_calls[SystemVersion.V5_GRAPH_FAST_SLOW.value]
        ),
    }
    return predictions, diagnostics


def _matrix_dict(matrix: TernaryEvaluation) -> dict[str, int | float | None]:
    return {
        "tp": matrix.true_positive,
        "fp": matrix.false_positive,
        "tn": matrix.true_negative,
        "fn": matrix.false_negative,
        "abstain_positive": matrix.abstain_positive,
        "abstain_negative": matrix.abstain_negative,
        "coverage": matrix.coverage,
        "abstain_rate": matrix.abstain_rate,
        "strict_recall": matrix.strict_recall,
        "covered_recall": matrix.covered_recall,
        "precision": matrix.precision,
        "population_false_positive_rate": matrix.population_false_positive_rate,
        "conservative_false_positive_rate": matrix.conservative_false_positive_rate,
        "covered_false_positive_rate": matrix.covered_false_positive_rate,
    }


def _evaluate_subset(
    labels: Mapping[str, OwaspLabel],
    predictions: Mapping[str, VerdictLabel],
    case_ids: list[str],
) -> dict[str, int | float | None]:
    truth = {case_id: labels[case_id].vulnerable for case_id in case_ids}
    subset_predictions = {case_id: predictions[case_id] for case_id in case_ids}
    return _matrix_dict(evaluate_ternary(truth, subset_predictions))


def _transition_count(
    labels: Mapping[str, OwaspLabel],
    before: Mapping[str, VerdictLabel],
    after: Mapping[str, VerdictLabel],
    case_ids: list[str],
) -> dict[str, dict[str, int]]:
    transitions: dict[str, Counter[str]] = {
        "positive": Counter(),
        "negative": Counter(),
    }
    for case_id in case_ids:
        polarity = "positive" if labels[case_id].vulnerable else "negative"
        transitions[polarity][f"{before[case_id]}->{after[case_id]}"] += 1
    return {
        polarity: dict(sorted(counts.items()))
        for polarity, counts in transitions.items()
    }


def evaluate_owasp_rag(
    labels: Mapping[str, OwaspLabel],
    predictions: Mapping[str, Mapping[str, VerdictLabel]],
) -> dict[str, object]:
    all_ids = sorted(labels)
    primary_ids = sorted(
        case_id for case_id, label in labels.items() if label.category in PRIMARY_CATEGORIES
    )
    category_ids: dict[str, list[str]] = defaultdict(list)
    for case_id, label in labels.items():
        category_ids[label.category].append(case_id)

    systems: dict[str, object] = {}
    for system in EXPERIMENT_SYSTEMS:
        system_predictions = predictions[system.value]
        systems[system.value] = {
            "predicted_vulnerable_count": sum(
                label == "VULNERABLE" for label in system_predictions.values()
            ),
            "predicted_safe_count": sum(
                label == "SAFE" for label in system_predictions.values()
            ),
            "abstain_count": sum(
                label == "ABSTAIN" for label in system_predictions.values()
            ),
            "overall": _evaluate_subset(labels, system_predictions, all_ids),
            "primary_subset": _evaluate_subset(labels, system_predictions, primary_ids),
            "categories": {
                category: _evaluate_subset(labels, system_predictions, sorted(case_ids))
                for category, case_ids in sorted(category_ids.items())
            },
        }
    text_recall = systems[SystemVersion.V2_TEXT_SINGLE.value]["primary_subset"]["strict_recall"]
    graph_recall = systems[SystemVersion.V3_GRAPH_SINGLE.value]["primary_subset"]["strict_recall"]
    retrieval_gain = None
    if text_recall is not None and graph_recall is not None:
        retrieval_gain = 100.0 * (graph_recall - text_recall)
    # The headline comparison maps ABSTAIN to VULNERABLE. Otherwise a system can
    # report an arbitrary FPR reduction merely by replacing alerts with refusal.
    single_fpr = systems[SystemVersion.V3_GRAPH_SINGLE.value]["primary_subset"][
        "conservative_false_positive_rate"
    ]
    multi_fpr = systems[SystemVersion.V4_GRAPH_MULTI.value]["primary_subset"][
        "conservative_false_positive_rate"
    ]
    fpr_reduction = None
    fpr_reduction_points = None
    if single_fpr is not None and multi_fpr is not None:
        fpr_reduction_points = 100.0 * (single_fpr - multi_fpr)
        if single_fpr:
            fpr_reduction = 100.0 * (single_fpr - multi_fpr) / single_fpr
    single_covered_fpr = systems[SystemVersion.V3_GRAPH_SINGLE.value][
        "primary_subset"
    ]["covered_false_positive_rate"]
    multi_covered_fpr = systems[SystemVersion.V4_GRAPH_MULTI.value][
        "primary_subset"
    ]["covered_false_positive_rate"]
    covered_fpr_reduction = None
    covered_fpr_reduction_points = None
    if single_covered_fpr is not None and multi_covered_fpr is not None:
        covered_fpr_reduction_points = 100.0 * (
            single_covered_fpr - multi_covered_fpr
        )
        if single_covered_fpr:
            covered_fpr_reduction = 100.0 * (
                single_covered_fpr - multi_covered_fpr
            ) / single_covered_fpr
    single_population_alert_rate = systems[SystemVersion.V3_GRAPH_SINGLE.value][
        "primary_subset"
    ]["population_false_positive_rate"]
    multi_population_alert_rate = systems[SystemVersion.V4_GRAPH_MULTI.value][
        "primary_subset"
    ]["population_false_positive_rate"]
    population_alert_reduction = None
    if (
        single_population_alert_rate is not None
        and multi_population_alert_rate is not None
        and single_population_alert_rate
    ):
        population_alert_reduction = 100.0 * (
            single_population_alert_rate - multi_population_alert_rate
        ) / single_population_alert_rate
    multi_recall = systems[SystemVersion.V4_GRAPH_MULTI.value]["primary_subset"]["strict_recall"]
    multi_recall_delta = None
    if graph_recall is not None and multi_recall is not None:
        multi_recall_delta = 100.0 * (multi_recall - graph_recall)
    single_coverage = systems[SystemVersion.V3_GRAPH_SINGLE.value]["primary_subset"]["coverage"]
    multi_coverage = systems[SystemVersion.V4_GRAPH_MULTI.value]["primary_subset"]["coverage"]
    multi_coverage_delta = None
    if single_coverage is not None and multi_coverage is not None:
        multi_coverage_delta = 100.0 * (multi_coverage - single_coverage)
    fast_disagreements = sum(
        predictions[SystemVersion.V4_GRAPH_MULTI.value][case_id]
        != predictions[SystemVersion.V5_GRAPH_FAST_SLOW.value][case_id]
        for case_id in all_ids
    )
    return {
        "primary_categories": sorted(PRIMARY_CATEGORIES),
        "primary_category_rationale": OWASP_HARNESS.primary_scope_rationale,
        "primary_case_count": len(primary_ids),
        "systems": systems,
        "primary_v3_vs_v2_strict_recall_gain_percentage_points": retrieval_gain,
        "primary_v4_vs_v3_fpr_reduction_percent": fpr_reduction,
        "primary_v4_vs_v3_fpr_reduction_percentage_points": fpr_reduction_points,
        "primary_v4_vs_v3_covered_fpr_reduction_percent": covered_fpr_reduction,
        "primary_v4_vs_v3_covered_fpr_reduction_percentage_points": (
            covered_fpr_reduction_points
        ),
        "primary_v4_vs_v3_population_false_alert_reduction_percent": (
            population_alert_reduction
        ),
        "primary_v4_vs_v3_strict_recall_delta_percentage_points": multi_recall_delta,
        "primary_v4_vs_v3_coverage_delta_percentage_points": multi_coverage_delta,
        "primary_v4_vs_v3_transition_count": _transition_count(
            labels,
            predictions[SystemVersion.V3_GRAPH_SINGLE.value],
            predictions[SystemVersion.V4_GRAPH_MULTI.value],
            primary_ids,
        ),
        "v5_vs_v4_label_disagreement_count": fast_disagreements,
    }


def run_owasp_rag_experiment(raw_root: Path) -> dict[str, object]:
    validate_project_harness()
    benchmark_root = raw_root / "BenchmarkJava"
    source_root = benchmark_root / "src" / "main" / "java"
    predictions, diagnostics = predict_owasp_rag(source_root)

    # Evaluator-only truth is loaded after all five systems have predicted every case.
    labels = load_owasp_expected_results(benchmark_root / "expectedresults-1.2beta.csv")
    run_identity = build_run_identity(
        find_project_root(raw_root),
        {"BenchmarkJava": benchmark_root},
    )
    result = {
        "dataset": OWASP_HARNESS.dataset_name,
        "harness_id": OWASP_HARNESS.harness_id,
        "dataset_role": OWASP_HARNESS.dataset_role.value,
        "claim_eligible": OWASP_HARNESS.claim_eligible,
        "candidate_protocol": OWASP_HARNESS.candidate_protocol,
        "run_identity": run_identity,
        "claim_assessment": assess_claim_eligibility(
            OWASP_HARNESS.claim_eligible,
            run_identity,
        ),
        "experiment": "local-vs-text-vs-ast-call-graph retrieval",
        "diagnostics": diagnostics,
        **evaluate_owasp_rag(labels, predictions),
    }
    validate_owasp_result_payload(result)
    return result
