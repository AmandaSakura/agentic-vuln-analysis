from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping
from pathlib import Path

from .datasets import load_owasp_expected_results
from .java_ast import parse_java_source
from .metrics import TernaryEvaluation, evaluate_ternary
from .retrieval import RepositoryIndex
from .types import Candidate, OwaspLabel, SystemVersion, VerdictLabel
from .workflow import AgentPipeline, PipelineConfig


EXPERIMENT_SYSTEMS = tuple(SystemVersion)
PRIMARY_CATEGORIES = frozenset({"cmdi", "ldapi", "pathtraver", "sqli", "xpathi"})
PRIMARY_CATEGORY_RATIONALE = (
    "Predeclared API families covered by the current command, LDAP, path, SQL, and XPath sink rules."
)
CANDIDATE_PROTOCOL = (
    "One source-derived servlet doGet method per BenchmarkTest case; no truth fields are used."
)
RETRIEVAL_TOP_K = 6
CONTEXT_TOKEN_BUDGET = 2000


def _entry_document(documents, class_name: str):
    expected = f"{class_name}.doGet"
    return next((document for document in documents if expected in document.defines), None)


def predict_owasp_rag(
    source_root: Path,
) -> tuple[dict[str, dict[str, VerdictLabel]], dict[str, object]]:
    """Run retrieval variants using Java source only; no labels enter this function."""

    source_files = sorted(source_root.glob("BenchmarkTest*.java"))
    if not source_files:
        raise ValueError(f"no OWASP Benchmark Java cases found under {source_root}")

    predictions = {system.value: {} for system in EXPERIMENT_SYSTEMS}
    evidence_documents = {system.value: Counter() for system in EXPERIMENT_SYSTEMS}
    verdict_paths = {system.value: Counter() for system in EXPERIMENT_SYSTEMS}
    verdict_labels = {system.value: Counter() for system in EXPERIMENT_SYSTEMS}
    expert_calls = Counter({system.value: 0 for system in EXPERIMENT_SYSTEMS})
    context_tokens = Counter({system.value: 0 for system in EXPERIMENT_SYSTEMS})
    max_context_tokens = Counter({system.value: 0 for system in EXPERIMENT_SYSTEMS})
    parse_error_cases: list[str] = []
    missing_entry_cases: list[str] = []
    for source_file in source_files:
        case_id = source_file.stem
        repository_id = f"OWASP:{case_id}"
        result = parse_java_source(
            repository_id,
            source_file.name,
            source_file.read_text(encoding="utf-8"),
        )
        if result.has_error:
            parse_error_cases.append(case_id)
        entry = _entry_document(result.documents, case_id)
        if entry is None:
            missing_entry_cases.append(case_id)
            for system in EXPERIMENT_SYSTEMS:
                predictions[system.value][case_id] = "ABSTAIN"
                verdict_paths[system.value]["missing_entry"] += 1
                verdict_labels[system.value]["ABSTAIN"] += 1
            continue

        index = RepositoryIndex(result.documents)
        candidate = Candidate(
            candidate_id=f"{case_id}:doGet",
            case_id=case_id,
            repository_id=repository_id,
            path=entry.path,
            line=int(entry.path.rsplit("@", 1)[-1]),
            query=entry.text,
        )
        for system in EXPERIMENT_SYSTEMS:
            verdict = AgentPipeline(
                index,
                PipelineConfig(
                    system=system,
                    top_k=RETRIEVAL_TOP_K,
                    context_token_budget=CONTEXT_TOKEN_BUDGET,
                ),
            ).run(candidate)
            predictions[system.value][case_id] = verdict.label
            verdict_paths[system.value][verdict.path] += 1
            verdict_labels[system.value][verdict.label] += 1
            expert_calls[system.value] += len(verdict.votes)
            context_tokens[system.value] += verdict.context_token_count
            max_context_tokens[system.value] = max(
                max_context_tokens[system.value],
                verdict.context_token_count,
            )
            evidence_documents[system.value].update(
                {"retrieved": len(verdict.votes[0].evidence_ids)}
            )

    diagnostics: dict[str, object] = {
        "source_case_count": len(source_files),
        "parse_error_count": len(parse_error_cases),
        "parse_error_cases": parse_error_cases,
        "missing_entry_count": len(missing_entry_cases),
        "missing_entry_cases": missing_entry_cases,
        "matched_sink_evidence_count": {
            system: counts["retrieved"] for system, counts in evidence_documents.items()
        },
        "verdict_path_count": {
            system: dict(sorted(counts.items())) for system, counts in verdict_paths.items()
        },
        "verdict_label_count": {
            system: dict(sorted(counts.items())) for system, counts in verdict_labels.items()
        },
        "expert_call_count": dict(sorted(expert_calls.items())),
        "retrieval_top_k": RETRIEVAL_TOP_K,
        "context_token_budget_per_case": CONTEXT_TOKEN_BUDGET,
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
    single_fpr = systems[SystemVersion.V3_GRAPH_SINGLE.value]["primary_subset"][
        "population_false_positive_rate"
    ]
    multi_fpr = systems[SystemVersion.V4_GRAPH_MULTI.value]["primary_subset"][
        "population_false_positive_rate"
    ]
    fpr_reduction = None
    fpr_reduction_points = None
    if single_fpr is not None and multi_fpr is not None:
        fpr_reduction_points = 100.0 * (single_fpr - multi_fpr)
        if single_fpr:
            fpr_reduction = 100.0 * (single_fpr - multi_fpr) / single_fpr
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
        "primary_category_rationale": PRIMARY_CATEGORY_RATIONALE,
        "primary_case_count": len(primary_ids),
        "systems": systems,
        "primary_v3_vs_v2_strict_recall_gain_percentage_points": retrieval_gain,
        "primary_v4_vs_v3_fpr_reduction_percent": fpr_reduction,
        "primary_v4_vs_v3_fpr_reduction_percentage_points": fpr_reduction_points,
        "primary_v4_vs_v3_strict_recall_delta_percentage_points": multi_recall_delta,
        "primary_v4_vs_v3_coverage_delta_percentage_points": multi_coverage_delta,
        "v5_vs_v4_label_disagreement_count": fast_disagreements,
    }


def run_owasp_rag_experiment(raw_root: Path) -> dict[str, object]:
    benchmark_root = raw_root / "BenchmarkJava"
    source_root = benchmark_root / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
    predictions, diagnostics = predict_owasp_rag(source_root)

    # Evaluator-only truth is loaded after all five systems have predicted every case.
    labels = load_owasp_expected_results(benchmark_root / "expectedresults-1.2beta.csv")
    return {
        "dataset": "OWASP BenchmarkJava 1.2beta",
        "dataset_role": "development benchmark previously inspected during rule iteration",
        "claim_eligible": False,
        "candidate_protocol": CANDIDATE_PROTOCOL,
        "experiment": "local-vs-text-vs-ast-call-graph retrieval",
        "diagnostics": diagnostics,
        **evaluate_owasp_rag(labels, predictions),
    }
