"""Read-only numerical synthesis of existing code and accepted result receipts."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import statistics
import subprocess


ROOT = Path(__file__).resolve().parents[4]
REPORT = ROOT / "docs/reports/cv_agent_technical_report_2026-10-01"
SOURCE_PATHS = [
    "audit/design_review_20260930/baseline.json",
    "audit/design_review_20260930/acceptance.json",
    "audit/design_review_20260930/tasks.json",
    "audit/design_review_20260930/cli-acceptance.json",
    "audit/design_review_20260930/transport-guard.json",
    ".hermes/plans/2026-09-30-remaining-work-final-summary.json",
    ".hermes/plans/2026-09-30-E-iter-results.json",
    ".hermes/plans/2026-09-30-G-A-decision.json",
    ".hermes/plans/2026-09-30-product-increment-preregistration.json",
    "audit/design_review_20260930/verification.md",
    "audit/design_review_20260930/final-source-manifest.json",
    ".hermes/plans/2026-09-30-K2-results.json",
    ".hermes/plans/2026-09-30-K3-results.md",
    ".hermes/plans/2026-09-30-K4-results.md",
    ".hermes/plans/2026-09-28-witness-stage2c-results.md",
    ".hermes/plans/2026-09-30-architect-exposure-disclosure.md",
    "artifacts/design_review_repair_20260930/final_full_pytest.log",
    "artifacts/design_review_repair_20260930/final_collection.log",
    "docs/CURRENT_STATUS.md",
    "docs/TEST_CONTRACT.md",
]


def load(path):
    return json.loads((ROOT/path).read_text())


def main():
    baseline = load(SOURCE_PATHS[0]); acceptance = load(SOURCE_PATHS[1])
    cli = load(SOURCE_PATHS[3]); summary = load(SOURCE_PATHS[5]); eiter = load(SOURCE_PATHS[6])
    modules = list((ROOT / "src/cv_agent").rglob("*.py"))
    by_layer = Counter(); lines = Counter()
    code_hash = hashlib.sha256()
    for path in sorted(modules):
        rel = path.relative_to(ROOT / "src/cv_agent")
        layer = rel.parts[0] if len(rel.parts) > 1 else "root"
        by_layer[layer] += 1
        lines[layer] += len(path.read_text().splitlines())
        code_hash.update(path.relative_to(ROOT).as_posix().encode() + b"\0")
        code_hash.update(hashlib.sha256(path.read_bytes()).digest())
    collection = (ROOT/"artifacts/design_review_repair_20260930/final_collection.log").read_text()
    test_counts = {name: int(count) for name, count in re.findall(r"^(tests/[^:]+): (\d+)$", collection, re.M)}
    assert sum(test_counts.values()) == 2684
    phases = [
        {"name": "M0 phase 1", "requests": summary["original_m0"]["phase1"]["requests"],
         "tokens": summary["original_m0"]["phase1"]["reported_tokens"]},
        {"name": "M0 phase 2", "requests": summary["original_m0"]["phase2"]["requests"],
         "tokens": summary["original_m0"]["phase2"]["reported_tokens"]},
        {"name": "E-iter", "requests": eiter["request_count"], "tokens": eiter["reported_total_tokens"]},
    ]
    assert sum(p["requests"] for p in phases) == 72
    assert sum(p["tokens"] for p in phases) == 447812
    cases = []
    for case in cli["cases"]:
        result = load(case["result_path"])
        cases.append({**case, "accounting": result["accounting"], "source_digest": result["identity"]["source_digest"],
            "diagnoses": [d["reason_code"] for d in result["diagnoses"]]})
    walls = [case["wall_seconds"] for case in cases]
    totals = {key: sum(case["counts"][key] for case in cases) for key in cases[0]["counts"]}
    property_states = Counter(state for case in cases for state in case["property_states"])
    einputs = [{"case": case["case"], "requests": case["model_calls"], "tokens": case["reported_total_tokens"],
        "elapsed_seconds": case["elapsed_seconds"], "observation_bytes": case["observation_units"],
        "physical_attempts": case["physical_witness_attempts"], "status": case["admitted_label"]}
        for case in eiter["cells"]]
    sizes = [case["tokens"] for case in einputs]
    data = {
        "schema_version": "technical-report-evidence-v1", "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "working_tree": "post-repair, uncommitted", "code_sha256": code_hash.hexdigest(),
        "source_file_count": len(modules), "source_lines_including_comments_and_blanks": sum(lines.values()),
        "by_layer_files": dict(by_layer), "by_layer_lines": dict(lines),
        "test_file_count": len(list((ROOT/"tests").glob("test_*.py"))), "collected_cases": 2684,
        "test_cases_by_file": test_counts, "baseline": baseline["baseline_full_suite_result"],
        "full_suite": acceptance["full_suite"], "enabled_checks": 126,
        "new_cases": 2684 - baseline["collected_tests"],
        "test_count_change_percent": 100*(2684-baseline["collected_tests"])/baseline["collected_tests"],
        "suite_time_difference_seconds": acceptance["full_suite"]["seconds"]-baseline["baseline_full_suite_result"]["seconds"],
        "suite_time_difference_percent": 100*(acceptance["full_suite"]["seconds"]/baseline["baseline_full_suite_result"]["seconds"]-1),
        "suite_time_difference_is_causal_speedup": False,
        "cli_cases": cases, "cli_totals": totals, "cli_property_states": dict(property_states),
        "cli_wall_seconds": {"n": len(walls), "mean": statistics.mean(walls), "median": statistics.median(walls),
            "minimum": min(walls), "maximum": max(walls), "sample_std": statistics.stdev(walls)},
        "cli_is_population_benchmark": False, "historical_phases": phases,
        "request_total": 72, "token_total": 447812, "request_cap": 210, "token_cap": 2500000,
        "request_cap_fraction": 72/210, "token_cap_fraction": 447812/2500000,
        "request_cap_unused": 210-72, "token_cap_unused": 2500000-447812,
        "overall_tokens_per_request": 447812/72,
        "eiter_cases": einputs, "eiter_token_dispersion": {"n": 4, "mean": statistics.mean(sizes),
            "median": statistics.median(sizes), "minimum": min(sizes), "maximum": max(sizes),
            "sample_std": statistics.stdev(sizes)},
        "budget_counterexample": {"total": 8192, "diagnostic_reserve": 256,
            "certificate_bytes": [2500,1000,1000,1000], "sum": 5500,
            "equal_first_share": 2048, "first_shortfall": 452,
            "remaining_after_delivery_and_reserve": 8192-5500-256},
        "acceptance_required": 31, "acceptance_conditional_not_enabled": 3,
        "gp": {name: acceptance[name] for name in ["GP0","GP1","GP2","GP3","GP4"]},
        "historical_G_A": "NO", "new_model_requests_in_report_work": 0,
        "new_target_experiments_in_report_work": 0,
        "input_sha256": {path: hashlib.sha256((ROOT/path).read_bytes()).hexdigest()
            for path in [*SOURCE_PATHS, *(case["result_path"] for case in cases)]},
    }
    (REPORT/"data/report_data.json").write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    macros = {"ModuleCount": len(modules), "SourceLines": sum(lines.values()), "TestFileCount": data["test_file_count"],
        "CollectedCases": 2684, "NewCases": 122, "TestGrowthPercent": f"{data['test_count_change_percent']:.2f}",
        "CliMeanMs": f"{1000*statistics.mean(walls):.2f}", "CliMedianMs": f"{1000*statistics.median(walls):.2f}",
        "CliMinMs": f"{1000*min(walls):.2f}", "CliMaxMs": f"{1000*max(walls):.2f}",
        "CliStdMs": f"{1000*statistics.stdev(walls):.2f}", "RequestUtilization": f"{100*72/210:.2f}",
        "TokenUtilization": f"{100*447812/2500000:.2f}", "AvgTokensPerRequest": f"{447812/72:.2f}"}
    (REPORT/"data/metrics.tex").write_text("% Generated from frozen existing result receipts.\n" +
        "\n".join(r"\newcommand{"+chr(92)+key+"}{"+str(value)+"}" for key,value in macros.items()) + "\n")
    print(json.dumps({"modules": len(modules), "source_lines": sum(lines.values()), "test_files": data["test_file_count"],
        "cli_counts": totals, "property_states": dict(property_states), "cli_ms": macros["CliMeanMs"]}))


if __name__ == "__main__": main()
