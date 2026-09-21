"""Pure advisory result accounting and explicit JSON publication helpers."""
from __future__ import annotations

import json
from pathlib import Path

from .datasets.advisory_config import PythonHeldoutPairExperimentConfig, heldout_truth, planned_heldout_cells
from .metrics import metrics, paired, replay_fast_prefix


def save_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(path)


def rows_with_truth(rows: list[dict], config: PythonHeldoutPairExperimentConfig) -> list[dict]:
    observed: dict[tuple[str, str], list[dict]] = {}
    for row in rows:
        observed.setdefault((row["case_id"], row["system"]), []).append(row)
    enriched = []
    planned_keys = set()
    for pair, case, system in planned_heldout_cells(config):
        key = (case.case_id, system.value)
        planned_keys.add(key)
        matching_rows = observed.get(key) or [
            {
                "case_id": case.case_id,
                "system": system.value,
                "status": "not_run",
                "predicted_label": None,
                "model_calls": 0,
                "tool_calls": 0,
                "latency_sec": 0,
                "verdict": None,
                "pair_id": pair.pair_id,
                "revision_role": case.revision_role,
            }
        ]
        for row in matching_rows:
            enriched.append(
                {
                    **row,
                    "ground_truth": heldout_truth(case.revision_role),
                    "category": pair.advisory,
                    "entry_id": pair.entry_id,
                    "planned_cell": True,
                }
            )
    enriched.extend(
        {**row, "planned_cell": False} for row in rows
        if (row["case_id"], row["system"]) not in planned_keys
    )
    return enriched


def build_heldout_summary(
    config: PythonHeldoutPairExperimentConfig,
    rows: list[dict],
    usage: dict,
) -> dict:
    all_rows = rows_with_truth(rows, config)
    grouped: dict[tuple[str, str], list[dict]] = {}
    for row in all_rows:
        if row["planned_cell"]:
            grouped.setdefault((row["case_id"], row["system"]), []).append(row)
    enriched = []
    duplicates = []
    for (case_id, system), matches in grouped.items():
        if len(matches) == 1:
            enriched.append(matches[0])
            continue
        duplicates.append({"case_id": case_id, "system": system, "rows": len(matches)})
        # An invalid duplicate cell occupies one denominator slot. Its raw
        # records remain in results.json, but none can win by overwrite order.
        enriched.append({
            **matches[0], "status": "failed", "predicted_label": None, "verdict": None,
            "model_calls": sum(row["model_calls"] for row in matches),
            "tool_calls": sum(row["tool_calls"] for row in matches),
            "latency_sec": sum(row["latency_sec"] for row in matches),
        })
    systems = [system.value for system in config.systems]
    summary = {
        "claim_eligible": False,
        "dataset_role": config.dataset_role,
        "unexpected_rows": [row for row in all_rows if not row["planned_cell"]],
        "duplicate_cells": duplicates,
        "systems": {
            system: metrics([row for row in enriched if row["system"] == system])
            for system in systems
        },
        "advisories": {
            advisory: {
                system: metrics(
                    [
                        row
                        for row in enriched
                        if row["system"] == system and row["category"] == advisory
                    ]
                )
                for system in systems
            }
            for advisory in sorted({row["category"] for row in enriched})
        },
        "paired": {
            f"{left}_vs_{right}": paired(enriched, left, right)
            for left, right in (("E2", "E3"), ("E3", "E4"), ("E4", "E5"))
        },
        "usage": usage,
        "full_review_prefix_replays": {
            row["case_id"]: replay_fast_prefix(row["verdict"])
            for row in enriched
            if row["system"] == "E4" and row.get("verdict") is not None
        },
    }
    return summary


def summarize_pair_run(run_dir: Path, config: PythonHeldoutPairExperimentConfig, rows: list[dict], usage: dict) -> dict:
    summary = build_heldout_summary(config, rows, usage)
    save_json(run_dir / "summary.json", summary)
    return summary
