from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable

from .types import DetectorCase, OwaspLabel, VulnGymLabel


def _read_jsonl(path: Path) -> Iterable[dict]:
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: expected an object")
            yield value


def load_vulngym_entries(path: Path) -> tuple[list[DetectorCase], dict[str, VulnGymLabel]]:
    """Split VulnGym rows into detector-safe identities and evaluator-only labels."""

    cases: list[DetectorCase] = []
    labels: dict[str, VulnGymLabel] = {}
    for row in _read_jsonl(path):
        case_id = str(row["entry_id"])
        if case_id in labels:
            raise ValueError(f"duplicate VulnGym entry_id: {case_id}")
        cases.append(
            DetectorCase(
                case_id=case_id,
                repository_url=str(row["repo_url"]),
                commit=str(row["commit"]),
            )
        )
        labels[case_id] = VulnGymLabel(
            case_id=case_id,
            report_id=str(row["report_id"]),
            verify=bool(row.get("verify", 0)),
            entry_point=row.get("entry_point"),
            critical_operation=row.get("critical_operation"),
            trace=row.get("trace"),
        )
    return cases, labels


def load_owasp_expected_results(path: Path) -> dict[str, OwaspLabel]:
    """Load the OWASP Benchmark truth table without mixing it into detector cases."""

    raw_lines = path.read_text(encoding="utf-8-sig").splitlines()
    rows: list[str] = []
    for line in raw_lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            possible_header = stripped.removeprefix("#").strip()
            normalized_header = possible_header.casefold()
            if "test name" in normalized_header and "real vulnerability" in normalized_header and "cwe" in normalized_header:
                rows.append(possible_header)
            continue
        rows.append(line)
    if not rows:
        raise ValueError("OWASP expected-results file has no data rows")
    reader = csv.DictReader(rows, delimiter=",", skipinitialspace=True)
    labels: dict[str, OwaspLabel] = {}
    for row in reader:
        normalized = {str(key).strip().lower(): str(value).strip() for key, value in row.items() if key}
        case_id = normalized.get("test name") or normalized.get("testname") or normalized.get("name")
        category = normalized.get("category", "unknown")
        vulnerable_text = normalized.get("real vulnerability") or normalized.get("vulnerable") or ""
        cwe_text = normalized.get("cwe") or normalized.get("cwe number") or "0"
        if not case_id:
            raise ValueError(f"OWASP row lacks a test name: {row}")
        if case_id in labels:
            raise ValueError(f"duplicate OWASP test name: {case_id}")
        labels[case_id] = OwaspLabel(
            case_id=case_id,
            category=category,
            vulnerable=vulnerable_text.casefold() in {"true", "1", "yes"},
            cwe=int(cwe_text),
        )
    return labels
