"""Validate VulnGym retrieval results against selected entries and revisions."""

from __future__ import annotations

from collections.abc import Mapping

from .defaults import VULNGYM_RETRIEVAL_HARNESS
from .models import RetrievalMode
from .results import _list, _mapping, _require_keys, _validate_run_identity


def _vulngym_summary(
    records: list[Mapping[str, object]],
    modes: tuple[str, ...],
) -> dict[str, object]:
    return {
        mode: {
            "hit_count": sum(
                bool(_mapping(record["hits"], "entries.hits")[mode])
                for record in records
            ),
            "hit_rate": (
                sum(
                    bool(_mapping(record["hits"], "entries.hits")[mode])
                    for record in records
                )
                / len(records)
                if records
                else None
            ),
        }
        for mode in modes
    }


def _validate_vulngym_summary(
    value: object,
    records: list[Mapping[str, object]],
    modes: tuple[str, ...],
    name: str,
) -> None:
    summary = _mapping(value, name)
    expected = _vulngym_summary(records, modes)
    if summary != expected:
        raise ValueError(f"VulnGym summary {name} is inconsistent with entry hits")


def validate_vulngym_result_payload(
    payload: Mapping[str, object],
    *,
    expected_entries: Mapping[str, Mapping[str, object]],
    expected_subject_revisions: Mapping[str, str],
) -> None:
    modes = tuple(
        mode.value for mode in VULNGYM_RETRIEVAL_HARNESS.retrieval_modes
    )
    if not expected_entries:
        raise ValueError("VulnGym validation requires selected entry identities")
    if not expected_subject_revisions:
        raise ValueError("VulnGym validation requires selected subject revisions")
    for entry_id, expected in expected_entries.items():
        subject_key = expected.get("subject_key")
        repository_url = expected.get("repository_url")
        if (
            not entry_id
            or not isinstance(subject_key, str)
            or not subject_key.strip()
            or not isinstance(repository_url, str)
            or not repository_url.strip()
        ):
            raise ValueError("selected VulnGym entry mapping lacks repository identity")
        if not isinstance(expected.get("cross_file"), bool):
            raise ValueError("selected VulnGym entry mapping has invalid cross-file state")
    expected_entry_ids = set(expected_entries)
    expected_cross_file_entry_ids = {
        entry_id
        for entry_id, expected in expected_entries.items()
        if bool(expected.get("cross_file"))
    }
    expected_entry_subjects = {
        str(expected.get("subject_key")) for expected in expected_entries.values()
    }
    if expected_entry_subjects != set(expected_subject_revisions):
        raise ValueError("selected VulnGym entries and subjects are inconsistent")
    if payload.get("harness_id") != VULNGYM_RETRIEVAL_HARNESS.harness_id:
        raise ValueError("VulnGym result carries the wrong harness id")
    if payload.get("dataset") != VULNGYM_RETRIEVAL_HARNESS.dataset_name:
        raise ValueError("VulnGym result carries the wrong dataset name")
    if payload.get("claim_eligible") is not False:
        raise ValueError("VulnGym oracle result cannot be claim eligible")
    if payload.get("dataset_role") != VULNGYM_RETRIEVAL_HARNESS.dataset_role.value:
        raise ValueError("VulnGym result carries the wrong dataset role")
    if payload.get("experiment") != VULNGYM_RETRIEVAL_HARNESS.experiment_name:
        raise ValueError("VulnGym result carries the wrong experiment name")
    if payload.get("limitation") != VULNGYM_RETRIEVAL_HARNESS.limitation:
        raise ValueError("VulnGym result must retain its oracle limitation")
    if payload.get("candidate_protocol") != VULNGYM_RETRIEVAL_HARNESS.candidate_protocol:
        raise ValueError("VulnGym result carries the wrong candidate protocol")
    _require_keys(
        payload,
        {
            "dataset",
            "experiment",
            "limitation",
            "run_identity",
            "claim_assessment",
            "candidate_protocol",
            "retrieval_contract",
            "entry_count",
            "cross_file_entry_count",
            "entries",
            "overall",
            "cross_file",
            "same_file",
            "resolved_entry_count",
            "resolved_critical_count",
            "context_tokenizer",
            "context_token_count",
            "max_context_token_count_per_entry",
            "context_evidence_count",
            "max_context_evidence_count_per_entry",
            "repository_profiles",
            "by_repository",
            "graph_vs_local_hit_gain_percentage_points",
            "graph_vs_text_hit_gain_percentage_points",
            "hybrid_vs_text_hit_gain_percentage_points",
            "missed_entry_ids",
        },
        "root",
    )
    expected_contract = {
        **VULNGYM_RETRIEVAL_HARNESS.budget.model_dump(mode="json"),
        "total_context_tokens": VULNGYM_RETRIEVAL_HARNESS.budget.total_context_tokens,
        "modes": list(modes),
        "hybrid_aggregation": VULNGYM_RETRIEVAL_HARNESS.hybrid_aggregation,
        "critical_hit_policy": VULNGYM_RETRIEVAL_HARNESS.critical_hit_policy,
    }
    if payload["retrieval_contract"] != expected_contract:
        raise ValueError("VulnGym result retrieval contract differs from the project harness")
    if payload["context_tokenizer"] != "deterministic word-or-punctuation units":
        raise ValueError("VulnGym result carries the wrong context tokenizer")

    entries_raw = _list(payload["entries"], "entries")
    records: list[Mapping[str, object]] = []
    entry_ids: list[str] = []
    for index, raw_record in enumerate(entries_raw):
        record = _mapping(raw_record, f"entries[{index}]")
        _require_keys(
            record,
            {
                "entry_id",
                "repository_url",
                "subject_key",
                "cross_file",
                "entry_resolved",
                "critical_resolved",
                "hits",
                "evidence_counts",
            },
            f"entries[{index}]",
        )
        entry_id = str(record["entry_id"])
        if not entry_id:
            raise ValueError("VulnGym entry identity cannot be empty")
        expected = expected_entries.get(entry_id)
        if expected is None:
            raise ValueError(f"unexpected VulnGym entry identity: {entry_id}")
        if not str(record["repository_url"]) or not str(record["subject_key"]):
            raise ValueError(f"VulnGym entry {entry_id} lacks repository identity")
        if (
            str(record["subject_key"]) != str(expected.get("subject_key"))
            or str(record["repository_url"])
            != str(expected.get("repository_url"))
        ):
            raise ValueError(
                f"VulnGym entry {entry_id} differs from its selected repository mapping"
            )
        if not isinstance(record["cross_file"], bool):
            raise ValueError(f"VulnGym entry {entry_id} has invalid cross-file state")
        if record["cross_file"] is not bool(expected.get("cross_file")):
            raise ValueError(f"VulnGym entry {entry_id} has the wrong cross-file stratum")
        if not isinstance(record["entry_resolved"], bool) or not isinstance(
            record["critical_resolved"],
            bool,
        ):
            raise ValueError(f"VulnGym entry {entry_id} has invalid resolution state")
        hits = _mapping(record["hits"], f"entries[{index}].hits")
        if set(hits) != set(modes) or any(
            not isinstance(hits[mode], bool) for mode in modes
        ):
            raise ValueError(f"VulnGym entry {entry_id} has an invalid hit vector")
        if (not record["entry_resolved"] or not record["critical_resolved"]) and any(
            bool(hits[mode]) for mode in modes
        ):
            raise ValueError(f"unresolved VulnGym entry {entry_id} cannot be a retrieval hit")
        evidence_counts = _mapping(
            record["evidence_counts"],
            f"entries[{index}].evidence_counts",
        )
        if set(evidence_counts) != set(modes):
            raise ValueError(f"VulnGym entry {entry_id} has an invalid evidence-count vector")
        for mode in modes:
            value = evidence_counts[mode]
            if type(value) is not int or int(value) < 0:
                raise ValueError(f"VulnGym entry {entry_id} has invalid evidence count for {mode}")
        records.append(record)
        entry_ids.append(entry_id)

    if len(entry_ids) != len(set(entry_ids)) or set(entry_ids) != expected_entry_ids:
        raise ValueError("VulnGym result entries differ from the selected entry identities")
    if type(payload["entry_count"]) is not int or payload["entry_count"] != len(
        expected_entry_ids
    ):
        raise ValueError("VulnGym entry count differs from the selected denominator")
    if (
        type(payload["cross_file_entry_count"]) is not int
        or payload["cross_file_entry_count"] != len(expected_cross_file_entry_ids)
    ):
        raise ValueError("VulnGym cross-file count differs from the selected stratum")
    if type(payload["resolved_entry_count"]) is not int or payload[
        "resolved_entry_count"
    ] != sum(bool(record["entry_resolved"]) for record in records):
        raise ValueError("VulnGym resolved-entry count is inconsistent")
    if type(payload["resolved_critical_count"]) is not int or payload[
        "resolved_critical_count"
    ] != sum(bool(record["critical_resolved"]) for record in records):
        raise ValueError("VulnGym resolved-critical count is inconsistent")

    cross_records = [record for record in records if bool(record["cross_file"])]
    same_records = [record for record in records if not bool(record["cross_file"])]
    _validate_vulngym_summary(payload["overall"], records, modes, "overall")
    _validate_vulngym_summary(
        payload["cross_file"],
        cross_records,
        modes,
        "cross_file",
    )
    _validate_vulngym_summary(
        payload["same_file"],
        same_records,
        modes,
        "same_file",
    )
    records_by_repository: dict[str, list[Mapping[str, object]]] = {}
    for record in records:
        records_by_repository.setdefault(str(record["repository_url"]), []).append(
            record
        )
    by_repository = _mapping(payload["by_repository"], "by_repository")
    if set(by_repository) != set(records_by_repository):
        raise ValueError("VulnGym repository summaries differ from selected repositories")
    for repository_url, repository_records in records_by_repository.items():
        _validate_vulngym_summary(
            by_repository[repository_url],
            repository_records,
            modes,
            f"by_repository.{repository_url}",
        )

    missed = _mapping(payload["missed_entry_ids"], "missed_entry_ids")
    if set(missed) != set(modes):
        raise ValueError("VulnGym missed-entry lists must cover every retrieval mode")
    for mode in modes:
        expected_missed = sorted(
            str(record["entry_id"])
            for record in records
            if not bool(_mapping(record["hits"], "entries.hits")[mode])
        )
        if missed[mode] != expected_missed:
            raise ValueError(f"VulnGym missed-entry list is inconsistent for {mode}")

    overall = _mapping(payload["overall"], "overall")
    rates = {
        mode: _mapping(overall[mode], f"overall.{mode}")["hit_rate"]
        for mode in modes
    }
    expected_gains = {
        "graph_vs_local_hit_gain_percentage_points": 100.0
        * (float(rates["graph"]) - float(rates["local"])),
        "graph_vs_text_hit_gain_percentage_points": 100.0
        * (float(rates["graph"]) - float(rates["text"])),
        "hybrid_vs_text_hit_gain_percentage_points": 100.0
        * (float(rates["hybrid"]) - float(rates["text"])),
    }
    for field, expected in expected_gains.items():
        if payload[field] != expected:
            raise ValueError(f"VulnGym gain field is inconsistent: {field}")

    context_totals = _mapping(payload["context_token_count"], "context_token_count")
    context_maxima = _mapping(
        payload["max_context_token_count_per_entry"],
        "max_context_token_count_per_entry",
    )
    evidence_totals = _mapping(payload["context_evidence_count"], "context_evidence_count")
    evidence_maxima = _mapping(
        payload["max_context_evidence_count_per_entry"],
        "max_context_evidence_count_per_entry",
    )
    if set(context_totals) != set(modes) or set(context_maxima) != set(modes):
        raise ValueError("VulnGym context diagnostics must cover every retrieval mode")
    if set(evidence_totals) != set(modes) or set(evidence_maxima) != set(modes):
        raise ValueError("VulnGym evidence-count diagnostics must cover every retrieval mode")
    for mode in modes:
        total = context_totals[mode]
        maximum = context_maxima[mode]
        if type(total) is not int or type(maximum) is not int or total < 0 or maximum < 0:
            raise ValueError(f"VulnGym context diagnostics are invalid for {mode}")
        limit = (
            VULNGYM_RETRIEVAL_HARNESS.budget.base_context_tokens
            if mode == RetrievalMode.LOCAL.value
            else VULNGYM_RETRIEVAL_HARNESS.budget.total_context_tokens
        )
        if maximum > limit or total > len(records) * limit or total < maximum:
            raise ValueError(f"VulnGym context budget was exceeded for {mode}")
        evidence_total = evidence_totals[mode]
        evidence_maximum = evidence_maxima[mode]
        expected_counts = [
            int(_mapping(record["evidence_counts"], "entries.evidence_counts")[mode])
            for record in records
        ]
        if (
            type(evidence_total) is not int
            or type(evidence_maximum) is not int
            or evidence_total != sum(expected_counts)
            or evidence_maximum != max(expected_counts, default=0)
        ):
            raise ValueError(f"VulnGym evidence-count diagnostics are inconsistent for {mode}")

    profiles_raw = _list(payload["repository_profiles"], "repository_profiles")
    profiles: dict[str, Mapping[str, object]] = {}
    for index, raw_profile in enumerate(profiles_raw):
        profile = _mapping(raw_profile, f"repository_profiles[{index}]")
        _require_keys(
            profile,
            {
                "subject_key",
                "repository_url",
                "commit",
                "dirty",
                "source_file_count",
                "function_document_count",
                "parse_error_count",
            },
            f"repository_profiles[{index}]",
        )
        subject_key = str(profile["subject_key"])
        if subject_key in profiles:
            raise ValueError(f"duplicate VulnGym subject profile: {subject_key}")
        if not isinstance(profile["dirty"], bool):
            raise ValueError(f"VulnGym subject profile {subject_key} has invalid dirty state")
        for field in (
            "source_file_count",
            "function_document_count",
            "parse_error_count",
        ):
            if type(profile[field]) is not int or int(profile[field]) < 0:
                raise ValueError(f"VulnGym subject profile {subject_key} has invalid {field}")
        if (
            int(profile["source_file_count"]) < 1
            or int(profile["function_document_count"]) < 1
            or int(profile["parse_error_count"]) > int(profile["source_file_count"])
        ):
            raise ValueError(f"VulnGym subject profile {subject_key} has impossible counts")
        profiles[subject_key] = profile
    if set(profiles) != set(expected_subject_revisions):
        raise ValueError("VulnGym subject profiles differ from selected subjects")
    if {str(record["subject_key"]) for record in records} != set(
        expected_subject_revisions
    ):
        raise ValueError("VulnGym entries do not cover every selected subject")
    for subject_key, revision in expected_subject_revisions.items():
        profile = profiles[subject_key]
        if profile["commit"] != revision:
            raise ValueError(f"VulnGym subject profile has wrong revision: {subject_key}")
        subject_records = [
            record
            for record in records
            if str(record["subject_key"]) == subject_key
        ]
        repository_urls = {
            str(record["repository_url"]) for record in subject_records
        }
        if repository_urls != {str(profile["repository_url"])}:
            raise ValueError(
                f"VulnGym subject profile has inconsistent repository URL: {subject_key}"
            )

    _validate_run_identity(payload)
    identity = _mapping(payload["run_identity"], "run_identity")
    datasets = _mapping(identity["datasets"], "run_identity.datasets")
    if set(datasets) != {"VulnGym", *expected_subject_revisions}:
        raise ValueError("VulnGym run identity has the wrong dataset/subject set")
    for subject_key, revision in expected_subject_revisions.items():
        dataset_identity = _mapping(
            datasets[subject_key],
            f"run_identity.datasets.{subject_key}",
        )
        if dataset_identity["revision"] != revision:
            raise ValueError(f"VulnGym run identity has wrong revision: {subject_key}")
        if profiles[subject_key]["dirty"] is not dataset_identity["dirty"]:
            raise ValueError(f"VulnGym subject dirty state is inconsistent: {subject_key}")
    assessment = _mapping(payload["claim_assessment"], "claim_assessment")
    if assessment["eligible"] is not False:
        raise ValueError("VulnGym oracle results cannot pass claim assessment")
