"""Measure real synthetic imports without claiming sampled peaks are exact."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import pytest

from cv_agent.evaluation.diagnostics.measure_import_resources import measure_import


def test_real_import_measurement_records_source_and_observed_resources(tmp_path: Path):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    source = checkout / "synthetic_measurement.py"
    source.write_text(
        "import os, time\n"
        "opened = [open(os.devnull) for _ in range(8)]\n"
        "time.sleep(0.12)\n"
    )
    prefix = tmp_path / "import-baseline"
    record = measure_import(checkout, Path(sys.executable).absolute(),
                            "synthetic_measurement", prefix)

    assert record["returncode"] == 0
    assert record["timed_out"] is False
    identity = record["import_identity"]
    assert identity["source_inside_checkout"] is True
    assert identity["module_file"] == str(source)
    assert identity["source_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert identity["executable"] == str(Path(sys.executable).absolute())
    assert record["gnu_time"]["max_rss_kib"] > 0
    assert record["gnu_time"]["user_cpu_seconds"] >= 0
    assert record["gnu_time"]["system_cpu_seconds"] >= 0
    assert record["target_samples"]["sample_count"] > 0
    assert record["target_samples"]["fd_observed_peak"] >= 11
    assert record["target_samples"]["fd_peak_is_lower_bound"] is True
    assert record["target_samples"]["memory_peaks_observed_only"] is True
    assert record["target_environment"]["PYTHONPATH"] == str(checkout)
    assert "-X" in record["argv"] and "importtime" in record["argv"]
    stored = json.loads(prefix.with_suffix(".json").read_text())
    assert stored == record
    for log in record["logs"].values():
        path = Path(log["path"])
        assert path.is_file()
        assert log["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()


def test_existing_artifact_is_preserved_and_prevents_import(tmp_path: Path):
    existing = tmp_path / "baseline.time.log"
    existing.write_text("historical timing")
    with pytest.raises(FileExistsError):
        measure_import(tmp_path, Path(sys.executable).absolute(), "unused", tmp_path / "baseline")
    assert existing.read_text() == "historical timing"
    assert not (tmp_path / "baseline.json").exists()


@pytest.mark.parametrize("module", ["os;print('bad')", "os.path()", "../os", ""])
def test_module_name_is_data_and_must_be_a_dotted_name(tmp_path: Path, module: str):
    with pytest.raises(ValueError, match="dotted"):
        measure_import(tmp_path, Path(sys.executable).absolute(), module, tmp_path / "invalid")
    assert list(tmp_path.iterdir()) == []


def test_import_failure_is_a_saved_failed_measurement(tmp_path: Path):
    source = tmp_path / "synthetic_failure.py"
    source.write_text("raise ImportError('intentional synthetic baseline failure')\n")
    record = measure_import(tmp_path, Path(sys.executable).absolute(),
                            "synthetic_failure", tmp_path / "failure")
    assert record["returncode"] != 0
    assert record["import_identity"] is None
    assert "import_identity_missing" in record["gaps"]
    assert "intentional synthetic baseline failure" in (tmp_path / "failure.importtime.log").read_text()
