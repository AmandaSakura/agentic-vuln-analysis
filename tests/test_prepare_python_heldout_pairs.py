import importlib
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[1]


def test_advisory_parser_extracts_same_repository_commit_and_versions():
    mod = importlib.import_module('cv_agent.evaluation.preparation.prepare_python_heldout_pairs')
    html = """
      <div>Package pip mlflow ( pip )</div>
      <div>Affected versions &lt; 3.4.0rc0</div>
      <div>Patched versions 3.4.0rc0</div>
      <h2>Description</h2>
      <a href="https://github.com/mlflow/mlflow/commit/1d7c8d4cf0a67d407499a8a4ffac387ea4f8194a">
        mlflow/mlflow@1d7c8d4
      </a>
      <a href="https://github.com/other/project/commit/2222222222222222222222222222222222222222">
        other/project@2222222
      </a>
    """
    assert mod.advisory_commit_urls("https://github.com/mlflow/mlflow", html) == (
        "https://github.com/mlflow/mlflow/commit/1d7c8d4cf0a67d407499a8a4ffac387ea4f8194a",
    )
    assert mod.advisory_versions(html) == {
        "affected_versions": "< 3.4.0rc0",
        "patched_versions": "3.4.0rc0",
    }


def test_line_parser_accepts_ranges():
    mod = importlib.import_module('cv_agent.evaluation.preparation.prepare_python_heldout_pairs')
    assert mod.first_line("493-494") == 493
    assert mod.first_line(761) == 761


def test_fixed_commit_selection_skips_unrelated_advisory_commit(monkeypatch):
    mod = importlib.import_module('cv_agent.evaluation.preparation.prepare_python_heldout_pairs')
    row = {
        "repo_url": "https://github.com/example/project",
        "commit": "a" * 40,
        "vuln_title": "Example eval issue",
        "vuln_category_l1": "injection",
        "vuln_category_l2": "eval",
        "entry_point": {"file": "app.py", "line": 1, "code": "def entry():", "desc": "entry"},
        "critical_operation": {
            "file": "app.py",
            "line": 2,
            "code": "return eval(value)",
            "desc": "eval sink",
        },
    }
    checkouts = {
        "b" * 40: "fixed-unrelated",
        "c" * 40: "fixed-candidate",
    }
    changed = {
        "b" * 40: ("docs/readme.md",),
        "c" * 40: ("app.py",),
    }
    texts = {
        ("vulnerable", "app.py"): "def entry(value):\n    return eval(value)\n",
        ("fixed-candidate", "app.py"): "def entry(value):\n    return value\n",
    }
    monkeypatch.setattr(mod, "ensure_checkout", lambda repo, commit: checkouts[commit])
    monkeypatch.setattr(mod, "verify_ancestry", lambda repo, old, new: True)
    monkeypatch.setattr(mod, "commit_changed_paths", lambda repo, commit: changed[commit])
    monkeypatch.setattr(mod, "read_checkout_text", lambda checkout, path: texts[(checkout, path)])
    monkeypatch.setattr(mod.Path, "is_file", lambda self: True)

    selected, rejected = mod.choose_fixed_commit(
        row,
        (
            f"https://github.com/example/project/commit/{'b' * 40}",
            f"https://github.com/example/project/commit/{'c' * 40}",
        ),
        "vulnerable",
    )

    assert selected["fixed_commit"] == "c" * 40
    assert rejected[0]["reason"] == "fixed_commit_does_not_touch_candidate_or_scope"


def test_fixed_commit_selection_rejects_partial_same_file_fix(monkeypatch):
    mod = importlib.import_module('cv_agent.evaluation.preparation.prepare_python_heldout_pairs')
    row = {
        "repo_url": "https://github.com/example/project",
        "commit": "a" * 40,
        "vuln_title": "World writable temp directory",
        "vuln_category_l1": "race",
        "vuln_category_l2": "permissions",
        "entry_point": {
            "file": "file_utils.py",
            "line": 1,
            "code": "def get_or_create_nfs_tmp_dir():",
            "desc": "entry",
        },
        "critical_operation": {
            "file": "file_utils.py",
            "line": 2,
            "code": "os.chmod(tmp_nfs_dir, 0o777)",
            "desc": "world-writable chmod",
        },
    }
    monkeypatch.setattr(mod, "ensure_checkout", lambda repo, commit: "fixed")
    monkeypatch.setattr(mod, "verify_ancestry", lambda repo, old, new: True)
    monkeypatch.setattr(mod, "commit_changed_paths", lambda repo, commit: ("file_utils.py",))
    monkeypatch.setattr(
        mod,
        "read_checkout_text",
        lambda checkout, path: (
            "def get_or_create_nfs_tmp_dir():\n"
            "    os.chmod(tmp_nfs_dir, 0o777)\n"
        ),
    )
    monkeypatch.setattr(mod.Path, "is_file", lambda self: True)

    selected, rejected = mod.choose_fixed_commit(
        row,
        (f"https://github.com/example/project/commit/{'b' * 40}",),
        "vulnerable",
    )

    assert selected is None
    assert rejected[0]["reason"] == "fixed_candidate_not_repaired"


def test_scope_mentions_uncommon_helper_basename_only():
    mod = importlib.import_module('cv_agent.evaluation.preparation.prepare_python_heldout_pairs')
    row = {
        "vuln_title": "MLflow command injection in mlserver.py",
        "vuln_category_l1": "injection",
        "vuln_category_l2": "command",
        "entry_point": {
            "file": "mlflow/pyfunc/backend.py",
            "line": 1,
            "code": "def serve(",
            "desc": "entry",
        },
        "critical_operation": {
            "file": "mlflow/pyfunc/backend.py",
            "line": 2,
            "code": "subprocess.Popen(command)",
            "desc": "sink",
        },
    }

    assert mod.scope_mentions_path(row, "mlflow/pyfunc/mlserver.py")
    assert not mod.scope_mentions_path(row, "mlflow/pyfunc/utils.py")


@pytest.mark.parametrize("mode,expected_reason", [
    ("missing_snippets", "candidate_source_snippet_not_found"),
    ("unchanged_helper", "fixed_candidate_not_repaired"),
    ("changed_helper", "candidate_specific_repair_observed"),
])
def test_repair_admission_requires_bound_source_and_observed_change(monkeypatch, mode, expected_reason):
    mod = importlib.import_module('cv_agent.evaluation.preparation.prepare_python_heldout_pairs')
    row = {
        "vuln_title": "Command injection in command_helper.py",
        "vuln_category_l1": "injection", "vuln_category_l2": "command",
        "entry_point": {"file": "app.py", "line": 1, "code": "def entry(value):"},
        "critical_operation": {"file": "app.py", "line": 2, "code": "return launch(value)"},
    }
    if mode == "missing_snippets":
        changed_paths = ("app.py",)
        texts = {("vulnerable", "app.py"): "unrelated = 1\n",
                 ("fixed", "app.py"): "unrelated = 2\n"}
    else:
        changed_paths = ("pkg/command_helper.py",)
        source = "def entry(value):\n    return launch(value)\n"
        texts = {
            ("vulnerable", "app.py"): source, ("fixed", "app.py"): source,
            ("vulnerable", "pkg/command_helper.py"): "return value\n",
            ("fixed", "pkg/command_helper.py"): (
                "return shlex.quote(value)\n" if mode == "changed_helper" else "return value\n"
            ),
        }
    monkeypatch.setattr(mod, "commit_changed_paths", lambda repo, commit: changed_paths)
    monkeypatch.setattr(mod, "read_checkout_text", lambda checkout, path: texts[(checkout, path)])

    result = mod.fixed_commit_repair_evidence(
        row, repository_url="https://github.com/example/project",
        vulnerable_checkout="vulnerable", fixed_checkout="fixed", fixed_commit="b" * 40,
    )

    assert result["reason"] == expected_reason
    assert result["verified"] is (mode == "changed_helper")
