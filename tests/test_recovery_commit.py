"""Owned offline fixtures exercise output publication, never target execution."""
from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path

import pytest

from cv_agent.domain.product_result import IdentityBundle, ReviewResult
from cv_agent.presentation import report
from cv_agent.presentation import commit


def result_fixture() -> ReviewResult:
    return ReviewResult(
        run_id="owned-output-control", run_state="COMPLETED",
        identity=IdentityBundle(source_digest="a" * 64,
            analysis_contract_digest="b" * 64, retrieval_view_revision="c" * 64),
    )


def test_raced_empty_output_is_not_replaced(tmp_path, monkeypatch):
    """A directory appearing after the initial exists check still belongs to its creator."""
    output = tmp_path / "output"
    original_fsync = os.fsync
    existing_inode = None

    def race_on_first_sync(fd):
        nonlocal existing_inode
        original_fsync(fd)
        if existing_inode is None:
            output.mkdir()
            existing_inode = output.stat().st_ino

    monkeypatch.setattr(report.os, "fsync", race_on_first_sync)
    with pytest.raises(FileExistsError):
        report.export_result(result_fixture(), output)
    assert output.stat().st_ino == existing_inode
    assert list(output.iterdir()) == []


def staged_fixture(tmp_path):
    staging = tmp_path / "staging"
    staging.mkdir(mode=0o700)
    private = staging / ".private"
    private.mkdir(mode=0o700)
    payloads = {
        "result.json": '{"run_id":"owned-result"}\n',
        "report.md": "# Owned local result\n",
        ".private/evidence.jsonl": '{"subject":"owned-result","proof":"bounded"}\n',
    }
    manifest = {name: hashlib.sha256(body.encode()).hexdigest() for name, body in payloads.items()}
    payloads["manifest.json"] = json.dumps(manifest, sort_keys=True) + "\n"
    for name, body in payloads.items():
        path = staging / name
        path.write_text(body)
        if name.startswith(".private/"):
            path.chmod(0o600)
    return staging, payloads


def test_atomic_commit_publishes_exact_complete_set_and_private_permissions(tmp_path):
    staging, payloads = staged_fixture(tmp_path)
    output = tmp_path / "output"
    commit.commit_directory(staging, output)
    assert not staging.exists()
    assert {str(p.relative_to(output)) for p in output.rglob("*") if p.is_file()} == set(payloads)
    for name, body in payloads.items():
        assert (output / name).read_text() == body
    manifest = json.loads((output / "manifest.json").read_text())
    for name, digest in manifest.items():
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == digest
    assert (output / ".private").stat().st_mode & 0o777 == 0o700
    assert (output / ".private/evidence.jsonl").stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("kind", ["empty", "nonempty", "symlink", "dangling-symlink", "file"])
def test_existing_target_is_never_replaced(tmp_path, kind):
    staging, payloads = staged_fixture(tmp_path)
    output = tmp_path / "output"
    if kind in {"empty", "nonempty"}:
        output.mkdir()
        if kind == "nonempty":
            (output / "old.json").write_text("existing owned result")
    elif kind in {"symlink", "dangling-symlink"}:
        original = tmp_path / "original"
        if kind == "symlink":
            original.mkdir()
        output.symlink_to(original, target_is_directory=True)
    else:
        output.write_text("existing file")
    original_inode = output.lstat().st_ino
    with pytest.raises(FileExistsError):
        commit.commit_directory(staging, output)
    assert output.lstat().st_ino == original_inode
    assert (staging / "result.json").read_text() == payloads["result.json"]
    if kind == "nonempty":
        assert (output / "old.json").read_text() == "existing owned result"
    if kind == "file":
        assert output.read_text() == "existing file"


@pytest.mark.parametrize("kind", ["empty", "nonempty", "symlink"])
def test_target_creation_at_commit_boundary_is_rejected(tmp_path, monkeypatch, kind):
    staging, _ = staged_fixture(tmp_path)
    output = tmp_path / "output"
    rename = commit._rename_no_replace
    original_inode = None

    def create_then_rename(source, target):
        nonlocal original_inode
        if kind == "symlink":
            existing = tmp_path / "existing"
            existing.mkdir()
            target.symlink_to(existing, target_is_directory=True)
        else:
            target.mkdir()
            if kind == "nonempty":
                (target / "keep").write_text("owned by concurrent creator")
        original_inode = target.lstat().st_ino
        rename(source, target)

    monkeypatch.setattr(commit, "_rename_no_replace", create_then_rename)
    with pytest.raises(FileExistsError):
        commit.commit_directory(staging, output)
    assert output.lstat().st_ino == original_inode
    assert staging.exists()
    if kind == "nonempty":
        assert (output / "keep").read_text() == "owned by concurrent creator"


@pytest.mark.parametrize("failure_at", ["file", "private", "staging", "parent"])
def test_sync_failure_before_commit_never_publishes_output(tmp_path, monkeypatch, failure_at):
    staging, _ = staged_fixture(tmp_path)
    output = tmp_path / "output"
    fsync = os.fsync
    failing_path = {"file": staging / "result.json", "private": staging / ".private",
                    "staging": staging, "parent": tmp_path}[failure_at]

    def fail_selected(fd):
        if Path(os.readlink(f"/proc/self/fd/{fd}")) == failing_path:
            raise OSError(errno.EIO, "owned injected sync error")
        fsync(fd)

    monkeypatch.setattr(commit.os, "fsync", fail_selected)
    with pytest.raises(OSError, match="owned injected sync error"):
        commit.commit_directory(staging, output)
    assert not output.exists()
    assert staging.exists()


def test_files_and_private_directory_sync_precede_commit_and_parent_sync_follows(tmp_path, monkeypatch):
    staging, _ = staged_fixture(tmp_path)
    output = tmp_path / "output"
    events = []
    fsync, rename = os.fsync, commit._rename_no_replace

    def track_sync(fd):
        events.append(("sync", Path(os.readlink(f"/proc/self/fd/{fd}"))))
        fsync(fd)

    def track_rename(source, target):
        events.append(("rename", target))
        rename(source, target)

    monkeypatch.setattr(commit.os, "fsync", track_sync)
    monkeypatch.setattr(commit, "_rename_no_replace", track_rename)
    commit.commit_directory(staging, output)
    names = [event[1] for event in events]
    rename_index = events.index(("rename", output))
    assert names.index(staging / ".private/evidence.jsonl") < names.index(staging / ".private")
    assert names.index(staging / ".private") < names.index(staging)
    assert names.index(staging / "result.json") < names.index(staging)
    assert names.index(staging / "report.md") < names.index(staging)
    assert names.index(staging / "manifest.json") < names.index(staging)
    assert names.index(staging) < rename_index
    assert events[rename_index - 1] == ("sync", tmp_path)
    assert events[rename_index + 1] == ("sync", tmp_path)


def test_final_parent_sync_error_explicitly_reports_publication(tmp_path, monkeypatch):
    staging, payloads = staged_fixture(tmp_path)
    output = tmp_path / "output"
    sync = commit.fsync_directory
    parent_calls = 0

    def fail_final_parent(path):
        nonlocal parent_calls
        if path == tmp_path:
            parent_calls += 1
            if parent_calls == 2:
                raise OSError(errno.EIO, "owned final sync failure")
        sync(path)

    monkeypatch.setattr(commit, "fsync_directory", fail_final_parent)
    with pytest.raises(commit.DirectoryCommitDurabilityError) as caught:
        commit.commit_directory(staging, output)
    assert caught.value.committed is True
    assert caught.value.output == output
    assert not staging.exists()
    assert (output / "manifest.json").read_text() == payloads["manifest.json"]


def test_unsupported_platform_has_no_replacing_rename_fallback(tmp_path, monkeypatch):
    staging, _ = staged_fixture(tmp_path)
    output = tmp_path / "output"
    monkeypatch.setattr(commit.sys, "platform", "unsupported-owned-control")
    monkeypatch.setattr(commit.os, "rename", lambda *_: pytest.fail("replacing rename is forbidden"))
    with pytest.raises(OSError) as caught:
        commit.commit_directory(staging, output)
    assert caught.value.errno == errno.ENOTSUP
    assert staging.exists() and not output.exists()


def test_unavailable_libc_symbol_has_no_replacing_rename_fallback(tmp_path, monkeypatch):
    staging, _ = staged_fixture(tmp_path)
    output = tmp_path / "output"
    monkeypatch.setattr(commit.ctypes, "CDLL", lambda *_, **__: object())
    monkeypatch.setattr(commit.os, "rename", lambda *_: pytest.fail("replacing rename is forbidden"))
    with pytest.raises(OSError) as caught:
        commit.commit_directory(staging, output)
    assert caught.value.errno == errno.ENOSYS
    assert staging.exists() and not output.exists()


def test_unsupported_filesystem_has_no_replacing_rename_fallback(tmp_path, monkeypatch):
    staging, _ = staged_fixture(tmp_path)
    output = tmp_path / "output"

    class UnsupportedRename:
        def __call__(self, *_):
            commit.ctypes.set_errno(errno.EOPNOTSUPP)
            return -1

    class UnsupportedLibc:
        renameat2 = UnsupportedRename()

    monkeypatch.setattr(commit.ctypes, "CDLL", lambda *_, **__: UnsupportedLibc())
    monkeypatch.setattr(commit.os, "rename", lambda *_: pytest.fail("replacing rename is forbidden"))
    with pytest.raises(OSError) as caught:
        commit.commit_directory(staging, output)
    assert caught.value.errno == errno.EOPNOTSUPP
    assert staging.exists() and not output.exists()


def test_staged_symlink_is_not_accepted_as_evidence(tmp_path):
    staging, _ = staged_fixture(tmp_path)
    private_target = tmp_path / "outside"
    private_target.write_text("outside owned control")
    (staging / "linked-evidence").symlink_to(private_target)
    output = tmp_path / "output"
    with pytest.raises(OSError, match="regular files and directories"):
        commit.commit_directory(staging, output)
    assert not output.exists()


def test_v1_export_keeps_schema_and_private_permissions(tmp_path):
    output = tmp_path / "output"
    exported = report.export_result(result_fixture(), output,
        private_records=({"owned_observation": "local private fixture"},))
    parsed = ReviewResult.model_validate_json((output / "result.json").read_text())
    assert parsed == exported
    assert parsed.schema_version == "product-review-v1"
    assert parsed.run_id == "owned-output-control"
    assert (output / ".private").stat().st_mode & 0o777 == 0o700
    for name in ("observations.jsonl", "completion.json"):
        assert (output / ".private" / name).stat().st_mode & 0o777 == 0o600
    completion = json.loads((output / ".private/completion.json").read_text())
    assert completion["authoritative"] is False
    assert completion["role"] == "postcommit-diagnostic"


@pytest.mark.parametrize("failure_at", ["write", "sync"])
def test_v1_completion_failure_does_not_invalidate_committed_result(tmp_path, monkeypatch, failure_at):
    output = tmp_path / "output"
    path_open, fsync = Path.open, os.fsync

    def fail_completion_open(path, *args, **kwargs):
        if path.name == "completion.json":
            raise OSError(errno.ENOSPC, "owned postcommit write failure")
        return path_open(path, *args, **kwargs)

    def fail_completion_sync(fd):
        if os.readlink(f"/proc/self/fd/{fd}").endswith("/completion.json"):
            raise OSError(errno.EIO, "owned postcommit sync failure")
        fsync(fd)

    if failure_at == "write":
        monkeypatch.setattr(Path, "open", fail_completion_open)
    else:
        monkeypatch.setattr(report.os, "fsync", fail_completion_sync)
    exported = report.export_result(result_fixture(), output)
    assert ReviewResult.model_validate_json((output / "result.json").read_text()) == exported
    assert "Run state: COMPLETED" in (output / "report.md").read_text()


def test_v1_staged_write_failure_cleans_staging_without_publication(tmp_path, monkeypatch):
    output = tmp_path / "output"
    path_open = Path.open

    def fail_result_write(path, *args, **kwargs):
        if path.name == "result.json":
            raise OSError(errno.ENOSPC, "owned staged write failure")
        return path_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_result_write)
    with pytest.raises(OSError, match="owned staged write failure"):
        report.export_result(result_fixture(), output)
    assert not output.exists()
    assert not list(tmp_path.glob(".output-*"))


def test_v1_cancel_before_commit_cleans_staging_without_publication(tmp_path, monkeypatch):
    output = tmp_path / "output"

    def cancelled(_):
        raise KeyboardInterrupt

    monkeypatch.setattr(report, "render_report", cancelled)
    with pytest.raises(KeyboardInterrupt):
        report.export_result(result_fixture(), output)
    assert not output.exists()
    assert not list(tmp_path.glob(".output-*"))
