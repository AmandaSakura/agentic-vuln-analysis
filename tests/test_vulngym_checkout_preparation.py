import importlib
import subprocess
from pathlib import Path

import pytest


def module():
    return importlib.import_module("cv_agent.evaluation.preparation.prepare_vulngym_checkouts")


def git(*args, cwd=None):
    return subprocess.run(["git", *args], cwd=cwd, check=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()


def test_checkout_preparation_fetches_exact_clean_commit_from_local_remote(tmp_path, monkeypatch):
    mod = module()
    monkeypatch.setattr(mod, "repository_key", lambda _: "https://github.com/example/repo")
    source = tmp_path / "source"
    source.mkdir()
    git("init", "--quiet", str(source))
    git("-C", str(source), "config", "user.email", "test@example.com")
    git("-C", str(source), "config", "user.name", "Test")
    (source / "app.py").write_text("def entry():\n    return 1\n")
    git("-C", str(source), "add", "app.py")
    git("-C", str(source), "commit", "--quiet", "-m", "initial")
    commit = git("-C", str(source), "rev-parse", "HEAD")
    remote = tmp_path / "remote.git"
    git("clone", "--quiet", "--bare", str(source), str(remote))

    checkout = mod.ensure_checkout(
        str(remote), commit, tmp_path / "cache", tmp_path / "subjects"
    )

    assert (checkout / "app.py").read_text() == "def entry():\n    return 1\n"
    assert git("-C", str(checkout), "rev-parse", "HEAD") == commit
    assert not git("-C", str(checkout), "status", "--porcelain")
    mod.remove_checkout(str(remote), commit, tmp_path / "cache", tmp_path / "subjects")
    assert not checkout.exists()
    assert mod.ensure_checkout(
        str(remote), commit, tmp_path / "cache", tmp_path / "subjects"
    ) == checkout


def test_checkout_refuses_invalid_sha_and_wrong_cache_origin(tmp_path):
    mod = module()
    with pytest.raises(ValueError, match="Invalid pinned commit"):
        mod.ensure_checkout("https://github.com/example/repo", "bad", tmp_path / "cache", tmp_path / "subjects")

    cache = tmp_path / "cache" / "example__repo"
    cache.mkdir(parents=True)
    (cache / ".git").mkdir()
    from unittest.mock import patch
    with patch.object(mod, "run_git", return_value="https://github.com/example/other"):
        with pytest.raises(ValueError, match="origin mismatch"):
            mod.ensure_repository_cache("https://github.com/example/repo", tmp_path / "cache")


def test_checkout_removal_refuses_dirty_source(tmp_path, monkeypatch):
    mod = module()
    checkout = tmp_path / "example__repo" / ("a" * 40)
    checkout.mkdir(parents=True)
    monkeypatch.setattr(mod, "repository_slug", lambda _: "example__repo")
    monkeypatch.setattr(mod, "git_identity", lambda _: type("Identity", (), {
        "revision": "a" * 40, "dirty": True
    })())
    with pytest.raises(ValueError, match="Refusing to remove a changed"):
        mod.remove_checkout("https://github.com/example/repo", "a" * 40,
                            tmp_path / "cache", tmp_path)
