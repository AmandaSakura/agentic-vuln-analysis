import json
import pytest
from cv_agent.experiment_model import load_experiment_model


@pytest.mark.parametrize("provider", ["deepseek", "gemini"])
def test_explicit_provider_uses_own_environment_and_keeps_key_out_of_metadata(monkeypatch, tmp_path, provider):
    monkeypatch.setenv("CV_AGENT_PROVIDER", provider)
    monkeypatch.setenv(provider.upper() + "_MODEL", "chosen-model")
    monkeypatch.setenv(provider.upper() + "_API_KEY", "test-secret")
    monkeypatch.setenv("ANTIGRAVITY_API_KEY", "wrong-provider-secret")
    config, key = load_experiment_model(tmp_path, "unused.json")
    assert key == "test-secret"
    assert config["model"] == "chosen-model"
    assert "secret" not in json.dumps(config)
    assert ("proxy_log_dir" in config) == (provider == "gemini")
    assert config["base_url"] == ("https://api.deepseek.com" if provider == "deepseek" else "http://127.0.0.1:8317/v1")


def test_missing_selected_key_does_not_fall_back(monkeypatch, tmp_path):
    monkeypatch.setenv("CV_AGENT_PROVIDER", "deepseek")
    monkeypatch.setenv("DEEPSEEK_MODEL", "chosen-model")
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.setenv("ANTIGRAVITY_API_KEY", "wrong-secret")
    with pytest.raises(ValueError, match="DEEPSEEK_API_KEY"):
        load_experiment_model(tmp_path, "unused.json")


def test_unknown_provider_rejected(monkeypatch, tmp_path):
    monkeypatch.setenv("CV_AGENT_PROVIDER", "typo")
    with pytest.raises(ValueError, match="CV_AGENT_PROVIDER"):
        load_experiment_model(tmp_path, "unused.json")
