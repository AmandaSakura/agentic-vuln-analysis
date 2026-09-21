"""Resolve an explicit provider selection without persisting credentials."""
import json
import os
from pathlib import Path


def load_experiment_model(root: Path, configured_path: str) -> tuple[dict, str]:
    provider = os.environ.get("CV_AGENT_PROVIDER")
    if provider is None:
        # Existing experiment protocols retain their declared model configuration.
        config = json.loads((root / configured_path).read_text())
        return config, _required("ANTIGRAVITY_API_KEY")
    profiles = {
        "deepseek": ("https://api.deepseek.com", "DEEPSEEK_MODEL", "DEEPSEEK_API_KEY"),
        "gemini": ("http://127.0.0.1:8317/v1", "GEMINI_MODEL", "GEMINI_API_KEY"),
    }
    if provider not in profiles:
        raise ValueError("CV_AGENT_PROVIDER must be deepseek or gemini")
    url, model_env, key_env = profiles[provider]
    config = dict(base_url=url, model=_required(model_env), temperature=0.0,
                  timeout_seconds=180, max_tokens=6000, thinking_mode="disabled")
    if provider == "gemini":
        config["proxy_log_dir"] = "/home/joker/.config/cliproxyapi/auths/logs"
    return config, _required(key_env)


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"{name} must be set and nonempty")
    return value
