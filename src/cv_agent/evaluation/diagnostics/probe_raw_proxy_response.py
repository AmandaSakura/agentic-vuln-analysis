"""One journaled proxy-response diagnostic through the pytest-gated runtime."""
import json
import os
from uuid import uuid4

from cv_agent.runtime.paths import PROJECT_ROOT as project_root
from cv_agent.runtime.journal import Journal, Trial, utc_now
from cv_agent.runtime.budget import Budget
from cv_agent.runtime.snapshots import snapshot_sources
from cv_agent.domain.chat import ChatMessage
from cv_agent.runtime.model import OpenAICompatibleChatModel


def main() -> None:
    config = json.loads((project_root / "configs/models/micro_benchmark_gemini_native.json").read_text())
    source = project_root / "artifacts/real_source_smoke/d1891dbaa76244d7a4dc76888c9e4dbc/events.jsonl"
    events = [json.loads(line) for line in source.read_text().splitlines()]
    request = next(event for event in events if event.get("event") == "model_start"
                   and event.get("system") == "E3" and "PrefectHQ" in event.get("case_id", ""))
    directory = project_root / "artifacts/transport_raw_diagnostic" / uuid4().hex
    directory.mkdir(parents=True)
    (directory / "metadata.json").write_text(json.dumps(dict(
        started_at=utc_now(), config=config, max_requests=1, tool_execution=False,
        source=str(source), source_sha256=snapshot_sources(project_root, directory), claim_eligible=False,
    ), indent=2) + "\n")
    trial = Trial("proxy-diagnostic", "transport-only", Journal(directory / "events.jsonl"))
    observe = Budget(1, 300).observer(trial, "transport_probe")

    def record(event):
        observe(event)
        if event["event"] == "model_response_received":
            raw = event["raw_response"]
            (directory / "raw_response.json").write_text(json.dumps(dict(
                response_body=raw,
                usage=raw.get("usage") if isinstance(raw, dict) else None,
            ), indent=2) + "\n")

    model = OpenAICompatibleChatModel(**config, api_key=os.environ["ANTIGRAVITY_API_KEY"], observer=record)
    model.complete([ChatMessage.model_validate(message) for message in request["messages"]], request["tools"])
    print(f"Recorded proxy response (not a native upstream response): {directory}")


if __name__ == "__main__":
    main()
