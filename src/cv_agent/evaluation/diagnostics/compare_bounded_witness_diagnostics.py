"""Compare two diagnostic witnesses only after their concrete inputs match."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


_INPUT_FIELDS = (
    "probe_path", "control_path", "probe_nonce", "control_nonce", "precondition_sha256",
)


def compare_diagnostics(first: dict[str, Any], second: dict[str, Any]) -> dict[str, Any]:
    results = (first["result"], second["result"])
    if any(result["status"] != "UNRESOLVED"
           or result["details"].get("diagnostic_only") is not True for result in results):
        raise ValueError("pair comparison requires two diagnostic-only unresolved results")
    left, right = (result["details"] for result in results)
    mismatched = [field for field in _INPUT_FIELDS
                  if field not in left or field not in right or left[field] != right[field]]
    if mismatched:
        raise ValueError("diagnostic inputs differ: " + ", ".join(mismatched))

    def observation(record: dict[str, Any]) -> dict[str, Any]:
        result = record["result"]
        details = result["details"]
        event = details.get("probe_event", {})
        replay = details.get("probe_replay", {})
        return {
            "manifest_sha256": record["manifest_sha256"],
            "source_digest": record["source_digest"],
            "status": result["status"],
            "gaps": result["gaps"],
            "first_event_kind": event.get("kind"),
            "first_event_name": event.get("event"),
            "first_event_phase": event.get("phase"),
            "reached_popen": details.get("reached_popen", False),
            "argv": event.get("argv"),
            "emitter_frame": event.get("emitter_frame"),
            "interpreter": event.get("interpreter"),
            "replay_ok": replay.get("ok"),
            "replay_arguments": replay.get("arguments"),
        }

    return {
        "same_concrete_input": True,
        "input": {field: left[field] for field in _INPUT_FIELDS},
        "first": observation(first),
        "second": observation(second),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("first", type=Path)
    parser.add_argument("second", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    first = json.loads(args.first.read_text())
    second = json.loads(args.second.read_text())
    result = compare_diagnostics(first, second)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(args.output)


if __name__ == "__main__":
    main()
