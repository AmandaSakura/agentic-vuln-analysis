"""Prepare fresh agent-designed static controls, separately from detector labels.

These are independent engineering controls, not human-reviewed product tasks or
held-out generalization evidence. The detector receives only copied source.
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import random


HERE = Path(__file__).resolve().parent
ROOT = HERE / "quality_controls"


def main():
    ROOT.mkdir(exist_ok=True)
    templates = [
        "    os.chmod(path, {mode})\n",
        "    selected = {mode}\n    os.chmod(path, selected)\n",
        "    if True:\n        os.chmod(path, {mode})\n",
        "    if False:\n        return None\n    else:\n        os.chmod(path, {mode})\n",
        "    selected = {mode}\n    alias = selected\n    os.chmod(path, alias)\n",
        "    selected = {mode} if True else 0\n    os.chmod(path, selected)\n",
        "    selected = 0 if False else {mode}\n    os.chmod(path, selected)\n",
        "    selected = ({mode})\n    os.chmod(path, selected)\n",
        "    unused = 19\n    os.chmod(path, {mode})\n",
        "    selected = {mode}\n    selected = selected\n    os.chmod(path, selected)\n",
        "    os.chmod(path, {decimal})\n",
        "    selected = {decimal}\n    os.chmod(path, selected)\n",
    ]
    cases = []
    for state, mode in (("SUPPORTED", "0o772"), ("REFUTED", "0o750")):
        for template in templates:
            cases.append((state, "import os\ndef inspect(path):\n" +
                          template.format(mode=mode, decimal=int(mode, 8)),
                          "Resolved selected chmod mode with constant control and builtin integer bindings."))
    unknown = [
        "def inspect(path, mode):\n    os.chmod(path, mode)\n",
        "def inspect(path):\n    mode = unknown_mode()\n    os.chmod(path, mode)\n",
        "def inspect(path, item):\n    os.chmod(path, item.mode)\n",
        "def inspect(path, item):\n    os.chmod(path, item['mode'])\n",
        "def inspect(path, item):\n    os.chmod(path, int(item))\n",
        "def inspect(path):\n    unknown_effect()\n    os.chmod(path, 0o750)\n",
        "@unregistered_wrapper\ndef inspect(path):\n    os.chmod(path, 0o750)\n",
        "def inspect(path, flag):\n    if flag:\n        os.chmod(path, 0o750)\n",
        "def inspect(path, flag):\n    mode = 0o750 if flag else 0o772\n    os.chmod(path, mode)\n",
        "def inspect(path):\n    try:\n        os.chmod(path, 0o750)\n    except Exception:\n        return None\n",
        "def inspect(path, items):\n    for item in items:\n        os.chmod(path, item)\n",
        "def inspect(path):\n    mode, = unresolved_iterable()\n    os.chmod(path, mode)\n",
    ]
    for body in unknown:
        cases.append(("UNKNOWN", "import os\n" + body,
                      "Unsupported or unproven value, execution or related effects require unresolved semantics."))
    rng = random.Random(20261001)
    rng.shuffle(cases)
    references = []
    for ordinal, (state, source, explanation) in enumerate(cases):
        neutral_id = "case-" + bytes(rng.randrange(256) for _ in range(8)).hex()
        case_root = ROOT / neutral_id
        case_root.mkdir(exist_ok=True)
        target = case_root / "entry.py"
        target.write_text(source, encoding="utf-8")
        parsed = ast.parse(source)
        lines = [node.lineno for node in ast.walk(parsed) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Attribute) and node.func.attr == "chmod"]
        assert len(lines) == 1
        references.append({"case_id": neutral_id, "expected_state": state,
                           "property_id": "chmod-mode-others-write", "source_path": "entry.py",
                           "selected_line": lines[0], "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
                           "reference_explanation": explanation})
    report = {"protocol": "fresh-agent-designed-static-controls-v1", "seed": 20261001,
              "design_owner": "agent other than product implementation owner",
              "human_independent": False, "held_out_claim_eligible": False,
              "model_requests": 0, "target_execution": 0,
              "labels_allowed_in_detector_inputs": False,
              "declared_counts": {"SUPPORTED": 12, "REFUTED": 12, "UNKNOWN": 12},
              "cases": references}
    (HERE / "quality_reference.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("Prepared 36 neutral owned controls; labels are in a separate scoring manifest.")


if __name__ == "__main__":
    main()
