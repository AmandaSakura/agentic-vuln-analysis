"""Isolated worker probe for LangChain template behavior without inherited credentials."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


class SyntheticMarker:
    """Non-sensitive marker object for evaluating template attribute traversal."""
    def __init__(self, secret: str = "CV_AGENT_SYNTHETIC_MARKER_65106"):
        self.secret = secret


def run_probe(checkout_dir: Path, scenario: str, template_format: str = "f-string") -> dict:
    core_dir = (checkout_dir / "libs/core").resolve()
    if not core_dir.is_dir():
        raise FileNotFoundError(f"libs/core not found in checkout: {checkout_dir}")

    # Ensure core_dir is at the front of sys.path
    core_dir_str = str(core_dir)
    if core_dir_str in sys.path:
        sys.path.remove(core_dir_str)
    sys.path.insert(0, core_dir_str)

    import langchain_core
    from langchain_core.prompts import PromptTemplate

    imported_file = Path(langchain_core.__file__).resolve()
    expected_parent = (core_dir / "langchain_core").resolve()
    if not imported_file.is_relative_to(expected_parent):
        raise RuntimeError(
            f"Imported langchain_core from {imported_file}, expected under {expected_parent}"
        )

    marker = SyntheticMarker("CV_AGENT_SYNTHETIC_MARKER_65106")
    result: dict = {
        "scenario": scenario,
        "template_format": template_format,
        "imported_langchain_core": str(imported_file),
        "python_version": sys.version,
    }

    if scenario == "benign":
        try:
            prompt = PromptTemplate.from_template("Hello {name}", template_format=template_format)
            rendered = prompt.format(name="World")
            result.update(status="BENIGN_OK" if rendered == "Hello World" else "UNEXPECTED_OUTPUT",
                          output=rendered, success=(rendered == "Hello World"))
        except Exception as error:
            result.update(status="ERROR", error_type=type(error).__name__, error_message=str(error))

    elif scenario == "attribute_access":
        try:
            prompt = PromptTemplate.from_template("Value: {marker.secret}", template_format=template_format)
            rendered = prompt.format(marker=marker)
            leaked = marker.secret in rendered
            result.update(
                status="EXPLOITED" if leaked else "UNEXPECTED_OUTPUT",
                output=rendered,
                leaked_secret=leaked,
            )
        except Exception as error:
            result.update(
                status="BLOCKED" if isinstance(error, ValueError) and
                "Invalid variable name 'marker.secret' in f-string template" in str(error) else "ERROR",
                error_type=type(error).__name__,
                error_message=str(error),
            )

    elif scenario == "dunder_access":
        try:
            prompt = PromptTemplate.from_template("Class: {marker.__class__.__name__}", template_format=template_format)
            rendered = prompt.format(marker=marker)
            leaked = "SyntheticMarker" in rendered
            result.update(
                status="EXPLOITED" if leaked else "UNEXPECTED_OUTPUT",
                output=rendered,
                leaked_dunder=leaked,
            )
        except Exception as error:
            result.update(
                status="BLOCKED" if isinstance(error, ValueError) and
                "Invalid variable name 'marker.__class__.__name__' in f-string template" in str(error) else "ERROR",
                error_type=type(error).__name__,
                error_message=str(error),
            )
    else:
        raise ValueError(f"Unknown scenario: {scenario}")

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="LangChain template probe")
    parser.add_argument("--checkout", type=Path, required=True, help="Path to LangChain checkout directory")
    parser.add_argument(
        "--scenario",
        choices=["benign", "attribute_access", "dunder_access"],
        required=True,
        help="Probe scenario to evaluate",
    )
    parser.add_argument("--format", default="f-string", help="Template format (default: f-string)")
    args = parser.parse_args()

    result = run_probe(args.checkout, args.scenario, args.format)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
