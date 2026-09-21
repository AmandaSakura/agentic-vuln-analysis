"""Isolated worker probe for Jinja sandbox attr-format behavior."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def run_probe(checkout: Path, scenario: str) -> dict:
    source_dir = (checkout / "src").resolve()
    if not source_dir.is_dir():
        raise FileNotFoundError(f"src not found in checkout: {checkout}")
    source_dir_text = str(source_dir)
    if source_dir_text in sys.path:
        sys.path.remove(source_dir_text)
    sys.path.insert(0, source_dir_text)

    import jinja2
    from jinja2.sandbox import SandboxedEnvironment

    imported_file = Path(jinja2.__file__).resolve()
    expected_parent = (source_dir / "jinja2").resolve()
    if not imported_file.is_relative_to(expected_parent):
        raise RuntimeError(f"Imported jinja2 from {imported_file}, expected under {expected_parent}")

    env = SandboxedEnvironment()
    result: dict = {
        "scenario": scenario,
        "imported_jinja2": str(imported_file),
        "python_version": sys.version,
    }

    if scenario == "benign":
        try:
            output = env.from_string("Hello {{ name }}").render(name="World")
            result.update(status="BENIGN_OK" if output == "Hello World" else "UNEXPECTED_OUTPUT",
                          success=output == "Hello World", output=output)
        except Exception as error:
            result.update(status="ERROR", error_type=type(error).__name__, error_message=str(error))
    elif scenario == "attr_format":
        try:
            output = env.from_string("{{ '{0.__class__}'|attr('format')(marker) }}").render(marker="x")
            if "str" in output:
                result.update(status="EXPLOITED", success=True, output=output, format_exposed=True)
            elif output == "":
                result.update(status="BLOCKED", success=True, output=output, format_exposed=False,
                              error_type="Undefined",
                              error_message="format attribute unavailable through sandbox attr filter")
            else:
                result.update(status="UNEXPECTED_OUTPUT", success=False, output=output, format_exposed=False)
        except Exception as error:
            message = str(error)
            blocked = (
                type(error).__name__ in {"SecurityError", "UndefinedError", "TemplateRuntimeError"}
                and ("format" in message or "unsafe" in message or "access" in message)
            )
            result.update(status="BLOCKED" if blocked else "ERROR",
                          error_type=type(error).__name__, error_message=message)
    else:
        raise ValueError(f"Unknown scenario: {scenario}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Jinja attr-format sandbox probe")
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--scenario", choices=("benign", "attr_format"), required=True)
    args = parser.parse_args()
    print(json.dumps(run_probe(args.checkout, args.scenario), sort_keys=True))


if __name__ == "__main__":
    main()
