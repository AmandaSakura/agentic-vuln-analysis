"""Stage the actual source snapshot as a product-only distribution, offline.

No root manifest or lockfile is changed. The staged package excludes research
orchestration and transport, but keeps the actual shared static dependency
closure, including dormant validator definitions and eager parser grammars.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys


HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[1]
PACKAGE = PROJECT / "src" / "cv_agent"
DEPENDENCIES = ("pydantic", "tree-sitter", "tree-sitter-go", "tree-sitter-java",
                "tree-sitter-javascript", "tree-sitter-typescript")
OMIT = {"evaluation", "baselines"}
AGENTS = {"__init__.py", "discovery.py", "scanner.py", "evidence_policy.py"}
RUNTIME_OMIT = {"model.py", "admission.py", "provider.py", "journal.py", "jev.py", "snapshots.py"}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--entry", choices=("main", "product_main"), default="product_main")
    args = parser.parse_args()
    destination = args.destination.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    (destination / "install.md").write_text(
        "# CV-AGENT 离线产品恢复发行物：patch1\n\n"
        "该目录正在从冻结源码构建本地发行物；完整安装说明和验收回执将在封装完成后写入。\n\n"
        "验收平台：Linux x86-64 / Python 3.13.5。所有构建及安装只使用已有缓存和本地依赖包；不联网、不升级。\n\n"
        "review v2 在受限子进程中运行；verify/view 的只读静态重放目前不在该 worker 内。\n"
        "summary 预算只约束 finding body，元数据豁免；存储故障及内部异常终止后续分析。\n"
        "用户真实环境与人工独立质量尚未测量。\n", encoding="utf-8")
    stage = destination / "source"
    included = []
    excluded = []
    for path in sorted(PACKAGE.rglob("*.py")):
        relative = path.relative_to(PACKAGE)
        if (relative.parts[0] in OMIT or (relative.parts[0] == "agents" and relative.name not in AGENTS)
                or (relative.parts[0] == "runtime" and relative.name in RUNTIME_OMIT)):
            excluded.append(relative.as_posix())
            continue
        target = stage / "src" / "cv_agent" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        included.append({"path": relative.as_posix(), "sha256": sha(path), "bytes": path.stat().st_size})
    dependencies = [f"{name}=={importlib.metadata.version(name)}" for name in DEPENDENCIES]
    manifest = f'''[project]
name = "cv-agent"
version = "0.1.0+recovery.20261001"
description = "Offline candidate-bound Python static review product snapshot"
requires-python = ">=3.12"
dependencies = {json.dumps(dependencies)}

[project.scripts]
cv-agent = "cv_agent.cli:{args.entry}"

[build-system]
requires = ["hatchling==1.32.4"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/cv_agent"]

[tool.hatch.build.targets.sdist]
include = ["/src", "/pyproject.toml", "/README.md", "/source-manifest.json"]
'''
    (stage / "pyproject.toml").write_text(manifest)
    (stage / "README.md").write_text("# CV-AGENT offline product snapshot\n\n"
        "Built from the recorded working source, including previously uncommitted fixes.\n"
        "This artifact contains no evaluation data, tests, research orchestration, provider transport or credentials.\n"
        "Shared dormant validator definitions remain in the import closure; product profiles do not run them.\n"
        "Python 3.13 on Linux is the acceptance platform; dependency setup is separate from offline use.\n"
        "No repository checkout or PYTHONPATH is needed after installation.\n")
    source_manifest = {"schema": "product-release-source-v1", "entry": args.entry,
                       "distribution_version": "0.1.0+recovery.20261001", "dependencies": dependencies,
                       "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=PROJECT, text=True).strip(),
                       "dirty_snapshot": True, "included": included, "excluded": excluded,
                       "tree_sha256": hashlib.sha256(json.dumps(included, sort_keys=True).encode()).hexdigest(),
                       "build_python": platform.python_version(), "network": "forbidden", "model_requests": 0}
    (stage / "source-manifest.json").write_text(json.dumps(source_manifest, indent=2) + "\n")
    command = ["uv", "build", "--offline", "--no-python-downloads", "--python", sys.executable,
               "--out-dir", str(destination / "dist"), str(stage)]
    completed = subprocess.run(command, cwd=destination, capture_output=True, text=True)
    (destination / "build.stdout.log").write_text(completed.stdout)
    (destination / "build.stderr.log").write_text(completed.stderr)
    receipt = {"source_manifest": "source/source-manifest.json", "source_manifest_sha256": sha(stage / "source-manifest.json"),
               "command": command, "return_code": completed.returncode,
               "artifacts": [{"path": path.relative_to(destination).as_posix(), "sha256": sha(path), "bytes": path.stat().st_size}
                             for path in sorted((destination / "dist").glob("*")) if path.is_file()]}
    (destination / "build-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))
    raise SystemExit(completed.returncode)


if __name__ == "__main__":
    main()
