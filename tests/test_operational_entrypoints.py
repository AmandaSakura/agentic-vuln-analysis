"""Operational commands run their owning modules, without Python trampolines."""
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
ENTRIES = json.loads((Path(__file__).parent/'fixtures/operational_entrypoints.json').read_text())


def test_all_forwarding_scripts_are_removed_and_original_guards_retained():
    assert len(ENTRIES) == 47
    for entry in ENTRIES:
        assert not (ROOT/'scripts'/entry['script']).exists(), entry['script']
        path = ROOT/'src'/Path(*entry['module'].split('.')).with_suffix('.py')
        tree = ast.parse(path.read_text())
        guard = next(node for node in tree.body if isinstance(node, ast.If)
                     and isinstance(node.test, ast.Compare)
                     and isinstance(node.test.left, ast.Name) and node.test.left.id == '__name__')
        original = entry['guard']
        relocations = json.loads((ROOT / 'tests/fixtures/config_relocation.json').read_text())
        for relocation in relocations:
            original = original.replace(relocation['old'], relocation['new'])
        assert ast.dump(guard) == ast.dump(ast.parse(original).body[0]), entry['module']


@pytest.mark.parametrize('name', ['gate', 'matrix'])
def test_heldout_shell_launches_module_with_the_original_environment(tmp_path, name):
    # Only the copied launcher's working directory changes. Never source real credentials.
    source = (ROOT/f'scripts/heldout_{name}.sh').read_text()
    script = tmp_path/f'heldout_{name}.sh'
    script.write_text(source.replace(str(ROOT), str(tmp_path)))
    (tmp_path/'.env.experiments').write_text('CV_AGENT_PROVIDER=offline\nDEEPSEEK_API_KEY=fake-offline\n')
    binary = tmp_path/'bin'
    binary.mkdir()
    uv = binary/'uv'
    uv.write_text(f'#!{sys.executable}\n' + '''import json, os, pathlib, sys
pathlib.Path(os.environ['CAPTURE']).write_text(json.dumps({
    'argv': sys.argv[1:], 'cwd': os.getcwd(),
    'provider': os.environ['CV_AGENT_PROVIDER'],
    'unbuffered': os.environ['PYTHONUNBUFFERED'],
    'key_was_exported': os.environ.get('DEEPSEEK_API_KEY') == 'fake-offline',
}))
''')
    uv.chmod(0o755)
    capture = tmp_path/'invocation.json'
    subprocess.run(['/bin/bash', str(script)], check=True, cwd=tmp_path,
                   env={'PATH': str(binary)+os.pathsep+'/usr/bin:/bin', 'CAPTURE': str(capture)})
    assert json.loads(capture.read_text()) == {
        'argv': ['run', '--no-sync', 'python', '-m',
                 f'cv_agent.evaluation.runners.run_python_heldout_pair_{name}'],
        'cwd': str(tmp_path), 'provider': 'offline', 'unbuffered': '1', 'key_was_exported': True,
    }


@pytest.mark.parametrize("name,digest", [
    ("jinja_attr_probe", "75ba30b445e8a98d2bf4739967a27707e525bdf1463bd614979ec53cbfada595"),
    ("langchain_template_probe", "344302dd3e7425bfd4256fe399674b5df21f258b1f6f8ecd9997bdeac9c8901e"),
])
def test_standalone_workers_preserve_bytes_and_start_in_isolation(tmp_path, name, digest):
    path = ROOT / "scripts" / "probes" / (name + ".py")
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
    result = subprocess.run(
        [sys.executable, "-I", str(path), "--help"], cwd=tmp_path,
        env={"PATH": os.environ["PATH"]}, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "--checkout" in result.stdout and "--scenario" in result.stdout


def test_scripts_root_contains_only_documented_shell_commands():
    assert {path.name for path in (ROOT / "scripts").iterdir()} == {
        "README.md", "probes", "heldout_gate.sh", "heldout_matrix.sh",
        "deepseek.sh", "fetch_benchmarks.sh",
    }
