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
@pytest.mark.parametrize('working_directory', ['project', 'elsewhere'])
def test_heldout_shell_launches_module_with_the_original_environment(tmp_path, name, working_directory):
    # Execute unchanged script bytes; relocation must not require source rewriting.
    source = (ROOT/f'scripts/heldout_{name}.sh').read_text()
    project = tmp_path/'project with spaces'
    (project/'scripts').mkdir(parents=True)
    script = project/f'scripts/heldout_{name}.sh'
    script.write_text(source)
    (project/'.env.experiments').write_text('CV_AGENT_PROVIDER=offline\nDEEPSEEK_API_KEY=fake-offline\n')
    elsewhere = tmp_path/'elsewhere'
    elsewhere.mkdir()
    # Even a broken launcher must not source this machine's real credentials.
    bash_env = tmp_path/'offline-source-guard.sh'
    bash_env.write_text('''source() {
    if [[ "$PWD/$1" != "$TEST_PROJECT/.env.experiments" ]]; then
        echo 'Refusing to source credentials outside the test project' >&2
        return 1
    fi
    builtin source "$@"
}
''')
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
    subprocess.run(['/bin/bash', str(script)], check=True,
                   cwd=project if working_directory == 'project' else elsewhere,
                   env={'PATH': str(binary)+os.pathsep+'/usr/bin:/bin', 'CAPTURE': str(capture),
                        'BASH_ENV': str(bash_env), 'TEST_PROJECT': str(project)})
    assert json.loads(capture.read_text()) == {
        'argv': ['run', '--no-sync', 'python', '-m',
                 f'cv_agent.evaluation.runners.run_python_heldout_pair_{name}'],
        'cwd': str(project), 'provider': 'offline', 'unbuffered': '1', 'key_was_exported': True,
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
