"""The package's supported import paths are its actual implementation packages."""
import ast
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RETIRED = frozenset(json.loads((Path(__file__).parent/'fixtures/retired_modules.json').read_text()))


def test_source_tests_and_launchers_import_canonical_modules():
    violations = []
    for folder in ('src', 'tests', 'scripts'):
        for path in (ROOT/folder).rglob('*.py'):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                targets = set()
                if isinstance(node, ast.ImportFrom):
                    target = node.module or ''
                    if node.level:
                        parts = path.relative_to(ROOT/folder).with_suffix('').parts
                        package = '.'.join(parts[:-1])
                        target = importlib.util.resolve_name('.'*node.level + target, package)
                    targets = {target, *(target+'.'+item.name for item in node.names)}
                elif isinstance(node, ast.Import):
                    targets = {item.name for item in node.names}
                for target in targets & RETIRED:
                    violations.append((str(path.relative_to(ROOT)), node.lineno, target))
    assert violations == []


def test_package_root_has_only_public_api_and_cli():
    package = ROOT/'src/cv_agent'
    assert {path.name for path in package.glob('*.py')} == {'__init__.py', 'cli.py'}
    assert not (package/'experts').exists()
    assert not (package/'validation_tools').exists()


def test_no_forwarding_implementations_remain():
    facades = [str(path.relative_to(ROOT)) for path in (ROOT/'src/cv_agent').rglob('*.py')
               if (ast.get_docstring(ast.parse(path.read_text())) or '').startswith('Compatibility export')]
    assert facades == []


def test_retired_python_modules_are_not_importable():
    import importlib
    import pytest

    for module in sorted(RETIRED):
        with pytest.raises(ModuleNotFoundError) as caught:
            importlib.import_module(module)
        assert caught.value.name in RETIRED
