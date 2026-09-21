"""Current documentation is small; archived evidence remains intact and reachable."""
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT/'docs'
LINKS = re.compile(r'\]\(([^)]+)\)')


def local_links(path):
    for target in LINKS.findall(path.read_text()):
        if '://' not in target and not target.startswith('#'):
            yield (path.parent/unquote(target.split('#', 1)[0])).resolve()


def test_documentation_root_has_only_current_guides():
    assert {p.name for p in DOCS.glob('*.md')} == {
        'README.md', 'ARCHITECTURE.md', 'CURRENT_STATUS.md', 'EXPERIMENTS.md', 'TEST_CONTRACT.md',
    }
    assert {p.name for p in DOCS.iterdir() if p.is_dir()} == {'reference', 'history'}
    assert (DOCS/'reference/HARNESS.md').is_file()
    assert (DOCS/'reference/FULL_SYSTEM_SPEC.md').is_file()


def test_all_local_documentation_links_resolve_and_documents_are_reachable():
    files = [ROOT/'README.md', *DOCS.rglob('*.md')]
    missing = [(str(path.relative_to(ROOT)), str(target))
               for path in files for target in local_links(path) if not target.exists()]
    assert missing == []
    seen = set()
    pending = [DOCS/'README.md']
    while pending:
        path = pending.pop().resolve()
        if path in seen:
            continue
        seen.add(path)
        pending.extend(target for target in local_links(path)
                       if target.suffix == '.md' and target.is_relative_to(DOCS))
    assert {path.resolve() for path in DOCS.rglob('*.md')} <= seen


def test_archived_document_content_is_preserved_except_relocated_local_links():
    manifest = json.loads((ROOT/'tests/fixtures/document_archive.json').read_text())
    assert len(manifest) == 54
    for entry in manifest:
        path = ROOT/entry['path']
        assert path.is_file(), entry['original_path']
        if path.suffix == '.md':
            text = LINKS.sub(lambda m: m.group(0) if '://' in m[1] or m[1].startswith('#')
                             else '](LOCAL_LINK)', path.read_text())
            content = text.encode()
        else:
            content = path.read_bytes()
        assert hashlib.sha256(content).hexdigest() == entry['content_sha256'], path
        assert not (ROOT/entry['original_path']).exists()
