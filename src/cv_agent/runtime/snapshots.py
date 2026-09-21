"""Preserve the source bytes used by an experiment."""
import hashlib

from cv_agent.runtime.admission import fingerprint_files


def snapshot_sources(root, run_dir):
    sources = fingerprint_files(root)
    source_hashes = {}
    for source in sources:
        relative = source.relative_to(root)
        content = source.read_bytes()
        snapshot = run_dir/'source'/relative
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes(content)
        source_hashes[str(relative)] = hashlib.sha256(content).hexdigest()
    return source_hashes
