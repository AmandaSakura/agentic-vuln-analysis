"""Repackage verified installed wheel contents for a local offline wheelhouse.

The uv cache's grammar index metadata references a different platform. This
script does not download or rebuild dependencies. It verifies each installed
RECORD file, keeps metadata/platform tags, and explicitly records local repack
identity rather than presenting it as an original upstream wheel hash.
"""
from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import importlib.metadata
import io
import json
from pathlib import Path
import re
import zipfile


NAMES = ("pydantic", "pydantic-core", "annotated-types", "typing-extensions", "typing-inspection",
         "tree-sitter", "tree-sitter-go", "tree-sitter-java", "tree-sitter-javascript", "tree-sitter-typescript")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    root = args.destination.resolve()
    root.mkdir(parents=True, exist_ok=False)
    distributions = []
    requirements = []
    for name in NAMES:
        distribution = importlib.metadata.distribution(name)
        version = distribution.version
        wheel_text = distribution.read_text("WHEEL")
        tags = [line.removeprefix("Tag: ") for line in wheel_text.splitlines() if line.startswith("Tag: ")]
        assert tags
        rows = list(csv.reader(io.StringIO(distribution.read_text("RECORD"))))
        files = []
        dist_info = None
        for relative, recorded_hash, recorded_size in rows:
            if ".." in Path(relative).parts or Path(relative).is_absolute():
                raise ValueError(f"Not a self-contained dependency wheel: {name} {relative}")
            if relative.endswith(".dist-info/RECORD"):
                dist_info = relative.rsplit("/", 1)[0]
                continue
            if relative.endswith(".pyc") or relative.endswith(".dist-info/INSTALLER") or relative.endswith(".dist-info/REQUESTED"):
                continue
            path = Path(distribution.locate_file(relative))
            data = path.read_bytes()
            if recorded_hash:
                algorithm, expected = recorded_hash.split("=", 1)
                assert algorithm == "sha256", (name, relative, algorithm)
                actual = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
                assert actual == expected, (name, relative, "installed RECORD hash mismatch")
            else:
                raise ValueError(f"Dependency file lacks recorded hash: {name} {relative}")
            assert len(data) == int(recorded_size), (name, relative, "installed RECORD size mismatch")
            files.append((relative, data, recorded_hash, recorded_size))
        assert dist_info is not None
        filename = re.sub(r"[-_.]+", "_", name) + "-" + version + "-" + tags[0] + ".whl"
        destination = root / filename
        record_stream = io.StringIO(newline="")
        writer = csv.writer(record_stream, lineterminator="\n")
        for relative, data, recorded_hash, recorded_size in sorted(files):
            writer.writerow((relative, recorded_hash, recorded_size))
        writer.writerow((dist_info + "/RECORD", "", ""))
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as wheel:
            for relative, data, _, _ in sorted(files):
                info = zipfile.ZipInfo(relative, (2026, 10, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o644 << 16
                wheel.writestr(info, data)
            info = zipfile.ZipInfo(dist_info + "/RECORD", (2026, 10, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            wheel.writestr(info, record_stream.getvalue().encode())
        digest = hashlib.sha256(destination.read_bytes()).hexdigest()
        distributions.append({"name": name, "version": version, "filename": filename, "sha256": digest,
                              "bytes": destination.stat().st_size, "platform_tags": tags,
                              "origin": "locally-repacked-unchanged-installed-wheel-contents",
                              "upstream_wheel_sha256": None, "verified_record_files": len(files),
                              "contents": [{"path": relative, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
                                           for relative, data, _, _ in sorted(files)]})
        requirements.append(f"{name}=={version} --hash=sha256:{digest}")
    manifest = {"schema": "local-dependency-wheelhouse-v1", "network": "not used", "dependency_upgrades": False,
                "original_wheels_available": False, "contents_match_installed_RECORD": True,
                "distributions": distributions}
    (root / "dependency-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (root / "requirements.lock").write_text("\n".join(requirements) + "\n")
    print(f"Sealed {len(distributions)} locally repacked dependency wheels with verified original RECORD contents.")


if __name__ == "__main__":
    main()
