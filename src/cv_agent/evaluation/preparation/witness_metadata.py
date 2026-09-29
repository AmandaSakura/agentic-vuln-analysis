"""Install wheel distribution metadata without installing its importable code."""

from __future__ import annotations

from email.parser import BytesParser
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from zipfile import ZipFile


def canonical_name(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9]+(?:[-_.][A-Za-z0-9]+)*", name):
        raise ValueError("invalid distribution name")
    return re.sub(r"[-_.]+", "-", name).lower()


def source_contamination(site: Path, module_name: str) -> list[str]:
    root = module_name.split(".", 1)[0]
    return [str(path) for path in (site / root, site / (root + ".py"))
            if path.exists() or path.is_symlink()]


def install_metadata(wheel: Path, expected_sha256: str, distribution: str,
                     site: Path, module_name: str) -> dict:
    """Validate every metadata leaf before writing any destination file."""
    raw = wheel.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != expected_sha256:
        raise ValueError("target_wheel_hash_mismatch")
    distribution = canonical_name(distribution)
    contaminated = source_contamination(site, module_name)
    if contaminated:
        raise ValueError("target_source_in_site_packages:" + ",".join(contaminated))
    members = {}
    with ZipFile(wheel) as archive:
        roots = {PurePosixPath(info.filename).parts[0] for info in archive.infolist()
                 if PurePosixPath(info.filename).parts
                 and PurePosixPath(info.filename).parts[0].endswith(".dist-info")}
        if len(roots) != 1:
            raise ValueError("target_wheel_metadata_root_nonunique")
        root = next(iter(roots))
        for info in archive.infolist():
            path = PurePosixPath(info.filename)
            if not path.parts or path.parts[0] != root:
                continue
            if (path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts)
                    or "\\" in info.filename or str(path) != info.filename.rstrip("/")):
                raise ValueError("unsafe_wheel_metadata_path")
            if stat.S_ISLNK(info.external_attr >> 16):
                raise ValueError("wheel_metadata_symlink")
            if info.is_dir():
                continue
            if info.filename in members or info.file_size > 8_000_000:
                raise ValueError("wheel_metadata_leaf_invalid")
            members[info.filename] = archive.read(info)
        if sum(map(len, members.values())) > 20_000_000:
            raise ValueError("wheel_metadata_too_large")
    metadata = members.get(root + "/METADATA")
    if metadata is None or root + "/WHEEL" not in members:
        raise ValueError("wheel_metadata_incomplete")
    parsed = BytesParser().parsebytes(metadata)
    name, version = parsed.get("Name"), parsed.get("Version")
    if name is None or version is None or canonical_name(name) != distribution:
        raise ValueError("wheel_distribution_identity_mismatch")
    expected_root = distribution.replace("-", "_") + "-" + version.replace("-", "_") + ".dist-info"
    if root.lower() != expected_root.lower():
        raise ValueError("wheel_metadata_directory_identity_mismatch")
    if (site / root).exists() or (site / root).is_symlink():
        raise FileExistsError("target metadata destination already exists")
    if not site.is_dir() or site.is_symlink():
        raise ValueError("destination site-packages must be an existing regular directory")
    # Original wheel RECORD contains package-code paths which are deliberately
    # absent. The new RECORD describes only the metadata actually installed.
    members.pop(root + "/RECORD", None)
    copied = []
    for name, content in sorted(members.items()):
        path = site.joinpath(*PurePosixPath(name).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(content)
        copied.append({"path": name, "sha256": hashlib.sha256(content).hexdigest(),
                       "size_bytes": len(content)})
    record_name = root + "/RECORD"
    record = "".join(item["path"] + ",," + str(item["size_bytes"]) + "\n" for item in copied)
    record += record_name + ",,\n"
    (site / record_name).write_text(record)
    copied.append({"path": record_name, "sha256": hashlib.sha256(record.encode()).hexdigest(),
                   "size_bytes": len(record.encode())})
    if source_contamination(site, module_name):
        raise ValueError("target_source_in_site_packages")
    return {"installation_kind": "distribution_metadata_only", "distribution": distribution,
            "version": version, "wheel_sha256": digest, "site": str(site),
            "copied_metadata_files": copied, "target_source_present": False,
            "requires_dist": parsed.get_all("Requires-Dist", [])}


def main() -> None:
    config = json.loads(Path(sys.argv[1]).read_text())
    result = install_metadata(Path(config["wheel"]), config["sha256"], config["distribution"],
                              Path(config["site"]), config["module_name"])
    Path(config["result"]).write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
