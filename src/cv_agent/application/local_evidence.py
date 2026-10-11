"""Complete local observation records, separate from a model delivery budget.

Verification checks consistency and integrity of a user-owned, self-generated
package. A producer name and a self-reported hash do not authenticate external
tool authority or prove that an arbitrary imported record was really executed.
The caller must retain the complete descriptor inventory; losing that inventory
cannot be detected by hashing only the records that remain.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from collections.abc import Iterable

from cv_agent.domain.evidence import ToolObservation, ValidationSubject
from cv_agent.presentation.commit import fsync_directory


RECORD_VERSION = "local-evidence-record-v1"
DEFAULT_MAX_BYTES = 64 * 1024 * 1024


class LocalEvidenceError(ValueError):
    """A complete material record could not be verified; do not reduce a subset."""


class LocalEvidenceBudgetError(LocalEvidenceError):
    """The declared local record byte budget cannot admit this complete record."""


def _bytes(value) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _copy(value):
    return json.loads(_bytes(value))


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise LocalEvidenceError("Evidence JSON contains an ambiguous duplicate field")
        result[key] = value
    return result


def _semantic_observation(observation: ToolObservation):
    value = observation.model_dump(mode="json")
    value["citation_id"] = None
    value["evidence_ids"] = sorted(set(value["evidence_ids"]))
    return value


def _descriptor(path: Path, producer_id: str, observation: ToolObservation,
                context: dict, payload: bytes) -> dict:
    return {
        "version": RECORD_VERSION, "path": os.fspath(path),
        "producer_id": producer_id, "sha256": _digest(payload), "size_bytes": len(payload),
        "content_sha256": _digest(observation.content.encode("utf-8")),
        "context_sha256": _digest(_bytes(context)),
        "subject": observation.subject.model_dump(mode="json") if observation.subject else None,
        "observation": observation.model_dump(mode="json"), "context": _copy(context),
    }


def _record_path(descriptor: dict, directory: Path | None) -> Path:
    try:
        path = Path(descriptor["path"])
    except (KeyError, TypeError, ValueError) as error:
        raise LocalEvidenceError("Evidence descriptor has no valid record path") from error
    if directory is not None:
        root = directory.resolve(strict=True)
        path = path if path.is_absolute() else root / path
        # Records are flat, exporter-owned files. Reject escaping paths and
        # intermediate symlink navigation rather than following a source alias.
        if path.parent.resolve(strict=True) != root or path.name in {"", ".", ".."}:
            raise LocalEvidenceError("Evidence record path is outside the declared local store")
    elif not path.is_absolute():
        raise LocalEvidenceError("A relative evidence path requires its declared package directory")
    return path


def read_descriptor(descriptor: dict, *, directory: Path | None = None,
                    subject: ValidationSubject | None = None,
                    context: dict | None = None,
                    max_bytes: int = DEFAULT_MAX_BYTES) -> tuple[str, ToolObservation]:
    """Read actual complete bytes and check every expected binding before use."""
    expected_keys = {"version", "path", "producer_id", "sha256", "size_bytes", "content_sha256",
                     "context_sha256", "subject", "observation", "context"}
    if not isinstance(descriptor, dict) or set(descriptor) != expected_keys:
        raise LocalEvidenceError("Evidence descriptor fields do not match the record contract")
    if descriptor["version"] != RECORD_VERSION:
        raise LocalEvidenceError("Unknown local evidence record version")
    if not isinstance(descriptor["producer_id"], str) or not descriptor["producer_id"]:
        raise LocalEvidenceError("Evidence descriptor requires its original producer identity")
    size = descriptor["size_bytes"]
    if type(size) is not int or size < 1 or size > max_bytes:
        raise LocalEvidenceError("Evidence record exceeds its declared complete byte limit")
    try:
        path = _record_path(descriptor, directory)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size != size:
                raise LocalEvidenceError("Evidence record is not the declared complete regular file")
            payload = stream.read(size + 1)
        if len(payload) != size or _digest(payload) != descriptor["sha256"]:
            raise LocalEvidenceError("Evidence record bytes or hash do not match the descriptor")
        record = json.loads(payload, object_pairs_hook=_unique_object)
        if not isinstance(record, dict) or set(record) != {"version", "producer_id", "observation", "context"}:
            raise LocalEvidenceError("Evidence record fields are incomplete or unknown")
        if record["version"] != RECORD_VERSION or record["producer_id"] != descriptor["producer_id"]:
            raise LocalEvidenceError("Evidence record producer or version does not match")
        try:
            observation = ToolObservation.model_validate(record["observation"])
        except (ValueError, TypeError) as error:
            raise LocalEvidenceError("Evidence observation is not the exact original schema") from error
        # Unknown observation fields cannot acquire authority by being silently
        # ignored during schema parsing. Require its canonical original schema.
        if observation.model_dump(mode="json") != record["observation"]:
            raise LocalEvidenceError("Evidence observation is not the exact original schema")
        if record["observation"] != descriptor["observation"]:
            raise LocalEvidenceError("Evidence descriptor does not contain the original observation")
        actual_subject = observation.subject.model_dump(mode="json") if observation.subject else None
        if actual_subject != descriptor["subject"] or (subject is not None and observation.subject != subject):
            raise LocalEvidenceError("Evidence record subject does not match its exact expected subject")
        if _digest(observation.content.encode("utf-8")) != descriptor["content_sha256"]:
            raise LocalEvidenceError("Evidence observation content hash does not match")
        if not isinstance(record["context"], dict) or record["context"] != descriptor["context"]:
            raise LocalEvidenceError("Evidence record context does not match")
        if _digest(_bytes(record["context"])) != descriptor["context_sha256"]:
            raise LocalEvidenceError("Evidence record context hash does not match")
        if context is not None and record["context"] != context:
            raise LocalEvidenceError("Evidence record belongs to a different analysis context")
        return record["producer_id"], observation
    except LocalEvidenceError:
        raise
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise LocalEvidenceError("A required complete local evidence record could not be read or validated") from error


def complete_local_observations(subject: ValidationSubject, descriptors: Iterable[dict], *,
                                directory: Path | None = None,
                                expected_context: dict | None = None,
                                expected_producers: Iterable[str] | None = None,
                                max_bytes: int = DEFAULT_MAX_BYTES) -> tuple[tuple[str, ToolObservation], ...]:
    """Verify the entire material inventory, then select the candidate's records.

    A missing unrelated record also prevents declaring this inventory complete.
    Independent verified UNKNOWN facts do not erase a sufficient positive fact;
    a missing/unverifiable material record is a different completeness failure.
    """
    original = {}
    total = 0
    for descriptor in descriptors:
        producer, observation = read_descriptor(descriptor, directory=directory,
            context=expected_context, max_bytes=max_bytes)
        if producer in original:
            previous, previous_context = original[producer]
            if (_semantic_observation(previous) != _semantic_observation(observation)
                    or previous_context != descriptor["context"]):
                raise LocalEvidenceError("One producer identity cannot describe different local records")
        else:
            total += descriptor["size_bytes"]
            if total > max_bytes:
                raise LocalEvidenceBudgetError("Complete local evidence inventory exceeds the declared byte limit")
            original[producer] = (observation, descriptor["context"])
    if expected_producers is not None and set(expected_producers) != set(original):
        raise LocalEvidenceError("The complete material producer inventory has missing or unexpected records")
    return tuple((producer, observation) for producer, (observation, _) in sorted(original.items())
                 if observation.subject == subject)


class EvidenceStore:
    """A private flat record store for one local run's original invocations."""

    def __init__(self, directory: Path, max_bytes: int = DEFAULT_MAX_BYTES):
        if type(max_bytes) is not int or max_bytes < 1:
            raise ValueError("Local evidence byte limit must be a positive integer")
        directory = Path(directory)
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.getuid():
            raise LocalEvidenceError("Evidence store must be a private user-owned real directory")
        self.directory = directory.resolve(strict=True)
        self.max_bytes = max_bytes
        self._descriptors: dict[str, dict] = {}
        self._expected_producers: set[str] = set()
        self._invalid_producers: set[str] = set()
        self._used_bytes = 0
        for path in self.directory.iterdir():
            mode = path.lstat().st_mode
            if not stat.S_ISREG(mode):
                raise LocalEvidenceError("Existing evidence store contains a nonregular record")
            self._used_bytes += path.stat().st_size
        if self._used_bytes > max_bytes:
            raise LocalEvidenceBudgetError("Existing local evidence exceeds the declared byte limit")

    @property
    def descriptors(self) -> tuple[dict, ...]:
        return tuple(_copy(item) for _, item in sorted(self._descriptors.items()))

    @property
    def used_bytes(self) -> int:
        return self._used_bytes

    @property
    def expected_producers(self) -> tuple[str, ...]:
        return tuple(sorted(self._expected_producers))

    @property
    def incomplete_producers(self) -> tuple[str, ...]:
        return tuple(sorted((self._expected_producers - self._descriptors.keys()) | self._invalid_producers))

    def read_descriptor(self, descriptor: dict, *, subject: ValidationSubject | None = None,
                        context: dict | None = None) -> tuple[str, ToolObservation]:
        return read_descriptor(descriptor, directory=self.directory, subject=subject,
                               context=context, max_bytes=self.max_bytes)

    def observations(self, subject: ValidationSubject) -> tuple[tuple[str, ToolObservation], ...]:
        if self._invalid_producers:
            raise LocalEvidenceError("Material producer identity conflicts must be resolved before reduction")
        return complete_local_observations(subject, self.descriptors, directory=self.directory,
                                            expected_producers=self._expected_producers,
                                            max_bytes=self.max_bytes)

    def persist(self, producer_id: str, observation: ToolObservation, *, context: dict) -> dict:
        if not isinstance(producer_id, str) or not producer_id:
            raise LocalEvidenceError("An original invocation requires its producer identity")
        # A failed persistence attempt remains a material completeness gap.
        # It cannot disappear merely because no success descriptor was returned.
        self._expected_producers.add(producer_id)
        if not isinstance(context, dict):
            raise LocalEvidenceError("A local observation requires its declared analysis context")
        context = _copy(context)
        if producer_id in self._descriptors:
            previous = self._descriptors[producer_id]
            try:
                _, original = self.read_descriptor(previous, context=context)
                if _semantic_observation(original) != _semantic_observation(observation):
                    raise LocalEvidenceError("One producer identity cannot describe different observations")
            except LocalEvidenceError:
                self._invalid_producers.add(producer_id)
                raise
            return _copy(previous)
        payload = _bytes({"version": RECORD_VERSION, "producer_id": producer_id,
                          "observation": observation.model_dump(mode="json"), "context": context})
        if len(payload) + self._used_bytes > self.max_bytes:
            raise LocalEvidenceBudgetError("No byte budget for the complete original local record")
        path = self.directory / (_digest(producer_id.encode("utf-8")) + ".json")
        fd, name = tempfile.mkstemp(prefix=".pending-", dir=self.directory)
        temporary = Path(name)
        linked = False
        try:
            with os.fdopen(fd, "wb") as stream:
                os.fchmod(stream.fileno(), 0o600)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            # Linking publishes a fully written inode and refuses an existing
            # record path atomically. There is no replacing write/rename path.
            os.link(temporary, path, follow_symlinks=False)
            linked = True
            fsync_directory(self.directory)
            temporary.unlink()
            fsync_directory(self.directory)
            descriptor = _descriptor(path, producer_id, observation, context, payload)
            self.read_descriptor(descriptor, context=context)
        except BaseException:
            if linked:
                path.unlink(missing_ok=True)
            raise
        finally:
            temporary.unlink(missing_ok=True)
        self._descriptors[producer_id] = descriptor
        self._used_bytes += len(payload)
        return _copy(descriptor)
