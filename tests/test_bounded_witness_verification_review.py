"""Integration regressions for source obligations during real preexec execution."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from cv_agent.domain.evidence import ValidationStatus
from cv_agent.runtime.witness.kernel import (
    SourceFileBinding,
    run_witness,
)
from test_bounded_execution_witness import NONCE, _manifest


@pytest.mark.parametrize("declared", [False, True])
def test_preexec_lazy_import_must_remain_source_bound(tmp_path: Path, declared: bool) -> None:
    helper = tmp_path / "latehelper.py"
    helper.write_text("def configure():\n    return None\n")
    manifest = _manifest(tmp_path, """
        import subprocess
        def preexec():
            import latehelper
            latehelper.configure()
        class Service:
            def serve(self, model_uri):
                subprocess.Popen(["bash", "-c", f"record {model_uri}"], preexec_fn=preexec)
    """)
    if declared:
        manifest = manifest.model_copy(update={"source_modules": (*manifest.source_modules,
            SourceFileBinding(module_name="latehelper", relative_path="latehelper.py",
                              sha256=hashlib.sha256(helper.read_bytes()).hexdigest()),
        )})
    result = run_witness(manifest, nonce=NONCE, verify_obligations=True)
    if declared:
        assert result.status == ValidationStatus.CONFIRMED, result.model_dump()
        assert result.raw_status == "EXPANDED_OBSERVED"
        assert result.details["control_replay"]["ok"] is True
    else:
        assert result.status == ValidationStatus.UNRESOLVED, result.model_dump()
        assert any("undeclared_imported_source:latehelper" in gap for gap in result.gaps)
