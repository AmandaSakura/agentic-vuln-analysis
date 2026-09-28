"""Actual monitoring controls for source-bound candidate branch obligations."""

from __future__ import annotations

import hashlib
import sys
import textwrap
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

from cv_agent.evaluation.diagnostics.witness_branches import BranchAssumptionObserver


def _module(root: Path, source: str, conditions: dict[str, bool], *, name: str = "sample"):
    text = textwrap.dedent(source).lstrip()
    path = root / f"{name}.py"
    path.write_text(text)
    binding = SimpleNamespace(module_name=name, relative_path=path.name,
                              sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    manifest = SimpleNamespace(checkout_root=root, source_modules=(binding,),
                               subject=SimpleNamespace(entry_condition_assumptions=conditions))
    module = ModuleType(name)
    module.__file__ = str(path)
    exec(compile(text, str(path), "exec", dont_inherit=True), module.__dict__)
    return manifest, module


def _observe(manifest, entry, *args):
    observer = BranchAssumptionObserver(manifest)
    try:
        observer.install(entry.__code__)
        value = entry(*args)
        return value, observer.report()
    finally:
        observer.close()


@pytest.mark.parametrize("flag", [False, True])
def test_real_branch_edges_observe_both_directions(tmp_path: Path, flag: bool) -> None:
    manifest, module = _module(tmp_path, """
        def serve(flag):
            if flag:
                return "yes"
            else:
                return "no"
    """, {"flag": flag})
    value, report = _observe(manifest, module.serve, flag)
    assert value == ("yes" if flag else "no")
    assert report["gaps"] == []
    assert report["observations"][0]["actual_values"] == [flag]
    assert report["observations"][0]["sha256"] == manifest.source_modules[0].sha256
    assert sys.monitoring.get_tool(4) is None


def test_negation_and_literal_quote_normalization_preserve_declared_fact(tmp_path: Path) -> None:
    manifest, module = _module(tmp_path, """
        import sys
        def serve():
            if not sys.platform.startswith("linux"):
                return "other"
            return "linux"
    """, {"sys.platform.startswith('linux')": True})
    value, report = _observe(manifest, module.serve)
    assert value == "linux"
    assert report["gaps"] == []
    assert report["observations"][0]["actual_values"] == [True]
    assert report["observations"][0]["inverted"] is True


def test_every_executed_occurrence_must_agree(tmp_path: Path) -> None:
    manifest, module = _module(tmp_path, """
        def helper(flag):
            if flag:
                return 1
            return 0
        def serve():
            helper(True)
            helper(False)
            if True:
                return 2
    """, {"flag": True})
    _, report = _observe(manifest, module.serve)
    assert "entry_condition_assumption_mismatch:flag" in report["gaps"]
    assert report["observations"][0]["actual_values"] == [False, True]
    assert report["observations"][0]["execution_count"] == 2


def test_unexecuted_definition_cannot_supply_condition(tmp_path: Path) -> None:
    manifest, module = _module(tmp_path, """
        def helper(flag):
            if flag:
                return 1
            return 0
        def serve():
            return 5
    """, {"flag": True})
    _, report = _observe(manifest, module.serve)
    assert "entry_condition_assumption_unverified:flag" in report["gaps"]
    assert report["observations"] == []


def test_conditions_are_never_re_evaluated(tmp_path: Path) -> None:
    manifest, module = _module(tmp_path, """
        counter = 0
        def condition():
            global counter
            counter += 1
            return True
        def serve():
            if condition():
                return 1
            return 0
    """, {"condition()": True})
    _, report = _observe(manifest, module.serve)
    assert module.counter == 1
    assert report["gaps"] == []


def test_occupied_tool_id_is_gap_and_owner_is_preserved(tmp_path: Path) -> None:
    manifest, module = _module(tmp_path, """
        def serve(flag):
            if flag:
                return 1
            return 0
    """, {"flag": True})
    sys.monitoring.use_tool_id(4, "existing-owner")
    try:
        _, report = _observe(manifest, module.serve, True)
        assert "condition_monitor_tool_id_occupied:4" in report["gaps"]
        assert "entry_condition_assumption_unverified:flag" in report["gaps"]
        assert sys.monitoring.get_tool(4) == "existing-owner"
    finally:
        sys.monitoring.free_tool_id(4)


def test_ast_match_does_not_accept_expression_substring(tmp_path: Path) -> None:
    manifest, module = _module(tmp_path, """
        def serve(flag):
            if flag and True:
                return 1
            return 0
    """, {"flag": True})
    _, report = _observe(manifest, module.serve, True)
    assert "condition_ast_not_found:flag" in report["gaps"]
    assert "entry_condition_assumption_unverified:flag" in report["gaps"]


def test_stale_file_binding_never_produces_observation(tmp_path: Path) -> None:
    manifest, module = _module(tmp_path, """
        def serve(flag):
            if flag:
                return 1
            return 0
    """, {"flag": True})
    (tmp_path / "sample.py").write_text("# changed after manifest\n")
    _, report = _observe(manifest, module.serve, True)
    assert "condition_source_mismatch:sample" in report["gaps"]
    assert report["observations"] == []


def test_runtime_code_with_matching_filename_but_other_contents_is_gap(tmp_path: Path) -> None:
    manifest, module = _module(tmp_path, """
        def serve(flag):
            if flag:
                return 1
            return 0
    """, {"flag": True})
    exec(compile("def serve(flag):\n    if flag:\n        return 999\n    return 0\n",
                 str(tmp_path / "sample.py"), "exec"), module.__dict__)
    _, report = _observe(manifest, module.serve, True)
    assert "condition_entry_code_mismatch" in report["gaps"]
    assert report["observations"] == []


def test_prior_and_other_thread_calls_do_not_supply_candidate_evidence(tmp_path: Path) -> None:
    manifest, module = _module(tmp_path, """
        import threading
        def helper(flag):
            if flag:
                return 1
            return 0
        def serve():
            thread = threading.Thread(target=helper, args=(True,))
            thread.start()
            thread.join()
    """, {"flag": True})
    observer = BranchAssumptionObserver(manifest)
    try:
        observer.install(module.serve.__code__)
        module.helper(True)
        module.serve()
        report = observer.report()
    finally:
        observer.close()
    assert "entry_condition_assumption_unverified:flag" in report["gaps"]
    assert report["observations"] == []


def test_lazy_source_bound_helper_gets_local_monitoring(tmp_path: Path) -> None:
    manifest, module = _module(tmp_path, """
        loader = None
        def serve():
            helper = loader()
            return helper(True)
    """, {"flag": True})
    helper_source = "def helper(flag):\n    if flag:\n        return 1\n    return 0\n"
    helper_path = tmp_path / "late.py"
    helper_path.write_text(helper_source)
    manifest.source_modules += (SimpleNamespace(
        module_name="late", relative_path="late.py",
        sha256=hashlib.sha256(helper_path.read_bytes()).hexdigest()),)

    def load():
        namespace = {}
        exec(compile(helper_source, str(helper_path), "exec", dont_inherit=True), namespace)
        return namespace["helper"]

    module.loader = load
    value, report = _observe(manifest, module.serve)
    assert value == 1
    assert report["gaps"] == []
    assert report["observations"][0]["module"] == "late"


@pytest.mark.parametrize("flag", [False, True])
def test_conditional_expression_records_actual_arm(tmp_path: Path, flag: bool) -> None:
    manifest, module = _module(tmp_path, """
        def serve(flag):
            return "yes" if flag else "no"
    """, {"flag": flag})
    value, report = _observe(manifest, module.serve, flag)
    assert value == ("yes" if flag else "no")
    assert report["gaps"] == []
    assert report["observations"][0]["actual_values"] == [flag]


@pytest.mark.parametrize("left,right", [(False, True), (True, False), (True, True)])
def test_complete_compound_condition_uses_exiting_edge(tmp_path: Path, left: bool, right: bool) -> None:
    manifest, module = _module(tmp_path, """
        def serve(left, right):
            if left and right:
                return "yes"
            return "no"
    """, {"left and right": left and right})
    _, report = _observe(manifest, module.serve, left, right)
    assert report["gaps"] == []
    assert report["observations"][0]["actual_values"] == [left and right]
    assert report["observations"][0]["execution_count"] == 1


def test_missing_monitoring_is_explicit_gap(tmp_path: Path, monkeypatch) -> None:
    manifest, module = _module(tmp_path, """
        def serve(flag):
            if flag:
                return 1
            return 0
    """, {"flag": True})
    monkeypatch.setattr(sys, "monitoring", None)
    _, report = _observe(manifest, module.serve, True)
    assert "condition_monitor_unavailable" in report["gaps"]
    assert "entry_condition_assumption_unverified:flag" in report["gaps"]


def test_constant_folded_test_remains_unverified(tmp_path: Path) -> None:
    manifest, module = _module(tmp_path, """
        def serve():
            if True:
                return 1
            return 0
    """, {"True": True})
    _, report = _observe(manifest, module.serve)
    assert "condition_bytecode_unsupported:True" in report["gaps"]
    assert "entry_condition_assumption_unverified:True" in report["gaps"]


@pytest.mark.parametrize("tamper", ["global", "local"])
def test_monitor_masks_cannot_be_disabled_after_valid_observations(tmp_path: Path, tamper: str) -> None:
    manifest, module = _module(tmp_path, """
        def serve(flag):
            if flag:
                return 1
            return 0
    """, {"flag": True})
    observer = BranchAssumptionObserver(manifest)
    try:
        observer.install(module.serve.__code__)
        module.serve(True)
        assert observer.report()["gaps"] == []
        if tamper == "global":
            sys.monitoring.set_events(4, 0)
            expected = "condition_monitor_global_events_changed"
        else:
            sys.monitoring.set_local_events(4, module.serve.__code__, 0)
            expected = "condition_monitor_local_events_changed:serve"
        report = observer.report()
        assert expected in report["gaps"]
        assert report["observations"][0]["actual_values"] == [True]
    finally:
        observer.close()


def test_callback_audit_mutation_keeps_gap_even_after_observation(tmp_path: Path) -> None:
    manifest, module = _module(tmp_path, """
        def serve(flag):
            if flag:
                return 1
            return 0
    """, {"flag": True})
    observer = BranchAssumptionObserver(manifest)
    try:
        observer.install(module.serve.__code__)
        module.serve(True)
        observer.audit_event("sys.monitoring.register_callback", (lambda: None,))
        assert "condition_monitor_callback_changed" in observer.report()["gaps"]
    finally:
        observer.close()


def test_failed_condition_occurrence_cannot_borrow_another_occurrence_result(tmp_path: Path) -> None:
    manifest, module = _module(tmp_path, """
        calls = 0
        def condition():
            global calls
            calls += 1
            if calls == 2:
                raise RuntimeError("no result")
            return True
        def serve():
            if condition():
                first = 1
            try:
                if condition():
                    second = 2
            except RuntimeError:
                return first
    """, {"condition()": True})
    _, report = _observe(manifest, module.serve)
    assert module.calls == 2
    assert any(gap.startswith("condition_occurrence_unverified:condition():sample:")
               for gap in report["gaps"])
    assert len(report["observations"]) == 1


def test_entry_callback_receives_exact_frame_and_monitor_cleans_after_raise(tmp_path: Path) -> None:
    manifest, module = _module(tmp_path, """
        def serve(flag):
            if flag:
                raise RuntimeError("target raised")
            return 0
    """, {"flag": True})
    frames = []
    observer = BranchAssumptionObserver(manifest)
    try:
        observer.install(module.serve.__code__, on_entry=lambda frame: frames.append(frame))
        with pytest.raises(RuntimeError, match="target raised"):
            module.serve(True)
        assert frames[0].f_code is module.serve.__code__
        assert frames[0].f_locals["flag"] is True
        assert observer.report()["gaps"] == []
        assert observer._candidate_frame is None
    finally:
        observer.close()
    assert sys.monitoring.get_tool(4) is None


def test_temporary_monitor_disabling_cannot_be_hidden_by_restoration(tmp_path: Path) -> None:
    manifest, module = _module(tmp_path, """
        def serve(flag):
            if flag:
                return 1
            return 0
    """, {"flag": True})
    observer = BranchAssumptionObserver(manifest)
    try:
        observer.install(module.serve.__code__)
        module.serve(True)
        mask = sys.monitoring.get_events(4)
        sys.monitoring.set_events.__call__(4, 0)
        module.serve(False)
        sys.monitoring.set_events(4, mask)
        report = observer.report()
        assert "condition_monitor_configuration_call" in report["gaps"]
        assert report["observations"][0]["actual_values"] == [True]
    finally:
        observer.close()


def test_optimizer_elided_arm_cannot_be_misread_as_false(tmp_path: Path) -> None:
    manifest, module = _module(tmp_path, """
        def serve(flag):
            if flag:
                pass
            return 0
    """, {"flag": False})
    _, report = _observe(manifest, module.serve, True)
    # Either a preserved NOP gives an actual mismatch, or the optimized layout
    # is unsupported. A collapsed arm never verifies the declared false value.
    assert report["gaps"]
    assert ("entry_condition_assumption_mismatch:flag" in report["gaps"]
            or "condition_bytecode_unsupported:flag" in report["gaps"])


def test_runtime_code_constants_cannot_execute_target_equality(tmp_path: Path) -> None:
    manifest, module = _module(tmp_path, """
        def serve(flag):
            if flag:
                return "yes"
            return "no"
    """, {"flag": True})
    equality_calls = []

    class HostileConstant:
        def __eq__(self, other):
            equality_calls.append(other)
            return True

        def __hash__(self):
            return hash("yes")

    code = module.serve.__code__
    module.serve.__code__ = code.replace(co_consts=tuple(
        HostileConstant() if value == "yes" else value for value in code.co_consts
    ))
    observer = BranchAssumptionObserver(manifest)
    try:
        observer.install(module.serve.__code__)
        report = observer.report()
        assert equality_calls == []
        assert "condition_entry_code_mismatch" in report["gaps"]
        assert report["observations"] == []
    finally:
        observer.close()


def test_runtime_helper_code_constants_cannot_execute_target_hash(tmp_path: Path) -> None:
    manifest, module = _module(tmp_path, """
        def helper(flag):
            if flag:
                return "yes"
            return "no"
        def serve(flag):
            return helper(flag)
    """, {"flag": True})
    protocol_calls = []

    class HostileConstant:
        def __eq__(self, other):
            protocol_calls.append("equality")
            return True

        def __hash__(self):
            protocol_calls.append("hash")
            return hash("yes")

    code = module.helper.__code__
    module.helper.__code__ = code.replace(co_consts=tuple(
        HostileConstant() if value == "yes" else value for value in code.co_consts
    ))
    _, report = _observe(manifest, module.serve, True)
    assert protocol_calls == []
    assert "condition_runtime_code_mismatch:helper" in report["gaps"]
    assert report["observations"] == []
