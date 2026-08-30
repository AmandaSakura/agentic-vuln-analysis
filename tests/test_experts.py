from cv_agent.experts import AuthorizationExpert, ScanExpert, TaintExpert
from cv_agent.types import Candidate, Evidence


def _candidate() -> Candidate:
    return Candidate(
        candidate_id="case",
        case_id="case",
        repository_id="repo",
        path="handler.py",
        line=1,
        query="handler",
    )


def _evidence(text: str, evidence_id: str = "graph:handler.py") -> Evidence:
    return Evidence(
        evidence_id=evidence_id,
        path=evidence_id.removeprefix("graph:"),
        text=text,
        retrieval="graph",
        score=1.0,
    )


def test_scanner_abstains_when_limited_rules_find_no_sink():
    vote = ScanExpert().evaluate(_candidate(), [_evidence("return value")])
    assert vote.label == "ABSTAIN"


def test_taint_requires_ordered_same_function_evidence():
    vote = TaintExpert().evaluate(
        _candidate(),
        [
            _evidence(
                "value = request.args['cmd']\nsubprocess.run(value, shell=True)\nsanitize(other)",
            )
        ],
    )
    assert vote.label == "VULNERABLE"


def test_taint_accepts_only_an_intervening_sanitizer_as_safe_evidence():
    vote = TaintExpert().evaluate(
        _candidate(),
        [
            _evidence(
                "value = request.args['cmd']\nvalue = sanitize(value)\nsubprocess.run(value, shell=True)",
            )
        ],
    )
    assert vote.label == "SAFE"


def test_authorization_guard_must_precede_operation_in_same_function():
    guarded = AuthorizationExpert().evaluate(
        _candidate(),
        [_evidence("require_permission(actor)\ndatabase.delete(user_id)")],
    )
    unguarded = AuthorizationExpert().evaluate(
        _candidate(),
        [
            _evidence("database.delete(user_id)"),
            _evidence("require_permission(actor)", "graph:unrelated.py"),
        ],
    )
    assert guarded.label == "SAFE"
    assert unguarded.label == "VULNERABLE"
