from cv_agent.scanner import StaticScanner
from cv_agent.types import CodeDocument


def test_static_scanner_emits_stable_candidates():
    document = CodeDocument(
        repository_id="repo",
        path="runner.py",
        text="def run(cmd):\n    return subprocess.run(cmd, shell=True)\n",
    )
    candidates = StaticScanner().scan("repo", [document])
    assert [candidate.line for candidate in candidates] == [2]
    assert {candidate.metadata["rule"] for candidate in candidates} == {"command-execution"}
