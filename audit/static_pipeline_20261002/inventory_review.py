"""A declared partial run is retained as a diagnostic, never a readiness pass."""
import json
import os
import subprocess
import sys

from cv_agent.application.product_boundary import worker_environment


def review_inventory(source, output):
    completed = subprocess.run([sys.executable, '-m', 'cv_agent', 'review', str(source),
        '--output', str(output), '--profile', 'product_triage_v2'],
        capture_output=True, text=True, timeout=150, env=worker_environment())
    for suffix, content in [('stdout.json', completed.stdout), ('stderr.txt', completed.stderr)]:
        path = output.parent / (output.name + '-review.' + suffix)
        path.write_text(content)
        os.chmod(path, 0o600)
    result = json.loads(completed.stdout)
    assert (result['run_state'], completed.returncode) in {('COMPLETED', 0), ('PARTIAL', 2)}
    assert result == json.loads((output / 'result.json').read_text())
    assert result['accounting']['model_requests'] == result['accounting']['target_executions'] == 0
    counts = result['counts']
    assert counts['inventory_complete'] and counts['parse_errors'] == 0
    assert counts['analysis_failed'] == counts['analysis_not_started'] == 0
    if result['run_state'] == 'PARTIAL':
        assert counts['analysis_blocked'] > 0
    return output
