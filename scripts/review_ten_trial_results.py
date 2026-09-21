"""Offline correction of the preserved ten-trial concurrency accounting."""
import json
from datetime import datetime
from run_micro_benchmark import project_root
from cv_agent.benchmark_evaluation import provider_usage


def run():
    config = json.loads((project_root / 'configs/ten_trial_offline_review.json').read_text())
    directory = project_root / config['run_directory']
    events = [json.loads(line) for line in (directory / 'events.jsonl').read_text().splitlines()]
    active = peak = 0
    for event in events:
        if event['event'] == 'model_start':
            active += 1
            peak = max(peak, active)
        elif event['event'] in {'model_reply', 'model_error'}:
            active -= 1
    result = dict(usage=provider_usage(events), peak_concurrency=peak,
                  active_requests_at_end=active,
                  elapsed_seconds=(datetime.fromisoformat(events[-1]['time']) -
                                   datetime.fromisoformat(events[0]['time'])).total_seconds(),
                  passed=False, full_expansion=False,
                  note='Offline accounting repair; original summaries and source snapshots preserved. No additional API calls.')
    (directory / 'offline_review.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    run()
