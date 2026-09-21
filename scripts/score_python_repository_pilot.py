"""Score an explicit frozen result directory; no detector or model is run here."""
import argparse
import json
from pathlib import Path

from cv_agent.discovery_evaluation import score_discovery


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('run_dir', type=Path)
    parser.add_argument('references', type=Path)
    args = parser.parse_args()
    text = args.references.read_text()
    references = ([json.loads(line) for line in text.splitlines() if line.strip()]
                  if args.references.suffix == '.jsonl' else list(json.loads(text).values()))
    report = score_discovery(json.loads((args.run_dir / 'inventory.json').read_text()),
                             json.loads((args.run_dir / 'results.json').read_text()), references)
    destination = args.run_dir / 'reference_score.json'
    with destination.open('x') as stream:
        stream.write(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
