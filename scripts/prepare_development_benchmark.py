"""Freeze and validate the development matrix without calling a model."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from cv_agent.agentic_live import load_owasp_agentic_inputs
from cv_agent.benchmark_evaluation import select_cases
from cv_agent.datasets import load_owasp_expected_results
from cv_agent.provenance import build_run_identity


def main():
    config = json.loads((ROOT / 'configs/development_benchmark.json').read_text())
    benchmark = ROOT / 'data/raw/BenchmarkJava'
    labels = load_owasp_expected_results(benchmark / 'expectedresults-1.2beta.csv')
    selected = select_cases(labels, config['per_category_per_label'])
    inputs = load_owasp_agentic_inputs(ROOT / 'data/raw', case_ids=selected)
    pilot = [next(case for case in selected if labels[case].category == config['pilot_category']
                  and labels[case].vulnerable == vulnerable) for vulnerable in (False, True)]
    output = ROOT / 'configs/development_manifest.json'
    if output.exists():
        raise FileExistsError('Manifest already frozen; do not replace after examining outcomes')
    output.write_text(json.dumps({
        'dataset_role': 'development', 'claim_eligible': False,
        'selection': 'SHA256 rank within category x label, seed cv-agent-development-20260919',
        'population_count': len(labels), 'case_ids': selected, 'pilot_case_ids': pilot,
        'systems': config['systems'], 'parse_error_paths': inputs.parse_error_paths,
        'labels': {case: labels[case].model_dump(mode='json') for case in selected},
        'candidates': [candidate.model_dump(mode='json') for candidate in inputs.candidates],
        'identity': build_run_identity(ROOT, {'BenchmarkJava': benchmark}),
    }, indent=2) + '\n')
    print(f'Frozen {len(selected)} cases, {len(selected)*len(config["systems"])} trials; pilot: {pilot}')
    print(f'Parse errors: {len(inputs.parse_error_paths)}; manifest: {output}')


if __name__ == '__main__':
    main()
