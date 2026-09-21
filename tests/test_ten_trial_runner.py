import importlib
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def runner(monkeypatch):
    return importlib.import_module('cv_agent.evaluation.runners.run_development_ten_trial')


def test_parallel_workers_cannot_exceed_global_request_budget(monkeypatch, tmp_path):
    mod = runner(monkeypatch)
    from cv_agent.evaluation.runners.run_micro_benchmark import Trial
    from cv_agent.evaluation.runners.run_development_benchmark import BudgetExceeded
    journal = mod.LockedJournal(tmp_path / 'events.jsonl')
    budget = mod.LockedBudget(7, 30)
    def attempt(i):
        try:
            budget.observer(Trial(str(i), 'E1', journal), 'scan')({'event': 'model_start'})
            return True
        except BudgetExceeded:
            return False
    with ThreadPoolExecutor(max_workers=2) as executor:
        admitted = list(executor.map(attempt, range(30)))
    assert sum(admitted) == budget.used == 7
    assert len(journal.path.read_text().splitlines()) == 7


def test_declared_matrix_cannot_duplicate_trials_or_expand_concurrency(monkeypatch):
    import json
    import pytest
    mod = runner(monkeypatch)
    config = json.loads((Path(__file__).parents[1] / 'configs/experiments/development_ten_trial.json').read_text())
    mod.validate_configuration(config)
    for changes in ({'case_ids': ['one', 'one']}, {'max_trials': 11}, {'concurrency': 4},
                    {'systems': ['E1'] * 5}):
        with pytest.raises(ValueError, match='Ten-trial protocol'):
            mod.validate_configuration({**config, **changes})


def test_acceptance_rejects_abstention_failure_wrong_label_and_missing_usage(monkeypatch):
    mod = runner(monkeypatch)
    from test_experiment_acceptance import evidence_rows
    rows, summary, expected, subjects = evidence_rows()
    row = rows[0]
    assert mod.acceptance(rows, summary, expected, subjects)
    assert not mod.acceptance(rows[:9], summary, expected, subjects)
    for changes in ({'status': 'abstained'}, {'status': 'failed'}, {'predicted_label': 'VULNERABLE'}):
        assert not mod.acceptance([{**row, **changes}, *rows[1:]], summary, expected, subjects)
    for field in ('invalid_responses', 'requests_without_reported_usage'):
        assert not mod.acceptance(rows, {'usage': {**summary['usage'], field: 1}}, expected, subjects)


def test_interrupt_stops_active_worker_admission_and_never_schedules_remainder(monkeypatch):
    from threading import Event
    import pytest
    mod = runner(monkeypatch)
    from cv_agent.evaluation.runners.run_development_benchmark import BudgetStopped
    budget = mod.LockedBudget(100, 60)
    second_started = Event()
    calls = []
    def worker(task):
        calls.append(task)
        if task == 0:
            assert second_started.wait(2)
            return task
        second_started.set()
        assert budget.cancelled.wait(2)
        with pytest.raises(BudgetStopped):
            budget.check()
        return task
    def stop(_):
        raise KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):
        mod.execute_trials(range(10), worker, budget, stop, 2)
    assert set(calls) == {0, 1}
    assert budget.cancelled.is_set()
