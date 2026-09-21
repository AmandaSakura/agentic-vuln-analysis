"""Shared request admission and bounded concurrent trial scheduling."""
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from threading import Event, RLock
import time


class BudgetExceeded(RuntimeError):
    pass


class BudgetStopped(BudgetExceeded):
    pass


class Budget:
    def __init__(self, requests, seconds):
        self.limit = requests
        self.used = 0
        self.deadline = time.monotonic() + seconds
        self.cancelled = Event()

    def check(self):
        if self.cancelled.is_set():
            raise BudgetStopped('Experiment stopped; no further requests admitted')
        if self.used >= self.limit or time.monotonic() >= self.deadline:
            raise BudgetExceeded('Predeclared request or wall-time limit reached')

    def stop(self):
        self.cancelled.set()

    def observer(self, trial, role):
        def record(event):
            if event['event'] == 'model_start':
                self.check()
                self.used += 1
            trial.record({'role': role, **event})
        return record


class LockedBudget(Budget):
    def __init__(self, requests, seconds):
        super().__init__(requests, seconds)
        self.lock = RLock()

    def observer(self, trial, role):
        record = super().observer(trial, role)
        def observe(event):
            with self.lock:
                record(event)
        return observe

    def stop(self):
        with self.lock:
            super().stop()


def execute_trials(tasks, worker, budget, progress, concurrency):
    """Only active slots are submitted; stop closes admission before joining."""
    iterator = iter(tasks)
    executor = ThreadPoolExecutor(max_workers=concurrency)
    pending = set()
    try:
        for _ in range(concurrency):
            task = next(iterator, None)
            if task is not None:
                pending.add(executor.submit(worker, task))
        while pending:
            finished, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in finished:
                progress(future.result())
            for _ in finished:
                task = next(iterator, None)
                if task is not None:
                    pending.add(executor.submit(worker, task))
    except BaseException:
        budget.stop()
        for future in pending:
            future.cancel()
        raise
    finally:
        executor.shutdown(wait=True, cancel_futures=True)
