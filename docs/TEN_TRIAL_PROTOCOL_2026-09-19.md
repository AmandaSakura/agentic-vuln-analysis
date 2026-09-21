# Ten-trial acceptance experiment

User limit: at most ten trials before considering full expansion. No replacement
trials, automatic retries or automatic full-run launch are included.

Fixed cases: BenchmarkTest00827 and BenchmarkTest02244, each on E1–E5.
These are the existing development pilot cases, not a new independent sample.
Entry selection uses the declared method name `doPost`, uniformly for both
cases and all systems; reference labels remain evaluator-only. The former
`doGet` experiment is preserved and is not pooled with this protocol.

Two trial workers run concurrently; model calls within each trial remain
sequential. A locked global request budget admits at most 200 requests in a
1,800-second admission window; already in-flight calls may finish afterward.
Journal writes are locked, and the full pytest gate runs before worker startup.
Model configuration is `micro_benchmark_gemini_native.json`: thinking parameter
omitted, no assertion that a particular upstream thinking budget is enforced.

Predeclared acceptance: all ten trials produce completed, non-abstaining labels
matching references, with no invalid model responses or missing reported usage.
Passing this development check is necessary but does not establish general
accuracy. Review validator evidence and transport diagnostics before expansion.
Failed acceptance blocks full expansion and is retained as diagnostic evidence.

Runner: `scripts/run_development_ten_trial.py`.
Configuration: `configs/development_ten_trial.json`.
Before launch: full offline suite 379 passed in 10.12 seconds.
Output: unique directory in `artifacts/development_benchmark/`, including source
snapshots, metadata, events, per-trial summaries and final `acceptance.json`.

## Result: acceptance failed; full expansion blocked

Run: `artifacts/development_benchmark/9595cfb27c094538a19a1e18613cf462/`.
Exactly ten trials finished in 169.13 seconds; peak in-flight requests was two,
and zero remained in flight at completion. No replacement trials were run.

| System | Negative case | Positive case |
| --- | --- | --- |
| E1 | SAFE | upstream_blocked: OTHER |
| E2 | SAFE | ABSTAIN |
| E3 | SAFE | VULNERABLE |
| E4 | SAFE | VULNERABLE |
| E5 | upstream_blocked: OTHER | VULNERABLE |

Seven labels match references, one trial abstained, two failed. All returned
expert validation statuses are UNRESOLVED: matching predictions do not supply
confirmed exploit or refutation evidence. No general accuracy claim follows.
Both failed calls have correlated native OTHER blocks. This run does not
isolate concurrency as a causal factor; no claim of rate limiting or keyword
filtering is established.

### Accounting repair

The original report's 300,021 tokens and -1 missing-usage count were incorrect.
The old aggregator used one global receive flag, so interleaved trials caused
a response to be counted twice. A failing offline regression reproduced this;
the repair tracks receive state per case/system/role and retains legacy serial
journal support. Correct totals: **56 requests, 54 valid replies, 2 invalid
responses, 296,132 reported tokens, zero requests without reported usage**.
Original artifacts and source snapshots are preserved; the corrected report
is `offline_review.json`. Rerun offline with `scripts/review_ten_trial_results.py`.

### Concrete follow-up before any new live batch

1. Keep concurrency at two; this run demonstrates bounded scheduling, not an
   advantage from increasing it further. Diagnose the two captured blocked
   exchanges offline; record unknown provider causes rather than retrying.
2. Keep the doPost protocol separately versioned. It exposes substantive code
   and enabled seven material predictions, but changing both entry and thinking
   configuration prevents causal attribution to either change alone.
3. For verified-vulnerability claims, design a candidate/source-bound Java
   validator with controlled positive and negative probes; existing UNRESOLVED
   static observations cannot satisfy this claim. Do not loosen acceptance or
   convert matching model labels into confirmation.
4. Full expansion remains blocked. This batch exhausts the authorized ten
   trials; further live verification must be a separately agreed batch.
