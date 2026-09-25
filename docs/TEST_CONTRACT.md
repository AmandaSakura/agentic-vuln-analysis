# Test contract

The development goal is a reproducible candidate-analysis research system with honest evidence and cost accounting. Passing pytest authorizes an experiment to start; it does not establish vulnerability recall, real-project safety, or research improvement.

| Boundary | Required behavior | Tests |
| --- | --- | --- |
| Candidate evidence | Confirmation belongs to this candidate and source snapshot; other helpers/fixtures cannot supply its proof | security contract, evidence validation |
| Static analysis | Report possible flows and suspicious guards/diffs without claiming exploit confirmation | security contract, taint regressions, validation tools |
| Concrete probe | Reachable builtin eval with controlled inputs is a bounded witness; shadowing/unsupported semantics remain unresolved | Python probe, security contract |
| Graph | A known qualified external call cannot link to an unrelated same-named local function | Python AST, security contract |
| Negative controls | Dead code, safe argv, dictionary update and constant refactoring do not confirm vulnerabilities | security contract |
| Scheduling | One final ballot per expert; dependencies obeyed; fixed-vote fast quorum cannot change full majority label | planner dependencies, agentic workflow, quorum |
| Retrieval | Same local base and declared augmentation budgets; tools cannot expand admitted paths | retrieval budget, agent budget units, source boundaries |
| Pair evaluation | Benign behavior preserved, intended rejection observed, detector IDs neutral | LangChain reproduction, security contract |
| Usage | Every made request counted; reported usage survives malformed responses and is counted once | model runtime, benchmark evaluation |
| Live admission | Full pytest must pass for the unchanged source snapshot before transport; failure or edits block calls | live gate |
| Test isolation | No real model/network experiment inside pytest; mocks and project-owned loopback HTTP only | conftest, live gate |

Before a repair, add an observable failing behavioral test. Then change implementation and run the relevant tests. Run the entire suite before any live experiment. Keep positive controls so that disabling a detector/validator cannot masquerade as fixing its false positives.

The live gate runs the full suite itself before the first model request in a process. Subsequent requests require identical source/config/test contents. An edit after admission stops the process's model calls; restart after completing the edit. No trusted pass-file or environment skip exists. Gate logs are local artifacts, not reusable admission credentials.

The current Jinja/LangChain checkouts and environments are optional for ordinary offline development, so real-checkout integration tests can skip when absent. Their orchestration correctness is also tested with deterministic mocks without those dependencies. A future LangChain-specific live runner must additionally require the actual pair prerequisites and passing integration checks; generic pytest success with skipped external fixtures is not evidence of pair readiness.

For a clean checkout, install the locked Python environment with `uv sync --locked`,
then run `uv run --no-sync pytest`. The Java boundary tests require Linux, a JDK
with `jdk.compiler`, and `cc`; they compile and execute the pinned two-case
[OWASP fixture](../tests/fixtures/java_command/README.md) in pytest temporary
directories. They do not require downloading `data/raw/BenchmarkJava`. Historical
review files linked by the documentation are tracked individually; bulk experiment
artifacts and real model credentials are not test prerequisites. Launcher tests
copy the scripts unchanged and load fake credentials only from a temporary project.

No automatic retry, provider fallback, broad benchmark run, or claimed safety proof is authorized merely by passing tests. Experiment configuration still defines the request budget and dataset role. HTTP errors/empty model choices are failures, not SAFE votes.
