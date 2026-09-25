# Pinned Java command-boundary fixture

This is a two-case subset of OWASP BenchmarkJava at commit
`2734ae486356765ea4e45393a28e20bcb5047f8c`, from
[OWASP-Benchmark/BenchmarkJava](https://github.com/OWASP-Benchmark/BenchmarkJava).
The upstream [LICENSE](BenchmarkJava/LICENSE) and Java copyright headers are
retained. The Java sources, two resources and license are byte-for-byte copies;
`expectedresults-1.2beta.csv` retains the upstream header and only the two selected
rows. [manifest.json](manifest.json) records the selection and SHA-256 hashes.

`BenchmarkTest00827` is the safe control and `BenchmarkTest02244` is the vulnerable
control. The four Thing helpers and two resources are the dependencies consumed
by the existing Java command validator. These labels remain test/evaluator data,
not detector prompts or evidence of held-out performance.

`tests/test_java_fixture.py` copies this subset and the existing C recorder into a
temporary project and runs the actual Java/C harness. It does not read a local
`data/raw` checkout or download a benchmark. The tests require a JDK with the
`jdk.compiler` module and a C compiler available as `cc` on Linux. The existing
controlled process-boundary checks and the `Utils.java` stub are unchanged.
