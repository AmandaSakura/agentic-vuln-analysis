# Real-source pairs and transport investigation

**Goal:** Reproduce an upstream vulnerable/fixed pair, audit label quality, and diagnose empty model responses with bounded runs.

**Architecture:** Preserve old manifests and results. Keep evaluator evidence separate from detector inputs. Compare explicit transport configurations against recorded requests, then run full checks only after inspecting the small diagnostic.

**Tech stack:** Python, uv, pytest, Git, existing live-model journal and budget.

- [ ] Inspect pinned proxy source and compare 1,200 vs 8,192 output-token limits using four recorded first requests, without executing tools or retries.
- [ ] Fetch advisory-linked LangChain patch and its exact vulnerable source; verify the public f-string attack with a synthetic local object and benign control in isolated package environments.
- [ ] Preserve source identities and reproduction outputs; label only the tested entry/attack, not an entire fixed repository SAFE.
- [ ] Record advisory corrections and exclusions separately from the previously frozen manifest; distinguish future tuning data from untouched held-out data.
- [ ] Run scanner coverage on the new pair without passing reference locations to the scanner; report missed candidates before considering model accuracy.
- [ ] Based on observed transport outcomes, run a bounded full-source followup or retain the service failure as unresolved.
- [ ] Add regression coverage for concrete bugs found, run full tests, update status and usage ledger.
