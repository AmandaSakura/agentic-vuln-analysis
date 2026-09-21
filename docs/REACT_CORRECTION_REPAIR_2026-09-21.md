# ReAct correction repair, 2026-09-21

Source run: artifacts/python_heldout_pair_matrix/eb2208ddaa934c369a0ed5bf18ee7f51.

hp003_b E4 exhausted its eight-step taint loop after five SAFE/UNRESOLVED responses placed SANITIZED evidence in counter_observation_ids. Roles are relative to the predicted label, so these responses were correctly rejected. The last response changed the role but contained malformed JSON.

The correction conversation omitted rejected assistant responses and supplied only a generic error. ReAct now retains the rejected JSON immediately before validation feedback. The expert prompt and SAFE validation error explicitly explain that sanitizers supporting SAFE belong in supporting_observation_ids, and counter means against the prediction.

Evidence acceptance rules, step limits, and request accounting are unchanged. Regression checks first failed on the old implementation. They cover correction history, misclassified evidence roles, corrected citations, and continued rejection of source reads as safety evidence. Full offline suite: 626 passed in 25.56s. git diff --check passed.

hp003_b E5 failed separately: upstream_blocked OTHER, zero candidates, 3331 prompt tokens and zero completion tokens. Existing proxy diagnostic tests cover failure classification and usage accounting. This evidence does not justify a local transport change.

No live calls were made for this repair. Historical artifacts remain unchanged and the matrix remains failed. Offline tests establish correction protocol behavior, not live recovery. Future measurements must disclose this post-run repair.
