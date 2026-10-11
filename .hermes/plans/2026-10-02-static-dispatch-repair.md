# Static dispatch repair and prospective validation

Problem: the line-level v2 dispatch guard counts every nested AST call and blocks a sole registered operation such as eval(compile(...)) or subprocess.run([str(item)]). Twelve public CLI controls cover nested arguments, module/import aliases, actual same-line multiple registered operations, and strong literal-mode positive/negative controls.

Change: operations.py exposes the discovery-rule inventory for a slice's line; service_v2.py counts distinct registered operations. Full original slice still goes to the validator; binding, side-effect, proof and UNKNOWN semantics remain enforced. No target execution is added.

- [x] Reproduce public failure: initial ten controls yielded 4 failed / 6 passed. Retain dispatch-before.log.
- [x] Repair operations.py and service_v2.py. First combined controls: 22 passed; add two alias controls and run twelve dispatch cases.
- [x] Fresh six-control model experiment: actual 6 requests / 8214 reported tokens. Public CLI package/verify/view/copy passed; original in-process gate 2964 passed/431.69s before credentials, immutable package verification after every tools-disabled single-shot reply passed.
- [x] After the new gate and live checks passed, unchanged twelve-component static policy completed all 239 files and 59 analyses with zero blocks/failures. All ancestor failures preserved; no cap increase or label rewrite. The nine former blocks matched identical source bytes and exact operation identities, and remained UNKNOWN after analysis.
- [x] Reconciled versions separately; published final-result.json, verification.md and CURRENT_STATUS. Original attack/witness matrix remains outside this work; 14 named-mode controls still UNKNOWN and independent/human quality still unmeasured.
