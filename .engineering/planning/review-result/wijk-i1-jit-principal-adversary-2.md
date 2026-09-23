---
format: aep.planning-md/1
id: review-result:wijk-i1-jit-principal-adversary-2
kind: review-result
status: active
title: Adversary pass 2 on I1 (jit-principal-record)
relations:
- reviews: story:jit-principal-record
revision: 1
---
unit: story:jit-principal-record, 4b0f452 (base 86a32ae) plus one untracked test file
verdict: nothing found
cases: executed 153→156, red 0
origin: introduced 0, pre-existing 0, undecided 0
wrote-outside-worktree: 3 paths under ~/.cache/claude-tmp/wijk/i1/scratch/ (adv2-helpers.rs, adv2-case.log, adv2-suite.log)
needs-coordinator: no

Could not break the correction. The copy-then-swap does not lose state, does not apply the event twice, and no assertion was relaxed.

Cases added in services/control-plane/tests/adversary_jit_principal_2.rs, all green: a_refused_provisioning_leaves_both_folds_exactly_as_they_were; the_retry_after_a_refusal_provisions_exactly_once; repeated_logins_provision_once_in_both_folds. `test result: ok. 3 passed; 0 failed`.

Suite: `cargo test -p mandate-control-plane --locked --no-fail-fast` EXIT=0, 156 passed. clippy Finished; fmt clean.

Attacked and could not break: lost concurrent state (provisioned takes &mut self; nothing touches self.federation between the clone at adapters.rs:2465 and the swap); clone depth (Projection, record.rs:442, derives Clone over three Vecs, no shared interior); double apply (applied once, to the copy); identity partial write (try_record, port.rs:622, decides before appending); the swapped-order mutant is unreachable (authenticate.rs:276,283 refuse empty and untrimmed subjects); relaxed assertions (serve.rs hunk is a doc comment; tests/adapters.rs only adds; adversary_jit_principal_1.rs unchanged since 7ad7cfa and passes).

```findings
[]
```
