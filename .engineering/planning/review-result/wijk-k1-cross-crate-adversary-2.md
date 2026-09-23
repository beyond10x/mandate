---
format: aep.planning-md/1
id: review-result:wijk-k1-cross-crate-adversary-2
kind: review-result
status: active
title: Adversary pass 2 on K1 (cross-crate-clauses)
relations:
- reviews: story:cross-crate-clauses
revision: 1
---
unit: story:cross-crate-clauses. Findings cover commit 2aa9f5c plus one untracked test file
verdict: red (strongest verdict: NEEDS-CHANGE)
cases: executed 244→245, red 1
origin: introduced 2, pre-existing 0, undecided 0
wrote-outside-worktree: ~/.cache/claude-tmp/wijk/k1/scratch/{adv2-alone.log, adv2-suite.log}
needs-coordinator: yes. The story's Acceptance no longer matches the corrected rows, and the DisableOAuthClient row needs a ruling on who owns it.

Case: xtask/tests/adversary_cross_crate_2.rs, the_disable_o_auth_client_denial_clause_is_decided_by_a_test_that_sees_disable_o_auth_client_refuse — red at :106:9: the clause "disablement cannot stop the issuance of new authorization codes to it" is a condition under which DisableOAuthClient is refused, and it is counted real on mandate-federation::adversary_writers_1::probe_a_disabled_registered_client_is_refused_at_authorization, whose every call of disable_oauth_client(..) reads the accepted event — the refusal it asserts is another command's.

Suite: cargo test -p xtask --locked --no-fail-fast EXIT=101, 244 passed, 1 failed; pass-1 cases green; clippy clean; registry 191 / 86 / 21 / 84.

F1 federation.json:308 NEEDS-CHANGE introduced blocker: the clause is a condition under which DisableOAuthClient itself is refused (federation.yaml:425); the test calls disable_oauth_client(...).expect(..) (adversary_writers_1.rs:222-229) and asserts AuthorizePublicClient's ClientDisabled, which row :154 already counts; disable.rs:197-226 has no refusal for it. Honest shape: deferred, like DisableFederationConnection's 'cannot commit' row (decision-blocker:epoch-atomicity). Reaches: every registry run counts it in the 86.
F2 story cross-crate-clauses Acceptance NEEDS-CHANGE introduced: Acceptance requires both federation rows under decided_in mandate-sts and counted real; 2aa9f5c satisfies neither; xtask/tests/obligations_registry.rs:737 was weakened from >= 2 to non-empty.

Not broken: 'STS code issuance' tiles and the composition reaches STS refusals federation does not pre-check (TargetDisabled, ProfileUnadmitted; adapters.rs:2689-2708 → :2791); story:agent-authority-kernel is live and consistent with sts.json:167; no over-refusal of committed rows; literal updates not tautological.

```findings
- file: contracts/obligations/federation.json
  line: 308
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the clause is a refusal of DisableOAuthClient, yet it is counted real on a test that requires disable_oauth_client to be accepted and asserts AuthorizePublicClient''s ClientDisabled instead'
- file: .engineering/planning/story/cross-crate-clauses.md
  category: acceptance
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'Acceptance still requires both federation rows under decided_in mandate-sts and counted real; 2aa9f5c satisfies neither and weakened xtask/tests/obligations_registry.rs:737 from >= 2 to non-empty to fit'
```
