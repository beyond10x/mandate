---
format: aep.planning-md/1
id: review-result:wijk-i3-sts-lifetime-adversary-2
kind: review-result
status: active
title: Adversary pass 2 on I3 (sts-lifetime-bounds)
relations:
- reviews: story:sts-lifetime-bounds
revision: 1
---
unit: story:sts-lifetime-bounds, at d57dc0a plus one untracked test file
verdict: red. 2 CONFIRMED doc-vs-code findings (warning), both introduced by the d57dc0a rewording, both reached only through request instants or hand-built records that no clock or writer produces
cases: executed 213→216, red 3
origin: introduced 2, pre-existing 0, undecided 0
wrote-outside-worktree: ~/.cache/claude-tmp/wijk/i3/scratch/adv2-suite.log
needs-coordinator: no

The corrected registry.rs doc (lines 139-144) is still false in two of its claims. The rewritten pass-1 case is not a relaxation. The code is right in all three places; only the doc needs to change.

Cases added in services/sts/tests/adversary_lifetime_bounds_2.rs, all red:
- an_admitted_profile_issues_readably_for_every_request_before_3000: PT1S admitted; request at 0000-01-01T00:00:00+01:00 returns Err(ExpiryUnbounded)
- a_self_contained_issuance_under_a_refused_bound_is_refused_after_9999_minus_max_ttl: P2600000D record, request 2881-06-10T00:00:00Z returns Ok(2881-06-11T00:00:00Z)
- a_redemption_under_a_refused_bound_is_refused_after_9999_minus_max_ttl: same record, code redeemed at 9000-01-01T00:00:00Z returns Ok(9000-01-01T00:05:00Z)

Suite: cargo test -p mandate-sts --locked --no-fail-fast exit 101, 213 passed, 3 failed (the three above). clippy Finished.

G1 registry.rs:140 CONFIRMED introduced: doc says an admitted profile issues readably for every request before 3000-01-01; PT1S at year 0 +01:00 is refused. Fix: 'from 0000-01-01T00:00:00Z up to 3000-01-01T00:00:00Z, UTC'. Reaches: nothing found.
G2 registry.rs:142 CONFIRMED introduced: 'exactly after 9999 minus max_ttl' holds only for reference issuance; self-contained uses the signer TTL (issue.rs:421), redemption caps at the code's expiry (redemption.rs:350). Fix: the line is 9999 minus the lifetime issued. Reaches: nothing found (refused-bound records come only from hand-built logs).

Could not break: the rewritten pass-1 case pins the boundary to the second (reference path); d57dc0a's doc edits in adversary_obligations_sts_1.rs are true; PT220898620799S from 3000-01-01 lands on 9999-12-31T23:59:59Z.

```findings
- file: services/sts/src/registry.rs
  line: 140
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the corrected doc says an admitted profile issues readably for every request before 3000-01-01, but PT1S at 0000-01-01T00:00:00+01:00 is refused ExpiryUnbounded'
- file: services/sts/src/registry.rs
  line: 142
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the exactly-after-9999-minus-max_ttl refusal line holds only for reference issuance; self-contained (signer ttl) and redemption (code-capped) issue past it under a refused-bound record'
```
