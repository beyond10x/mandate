---
format: aep.planning-md/1
id: review-result:wl-l1-trailing-dots-adversary-1
kind: review-result
status: active
title: Adversary pass 1 on L1 (trailing dots)
relations:
- reviews: story:federation-guard-trailing-dots
- reviews: story:bracketed-literal-trailing-dot
revision: 1
---
unit: story:federation-guard-trailing-dots + story:bracketed-literal-trailing-dot, commit 4f268d7 on base bde627b, plus one untracked test file
verdict: red
cases: executed 330→335, red 3
origin: introduced 0, pre-existing 3, undecided 0
wrote-outside-worktree: ~/.cache/claude-tmp/wl/l1/scratch/base/ (target deleted), suite-adv1.log
needs-coordinator: yes. The IPv4-literal finding sits outside the stories' out-of-scope premise.

Both stories' acceptance holds. Three red cases, all red at bde627b too.

Cases in crates/mandate-federation/tests/adversary_trailing_dots_1.rs: an_ipv4_literal_with_one_trailing_dot_is_admitted_only_if_the_fetcher_reaches_it (red: http://127.0.0.1 -> http://127.0.0.1./jwks: Err(127.0.0.1.:80 does not resolve)); a_plaintext_name_with_an_empty_label_elsewhere_is_admitted_only_if_the_fetcher_reaches_it (red: .localdomain, ..localdomain, keys..localdomain); the_two_guards_agree_on_the_localdomain_class (red: localhost.localdomain federation true, control-plane false); the_two_guards_agree_on_every_dot_spelling_of_the_loopback (green; red at base with 24 disagreements); a_loopback_name_with_one_trailing_dot_is_admitted_and_the_fetcher_resolves_it (green control). Resolution results depend on this machine's glibc resolver.

Suite: cargo test -p mandate-federation --locked --no-fail-fast EXIT=101, 332 passed, 3 failed.

F1 verifier_real.rs:347 NEEDS-CHANGE pre-existing warning: 127.0.0.1. is admitted as the issuer's own origin; ToSocketAddrs cannot resolve it; the class case (tests/verifier_real.rs ~2976, read.strip_suffix('.')) cannot see it. Reaches: nothing found.
F2 verifier_real.rs:628 CONFIRMED pre-existing note: loopback uses ends_with(".localdomain"), so .localdomain, ..localdomain, keys..localdomain count as loopback and are unresolvable; origin refuses an empty label only at the end.
F3 services/control-plane/src/adapters.rs:620 CONFIRMED pre-existing note: the doc says the two guards cannot disagree about one host, but the localdomain class is loopback to one and not the other.

Could not break: localhost.. and ports refused and agreed everywhere; [::1.], [::1..], [.::1] refused; no rewritten pinned case relaxed; ., .., .localhost, local..host agreed.

```findings
- file: crates/mandate-federation/src/verifier_real.rs
  line: 347
  category: acceptance
  severity: warning
  verdict: NEEDS-CHANGE
  origin: pre-existing
  message: 'an unbracketed IPv4 literal with one trailing dot (127.0.0.1.) is admitted as the issuer''s own origin and the fetcher cannot resolve it, and the class case strips that dot so it cannot see this'
- file: crates/mandate-federation/src/verifier_real.rs
  line: 628
  category: boundary
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: loopback matches any suffix .localdomain, so hosts with a leading or mid-name empty label are admitted as plaintext loopback issuers the resolver refuses
- file: services/control-plane/src/adapters.rs
  line: 620
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: is_loopback claims the two guards cannot disagree about one host, yet the federation guard counts the localdomain class as loopback and the control plane does not
```
