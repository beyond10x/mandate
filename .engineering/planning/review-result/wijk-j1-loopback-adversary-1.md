---
format: aep.planning-md/1
id: review-result:wijk-j1-loopback-adversary-1
kind: review-result
status: active
title: Adversary pass 1 on J1 (control-plane-loopback-fold)
relations:
- reviews: story:control-plane-loopback-fold
revision: 1
---
unit: story:control-plane-loopback-fold — commit b8c25f3 on base 9a68796, plus one untracked test file
verdict: red
cases: executed 159→162, red 2
origin: introduced 2, pre-existing 0, undecided 0
wrote-outside-worktree: ~/.cache/claude-tmp/wijk/j1/scratch/adv1-suite.log, adv1-suite-nff.log
needs-coordinator: no

No spelling tried gets plaintext through to a host other than loopback. The fold does now admit plaintext for authorities that are not valid URI hosts; the base refused every one of them.

Cases in services/control-plane/tests/adversary_loopback_fold_1.rs:
- a_plaintext_authority_that_is_no_rfc3986_host_is_not_admitted — red: admitted ["http://::1:8080", "http://::1:", "http://0::1:8080", "http://[localhost]:8080", "http://[127.0.0.1]", "http://[::1.]:8080"]
- a_plaintext_host_with_an_empty_trailing_label_is_not_admitted — red: admitted ["http://localhost..:8080", "http://127.0.0.1..."]
- no_spelling_of_another_host_is_admitted_over_plaintext — green, 34 hostile spellings refused (userinfo in every placement, percent-encoding, IPv4-mapped/compatible IPv6, 0.0.0.0, [::], 127.1, 2130706433, 0x7f.0.0.1, zone ids, empty hosts, .localhost, localhost.evil.example., bad ports, stray brackets)

Suite: cargo test -p mandate-control-plane --locked --no-fail-fast EXIT=101, 162 ran, 2 red (this file only).

F1 adapters.rs:651/:645 CONFIRMED warning introduced: unbracketed IPv6 and bracketed non-IPv6 hosts admitted as plaintext loopback; RFC 3986 3.2.2 allows neither. Fix: bracketed host must parse as Ipv6Addr; refuse unbracketed host containing ':'. Reaches: only the operator's issuer setting (main.rs:226, serving.issuer); no fixture or workflow found.
F2 adapters.rs:661 CONFIRMED note introduced: trim_end_matches strips every trailing dot, so localhost.. is admitted. Fix: strip at most one. Reaches: operator setting only.

The federation guard (verifier_real.rs:434,:534,:561) reads all eight strings as loopback too; the guards agree on them. Remaining disagreements are the two the implementor stated (.localdomain; anything after ] other than a port).

```findings
- file: services/control-plane/src/adapters.rs
  line: 651
  category: boundary
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'is_loopback now admits authorities that are not URI hosts as plaintext loopback: unbracketed IPv6 (http://::1:8080) and bracketed hosts that are not IPv6 (http://[localhost]:8080, http://[127.0.0.1]), all refused at base'
- file: services/control-plane/src/adapters.rs
  line: 661
  category: boundary
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: trim_end_matches strips every trailing dot, so localhost.. and 127.0.0.1... are admitted as a plaintext loopback issuer
```
