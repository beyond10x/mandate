---
format: aep.planning-md/1
id: review-result:wl-l1-trailing-dots-adversary-2
kind: review-result
status: active
title: Adversary pass 2 on L1 (trailing dots)
relations:
- reviews: story:federation-guard-trailing-dots
- reviews: story:bracketed-literal-trailing-dot
revision: 1
---
unit: story:federation-guard-trailing-dots + story:bracketed-literal-trailing-dot, HEAD edfc215 over base bde627b, plus one untracked test file
verdict: red (one INFEASIBLE, pre-existing note; nothing introduced)
cases: executed 335→337, red 1
origin: introduced 0, pre-existing 1, undecided 0
wrote-outside-worktree: ~/.cache/claude-tmp/wl/l1/scratch/adv2-suite.log; base copy (deleted)
needs-coordinator: yes. Decide whether the correction's 'an address has no absolute form' rule should cover the IPv4 spellings the resolver reads as addresses but Rust's parser does not.

Cases in crates/mandate-federation/tests/adversary_trailing_dots_2.rs: a_numeric_shorthand_address_with_a_trailing_dot_is_admitted_only_if_the_fetcher_reaches_it (red; also red at bde627b: https://127.1 -> https://127.1./jwks: Err(127.1.:443 does not resolve), same for 2130706433, 0x7f.1, 0x7f000001, issuer with and without the dot); the_two_guards_agree_on_every_spelling_but_the_localdomain_class (green across 25 hosts x dot placements x 8 port tails; localhost. admitted by both and resolves). getent ahostsv4: 127.1, 2130706433, 0x7f.1 resolve; every dotted form fails.

Suite: cargo test -p mandate-federation --locked --no-fail-fast EXIT=101, 336 passed, 1 failed. clippy and fmt clean.

F1 verifier_real.rs:492 INFEASIBLE pre-existing note: origin decides what is an address with IpAddr::from_str, so numeric shorthands with a trailing dot are folded and admitted as the issuer's own origin and the resolver cannot look them up. Reaches: nothing found in repo, docs, scenarios or conformance vectors. Fix: refuse a trailing-dot host whose labels are all numeric or hex.

Could not break: no over-refusal of any issuer or JWKS URI in the repo; localhost. admitted and resolving on both guards; IPv6 and bracket spellings agree; empty labels refused everywhere; zero disagreements outside .localdomain; no relaxed pin; the transcribed is_loopback matches HEAD.

```findings
- file: crates/mandate-federation/src/verifier_real.rs
  line: 492
  category: boundary
  severity: note
  verdict: INFEASIBLE
  origin: pre-existing
  message: 'origin decides what counts as an address with IpAddr::from_str, so numeric shorthands with a trailing dot (127.1., 2130706433., 0x7f.1.) are folded and admitted as the issuer''s own origin, yet the resolver cannot look them up, the same class as 127.0.0.1. which the correction refuses'
```
