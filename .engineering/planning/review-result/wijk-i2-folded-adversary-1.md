---
format: aep.planning-md/1
id: review-result:wijk-i2-folded-adversary-1
kind: review-result
status: active
title: Adversary pass 1 on I2 (folded-is-not-an-address-fold)
relations:
- reviews: story:folded-is-not-an-address-fold
revision: 1
---
unit: story:folded-is-not-an-address-fold, commit 29d7257 on base 86a32ae, plus one new untracked test file
verdict: red
cases: executed 317→320, red 3
origin: introduced 1, pre-existing 1, undecided 0
wrote-outside-worktree: ~/.cache/claude-tmp/wijk/i2/scratch/adv1-red.log, adv1-suite.log, adv1-base.log, adv1-base/ (deleted, 412M)
needs-coordinator: no

Cases in crates/mandate-federation/tests/adversary_folded_address_1.rs, all red at head:
- a_bracketed_literal_with_trailing_junk_is_the_default_port_… (red at base too)
- the_widening_admits_a_second_spelling_… (green at base)
- an_https_literal_issuer_admits_… (red at base too)

Red output:
issuer http://[::1] (port 80): the guard admitted http://[::1]x:44479/jwks as the issuer's own origin (admitted=true), and the shipped agent connected to port 44479 on it (reached=true) — the guard and the fetcher read two different ports
issuer http://[::1] (port 80): the guard admitted http://[0:0::0:1]x:35497/jwks as the issuer's own origin (admitted=true), and the shipped agent connected to port 35497 on it (reached=true)
issuer https://[2001:db8::7] (port 443): https://[2001:db8::7]x:22/jwks names port 22 to http::Authority::port and was admitted as the issuer's own origin
test result: FAILED. 0 passed; 3 failed

Cause: verifier_real.rs:452 origin treats anything after ] not starting with ':' as no port (default); http::Authority::port takes the last ':' and ureq connects to it. The 29d7257 widening (:348) lets every spelling of the address through, not only the issuer's exact one.

Suite: cargo test -p mandate-federation --locked --no-fail-fast 317 passed, 3 failed, EXIT=101. Base check via git archive 86a32ae export: 1 passed, 2 failed.

Reaches: the issuer's discovery document supplies jwks_uri (key_set); normalised_issuer accepts https://[v6] and http://[::1] on the default port. No deployment or fixture found that uses one (end_to_end.rs uses 127.0.0.1:<port>).
Suggested fix: at :452 refuse text after ] that does not start with ':'. Closes both.

Could not break: zone ids (reasoned, not run); IPv4 leading zeros; unbracketed IPv6 fails closed in the http crate (read, not run); name vs address and mapped vs IPv4; scheme mismatch; adversary_host_spelling_2.rs diff is doc-only.

```findings
- file: crates/mandate-federation/src/verifier_real.rs
  line: 452
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: 'origin reads [addr]x:P as the default port while http::Authority::port and ureq connect to P, so an IPv6-literal issuer on its default port admits a fetch to another port on its host'
- file: crates/mandate-federation/src/verifier_real.rs
  line: 348
  category: boundary
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the one_host widening extends that port disagreement from the exact issuer spelling to every IpAddr spelling of it, and [0:0::0:1]x:P is admitted and fetched on P where base refused it'
```
