---
format: aep.planning-md/1
id: review-result:wijk-i2-folded-adversary-2
kind: review-result
status: active
title: Adversary pass 2 on I2 (folded-is-not-an-address-fold)
relations:
- reviews: story:folded-is-not-an-address-fold
revision: 1
---
unit: story:folded-is-not-an-address-fold, commit 4783e6a (working tree clean apart from one new untracked test file)
verdict: red
cases: executed 321→323, red 1
origin: introduced 1, pre-existing 1, undecided 0
wrote-outside-worktree: ~/.cache/claude-tmp/wijk/i2/scratch/{adv2-authorities.txt, adv2-red.log, adv2-base.log, adv2-mutants.sh, adv2-mutants.log, adv2-suite.log}, adv2-ws/ (deleted)
needs-coordinator: no

Cases in crates/mandate-federation/tests/adversary_folded_address_2.rs:
- a_bracketed_literal_the_guard_admits_as_the_issuers_own_is_one_the_fetcher_resolves — red: e.g. issuer http://[::1]: the guard admitted http://[::1.]/jwks as ::1, and the fetcher reads it as Err("[::1.]:80 does not resolve: failed to lookup address information: Name or service not known"); same for [::1..], :8443, https://[2001:db8::7.]
- the_shapes_real_identity_providers_publish_are_still_admitted — green (Google, Entra, Okta, Auth0, Keycloak, Cognito shapes; 127.0.0.1:<port>; [::1]:port; localhost; underscore host)
Base check: same 6 lines red with the 86a32ae verifier_real.rs, so pre-existing.

Suite: cargo test -p mandate-federation --locked --no-fail-fast 322 passed, 1 failed, EXIT=101.

F1 verifier_real.rs:478 CONFIRMED pre-existing note: brackets parse folded(host), so [v6.] and [v6..] are admitted while ureq cannot resolve them; fails closed; contradicts :470 and the doc row at tests/verifier_real.rs:103. Dropping folded turns 3 existing cases red (verifier_real.rs:2510, :2680, adversary_host_spelling_2.rs:172) — a design call. Reaches: nothing found.
F2 tests/verifier_real.rs:2804 CONFIRMED introduced note: the class case strips trailing dots from the ureq host before comparing; mutant M6 (drop folded at :478) stays green. Test coverage only.

Could not break: 132 repo authorities, none refused; class case kills M1, M2, M3, M5; M4 survives but http Port::from_str also reads +22 as 22; no other admitting disagreement found; multiple trailing dots unchanged from base.

```findings
- file: crates/mandate-federation/src/verifier_real.rs
  line: 478
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: 'the bracket grammar parses folded(host), so [v6.] and [v6..] are admitted as the issuer''s own origin while the ureq resolver cannot resolve them; fails closed, contradicts the comment at :470 and the doc row at tests/verifier_real.rs:103'
- file: crates/mandate-federation/tests/verifier_real.rs
  line: 2804
  category: mutant
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the class case strips trailing dots from the ureq host before comparing, so dropping folded from the Ipv6Addr check at verifier_real.rs:478 leaves it green'
```
