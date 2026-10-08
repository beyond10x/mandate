---
format: aep.planning-md/3
id: story:bracketed-literal-trailing-dot
kind: story
status: implemented
title: A bracketed issuer literal with a trailing dot is admitted and cannot be fetched
relations:
- decomposes: epic:authentication
- serves: vision:mandate
scope:
- confidence: cited
  path: crates/mandate-federation/src/verifier_real.rs
- confidence: cited
  path: crates/mandate-federation/tests/adversary_host_spelling_2.rs
- confidence: cited
  path: crates/mandate-federation/tests/verifier_real.rs
revision: 5
transitions:
- {from: "draft", to: "proposed", at: "2026-09-23T11:18:24Z", actor: "human:timo", revision: 3, imported: true}
- {from: "proposed", to: "active", at: "2026-09-23T11:18:26Z", actor: "human:timo", revision: 4, imported: true}
- {from: "active", to: "implemented", at: "2026-09-23T12:35:44Z", actor: "human:timo", revision: 5, decided_on: {"recorded":{"test_result":1}}, imported: true}
---
# A bracketed issuer literal with a trailing dot is admitted and cannot be fetched

## Why

Found by the second adversary pass on unit I2 of wave I (`review-result:wijk-i2-folded-adversary-2`),
at commit `4783e6a` on `impl/folded-is-not-an-address-fold`, and confirmed pre-existing against
`86a32ae`.

`crates/mandate-federation/src/verifier_real.rs:478` parses `folded(host)` as the bracketed
`Ipv6Addr`, so `[::1.]` and `[::1..]` are admitted as the issuer's own origin. The ureq resolver
reads them as the name `[::1.]` and cannot resolve them
(`[::1.]:80 does not resolve: failed to lookup address information`). The fetch fails closed; no
other destination is reached. The comment at `:470` says brackets hold "an IPv6 address and nothing
else", and three existing cases pin the admission (`tests/verifier_real.rs:2510`, `:2680`,
`tests/adversary_host_spelling_2.rs:172`).

The unit's class case at `tests/verifier_real.rs:2804` strips trailing dots from the host ureq
reads before comparing, so a mutant dropping `folded` from `:478` stays green.

What reaches it: nothing found in the repository — a discovery document would have to publish its
`jwks_uri` spelled that way.

## Acceptance

Given an issuer `http://[::1]`, when a discovery document names `http://[::1.]/jwks`, then the guard
answers what the fetcher does: either it refuses the destination, or the fetcher reaches `::1`. The
three pinned cases are rewritten to the decided answer, and the class case compares against the
host ureq reads without folding.

## Out of scope

Unbracketed trailing dots (`localhost.`), which the fetcher resolves.
