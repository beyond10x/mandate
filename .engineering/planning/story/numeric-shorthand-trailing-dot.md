---
format: aep.planning-md/1
id: story:numeric-shorthand-trailing-dot
kind: story
status: draft
title: A numeric shorthand address with a trailing dot is admitted and cannot be fetched
relations:
- decomposes: epic:authentication
- serves: vision:mandate
scope:
- confidence: cited
  path: crates/mandate-federation/src/verifier_real.rs
- confidence: cited
  path: crates/mandate-federation/tests/adversary_trailing_dots_2.rs
revision: 2
---
# A numeric shorthand address with a trailing dot is admitted and cannot be fetched

## Why

Adversary pass 2 on unit L1 of wave L (`review-result:wl-l1-trailing-dots-adversary-2`), pre-existing at `bde627b`: `crates/mandate-federation/src/verifier_real.rs` `origin` (~`:492`) decides what is an address with `IpAddr::from_str`, so the resolver-only IPv4 spellings `127.1.`, `2130706433.`, `0x7f.1.`, `0x7f000001.` count as names: the dot is folded and the host is admitted as the issuer's own origin, while the resolver cannot look the dotted form up. It fails closed. Wave L refuses `127.0.0.1.` for the same reason.

What reaches it: nothing found in the repository, docs, scenarios or conformance vectors.

## Acceptance

Given an issuer spelled with a numeric IPv4 shorthand, when a destination names the same shorthand with a trailing dot, then the guard refuses it; the case in `crates/mandate-federation/tests/adversary_trailing_dots_2.rs` that pins today's admission is re-pinned to the refusal.
