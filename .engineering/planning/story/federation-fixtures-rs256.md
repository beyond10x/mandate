---
format: aep.planning-md/1
id: story:federation-fixtures-rs256
kind: story
status: active
title: A recorded-shape RS256 ID token from an external IdP is admitted
relations:
- decomposes: epic:authentication
- serves: vision:mandate
scope:
- confidence: inferred
  path: crates/mandate-federation/src/verifier_real.rs
- confidence: inferred
  path: crates/mandate-federation/tests
revision: 4
---
# A recorded-shape RS256 ID token from an external IdP is admitted

## Why

No case drives an ID token shaped like a real IdP's: RS256, a URL-named tenant claim such as `https://idp.example/claims/org_id`, a pairwise `sub`, an `azp`. The verifier carries only string-valued claims into tenant resolution (`crates/mandate-federation/src/verifier_real.rs:1333-1346`), so a non-string tenant claim silently resolves nothing.

## Acceptance

`cargo test -p mandate-federation --locked` carries cases in which such a token is admitted and resolves its tenant by the URL-named claim, and in which a numeric or array tenant claim is refused with a reason that names the claim's type.

## Scope

- `crates/mandate-federation/tests` (new file); `src/authenticate.rs` or `src/verifier_real.rs` for the typed refusal — inferred
