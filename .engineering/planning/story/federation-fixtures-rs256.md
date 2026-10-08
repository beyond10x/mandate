---
format: aep.planning-md/3
id: story:federation-fixtures-rs256
kind: story
status: implemented
title: A recorded-shape RS256 ID token from an external IdP is admitted
relations:
- decomposes: epic:authentication
- serves: vision:mandate
scope:
- confidence: inferred
  path: crates/mandate-federation/src/verifier_real.rs
- confidence: inferred
  path: crates/mandate-federation/tests
revision: 5
transitions:
- {from: "draft", to: "proposed", at: "2026-09-23T15:17:16Z", actor: "human:timo", revision: 3, imported: true}
- {from: "proposed", to: "active", at: "2026-09-23T15:17:20Z", actor: "human:timo", revision: 4, imported: true}
- {from: "active", to: "implemented", at: "2026-09-23T21:34:49Z", actor: "human:timo", revision: 5, decided_on: {"recorded":{"test_result":1,"review_outcome":3}}, imported: true}
---
# A recorded-shape RS256 ID token from an external IdP is admitted

## Why

No case drives an ID token shaped like a real IdP's: RS256, a URL-named tenant claim such as `https://idp.example/claims/org_id`, a pairwise `sub`, an `azp`. The verifier carries only string-valued claims into tenant resolution (`crates/mandate-federation/src/verifier_real.rs:1333-1346`), so a non-string tenant claim silently resolves nothing.

## Acceptance

`cargo test -p mandate-federation --locked` carries cases in which such a token is admitted and resolves its tenant by the URL-named claim, and in which a numeric or array tenant claim is refused with a reason that names the claim's type.

## Scope

- `crates/mandate-federation/tests` (new file); `src/authenticate.rs` or `src/verifier_real.rs` for the typed refusal — inferred
