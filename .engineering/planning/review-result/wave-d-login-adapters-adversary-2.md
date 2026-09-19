---
format: aep.planning-md/1
id: review-result:wave-d-login-adapters-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — login adapters
relations:
- reviews: story:login-adapters
revision: 1
---
```
unit: story:login-adapters — impl/login-adapters on 75f41b5, after correction 1
verdict: NEEDS-CHANGE (2 blockers, 4 warnings, 2 notes)
cases: 140 → 146 executed, 6 red when written
origin: introduced 8 / pre-existing 0
```

```findings
- file: crates/mandate-proto/src/oauth.rs
  line: 469
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'ClientUnregistered, ClientOutsideOrganization and ClientDisabled are raised on the redemption path through binding::bound_client and code::admitted_client and answer invalid_client, which the adapter contract forbids for any redemption-reachable clause and which obliges HTTP 401 on a road advertising token_endpoint_auth_methods_supported none'
- file: crates/mandate-proto/tests/oauth.rs
  line: 489
  category: mutant
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'token_endpoint_clauses reads only redemption.rs and binding.rs, so the class check the document presents as its proof never sees the three clauses code::admitted_client raises one call hop further on the same path'
- file: crates/mandate-server/src/decode.rs
  line: 674
  category: acceptance
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the three body decoders measure the query string and never read or refuse it, so a POST carrying organization_id, audience, subject and actor in its target decodes Ok, against rule 1 and the story''s "every undeclared field is refused"'
- file: crates/mandate-proto/src/oauth.rs
  line: 267
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'ErrorCode::AUTHORIZATION_ENDPOINT is documented as RFC 6749 section 4.1.2.1''s set and omits unauthorized_client on the stated ground that no refusal produces it, while publicclient::registered_public_client raises ClientUnknown, ClientDisabled and ClientNotPublic at /oauth/authorize, all answered access_denied'
- file: crates/mandate-server/src/decode.rs
  line: 724
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'free_text refuses Unicode category Cc, so a state carrying a C1 control U+0080-U+009F is refused although rule 8 and two rustdoc lines name the refused class as C0 and DEL only'
- file: crates/mandate-server/src/metadata.rs
  line: 102
  category: judgement
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the metadata advertises introspection_endpoint with no introspection_endpoint_auth_methods_supported while the introspection decoder requires a bearer caller proof, under a section headed "what is advertised is what is enforced"'
- file: crates/mandate-server/src/metadata.rs
  line: 255
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'Jwk::members drops an unadmitted parameter silently where the document says the rendering refuses; nothing in this crate fills Jwks::keys'
- file: crates/mandate-server/src/metadata.rs
  line: 286
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'Jwks::to_json renders two keys carrying the same kid without complaint, which RFC 7517 section 4.5 says should be distinct; nothing in this crate fills Jwks::keys'
```

Held under attack: the nine `AuthorizePublicClient` inputs required (contract-faithful), percent-decoding non-expanding, byte ceilings, `single_header` case handling, empty body at authorize, `scope` splitting, the by-verifier `code_id` index constructible, `Jwk` private-member leak closed, route disjointness, the 25 obligation clauses, `CLAUSE_CODES` completeness, both endpoints' code images.

Rulings (coordinator, correction round 2, the last): F1 blocker holds — after correction 1 the rule is a documented check, so a violation is contract drift; the three clauses answer `invalid_grant` at the token endpoint. F2 — the check follows calls transitively (imports and paths) from `redeem_authorization_code`; the adversary case is amended to the same method as its control. F3 — a body route admits no query: `Refusal::QueryNotAdmitted`, the mirror of `BodyNotAdmitted`, after the ceiling; rule 7 reworded; adversary cases 4 and 5 amended to that refusal. F4 — `ErrorCode::UnauthorizedClient` added; the authorize endpoint maps by `mandate_federation::Denied.clause` (`ClientUnknown`, `ClientDisabled`, `ClientNotPublic` → `unauthorized_client`) with reason as the fallback; whether such a refusal is redirected or rendered is the listener's (recorded on `story:product-listener`). F5 — the document: the class is Unicode category `Cc`; predicate unchanged; adversary case 6 amended. F6 — no registered auth-method value names a bearer caller proof, so the member stays absent and the document says so in the metadata section. F7 — the rendering filter is removed and the sentence with it; `Jwk::new` is the one refusal. F8 — `Jwks` gains a constructor refusing a repeated `kid`.
