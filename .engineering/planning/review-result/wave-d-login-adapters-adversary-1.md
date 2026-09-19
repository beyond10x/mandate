---
format: aep.planning-md/1
id: review-result:wave-d-login-adapters-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — login-adapters
relations:
- reviews: story:login-adapters
revision: 1
---
```
unit: story:login-adapters — impl/login-adapters on 75f41b5 (14 files)
verdict: NEEDS-CHANGE (1 blocker, 10 warnings, 1 note)
cases: 12 (9 server, 3 proto); 10 red, 2 held controls; suite 110 → 122
origin: introduced 11 / pre-existing 1
```

```findings
- file: crates/mandate-server/src/decode.rs
  line: 23
  category: acceptance
  severity: blocker
  verdict: INFEASIBLE
  origin: pre-existing
  message: 'credential.yaml''s header assigns code_id resolution to the trusted adapter, this unit reassigns it to the STS, and services/sts/src/redemption.rs:101 declares code_id a required input it never resolves — so nothing on the composed road produces one'
- file: crates/mandate-proto/src/oauth.rs
  line: 402
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'DenialClause::ClientMismatch maps to invalid_client where RFC 6749 section 5.2 names issued-to-another-client under invalid_grant, obliging an HTTP 401 on a road whose metadata advertises token_endpoint_auth_methods_supported: none'
- file: crates/mandate-proto/src/oauth.rs
  line: 365
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'TargetUnregistered, OrganizationMismatch, TargetDisabled and ExpiryUnbounded all answer invalid_scope on the redemption path, where the token endpoint declares no scope parameter'
- file: crates/mandate-server/src/decode.rs
  line: 530
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'redeem_authorization_code never calls single_header, so two Authorization headers are admitted, against the contract document''s rule for all four decoders'
- file: docs/architecture/adapter-contract.md
  line: 120
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the token endpoint admits Authorization: Basic, so the justification for token_endpoint_auth_methods_supported: none holds for the body parameter only'
- file: crates/mandate-server/src/decode.rs
  line: 488
  category: contract-drift
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'authorize_public_client bounds the query and never the body, so an 8193-byte body decodes Ok, against the document''s ceiling for all four decoders'
- file: crates/mandate-server/src/decode.rs
  line: 577
  category: boundary
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'an introspection body of token= decodes to a zero-byte credential_proof, admitted where the document says an absent or malformed presented credential is refused'
- file: crates/mandate-server/src/decode.rs
  line: 549
  category: boundary
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the same empty-string admission on code= at the token endpoint and on "proof":"" in the federation login body'
- file: crates/mandate-server/src/decode.rs
  line: 512
  category: boundary
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the decoded state carries CR/LF unbounded, and the listener must echo state into a Location header; the contract names no bound on state or nonce'
- file: docs/architecture/adapter-contract.md
  line: 212
  category: judgement
  severity: warning
  verdict: INFEASIBLE
  origin: introduced
  message: 'the authorization endpoint''s handler refusals are mandate-federation''s separate DenialClause with no mapping to any ErrorCode, and that crate is outside both ceilings'
- file: crates/mandate-server/src/metadata.rs
  line: 147
  category: contract-drift
  severity: warning
  verdict: INFEASIBLE
  origin: introduced
  message: 'Jwk::parameters is an open name/value list with no admitted set, so private JWK members would render into the published document; nothing in the tree builds a Jwk yet'
- file: crates/mandate-server/src/metadata.rs
  line: 159
  category: mutant
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'a parameters entry colliding with kty/kid/use/alg silently replaces it'
```

Held: `CLAUSE_CODES` covers all 42 `DenialClause` variants; `Refusal::ALL` and `ErrorCode::ALL` complete; form decoding refuses duplicates, empty keys, bad escapes, non-UTF-8; JSON bodies refuse duplicates, nesting, non-objects; `code_id` smuggling refused in four spellings; the S256 shape predicates; the generated-path predicate on every published path and the edge cases; the route table disjoint; 61 = 61 both ways, 25 clauses, 57 generated rows; the metadata rendering byte-stable; no caller byte reaches an error body (by type).

Rulings (coordinator, correction round 1): F1 `invalid_grant`; F2 `invalid_grant` for the target clauses, `invalid_request` for `ExpiryUnbounded`; F3/F4 empty credential fields refused; F5/F6 one `Authorization` header and no presented client credential at the token endpoint; F7 one body ceiling helper; F8 `state`/`nonce` bounded and control-free; F9/F10 an admitted JWK parameter set; F11 `code_for_reason` for the authorization endpoint, the composition maps by reason there; F12 (blocker) routed — `code_id` resolution from the presented code is the composition's through a by-verifier read the STS store exposes (`story:product-listener`, `services/sts/src/store.rs` added to its scope).
