---
format: aep.planning-md/1
id: story:login-adapters
kind: story
status: implemented
title: 'Decode the login road''s requests: routes, verified context, form encoding, the obligations registry'
relations:
- decomposes: epic:sts-credentials
- serves: vision:mandate
- depends_on: story:canonical-types
- informed_by: story:protocol-adapters
scope:
- confidence: cited
  path: crates/mandate-proto/src/lib.rs
- confidence: inferred
  path: crates/mandate-proto/src/oauth.rs
- confidence: inferred
  path: crates/mandate-proto/tests/oauth.rs
- confidence: inferred
  path: crates/mandate-server/src/context.rs
- confidence: cited
  path: crates/mandate-server/src/lib.rs
- confidence: inferred
  path: crates/mandate-server/src/metadata.rs
- confidence: inferred
  path: crates/mandate-server/src/obligations.rs
- confidence: inferred
  path: crates/mandate-server/src/routes.rs
- confidence: inferred
  path: crates/mandate-server/tests/conformance.rs
- confidence: inferred
  path: crates/mandate-server/tests/context.rs
- confidence: inferred
  path: crates/mandate-server/tests/metadata.rs
- confidence: inferred
  path: crates/mandate-server/tests/obligations.rs
- confidence: inferred
  path: crates/mandate-server/tests/routes.rs
- confidence: inferred
  path: docs/architecture/adapter-contract.md
revision: 16
---
# Decode the login road's requests: routes, verified context, form encoding, the obligations registry

Split from `story:protocol-adapters` at the wave D opening (2026-09-19): that story keeps its full acceptance (every product route, the denial-audit path, the exchange and SCIM rows) and its draft `depends_on` edges; this one carries the four units the customer login road needs, depending on nothing that is not on `main`.

## Acceptance

Given the four road requests (`AuthenticateFederation`, `AuthorizePublicClient`, the token endpoint `RedeemAuthorizationCode`, introspection), when the adapter library decodes each from its wire form, then exactly the command's declared inputs reach the handler and every undeclared field is refused (no caller-supplied selector passes through), the token request is decoded from `application/x-www-form-urlencoded` and refused with the standard OAuth error body when malformed, the product route table is provably disjoint from the 61 generated `/<domain>/commands/<Command>` routes, and the obligations registry equals the OpenAPI operationId set.

## Required observations

`context`: a `VerifiedContext` built from credential evidence alone with every caller-supplied selector stripped (case `credential-containment`); `routes`: the product route table as data for the three road routes plus introspection, and the proof its intersection with the generated command routes is empty; `oauth`: form decoding (`&`/`=` splitting and percent-decoding in `std`), the standard error bodies as JSON, the `pkce-missing` and `pkce-plain` wire refusals as named tests; `obligations`: the typed registry over every command with the equality test against the four `generated/openapi/*.yaml` operationIds (61) and one negative test per deny clause of the road commands; `docs/architecture/adapter-contract.md` as the written adapter contract the gate now reads. No listener, no socket, no async, no new dependency.

## Scope

Derived 2026-09-19 by `story-scoper` on `main` at `6f6f639` (wave C merged). **cited** = read from the tree; **inferred** = a reading that could be wrong.

- **Primary surface:** `crates/mandate-server` — cited; `docs/architecture/ownership.md:20` gives it the shared transport/authentication adapter and denies it PDP or issuance authority; `crates/mandate-server/src/lib.rs:1-4` is a scaffold. Secondary: `crates/mandate-proto` (the `oauth` unit; `crates/mandate-proto/src/lib.rs:1-223`, `pub mod oauth;` after `:119`).
- **No manifest, boundary or `xtask` edit:** `crates/mandate-server/Cargo.toml:13-15` carries `mandate-types` and `mandate-proto`; `dependency-boundaries.json:98-101` keys `mandate-server`; `PACKAGES = 22`, `LIBRARIES = 17` hold — cited. `Cargo.lock` holds no `axum`, `hyper`, `tower`, `url`, `form_urlencoded`, `serde_urlencoded`; `http`/`httparse`/`percent-encoding` are transitive to other packages and not admitted here — cited. The request value is a crate-local plain struct over `mandate-types` values, on the precedent of the two `RequestContext` types (`crates/mandate-federation/src/lib.rs:374-395`, `services/sts/src/lib.rs:162-175`) — inferred.

### Units — one implementor; rows in order

| Unit | Files (to create) | Delivers | Test file |
|---|---|---|---|
| `context` | `crates/mandate-server/src/context.rs` | `VerifiedContext` (`crates/mandate-types/src/record.rs:57-95`) from validated credential evidence; selectors stripped (`combined.md:51`); the acceptance, case `credential-containment` | `tests/context.rs` |
| `routes` | `src/routes.rs` | the product route table as data (the three road routes and introspection, paths chosen and reviewed against `docs/sources/original-design.md:1784-1796,1855-1862`); the proof its intersection with the 61 generated routes is empty (read from `generated/openapi/*.yaml`) | `tests/routes.rs` |
| `oauth` | `crates/mandate-proto/src/oauth.rs` | form decoding in `std`; the standard OAuth error bodies (`invalid_request`, `invalid_grant`, `invalid_client`, `unsupported_grant_type`) as JSON through `serde_json`; `pkce-missing`, `pkce-plain` as wire refusals | `crates/mandate-proto/tests/oauth.rs` |
| `obligations` | `src/obligations.rs` | the typed registry, equal to the operationId set of the four OpenAPI documents (61); one negative test per deny clause of the three road commands and introspection | `tests/obligations.rs` |
| crate roots | `crates/mandate-server/src/lib.rs`, `crates/mandate-proto/src/lib.rs` | `mod` lines, crate docs; `tests/conformance.rs` | — |
| document | `docs/architecture/adapter-contract.md` | the adapter contract the registry is the code of (`runtime-decisions.md:118`); the gate reads every `docs/architecture/*.md` (`xtask/src/documents.rs:153-175`) | — |

- **Gate:** `cargo fmt -p mandate-server -p mandate-proto -- --check`; `cargo clippy -p mandate-server -p mandate-proto --all-targets --locked -- -D warnings`; `cargo test -p mandate-server -p mandate-proto --locked`, counts reported; `cargo xtask documents --root .`.
- **`decision-blocker:guards`** (`runtime-decisions.md:117-121`): this story produces items 1, 2, 3 and the table half of 5; item 4 (the `TokenExchangeDenied` durable audit) stays with `story:protocol-adapters`' `denial` unit behind `decision-blocker:audit-routing`; the blocker does not clear here.
- **Left with `story:protocol-adapters`:** `metadata` (RFC 8414 shape), `denial`, `ingress` (both outside `mandate-server`'s ceiling — `AuditRecord` is `mandate-model` — and behind `decision-blocker:audit-routing`), the exchange, SCIM, revocation rows of the route table, and the three draft edges.
- **Drift found:** `runtime-decisions.md:117` says 59 commands (61 now); the `serve` refusal is at `xtask/src/main.rs:459-474` over six binaries; the `context` unit's evidence type is `crates/mandate-types/src/record.rs:57-95`, not `record.rs:63-94` of federation; `audit.yaml:113` is a `CredentialRevoked` field, not `RecordAuditEvent`.

### Would collide with

Any unit touching `crates/mandate-server/**` or `crates/mandate-proto/src/lib.rs`; not `services/sts/**`, not `crates/mandate-federation/**`; `story:product-listener` shares no file (its files are `services/sts/src/serve.rs`, `crates/mandate-federation/src/adapters.rs`, the manifests and `xtask/src/main.rs`).

## Exclusions

Any listener, socket, `serve`, async (`story:product-listener`); the denial-audit path (`story:protocol-adapters`, `decision-blocker:audit-routing`); `generated/**`; `tests/security/cases.json`; `#[ignore]`.

- Addendum at the wave D opening: the `metadata` unit (the RFC 8414 document shape and the JWKS document shape built from the route table; nothing served, no key material) joins this story — `story:product-listener` serves both documents and its acceptance names the served metadata; files `crates/mandate-server/src/metadata.rs`, `tests/metadata.rs`.

## Rulings — wave D opening, 2026-09-19

Coordinator, after `review-result:wave-d-design-r1`.

1. **`context` becomes `decode`.** No road command declares a `context` input (`federation.yaml` `AuthenticateFederation`: `connection_id`, `proof`; `AuthorizePublicClient`: the session proof and the request fields; `credential.yaml` `RedeemAuthorizationCode`: client, code, verifier, redirect; `IntrospectCredential`: two proofs), and `crates/mandate-federation/src/lib.rs:360-372` records that `VerifiedContext`'s `credential` had no source on them. The road unit is therefore the decoding boundary: one decoder per road command building exactly the declared input from the wire form, refusing undeclared fields, passing no selector through. `VerifiedContext` from credential evidence and the `credential-containment` case stay with `story:protocol-adapters`' product routes.
2. **`metadata` is this story's** (the addendum stands; the Scope's "left with `protocol-adapters`" line is corrected below).
3. **Route paths.** The `routes` unit proposes them against `docs/sources/original-design.md:1784-1796,1855-1862`; the coordinator reviews and fixes them at the unit's adversary pass and records them in this story; that review is the one `story:protocol-adapters` reserved. Reported to the operator with the wave.
4. **`story:invariant-boundary-validation`** names the context unit as its mitigation surface; `depends_on story:login-adapters` recorded there.

- Correction at the wave D opening: the `metadata` unit is `story:login-adapters`' (not left with `story:protocol-adapters`); the `context` unit is `decode` (ruling 1). The Units table above reads with those two changes.

- Corrections at the wave D opening, after `review-result:wave-d-parallel-r1`: (a) `story:product-listener`'s files are `services/control-plane/**` (ruling D1); the collision statement above that names `services/sts/src/serve.rs` and `crates/mandate-federation/src/adapters.rs` is withdrawn — the two stories share no file. (b) The coordinator writes `xtask/src/main.rs` (`LIBRARIES` 17 → 18) and `dependency-boundaries.json` (the `mandate-control-plane` key) in the wave's opening commit, before this story's tree is cut; this story writes neither. (c) The RFC 8414 metadata and JWKS document paths (`/.well-known/oauth-authorization-server`, `/oauth/jwks`) are entries of this story's route table (`crates/mandate-server/src/routes.rs`), so the disjointness proof covers them; the listener serves the table and nothing outside it. (d) `story:declared-writers` (active) holds `systems/**` and `generated/**`; no unit of it runs in wave D, so the 61 `generated/openapi/*.yaml` operationIds this story's `obligations` equality and disjointness proof pin are fixed for the wave.

- Coordinator review of the route paths (ruling 3), at the unit's adversary pass 1, 2026-09-19: accepted as proposed — `POST /v1/federation/login` (`AuthenticateFederation`; the act, not the connection, in the path), `GET /oauth/authorize` (`AuthorizePublicClient`, `original-design.md:1857`), `POST /oauth/token` (`:1858`), `POST /oauth/introspect` (`:1860`), `GET /.well-known/oauth-authorization-server` (`:1855`), `GET /oauth/jwks` (`:1862`). The session proof at the authorization endpoint travels in `Authorization: Bearer`, never in the query string; a cookie-borne session adapter for browser redirects is named residue for `story:product-listener`. `ErrorCode` carries `unsupported_response_type` as a sixth code (RFC 6749 §4.1.2.1) — accepted. Reported to the operator with the wave.

- Correction round 1 landed (2026-09-19): the twelve findings closed as ruled, each as its class (one `credential()` helper over five wire credential fields; every decoder through `single_header`; one `entry()` ceiling gate; `free_text()` over `state`, `nonce`, `redirect_uri`, `scope`; `Jwk::ADMITTED_PARAMETERS` enforced twice; `code_for_reason` exhaustive; a class check that no redemption-reachable clause answers `invalid_scope`/`invalid_client`). The coordinator restated the CRLF adversary case to the ruled refusal (`Refusal::ControlCharacter`). One factual correction to ruling 1's parenthetical: `ExpiryUnbounded` is reachable at the token endpoint (`services/sts/src/redemption.rs:342-349`); the `invalid_request` mapping stands with the cost stated in `oauth.rs` (§5.2's closed set names the caller for a condition it cannot correct). Two crates 110 → 140 tests.

- Adversary pass 2 (2026-09-19): 2 blockers, 4 warnings, 2 notes, rulings in `review-result:wave-d-login-adapters-adversary-2`; the coordinator amended adversary cases 2, 4, 5 and 6 to the rulings (call-following reachability; `QueryNotAdmitted`; class `Cc`); correction 2 dispatched, the last round.

- Correction 2 result (2026-09-19): 155 tests across the two crates, clippy clean, `documents` and `boundaries` green; unit committed as `d3f6445`, merged as `6c4c397`. Coordinator deviations: the implementor's clippy patch for the coordinator's amended adversary file (dead helper, collapsible `if`) and its F7 patch (`Jwk.parameters` private with an accessor, the rendering filter removed, the two adversary-1 struct literals rewritten through `Jwk::new`) were applied by the coordinator, since both touch coordinator-owned adversary files. `ClientNotPublic` also answers `invalid_grant` (the call-following check reached it).
