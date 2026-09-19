---
format: aep.planning-md/1
id: story:oauth-transaction
kind: story
status: active
title: Issue and redeem authorization codes at the STS, behind ports
relations:
- decomposes: epic:sts-credentials
- serves: vision:mandate
- depends_on: story:credential-profiles
- depends_on: story:pkce-sessions
- informed_by: story:oauth-integration
- depends_on: story:declared-writers
scope:
- confidence: inferred
  path: crates/mandate-federation/src/lib.rs
- confidence: inferred
  path: crates/mandate-token/src/projection.rs
- confidence: inferred
  path: crates/mandate-token/tests/contract_agreement.rs
- confidence: inferred
  path: crates/mandate-token/tests/projection.rs
- confidence: inferred
  path: services/sts/src/binding.rs
- confidence: inferred
  path: services/sts/src/code.rs
- confidence: cited
  path: services/sts/src/lib.rs
- confidence: inferred
  path: services/sts/src/redemption.rs
- confidence: inferred
  path: services/sts/src/store.rs
- confidence: inferred
  path: services/sts/tests/binding.rs
- confidence: inferred
  path: services/sts/tests/code.rs
- confidence: cited
  path: services/sts/tests/contract_agreement.rs
- confidence: inferred
  path: services/sts/tests/emitted_events.rs
- confidence: inferred
  path: services/sts/tests/redemption.rs
- confidence: inferred
  path: services/sts/tests/replay.rs
- confidence: inferred
  path: services/sts/tests/store.rs
- confidence: cited
  path: tests/security/cases.json
revision: 8
---
# Issue and redeem authorization codes at the STS, behind ports

Split from `story:oauth-integration` at the wave C opening (2026-09-19): that story keeps its acceptance over the actual OAuth endpoint and its `depends_on` the endpoint stories; this one carries the STS-side transaction that the endpoint will bind to transport, and depends on nothing that is not on `main`.

## Acceptance

Given a fresh authorization code issued through `IssueAuthorizationCode`, when the public client redeems it through `RedeemAuthorizationCode` with the matching PKCE verifier, client and redirect, then exactly one correctly scoped credential is issued and recorded in the log, a second redemption of the same code is the declared wrong-state outcome, and two concurrent redemptions issue at most one credential.

## Required observations

The `AuthorizationCode` record folds from `AuthorizationCodeIssued` and `AuthorizationCodeRedeemed` and rebuilds from `&[]`; the code's verifier is stored non-reversibly through `CredentialDomain::AuthorizationCodeVerifier`; redemption re-reads the client, the exact redirect, the tenant, and the session's epochs through a port declared here with a `pub` double; the one-winner race is a compare-and-set on expected stream version through an event-log port with a `pub` in-memory fake; every accepted outcome emits exactly its declared event, validated against the schema and payload sources; every denied path emits nothing and leaves the fold unchanged; the `pkce-valid`, `pkce-wrong`, `pkce-redirect`, `pkce-reuse` corpus cases as named tests; `pkce-missing` and `pkce-plain` as unrepresentability statements at the STS (the wire refusal is `story:protocol-adapters`'); `pkce-state-nonce` reassigned to `AuthorizePublicClient`'s owner.

## Scope

Derived 2026-09-19 by `story-scoper` on `main` at `7f3bcd7` (wave B merged). **cited** = read from the tree; **inferred** = a reading that could be wrong.

- **Primary surface:** `services/sts` — cited; every unit lands there. `crates/mandate-token` is not edited: `CredentialDomain::AuthorizationCodeVerifier` exists (`crates/mandate-token/src/verifier.rs:76-81`) and `AccessCredential` is consumed, not re-declared.
- **The record's home:** `services/sts/src/store.rs` — cited three ways: `crates/mandate-token/src/projection.rs:14-16` ("`services/sts` owns the code record"), `docs/architecture/ownership.md:15` ("STS: the authorization-code projection"), `services/sts/src/lib.rs:137-140`. The new fold type needs a name distinct from `mandate_token::projection::Projection` — inferred.

### Units — one implementor; rows in order

| Unit | Files (to create) | Symbols | ESS | Test file |
|---|---|---|---|---|
| U1 `store` | `src/store.rs`, `tests/store.rs` | the `AuthorizationCode` record, its `State`, its event enum with `ess_name()`, fold and `apply`; the expected-version append port and its `pub` in-memory fake — inferred | entity `credential.yaml:113-163`, `.State` `:136-147` — cited | `tests/store.rs` |
| U2 `code` | `src/code.rs`, `tests/code.rs` | decider in the landed shape (`services/sts/src/issue.rs:341-351`); verifier through `verifier_in(.., CredentialDomain::AuthorizationCodeVerifier, ..)` (`crates/mandate-token/src/verifier.rs:81,106`) — cited | `IssueAuthorizationCode` (`credential.yaml:435-485`) → `AuthorizationCodeIssued` (`:675-698`) — cited | `tests/code.rs` |
| U3 `binding` | `src/binding.rs`, `tests/binding.rs` | the session/epoch read port (a narrowed mirror of `mandate_identity::IdentityRead`, `crates/mandate-identity/src/port.rs:175-202`, over `mandate-types` values alone) and its `pub` double; the client, exact-redirect and tenant re-reads the denial names (`credential.yaml:239`) — cited | — | `tests/binding.rs` |
| U4 `redemption` | `src/redemption.rs`, `tests/redemption.rs` | the decider and the one command-path function that appends through the port — the first in this crate — inferred | `RedeemAuthorizationCode` (`credential.yaml:209-245`) → `AuthorizationCodeRedeemed` (`:583-590`); `wrong-state` `:235-237` — cited | `tests/redemption.rs` |

U5 `audit` (the denial-audit stand-in) is residue: `docs/architecture/audit-routing.md:10-27` has no row for code issuance or redemption and `decision-blocker:audit-routing` holds the vocabulary — cited.

- **Gate:** `cargo fmt -p mandate-sts -- --check`; `cargo clippy -p mandate-sts --all-targets --locked -- -D warnings`; `cargo test -p mandate-sts --locked`, counts reported.
- **Minimum set for the acceptance:** U1–U4 — inferred.

### Coordinator-owned — pre-landed in the opening commit; no unit edits them

- `services/sts/src/lib.rs` — cited: the `pub mod` block (`:44-47`), the `realizes!` rows (`:68-94`), `ESS_UNREALIZED` (`:129-153`: `IssueAuthorizationCode`, `RedeemAuthorizationCode`, `AuthorizationCode`, `AuthorizationCodeIssued`, `AuthorizationCodeRedeemed` struck; `AuthorizationCode.State` moved into the registry once the STS folds it, `mandate-federation` keeping a port view), `IdentityAllocator::next_authorization_code_id` (`:185-192`; `credential.yaml:482-483` binds `code_id` from the response).
- `services/sts/tests/contract_agreement.rs` (`:205`, `:233-260`), `tests/emitted_events.rs`, `tests/replay.rs` — the new command and record need rows by those files' own conventions.
- `services/sts/src/main.rs` stays the stub — cited; `xtask/src/main.rs:464,471-473` keeps asserting `serve` fails.
- `tests/security/cases.json` — the coordinator reassigns `pkce-state-nonce` to `story:pkce-sessions` (state and nonce are `AuthorizePublicClient`'s inputs, `crates/mandate-federation/src/authorize.rs:155-162`; neither STS command takes them, `credential.yaml:210-220,436-454`).
- Not touched: `dependency-boundaries.json`, `Cargo.toml`, `Cargo.lock`, `xtask/`, `crates/mandate-token/**`. `eventlog-core` is not admitted to `mandate-sts` (its entry lists no `eventlog-*`; the `external` list is the fallback for packages with no entry, `xtask/src/main.rs:215`) and is not taken: `docs/adr/0009-event-sourced-persistence.md:17` — the CAS is the kit's own and no second mechanism is introduced — so the fake is a test double with the kit's shape (one append group per boundary, compare-and-set on expected stream version, callbacks committing inside the group or rolling back with it), which advances `decision-blocker:epoch-atomicity` and does not clear it (`runtime-decisions.md:141` also wants each boundary's isolation level named).

### The control plane's call — a value, not a port

`crates/mandate-federation/src/authorize.rs:21-23`: `IssueAuthorizationCode` is assembled as an input (`IssueAuthorizationCodeInput`, `:194-213`, carried on `ValidationCandidate.issuance` `:248`) and never called. The STS-side decider satisfies it through the composition, by value; no `mandate-sts → mandate-federation` edge; the adapter is `story:product-listener`'s (`port-adapters`).

### Contract gaps — routed to `story:declared-writers` (contract round, before U4 is cut)

1. `RedeemAuthorizationCode.accepted` emits `AuthorizationCodeRedeemed` alone (`credential.yaml:222-224`), carrying `context`, `code_id`, `descriptor` and no `credential_id` (`:583-590`), with `moves: AuthorizationCode.consume` (`:232`) and no `creates:` — the credential the acceptance counts is not in the log. The wave C contract round gives `AuthorizationCodeRedeemed` the fields the `AccessCredential` record needs (`credential_id` from the response, `reference_verifier` generated) and declares in the `credential.yaml` header that it also seeds an `AccessCredential` (the one-subject-per-outcome limit, routed to the ESS wave as before).
2. `RedeemAuthorizationCode` takes no `context` (`:210-220`) while its event declares `context: generated: true` (`:227-228`) and its denial names a stale source/session epoch (`:239`): both come from the code record (`:120-121`) through U3's port — stated in the outcome summary.
3. `pkce_verifier` is non-optional (`:217-218`); `pkce-missing` is the adapter's case (`story:protocol-adapters`), noted on the corpus row.

### Would collide with

- Any unit editing `services/sts/src/lib.rs` — coordinator-owned this wave.
- `story:constrained-exchange` — scope is the bare directory `services/sts`; refine before scheduling either.
- `services/sts/tests/{contract_agreement,emitted_events,replay}.rs` — `story:credential-profiles`' files, merged; coordinator rows.
- `systems/mandate/domains/credential.yaml`, `generated/**` — `story:declared-writers`'; the contract gaps land there and are regenerated before U4.

## Exclusions

Any HTTP route, `serve`, form encoding, standard OAuth error bodies (`story:protocol-adapters`, `story:product-listener`); `AuthorizePublicClient` (landed in `mandate-federation`); `ExchangeCredential` (`story:constrained-exchange`); the audit record (`decision-blocker:audit-routing`); `#[ignore]`.

- Collisions addendum (wave C opening, after `review-result:wave-c-parallel-r1`): `story:product-listener` holds `services/sts/src/lib.rs` as cited scope and declares a coordinator `mod serve;` edit; it is not selected this wave and is sequential by its `depends_on` chain, so the file is this story's implementor's for wave C and returns to the coordinator when that story is scheduled.

## Rulings — wave C opening, 2026-09-19

Coordinator, after `review-result:wave-c-parallel-r1` and `review-result:wave-c-design-r1`.

1. **Order.** This story's tree is cut after `story:declared-writers`' contract round 2 has merged and the coordinator has regenerated; `depends_on story:declared-writers` records it (design 5).
2. **The credential the redemption issues.** The contract round gives `AuthorizationCodeRedeemed` every field the `AccessCredential` record needs, mirroring `CredentialReferenceIssued`'s record fields (`credential_id` and `target` from a widened response, `descriptor` as today, `reference_verifier` and `issued_at` generated by the outcome), and declares in the `credential.yaml` header that the event seeds an `AccessCredential` beside the `moves: AuthorizationCode.consume` it already declares (design 3). The fold arm that materializes that record lives with the other credential records: this story edits `crates/mandate-token/src/projection.rs` for that one arm and its tests (`story:credential-profiles` is implemented; no other story holds the crate this wave) (design 2).
3. **One realizer.** When the STS folds `AuthorizationCode`, `mandate.credential.AuthorizationCode.State` is realized by `mandate-sts` alone; this story removes it from `crates/mandate-federation/src/lib.rs`'s registry (federation's `AuthorizationCodeState` stays a port view, as wave B did for `Principal.State`) and its gate runs `cargo test -p mandate-federation` as well (design 4).
4. **Ownership.** `services/sts/src/lib.rs` is this story's implementor's this wave (the registry rows, `ESS_UNREALIZED`, the allocator method); the "coordinator-owned" line in the Scope is superseded (the wave B precedent).
5. **Corpus.** `pkce-valid`, `pkce-wrong`, `pkce-redirect`, `pkce-reuse` are this story's rows; `pkce-missing`, `pkce-plain` are `story:protocol-adapters`'; `pkce-state-nonce` stays `story:oauth-integration`'s (`story:pkce-sessions` owns no corpus case) (design 6).
6. **The fake.** The event-log port's `pub` in-memory compare-and-set fake is a test double, not a second durable mechanism; `decision-blocker:epoch-atomicity` is advanced by the race case and not cleared.
