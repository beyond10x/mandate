---
format: aep.planning-md/1
id: story:testkit-doubles
kind: story
status: draft
title: Test doubles live in mandate-testkit, not in library crates
relations:
- decomposes: epic:foundations
- serves: vision:mandate
- depends_on: story:federation-linking
- depends_on: story:session-epochs
- depends_on: story:graph-policy
scope:
- confidence: cited
  path: Cargo.lock
- confidence: cited
  path: crates/mandate-federation/Cargo.toml
- confidence: cited
  path: crates/mandate-federation/src/lib.rs
- confidence: cited
  path: crates/mandate-federation/src/verifier.rs
- confidence: cited
  path: crates/mandate-federation/tests/adversary_pass1.rs
- confidence: cited
  path: crates/mandate-federation/tests/adversary_pass2.rs
- confidence: cited
  path: crates/mandate-federation/tests/authenticate.rs
- confidence: cited
  path: crates/mandate-federation/tests/link.rs
- confidence: cited
  path: crates/mandate-federation/tests/record.rs
- confidence: cited
  path: crates/mandate-federation/tests/verifier.rs
- confidence: cited
  path: crates/mandate-graph/Cargo.toml
- confidence: cited
  path: crates/mandate-graph/src/double.rs
- confidence: cited
  path: crates/mandate-graph/src/lib.rs
- confidence: cited
  path: crates/mandate-graph/tests/adversary_double.rs
- confidence: cited
  path: crates/mandate-graph/tests/adversary_double_2.rs
- confidence: cited
  path: crates/mandate-graph/tests/double.rs
- confidence: cited
  path: crates/mandate-graph/tests/port.rs
- confidence: cited
  path: crates/mandate-graph/tests/revocation.rs
- confidence: cited
  path: crates/mandate-identity/Cargo.toml
- confidence: cited
  path: crates/mandate-identity/src/lib.rs
- confidence: cited
  path: crates/mandate-identity/src/port.rs
- confidence: cited
  path: crates/mandate-identity/tests/adversary_expiry.rs
- confidence: cited
  path: crates/mandate-identity/tests/adversary_lifecycle.rs
- confidence: cited
  path: crates/mandate-identity/tests/adversary_monotonic.rs
- confidence: cited
  path: crates/mandate-identity/tests/adversary_ordering.rs
- confidence: cited
  path: crates/mandate-identity/tests/adversary_timestamp_form.rs
- confidence: cited
  path: crates/mandate-identity/tests/increment.rs
- confidence: cited
  path: crates/mandate-identity/tests/port.rs
- confidence: cited
  path: crates/mandate-identity/tests/refresh.rs
- confidence: cited
  path: crates/mandate-identity/tests/staleness.rs
- confidence: cited
  path: crates/mandate-identity/tests/surface.rs
- confidence: cited
  path: crates/mandate-policy/Cargo.toml
- confidence: cited
  path: crates/mandate-policy/src/double.rs
- confidence: cited
  path: crates/mandate-policy/src/lib.rs
- confidence: cited
  path: crates/mandate-policy/tests/adversary_precedence.rs
- confidence: cited
  path: crates/mandate-policy/tests/adversary_precedence_2.rs
- confidence: cited
  path: crates/mandate-policy/tests/double.rs
- confidence: cited
  path: crates/mandate-testkit/Cargo.toml
- confidence: inferred
  path: crates/mandate-testkit/src/federation.rs
- confidence: inferred
  path: crates/mandate-testkit/src/graph.rs
- confidence: inferred
  path: crates/mandate-testkit/src/identity.rs
- confidence: cited
  path: crates/mandate-testkit/src/lib.rs
- confidence: inferred
  path: crates/mandate-testkit/src/policy.rs
- confidence: inferred
  path: crates/mandate-testkit/tests/surface.rs
- confidence: cited
  path: dependency-boundaries.json
revision: 4
---
# Test doubles live in mandate-testkit, not in library crates

## Acceptance

Given the workspace after wave 2, when `cargo doc` is read for `mandate-federation`, `mandate-identity`, `mandate-graph` and `mandate-policy`, then no type that admits every proof, seeds a fold around its guards, or records instead of issuing is exported by a library crate; each lives in `crates/mandate-testkit` and reaches the library crates' integration tests through a dev-dependency.

## Required observations

Filed from the wave-2 adversary passes, 2026-09-18. Integration tests are separate crates, so every double a story needed was made `pub` in the library: `mandate-federation` exports `ConstructedVerifier::admitting` (admits every proof, no cryptography), `SequentialAllocator`, `RecordingSessionIssuer`, `RecordedPrincipals` (`review-result:wave2-federation-linking-adversary-2` J3); `mandate-identity` exports `IdentityLog` with its seeding constructors behind `#[doc(hidden)]`, which removes them from rustdoc and not from the API (`review-result:wave2-session-epochs-adversary-2` F3); `mandate-graph` and `mandate-policy` export `GraphDouble` and `PolicyDouble` by the story's own design. Nothing in the gate distinguishes them from shippable code: `cargo xtask boundaries` checks dependencies, not exports. The coordinator ruled in both waves that the doubles stay `pub` until a home exists; this story is that home.

`crates/mandate-testkit` exists in the workspace (`Cargo.toml` members) and has no consumers. Adding it as a dev-dependency of the four crates touches `dependency-boundaries.json` (`xtask/src/main.rs:117-127` enforces the ceiling on dev-dependencies too), so the boundary edit is this story's and no other's.

## Scope

- **Derived:** 2026-09-18 by `story-scoper` on `integration/wave-20260918-004`, file granularity. Every line is **cited** or **inferred**.
- **Primary surface:** `crates/mandate-testkit` receives; `crates/mandate-{federation,identity,graph,policy}/src` release — cited (`docs/architecture/ownership.md:20` gives testkit "fixtures and future conformance/security support").
- **Doubles today, all `pub` — cited:**
  - `crates/mandate-federation/src/lib.rs:296` `SequentialAllocator`, `:342` `RecordedPrincipals`, `:410` `RecordingSessionIssuer`; private `const fn minted :310` shared by two of them. Removal range `:288-444`. Crate docs `:12-14` and `:17-22` intra-doc-link all three and become false.
  - `crates/mandate-federation/src/verifier.rs:105` `ConstructedVerifier` (`:92-160`). Private `fn admitted :163-171` encodes `decision-blocker:algorithm-policy` (empty allowlist refused) — library behaviour a real verifier also needs, so it stays and turns `pub` — inferred.
  - `crates/mandate-identity/src/port.rs:219` `IdentityLog` (`:190-419`); re-exported at `src/lib.rs:126-128`; the crate-root doctest `src/lib.rs:44-70` constructs it. The three `#[doc(hidden)]` `IdentityEvent` variants (`port.rs:156,:165,:177`) stay: `port.rs:134-136` assigns un-hiding to `story:event-payloads-for-folds`. Module doc `port.rs:129-145` must be rewritten.
  - `crates/mandate-graph/src/double.rs:52` `GraphDouble`, whole file (497 lines); `pub mod double;` `src/lib.rs:72`.
  - `crates/mandate-policy/src/double.rs:38` `PolicyDouble`, whole file (322 lines); `pub mod double;` `src/lib.rs:59`.
- **Direction today:** `mandate-testkit` → `mandate-types`, `mandate-model`, `mandate-authz` (`crates/mandate-testkit/Cargo.toml:13-16`); no crate names testkit — cited. After the move testkit depends on all four libraries while each library dev-depends on testkit.
- **Is that cycle legal:** yes — cargo permits `[dev-dependencies]` on a crate that itself depends on the current crate (`tokio`↔`tokio-test` shape) — inferred from cargo semantics, proven by the first `--locked` test run after the pre-land. Consequence: `#[cfg(test)]` code in `src/` cannot use testkit's doubles for that crate's own traits; none of the four crates has `#[cfg(test)]` or `#[test]` under `src/` — cited; standing rule from now on. `cargo doc -p <lib>` builds no dev-deps, so the doubles leave the rendered docs — the acceptance.
- **Recommendation, option A:** testkit depends on the four; the four dev-depend on testkit; doubles copied verbatim, one `use` line changed per test file. B (a `testkit` cargo feature per library) fails "each lives in `crates/mandate-testkit`". C (move the integration tests into testkit) makes `cargo test -p mandate-graph` prove nothing. A widens no API: every helper the doubles call is already `pub` (graph `relationship.rs:91,:103`, `revocation.rs:38`, `topology.rs:123`, `port.rs:87,:146`; policy `precedence.rs:150,:249`, `port.rs:239,:299,:316`; identity `port.rs:36,:52,:68`, `session.rs:86,:95`, `snapshot.rs:124`, `generation.rs:30,:52`) — cited.
- **Files, testkit side:** `crates/mandate-testkit/src/lib.rs` — cited, exists; `src/federation.rs`, `src/identity.rs`, `src/graph.rs`, `src/policy.rs`, `tests/surface.rs` — inferred. `crates/mandate-testkit/Cargo.toml:13-16` gains four path deps — cited.
- **Files, library side:** `crates/mandate-federation/src/lib.rs` (`:12-22`, `:288-444`), `src/verifier.rs` (`:92-160`; `admitted :163` → `pub`), `crates/mandate-identity/src/port.rs` (`:129-145`, `:190-419`), `crates/mandate-identity/src/lib.rs` (`:44-70`, `:126-128`), `crates/mandate-graph/src/double.rs` (deleted), `crates/mandate-graph/src/lib.rs:72`, `crates/mandate-policy/src/double.rs` (deleted), `crates/mandate-policy/src/lib.rs:59` — cited.
- **Files, integration tests (import line only, 24 files) — cited:** federation `tests/adversary_pass1.rs:17-19`, `adversary_pass2.rs:21-24`, `authenticate.rs:19-22`, `link.rs:15-18`, `record.rs:17`, `verifier.rs:11`; identity `tests/adversary_expiry.rs:19`, `adversary_lifecycle.rs:15`, `adversary_monotonic.rs:17`, `adversary_ordering.rs:25`, `adversary_timestamp_form.rs:27`, `increment.rs:6`, `port.rs:6`, `refresh.rs:7`, `staleness.rs:6`, `surface.rs:5` (`:52` pins `IdentityLog` on the identity surface — that assertion inverts); graph `tests/adversary_double.rs:7`, `adversary_double_2.rs:9`, `double.rs:8`, `port.rs:7`, `revocation.rs:14`; policy `tests/adversary_precedence.rs:9`, `adversary_precedence_2.rs:9`, `double.rs:7`.
- **Gate, per unit:** `cargo clippy -p <crate> --all-targets --locked -- -D warnings && cargo test -p <crate> --locked`. Acceptance: `cargo doc -p <crate> --no-deps` and read the index for the seven names — `cargo doc` is not in `cargo xtask check` (`:294-312`), so this is a manual read — cited.
- **Confidence:** high — every double, consumer, re-export, doctest and helper visibility was read at `file:line`; the one load-bearing inferred claim is the dev-cycle legality.
- **Would collide with:** any unit editing `crates/mandate-federation/src/{lib,verifier}.rs`; `crates/mandate-identity/src/{port,lib}.rs`; `crates/mandate-graph/src/{double,lib}.rs`; `crates/mandate-policy/src/{double,lib}.rs`; the 24 test files above; anything under `crates/mandate-testkit/`; and, via the coordinator pre-land, `Cargo.lock`, `dependency-boundaries.json` and the five manifests.
- **Sibling overlap:** `story:pkce-sessions` — `crates/mandate-federation/src/lib.rs` (disjoint hunks, same file; never the same wave); its unit B's `pub` double in `src/publicclient.rs` is the class this story removes and belongs in `crates/mandate-testkit/src/federation.rs` once this story lands. `story:check-api` — its tests cite `GraphDouble`/`PolicyDouble`; after this story `mandate-authz` needs `[dev-dependencies] mandate-testkit` and `dependency-boundaries.json:20-25` widened. `story:agent-authority-kernel`, `story:agent-security` — directory-granularity `crates/mandate-policy` covers unit P; `waves` will not report it. `story:signing-and-verification` — same `mandate-federation` array in `dependency-boundaries.json`; `verifier.rs:95-97` names that story in the doc unit F rewrites.

### Excluded (coordinator-owned; not in any unit row)

- `dependency-boundaries.json` — five arrays: `"mandate-graph"`, `"mandate-policy"`, `"mandate-identity"`, `"mandate-federation"` each append `"mandate-testkit"`; `"mandate-testkit"` appends `"mandate-federation"`, `"mandate-identity"`, `"mandate-graph"`, `"mandate-policy"` (keep `"mandate-authz"`). `xtask/src/main.rs:117-128` walks dev edges too; `:104` counts unchanged — cited. If `story:check-api` keeps using the doubles: `"mandate-authz"` appends `"mandate-testkit"` too.
- `Cargo.lock` and the five `Cargo.toml` (`[dev-dependencies] mandate-testkit = { version = "0.1.0", path = "../mandate-testkit" }` in four; four path deps in testkit's) — pre-landed with the lock and the JSON in one coordinator commit before unit T. An unused dev-dependency raises no lint (`unused_crate_dependencies` is not in `[workspace.lints]`) — cited.
- `xtask/src/main.rs`, `deny.toml`, `Taskfile.yml` — read, not edited.

### Units

Order: T first; F, I, G, P are pairwise file-disjoint and may run in parallel after T, or one agent runs T→F→I→G→P serially.

| Unit | Owns | Test file | Produces |
|---|---|---|---|
| T `mandate-testkit` | `crates/mandate-testkit/src/lib.rs`, `src/federation.rs`, `src/identity.rs`, `src/graph.rs`, `src/policy.rs` | `crates/mandate-testkit/tests/surface.rs` | the seven doubles copied verbatim; root re-exports; `surface.rs` proves each implements its library port from outside |
| F `mandate-federation` | `src/lib.rs`, `src/verifier.rs` | the six federation test files | `lib.rs:288-444` and `verifier.rs:92-160` removed, `admitted` made `pub`, crate docs rewritten; six imports re-pointed |
| I `mandate-identity` | `src/port.rs`, `src/lib.rs` | the ten identity test files | `port.rs:190-419` removed, module doc rewritten, `lib.rs:126-128` no longer re-exports `IdentityLog`, doctest `:44-70` uses `mandate_testkit::IdentityLog`; `surface.rs:52` inverted |
| G `mandate-graph` | `src/double.rs` (deleted), `src/lib.rs` | the five graph test files | `pub mod double;` gone (`lib.rs:72`) |
| P `mandate-policy` | `src/double.rs` (deleted), `src/lib.rs` | the three policy test files | `pub mod double;` gone (`lib.rs:59`) |

### Not established

- Dev-dependency-cycle legality is cargo knowledge, not proven here.
- Whether `IdentityLog` moving out of `mandate-identity` is wanted: `port.rs:139-141` also offers it "for a host that has no adapter yet"; the residual is that the three hidden `IdentityEvent` variants stay `pub` in the library.
- `crates/mandate-testkit/src/*.rs` file names and `tests/surface.rs` are the scoper's split.

## Exclusions

No behaviour change in any double. No new double. `mandate-model`'s `Tenancy`/`Topology` are folds, not doubles, and stay.
