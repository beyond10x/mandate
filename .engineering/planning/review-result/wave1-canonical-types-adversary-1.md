---
format: aep.planning-md/1
id: review-result:wave1-canonical-types-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — canonical types, wave 1
relations:
- reviews: story:canonical-types
revision: 1
---
```
unit: story:canonical-types — worktree mandate-w1-canonical-types, branch impl/canonical-types, uncommitted working tree over base dc76aa3
verdict: NEEDS-CHANGE
cases: executed 54→62, red 4
origin: introduced 7 / pre-existing 0 / undecided 0
needs-coordinator: whether mandate-proto may add mandate-model/mandate-token to its dependency-boundaries.json array (finding 2) — the story's allocation line and the implementor's stated blocker disagree
```

`<before>` = 54 is the implementing state's own green run. No suite was run before the cases existed.

The adversary modified no tracked file. `git --no-pager diff --numstat` lists zero paths under `tests/`. It added four untracked test files, 311 lines: `crates/mandate-{types,model,token,proto}/tests/adversary.rs`. No implementation file was touched. No existing case was deleted, skipped, weakened or rewritten.

## The four red cases, each run alone before the suite

`mandate-proto/tests/adversary.rs:28` — `OrganizationId::from_wire` refuses a `PrincipalId` wire form. RED: `a PrincipalId wire form decoded into an OrganizationId: Ok(OrganizationId(Uuid([27, 78, 40, 186, ...])))`, exit 101.

`mandate-proto/tests/adversary.rs:103` — every accepted type the projection puts on the wire carries a `WireContract`. RED: `accepted types the projection puts on the wire with no WireContract: ["mandate.core.AuditRecord", "mandate.core.CredentialDescriptor", "mandate.core.CredentialProfile", "mandate.core.Decision", "mandate.core.DecisionChallenge", "mandate.core.TenantResolutionRule"]`, exit 101.

`mandate-types/tests/adversary.rs:72` — `AuthorityScope` refuses `{"space":null}`, a form the projection does not declare. RED: `decoded an undeclared wire form {"actions":[],"resources":[],"space":null} into Ok(AuthorityScope { actions: [], resources: [], space: None })`, exit 101.

`mandate-model/tests/adversary.rs:85` — no persisted record's wire form carries credential material in any wrapper. RED: `credential material reached a persisted record's wire form: {"correlation":"correlation","secret":"YWJj"}`, exit 101.

Four control cases green: each `compile_fail` body compiles once exactly one token changes, which is what makes the corresponding case a proof rather than an accident.

## Suite

`cargo test --workspace --locked --no-fail-fast`: executed 62, passed 58, failed 4, exit 101. `cargo clippy` on the four packages exits 0 with the new files present, so the red is assertion failure and nothing else. `task check` exits 201 under a custom `CARGO_TARGET_DIR` — known, pre-existing, not counted.

## Findings

1. `crates/mandate-proto/src/lib.rs:42` — NEEDS-CHANGE / introduced / **blocker**. The doc on `WireError::Decode` says "Decoding refuses; it never coerces one identifier into another", and `:20` says "A wire form decoded into the wrong identifier is a refusal, not a coercion". `OrganizationId::from_wire` of a `PrincipalId` wire form returns `Ok`. What reaches it: `WireContract::from_wire`, a public default method on a public trait, documented at `:74-81`. The unit's own `proto/tests/conformance.rs:58` asserts the two wire forms are *equal*, which makes refusal impossible — two halves of one commit disagree. Fix: delete the false sentence at `:20` and `:42`; identifier separation here is type-level only and the doc must say so.
2. `crates/mandate-proto/src/lib.rs:147` — NEEDS-CHANGE / introduced / warning. `WIRE_CONTRACTS` covers the 68 `Owner::Types` types. Six accepted types the projection names in `generated/schema/{commands,responses,events}` carry no `WireContract`. Token-boundary matched, not substring. The rationale at `crates/mandate-types/src/inventory.rs:50` — admitting model and token "would reverse the declared dependency direction" — is not supported by `dependency-boundaries.json`: only `mandate-client` and `mandate-server` depend on `mandate-proto`, so neither `mandate-model` nor `mandate-token` does, and the edge is new rather than reversed. It moves neither of xtask's 20/14 counts.
3. `crates/mandate-types/src/record.rs:37` — CONFIRMED / introduced / warning. The projection declares `AuthorityScope.space` as `$ref mandate.core.SpaceId` = `{"type":"string",...}`; `null` is not a declared form. `#[serde(default, skip_serializing_if)]` with `Option<T>` accepts it and decodes to `None`, and it is not a fixed point — re-serializing omits the key. Untrusted wire input on a public decoder; no privileged state needed. Systemic: the same attribute pair is on 3 fields in `record.rs`, 4 in `Decision`, 17 in `AuditRecord`, 2 in `TenantResolutionRule`, 2 in `CredentialDescriptor`. The unit's own optional-field case covers omitted and present; this is the third wire state.
4. `crates/mandate-types/src/marker.rs:18` — INFEASIBLE / introduced / warning. The test file compiled: `canonical_record!` admitted a field of type `Envelope<CredentialSecret>` where `Envelope` is local to the test crate with a hand-written `impl PersistedValue`. `marker.rs:7-10` claims the orphan rule refuses every outside impl and that "the guarantee is therefore the absence of an impl here"; `macros.rs:154` claims no record can hold one "in any wrapper". Both are false for a local wrapper over the foreign type, which the orphan rule permits. INFEASIBLE because it needs a future author to write one `impl` line, not because it does not hold. Nothing in the tree reaches it — the state was built.
5. `crates/mandate-proto/src/lib.rs:23` — CONFIRMED / introduced / warning. The `compile_fail` body is `let organization: OrganizationId = principal.to_wire().unwrap();`. `to_wire` returns `Result<String, _>`, so the annotation is compared against `String`. The control compiles with `String` and nothing else changed, and naming `PrincipalId` leaves the case failing identically. `cargo test --doc` reports it green, so the suite records a proof of identifier separation the case does not perform. The other seven `compile_fail` cases are sound — their controls compile with exactly one token changed.
6. `crates/mandate-types/tests/inventory.rs:172` — CONFIRMED / introduced / note. The pattern scan reads `document["$defs"][entry.ess_name].get("pattern")`, the top-level node only, and does not descend into `properties`. The test's name is broader than what it decides. Nothing today: the whole `generated/schema` tree was re-derived and declares exactly the two patterns the test names. It becomes live on the first regeneration putting a `pattern` on an inline string property.
7. `crates/mandate-model/Cargo.toml:16` — CONFIRMED / introduced / note. `serde_json` is a regular, non-dev dependency of `mandate-model` and `mandate-token` and appears in no library source of either. Same at `crates/mandate-token/Cargo.toml:16`. `dependency-boundaries.json` now permanently permits it as a runtime dependency of two crates that do not use it, and the policy file cannot express "test-only".

All seven are `introduced`: at `dc76aa3` all four crates are 4-line `//!` scaffolds with no items and no `tests/` directory, so nothing reproduces against the base.

## Attacked and could not break

The inventory account, re-derived independently from `generated/schema`: 110 type entries, 74 `mandate.core.*`, 36 `.State` all non-core and none accepted; 36 entities; the three ownership placeholders carry exactly `{id, state}`. Every claim holds.

The `x-ess-kind` breakdown: 55 newtype / 8 enum / 9 struct / 2 union, and within the newtypes 34 `format: uuid` / 19 plain string / 2 base64 — set-identical to `identifier.rs` (34), `text.rs` (19), `credential.rs` (2). No type is in the wrong declaration macro in either direction.

Every struct against its projection: 9 structs, 76 properties; field names, `required` versus `Option<T>`, and every `$ref` match exactly. 8 enums / 38 variants and both unions' tags and variant titles match.

The "set equals the `Owner` share" assertions are not tautologies: the chain is `generated/schema` file names → `ACCEPTED` → the per-crate macro declaration lists → `wire_contracts!`, three independently authored lists each pinned to the next.

Zero references to `CredentialSecret`/`CredentialProof` in `entities` or `events`; 6 and 6 in `commands`/`responses` where they belong.

`canonical_record!`'s field-omission guard: a field not named is `E0027`. The full set of `PersistedValue` impls is closed and enumerable — no `Box<T>`, `&T`, tuple, array or `u8` impl exists, so no in-tree container launders a transient value without a new impl, which is finding 4.

base64 and UUID codecs: padding 0/1/2, empty input, `=` inside the body, trailing-bit rejection, uppercase UUID rendering as lower-case canonical output, separator positions. No accepted non-canonical form, no lossy round-trip.

Round-trip honesty: `conformance::check` serializes, re-serializes for determinism, decodes, compares, re-serializes for fixed point, and refuses every `REJECTED_WIRE` form — for all 74, not a sample.

`Cargo.lock` gained no `[[package]]` entry. The brief's `xtask/src/main.rs:113` is the `publish` check; the dependency loop is `:117`, the fallback `:119`, the 20/14 assert `:104`. The implementor's correction is right and the counts are unmoved.

```findings
- file: crates/mandate-proto/src/lib.rs
  line: 42
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: the doc promises decoding never coerces one identifier into another but OrganizationId::from_wire accepts a PrincipalId wire form and returns Ok, contradicting the unit's own test that asserts the two wire forms are equal
- file: crates/mandate-proto/src/lib.rs
  line: 147
  category: acceptance
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: six accepted types the projection names in commands, responses and events carry no WireContract, and the stated reason at inventory.rs:50 is unsupported because nothing in dependency-boundaries.json makes mandate-model or mandate-token depend on mandate-proto
- file: crates/mandate-types/src/record.rs
  line: 37
  category: boundary
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: an optional field decodes explicit JSON null, which the projection does not declare for it, and the resulting wire form is not a fixed point
- file: crates/mandate-types/src/marker.rs
  line: 18
  category: judgement
  severity: warning
  verdict: INFEASIBLE
  origin: introduced
  message: PersistedValue is unsealed, so a downstream crate can implement it for a local wrapper over CredentialSecret and canonical_record! admits the field, falsifying the absolute guarantee claimed at marker.rs:7 and macros.rs:154
- file: crates/mandate-proto/src/lib.rs
  line: 23
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: the compile_fail case offered as proof that the identifier types do not convert fails on a String/OrganizationId mismatch and passes identically whichever identifier is named, so it proves nothing about identifier separation
- file: crates/mandate-types/tests/inventory.rs
  line: 172
  category: mutant
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: the pattern scan reads only the top-level $defs node, so a pattern declared on a nested inline string property would satisfy a test whose name claims the projection declares no pattern the suite does not enforce
- file: crates/mandate-model/Cargo.toml
  line: 16
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: serde_json is a regular rather than dev dependency of mandate-model and mandate-token and is used by no library source in either, so the boundary policy now permits it at runtime in two crates that do not need it
```
