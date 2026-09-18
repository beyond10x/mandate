---
format: aep.planning-md/1
id: review-result:wave1-canonical-types-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — canonical types, wave 1
relations:
- reviews: story:canonical-types
revision: 1
---
```
unit: story:canonical-types, worktree mandate-w1-canonical-types, branch impl/canonical-types, uncommitted over base dc76aa3
verdict: NEEDS-CHANGE
cases: executed 66→69, red 3
origin: introduced 6 / pre-existing 0 / undecided 0
needs-coordinator: retiring pass 1's unsatisfiable case — hard rule 2 forbids the adversary, and the implementor doing it would read as weakening an adversary case
```

The adversary added exactly one untracked file, `crates/mandate-proto/tests/adversary_second_pass.rs`, three cases. No implementation file touched, no existing test file modified. `rustfmt --check` exit 0, `cargo clippy -p mandate-proto --locked --tests -- -D warnings` exit 0 on it.

## Ruling on the unsatisfiability claim — the implementor is right

Verified independently rather than taken. The two `$defs` nodes are byte-identical after dropping `title` and `x-ess-name`: both `{"format":"uuid","pattern":"^[0-9a-fA-F]{8}-…","type":"string","x-ess-kind":"newtype"}`. `fn from_wire(text: &str) -> Result<Self, WireError>` at `crates/mandate-proto/src/lib.rs:101` is a function of the string alone, so `Ok` and `Err` for one string is a contradiction.

The three alternatives the coordinator asked about, ruled:

**Tagged envelope at the contract boundary — OUT.** Inside `to_wire`, `mandate-types/tests/conformance.rs:143` validates the encoded form against `$defs[ess_name]`, which is `{"type":"string"}`; an object panics at "encodes as a JSON string". `mandate-proto/src/lib.rs:151` reports a canonical-form mismatch. Pass 1's own `:45-48` pins `to_wire()` to `"\"<uuid>\""`. It trades one red for three, two of them the projection. As a separate `to_envelope`/`from_envelope` API it leaves `from_wire` untouched and does not satisfy the case. **Correction to the implementor's argument:** the gate that would break is the projection conformance suite, not `cargo xtask contracts` — that gate only byte-compares `generated/` against a regeneration, and no Rust change can move it.

**`from_wire` taking a context — OUT on merit, not feasibility.** `from_wire(text, expected: &str)` checked against `Self::ESS_NAME` is implementable and changes no ESS meaning. But the discriminating information comes from the caller's own argument, so the refusal is a tautology about the caller rather than a property of the wire form. It renames the type-level separation the unit already has, more weakly — runtime instead of compile time. It also would not compile pass 1's one-argument call.

**`parse`/`from_wire` split — OUT trivially.** Both are functions of the string alone, and the projection declares one lexical form.

The acceptance requirement "prove `PrincipalId` cannot substitute `OrganizationId`" is discharged by the compile_fail pair, verified to fail with exactly `E0308: mismatched types` and nothing else.

## The three new cases

`every_admitted_type_serializes_into_the_form_its_projection_declares` — RED. `admitted types whose serde serialization is not the declared form: ["mandate.core.CredentialSecret: serde renders \"<redacted>\", which the declared pattern ^(?:[A-Za-z0-9+/]{4})*… refuses", …]` — 3 CredentialSecret samples, 3 CredentialProof samples.

`the_declared_credential_material_is_not_reachable_without_naming_canonical` — RED. `mandate.core.CredentialSecret: WireContract::to_wire rendered the credential material: "YWJj"`.

`the_explicit_null_walk_reaches_every_field_every_record_declares` — green control. Every declared property of all 9 records appears in at least one encoded sample, so `conformance.rs:152`'s walk is non-vacuous.

Suite: `cargo test --workspace --locked --no-fail-fast` exit 101, 69 executed, 66 passed, 3 failed. 69 − 3 = 66, corroborating the unit's reported count from a second source. `cargo xtask boundaries` exit 0.

## Findings

1. `crates/mandate-proto/tests/adversary.rs:28` — CONFIRMED / introduced / **blocker**. `cargo xtask check` → `cargo test --workspace --locked` exit 101. The acceptance statement says the suite exits zero; the tree as it stands does not.
2. `crates/mandate-proto/tests/adversary.rs:25` — INFEASIBLE / introduced by adversary pass 1, not by the implementor's code / blocker-to-clear. The case demands `Ok` and `Err` from one pure function on one string. The coordinator must retire it; the implementor doing so would read as weakening an adversary case.
3. `crates/mandate-proto/tests/adversary_second_pass.rs:132` — NEEDS-CHANGE / introduced / warning. `serde_json::to_string` of all three samples of each transient type renders `"<redacted>"`, which the declared base64 pattern refuses. `Serialize` is the only rendering a derived container reaches, and 12 files under `generated/schema/{commands,responses}` `$ref` these two types. No such envelope exists in this tree yet, so nothing reaches it today — it is a wall the next unit hits on day one, invisible because the suite is green about it.
4. `crates/mandate-types/src/macros.rs:164` — CONFIRMED / introduced / warning. The doc claims the declared base64 form is reachable only through `Canonical::encode`. `CredentialSecret::to_wire()` returns `"YWJj"` — the material — from a caller that never names `Canonical`. `wire_contracts!` lists both transient types among the 74 with no marking, and `mandate-client` and `mandate-server` both depend on `mandate-proto`.
5. `crates/mandate-types/tests/inventory.rs:170` — CONFIRMED / introduced / note. Every `pattern` in the generated corpus sits at `$defs/<name>/pattern`, so a single-node read yields the same two-element set as the new full-depth walk. Reverting the recursion leaves the case green. A coverage gap, not a behaviour defect; a nested pattern could not be planted because the scan's path is compile-time fixed and mutating a generated contract is out of bounds.
6. `crates/mandate-types/src/lib.rs:142` — CONFIRMED / introduced / note. `pub mod conformance;` with `serde_json` in `[dependencies]`, so `Canonical::encode` links into every downstream crate, `mandate-audit` included.

## The six corrections, verified

| Claim | Verdict |
|---|---|
| boundaries, 74 wire contracts, direction | **Holds.** 74 entries, no duplicates, set-equal to `ACCEPTED`. `libraries` 14, packages 20, confirmed by the gate itself. `proto -> model` and `proto -> token` are new edges, no reversal and no cycle. `types -> model -> graph/policy -> authz` and `token -> types` unchanged. |
| 30 optional fields, walk not vacuous | **Holds; the implementor's count is right and the adversary's was two short.** 30 `Option<T>` fields, 30 `deserialize_with`, one to one. The control is green. |
| proto compile_fail body | **Holds.** Each body compiled standalone against the built rlibs: proto's aborts with exactly one error, `E0308`. Every other compile_fail is single-error and correct — `E0277 PersistedValue` ×4, `E0277 From<PrincipalId>`, `E0369 cannot add {integer} to EpochSnapshotRef`. |
| recursive pattern scan | **Correct but unobservable** — finding 5. |
| redaction | **Projection conformance holds for `Canonical::encode`, not for `Serialize`** — finding 3. `PersistedValue` blocks a direct field and `Option`/`Vec` of one; the local-wrapper hole is real and named honestly at `marker.rs:13-18`, and `Serialize` redacts through it. `Debug` redacts, no `Display`, `ParseError` carries no offending value. Material routes are `Canonical::encode`, `WireContract::to_wire` and `expose_bytes` + `value::encode_base64`. Redaction broke the serde round-trip for these two types deliberately and the unit's own case pins it; no other round-trip regressed. |
| `serde_json` to dev-deps | **Holds, and verifies brief decision 7.** `cargo metadata --no-deps` lists `('serde_json','dev')` inside `dependencies` for model and token — the kind is not filtered — and both keep the boundary entry. |

`cargo fmt --all` claim holds exactly: one hunk, a single `assert!` wrapped, 107 → 110, no semantic change. The other three pass-1 files carry pass-1 mtimes, before the implementor's round.

## Merge call

Do not merge as it stands, but the only blocker is bookkeeping rather than code. `task check` exits 1 because pass 1's case is red, and that case is unsatisfiable. Retire it as INFEASIBLE with the reason recorded and the gate goes green; nothing else found holds the unit. Findings 3 and 4 should land in this unit or as the first item of the wire unit. 5 and 6 are notes.

## Attacked and could not break

All 74 accepted names, `x-ess-kind` 55/8/9/2 and owners 68/4/2/0 against the projection — exact. All 8 enums' variant lists — exact, in order, none dropped or invented. All 9 structs' property sets, `required` sets and per-property `$ref` targets — exact, no field missing, none extra, no optionality inversion. All 53 string newtypes: every uuid-realized type declares `format: uuid` and the uuid pattern, every text-realized type declares neither. base64 boundaries: empty, `"A"`, `"A==="`, `"===="`, `"=AAA"`, non-canonical trailing bits, padding over 2, `+`/`/` alphabet — correct and inverse. UUID boundaries: length, separator positions, the index-34 read, non-ASCII, uppercase normalisation. Union wire shape, tag set, the `{"kind":"generation","value":7}` refusal, `deny_unknown_fields` on records and unions. Duplicate-key and explicit-null decoding for every record; `Case.encoded` fixed point after decode.

```findings
- file: crates/mandate-proto/tests/adversary.rs
  line: 28
  category: acceptance
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: task check exits 1 because this case is red, so the acceptance statement that the canonical type conformance suite exits zero is not met by the tree as it stands.
- file: crates/mandate-proto/tests/adversary.rs
  line: 25
  category: judgement
  severity: blocker
  verdict: INFEASIBLE
  origin: introduced
  message: the case demands Ok and Err from one pure function on one string and the projection declares identical nodes for both identifiers, so it cannot be satisfied without an envelope that breaks three projection-conformance cases; the coordinator must retire it, not the implementor.
- file: crates/mandate-proto/tests/adversary_second_pass.rs
  line: 132
  category: acceptance
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: serde serialization of CredentialSecret and CredentialProof renders a redacted marker which the declared base64 pattern refuses, so no derived container can render the form the 12 generated command and response schemas require and the unit ships no serialize_with helper for it.
- file: crates/mandate-types/src/macros.rs
  line: 164
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: the doc claims the declared base64 form is reachable only through Canonical::encode, but wire_contracts! gives both transient types a public WireContract::to_wire that returns the material to a caller that never names Canonical.
- file: crates/mandate-types/tests/inventory.rs
  line: 170
  category: mutant
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: every pattern in the generated corpus sits at $defs/<name>/pattern, so a single-node read yields the same two-element set as the new full-depth walk and reverting the recursion leaves this case green.
- file: crates/mandate-types/src/lib.rs
  line: 142
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: the conformance harness ships in the library rather than behind a feature, so Canonical::encode - the route to credential material - links into every downstream crate including mandate-audit.
```
