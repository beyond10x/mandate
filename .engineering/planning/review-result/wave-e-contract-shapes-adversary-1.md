---
format: aep.planning-md/1
id: review-result:wave-e-contract-shapes-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — contract-shapes
relations:
- reviews: story:contract-shapes
revision: 1
---
```
unit: story:contract-shapes — xtask/src/emit.rs, xtask/tests/emit.rs, crates/mandate-contract/{src/lib.rs,tests/shapes.rs}, generated/rust/mandate-contract/src/*.rs, uncommitted on impl/contract-shapes at base 9401ab9
verdict: needs-change
cases: executed 55 → 67, red 8 (adversary files xtask/tests/adversary_emit_1.rs 8 cases: 2 held, 6 confirmed; crates/mandate-contract/tests/adversary_shapes_1.rs 4 cases: 2 held, 2 confirmed)
findings: 11 — 1 blocker, 3 warnings, 7 notes
```

```findings
- file: xtask/src/emit.rs
  line: 655
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: KEYWORDS covers Rust's strict keywords only, so a field named try, gen, box, final or yield - all legal under ESS's own field grammar - is emitted verbatim and the generated file does not parse.
- file: generated/rust/mandate-contract/src/types.rs
  line: 40
  category: property
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: Presence::Absent serializes to null and Presence refuses null on the way back, so the crate's public optional carrier cannot read its own output outside a skip_serializing_if field position.
- file: generated/rust/mandate-contract/src/events.rs
  line: 525
  category: contract-drift
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: the schema projects generation as an unbounded JSON integer, which admits 1.0 and 9223372036854775808, and the emitted i64 refuses both.
- file: xtask/tests/emit.rs
  line: 450
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: no golden and no round-trip case exercises a list field, so the list-to-Vec mapping line is pinned by nothing once the coordinator regenerates and contracts() compares the emitter against itself.
- file: xtask/src/emit.rs
  line: 552
  category: boundary
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: a declared name the model does not carry is emitted as a reference to a type that does not exist rather than refused, and the credential guard silently passes the same unresolvable name.
- file: xtask/src/emit.rs
  line: 216
  category: boundary
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: two declarations whose declaration_name collides are emitted twice under one Rust name; ESS copies the same function but guards it with name_collision at realize.rs:272.
- file: xtask/src/emit.rs
  line: 392
  category: boundary
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: an entity that declares a field named state is emitted as a record carrying two pub state fields instead of being refused.
- file: xtask/src/emit.rs
  line: 558
  category: boundary
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: a list of an optional is emitted as Vec<Presence<T>>, a shape whose own serialization it cannot deserialize, with no refusal.
- file: xtask/src/emit.rs
  line: 408
  category: boundary
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: an entity whose lifecycle admits no state is emitted as an uninhabited state enum and a record no document can ever satisfy.
- file: xtask/src/emit.rs
  line: 13
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: the module doc promises an ESS story will replace the emitter byte-for-byte, but ESS 0.26.0's Rust realization already maps integers to serde_json::Number, refs to Box, unions to untagged variants and names the carrier EssPresence.
- file: crates/mandate-contract/src/lib.rs
  line: 30
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: the story's Scope says the generated modules sit under an allow(clippy::all) scope and the file carries no such attribute.
```

Held under attack: all 311 emitted declarations agree with all 311 ESS schema artifacts in both directions (44 enums' rename lists, 2 unions' tag/content/labels, 201 records' key sets, optional-vs-required, `deny_unknown_fields` ⇔ `additionalProperties: false`); 24 schema-validated documents over 10 events and 5 entities round-trip byte-equal; `declaration_name` is byte-for-byte ESS's; primitive mapping matches the schema formats; credential refusal through newtypes, structs, unions, lists and optionals; the header digest is over the bytes read; a cached-output mutant is killed by the digest case and the five refusals; every entity's state enum is exactly its lifecycle. Evidence under the unit's scratch `adversary1/`.
