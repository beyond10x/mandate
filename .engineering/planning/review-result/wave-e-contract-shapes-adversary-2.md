---
format: aep.planning-md/1
id: review-result:wave-e-contract-shapes-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — contract-shapes
relations:
- reviews: story:contract-shapes
revision: 1
---
```
unit: story:contract-shapes — xtask/src/emit.rs, xtask/tests/emit.rs, crates/mandate-contract/{src/lib.rs,tests/shapes.rs}, generated/rust/**, uncommitted on impl/contract-shapes at base 9401ab9, after correction round 1
verdict: needs-change
cases: executed 79 → 88, red 3 (adversary files xtask/tests/adversary_emit_2.rs 6 cases: 4 held, 2 confirmed; crates/mandate-contract/tests/adversary_shapes_2.rs 3 cases: 2 held, 1 confirmed); pass-1 files 12/12 green
findings: 7 — 1 blocker, 2 warnings, 4 notes; pass-1 classes held except the absence class (regressed by the blocker)
```

```findings
- file: xtask/src/emit.rs
  line: 841
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'nested_optional refuses an optional only inside a list, so an optional in a union variant, in a newtype of, or inside another optional is emitted as a Presence in a position where the ESS schema projection spells absence as null or as a dropped content key, and ess specify compile accepts all three.'
- file: xtask/src/emit.rs
  line: 886
  category: mutant
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the unmapped primitive and unmapped type expression refusals name neither the declaration nor the field that carries them, while every other refusal in the same enumeration does and the unit own keyword case asserts that it must.'
- file: xtask/src/emit.rs
  line: 882
  category: boundary
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the comment claims Number keeps every integer the schema admits exactly, but serde_json without arbitrary_precision turns 2^64+1 into 1.8446744073709552e+19 and -0 into -0.0; the exactness claim is scoped to the i64/u64 range by ruling.'
- file: xtask/tests/adversary_emit_1.rs
  line: 428
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the pass-1 case doc comment stated that Presence::Absent serializes to null, the opposite of the round-1 ruling; amended by the coordinator.'
- file: xtask/src/emit.rs
  line: 26
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the module doc says the emitter encodes the declared tag and content keys, but the content key value is a literal at emit.rs:578 and the IR union body declares a tag only.'
- file: .engineering/planning/story/contract-shapes.md
  line: 37
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'the story Scope still specifies integer as i64, modules under allow(clippy::all) and a source_digest header, none of which shipped; superseded by the rulings after adversary pass 1 and this one.'
- file: xtask/src/emit.rs
  line: 311
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the doc says validation is in new() rather than spread through the renderers, but the credential refusal and every identifier check run in entities, events, record and enumeration; the all-or-nothing consequence still holds because files() evaluates all four before emit() writes.'
```

Held: 719 schema keys agree with the emitted Rust type both ways (integer ⇔ Number, list ⇔ Vec, $ref ⇔ declaration_name, optional ⇔ Presence); the committed emission is byte-identical to `render(committed ir)`; all four files are rustfmt fixed points; keyword and digit-leading names unreachable (ESS refuses at compile); the collision, dangling-reference (through optional<list<declared>>) and injected-state-enum refusals hold; absence omits the key one record below an event; the crate's public surface carries what the E2 agreement tests need. Three mutants (i64 back, Presence null, collision check dropped) each killed. Evidence under the unit's scratch `adversary2/`.
