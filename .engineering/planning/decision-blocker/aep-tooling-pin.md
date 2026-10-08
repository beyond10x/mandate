---
format: aep.planning-md/3
id: decision-blocker:aep-tooling-pin
kind: decision-blocker
status: cleared
title: Repository tooling pins aep 0.55.0 and the journal layout
revision: 3
transitions:
- {from: "open", to: "cleared", at: "2026-10-08T21:01:51Z", actor: "human:timo", revision: 3}
---
The planning store moved to `aep.project/5`, and the repository's own tooling still requires `aep` 0.55.0, which reads none of the 289 migrated documents (`blocked` prints a warning and `[]`).

Places that pin the old layout:

- `.github/workflows/ci.yml:24` installs `aep` 0.55.0.
- `xtask/src/main.rs:595` refuses any `aep` other than `protocol 0.55.0` in `cargo xtask check`.
- `xtask/src/conform.rs:1138` reads release evidence from `.engineering/planning/journal.jsonl`, which the migration removed; the records now live under `.engineering/evidence/executable-system-specification/mandate/`.
- `xtask/tests/conform.rs`, `adversary_conform_1.rs` and `adversary_conform_2.rs` write journal fixtures.
- `AGENTS.md` names AEP 0.55.0 as the store's sole writer.

Decision: extend the store migration to move these to the current `aep` release, or keep the store on `aep.project/1`.

## Decided

Tooling pin moved to aep 0.69.1, in the same change as the store migration: `ci.yml` and `cargo xtask check` require aep 0.69.1, `cargo xtask conform --release` reads the evidence record files under `.engineering/evidence/`, the three conformance test files write that layout, and `AGENTS.md` and `README.md` name the new pin.
