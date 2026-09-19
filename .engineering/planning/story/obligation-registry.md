---
format: aep.planning-md/1
id: story:obligation-registry
kind: story
status: draft
title: Every external denial clause of an implemented command is bound to a real-path test
relations:
- decomposes: epic:foundations
- serves: vision:mandate
- depends_on: story:coverage-map
scope:
- confidence: inferred
  path: contracts/obligations.json
- confidence: inferred
  path: crates/mandate-authz/tests/obligations.rs
- confidence: inferred
  path: crates/mandate-federation/tests/obligations.rs
- confidence: inferred
  path: crates/mandate-identity/tests/obligations.rs
- confidence: inferred
  path: crates/mandate-model/tests/obligations.rs
- confidence: cited
  path: generated/conformance/obligations-report.json
- confidence: inferred
  path: xtask/src/obligations_registry.rs
- confidence: inferred
  path: xtask/tests/obligations_registry.rs
revision: 3
---
## Acceptance

Given `contracts/obligations.json`, when `cargo xtask obligations-registry` runs, then every IR command has an entry and no entry names a non-compiled command; every `implemented` command has at least one `denial` test per external clause with `path: real` and one `no-state-change` test, or the gate fails; `double`-backed tests are counted in their own column and never as conforming; every `tests/security/cases.json` id is bound to a test or deferred to its story; every addendum requirement (resolution order 1–9, §5.x) is bound; and `generated/conformance/obligations-report.json` is byte-identical to the run.

## Scope

- `contracts/obligations.json` — inferred; format `mandate-obligations/1`; per command `{status, tests: [{id, kind: denial|accepted|no-state-change|precedence|denial-audit, clause, path: real|double, double?, blocked_on?}]}`, `addendum` and `cases` sections.
- `xtask/src/obligations_registry.rs` — inferred; the step (IR ↔ registry both directions; test-id existence via `cargo test -- --list`; rules above; report writer).
- `xtask/tests/obligations_registry.rs` — inferred; red/green over a scratch copy.
- `generated/conformance/obligations-report.json` — cited (generated).
- New real-path denial tests, one file per crate so no other unit's file is touched: `crates/mandate-federation/tests/obligations.rs`, `crates/mandate-identity/tests/obligations.rs`, `crates/mandate-authz/tests/obligations.rs`, `crates/mandate-model/tests/obligations.rs` — inferred; every external clause of the 21 implemented commands driven through the real validation path with a malformed or mismatched input, plus a `no-state-change` assertion per command and precedence tests where two denials compete. Clauses only a double can reach today (proof verification) are registered `path: double`, `blocked_on: story:signing-and-verification`.
- `denial-audit` entries are `deferred` for every command until ESS carries `audits:` (the ESS story).

### Units

| Unit | Owns | Test |
|---|---|---|
| `registry+step` | `contracts/obligations.json`, `xtask/src/obligations_registry.rs` | `xtask/tests/obligations_registry.rs` |
| `tests` | the four `tests/obligations.rs` files | themselves |

One agent, serially. The coordinator wires the `mod`, `Action`, `Check` line.

### Excluded

`xtask/src/main.rs`, `docs/architecture/command-obligations.md` (text unchanged), `Cargo.*`, every `src/`.

### Gate

`cargo test -p xtask -p mandate-federation -p mandate-identity -p mandate-authz -p mandate-model --locked`; `cargo xtask obligations-registry` on the tree.
