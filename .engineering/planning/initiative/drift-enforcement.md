---
format: aep.planning-md/1
id: initiative:drift-enforcement
kind: initiative
status: draft
title: Drift enforcement — the standing tracker of the ESS agreement programme
relations:
- serves: vision:mandate
revision: 5
---
# Drift enforcement — the standing tracker

The plan of 2026-09-19 (`docs/plans/2026-09-19-wave-e-execution.md`, sections A and B) makes ESS-to-implementation agreement an acceptance condition of `task check`. E1 landed the structural half. This artifact tracks every remaining enforcement item until each is `implemented`, so no wave report can read as "done" while a row below is open. Rows are updated by the coordinator at every wave close.

## Standing

| Item | Story | Status (2026-09-19) | Enforced by, when done |
|---|---|---|---|
| Generated contract shapes, byte-compared | `story:contract-shapes` | implemented (E1) | `cargo xtask contracts` |
| Creators and wrong-state outcomes in the contract | `story:contract-creates` | implemented (E1) | synthesize refusals 106 → 52 |
| Tenancy and graph as events | `story:tenancy-graph-events` | implemented (E1) | folds, replay |
| Emitted events validated against closed schemas | `story:event-validation-harness` | implemented (E1) | `mandate-testkit` in every `emitted_events.rs` |
| Federation/identity agreement, model agreement | `story:federation-identity-alignment`, `story:model-agreement` | implemented (wave A) | `contract_agreement.rs`, the state-enum account |
| Coverage map: every contract element mapped to symbols and tests, receipt byte-compared | `story:coverage-map` | **draft — wave E2, scoping now** | `cargo xtask coverage` |
| Authored denial scenarios the synthesizer cannot express | `story:authored-denial-scenarios` | **draft — wave E2, scoping now** | the suite |
| In-process ESS conformance target over the real handlers | `story:conformance-target` | **draft — wave E3, scoping now** | `mandate-conform`, report/2 |
| Named mutation controls | `story:mutation-controls` | **draft — wave E3, scoping now** | `cargo xtask mutants` |
| Obligation registry: every external denial clause bound to a real-path test | `story:obligation-registry` | draft — wave E3 | `cargo xtask obligations` (registry) |
| `cargo xtask conform` in the gate, evidence bound, `executable-system-specification:mandate` | `story:conform-gate` | draft — wave E3 | the gate; `conformance_status` |
| Entity invariants at the boundary | `story:invariant-boundary-validation` | draft | schema + adapter checks |
| ESS: realizer admits element roots; coverage selection scope; refusal audits; synthesizer consults entity invariants; invariant comparisons typed; one subject per outcome | ESS repository stories (`realizer-element-roots`, `coverage-selection-scope`, `refusal-audits`) + three gaps from waves B and C | not started | the ESS release Mandate repins to (E4) |
| E4 close: repin, retire the xtask emitter if outputs match, review-result with the mutant table, CHANGELOG counts | coordinator | not started | — |

## What today's gate proves and does not

Proves: projections match; every hand-written record, event and input round-trips its generated shape; every emitted event of a realized command conforms to its schema and payload sources; every domain's realization registry equals the declared element set; every obligations row is the contract's denial verbatim; the STS's every constructed denial clause maps to its command's text both ways. Does not prove: any of the 146 synthesized scenarios executing against a handler (0 executed); a cross-crate one-realizer-per-element check for all crates; that a named mutant is caught; that every external denial clause has a real-path test.

## Rule

An enforcement row moves only on `test_result` evidence from `task check` and a `review-result` with the findings block the plan names; a wave report to the operator names this artifact's open rows.

## Release stance, restated 2026-09-19

A library-only tag may ship while `conformance_status` is `failed`, provided every failed scenario names a live `blocked_on` story in the run and `CHANGELOG.md` carries the report/2 counts verbatim (`passed`, `failed`, `unsupported`, `error`). Blocked-on-unrealized-command scenarios answer `Unsupported` (ESS's definition: a permanent property of the target), not `Unavailable`. No deployment until the report is `passed` on real paths. The E4 close retires the xtask emitter together with the `deny-unknown-fields-removed` mutant anchored on it.

Further ESS gaps found by wave D's authored-scenarios unit (2026-09-19), for the ESS repository stories above: (a) `$instance` inside a union value (`target: {kind: principal, value: {$instance: generation}}`) compiles and is never resolved — the suite carries the literal mapping and nothing refuses it; (b) `$instance` is admitted at the top level of a field only, so a command whose organization sits inside a struct (`Check.context.organization`) cannot name an allocated instance; (c) `setup.fields` refuses any name the entity does not declare, so a projection the handler reads but the entity does not carry (`AccessCredential.target`) cannot be seeded.

(d) an `Integer` literal in `setup:`/`arrange` compiles to a float (`0` → `0.0`) in the format-5 suite.

Sub-agent outage (2026-09-19, ~15:40 Europe/Berlin): the Opus weekly limit was hit ("resets Sep 24, 4am (Europe/Berlin)", HTTP 429). Three running agents were terminated mid-work: the `product-listener` implementor (left `services/control-plane/src/adapters.rs` 1251 lines, `tests/adapters.rs` 515, `tests/serve.rs` 609 and the `services/sts/src/store.rs` by-verifier read in its tree; no `serve.rs`, `lib.rs` and `main.rs` still stubs; no gate run), the `conformance-target` adversary 2 (nothing written) and the `mutation-controls` adversary 2 (nothing written). `coverage-map` correction 2 is not dispatched. Every sub-agent is on Opus by operator instruction; the choice between waiting for the reset, another model, or coordinator-side work is recorded as an open operator decision on the wave page.
