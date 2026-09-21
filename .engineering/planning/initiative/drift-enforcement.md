---
format: aep.planning-md/1
id: initiative:drift-enforcement
kind: initiative
status: draft
title: Drift enforcement — the standing tracker of the ESS agreement programme
relations:
- serves: vision:mandate
revision: 7
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
| Coverage map: every contract element mapped to symbols and tests, receipt byte-compared | `story:coverage-map` | **implemented (wave D, PR #14)** | `cargo xtask coverage` |
| Authored denial scenarios the synthesizer cannot express | `story:authored-denial-scenarios` | **active — 20 files green in its tree; bot commit refused by the secrets scanner on synthetic JWS fixtures (trusted-policy exception is the operator's); merges in wave D's second half** | the suite |
| In-process ESS conformance target over the real handlers | `story:conformance-target` | **active — green in its tree after adversary 1 + correction 1 (report/2 29 / 54 / 0 / 63 / 0 of 146); adversary 2 owed (Opus quota); merges in wave D's second half** | `mandate-conform`, report/2 |
| Named mutation controls | `story:mutation-controls` | **active — green in its tree after adversary 1 + correction 1 (ten mutants, 26 s); adversary 2 owed (Opus quota); merges in wave D's second half, then round 2 (`coverage_mutants.rs`, `manifest-relabel`)** | `cargo xtask mutants` |
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

## Wave D, second half — the obligations registry bound, 2026-09-21

Seven per-crate binding stories landed on `integration/wave-20260919-005`, each after two adversary passes and at most two corrections. Full `task check` on `09ad164`: exit 0, **1,821 tests across 215 targets**.

| crate | clauses | real | double | deferred | unit / merge |
|---|---|---|---|---|---|
| `mandate-sts` | 52 | 32 | 0 | 20 | `07afd0f` / `a2a55c3` |
| `mandate-federation` | 40 | 28 | 3 | 9 | `ecd2471` / `7275385` |
| `mandate-identity` | 12 | 4 | 2 | 6 | `fce76be` / `6216008` |
| `mandate-graph` | 19 | 0 | 8 | 11 | `6418ed2` / `18ace4c` |
| `mandate-model` | 42 | 12 | 0 | 30 | `602da3b` / `87bcef3` |
| `mandate-policy` | 10 | 0 | 6 | 4 | `9f8f625` / `058a56c` |
| `mandate-authz` | 15 | 7 | 2 | 6 | `ac22270` / `7d69b5c` |
| **all** | **190** | **83** | **21** | **86** | |

`cargo xtask conform` on the same head: 146 scenarios, 29 passed / 54 failed / 0 error / 63 unsupported / 0 skipped, `spec_digest 2f11d2da…`, implementation `9e72929ba517`, 318 projections agreeing. Recorded on `executable-system-specification:mandate` (`validated`, `ess_conformance` at `git:09ad164`). Not `conforming`: 54 scenarios are unmet and each names a live story.

### The finding this half exists to record

**Most of what the contract publishes as a refusal, the crates do not decide.** 86 of 190 clauses are deferred, and the large majority name a path the owning crate cannot reach at all — not work its binding story could have done. Three crates decide nothing: `mandate-graph` 0 of 19, `mandate-policy` 0 of 10, and `mandate-model` 12 of 42. Every decider in the first two sits behind a port whose only implementor is a standing double.

The registry's value is that this number can now fall by work and cannot fall by deletion: a clause is a verbatim substring of the declared cause and the clauses of one command tile it, so dropping one is refused.

### What moved, and why each number moved

- `mandate-authz` was carried into the wave as **already satisfied** at `5 / 5 / 0 / 0` and archived in the plan. It is `15 / 7 / 2 / 6`. Two clauses each published several conditions behind rows that decided fewer; splitting them exposed eight conditions nothing decides, and two survivors then fell on measurement — one covered on a branch no input can reach (`space_id` is written as a literal `None`), one bound to a tenancy refusal with `VerifiedContext::credential` read nowhere in the crate.
- `mandate-graph` fell 6 → 0. Two of the six were pre-existing: a `TenantMismatch` asserted from a `Tree` stub inside a test binary, and a model-admission clause the crate's own module doc attributes to `mandate-policy`.
- `mandate-policy` fell 6 → 4 (two `double` rows named cases that never call the command they were cited for) and rose to 6 again when both later-version clauses were split one condition per clause.
- `mandate-model` gained a clause (41 → 42) when a bundled authority conjunct was split out of a row counted `real`.

### Rules established this half

1. A clause decided by store/adapter code whose only implementor is a standing double is `double`, not `real`; a row is evidence of a command only when the command's own path calls the deciding function.
2. A `double` value is a `::`-separated Rust path into a **library** target. A stub inside a test binary is not one.
3. A re-pointing names a live story or an open `decision-blocker` **with a cited source line that contains the statement it is cited for**.
4. A crate's module doc naming another crate is a **hypothesis** about where a decision lives, not a measurement. Twice this wave it was wrong, and the registry step cannot catch it — it checks only that a deferral is not the crate's own binding story.
5. A count or an enumeration written into a document that another story is still editing is false on a schedule nobody controls. `contracts/obligations/README.md` now states no count of double-backed clauses, no closed deferral list, and no claim about how many implementors a port has.

### Gaps recorded rather than fixed

- `story:unpublished-refusals` — four crates refuse on conditions their declared cause publishes no clause for (`mandate-graph`'s `declared_name`, `mandate-policy`'s unresolved id, `mandate-authz`'s `!direct`, `mandate-model`'s two `wrong-state` refusals), plus a published 409 the only implementor answers as an accepted repeat.
- `story:cross-crate-clauses` — five gaps in the registry step: a `double` value is checked only for non-emptiness; one test id may discharge rows of two kinds; `cases` rows inherit a clause-shaped one-path rule whose escape hatch does not exist for them; a deferral's owner is unmeasured; and the substring rule fights the granularity rule, so nine of `authz.json`'s fifteen clause names are bare nouns.
- `story:declared-writers` — three crates route a live gap through a source comment to a story that is **finished** (`story:session-epochs`, `story:check-api`, `story:event-payloads-for-folds`). A comment naming a story is a claim about ownership that nothing rechecks when the story closes.

### Still open

`story:authored-denial-scenarios` is green in `mandate-wd-authored` and cannot be committed: the `b10x-gates` pre-commit hook refuses it on 13 secret-scanner findings over synthetic JWS fixtures. Twelve are `jwt`/`jwt-base64` on a fixture decoding to `{"alg":"RS256","typ":"JWT","kid":"k1"}` and `{"iss":"https://other.example.test","aud":"mandate-client","sub":"u-1"}`; one is `generic-api-key` on the base64 of the literal string `credential-issued-for-api-b…`. No key material. Admission is a trusted-policy exception and is the operator's. `4f130a6` on `impl/authored-denial-scenarios` holds the one path of 21 the hook admits; the other 20 stay staged behind a verified export.
