---
format: aep.planning-md/1
id: executable-system-specification:mandate
kind: executable-system-specification
status: validated
title: Mandate's executable system specification and its conformance evidence
model_digest: 2f11d2daffc2d75bb4ca8c0485aedc56fb2a712cdaed6347fc48b8ba2b1f7ca6
revision: 3
---
## What this records

The conformance evidence for `systems/mandate`, read from a run on the merged head of wave D's second half. Created and recorded by the coordinator at wave close, per `docs/adr/0010-drift-enforcement.md` §6.

## The run

`cargo xtask conform` inside `task check` on `09ad164`:

| measure | value |
|---|---|
| scenarios | 146 |
| passed | 29 |
| failed | 54 |
| error | 0 |
| unsupported | 63 |
| skipped | 0 |
| `conformance_status` | `failed` |
| `spec_digest` | `2f11d2daffc2d75bb4ca8c0485aedc56fb2a712cdaed6347fc48b8ba2b1f7ca6` |
| implementation | `9e72929ba517` |
| projections agreeing | 318 |

## Why `validated` and not `conforming`

`conforming` would claim the suite passes, and 54 scenarios do not. ADR 0010 §6 is explicit that a library tag may ship with `conformance_status: failed` — Mandate's contract is ahead of its realization by construction, and a gate requiring `passed` would require either finishing everything or weakening the suite. What a tag must carry instead is honesty about the number: **every non-passed scenario names a live `blocked_on` story**, and the counts are in the CHANGELOG for the tagged commit.

The run's own attribution, as the gate printed it:

| not passed | authored | recorded | story |
|---|---|---|---|
| 53 | 53 | 0 | `story:ess-synthesizer-prerequisites` |
| 13 | 0 | 13 | `story:directory-provenance` |
| 13 | 0 | 13 | `story:testkit-doubles` |
| 10 | 0 | 10 | `story:agent-authority-kernel` |
| 9 | 0 | 9 | `story:graph-policy-adapter` |
| 6 | 0 | 6 | `story:audit-worker-delivery` |
| 5 | 0 | 5 | `story:constrained-exchange` |
| 4 | 0 | 4 | `story:declared-writers` |
| 2 | 0 | 2 | `story:oauth-integration` |
| 1 | 1 | 0 | `story:refusal-discriminators` |
| 1 | 0 | 1 | `story:agent-security` |

Every one of those eleven is live — none is on a terminal rung. Two tests in `crates/mandate-conformance/tests/` now check that mechanically on every run, and they check it through the two-ledger rule rather than around it: a scenario the target executed with its expectation unmet carries the marker `story:conform-gate`, which is **not** an attribution, and the authored `contracts/expected-outcomes.json` is what owns it. Both tests were red at this close because they read the marker as an attribution; the gap they reported did not exist and the reading did.

## What the same gate proves beside conformance

- 1,821 tests across 215 targets, `task check` exit 0.
- 292 contract elements mapped: 201 implemented, 29 declared, 62 deferred.
- 190 external denial clauses: 83 decided on the real path, 21 reached only by a double, 86 deferred with a named live owner.
- 22 packages satisfy metadata and dependency boundaries; 10 declared documents present; 11 named mutants each refused by the target it names.
