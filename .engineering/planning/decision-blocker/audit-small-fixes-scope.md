---
format: aep.planning-md/3
id: decision-blocker:audit-small-fixes-scope
kind: decision-blocker
status: cleared
title: 'Scope of the audit small code fixes: G-21, G-46, G-48'
relations:
- blocks: story:audit-small-code-fixes
revision: 2
transitions:
- {from: "open", to: "cleared", at: "2026-10-16T16:37:34Z", actor: "human:timo", revision: 2}
---
# Scope of the audit's small code fixes: G-21, G-46, G-48

## What was undecided

`story:audit-small-code-fixes` lists three gaps whose fix reaches outside its Scope or changes more than a small fix: G-21 (the conformance target seeds no `ConfiguredAdmission` for `RegisterOAuthClient`; the fix is in `crates/mandate-conformance/src/commands/federation.rs`), G-46 (a decider result that narrows needs a sealed `Decided` type returned by every `mandate-authz` `decide_*`, about 80 call sites) and G-48 (a foreign record answers `TenantMismatch` where an unknown one answers `Denied` or `InvalidCredential`). About six rows of `contracts/expected-outcomes.json` move from failed to passed and are outside the Scope.

## Decided (operator, 2026-10-16)

- G-21: the story's Scope takes `crates/mandate-conformance/src/commands/federation.rs`; the target seeds a standing `ConfiguredAdmission` from the scenario's caller context. Test-harness code only.
- G-46: split into `story:audit-sealed-decided`, a draft sequenced after this wave; the gap is recorded there.
- G-48: in this story, session revoke answers `InvalidCredential` and the graph and policy doubles answer `Denied` for a foreign record as for an unknown one. Graph `placement` and `register_resource` with a foreign-held id go to `story:audit-foreign-placement`.
- The `contracts/expected-outcomes.json` rows go into the story's Scope; the overlap with `story:audit-manifest-owners` is resolved at integration.

Each choice can be undone, and none changes a public contract in this wave.
