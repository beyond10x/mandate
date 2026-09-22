---
format: aep.planning-md/1
id: review-result:wave-h-link-absent-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — link-absent-discriminates
relations:
- reviews: story:link-absent-discriminates
revision: 1
---
# Adversary pass 2 — `story:link-absent-discriminates`

Against `8b7a6e0`, the correction that answered pass 1. Returned 2026-09-22.

```
unit: story:link-absent-discriminates
verdict: red
cases: executed 348→351, red 3 (mandate-federation 308→310; mandate-conformance 40→41)
origin: introduced 4, pre-existing 2, undecided 0
wrote-outside-worktree: 10 logs under ~/.cache/claude-tmp/waveh/h1-link-absent/adv2/
needs-coordinator: no
```

Two untracked test files added, both under `tests/`. No implementation file was edited or mutated —
every probe is a store written inside a case.

## The ledger against pass 1

Pass 1: 6 findings. Pass 2: 6. **Carried 0, new 6, resolved 6.** Pass 1 attacked whether the fold
held; pass 2 attacks whether the port change means what the correction says it means.

## What it attacked and could not break

- the provisioning guard over `Projection`: 8 state masks × 8 append orders, duplicates, reordering,
  empty and multi-record vectors through a conforming store. `!records_on_key(..).is_empty()` is
  state-blind and the derived `link` reproduces the old `min_by_key` preference exactly
- `link_external_principal`'s `LinkConflict` and `Projection::conflicts()` are unchanged from
  `06c6747`: both read `link(..)` then test `state == Linked`, so the fallback arm is never
  observable to a decision
- `declared_link_states()`: the IR shape was read directly. A rename fails the `kind` assert, a
  missing file fails the `expect`, a truncated file fails the parse, an unmapped variant panics by
  name. All four fail loudly
- removing `key_holds_no_record` is behaviour-preserving: the pre-check's key and the command's key
  are the same triple over the same records, and the only observable change is one fewer `verify`
- **no assertion was deleted between `06c6747` and `8b7a6e0`.** The one removal in
  `adversary_pass2.rs:470` is replaced by `expect_err` plus two stronger assertions

## Findings

```findings
- file: crates/mandate-federation/src/lib.rs
  line: 554
  category: contract-drift
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'LinkStore::link is a defaulted trait method, so an implementor can still override it and deny LinkAbsent to a validly linked caller, which lib.rs 517-518, record.rs 426 and adversary_wave_h_1.rs 419-421 each state is impossible'
- file: crates/mandate-federation/src/authenticate.rs
  line: 119
  category: contract-drift
  severity: warning
  verdict: INFEASIBLE
  origin: pre-existing
  message: 'the derived link never checks that a record the store answered is on the key it was asked about, so a store answering a foreign record has a session issued in the resolved organization for that record principal; constructed by the case, no in-repo store does it'
- file: crates/mandate-conformance/tests/target.rs
  line: 1043
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: 'the completeness guard scans only methods overridden in src/external.rs, so a defaulted port method is invisible to it, and this unit added exactly one (LinkStore::link) without the guard firing'
- file: services/control-plane/src/adapters.rs
  line: 2346
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the correlation is not an input to the command decision; provision_external_principal reads request.correlation only when building the accepted outcome event, and no refusal path reads request at all'
- file: crates/mandate-federation/src/lib.rs
  line: 482
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: pre-existing
  message: 'ConnectionStore::enabled_for_issuer leaves the Enabled filter to the implementor and resolve_tenant never re-reads candidate.state, which is the same class as the original defect, but a non-filtering store can only add denials because the final organization check reads the selected connection'
- file: services/control-plane/tests/serve.rs
  line: 2210
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: 'the unit edited and added files under services/control-plane/tests, which its brief assigned to another unit; the port-call count 4 to 3 is a correct consequence of removing the adapter own verify and no assertion was dropped'
```

## How the coordinator routed each

The attacking budget is spent. The correction answering this pass is verified by the coordinator.

| finding | row taken |
|---|---|
| `lib.rs:554` — `link` is defaulted, not sealed | back to the implementor. It is a **blocker** and it is the unit's own claim: three places in the tree say an implementor cannot answer this, and an implementor can. A blanket impl on a separate trait cannot be overridden downstream; that or the claim goes |
| `authenticate.rs:119` — the derivation never checks the record is on the key it was asked | back with it, because it is one filter in a derivation this unit now owns and it strictly narrows. `INFEASIBLE` and pre-existing, so if it turns out to be more than one filter it is filed instead |
| `tests/target.rs:1043` — the completeness guard scans overrides, not declarations | back to the implementor, which already edited that file. The adversary's case **is** the scan |
| `adapters.rs:2346` — the correlation is not an input to the decision | back to the implementor: one sentence, and it is the sentence written to answer pass 1's finding 3 |
| `lib.rs:482` — `enabled_for_issuer` | filed as `story:enabled-for-issuer-filters-in-the-implementor`. Pre-existing, untouched by this unit, and the direction is closed — a non-filtering store can only add denials |
| `serve.rs:2210` — the unit wrote in another unit's assignment | coordination only, and the coordinator caused it: the patch was applied by me. Checked against H4's branch with `git merge-tree` before the merges |
