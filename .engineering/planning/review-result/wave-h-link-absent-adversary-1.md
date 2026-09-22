---
format: aep.planning-md/1
id: review-result:wave-h-link-absent-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — link-absent-discriminates
relations:
- reviews: story:link-absent-discriminates
revision: 1
---
# Adversary pass 1 — `story:link-absent-discriminates`

Against `e9f69cf` in `mandate-wh-link-absent`, base `06c6747`. Returned 2026-09-22.

```
unit: story:link-absent-discriminates
verdict: CONFIRMED (warning) — one red case, no blocker
cases: executed 306→308 (mandate-federation), 137→138 (mandate-control-plane), red 1
origin: introduced 3 / pre-existing 3 / undecided 0
wrote-outside-worktree: 2 log paths under ~/.cache/claude-tmp/waveh/h1-link-absent/
needs-coordinator: yes — F1's severity is a routing call; F6 is the coordinator's own document
```

No implementation file was changed. Two untracked test files added:
`crates/mandate-federation/tests/adversary_wave_h_1.rs` (2 cases, 1 red) and
`services/control-plane/tests/adversary_wave_h_1.rs` (1 case, green).

## The red case, as captured

```
thread '...' panicked at crates/mandate-federation/tests/adversary_wave_h_1.rs:439:28:
a record holds this key and its link was revoked, so the key is not free to create a record on.
The command minted PrincipalId(Uuid([160, 1, 40, ...])) for the subject whose link was revoked,
because the state-blindness it depends on is a property of `Projection` and not of `LinkStore`:
Provisioned { external_principal_id: ..., link_method: ConfiguredFederation, ... }

test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out
```

## Suites after the cases existed

```
cargo test -p mandate-federation --locked --no-fail-fast   passed=307 failed=1 executed=308, exit 101
cargo test -p mandate-control-plane --locked --no-fail-fast passed=138 failed=0 executed=138, exit 0
cargo xtask obligations-registry                            190 / 83 / 21 / 86, exit 0
cargo clippy -p mandate-federation -p mandate-control-plane --locked --tests   no warnings
```

## Attacked and could not break

- `Projection::link`'s preference-with-fallback under **8 state masks × 8 append orders** over three
  records on one key. `link()`, the principal `authenticate_federation` issues, `LinkConflict`,
  `conflicts()` and `ExternalKeyExists` all match a reference stated from the story rather than read
  off the code. Green.
- `conflicts()` invariance: its outer `Linked` filter means the fallback path is unreachable from it.
- A key holding several non-`Linked` records — `min_by_key` on a unique id is order-independent.
- Relink after revoke through a lawful `link_method`, then a second revocation: `LinkAbsent`, and
  nothing created.
- Whether the removed adapter pre-check took a second condition with it: **it did not.**
  `resolve_tenant` refuses `OrganizationMismatch` unless the resolved organization is the
  connection's, so the pre-check's key and the library's were always the same value — and the old
  pre-check keyed on a *separately verified* subject, which the removal fixes.
- The reversal in `tests/adversary_pass2.rs` is strictly stronger, not narrower.
- `serve.rs`'s 4 → 3 bound is right: the removed pre-check made exactly one `verifier.verify`; the
  remaining three are the login, `provision`'s `resolve` and the retry.

## Findings

```findings
- file: crates/mandate-federation/src/authenticate.rs
  line: 195
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: the ExternalKeyExists guard now depends on LinkStore surfacing Unlinked rows, which the port contract at lib.rs:513 does not require and at lib.rs:529 explicitly permits an implementation to withhold, so the state-blindness the story asked to be inherited by every composition is a property of Projection alone
- file: crates/mandate-federation/tests/authenticate.rs
  line: 564
  category: mutant
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: the exhaustive-state guard matches over a hand-written states array, so a new LinkState variant is satisfied by a do-nothing match arm while the loop that drives provision_external_principal still iterates the old two
- file: services/control-plane/src/adapters.rs
  line: 2373
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: removing the pre-check means a refused provisioning now reaches provisioned(), which draws one identity from the deployment's SecretSource at :2392 before the command refuses, on a path the same file documents as creating nothing
- file: services/control-plane/tests/serve.rs
  line: 2299
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: the revocation-recovery case documents an administrator LinkExternalPrincipal and records an ExternalPrincipalLinked carrying the one link_method that command refuses, so the composition-level evidence for relink-after-revoke rested on an event no command in this domain can emit
- file: crates/mandate-federation/src/record.rs
  line: 513
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: the fold enforces the pinned link_method literal on ExternalPrincipalProvisioned and enforces nothing on ExternalPrincipalLinked, so a log carrying ConfiguredFederation on that variant reads as valid and two in-tree fixtures already rest on the gap
- file: .engineering/planning/story/link-absent-discriminates.md
  line: 103
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: the Scope section still claims that removing the Linked filter from Projection::link alone leaves authenticate_federation unchanged, which the implementor measured false against tests/replay.rs and which revision 10 has not corrected
```

## How the coordinator routed each

| finding | row taken |
|---|---|
| `authenticate.rs:195` — the guarantee is `Projection`'s, not the port's | back to the implementor, with permission to touch `crates/mandate-conformance/src/external.rs`, which no other unit of this wave holds. The story exists to stop the next composition inheriting the defect; a guarantee that lives in one implementation does not do that |
| `tests/authenticate.rs:564` — a do-nothing arm satisfies the exhaustive guard | back to the implementor |
| `adapters.rs:2373` — one identity drawn before the refusal | back to the implementor: move the draw after the command admits, or correct the sentence that says the path creates nothing |
| `serve.rs:2299` and `record.rs:513` — a fixture resting on an event no command emits | filed together as `story:linked-event-method-unenforced`. Pre-existing, and the second is the reason the first was possible |
| the `## Scope` mechanism claim | the coordinator's own document. Rewritten at the close, from the implementor's measurement |
