---
format: aep.planning-md/1
id: story:linked-event-method-unenforced
kind: story
status: draft
title: The fold admits a link method no command can emit
relations:
- decomposes: epic:hardening
- serves: vision:mandate
scope:
- confidence: cited
  path: crates/mandate-federation/src/record.rs
- confidence: inferred
  path: crates/mandate-federation/tests/record.rs
- confidence: inferred
  path: services/control-plane/src/adapters.rs
- confidence: inferred
  path: services/control-plane/tests/adversary_jit_login.rs
- confidence: inferred
  path: services/control-plane/tests/adversary_listener_1.rs
- confidence: inferred
  path: services/control-plane/tests/adversary_listener_2.rs
- confidence: inferred
  path: services/control-plane/tests/adversary_login_pass2.rs
- confidence: inferred
  path: services/control-plane/tests/authority.rs
- confidence: cited
  path: services/control-plane/tests/serve.rs
revision: 4
---
# The fold admits a link method no command can emit

## Why

`crates/mandate-federation/src/record.rs` enforces the two pinned literals on
`ExternalPrincipalProvisioned` (`:550`) because, in the fold's own words, the write path is not the
only way an event reaches a fold. Its `ExternalPrincipalLinked` arm (`:513`) enforces nothing:
a log carrying `link_method: ConfiguredFederation` on that variant reads as valid, although
`link_external_principal` refuses exactly that method (`crates/mandate-federation/src/link.rs:93-98`,
`LinkingAuthority`) and no other command in this domain emits the event.

Two in-tree fixtures already rest on the gap, and one of them was the only composition-level evidence
for a real property. `services/control-plane/tests/serve.rs:2299`,
`an_explicitly_relinked_subject_logs_in_again_and_provisions_nothing`, documents its fixture as *"an
administrator's `LinkExternalPrincipal` … the command a revoked user comes back through"* and then
records an `ExternalPrincipalLinked` carrying `ConfiguredFederation`. `serve.rs:189` seeds the same
unlawful method.

So the evidence that a revoked user can come back at all stood on an event the write path cannot
produce. Measured 2026-09-22 by the adversary of `story:link-absent-discriminates`, which drove the
same recovery with `ExternalLinkMethod::Administrator` and found the behaviour itself is correct —
`services/control-plane/tests/adversary_wave_h_1.rs:130`, green. The defect is the fold's silence and
the two fixtures it admitted, not the recovery path.

## What this story delivers

The `ExternalPrincipalLinked` arm of the fold refuses a `link_method` the command that owns the event
cannot emit, the way the `ExternalPrincipalProvisioned` arm already refuses its two. The two fixtures
are corrected to the method a command can actually produce.

## Acceptance

`cargo test -p mandate-federation --locked` exits 0 with a case in which a log carrying
`ExternalPrincipalLinked { link_method: ConfiguredFederation }` is refused by the fold, red before the
change and green after. `cargo test -p mandate-control-plane --locked` exits 0 with both fixtures
seeding `ExternalLinkMethod::Administrator`, and
`an_explicitly_relinked_subject_logs_in_again_and_provisions_nothing` still asserting what it asserts
today.

## Out of scope

What `LinkExternalPrincipal` itself admits. Any other fold arm's literals.

## Scope

Derived 2026-09-23 by `aep-drive:story-scoper` at `92fc026`. Every line is **cited** or **inferred**.

- **Primary surface:** `crates/mandate-federation` fold — cited
- **Files:** `crates/mandate-federation/src/record.rs:515` (`ExternalPrincipalLinked` arm of `apply`; the body's `:513` has drifted) — cited
- **Files:** `services/control-plane/tests/serve.rs:190`, `:2416` — cited
- **Also likely:** `services/control-plane/src/adapters.rs:962-970` — inferred (found by grep, not named by the story)
- **Also likely:** `services/control-plane/tests/{adversary_jit_login.rs:239,adversary_listener_1.rs:165,adversary_listener_2.rs:177,adversary_login_pass2.rs:582,authority.rs:309}` — inferred, same fixture shape
- **Confidence:** high on the site, **low on the premise**

**The premise does not hold at `92fc026`.** The body says no other command emits the event. The production connection seeding at `services/control-plane/src/adapters.rs:962-970` emits `ExternalPrincipalLinked { link_method: ConfiguredFederation }`, and `:793-797` documents why ("A seeded link is `ConfiguredFederation`, which is what it is"). A fold that refuses the method breaks every seeded `--connection` link. What method a seeded link carries has to be decided before this story is implementable; it was left out of waves I–K for that reason.
