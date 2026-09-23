---
format: aep.planning-md/1
id: story:sts-lifetime-bounds
kind: story
status: implemented
title: Resource-server profiles are bounded to the renderable timeline
relations:
- decomposes: epic:foundations
- informed_by: initiative:drift-enforcement
- serves: vision:mandate
scope:
- confidence: inferred
  path: services/sts/src/code.rs
- confidence: inferred
  path: services/sts/src/issue.rs
- confidence: cited
  path: services/sts/src/lib.rs
- confidence: inferred
  path: services/sts/src/redemption.rs
- confidence: cited
  path: services/sts/src/registry.rs
- confidence: cited
  path: services/sts/tests/adversary_obligations_sts_1.rs
revision: 8
---
## Why

`services/sts/src/registry.rs:142` `admits_profile` asks only that `max_ttl` is a positive span. A registration with `max_ttl: PT99999999H` is admitted, `issue_reference_credential` then mints a secret and issues `expires_at` `13434-08-30T15:00:00Z`, and `services/sts/src/lib.rs:312-320` reads that instant back as `None`, so the credential is not live at the instant it was minted (`review-result:wave-d-obligations-sts-adversary-1` F2). `services/control-plane/src/adapters.rs:1477` `renders_readably` refuses the same span for the code and session lifetimes at startup; the profile reaches the same renderer with no bound.

## Outcome

`admits_profile` refuses a `max_ttl` whose span, added to any instant the crate renders, leaves the four-digit year, and every issuance path refuses an `expires_at` the crate's own reader cannot read back.

## Acceptance

`register_resource_server` with `max_ttl: PT99999999H` is refused with `ProfileUnadmitted`; `services/sts/tests/adversary_obligations_sts_1.rs` case `a_profile_bound_past_the_readable_year_is_refused_or_renders_readably` asserts the refusal and is green; `cargo test -p mandate-sts --locked` exits 0.

## Scope

Derived 2026-09-23 by `aep-drive:story-scoper` at `92fc026`. Every line is **cited** or **inferred**.

- **Primary surface:** `services/sts` — cited
- **Files:** `services/sts/src/registry.rs:142` (`admits_profile`); `src/lib.rs:305-322,433` (`instant::seconds_of`, `instant::at`); `tests/adversary_obligations_sts_1.rs` — cited
- **Also likely:** `services/sts/src/issue.rs:303`, `src/redemption.rs:350` (the `instant::at` issuance sites), `src/code.rs` — inferred
- **Symbols:** `admits_profile`, `DenialClause::ProfileUnadmitted`, `issue_reference_credential` (`issue.rs:341`) — cited
- **Confidence:** high for `registry.rs`; medium for "every issuance path"
- **Would collide with:** `story:sts-refusal-draws-nothing` on `issue.rs`, `redemption.rs`

## Scope — confirmed at close

From the implementor's confirmation table, wave I–K (`docs/plans/2026-09-23-waves-i-j-k-execution.md`). Corrections to the `## Scope` above are kept visible here, not deleted there.

sts-lifetime-bounds
- `registry.rs` `admits_profile`, `lib.rs` `instant::at` (the fix point), `issue.rs`, `redemption.rs` — confirmed
- `code.rs` (inferred) — not needed: nothing is rendered there
