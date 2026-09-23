---
format: aep.planning-md/1
id: story:sts-refusal-draws-nothing
kind: story
status: implemented
title: STS handlers draw from the secret source and allocator only after every refusal
relations:
- decomposes: epic:foundations
- informed_by: initiative:drift-enforcement
- serves: vision:mandate
scope:
- confidence: cited
  path: contracts/obligations/sts.json
- confidence: cited
  path: services/control-plane/src/adapters.rs
- confidence: cited
  path: services/sts/src/issue.rs
- confidence: cited
  path: services/sts/src/lib.rs
- confidence: cited
  path: services/sts/src/redemption.rs
- confidence: inferred
  path: services/sts/src/store.rs
- confidence: cited
  path: services/sts/tests/adversary_obligations_sts_2.rs
revision: 9
---
## Why

Two handlers in `services/sts` draw from the deployment before a refusal they can still make (`review-result:wave-d-obligations-sts-adversary-2` F1, F2). `redeem_and_consume` mints the reference secret and the credential identity (`src/redemption.rs:354-357`) and only then appends under a compare-and-set (`:436`); the losing half of two concurrent redemptions has drawn both when the append refuses. `issue_self_contained_credential` draws the credential identity (`src/issue.rs:424`) before `sign_credential` can refuse (`SigningRefused`, `:436`). `systems/mandate/domains/credential.yaml:245` says a failed or replayed transaction produces no credential, and every other handler in the crate ("Nothing above this line mints anything") draws last.

## Outcome

Every refusal a handler can still make precedes any draw from the secret source or the identity allocator; the losing compare-and-set half and a signer-refused issuance leave both untouched.

## Acceptance

`services/sts/tests/adversary_obligations_sts_2.rs` cases `a_redemption_that_loses_its_compare_and_set_has_already_drawn_credential_material` and `a_self_contained_issuance_refused_by_the_signer_has_already_drawn_a_credential_identity` are flipped to assert no draw and are green; `cargo test -p mandate-sts --locked` exits 0; the `no_state_change` rows of both commands in `contracts/obligations/sts.json` name a case that inspects the secret source and the allocator on the refusing path.

## Scope

Derived 2026-09-23 by `aep-drive:story-scoper` at `92fc026`. Every line is **cited** or **inferred**.

- **Primary surface:** `services/sts` — cited
- **Files:** `services/sts/src/redemption.rs:354-357,436` (`redeem_and_consume`); `src/issue.rs:424,436` (`issue_self_contained_credential`); `tests/adversary_obligations_sts_2.rs` — cited
- **Symbols:** `next_secret`, `next_credential_id`, `sign_credential`, `SigningRefused` — cited
- **Also likely:** `services/sts/src/store.rs` — inferred, if the CAS outcome must be known before the draw
- **Documents:** `contracts/obligations/sts.json` (`no_state_change` rows) — cited
- **Confidence:** high
- **Design choice inside the unit:** draws cannot move after an append that needs their output; the CAS half needs a pre-check or a reservation

## Scope — confirmed at close

From the implementor's confirmation table, wave I–K (`docs/plans/2026-09-23-waves-i-j-k-execution.md`). Corrections to the `## Scope` above are kept visible here, not deleted there.

sts-refusal-draws-nothing
- `redemption.rs`, `issue.rs`, `store.rs`, `contracts/obligations/sts.json` — confirmed
- not in scope but needed: `services/sts/src/lib.rs` (`IdentityAllocator`), `services/control-plane/src/adapters.rs` (`SystemAllocator`, `StatedResourceServerIdentity`)
