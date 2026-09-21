---
format: aep.planning-md/1
id: story:sts-refusal-draws-nothing
kind: story
status: draft
title: STS handlers draw from the secret source and allocator only after every refusal
relations:
- decomposes: epic:foundations
- informed_by: initiative:drift-enforcement
- serves: vision:mandate
revision: 1
---
## Why

Two handlers in `services/sts` draw from the deployment before a refusal they can still make (`review-result:wave-d-obligations-sts-adversary-2` F1, F2). `redeem_and_consume` mints the reference secret and the credential identity (`src/redemption.rs:354-357`) and only then appends under a compare-and-set (`:436`); the losing half of two concurrent redemptions has drawn both when the append refuses. `issue_self_contained_credential` draws the credential identity (`src/issue.rs:424`) before `sign_credential` can refuse (`SigningRefused`, `:436`). `systems/mandate/domains/credential.yaml:245` says a failed or replayed transaction produces no credential, and every other handler in the crate ("Nothing above this line mints anything") draws last.

## Outcome

Every refusal a handler can still make precedes any draw from the secret source or the identity allocator; the losing compare-and-set half and a signer-refused issuance leave both untouched.

## Acceptance

`services/sts/tests/adversary_obligations_sts_2.rs` cases `a_redemption_that_loses_its_compare_and_set_has_already_drawn_credential_material` and `a_self_contained_issuance_refused_by_the_signer_has_already_drawn_a_credential_identity` are flipped to assert no draw and are green; `cargo test -p mandate-sts --locked` exits 0; the `no_state_change` rows of both commands in `contracts/obligations/sts.json` name a case that inspects the secret source and the allocator on the refusing path.
