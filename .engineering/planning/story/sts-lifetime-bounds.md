---
format: aep.planning-md/1
id: story:sts-lifetime-bounds
kind: story
status: draft
title: Resource-server profiles are bounded to the renderable timeline
relations:
- decomposes: epic:foundations
- informed_by: initiative:drift-enforcement
- serves: vision:mandate
revision: 1
---
## Why

`services/sts/src/registry.rs:142` `admits_profile` asks only that `max_ttl` is a positive span. A registration with `max_ttl: PT99999999H` is admitted, `issue_reference_credential` then mints a secret and issues `expires_at` `13434-08-30T15:00:00Z`, and `services/sts/src/lib.rs:312-320` reads that instant back as `None`, so the credential is not live at the instant it was minted (`review-result:wave-d-obligations-sts-adversary-1` F2). `services/control-plane/src/adapters.rs:1477` `renders_readably` refuses the same span for the code and session lifetimes at startup; the profile reaches the same renderer with no bound.

## Outcome

`admits_profile` refuses a `max_ttl` whose span, added to any instant the crate renders, leaves the four-digit year, and every issuance path refuses an `expires_at` the crate's own reader cannot read back.

## Acceptance

`register_resource_server` with `max_ttl: PT99999999H` is refused with `ProfileUnadmitted`; `services/sts/tests/adversary_obligations_sts_1.rs` case `a_profile_bound_past_the_readable_year_is_refused_or_renders_readably` asserts the refusal and is green; `cargo test -p mandate-sts --locked` exits 0.
