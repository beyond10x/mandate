---
format: aep.planning-md/3
id: story:audit-sealed-decided
kind: story
status: draft
title: Decider results narrow to what was decided
relations:
- decomposes: epic:authorization
- serves: vision:mandate
revision: 1
---
# Decider results narrow to what was decided

## Acceptance

Given every `decide_*` function of `crates/mandate-authz/src/command.rs` returning a sealed `Decided<E>` that only that crate constructs, when `cargo test -p mandate-authz -p mandate-control-plane` runs, then `services/control-plane/src/adapters.rs` `record_delegation` accepts only a `Decided<DelegationEvent>`, a test that builds a `DelegationEvent` by hand and passes it does not compile (a `trybuild` or doc `compile_fail` case), and the existing decider tests pass unchanged in outcome.

## Context

Audit gap G-46: the control plane records any `DelegationEvent` it is given without re-deciding it. `Result<DelegationEvent, Denied>` narrows nothing, because the event type is public. A sealed wrapper reaches about 80 call sites, which is more than a small fix (decision-blocker:audit-small-fixes-scope).

## Scope

- `crates/mandate-authz/src/command.rs` and its callers in `crates/mandate-authz`, `crates/mandate-conformance`, `services/control-plane`
