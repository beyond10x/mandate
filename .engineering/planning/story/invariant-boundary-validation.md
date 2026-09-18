---
format: aep.planning-md/1
id: story:invariant-boundary-validation
kind: story
status: draft
title: Enforce entity invariants the schema projection drops
relations:
- decomposes: epic:hardening
- serves: vision:mandate
- depends_on: story:protocol-adapters
revision: 1
---
# Enforce entity invariants at the boundary the schema projection drops them at

## Acceptance

Given a record whose entity invariant bounds a field, when a value outside the bound arrives at a product adapter, then it is refused before any command runs, although `generated/schema/entities/**` admits it.

## Required observations

ESS 0.25.0 projects an entity `invariants:` entry into prose only; the JSON Schema for the entity carries no `minimum`, `const` or equivalent. Found by the wave-2 adversary against `story:domain-runtime`: `Delegation.transitive` declares `transitive == false` and projects as `{"type":"boolean"}`; the three epoch `generation >= 0` invariants project as `{"type":"integer"}`. The projection is ESS's; the mitigation here is boundary validation in the trusted adapter (`story:protocol-adapters`, `context` unit) against the compiled IR's invariants, and a test that every declared invariant has a boundary check. The ESS-side fix is out of this repository.

## Scope

- `crates/mandate-server/src/context.rs` — inferred; after `story:protocol-adapters`.
- Read, not written: the compiled IR from `ess specify compile`.
