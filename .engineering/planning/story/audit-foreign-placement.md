---
format: aep.planning-md/3
id: story:audit-foreign-placement
kind: story
status: draft
title: Graph placement and resource registration answer a foreign id like an unknown one
relations:
- decomposes: epic:authorization
- serves: vision:mandate
revision: 1
---
# Graph placement and resource registration answer a foreign id like an unknown one

## Acceptance

Given `systems/mandate` stating the answer for a placement lookup and a resource registration whose id another organization holds, validated with `ess specify validate --strict-requires`, when `cargo test -p mandate-graph` and `cargo xtask conform` run, then the graph `placement` of a foreign-held resource answers exactly as an unknown one, `register_resource` with a foreign-held id answers exactly as the declared refusal for an unknown caller, and no answer names or reveals the other organization.

## Context

Audit gap G-48, remainder: `placement` answers `Unavailable` for an unknown resource and `TenantMismatch` for a foreign one, and changing it is a contract change that needs its own design (decision-blocker:audit-small-fixes-scope). The session revoke and the graph and policy doubles were made to answer alike in the audit's small code fixes.

## Scope

- `crates/mandate-graph/src/{lib,double}.rs`, `systems/mandate/domains/` (the graph commands), the matching scenarios
