---
format: aep.planning-md/3
id: story:supersede-agent-ceiling
kind: story
status: draft
title: Supersede an agent capability ceiling
relations:
- decomposes: epic:agents-workloads
- serves: vision:mandate
revision: 1
---
# Supersede an agent capability ceiling

## Acceptance

Given a recorded agent with a capability ceiling, when `mandate.delegation.SupersedeAgentCapabilityCeiling` is decided over the seeded ceilings, then the declared move is realized and its event is folded so that `Check` reads the new ceiling; if the current ESS cannot express a create beside a move in one outcome, the specification is changed once ESS admits that shape and the story records the stop. The command's `/outcome/accepted` and `/outcome/denied` scenarios pass, and the command leaves `ESS_UNREALIZED` in `crates/mandate-authz/src/lib.rs`.

## Scope

- `systems/mandate/domains/delegation.yaml` (`SupersedeAgentCapabilityCeiling`)
- `crates/mandate-authz/src/command.rs`, `crates/mandate-authz/src/event.rs`, `crates/mandate-authz/src/lib.rs`
- `contracts/coverage.json`, `contracts/obligations/authz.json`

## Source

Audit G-14 (story S-08).
