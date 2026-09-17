---
format: aep.planning-md/1
id: story:advanced-delegation
kind: story
status: draft
title: Review advanced delegation and global trust options
relations:
- decomposes: epic:advanced-delegation
- serves: vision:mandate
- depends_on: story:agent-security
scope:
- confidence: cited
  path: docs/rfcs
revision: 2
---
# Review advanced delegation and global trust options

## Acceptance

Given the implemented single-hop security model, when the advanced-delegation proposal is reviewed, then one recorded decision either admits a bounded next design or keeps advanced delegation disabled.

## Required observations

Deferred: require explicit design approval and threat review before implementation. Decide global linking and device flow separately; prove every proposed chain retains actors and narrows scope/audience/expiry.

## Scope

- `docs/rfcs` — cited planned scope; canonical directory granularity.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.
