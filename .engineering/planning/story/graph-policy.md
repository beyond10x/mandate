---
format: aep.planning-md/1
id: story:graph-policy
kind: story
status: draft
title: Implement graph and policy ports with chosen adapter
relations:
- decomposes: epic:authorization
- serves: vision:mandate
- depends_on: story:canonical-types
scope:
- confidence: cited
  path: crates/mandate-graph
- confidence: cited
  path: crates/mandate-policy
revision: 3
---
# Implement graph and policy ports with chosen adapter

## Acceptance

Given a grant revoked at revision R, when the graph/policy port checks inherited access with minimum revision R, then it returns denied without leaking concrete backend types.

## Required observations

Choose graph and policy engine in ADR before concrete adapter; inheritance, deny precedence, role bundles, revision/consistency and mutation idempotency tested. graph-revocation passes at required revision; backend types do not leak into domain.

## Scope

- `crates/mandate-graph` — cited planned scope; canonical directory granularity.
- `crates/mandate-policy` — cited planned scope; canonical directory granularity.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.
