---
format: aep.planning-md/1
id: story:constrained-exchange
kind: story
status: draft
title: Implement authority-bearing constrained exchange
relations:
- decomposes: epic:sts-credentials
- serves: vision:mandate
- depends_on: story:credential-profiles
- depends_on: story:check-api
- depends_on: story:session-epochs
- depends_on: story:agent-authority-kernel
- informed_by: initiative:next-ten-waves
scope:
- confidence: cited
  path: services/sts
revision: 3
---
# Implement authority-bearing constrained exchange

## Acceptance

Given a delegated subject/actor credential request, when STS exchanges it, then the resulting credential represents no authority, target or validity interval outside the intersection of all applicable input bounds.

## Required observations

Both core tracks accepted. Every exchange corpus case passes on runtime, plus property tests for set intersection/expiry minimum and service downstream example. Preserve subject/actor, apply agent ceilings and delegation, reject transitive chains and target escalation.

## Scope

- `services/sts` — cited planned scope; canonical directory granularity.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.

## Ten-wave refinement

The original story requires ceilings and delegation checks, while agent-security originally depended on exchange. story:agent-authority-kernel now owns those reusable checks and is a typed prerequisite here; this STS unit consumes them and owns credential narrowing/issuance. Later agent-security owns per-tool PEP integration. Source: this story Required observations and docs/architecture/combined.md:7. This resolves an inferred ordering gap without removing either security obligation.
