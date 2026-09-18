---
format: aep.planning-md/1
id: story:agent-authority-kernel
kind: story
status: draft
title: Implement shared agent authority and delegation checks before exchange
relations:
- decomposes: epic:agents-workloads
- serves: vision:mandate
- depends_on: story:check-api
- depends_on: story:session-epochs
- informed_by: initiative:next-ten-waves
scope:
- confidence: inferred
  path: crates/mandate-authz
- confidence: inferred
  path: crates/mandate-policy
revision: 4
---
# Implement shared agent authority and delegation checks before exchange

## Acceptance

Given a subject, independently authenticated actor, applicable ceilings, delegation and requested capability, when the shared authority evaluator checks the request, then its permitted set is exactly the applicable intersection and never exceeds any input bound.

## Required observations

Property cases cover autonomous and delegated agents, platform/tenant ceiling intersection, expired or revoked delegation and disabled actor, mismatched organization, unchanged subject/actor, minimum expiry, absent required evidence, transitive-chain denial and approval-required as allowed=false. This story owns reusable evaluation functions used by STS; story:agent-security subsequently owns tool-call PEP and execution integration. Consume existing typed records behind ports; no token issuance, HTTP, new workload federation or persistence implementation. Ceiling uniqueness must have a reviewed admission rule before accepting runtime data.

## Contract and provenance

systems/mandate/domains/delegation.yaml: Agent, AgentCapabilityCeiling, Delegation, Execution and Approval; domains/core.yaml: VerifiedContext and AuthorityScope; domains/authorization.yaml: Check. No new entity.

Sources: docs/architecture/combined.md:7; docs/sources/architecture-addendum.md:554; .engineering/planning/story/constrained-exchange.md:25; .engineering/planning/story/agent-security.md:23. Placement in wave 5 is a coordinator inference from dependencies and ownership, not an approved work order.

## Scope

Derived 2026-09-18 by `story-scoper`; read-only conditional preparation. Each assessment is marked cited or inferred.

- **Primary surface:** `crates/mandate-authz` — inferred implementation surface for reusable authority intersection, subject/actor preservation, delegation validation and expiry bounds; the ownership map assigns delegation intersections to this package.
- **Also likely:** `crates/mandate-policy` — inferred implementation surface for applicable ceiling intersection, deny precedence and approval-required evaluation through existing policy ports.
- **Files:** package-local source modules and executable property tests — inferred; exact filenames depend on the preceding check API implementation.
- **Symbols:** Agent, AgentCapabilityCeiling, Delegation, Execution, Approval, VerifiedContext, AuthorityScope and Check — cited existing ESS declarations; the story introduces no new entity.
- **Documents:** none required by the acceptance — cited; this story owns executable evaluation.
- **Boundary:** consume authenticated inputs, typed records and current-state evidence through ports; token issuance, HTTP, workload federation, persistence and tool-call execution integration remain outside this unit — cited.
- **Confidence:** medium — inferred; package ownership is established, but both packages currently contain foundation scaffolds and no evaluator or port symbols.
- **Would collide with:** any unit changing `crates/mandate-authz` or `crates/mandate-policy`, including their package-local runtime tests — inferred.

## Validation

Run meaningful package or document checks named in the implementation brief, preserve the initially failing runtime cases where applicable, report executed case counts, then run `task check` on integration. Contract corpus validation alone is not runtime evidence. Every nonterminal prerequisite and open decision blocker must be resolved before dispatch.
