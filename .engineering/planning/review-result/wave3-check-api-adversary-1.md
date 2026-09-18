---
format: aep.planning-md/1
id: review-result:wave3-check-api-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — story:check-api
tags:
- model-deviation-opus
relations:
- reviews: story:check-api
revision: 1
---
```
unit: story:check-api — working tree at <worktree>, branch impl/check-api, uncommitted over base 0d1947d
verdict: CONFIRMED (blocker)
cases: executed 41→48, red 6
origin: introduced 6 / pre-existing 0 / undecided 0
wrote-outside-worktree: 1 path (<scratch>/suite-after-tuYuzN.log)
needs-coordinator: whether the actor half of combined.md:53 is this story's or story:agent-security's
```

## Diff under attack

```
 crates/mandate-authz/src/context.rs          | 146 +++++
 crates/mandate-authz/src/decision.rs         | 278 ++++++++++
 crates/mandate-authz/src/evaluate.rs         | 252 +++++++++
 crates/mandate-authz/src/lib.rs              | 196 ++++++-
 crates/mandate-authz/tests/check_contract.rs | 535 ++++++++++++++++++
 crates/mandate-authz/tests/context.rs        | 329 ++++++++++++
 crates/mandate-authz/tests/decision.rs       | 447 +++++++++++++++
 crates/mandate-authz/tests/evaluate.rs       | 777 +++++++++++++++++++++++++++
 8 files changed, 2957 insertions(+), 3 deletions(-)
```

Adversary file: `crates/mandate-authz/tests/adversary_check.rs` (7 cases; 6 red, 1 green). Suite after: `adversary_check` FAILED 1 passed 6 failed; `check_contract` 6, `context` 9, `decision` 11, `evaluate` 15 ok.

## Findings

```yaml
findings:
  - id: F1
    severity: high
    verdict: CONFIRMED
    origin: introduced
    location: "crates/mandate-authz/src/context.rs:115"
    message: "check reads AuthorityScope.space and never reads its actions or resources, so a request made under a scope covering no action, another action or another resource is allowed (adversary_check.rs:230,242,260), while combined.md:53 puts requested authority inside the intersection and evaluate.rs:81 applies the opposite closed direction to a ceiling's empty allowed_actions in the same commit."
  - id: F2
    severity: high
    verdict: CONFIRMED
    origin: introduced
    location: "crates/mandate-authz/src/context.rs:104"
    message: "VerifiedContext.actor is read by no line of the crate (grep over src/ returns zero hits), so membership, the graph query and the ceilings all concern the subject alone and a delegated request decides identically to a direct one (adversary_check.rs:281), against combined.md:53's actor-ceiling intersection and the package's own subject/actor remit."
  - id: F3
    severity: medium
    verdict: INFEASIBLE
    origin: introduced
    location: "crates/mandate-authz/src/decision.rs:205"
    message: "A PolicyError::Denied(ApprovalRequired) is rewritten to Unavailable, reporting a decision policy did make as an outage and contradicting denial_reason()'s promise, but no adapter or double in the tree emits that error today so the adversary built the state."
  - id: F4
    severity: low
    verdict: INFEASIBLE
    origin: introduced
    location: "crates/mandate-authz/src/decision.rs:156"
    message: "An allow returns before Authority.challenges is read, so challenge material attached to a PolicyEffect::Allow evaluation is dropped and the caller is told there is nothing to satisfy; the port documents challenge as carried only with ApprovalRequired, so no conforming adapter reaches it."
  - id: F5
    severity: low
    verdict: CONFIRMED
    origin: introduced
    location: "crates/mandate-authz/src/evaluate.rs:233"
    message: "Authority.challenges has one writer over a single Option, so strictest never ranks more than one requirement in any reachable state and tests/decision.rs:283 exercises the two-source case only by hand-building an Authority that evaluate cannot produce."
  - id: F6
    severity: low
    verdict: CONFIRMED
    origin: introduced
    location: "crates/mandate-authz/tests/decision.rs:389"
    message: "every_declared_denial_reason_is_told_under_its_own_name proves the DenialReason-to-DecisionReason mapping from hand-built Authority values, not that check can produce each reason; StaleEpoch has no producer in mandate-graph or mandate-policy, so no check can ever tell a caller that reason."
```

## Attacked and could not break

Stale `Observed.revision` below `minimum` (no ordering on `AuthzRevision` in the ceiling; `port.rs:161` assigns the floor to the reader); ceilings (`tests/evaluate.rs:396-572` kills the mutants tried); deny precedence (consumed from `mandate-policy`); `allowed`/`reason` consistency; audience+tenant together (fixed `bind` order); duplicate `DecisionId` and past `expires_at` (the port double's contract); determinism (green). Mutation probe not run (the only unkillable guard by reading is in `mandate-policy`, outside the unit).
