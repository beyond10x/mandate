---
format: aep.planning-md/3
id: story:decision-model-version-reauth
kind: story
status: draft
title: Decisions report their model version and a reauthentication requirement
relations:
- decomposes: epic:authorization
- serves: vision:mandate
revision: 1
---
# Decisions report their model version and a reauthentication requirement

## Acceptance

Given an authorization model with a recorded version and a policy that requires reauthentication, when `mandate.authorization.Check` decides a request, then `Decision.model_version` carries that version (typed `AuthorizationModelVersion`), and a reauthentication challenge is answered as the declared `DecisionChallenge.requirement` instead of `Unavailable`. ESS scenarios `check-reports-model-version` and `check-reauthentication-challenge` pass, and `story:check-api`'s "no owning story yet" residue names this story.

## Scope

- `systems/mandate/domains/policy.yaml`, `systems/mandate/domains/core.yaml` (`AuthorizationModel.version`, `DecisionChallenge`)
- `crates/mandate-authz/src/decision.rs`, `crates/mandate-authz/src/lib.rs`
- `crates/mandate-policy` (model version read)
- `contracts/coverage.json`

## Source

Audit G-11 (story S-05).
