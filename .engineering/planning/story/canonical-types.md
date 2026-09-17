---
format: aep.planning-md/1
id: story:canonical-types
kind: story
status: proposed
title: Realize accepted canonical Rust types
relations:
- decomposes: epic:foundations
- serves: vision:mandate
- depends_on: story:foundation-contracts
scope:
- confidence: cited
  path: Cargo.lock
- confidence: cited
  path: Cargo.toml
- confidence: cited
  path: crates/mandate-model
- confidence: cited
  path: crates/mandate-proto
- confidence: cited
  path: crates/mandate-token
- confidence: cited
  path: crates/mandate-types
- confidence: cited
  path: dependency-boundaries.json
revision: 9
---
# Realize accepted canonical Rust types

## Acceptance

Given the accepted ESS type set, when the canonical Rust conformance suite serializes and decodes each admitted type, then the canonical type conformance suite exits zero.

## Required observations

Realize the explicitly accepted ESS identifier, enum, record and wire types with deterministic serialization; prove PrincipalId cannot substitute OrganizationId and transient CredentialSecret/Proof cannot enter persisted records. Use ESS type realization support where admitted; account for every accepted type and exclusion. No numeric epochs, invented lifecycle, crypto, PDP or HTTP implementation. task check and compile-fail/round-trip tests pass.

## Scope

- `crates/mandate-types` — cited planned scope; canonical directory granularity.
- `crates/mandate-model` — cited planned scope; canonical directory granularity.
- `crates/mandate-token` — cited planned scope; canonical directory granularity.
- `crates/mandate-proto` — cited planned scope; canonical directory granularity.

## Validation and contract

`task check` and the runtime tests named above. `tests/security/cases.json` is a contract corpus, not runtime evidence. ESS: `systems/mandate/ess-inputs.yaml`. Source: `docs/requirements.md` and combined architecture.

## Final review disposition

Round-two acceptance found two independent results in the acceptance sentence. The final wording names one suite outcome; the required round-trip and compile-fail observations remain below it. This editorial correction was made after the final critic round and has not been re-reviewed; no third round is claimed.

## Scope and acceptance clarification after the technical review

The scope includes dependency-boundaries.json, Cargo.toml and Cargo.lock so required serialization dependencies can be admitted and pinned with the consuming crates. No external dependency is silently permitted by the existing gate.

The accepted realization set must explicitly exclude the empty principal/organization/federation generation ownership placeholders and the incomplete numerical SecurityEpochSnapshot representation until UNMAPPED-EPOCH is cleared. AuthoritySubject is an admitted tagged value type; its conditional storage foreign keys remain blocked under UNMAPPED-SUBJECT-RELATIONS. Realizing a value type does not implement those storage or policy semantics. The scope/exclusion inventory is required before dispatch; the first Wave remains a proposal and Drive still requires its reviewed verifier and operator spending limits.

These corrections follow review-result:design-review-1 and review-result:contracts-review-1. They do not rewrite those verdicts or claim another completed critic round.
