---
format: aep.planning-md/1
id: review-result:wave3-event-payloads-for-folds-adversary-1
kind: review-result
status: active
title: Adversary pass 1 — story:event-payloads-for-folds
tags:
- model-deviation-opus
relations:
- reviews: story:event-payloads-for-folds
revision: 1
---
```
unit: story:event-payloads-for-folds — working tree at <worktree>, branch impl/event-payloads-for-folds, uncommitted over base 0d1947d
verdict: CONFIRMED (blocker)
cases: executed 41→50, red 4
origin: introduced 6 / pre-existing 4 / undecided 0
wrote-outside-worktree: 5 paths under <scratch>/adv1-5BKiPJ/ and <scratch>/{.adv1-path,compile.err,compiled.json}
needs-coordinator: raise the 65→70 event pin at contract_adversary.rs:709; the D1 ruling's record.rs bound does not cover the two federation events this unit reshaped
```

## Diff under attack

```
 systems/mandate/domains/credential.yaml | 22 ++++++++++
 systems/mandate/domains/delegation.yaml | 33 ++++++++++++++
 systems/mandate/domains/directory.yaml  | 67 ++++++++++++++++++++++++++++
 systems/mandate/domains/federation.yaml | 78 ++++++++++++++++++++++++++++++---
 systems/mandate/domains/graph.yaml      | 31 +++++++++++++
 systems/mandate/domains/identity.yaml   | 44 +++++++++++++++++++
 systems/mandate/domains/tenancy.yaml    | 12 +++++
 7 files changed, 281 insertions(+), 6 deletions(-)
```

Adversary file: `crates/mandate-types/tests/adversary_fold_inputs.rs` (9 cases; 3 red, 6 green including the residue tripwire pinning 15 entities). `contract_adversary` red only on the 65-event pin (`:709`), 8 pass. `ess specify validate` valid.

## Findings

```yaml
findings:
  - id: F1
    severity: high
    verdict: CONFIRMED
    origin: introduced
    location: "systems/mandate/components.yaml:53"
    message: "The five events this unit added are published by no component, so no deployment in the contract is declared to write them, while the audit.yaml precedent their own headers cite is published by mandate-worker at components.yaml:157."
  - id: F2
    severity: high
    verdict: CONFIRMED
    origin: introduced
    location: "systems/mandate/domains/graph.yaml:172"
    message: "ResourceRegistered.id, ResourceRegistered.resource_type and RelationshipWritten.resource_id are declared generated: true although RegisterResource and WriteRelationship take those exact values from the caller inside input.resource: ResourceRef, so the folded row names a type and a resource no request asked for."
  - id: F3
    severity: medium
    verdict: NEEDS-CHANGE
    origin: introduced
    location: "systems/mandate/domains/directory.yaml:438"
    message: "DirectoryGroupMembership and MembershipContribution fold only if the reader pairs membership_ids with principal_ids and contributions with team_membership_ids by index, which nothing in the contract declares, so the real unfoldable residue is 17 entities and not 15."
  - id: F4
    severity: medium
    verdict: CONFIRMED
    origin: pre-existing
    location: "crates/mandate-types/tests/adversary_fold_inputs.rs:357"
    message: "Fifteen of the thirty-two entities with a declared transition still cannot be rebuilt from the event log, eleven of them in the seven domain files this story owns, so the acceptance statement does not hold as written."
  - id: F5
    severity: medium
    verdict: CONFIRMED
    origin: pre-existing
    location: "systems/mandate/domains/identity.yaml:275"
    message: "RefreshSession and federation.AuthorizePublicClient still mint a VerifiedContext with generated: true although neither takes a context input and VerifiedContext.credential is required, which is the same defect shape (a) fixed on two events in this commit."
  - id: F6
    severity: medium
    verdict: NEEDS-CHANGE
    origin: introduced
    location: "crates/mandate-federation/src/lib.rs:141"
    message: "The RequestContext doc comment and the FederationEvent variants at record.rs:173 and :194 still describe a context field that these two events no longer have, and no test in any crate compares a Rust event type against the yaml, so the drift is silent."
  - id: F7
    severity: medium
    verdict: CONFIRMED
    origin: introduced
    location: "systems/mandate/domains/directory.yaml:320"
    message: "DirectoryGroupMembershipChanged.principal_ids is sourced from input.members with nothing declaring whether it is the full post-sync set or a delta, and a fold computes removals differently under each reading."
  - id: F8
    severity: medium
    verdict: CONFIRMED
    origin: introduced
    location: "systems/mandate/domains/identity.yaml:7"
    message: "The header names mandate.federation.AuthenticateFederation as the writer of the three identity seeding events, but that command's accepted outcome emits only FederationAuthenticated and the generated contract states nothing in the system emits them; directory.yaml:5 names no command at all."
  - id: F9
    severity: low
    verdict: CONFIRMED
    origin: pre-existing
    location: "systems/mandate/domains/credential.yaml:148"
    message: "mandate.credential.TokenExchangeDenied has no producing command, so eleven events are producerless rather than the ten the unit accounts for; it is published by mandate-sts, so it is not part of the writer finding."
  - id: F10
    severity: low
    verdict: CONFIRMED
    origin: pre-existing
    location: "systems/mandate/domains/federation.yaml:266"
    message: "mandate.identity.Principal folds only because its one creation event pins kind to the literal User and declares display_name generated: true, so a rebuilt Principal row carries a display name the runtime invented."
```

## Attacked and could not break

Every `moves` outcome carries the moved record's identity (34 of 34). `ess specify validate` clean, and it does not enforce `components.yaml` publish coverage, event producers or payload-source sanity. No event carries `CredentialSecret`/`CredentialProof`. No event has two producers; 110/59/36 pins unmoved. Yaml and compiled field lists agree for all 70 events. `DirectoryGroupRecorded`/`SyncJobRecorded` field types match their entities. No new type smuggled in.
