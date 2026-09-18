---
format: aep.planning-md/1
id: review-result:wave3-event-payloads-for-folds-adversary-2
kind: review-result
status: active
title: Adversary pass 2 — story:event-payloads-for-folds
tags:
- model-deviation-opus
relations:
- reviews: story:event-payloads-for-folds
revision: 1
---
```
unit: story:event-payloads-for-folds, adversary pass 2 (final) — working tree at <worktree>, branch impl/event-payloads-for-folds, uncommitted correction round 1 over base 0d1947d
verdict: CONFIRMED (blocker)
cases: executed 50→56, red 4
origin: introduced 5 / pre-existing 3 / undecided 0
wrote-outside-worktree: 1 path (<scratch>/adv2-FTZpuL/ and <scratch>/.adv2-path)
needs-coordinator: raise the event pin 65→72 at contract_adversary.rs:709; decide the publishing component for the four directory seeding events; extend the D1 alignment bound to SessionRefreshed
```

Adversary file this pass: `crates/mandate-types/tests/adversary_fold_inputs_2.rs` (6 cases; 3 red, 3 green), with an exact-type reader that descends one level into carried structs and never into `VerifiedContext`. Pass 1's 9 cases green; `contract_adversary` red only on its 65 pin.

## Findings

```yaml
findings:
  - id: G1
    severity: high
    verdict: NEEDS-CHANGE
    origin: introduced
    location: "systems/mandate/components.yaml:166"
    message: "mandate-worker publishes four mandate.directory events while owning only mandate.audit; mandate.directory is owned by mandate-control-plane, which also accepts every directory command including SyncDirectoryMembership, so the deployment declared to write those records is neither the owner of their domain nor the component that accepts the commands causing them; at base all 65 events were published by their domain's owner; ess specify validate enforces nothing about it."
  - id: G2
    severity: medium
    verdict: NEEDS-CHANGE
    origin: introduced
    location: "crates/mandate-types/tests/adversary_fold_inputs.rs:357"
    message: "The recorded residue of sixteen entities includes mandate.graph.Relation and mandate.audit.AuditEvent, both of which fold once the reader descends one level into a carried struct (RelationshipWritten.resource: ResourceRef carries resource_id exactly; AuditEventRecorded.record: AuditRecord carries all 20 fields), so the true residue is fourteen and resource: ResourceRef is enough to rebuild Relation."
  - id: G3
    severity: medium
    verdict: NEEDS-CHANGE
    origin: introduced
    location: "systems/mandate/domains/directory.yaml:318"
    message: "DirectoryGroupMembershipChanged and DirectoryGroupTeamMappingCreated name rows by identity from mandate-control-plane while the only events that create those rows are published by mandate-worker, and no correlation or declared order joins the two writers."
  - id: G4
    severity: medium
    verdict: NEEDS-CHANGE
    origin: introduced
    location: "systems/mandate/domains/identity.yaml:275"
    message: "SessionRefreshed generates principal_id and organization_id, two facts SessionOpened already carries for the same session with nothing declaring they agree, while the crate that produces the outcome (crates/mandate-identity/src/session.rs:42) carries only session_id and still documents a context the event no longer has; the identity fold does not consume SessionRefreshed."
  - id: G5
    severity: medium
    verdict: NEEDS-CHANGE
    origin: introduced
    location: "crates/mandate-federation/src/lib.rs:141"
    message: "Pass-1 F6 still stands: the RequestContext doc comment and the FederationEvent variants at record.rs:173 and :194 still describe a context field that FederationAuthenticated and ExternalPrincipalProvisioned no longer have; no test compares a Rust event type against the yaml."
  - id: G6
    severity: medium
    verdict: CONFIRMED
    origin: pre-existing
    location: "crates/mandate-types/tests/adversary_fold_inputs_2.rs:334"
    message: "Fourteen of the thirty-two entities with a declared transition still cannot be rebuilt from the event log, ten of them in the seven domain files this story owns."
  - id: G7
    severity: medium
    verdict: CONFIRMED
    origin: pre-existing
    location: "systems/mandate/domains/credential.yaml:216"
    message: "ExchangeCredential, IntrospectCredential and RedeemAuthorizationCode still mint a VerifiedContext with generated: true although none takes a context input and VerifiedContext.credential is required."
  - id: G8
    severity: low
    verdict: CONFIRMED
    origin: pre-existing
    location: "systems/mandate/domains/credential.yaml:148"
    message: "mandate.credential.TokenExchangeDenied still has no producing command, so thirteen events are producerless: the five audit events, this one and the seven seeding events."
```

## Attacked and could not break

The six per-record seeding events mirror their entities exactly (names, types, order, identity first; `MembershipContribution.mapping_id` is `Optional` on the entity). Every emitted event is published by exactly one component; 72 of 72 published. `challenge` on `AuthorizationCodeIssued` is not credential material (`crates/mandate-types/src/marker.rs:32-41`, `inventory.rs:216-227`; RFC 7636 §4.3 sends `code_challenge` through the user agent). The pins hold after regeneration: 110/36 unchanged; 53 `mandate.core.*` types on events all in `mandate-proto`'s 78-entry accepted set; `ResourceRef` already in `WIRE_CONTRACTS` (`lib.rs:213`). Could not establish: the intended host for the directory seeding events (prose and ownership disagree); whether the regeneration commit is expected to grow the crate-side `SessionRefreshed`.
