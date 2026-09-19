---
format: aep.planning-md/1
id: story:epoch-snapshot-generations
kind: story
status: draft
title: Security epoch snapshots declare their generations and refresh proofs resolve to sessions
relations:
- decomposes: epic:foundations
- informed_by: initiative:drift-enforcement
revision: 1
---
## Why

`mandate.identity.SecurityEpochSnapshot` declares no generation (`systems/mandate/domains/identity.yaml:132-148`) and `EpochSnapshotRecorded` carries none (`:350-359`), while the runtime snapshot (`crates/mandate-identity/src/snapshot.rs:83,85`) holds `principal_generation` and `organization_generation` and `services/sts/src/binding.rs:280-285` decides `StaleEpoch` on them. A stale-epoch scenario therefore cannot be established from a file: the runner would have to invent the generation. `mandate.identity.RefreshCredential` is projected by no crate (`mandate_identity::ESS_UNREALIZED`), so a refresh proof resolves to no session and `RefreshSession` is `Unsupported` in the conformance target.

Found by wave D (2026-09-19): `review-result:wave-d-authored-denials-adversary-2` F4/F5, `story:conformance-target` item 6. `story:session-epochs` is `implemented`, so this is the live home.

## Outcome

- `SecurityEpochSnapshot` declares its generations and `EpochSnapshotRecorded` carries them; the projections regenerate.
- `RefreshCredential` is projected in `mandate-identity` with a port from a refresh proof to its session.
- The authored scenarios `identity-stale-epoch-refresh` and `pkce-stale-session-epoch` return to `systems/mandate/scenarios/` and pass in the conformance run; `RefreshSession` leaves the target's unsupported set.

## Acceptance

`cargo xtask conform` reports the two stale-epoch scenarios and both `RefreshSession` scenarios `passed` with no standing double on the epoch path.
