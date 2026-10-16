---
format: aep.planning-md/3
id: story:signing-key-revocations-restart
kind: story
status: draft
title: Signing-key revocations survive a rebuild of the signer
relations:
- decomposes: epic:sts-credentials
- serves: vision:mandate
revision: 1
---
# Signing-key revocations survive a rebuild of the signer

## Acceptance

Given a signing key revoked through the declared `SigningKey` lifecycle, when the signer is rebuilt from the `SigningKey` fold (as a restart does), then it is constructed through `RealSigner::new_with_revocations` by a non-test caller and refuses to sign with the revoked key; test `revoked_key_stays_revoked_across_restart` passes, and the owner text at `crates/mandate-token/src/signing_real.rs` names this story instead of the closed `story:credential-profiles`.

## Scope

- `crates/mandate-token/src/signing_real.rs`
- the composition that builds the signer (`services/control-plane/src/adapters.rs` or `services/sts`)
- `systems/mandate/domains/credential.yaml` (only if the clause wording changes)
- `contracts/coverage.json`

## Source

Audit G-07 (story S-04).
