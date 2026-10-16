---
format: aep.planning-md/3
id: story:session-proof-contract
kind: story
status: draft
title: The session proof is part of the contract
relations:
- decomposes: epic:authentication
- serves: vision:mandate
revision: 1
---
# The session proof is part of the contract

## Acceptance

Given `AuthenticateFederation`'s declared response revised to include `session_proof`, when a login succeeds, then the proof's verifier is recorded by a declared event and the control plane resolves session proofs at `GET /oauth/authorize` from that record alone; ESS scenario `authorize-with-unknown-session-proof` passes, and the generated OpenAPI response carries `session_proof`.

## Scope

- `systems/mandate/domains/federation.yaml`, `systems/mandate/domains/identity.yaml`
- `services/control-plane/src/serve.rs`, `services/control-plane/src/adapters.rs`
- `crates/mandate-identity` (session verifier record)

## Source

Audit G-39 (story S-16).
