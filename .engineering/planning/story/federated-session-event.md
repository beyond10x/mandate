---
format: aep.planning-md/3
id: story:federated-session-event
kind: story
status: draft
title: Federated sessions open through FederationAuthenticated
relations:
- decomposes: epic:authentication
- serves: vision:mandate
revision: 1
---
# Federated sessions open through FederationAuthenticated

## Acceptance

Given a direct login at `POST /v1/federation/login` and a relying-party login through the handoff, when either opens a session, then the session is folded from `FederationAuthenticated` as `identity.yaml` declares rather than from `SessionOpened`, and a replay test rebuilds the federated session from that event alone.

## Scope

- `systems/mandate/domains/identity.yaml` (only if the declaration changes)
- `services/control-plane/src/adapters.rs` (session opening)
- `crates/mandate-identity/src/session.rs`, `crates/mandate-identity/src/port.rs`

## Source

Audit G-44 (story S-20).
