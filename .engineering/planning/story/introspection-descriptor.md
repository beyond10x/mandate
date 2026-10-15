---
format: aep.planning-md/3
id: story:introspection-descriptor
kind: story
status: draft
title: Introspection answers the declared descriptor and records its event
relations:
- decomposes: epic:sts-credentials
- serves: vision:mandate
revision: 1
---
# Introspection answers the declared descriptor and records its event

## Acceptance

Given a control plane serving an active reference credential, when a registered resource server calls `POST /oauth/introspect` for it, then the answer carries `exp`, `scope`, the organization and `act` (when the credential names an actor) beside today's `active`, `credential_id`, `aud` and `sub`, and exactly one `mandate.credential.CredentialIntrospected` is appended; an inactive answer appends the event without the descriptor. ESS scenarios `introspect-active-descriptor` and `introspect-event-recorded` pass under `cargo xtask conform`, and `services/control-plane/tests/serve.rs` asserts the rendered members.

## Scope

- `systems/mandate/domains/credential.yaml` (`CredentialDescriptor`, `CredentialIntrospected`; scenarios under `systems/mandate/scenarios/`)
- `services/control-plane/src/serve.rs` (introspection rendering)
- `services/control-plane/src/adapters.rs` (`Deployment::introspect`, event append)
- `services/sts/src/resolve.rs`
- `docs/public/federated-login.md` (introspection members)

## Source

Audit G-01 (story S-01).
