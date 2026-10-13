---
format: aep.planning-md/3
id: decision-blocker:identity-uniqueness
kind: decision-blocker
status: cleared
title: UNMAPPED-UNIQUENESS
relations:
- blocks: story:federation-linking
- blocks: story:credential-profiles
- blocks: story:agent-security
revision: 4
transitions:
- {from: "open", to: "cleared", at: "2026-10-13T05:20:16Z", actor: "human:timo", revision: 4, decided_on: {"recorded":{"approval":1}}}
---
Enforce external key uniqueness by organization, immutable configured issuer and external subject; connection/organization agreement; organization-local registered audience uniqueness; and one current ceiling per agent and platform/tenant scope. Enforce these atomically in storage. Issuer is derived from the validated connection. Nominal IDs and plain JSON Schema do not establish composite uniqueness.

Source: `docs/architecture/unmapped.md`, `docs/architecture/ownership.md` and the preserved technical reviews. Clear only with concrete reviewed semantics and verification evidence.

## Ceiling half decided (2026-10-12)

The ceiling key, the current record and the conflict rule are decided in `decision-blocker:identity-uniqueness-ceiling`, which now blocks `story:agent-authority-kernel` in place of this record. The external-principal, audience and exchange-source halves, and runtime ceiling data for `story:agent-security`, stay open here.

## Decided (operator, 2026-10-13)

The three remaining halves are decided on the enforcement that already ships, the pattern `decision-blocker:identity-uniqueness-ceiling` chose for the ceiling: the command path refuses before it emits, and the fold keeps a conflict view so a race is recorded rather than resolved silently.

- **External principal.** The key is (organization, issuer of the validated connection, external subject); the issuer is read from the connection, never supplied. `link_external_principal` and `provision_external_principal` deny on a held key; the fold reports `ExternalKeyConflict`, and the smallest `external_principal_id` holds the key (`crates/mandate-federation/src/record.rs:330-350`, `:765-780`).
- **Audience.** A resource-server audience is unique among the enabled registrations of one organization. `RegisterResourceServer` refuses through `admits_audience` (`services/sts/src/registry.rs:224-226`); the projection reports `AudienceConflict` (`crates/mandate-token/src/projection.rs:440-454`).
- **Exchange sources.** Every allowed source resolves to a registration that is enabled and in the verified organization at registration (`services/sts/src/registry.rs:231-250`), and an exchange whose subject credential's registration is not listed is denied `SourceUnadmitted` (`services/sts/src/exchange.rs:475`).
- **Runtime ceiling data.** A capability ceiling enters only through `SupersedeAgentCapabilityCeiling`, under the key, current-record and conflict rule of `decision-blocker:identity-uniqueness-ceiling`. `story:agent-security` owns that command.

## Moved, not decided here

Atomic enforcement of these keys in storage (a unique index) needs persistence. It is `decision-blocker:identity-uniqueness-storage`, which blocks `story:domain-folds-over-the-kit`.
