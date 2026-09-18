# Audit routing obligations

The worker's trusted `mandate.audit.RecordAuditEvent` port accepts a redacted `AuditRecord` and returns an `AuditEventId`. The source deployment must supply authenticated emitter context independently of the optional subject and tenant of the event. An invalid credential can leave those fields unknown; client selectors cannot fill them in.

The following table maps all 18 categories in addendum §14. Names in the first column are the required audit vocabulary; a source notification is not itself proof of durable audit persistence. `UNMAPPED-AUDIT-ROUTING` blocks runtime acceptance of delivery, transactional outboxes, deduplication and failure policy. Dedicated audit notifications without a source mutation port remain declarations pending the named story.

| Audit category | Source notification / remaining producer obligation | Story |
|---|---|---|
| external_principal.linked | federation.ExternalPrincipalLinked | federation-linking |
| external_principal.unlinked | federation.ExternalPrincipalUnlinked; audit.ExternalPrincipalUnlinked is its redacted notification shape | federation-linking |
| federation.connection.created | federation.FederationConnectionCreated | federation-linking |
| federation.connection.changed | audit.FederationConnectionChanged; there is no update command — a changed connection is DisableFederationConnection plus RegisterFederationConnection (immutable-with-status, 2026-09-18) | federation-linking |
| federation.connection.disabled | federation.FederationConnectionDisabled | session-epochs |
| security_epoch.incremented | identity.SecurityEpochIncremented; numeric mutation remains UNMAPPED-EPOCH | session-epochs |
| directory_group.created | audit.DirectoryGroupCreated; provisioning producer remains UNMAPPED-ORCHESTRATION | directory-provenance |
| directory_group.membership_changed | directory.DirectoryGroupMembershipChanged and DirectoryGroupMembershipRemoved | directory-provenance |
| directory_group.team_mapping_created | directory.DirectoryGroupTeamMappingCreated | directory-provenance |
| directory_group.team_mapping_removed | directory.DirectoryGroupTeamMappingRemoved | directory-provenance |
| resource_server.registered | credential.ResourceServerRegistered | credential-profiles |
| resource_server.disabled | credential.ResourceServerDisabled | credential-profiles |
| credential.reference_issued | credential.CredentialReferenceIssued | credential-profiles |
| credential.self_contained_issued | credential.CredentialSelfContainedIssued | credential-profiles |
| credential.introspected | credential.CredentialIntrospected | credential-profiles |
| credential.revoked | credential.AccessCredentialRevoked; audit.CredentialRevoked is the common redacted shape; session/refresh/delegation revocations retain their own source events | credential-profiles |
| token_exchange.allowed | credential.TokenExchangeAllowed | constrained-exchange |
| token_exchange.denied | credential.TokenExchangeDenied and audit.TokenExchangeDenied; rejection audit is a separate trusted boundary under UNMAPPED-DENIAL-AUDIT | constrained-exchange |

All names above omit the `mandate.` prefix. Additional original-design events, including authorization decisions, relation/grant changes and principal/session revocations, use the same append boundary. The complete admitted `AuditAction`/`AuditOutcome` vocabulary and producer-to-record transformations must be specified and checked before implementing that boundary; nominal strings do not enforce the vocabulary.

Exchange records carry subject, actor, verified organization when known, source/issued credential identifiers and kinds, requested/issued audience and scope, delegation, execution, result, policy/model/graph versions and decision/request correlation. Producers must populate applicable fields and reject secrets in all strings. Optional fields preserve unknown or inapplicable facts; they do not authorize dropping known decision evidence. Neither JSON Schema nor this table enforces redaction, provenance or atomic persistence.

Blockers and required exit evidence are in [unmapped semantics](unmapped.md). The [ownership map](ownership.md) assigns source state and the append port to deployments.
