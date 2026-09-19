<!--
generated from mandate v1
model digest e6c0315aa5b87175ed6d714a2786c1f14085b00a46145448d5f73eb6cd4b4fd7
contract digest slice-sha256/2:292928e3cd6d60c5cd66259ac92189b430450ab63ade146e4d77839f19c7b4fe
do not edit: regenerate with `ess generate`
-->

# core

`mandate.core` is one of mandate's bounded contexts. [Back to the index](../index.md).

## Types

### `AccessCredentialId`

`mandate.core.AccessCredentialId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `Action`

`mandate.core.Action` wraps `String` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `ActionPattern`

`mandate.core.ActionPattern` wraps `String` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `AgentCapabilityCeilingId`

`mandate.core.AgentCapabilityCeilingId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `ApprovalId`

`mandate.core.ApprovalId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `Audience`

`mandate.core.Audience` wraps `String` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `AuditAction`

`mandate.core.AuditAction` wraps `String` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `AuditEventId`

`mandate.core.AuditEventId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `AuditOutcome`

`mandate.core.AuditOutcome` wraps `String` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `AuditRecord`

`mandate.core.AuditRecord` is a record of 21 fields:

- `subject` — `Optional<mandate.core.PrincipalId>`, which may be absent
- `actor` — `Optional<mandate.core.PrincipalId>`, which may be absent
- `organization_id` — `Optional<mandate.core.OrganizationId>`, which may be absent
- `event_type` — `mandate.core.AuditAction`
- `correlation` — `mandate.core.CorrelationId`
- `decision_id` — `Optional<mandate.core.DecisionId>`, which may be absent
- `requested_audience` — `Optional<mandate.core.Audience>`, which may be absent
- `issued_audience` — `Optional<mandate.core.Audience>`, which may be absent
- `requested_scope` — `Optional<mandate.core.AuthorityScope>`, which may be absent
- `credential_kind` — `Optional<mandate.core.CredentialKind>`, which may be absent
- `delegation_id` — `Optional<mandate.core.DelegationId>`, which may be absent
- `execution_id` — `Optional<mandate.core.ExecutionId>`, which may be absent
- `result` — `mandate.core.AuditOutcome`
- `occurred_at` — `Timestamp`
- `policy_version` — `Optional<mandate.core.PolicyVersion>`, which may be absent
- `model_version` — `Optional<mandate.core.AuthorizationModelVersion>`, which may be absent
- `authz_revision` — `Optional<mandate.core.AuthzRevision>`, which may be absent
- `source_credential_kind` — `Optional<mandate.core.CredentialKind>`, which may be absent
- `source_credential_id` — `Optional<mandate.core.CredentialId>`, which may be absent
- `issued_credential_id` — `Optional<mandate.core.CredentialId>`, which may be absent
- `issued_scope` — `Optional<mandate.core.AuthorityScope>`, which may be absent

### `AuthorityScope`

`mandate.core.AuthorityScope` is a record of three fields:

- `actions` — `List<mandate.core.Action>`
- `resources` — `List<mandate.core.ResourceRef>`
- `space` — `Optional<mandate.core.SpaceId>`, which may be absent

### `AuthoritySubject`

`mandate.core.AuthoritySubject` is one of two shapes, told apart by a `kind` field — tagged, so a decoder never has to guess which branch it is reading:

- `principal` — `mandate.core.PrincipalId`
- `team` — `mandate.core.TeamId`

### `AuthorizationCodeId`

`mandate.core.AuthorizationCodeId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `AuthorizationModelId`

`mandate.core.AuthorizationModelId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `AuthorizationModelVersion`

`mandate.core.AuthorizationModelVersion` wraps `String` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `AuthzRevision`

`mandate.core.AuthzRevision` wraps `String` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `ClientId`

`mandate.core.ClientId` wraps `String` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `CorrelationId`

`mandate.core.CorrelationId` wraps `String` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `CredentialDescriptor`

`mandate.core.CredentialDescriptor` is a record of nine fields:

- `kind` — `mandate.core.CredentialKind`
- `subject` — `mandate.core.PrincipalId`
- `actor` — `Optional<mandate.core.PrincipalId>`, which may be absent
- `organization` — `mandate.core.OrganizationId`
- `audience` — `mandate.core.Audience`
- `scope` — `mandate.core.AuthorityScope`
- `delegation` — `Optional<mandate.core.DelegationId>`, which may be absent
- `execution` — `Optional<mandate.core.ExecutionId>`, which may be absent
- `expires_at` — `Timestamp`

### `CredentialId`

`mandate.core.CredentialId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `CredentialKind`

`mandate.core.CredentialKind` is one of `SelfContained` and `Reference`.

### `CredentialProfile`

`mandate.core.CredentialProfile` is a record of six fields:

- `name` — `String`
- `kind` — `mandate.core.CredentialKind`
- `revocation` — `mandate.core.RevocationGuarantee`
- `max_ttl` — `Duration`
- `positive_cache_ttl` — `Duration`
- `requires_online_authorization` — `Boolean`

### `CredentialProof`

`mandate.core.CredentialProof` wraps `Bytes` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `CredentialSecret`

`mandate.core.CredentialSecret` wraps `Bytes` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `CredentialVerifier`

`mandate.core.CredentialVerifier` wraps `String` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `Decision`

`mandate.core.Decision` is a record of seven fields:

- `allowed` — `Boolean`
- `reason` — `mandate.core.DecisionReason`
- `decision_id` — `mandate.core.DecisionId`
- `revision` — `Optional<mandate.core.AuthzRevision>`, which may be absent
- `challenge` — `Optional<mandate.core.DecisionChallenge>`, which may be absent
- `policy_version` — `Optional<mandate.core.PolicyVersion>`, which may be absent
- `model_version` — `Optional<mandate.core.AuthorizationModelVersion>`, which may be absent

### `DecisionChallenge`

`mandate.core.DecisionChallenge` is a record of four fields:

- `action` — `mandate.core.Action`
- `resource` — `mandate.core.ResourceRef`
- `approver_policy` — `mandate.core.PolicyId`
- `expires_at` — `Timestamp`

### `DecisionId`

`mandate.core.DecisionId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `DecisionReason`

`mandate.core.DecisionReason` is one of `Allowed`, `Denied`, `ApprovalRequired`, `InvalidCredential`, `TenantMismatch`, `AudienceMismatch`, `Unavailable` and `StaleEpoch`.

### `DelegationId`

`mandate.core.DelegationId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `DenialReason`

`mandate.core.DenialReason` is one of `Denied`, `ApprovalRequired`, `InvalidCredential`, `TenantMismatch`, `AudienceMismatch`, `Unavailable` and `StaleEpoch`.

### `DirectoryGroupId`

`mandate.core.DirectoryGroupId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `DirectoryGroupMembershipId`

`mandate.core.DirectoryGroupMembershipId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `DirectoryGroupTeamMappingId`

`mandate.core.DirectoryGroupTeamMappingId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `EpochSnapshotRef`

`mandate.core.EpochSnapshotRef` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `ExecutionId`

`mandate.core.ExecutionId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `ExternalLinkMethod`

`mandate.core.ExternalLinkMethod` is one of `Administrator`, `AuthenticatedConfirmation`, `VerifiedMigration`, `ConfiguredFederation` and `SecuritySupport`.

### `ExternalPrincipalId`

`mandate.core.ExternalPrincipalId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `ExternalSubject`

`mandate.core.ExternalSubject` wraps `String` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `FederationConnectionId`

`mandate.core.FederationConnectionId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `GrantId`

`mandate.core.GrantId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `Issuer`

`mandate.core.Issuer` wraps `String` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `KeyReference`

`mandate.core.KeyReference` wraps `String` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `MembershipContributionId`

`mandate.core.MembershipContributionId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `MembershipSource`

`mandate.core.MembershipSource` is one of `Manual` and `DirectoryMapping`.

### `OAuthClientId`

`mandate.core.OAuthClientId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `OrganizationId`

`mandate.core.OrganizationId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `OrganizationMembershipId`

`mandate.core.OrganizationMembershipId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `PkceChallenge`

`mandate.core.PkceChallenge` wraps `String` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `PkceMethod`

`mandate.core.PkceMethod` is one of `S256`.

### `PolicyId`

`mandate.core.PolicyId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `PolicyVersion`

`mandate.core.PolicyVersion` wraps `String` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `PrincipalId`

`mandate.core.PrincipalId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `PrincipalKind`

`mandate.core.PrincipalKind` is one of `User`, `Service`, `Agent` and `ServiceAccount`.

### `RedirectUri`

`mandate.core.RedirectUri` wraps `String` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `RefreshCredentialId`

`mandate.core.RefreshCredentialId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `RelationId`

`mandate.core.RelationId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `ResourceId`

`mandate.core.ResourceId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `ResourceRef`

`mandate.core.ResourceRef` is a record of two fields:

- `resource_type` — `mandate.core.ResourceType`
- `resource_id` — `mandate.core.ResourceId`

### `ResourceServerId`

`mandate.core.ResourceServerId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `ResourceType`

`mandate.core.ResourceType` wraps `String` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `RevocationGuarantee`

`mandate.core.RevocationGuarantee` is one of `ImmediateOnline` and `BoundedOffline`.

### `SecurityEpochTarget`

`mandate.core.SecurityEpochTarget` is one of three shapes, told apart by a `kind` field — tagged, so a decoder never has to guess which branch it is reading:

- `federation` — `mandate.core.FederationConnectionId`
- `organization` — `mandate.core.OrganizationId`
- `principal` — `mandate.core.PrincipalId`

### `SessionId`

`mandate.core.SessionId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `SigningAlgorithm`

`mandate.core.SigningAlgorithm` wraps `String` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `SigningKeyId`

`mandate.core.SigningKeyId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `SpaceId`

`mandate.core.SpaceId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `SyncJobId`

`mandate.core.SyncJobId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `TeamId`

`mandate.core.TeamId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `TeamMembershipId`

`mandate.core.TeamMembershipId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `TenantResolutionRule`

`mandate.core.TenantResolutionRule` is a record of three fields:

- `configured_organization` — `mandate.core.OrganizationId`
- `verified_claim_name` — `Optional<String>`, which may be absent
- `verified_claim_value` — `Optional<String>`, which may be absent

### `TrustDomain`

`mandate.core.TrustDomain` wraps `String` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

### `VerifiedContext`

`mandate.core.VerifiedContext` is a record of eight fields:

- `subject` — `mandate.core.PrincipalId`
- `actor` — `Optional<mandate.core.PrincipalId>`, which may be absent
- `organization` — `mandate.core.OrganizationId`
- `audience` — `mandate.core.Audience`
- `credential` — `mandate.core.CredentialId`
- `delegation` — `Optional<mandate.core.DelegationId>`, which may be absent
- `execution` — `Optional<mandate.core.ExecutionId>`, which may be absent
- `correlation` — `mandate.core.CorrelationId`

### `WorkloadIdentityId`

`mandate.core.WorkloadIdentityId` wraps `Uuid` and is not interchangeable with one: the whole value of naming it separately is the crossings the model then refuses.

Two of the types above are reached by nothing else in this system: `mandate.core.AccessCredentialId` and `mandate.core.CredentialSecret`. No entity, view, command, event, error or crossing names them, so it is either vocabulary something outside this specification uses or a leftover — and only a person can tell which.


---

Generated from mandate v1 · model digest `e6c0315aa5b87175ed6d714a2786c1f14085b00a46145448d5f73eb6cd4b4fd7` · contract digest `slice-sha256/2:292928e3cd6d60c5cd66259ac92189b430450ab63ade146e4d77839f19c7b4fe`. Do not edit this file; change the specification and regenerate it with `ess generate`.
