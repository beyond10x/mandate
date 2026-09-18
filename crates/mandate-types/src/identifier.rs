//! The accepted `newtype of Uuid` identifiers.
//!
//! Thirty-four distinct types over one wire form. `EpochSnapshotRef` is among them: it
//! is an immutable handle to a recorded snapshot, never a generation and never counted.

canonical_uuid_identifiers! {
    PrincipalId, OrganizationId, OrganizationMembershipId,
    TeamId, TeamMembershipId, MembershipContributionId,
    SpaceId, ResourceId, GrantId,
    RelationId, DelegationId, ExecutionId,
    ExternalPrincipalId, FederationConnectionId, DirectoryGroupId,
    DirectoryGroupMembershipId, DirectoryGroupTeamMappingId, ResourceServerId,
    CredentialId, SessionId, RefreshCredentialId,
    DecisionId, AuditEventId, PolicyId,
    AuthorizationModelId, WorkloadIdentityId, ApprovalId,
    OAuthClientId, AuthorizationCodeId, SigningKeyId,
    SyncJobId, EpochSnapshotRef, AccessCredentialId,
    AgentCapabilityCeilingId,
}
