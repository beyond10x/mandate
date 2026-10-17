//! The accepted `enum` types, rendered as the declared variant names.

canonical_enums! {
    PrincipalKind { User, Service, Agent, ServiceAccount },
    CredentialKind { SelfContained, Reference },
    RevocationGuarantee { ImmediateOnline, BoundedOffline },
    MembershipSource { Manual, DirectoryMapping },
    ExternalLinkMethod { Administrator, AuthenticatedConfirmation, VerifiedMigration, ConfiguredFederation, SecuritySupport },
    DecisionReason { Allowed, Denied, ApprovalRequired, InvalidCredential, TenantMismatch, AudienceMismatch, Unavailable, StaleEpoch, InvalidClient },
    PkceMethod { S256 },
    OAuthClientType { Public, Confidential },
    SubjectFormat { MandatePrincipal, DexCompatible },
    IdTokenSigningAlgorithm { RS256, ES256 },
    DenialReason { Denied, ApprovalRequired, InvalidCredential, TenantMismatch, AudienceMismatch, Unavailable, StaleEpoch, InvalidClient },
}
