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

/// `mandate.credential.IdentityScope`: an OpenID Connect scope a code records (OIDC Core
/// section 5.4), rendered as the declared variant names.
///
/// The one authored type of a domain other than `mandate.core` this crate realizes; it is
/// here because the authorization endpoint's decoder (`mandate-server`) reads it and depends
/// on this crate alone. `crate::inventory::DOMAIN_TYPES_REALIZED` accounts for it.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    ::serde::Serialize,
    ::serde::Deserialize,
)]
pub enum IdentityScope {
    /// The declared `OpenId` variant: the request is an OpenID Connect request.
    OpenId,
    /// The declared `Email` variant.
    Email,
    /// The declared `Profile` variant.
    Profile,
    /// The declared `Groups` variant.
    Groups,
    /// The declared `OfflineAccess` variant.
    OfflineAccess,
}

impl IdentityScope {
    /// Every variant the contract declares, in declaration order.
    pub const VARIANTS: &'static [Self] = &[
        Self::OpenId,
        Self::Email,
        Self::Profile,
        Self::Groups,
        Self::OfflineAccess,
    ];

    /// The OAuth `scope` token that names this scope (OIDC Core sections 3.1.2.1, 5.4 and
    /// 11), or `groups`, the claim set the upstream directory supplies.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::OpenId => "openid",
            Self::Email => "email",
            Self::Profile => "profile",
            Self::Groups => "groups",
            Self::OfflineAccess => "offline_access",
        }
    }

    /// The scope a `scope` token names, when it names one.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        Self::VARIANTS
            .iter()
            .copied()
            .find(|scope| scope.token() == token)
    }
}

impl crate::PersistedValue for IdentityScope {}
