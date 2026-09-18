//! The account of what this milestone accepted and what it excluded.
//!
//! The entries below are decided against `generated/schema/types`, the compiled model's
//! own type index, by `tests/inventory.rs`. The compiled index holds 110 entries: the 74
//! authored `mandate.core` types named here, and one derived `<Entity>.State` enum per
//! entity, which this milestone does not realize.

/// How the contract declares a type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// `kind: newtype`.
    Newtype,
    /// `kind: enum`.
    Enum,
    /// `kind: struct`.
    Struct,
    /// `kind: union`.
    Union,
}

impl Kind {
    /// The `x-ess-kind` the projection carries for this kind.
    #[must_use]
    pub const fn as_ess_kind(self) -> &'static str {
        match self {
            Self::Newtype => "newtype",
            Self::Enum => "enum",
            Self::Struct => "struct",
            Self::Union => "union",
        }
    }
}

/// The crate that declares a realized type.
///
/// Nothing in the tree declares this partition; it follows the story's allocation of the
/// four crates and is decided, per type, by `tests/inventory.rs` in this crate and by the
/// conformance suite of each owning crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Owner {
    /// `mandate-types`: identifiers, enums, unions, shared value records, and the
    /// transient credential boundary.
    Types,
    /// `mandate-model`: the accepted domain records.
    Model,
    /// `mandate-token`: the accepted credential-format records.
    Token,
    /// `mandate-proto`: wire contracts and explicit conversions.
    ///
    /// This axis is *declaration* ownership — where the Rust type is written — and no
    /// authored `mandate.core` type is declared here, so this variant holds none of the
    /// 74. That is not the same as carrying no accepted type: `mandate-proto` carries a
    /// `WireContract` for **all** 74, including the six records `mandate-model` and
    /// `mandate-token` declare, which it reaches through the
    /// `mandate-proto -> mandate-model` and `mandate-proto -> mandate-token` entries in
    /// `dependency-boundaries.json`.
    ///
    /// An earlier revision of this file gave a different reason for proto carrying only
    /// part of the set — that those two edges "would reverse the declared dependency
    /// direction". They do not: the policy has `mandate-client` and `mandate-server`
    /// depending on `mandate-proto` and neither `mandate-model` nor `mandate-token` doing
    /// so, which makes both new edges, not reversals.
    Proto,
}

/// One accepted type, with the kind the contract declares and the crate that realizes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accepted {
    /// The ESS model name.
    pub ess_name: &'static str,
    /// The kind the projection declares.
    pub kind: Kind,
    /// The crate that declares the realization.
    pub owner: Owner,
}

/// One excluded model element, with the reason it was excluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Excluded {
    /// The ESS model name.
    pub ess_name: &'static str,
    /// Why this milestone does not realize it.
    pub reason: &'static str,
}

/// Every accepted type, in the order `systems/mandate/domains/core.yaml` declares them.
pub const ACCEPTED: &[Accepted] = &[
    Accepted {
        ess_name: "mandate.core.PrincipalId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.OrganizationId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.OrganizationMembershipId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.TeamId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.TeamMembershipId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.MembershipContributionId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.SpaceId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.ResourceId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.GrantId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.RelationId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.DelegationId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.ExecutionId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.ExternalPrincipalId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.FederationConnectionId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.DirectoryGroupId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.DirectoryGroupMembershipId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.DirectoryGroupTeamMappingId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.ResourceServerId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.CredentialId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.SessionId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.RefreshCredentialId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.DecisionId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.AuditEventId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.PolicyId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.AuthorizationModelId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.WorkloadIdentityId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.ApprovalId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.OAuthClientId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.AuthorizationCodeId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.SigningKeyId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.SyncJobId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.Action",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.ResourceType",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.Audience",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.Issuer",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.ExternalSubject",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.ClientId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.AuthzRevision",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.PolicyVersion",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.CorrelationId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.CredentialVerifier",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.KeyReference",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.PkceChallenge",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.RedirectUri",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.TrustDomain",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.ActionPattern",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.CredentialSecret",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.CredentialProof",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.PrincipalKind",
        kind: Kind::Enum,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.CredentialKind",
        kind: Kind::Enum,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.RevocationGuarantee",
        kind: Kind::Enum,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.MembershipSource",
        kind: Kind::Enum,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.ExternalLinkMethod",
        kind: Kind::Enum,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.DecisionReason",
        kind: Kind::Enum,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.PkceMethod",
        kind: Kind::Enum,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.ResourceRef",
        kind: Kind::Struct,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.AuthorityScope",
        kind: Kind::Struct,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.EpochSnapshotRef",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.VerifiedContext",
        kind: Kind::Struct,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.CredentialDescriptor",
        kind: Kind::Struct,
        owner: Owner::Token,
    },
    Accepted {
        ess_name: "mandate.core.CredentialProfile",
        kind: Kind::Struct,
        owner: Owner::Token,
    },
    Accepted {
        ess_name: "mandate.core.TenantResolutionRule",
        kind: Kind::Struct,
        owner: Owner::Model,
    },
    Accepted {
        ess_name: "mandate.core.DecisionChallenge",
        kind: Kind::Struct,
        owner: Owner::Model,
    },
    Accepted {
        ess_name: "mandate.core.Decision",
        kind: Kind::Struct,
        owner: Owner::Model,
    },
    Accepted {
        ess_name: "mandate.core.AccessCredentialId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.AgentCapabilityCeilingId",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.AuthorizationModelVersion",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.SigningAlgorithm",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.DenialReason",
        kind: Kind::Enum,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.AuthoritySubject",
        kind: Kind::Union,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.SecurityEpochTarget",
        kind: Kind::Union,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.AuditAction",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.AuditOutcome",
        kind: Kind::Newtype,
        owner: Owner::Types,
    },
    Accepted {
        ess_name: "mandate.core.AuditRecord",
        kind: Kind::Struct,
        owner: Owner::Model,
    },
];

/// The excluded model entities.
///
/// These are entities, not types: none of them appears in the compiled type index, and
/// none is realized here.
pub const EXCLUDED_ENTITIES: &[Excluded] = &[
    Excluded {
        ess_name: "mandate.identity.PrincipalSecurityEpoch",
        reason: "the contract declares the generation as a non-negative Integer, but the \
                 arithmetic over it — monotonic increment, comparison and denial at the \
                 maximum — is not realized here, and no Rust representation of the record \
                 is accepted by this milestone; see UNMAPPED-EPOCH",
    },
    Excluded {
        ess_name: "mandate.identity.OrganizationSecurityEpoch",
        reason: "the declared non-negative Integer generation is realized by no type here; \
                 increment, comparison and overflow denial remain unrealized; see \
                 UNMAPPED-EPOCH",
    },
    Excluded {
        ess_name: "mandate.identity.FederationSecurityEpoch",
        reason: "the declared non-negative Integer generation is realized by no type here; \
                 increment, comparison and overflow denial remain unrealized; see \
                 UNMAPPED-EPOCH",
    },
    Excluded {
        ess_name: "mandate.identity.SecurityEpochSnapshot",
        reason: "the snapshot representation is incomplete pending UNMAPPED-EPOCH; only its \
                 identity, mandate.core.EpochSnapshotRef, is realized, and only as an \
                 immutable handle",
    },
];

/// The semantics this milestone deliberately does not realize.
pub const EXCLUDED_SEMANTICS: &[&str] = &[
    "numeric epoch generations and any arithmetic over them, pending UNMAPPED-EPOCH",
    "conditional subject storage foreign keys, pending UNMAPPED-SUBJECT-RELATIONS",
    "the 36 derived <Entity>.State enums the compiled model adds to the authored types",
    "lifecycle behavior of any kind; a realized value type implements no transition",
    "cryptography: no signing, verification, hashing or key handling",
    "policy decision point evaluation",
    "HTTP, transport and server implementation",
];
