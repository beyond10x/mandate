//! Named identifiers and validated primitives.
//!
//! Foundation scaffold; normative contracts live in `systems/mandate`.
//! Runtime behavior is not implemented in this milestone.
//!
//! # Identifier separation
//!
//! Two identifiers share a wire form. They do not share a Rust type, and there is no
//! conversion between them.
//!
//! ```
//! use mandate_types::OrganizationId;
//!
//! fn tenant_of(_: OrganizationId) {}
//!
//! tenant_of(OrganizationId::parse("1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b").unwrap());
//! ```
//!
//! The same call with a `PrincipalId` does not compile. Only the identifier type
//! differs from the example above.
//!
//! ```compile_fail
//! use mandate_types::{OrganizationId, PrincipalId};
//!
//! fn tenant_of(_: OrganizationId) {}
//!
//! tenant_of(PrincipalId::parse("1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b").unwrap());
//! ```
//!
//! Nor is there a conversion to reach for instead.
//!
//! ```compile_fail
//! use mandate_types::{OrganizationId, PrincipalId};
//!
//! let principal = PrincipalId::parse("1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b").unwrap();
//! let organization: OrganizationId = principal.into();
//! ```
//!
//! # The transient credential boundary
//!
//! A value that may appear in a persisted record implements [`PersistedValue`].
//! `CredentialSecret` and `CredentialProof` are [`Transient`] and deliberately do not.
//!
//! ```
//! use mandate_types::{CorrelationId, PersistedValue};
//!
//! fn persistable<T: PersistedValue>() {}
//!
//! persistable::<CorrelationId>();
//! ```
//!
//! ```compile_fail
//! use mandate_types::{CredentialSecret, PersistedValue};
//!
//! fn persistable<T: PersistedValue>() {}
//!
//! persistable::<CredentialSecret>();
//! ```
//!
//! Wrapping it does not help, which is what makes this a boundary rather than one case.
//!
//! ```compile_fail
//! use mandate_types::{CredentialSecret, PersistedValue};
//!
//! fn persistable<T: PersistedValue>() {}
//!
//! persistable::<Option<CredentialSecret>>();
//! ```
//!
//! ```compile_fail
//! use mandate_types::{CredentialProof, PersistedValue};
//!
//! fn persistable<T: PersistedValue>() {}
//!
//! persistable::<Vec<CredentialProof>>();
//! ```
//!
//! A record declared through [`canonical_record`] proves the same thing field by field.
//! A well-formed record is accepted:
//!
//! ```
//! use mandate_types::{CorrelationId, PrincipalId};
//!
//! #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
//! pub struct Trace {
//!     pub subject: PrincipalId,
//!     pub correlation: CorrelationId,
//! }
//!
//! mandate_types::canonical_record!(Trace { subject, correlation }, samples: vec![Trace {
//!     subject: PrincipalId::parse("1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b").unwrap(),
//!     correlation: CorrelationId::new("correlation"),
//! }]);
//! ```
//!
//! The same record with a transient field is not:
//!
//! ```compile_fail
//! use mandate_types::{CorrelationId, CredentialSecret};
//!
//! #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
//! pub struct Trace {
//!     pub secret: CredentialSecret,
//!     pub correlation: CorrelationId,
//! }
//!
//! mandate_types::canonical_record!(Trace { secret, correlation }, samples: vec![Trace {
//!     secret: CredentialSecret::from_bytes(b"abc".to_vec()),
//!     correlation: CorrelationId::new("correlation"),
//! }]);
//! ```
//!
//! # Epoch snapshot references
//!
//! `EpochSnapshotRef` is an immutable record handle. It parses and it renders:
//!
//! ```
//! use mandate_types::EpochSnapshotRef;
//!
//! let handle = EpochSnapshotRef::parse("1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b").unwrap();
//! assert_eq!(handle.to_string(), "1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b");
//! ```
//!
//! It is not a generation, so it does not count:
//!
//! ```compile_fail
//! use mandate_types::EpochSnapshotRef;
//!
//! let handle = EpochSnapshotRef::parse("1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b").unwrap();
//! let next = handle + 1;
//! ```

/// What a transient credential value renders instead of its material.
///
/// Chosen so that it is not a form the contract declares: it is not valid base64, so a
/// redacted value cannot be mistaken for, or decoded back into, a credential.
pub const REDACTED: &str = "<redacted>";

#[macro_use]
mod macros;

pub mod conformance;
pub mod inventory;
pub mod value;

mod credential;
mod enumeration;
mod identifier;
mod marker;
mod record;
mod text;
mod union;

pub use credential::{CredentialProof, CredentialSecret};
pub use enumeration::{
    CredentialKind, DecisionReason, DenialReason, ExternalLinkMethod, MembershipSource, PkceMethod,
    PrincipalKind, RevocationGuarantee,
};
pub use identifier::{
    AccessCredentialId, AgentCapabilityCeilingId, ApprovalId, AuditEventId, AuthorizationCodeId,
    AuthorizationModelId, CredentialId, DecisionId, DelegationId, DirectoryGroupId,
    DirectoryGroupMembershipId, DirectoryGroupTeamMappingId, EpochSnapshotRef, ExecutionId,
    ExternalPrincipalId, FederationConnectionId, GrantId, MembershipContributionId, OAuthClientId,
    OrganizationId, OrganizationMembershipId, PolicyId, PrincipalId, RefreshCredentialId,
    RelationId, ResourceId, ResourceServerId, SessionId, SigningKeyId, SpaceId, SyncJobId, TeamId,
    TeamMembershipId, WorkloadIdentityId,
};
pub use marker::{PersistedValue, Transient};
pub use record::{AuthorityScope, ResourceRef, VerifiedContext};
pub use text::{
    Action, ActionPattern, Audience, AuditAction, AuditOutcome, AuthorizationModelVersion,
    AuthzRevision, ClientId, CorrelationId, CredentialVerifier, ExternalSubject, Issuer,
    KeyReference, PkceChallenge, PolicyVersion, RedirectUri, ResourceType, SigningAlgorithm,
    TrustDomain,
};
pub use union::{AuthoritySubject, SecurityEpochTarget};
pub use value::{Duration, ParseError, Timestamp, Uuid};
