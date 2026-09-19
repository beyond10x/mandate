//! Wire contracts and explicit conversions.
//!
//! Foundation scaffold; normative contracts live in `systems/mandate`.
//! Runtime behavior is not implemented in this milestone.
//!
//! # What crossing the wire is, and what it is not
//!
//! Crossing the wire is a named call, never an inferred one.
//!
//! ```
//! use mandate_proto::WireContract;
//! use mandate_types::PrincipalId;
//!
//! let principal = PrincipalId::parse("1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b").unwrap();
//! let wire = principal.to_wire().unwrap();
//! assert_eq!(wire, "\"1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b\"");
//! assert_eq!(PrincipalId::from_wire(&wire).unwrap(), principal);
//! ```
//!
//! **Identifier separation is a property of the Rust types, not of the wire form.** The
//! projection declares `mandate.core.PrincipalId` and `mandate.core.OrganizationId` as the
//! same JSON string — byte for byte the same schema node apart from its title and
//! `x-ess-name` — so one identifier's wire form is a valid wire form of the other, and
//! [`WireContract::from_wire`] cannot tell them apart. It does not claim to. An earlier
//! revision of this file claimed it refused that substitution; it did not, and the claim
//! could not have been made true without inventing a wire form the contract does not
//! declare. `tests/conformance.rs` pins the two forms as equal.
//!
//! # Two of these contracts carry credential material
//!
//! `mandate.core.CredentialSecret` and `mandate.core.CredentialProof` are among the 74
//! contracts below, because the projection names them from six commands and six responses
//! and this crate is where those cross. [`WireContract::to_wire`] on those two therefore
//! renders the declared base64 material, not the redaction their [`serde::Serialize`]
//! renders — it delegates to `Canonical::encode`, which is the same sanctioned rendering.
//! That is deliberate: the crossing is what this crate is for, and it is a named call on a
//! named trait rather than something a derive reaches. `mandate-client` and
//! `mandate-server` depend on this crate, so a reader there sees the material only by
//! writing `to_wire`.
//!
//! # Identifier separation
//!
//! What separates two identifiers is the type, at the call site, before any wire form
//! exists:
//!
//! ```
//! use mandate_types::OrganizationId;
//!
//! fn tenant(_: OrganizationId) {}
//!
//! tenant(OrganizationId::parse("1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b").unwrap());
//! ```
//!
//! The same call with a `PrincipalId` does not compile. Only the identifier type differs
//! from the example above, so that mismatch is the only thing this case can be failing
//! for.
//!
//! ```compile_fail
//! use mandate_types::{OrganizationId, PrincipalId};
//!
//! fn tenant(_: OrganizationId) {}
//!
//! tenant(PrincipalId::parse("1b4e28ba-2fa1-4d8e-b1b0-8c1d4e5f6a7b").unwrap());
//! ```

use mandate_types::conformance::Canonical;

/// A wire crossing this crate refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireError {
    /// A value could not be rendered in its wire form.
    Encode(String),
    /// A wire form was not the declared form of the target type.
    ///
    /// "The declared form of the target type" is all this decides. Two identifiers whose
    /// projections declare the same JSON string accept each other's wire forms; see the
    /// module documentation.
    Decode(String),
}

impl core::fmt::Display for WireError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Encode(detail) => write!(formatter, "wire encoding failed: {detail}"),
            Self::Decode(detail) => write!(formatter, "wire decoding failed: {detail}"),
        }
    }
}

impl std::error::Error for WireError {}

/// The wire contract of a canonical type.
///
/// Implemented per type, never by a blanket impl: a type crosses the wire because this
/// crate says it does, and the crossing is a named call. The form is the canonical one the
/// projection declares — this crate adds no envelope, no tag and no type name of its own.
pub trait WireContract: Canonical {
    /// The ESS model name whose projection decides this wire form.
    const ESS_NAME: &'static str;

    /// Render the declared wire form.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::Encode`] when the value cannot be rendered.
    fn to_wire(&self) -> Result<String, WireError> {
        Canonical::encode(self).map_err(|error| WireError::Encode(error.to_string()))
    }

    /// Read the declared wire form.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::Decode`] when `text` is not the declared form of this type.
    fn from_wire(text: &str) -> Result<Self, WireError> {
        Canonical::decode(text).map_err(|error| WireError::Decode(error.to_string()))
    }
}

/// The OAuth road's wire encodings: forms, the standard error bodies, the JSON documents.
pub mod oauth;

macro_rules! wire_contracts {
    ($($name:path),+ $(,)?) => {
        $(
            impl WireContract for $name {
                const ESS_NAME: &'static str =
                    <$name as ::mandate_types::conformance::Canonical>::ESS_NAME;
            }
        )+

        /// Every ESS model name this crate carries a wire contract for.
        ///
        /// This is the whole accepted type set. A type the projection names from a command,
        /// response or event is on the wire by the contract's own reckoning, and there is no
        /// accepted type without a contract here; `tests/conformance.rs` decides that
        /// against `mandate_types::inventory::ACCEPTED`.
        pub const WIRE_CONTRACTS: &[&str] = &[
            $(<$name as WireContract>::ESS_NAME),+
        ];

        /// The wire conformance suite.
        pub mod conformance {
            use super::WireContract;
            use ::mandate_types::conformance::Canonical;

            /// Check every wire contract, and report each one that failed.
            ///
            /// The explicit conversion must be inverse for every declared sample, and must
            /// render the canonical form rather than one of this crate's invention.
            #[must_use]
            pub fn run() -> Vec<String> {
                let mut failures = Vec::new();
                $(check::<$name>(&mut failures);)+
                failures
            }

            fn check<T: WireContract>(failures: &mut Vec<String>) {
                let name = <T as WireContract>::ESS_NAME;
                for sample in <T as Canonical>::samples() {
                    let wire = match sample.to_wire() {
                        Ok(wire) => wire,
                        Err(error) => {
                            failures.push(format!("{name}: {error}"));
                            continue;
                        }
                    };
                    match Canonical::encode(&sample) {
                        Ok(canonical) if canonical == wire => {}
                        Ok(canonical) => failures.push(format!(
                            "{name}: wire form {wire} is not the canonical form {canonical}"
                        )),
                        Err(error) => failures.push(format!("{name}: {error}")),
                    }
                    match T::from_wire(&wire) {
                        Ok(decoded) if decoded == sample => {}
                        Ok(_) => failures
                            .push(format!("{name}: the explicit conversion is not inverse")),
                        Err(error) => failures.push(format!("{name}: {error}")),
                    }
                }
            }
        }
    };
}

wire_contracts! {
    ::mandate_types::PrincipalId, ::mandate_types::OrganizationId,
    ::mandate_types::OrganizationMembershipId, ::mandate_types::TeamId,
    ::mandate_types::TeamMembershipId, ::mandate_types::MembershipContributionId,
    ::mandate_types::SpaceId, ::mandate_types::ResourceId,
    ::mandate_types::GrantId, ::mandate_types::RelationId,
    ::mandate_types::DelegationId, ::mandate_types::ExecutionId,
    ::mandate_types::ExternalPrincipalId, ::mandate_types::FederationConnectionId,
    ::mandate_types::DirectoryGroupId, ::mandate_types::DirectoryGroupMembershipId,
    ::mandate_types::DirectoryGroupTeamMappingId, ::mandate_types::ResourceServerId,
    ::mandate_types::CredentialId, ::mandate_types::SessionId,
    ::mandate_types::RefreshCredentialId, ::mandate_types::DecisionId,
    ::mandate_types::AuditEventId, ::mandate_types::PolicyId,
    ::mandate_types::AuthorizationModelId, ::mandate_types::WorkloadIdentityId,
    ::mandate_types::ApprovalId, ::mandate_types::OAuthClientId,
    ::mandate_types::AuthorizationCodeId, ::mandate_types::SigningKeyId,
    ::mandate_types::SyncJobId, ::mandate_types::Action,
    ::mandate_types::ResourceType, ::mandate_types::Audience,
    ::mandate_types::Issuer, ::mandate_types::ExternalSubject,
    ::mandate_types::ClientId, ::mandate_types::AuthzRevision,
    ::mandate_types::PolicyVersion, ::mandate_types::CorrelationId,
    ::mandate_types::CredentialVerifier, ::mandate_types::KeyReference,
    ::mandate_types::PkceChallenge, ::mandate_types::RedirectUri,
    ::mandate_types::TrustDomain, ::mandate_types::ActionPattern,
    ::mandate_types::CredentialSecret, ::mandate_types::CredentialProof,
    ::mandate_types::PrincipalKind, ::mandate_types::CredentialKind,
    ::mandate_types::RevocationGuarantee, ::mandate_types::MembershipSource,
    ::mandate_types::ExternalLinkMethod, ::mandate_types::DecisionReason,
    ::mandate_types::PkceMethod, ::mandate_types::ResourceRef,
    ::mandate_types::AuthorityScope, ::mandate_types::EpochSnapshotRef,
    ::mandate_types::VerifiedContext, ::mandate_token::CredentialDescriptor,
    ::mandate_token::CredentialProfile, ::mandate_model::TenantResolutionRule,
    ::mandate_model::DecisionChallenge, ::mandate_model::Decision,
    ::mandate_types::AccessCredentialId, ::mandate_types::AgentCapabilityCeilingId,
    ::mandate_types::AuthorizationModelVersion, ::mandate_types::SigningAlgorithm,
    ::mandate_types::DenialReason, ::mandate_types::AuthoritySubject,
    ::mandate_types::SecurityEpochTarget, ::mandate_types::AuditAction,
    ::mandate_types::AuditOutcome, ::mandate_model::AuditRecord,
}
