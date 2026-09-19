//! Format-neutral credentials and cryptographic adapters.
//!
//! Foundation scaffold; normative contracts live in `systems/mandate`.
//! Runtime behavior is not implemented in this milestone.
//!
//! # Credential formats describe authority, never material
//!
//! ```
//! use mandate_token::CredentialProfile;
//! use mandate_types::{CredentialKind, Duration, PersistedValue, RevocationGuarantee};
//!
//! fn persistable<T: PersistedValue>() {}
//!
//! persistable::<CredentialProfile>();
//!
//! let profile = CredentialProfile {
//!     name: "default".to_owned(),
//!     kind: CredentialKind::Reference,
//!     revocation: RevocationGuarantee::ImmediateOnline,
//!     max_ttl: Duration::new("PT1H"),
//!     positive_cache_ttl: Duration::new("PT30S"),
//!     requires_online_authorization: true,
//! };
//! assert_eq!(serde_json::to_value(&profile).unwrap()["max_ttl"], "PT1H");
//! ```
//!
//! No credential-format type in this crate can carry a transient secret:
//!
//! ```compile_fail
//! use mandate_types::{Audience, CredentialSecret};
//!
//! #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
//! pub struct IssuedCredential {
//!     pub audience: Audience,
//!     pub secret: CredentialSecret,
//! }
//!
//! mandate_types::canonical_record!(IssuedCredential { audience, secret }, samples: vec![
//!     IssuedCredential {
//!         audience: Audience::new("mandate"),
//!         secret: CredentialSecret::from_bytes(b"abc".to_vec()),
//!     }
//! ]);
//! ```

use serde::{Deserialize, Serialize};

use mandate_types::conformance::first_sample;
use mandate_types::{
    Audience, AuthorityScope, CredentialKind, DelegationId, Duration, ExecutionId, OrganizationId,
    PrincipalId, RevocationGuarantee, Timestamp,
};

/// `mandate.core.CredentialDescriptor`: what a credential asserts.
///
/// A descriptor names authority. It carries no credential material: `CredentialSecret`
/// and `CredentialProof` are transient and cannot be fields of a record declared through
/// [`mandate_types::canonical_record`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialDescriptor {
    /// The credential kind.
    pub kind: CredentialKind,
    /// The subject the credential speaks for.
    pub subject: PrincipalId,
    /// The actor the subject acts through, when there is one.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub actor: Option<PrincipalId>,
    /// The organization the credential is confined to.
    pub organization: OrganizationId,
    /// The audience the credential is for.
    pub audience: Audience,
    /// The authority the credential carries.
    pub scope: AuthorityScope,
    /// The delegation in force, when there is one.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub delegation: Option<DelegationId>,
    /// The execution in force, when there is one.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub execution: Option<ExecutionId>,
    /// When the credential stops being valid.
    pub expires_at: Timestamp,
}

mandate_types::canonical_record!(
    CredentialDescriptor {
        kind,
        subject,
        actor,
        organization,
        audience,
        scope,
        delegation,
        execution,
        expires_at
    },
    samples: vec![
        CredentialDescriptor {
            kind: CredentialKind::SelfContained,
            subject: first_sample::<PrincipalId>(),
            actor: None,
            organization: first_sample::<OrganizationId>(),
            audience: Audience::new("mandate"),
            scope: first_sample::<AuthorityScope>(),
            delegation: None,
            execution: None,
            expires_at: Timestamp::new("2026-09-18T00:00:00Z"),
        },
        CredentialDescriptor {
            kind: CredentialKind::Reference,
            subject: first_sample::<PrincipalId>(),
            actor: Some(first_sample::<PrincipalId>()),
            organization: first_sample::<OrganizationId>(),
            audience: Audience::new("mandate"),
            scope: first_sample::<AuthorityScope>(),
            delegation: Some(first_sample::<DelegationId>()),
            execution: Some(first_sample::<ExecutionId>()),
            expires_at: Timestamp::new("2026-09-18T00:00:00Z"),
        },
    ]
);

/// `mandate.core.CredentialProfile`: the shape of credentials a profile issues.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialProfile {
    /// The profile name.
    pub name: String,
    /// The credential kind the profile issues.
    pub kind: CredentialKind,
    /// The revocation guarantee the profile offers.
    pub revocation: RevocationGuarantee,
    /// The longest lifetime the profile issues.
    pub max_ttl: Duration,
    /// How long a positive authorization result may be cached.
    pub positive_cache_ttl: Duration,
    /// Whether authorization must be resolved online.
    pub requires_online_authorization: bool,
}

mandate_types::canonical_record!(
    CredentialProfile {
        name,
        kind,
        revocation,
        max_ttl,
        positive_cache_ttl,
        requires_online_authorization
    },
    samples: vec![
        CredentialProfile {
            name: "reference".to_owned(),
            kind: CredentialKind::Reference,
            revocation: RevocationGuarantee::ImmediateOnline,
            max_ttl: Duration::new("PT1H"),
            positive_cache_ttl: Duration::new("PT30S"),
            requires_online_authorization: true,
        },
        CredentialProfile {
            name: "self-contained".to_owned(),
            kind: CredentialKind::SelfContained,
            revocation: RevocationGuarantee::BoundedOffline,
            max_ttl: Duration::new("PT15M"),
            positive_cache_ttl: Duration::new("PT0S"),
            requires_online_authorization: false,
        },
    ]
);

pub mod signing_real;

/// The conformance registry for the accepted credential-format types.
pub mod conformance {
    use mandate_types::conformance::{Case, Entry};

    /// Every conformance entry this crate declares.
    #[must_use]
    pub fn entries() -> Vec<Entry> {
        vec![
            Entry::of::<crate::CredentialDescriptor>(),
            Entry::of::<crate::CredentialProfile>(),
        ]
    }

    /// Run every conformance entry this crate declares.
    #[must_use]
    pub fn cases() -> Vec<Case> {
        entries().iter().map(Entry::run).collect()
    }
}
