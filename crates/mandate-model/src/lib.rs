//! Framework-independent canonical domain.
//!
//! Foundation scaffold; normative contracts live in `systems/mandate`.
//! Runtime behavior is not implemented in this milestone.
//!
//! # Credential containment
//!
//! The four accepted `mandate.core` records declared in this file —
//! [`TenantResolutionRule`], [`DecisionChallenge`], [`Decision`] and [`AuditRecord`] — are
//! declared through [`mandate_types::canonical_record`], which requires each field to be a
//! [`mandate_types::PersistedValue`].
//!
//! The six projections in [`tenancy`] and [`graph`] are not, and cannot be: that macro
//! hardcodes the `mandate.core.` prefix and every one of them is a `mandate.tenancy.*` or
//! `mandate.graph.*` entity. The bound reaches them all the same, because each module
//! carries the macro's own field check written out — `tenancy.rs`'s and `graph.rs`'s
//! `const _: () = { … }` blocks destructure every projection without `..` and require
//! [`mandate_types::PersistedValue`] of every field. A field added to any of the six, or
//! one whose type the boundary does not admit, does not compile.
//!
//! A domain record that carries an identifier is accepted:
//!
//! ```
//! use mandate_model::AuditRecord;
//! use mandate_types::PersistedValue;
//!
//! fn persistable<T: PersistedValue>() {}
//!
//! persistable::<AuditRecord>();
//! ```
//!
//! A domain record cannot be declared with a transient credential field:
//!
//! ```compile_fail
//! use mandate_types::{CorrelationId, CredentialProof};
//!
//! #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
//! pub struct IssuanceRecord {
//!     pub correlation: CorrelationId,
//!     pub proof: CredentialProof,
//! }
//!
//! mandate_types::canonical_record!(IssuanceRecord { correlation, proof }, samples: vec![
//!     IssuanceRecord {
//!         correlation: CorrelationId::new("correlation"),
//!         proof: CredentialProof::from_bytes(b"abc".to_vec()),
//!     }
//! ]);
//! ```

pub mod graph;
pub mod tenancy;

use serde::{Deserialize, Serialize};

use mandate_types::conformance::first_sample;
use mandate_types::{
    Action, Audience, AuditAction, AuditOutcome, AuthorityScope, AuthorizationModelVersion,
    AuthzRevision, CorrelationId, CredentialId, CredentialKind, DecisionId, DecisionReason,
    DelegationId, ExecutionId, OrganizationId, PolicyId, PolicyVersion, PrincipalId, ResourceRef,
    Timestamp,
};

/// `mandate.core.TenantResolutionRule`: how a configured organization is selected.
///
/// The organization is configured, never taken from an unvalidated selector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantResolutionRule {
    /// The configured organization the rule resolves to.
    pub configured_organization: OrganizationId,
    /// The validated claim name the rule matches on, when it matches on one.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub verified_claim_name: Option<String>,
    /// The validated claim value the rule matches on, when it matches on one.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub verified_claim_value: Option<String>,
}

mandate_types::canonical_record!(
    TenantResolutionRule { configured_organization, verified_claim_name, verified_claim_value },
    samples: vec![
        TenantResolutionRule {
            configured_organization: first_sample::<OrganizationId>(),
            verified_claim_name: None,
            verified_claim_value: None,
        },
        TenantResolutionRule {
            configured_organization: first_sample::<OrganizationId>(),
            verified_claim_name: Some("org".to_owned()),
            verified_claim_value: Some("acme".to_owned()),
        },
    ]
);

/// `mandate.core.DecisionChallenge`: what an approval-required decision asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionChallenge {
    /// The action under challenge.
    pub action: Action,
    /// The resource under challenge.
    pub resource: ResourceRef,
    /// The policy that names the approver.
    pub approver_policy: PolicyId,
    /// When the challenge stops being answerable.
    pub expires_at: Timestamp,
}

mandate_types::canonical_record!(
    DecisionChallenge { action, resource, approver_policy, expires_at },
    samples: vec![DecisionChallenge {
        action: Action::new("approve"),
        resource: first_sample::<ResourceRef>(),
        approver_policy: first_sample::<PolicyId>(),
        expires_at: Timestamp::new("2026-09-18T00:00:00Z"),
    }]
);

/// `mandate.core.Decision`: the recorded outcome of an authorization question.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    /// Whether the request was allowed.
    pub allowed: bool,
    /// The declared reason.
    pub reason: DecisionReason,
    /// The identity of this decision.
    pub decision_id: DecisionId,
    /// The authorization revision the decision was taken at, when recorded.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub revision: Option<AuthzRevision>,
    /// The challenge to answer, when approval is required.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub challenge: Option<DecisionChallenge>,
    /// The policy version in force, when recorded.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub policy_version: Option<PolicyVersion>,
    /// The authorization model version in force, when recorded.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub model_version: Option<AuthorizationModelVersion>,
}

mandate_types::canonical_record!(
    Decision { allowed, reason, decision_id, revision, challenge, policy_version, model_version },
    samples: vec![
        Decision {
            allowed: true,
            reason: DecisionReason::Allowed,
            decision_id: first_sample::<DecisionId>(),
            revision: None,
            challenge: None,
            policy_version: None,
            model_version: None,
        },
        Decision {
            allowed: false,
            reason: DecisionReason::ApprovalRequired,
            decision_id: first_sample::<DecisionId>(),
            revision: Some(AuthzRevision::new("revision")),
            challenge: Some(first_sample::<DecisionChallenge>()),
            policy_version: Some(PolicyVersion::new("v1")),
            model_version: Some(AuthorizationModelVersion::new("v1")),
        },
    ]
);

/// `mandate.core.AuditRecord`: what an audit event records.
///
/// Every field is a [`mandate_types::PersistedValue`]; the transient credential types
/// are not, so no credential material can be added to this record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    /// The subject the event concerns.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub subject: Option<PrincipalId>,
    /// The actor the subject acted through.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub actor: Option<PrincipalId>,
    /// The organization the event occurred in.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub organization_id: Option<OrganizationId>,
    /// The event type.
    pub event_type: AuditAction,
    /// The correlation carried through the request.
    pub correlation: CorrelationId,
    /// The decision this event records, when there was one.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub decision_id: Option<DecisionId>,
    /// The audience that was requested.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub requested_audience: Option<Audience>,
    /// The audience that was issued.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub issued_audience: Option<Audience>,
    /// The scope that was requested.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub requested_scope: Option<AuthorityScope>,
    /// The credential kind involved.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub credential_kind: Option<CredentialKind>,
    /// The delegation in force.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub delegation_id: Option<DelegationId>,
    /// The execution in force.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub execution_id: Option<ExecutionId>,
    /// The recorded outcome.
    pub result: AuditOutcome,
    /// When the event occurred.
    pub occurred_at: Timestamp,
    /// The policy version in force.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub policy_version: Option<PolicyVersion>,
    /// The authorization model version in force.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub model_version: Option<AuthorizationModelVersion>,
    /// The authorization revision in force.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub authz_revision: Option<AuthzRevision>,
    /// The kind of the credential the request presented.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub source_credential_kind: Option<CredentialKind>,
    /// The identity of the credential the request presented.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub source_credential_id: Option<CredentialId>,
    /// The identity of the credential that was issued.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub issued_credential_id: Option<CredentialId>,
    /// The scope that was issued.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "mandate_types::value::present"
    )]
    pub issued_scope: Option<AuthorityScope>,
}

mandate_types::canonical_record!(
    AuditRecord {
        subject,
        actor,
        organization_id,
        event_type,
        correlation,
        decision_id,
        requested_audience,
        issued_audience,
        requested_scope,
        credential_kind,
        delegation_id,
        execution_id,
        result,
        occurred_at,
        policy_version,
        model_version,
        authz_revision,
        source_credential_kind,
        source_credential_id,
        issued_credential_id,
        issued_scope
    },
    samples: vec![
        AuditRecord {
            subject: None,
            actor: None,
            organization_id: None,
            event_type: AuditAction::new("mandate.authorization.Check"),
            correlation: CorrelationId::new("correlation"),
            decision_id: None,
            requested_audience: None,
            issued_audience: None,
            requested_scope: None,
            credential_kind: None,
            delegation_id: None,
            execution_id: None,
            result: AuditOutcome::new("allowed"),
            occurred_at: Timestamp::new("2026-09-18T00:00:00Z"),
            policy_version: None,
            model_version: None,
            authz_revision: None,
            source_credential_kind: None,
            source_credential_id: None,
            issued_credential_id: None,
            issued_scope: None,
        },
        AuditRecord {
            subject: Some(first_sample::<PrincipalId>()),
            actor: Some(first_sample::<PrincipalId>()),
            organization_id: Some(first_sample::<OrganizationId>()),
            event_type: AuditAction::new("mandate.credential.IssueSelfContainedCredential"),
            correlation: CorrelationId::new("correlation"),
            decision_id: Some(first_sample::<DecisionId>()),
            requested_audience: Some(Audience::new("mandate")),
            issued_audience: Some(Audience::new("mandate")),
            requested_scope: Some(first_sample::<AuthorityScope>()),
            credential_kind: Some(CredentialKind::SelfContained),
            delegation_id: Some(first_sample::<DelegationId>()),
            execution_id: Some(first_sample::<ExecutionId>()),
            result: AuditOutcome::new("allowed"),
            occurred_at: Timestamp::new("2026-09-18T00:00:00Z"),
            policy_version: Some(PolicyVersion::new("v1")),
            model_version: Some(AuthorizationModelVersion::new("v1")),
            authz_revision: Some(AuthzRevision::new("revision")),
            source_credential_kind: Some(CredentialKind::Reference),
            source_credential_id: Some(first_sample::<CredentialId>()),
            issued_credential_id: Some(first_sample::<CredentialId>()),
            issued_scope: Some(first_sample::<AuthorityScope>()),
        },
    ]
);

/// The conformance registry for the accepted domain records.
pub mod conformance {
    use mandate_types::conformance::{Case, Entry};

    /// Every conformance entry this crate declares.
    #[must_use]
    pub fn entries() -> Vec<Entry> {
        vec![
            Entry::of::<crate::TenantResolutionRule>(),
            Entry::of::<crate::DecisionChallenge>(),
            Entry::of::<crate::Decision>(),
            Entry::of::<crate::AuditRecord>(),
        ]
    }

    /// Run every conformance entry this crate declares.
    #[must_use]
    pub fn cases() -> Vec<Case> {
        entries().iter().map(Entry::run).collect()
    }
}
