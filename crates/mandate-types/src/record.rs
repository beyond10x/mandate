//! The shared value records: the `struct` types more than one domain refers to.
//!
//! The accepted domain records live in `mandate-model` and the accepted
//! credential-format records in `mandate-token`; every one of them is declared the same
//! way, through [`crate::canonical_record`].

use serde::{Deserialize, Serialize};

use crate::conformance::Entry;
use crate::{Action, Audience, CorrelationId, CredentialId, DelegationId, ExecutionId};
use crate::{OrganizationId, PrincipalId, ResourceId, ResourceType, SpaceId};

/// `mandate.core.ResourceRef`: a resource named by its type and identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRef {
    /// The declared resource type.
    pub resource_type: ResourceType,
    /// The declared resource identity.
    pub resource_id: ResourceId,
}

crate::canonical_record!(ResourceRef { resource_type, resource_id }, samples: vec![ResourceRef {
    resource_type: ResourceType::new("document"),
    resource_id: crate::conformance::first_sample::<ResourceId>(),
}]);

/// `mandate.core.AuthorityScope`: the actions and resources an authority covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityScope {
    /// The declared actions.
    pub actions: Vec<Action>,
    /// The declared resources.
    pub resources: Vec<ResourceRef>,
    /// The optional space the scope is confined to.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::value::present"
    )]
    pub space: Option<SpaceId>,
}

crate::canonical_record!(
    AuthorityScope { actions, resources, space },
    samples: vec![
        AuthorityScope { actions: Vec::new(), resources: Vec::new(), space: None },
        AuthorityScope {
            actions: vec![Action::new("read"), Action::new("write")],
            resources: vec![crate::conformance::first_sample::<ResourceRef>()],
            space: Some(crate::conformance::first_sample::<SpaceId>()),
        },
    ]
);

/// `mandate.core.VerifiedContext`: the authenticated context a command is evaluated in.
///
/// Every selector here comes from credential validation. An optional actor is preserved
/// exactly: absent stays absent across a round trip, present stays present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedContext {
    /// The validated subject.
    pub subject: PrincipalId,
    /// The validated actor, when the subject acts through one.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::value::present"
    )]
    pub actor: Option<PrincipalId>,
    /// The validated organization.
    pub organization: OrganizationId,
    /// The validated audience.
    pub audience: Audience,
    /// The credential the context was validated from.
    pub credential: CredentialId,
    /// The delegation in force, when there is one.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::value::present"
    )]
    pub delegation: Option<DelegationId>,
    /// The execution in force, when there is one.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::value::present"
    )]
    pub execution: Option<ExecutionId>,
    /// The correlation carried through the request.
    pub correlation: CorrelationId,
}

crate::canonical_record!(
    VerifiedContext {
        subject,
        actor,
        organization,
        audience,
        credential,
        delegation,
        execution,
        correlation
    },
    samples: vec![
        VerifiedContext {
            subject: crate::conformance::first_sample::<PrincipalId>(),
            actor: None,
            organization: crate::conformance::first_sample::<OrganizationId>(),
            audience: Audience::new("mandate"),
            credential: crate::conformance::first_sample::<CredentialId>(),
            delegation: None,
            execution: None,
            correlation: CorrelationId::new("correlation"),
        },
        VerifiedContext {
            subject: crate::conformance::first_sample::<PrincipalId>(),
            actor: Some(crate::conformance::first_sample::<PrincipalId>()),
            organization: crate::conformance::first_sample::<OrganizationId>(),
            audience: Audience::new("mandate"),
            credential: crate::conformance::first_sample::<CredentialId>(),
            delegation: Some(crate::conformance::first_sample::<DelegationId>()),
            execution: Some(crate::conformance::first_sample::<ExecutionId>()),
            correlation: CorrelationId::new("correlation"),
        },
    ]
);

pub(crate) fn entries() -> Vec<Entry> {
    vec![
        Entry::of::<ResourceRef>(),
        Entry::of::<AuthorityScope>(),
        Entry::of::<VerifiedContext>(),
    ]
}
