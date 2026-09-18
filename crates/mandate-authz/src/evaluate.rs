//! One authority read, one policy read, the ceilings, folded through deny precedence.
//!
//! `docs/architecture/combined.md:53` — "denies override grants" — and the ranking of
//! challenge requirements are `mandate-policy`'s single home
//! (`crates/mandate-policy/src/precedence.rs`). This module consumes
//! [`mandate_policy::precedence::combine`] and restates neither. What it owns is *which*
//! components go in: the graph's answer expanded against the role catalog, policy's
//! effect, and one component per applicable capability ceiling.
//!
//! # Exactly one read of each port
//!
//! A decision is one question, so the graph is asked once and policy is asked once. A
//! refusal from either is a component, never an early return: a policy refusal must still
//! be combined with the graph's answer, and neither port's inability to answer may be
//! reported as the other's decision.
//!
//! # An inability to answer is never an allow
//!
//! [`mandate_graph::port::GraphError::CouldNotAnswer`] and
//! [`mandate_policy::port::PolicyError::CouldNotAnswer`] both report
//! [`mandate_types::DenialReason::Unavailable`] through their own `denial_reason()`, and
//! that reason enters the fold as a refusal. `combine` gives every refusal precedence over
//! every allow, so an outage cannot be overridden by the other port answering yes. This is
//! the `pdp-outage` case (`tests/security/cases.json:602`): deny, and invent no local
//! permission.
//!
//! # The ceiling shape is declared here, minimally
//!
//! `mandate.delegation.AgentCapabilityCeiling` declares `allowed_actions` and
//! `denied_actions` as `List<mandate.core.ActionPattern>`, an `organization_id` that is
//! absent for a platform ceiling and present for a tenant one, and the rule that "all
//! applicable platform/tenant ceilings intersect"
//! (`systems/mandate/domains/delegation.yaml:5,:106-111`). No type in this crate's
//! dependency ceiling projects that entity and nothing anywhere matches an
//! [`mandate_types::ActionPattern`] against an [`mandate_types::Action`], so [`Ceiling`]
//! and [`covers`] are the minimum this module needs to apply one. The projection from the
//! recorded entity is `story:agent-authority-kernel`'s
//! (`docs/architecture/ownership.md:16`), and it is expected to replace [`Ceiling`]'s
//! construction, not its meaning.
//!
//! A ceiling bounds; it never grants. A ceiling that admits the action contributes
//! [`Component::Nothing`] — the identity of the fold — so a request no source allowed is
//! still refused, and a ceiling that does not admit it contributes a refusal that
//! overrides every allow. That is what makes the applicable ceilings an intersection.
//!
//! # The requested authority is a bound too, and reads the same way
//!
//! `combined.md:53` puts **requested authority** inside the same intersection as the actor
//! ceiling and the tenant, space and resource bindings, and states the closed direction for
//! all of them in one clause: "an empty source list grants none".
//! `mandate.core.AuthorityScope` is "the actions and resources an authority covers"
//! (`crates/mandate-types/src/record.rs:28-43`) and its first canonical sample is the empty
//! one, so a request made under a scope covering no action and no resource has requested
//! nothing and [`requested`] refuses it. A scope, like a ceiling, bounds and never grants:
//! covering the request contributes [`Component::Nothing`]. The scope's `space` is bound
//! earlier, by [`crate::context::bind`], because a space is a tenancy fact rather than a
//! component of authority.

use mandate_graph::port::{GraphQuery, GraphRead, Observed};
use mandate_policy::port::{AttributeSet, Challenge, PolicyEvaluator, PolicyRequest};
use mandate_policy::precedence::{Combined, Component, RoleCatalog, combine, expand};
use mandate_types::{
    Action, ActionPattern, AuthorityScope, AuthoritySubject, AuthzRevision, DenialReason,
    OrganizationId, PolicyVersion, ResourceRef, VerifiedContext,
};

/// One capability ceiling, as this module needs it.
///
/// See the module documentation: the fields are the three of
/// `mandate.delegation.AgentCapabilityCeiling` that bound an action. `scope` and
/// `max_delegation_ttl` bound other things and are not read here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ceiling {
    /// The organization this ceiling is recorded for; absent means a platform ceiling,
    /// which applies to every organization (`delegation.yaml:5`).
    pub organization: Option<OrganizationId>,
    /// The action patterns the ceiling admits.
    pub allowed_actions: Vec<ActionPattern>,
    /// The action patterns the ceiling refuses, whatever it admits.
    pub denied_actions: Vec<ActionPattern>,
}

impl Ceiling {
    /// Whether this ceiling applies to a request made in this organization.
    #[must_use]
    pub fn applies(&self, organization: &OrganizationId) -> bool {
        self.organization
            .as_ref()
            .is_none_or(|recorded| recorded == organization)
    }

    /// Whether this ceiling admits the action.
    ///
    /// A denied pattern wins over an allowed one, and an empty `allowed_actions` admits
    /// nothing: the same closed direction `combined.md:53` states for an empty source
    /// list.
    #[must_use]
    pub fn admits(&self, action: &Action) -> bool {
        !self
            .denied_actions
            .iter()
            .any(|pattern| covers(pattern, action))
            && self
                .allowed_actions
                .iter()
                .any(|pattern| covers(pattern, action))
    }

    /// The component this ceiling contributes to a request for this action.
    ///
    /// A ceiling never grants: admitting contributes the identity of the fold, so a
    /// request no source allowed stays refused.
    #[must_use]
    pub fn component(&self, action: &Action) -> Component {
        if self.admits(action) {
            Component::Nothing
        } else {
            Component::Denied(DenialReason::Denied)
        }
    }
}

/// Whether an action pattern covers an action.
///
/// `mandate.core.ActionPattern` is declared as a bare string
/// (`crates/mandate-types/src/text.rs:8`) and no document in `systems/mandate` states its
/// grammar, so the minimum that can express a ceiling is declared here and nothing more:
/// a pattern is either the action itself, or a prefix ending in `*` that covers every
/// action starting with that prefix. `*` alone therefore covers every action. A wider
/// grammar is a decision for whoever projects the recorded entity, and guessing one here
/// would put actions inside a ceiling that its author did not write.
#[must_use]
pub fn covers(pattern: &ActionPattern, action: &Action) -> bool {
    match pattern.as_str().strip_suffix('*') {
        Some(prefix) => action.as_str().starts_with(prefix),
        None => pattern.as_str() == action.as_str(),
    }
}

/// The component the requested authority contributes.
///
/// A request made under no scope has narrowed nothing and contributes the identity of the
/// fold; a request made under a scope is inside it only when the scope names both the
/// action and the resource. `AuthorityScope.actions` is a `List<Action>` and not a list of
/// patterns (`crates/mandate-types/src/record.rs:31-43`), so an action is named by
/// equality and no grammar is invented for it here.
///
/// A resource is named by its **identity**. `graph.yaml:8-11` declares
/// `mandate.graph.Resource`'s identity as `id: ResourceId` alone, with `resource_type` a
/// field of the record, and `mandate-graph` reads the same `AuthorityScope.resources`
/// field under exactly that rule (`crates/mandate-graph/src/double.rs:182-190`: "A grant
/// naming the right resource id under a stale `resource_type` names the same resource").
/// Comparing the whole `ResourceRef` here would apply a second identity rule to one value
/// in one decision, so that the graph finds authority on a resource this bound then says
/// was never requested.
#[must_use]
pub fn requested(
    scope: Option<&AuthorityScope>,
    action: &Action,
    resource: &ResourceRef,
) -> Component {
    match scope {
        None => Component::Nothing,
        Some(scope)
            if scope.actions.contains(action)
                && scope
                    .resources
                    .iter()
                    .any(|named| named.resource_id == resource.resource_id) =>
        {
            Component::Nothing
        }
        Some(_) => Component::Denied(DenialReason::Denied),
    }
}

/// What the ports are asked, for one bound request.
#[derive(Debug)]
pub struct Read<'a> {
    /// The credential-derived context. Its organization is the tenancy bound.
    pub context: &'a VerifiedContext,
    /// The subject the question is about, as [`crate::context::bind`] derived it.
    pub subject: &'a AuthoritySubject,
    /// The action requested.
    pub action: &'a Action,
    /// The resource the action is on.
    pub resource: &'a ResourceRef,
    /// The relation or role name the graph is asked about.
    ///
    /// The contract declares no mapping from an action to the relation names that carry
    /// it — `mandate.graph.Grant.role` is a bare string and no domain declares a catalog
    /// (`crates/mandate-policy/src/precedence.rs:8-15`) — so the caller names the relation
    /// and [`mandate_policy::precedence::expand`] decides whether it carries the action.
    pub relation: &'a str,
    /// The freshness floor the read must not answer below.
    pub minimum: &'a AuthzRevision,
    /// The attribute input policy evaluates against.
    pub attributes: &'a AttributeSet,
    /// The authority the request was made under, when it was made under one. Intersected
    /// by [`requested`]; its `space` is bound by [`crate::context::bind`].
    pub scope: Option<&'a AuthorityScope>,
    /// Every capability ceiling the caller holds. Those that apply intersect.
    pub ceilings: &'a [Ceiling],
}

/// What the ports answered, folded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority {
    /// The fold of every component, through [`combine`].
    pub combined: Combined,
    /// The revision the graph answered at, when it answered.
    pub revision: Option<AuthzRevision>,
    /// The policy version the answer was made under, when policy answered.
    pub policy_version: Option<PolicyVersion>,
    /// The challenge material policy carried, when it asked for one.
    pub challenges: Vec<Challenge>,
}

impl Authority {
    /// The authority of a request that was refused before any port was read.
    ///
    /// A binding refusal ([`crate::context::bind`]) reads nothing, so it carries no
    /// revision, no policy version and no challenge — and it is still assembled into a
    /// decision by the one path that assembles every other one.
    #[must_use]
    pub const fn refused(reason: DenialReason) -> Self {
        Self {
            combined: Combined::Denied(reason),
            revision: None,
            policy_version: None,
            challenges: Vec::new(),
        }
    }
}

/// Ask the graph once, ask policy once, apply the ceilings, and fold the lot.
#[must_use]
pub fn evaluate<G, P, C>(graph: &G, policy: &P, catalog: &C, read: &Read<'_>) -> Authority
where
    G: GraphRead<Revision = AuthzRevision> + ?Sized,
    P: PolicyEvaluator + ?Sized,
    C: RoleCatalog + ?Sized,
{
    let mut components: Vec<Component> = Vec::new();
    let mut revision = None;
    let mut policy_version = None;
    let mut challenges = Vec::new();

    // The graph answers whether the subject holds the named relation; whether that
    // relation carries the requested action is the catalog's, and an unknown role name
    // refuses (`crates/mandate-policy/src/precedence.rs:186-209`).
    match graph.check(
        &GraphQuery {
            context: read.context,
            subject: read.subject,
            resource: read.resource,
            relation: read.relation,
        },
        read.minimum,
    ) {
        Ok(Observed { revision: at, .. }) => {
            revision = Some(at);
            components.push(
                expand(
                    catalog,
                    &read.context.organization,
                    read.relation,
                    read.action,
                )
                .component(),
            );
        }
        Err(refusal) => components.push(Component::Denied(refusal.denial_reason())),
    }

    match policy.evaluate(&PolicyRequest {
        context: read.context,
        subject: read.subject,
        action: read.action,
        resource: read.resource,
        attributes: read.attributes,
    }) {
        Ok(evaluation) => {
            policy_version = Some(evaluation.version);
            components.push(Component::of_effect(evaluation.effect));
            // An answer that attaches challenge material has stated something the caller
            // must satisfy, whatever effect it carries beside it. Dropping it because the
            // effect said `Allow` would tell the caller there is nothing to satisfy. What
            // the pair comes to is precedence's to decide, not this module's: an approval
            // requirement overrides an allow and loses to a refusal
            // (`crates/mandate-policy/src/precedence.rs:130-175`).
            if let Some(challenge) = evaluation.challenge {
                components.push(Component::ApprovalRequired);
                challenges.push(challenge);
            }
        }
        Err(refusal) => components.push(Component::Denied(refusal.denial_reason())),
    }

    components.push(requested(read.scope, read.action, read.resource));

    for ceiling in read
        .ceilings
        .iter()
        .filter(|ceiling| ceiling.applies(&read.context.organization))
    {
        components.push(ceiling.component(read.action));
    }

    Authority {
        combined: combine(&components),
        revision,
        policy_version,
        challenges,
    }
}
