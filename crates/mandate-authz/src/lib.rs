//! `mandate.authorization.Check`: the one question a policy enforcement point asks, and
//! the decision it gets back.
//!
//! `systems/mandate/domains/authorization.yaml:4-26` declares exactly one command —
//! `Check(context, action, resource) -> Decision`, refused with
//! `mandate.authorization.Denied` — one event, `DecisionRecorded`, and no entity.
//! `docs/architecture/ownership.md:13` gives that domain to this crate. [`check`] is the
//! command; the three modules under it are the three things it does, in order:
//!
//! | Module | What it decides |
//! |---|---|
//! | [`context`] | whether the credential-derived context binds: tenant, audience, resource, space |
//! | [`evaluate`] | what the graph, policy and the capability ceilings come to, folded through deny precedence |
//! | [`decision`] | the `mandate.core.Decision` record that is returned and recorded |
//!
//! # What this crate does not decide
//!
//! Deny precedence and the ranking of challenge requirements have one home,
//! `mandate_policy::precedence` (`crates/mandate-policy/src/precedence.rs:1-6` names
//! `story:check-api` as its consumer), and this crate consumes it rather than restating
//! it. Whether a subject holds a relation is `mandate_graph::port::GraphRead`'s; whether
//! policy permits the action is `mandate_policy::port::PolicyEvaluator`'s; whether an
//! organization admits authority and a subject is a member of it is
//! `mandate_model::tenancy::Tenancy`'s. No storage engine and no policy engine is chosen
//! here: both ports are answered in tests by the doubles those crates publish.
//!
//! # Fail closed, in one direction
//!
//! `docs/architecture/combined.md:55` requires an outage to deny. Both ports distinguish a
//! decision against the caller from an inability to decide, and both report the second as
//! [`mandate_types::DenialReason::Unavailable`]. That reason enters the fold as a refusal,
//! and a refusal beats every allow, so neither port being down can be answered with the
//! other port's yes. This is the `pdp-outage` case
//! (`tests/security/cases.json:602`): deny, and invent no local permission.
//!
//! # Only direct requests are decided
//!
//! `docs/architecture/combined.md:53` makes effective authority the intersection of the
//! subject's authority, the **actor ceiling**, the **explicit delegation**, the requested
//! authority, the tenant, space and resource bindings, the registered target and current
//! policy. Every one of those bounds is read here except the actor ceiling and the
//! delegation, and no port in this crate's dependency ceiling can read either:
//! `mandate.delegation` is projected by nothing in `dependency-boundaries.json:20-25`. A
//! bound that cannot be evaluated cannot be intersected, so a `VerifiedContext` naming an
//! actor other than its subject, a delegation or an execution is **refused**
//! ([`context::direct`]) rather than decided as though it were unbounded. The actor-ceiling
//! intersection and the `agent_id` binding of `mandate.delegation.AgentCapabilityCeiling`
//! are `story:agent-authority-kernel`'s (`docs/architecture/ownership.md:16`); until they
//! land, a delegated request gets a refusal and never an allow.
//!
//! # A reauthentication challenge cannot be expressed by this contract
//!
//! `mandate_policy::port::ChallengeRequirement` has two variants and `combined.md:67` makes
//! the choice between them meaningful: an approval is given by a second party, a
//! reauthentication is cleared by the caller alone. `mandate.core.DecisionChallenge` carries
//! that choice nowhere — it declares `action`, `resource`, `approver_policy` and
//! `expires_at`, and no requirement (`crates/mandate-model/src/lib.rs:103-116`) — so a
//! decision cannot tell a caller to reauthenticate, and issuing one as an approval would
//! name an approver for something no approver acts on. Until the contract carries it, a
//! request whose strictest requirement is a reauthentication is refused as
//! [`mandate_types::DenialReason::Unavailable`]. **The gap is
//! `mandate.core.DecisionChallenge.requirement`**: adding it is an ESS change to
//! `systems/mandate` and a `mandate-model` change, both outside this story, and it is
//! recorded here for the follow-up that makes them.
//!
//! # `Decision.model_version` is always absent
//!
//! No port in this crate's dependency ceiling returns an
//! [`mandate_types::AuthorizationModelVersion`]: `mandate_policy::port::Evaluation` carries
//! a `PolicyVersion` and `mandate.policy.AuthorizationModel.version` is itself a
//! `PolicyVersion` (`crates/mandate-policy/src/record.rs:129`). Every decision this crate
//! assembles therefore records `model_version: None` rather than attributing itself to a
//! model version nobody stated. Widening the policy port is a later change.
//!
//! # What the caller must supply, and why
//!
//! [`CheckRequest`] carries the contract's three inputs and five values no port in the
//! ceiling can answer for: the audience the credential is required to carry, the relation
//! name the graph is asked about, the revision floor the read must not answer below, the
//! attribute input, the scope the request is made under, and the capability ceilings that
//! bound it. Each is documented at its field with the reason it cannot be looked up here.

pub mod context;
pub mod decision;
pub mod evaluate;

mandate_types::realizes! {
    "mandate.authorization.Check" => crate::check,
    "mandate.authorization.Denied" => crate::decision::Denied,
}

/// Every declared `mandate.authorization` element this crate does **not** realize, with the
/// reason.
///
/// A coverage registry that names what it covers and says nothing about the rest is read as
/// a claim about the whole domain. This is the other half of [`ESS_REALIZATIONS`], and
/// `crates/mandate-authz/tests/contract_agreement.rs` decides the pair against the compiled
/// model in both directions: an element this list names and the registry also realizes is a
/// contradiction, and an element neither one names is an element nobody accounted for.
///
/// There is one, and it is not an oversight. `authorization.yaml:12-20` emits
/// `DecisionRecorded` from the accepted outcome, and this crate returns the decision to its
/// caller instead: it holds no event payload type, no allocator of one, and no port that
/// could append it. `story:check-api` recorded why — `DecisionRecorded` "changes no entity …
/// so it is not a move-event" — and the adapter that records it is the decision point's
/// deployment, not this library.
pub const ESS_UNREALIZED: &[(&str, &str)] = &[(
    "mandate.authorization.DecisionRecorded",
    "no event payload type is declared here: [`check`] returns the decision to its caller \
     and the recording adapter appends it; owner story:check-api",
)];

use mandate_graph::port::GraphRead;
use mandate_graph::topology::ResourceLookup;
use mandate_model::Decision;
use mandate_model::graph::Topology;
use mandate_model::tenancy::Tenancy;
use mandate_policy::port::{AttributeSet, PolicyEvaluator};
use mandate_policy::precedence::RoleCatalog;
use mandate_types::{
    Action, Audience, AuthorityScope, AuthzRevision, ResourceRef, VerifiedContext,
};

use crate::context::Binding;
use crate::decision::{ChallengeIssuer, DecisionIdAllocator, Denied, Taken};
use crate::evaluate::{Authority, Ceiling, Read};

/// What `mandate.authorization.Check` is asked.
#[derive(Debug)]
pub struct CheckRequest<'a> {
    /// The credential-derived context (`authorization.yaml:6-7`). Its organization is the
    /// tenancy bound and is never taken from a caller-supplied selector.
    pub context: &'a VerifiedContext,
    /// The action requested (`authorization.yaml:8-9`).
    pub action: &'a Action,
    /// The resource the action is on (`authorization.yaml:10-11`).
    pub resource: &'a ResourceRef,
    /// The audience the credential is required to have been issued for.
    ///
    /// No audience registry is reachable from this crate's dependency ceiling —
    /// `mandate-token` owns resource servers (`docs/architecture/ownership.md:15`) and is
    /// not a dependency — so the caller states what it requires and the verified audience
    /// is compared against it.
    pub expected_audience: &'a Audience,
    /// The relation or role name the graph is asked about.
    ///
    /// `mandate.graph.Grant.role` is a bare string and no domain declares a mapping from
    /// an action to the roles that carry it, so the caller names the relation and
    /// [`mandate_policy::precedence::expand`] decides whether it carries the action.
    pub relation: &'a str,
    /// The revision the read must not answer below (`crates/mandate-graph/src/port.rs:161-165`).
    pub minimum: &'a AuthzRevision,
    /// The attribute input policy evaluates against.
    pub attributes: &'a AttributeSet,
    /// The authority the request is made under, when it is made under one.
    ///
    /// Two bounds, read in two places: its `space` binds in [`context::bind`], and its
    /// `actions` and `resources` are intersected with the request by
    /// [`evaluate::requested`] — `combined.md:53` puts requested authority inside the same
    /// intersection as every other bound, and a scope that covers neither grants none.
    pub scope: Option<&'a AuthorityScope>,
    /// The capability ceilings the caller holds. Every applicable one intersects
    /// (`systems/mandate/domains/delegation.yaml:5`).
    pub ceilings: &'a [Ceiling],
}

/// The decision point: the ports and the projections a decision is taken against.
///
/// Held as one value so the entry point takes a request, an allocator and this, rather
/// than eight parameters that could be passed in the wrong order.
#[derive(Debug)]
pub struct Pdp<'a, G, P, C, I>
where
    G: GraphRead<Revision = AuthzRevision> + ResourceLookup + ?Sized,
    P: PolicyEvaluator + ?Sized,
    C: RoleCatalog + ?Sized,
    I: ChallengeIssuer + ?Sized,
{
    /// The relationship graph: the authority read, and where a resource sits.
    pub graph: &'a G,
    /// The policy evaluator.
    pub policy: &'a P,
    /// What actions a role name carries.
    pub catalog: &'a C,
    /// What an approval-required decision needs and no port answers.
    pub issuer: &'a I,
    /// The tenancy projection: which organizations admit authority, and who is a member.
    pub tenancy: &'a Tenancy,
    /// The resource projection, read for a resource's space.
    pub topology: &'a Topology,
}

/// Decide one `mandate.authorization.Check`.
///
/// The context binds first and a request that does not bind reads no authority at all;
/// what the ports and ceilings come to is then folded through deny precedence; and the one
/// assembly path turns that into the decision, refusal included.
///
/// # Errors
///
/// [`Denied`] for every outcome that is not an allow, carrying both the declared reason
/// and the decision that was taken — including the `allowed=false` decision with a
/// structured challenge that an approval requirement produces.
pub fn check<G, P, C, I, A>(
    pdp: &Pdp<'_, G, P, C, I>,
    allocator: &mut A,
    request: &CheckRequest<'_>,
) -> Result<Decision, Denied>
where
    G: GraphRead<Revision = AuthzRevision> + ResourceLookup + ?Sized,
    P: PolicyEvaluator + ?Sized,
    C: RoleCatalog + ?Sized,
    I: ChallengeIssuer + ?Sized,
    A: DecisionIdAllocator + ?Sized,
{
    let taken = Taken {
        context: request.context,
        action: request.action,
        resource: request.resource,
    };

    // Binding first, and a refusal returns without reading a port: a request whose context
    // does not stand must not ask the graph or policy anything on its behalf.
    let authority = match context::bind(
        pdp.tenancy,
        pdp.topology,
        pdp.graph,
        &Binding {
            context: request.context,
            resource: request.resource,
            expected_audience: request.expected_audience,
            scope: request.scope,
        },
    ) {
        Ok(bound) => evaluate::evaluate(
            pdp.graph,
            pdp.policy,
            pdp.catalog,
            &Read {
                context: request.context,
                subject: &bound.subject,
                action: request.action,
                resource: &bound.resource,
                relation: request.relation,
                minimum: request.minimum,
                attributes: request.attributes,
                scope: request.scope,
                ceilings: request.ceilings,
            },
        ),
        Err(reason) => Authority::refused(reason),
    };

    decision::decide(allocator, pdp.issuer, &taken, &authority)
}
