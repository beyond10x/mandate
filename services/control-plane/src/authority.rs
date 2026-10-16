//! The composition's authority decision: `mandate.authorization.Check`, asked **before** the
//! composition dispatches a handler.
//!
//! # Why the dependency boundary moved, and why here
//!
//! `mandate_authz::check` (`crates/mandate-authz/src/lib.rs`) is the decider this workspace
//! has. Nothing could call it: `dependency-boundaries.json` admitted `mandate-authz` to
//! `mandate-testkit` and `mandate-conformance` and to nothing else, both test
//! infrastructure. It cannot be admitted to `mandate-model` — `mandate-authz` depends on
//! `mandate-model`, so that edge is a cycle, and `crates/mandate-model/src/tenancy.rs:93-95`
//! records the consequence: whether a caller holds the authority a command names "is
//! `mandate-authz`'s and is decided nowhere here".
//!
//! One level up the cycle does not exist. This package already sees every domain crate the
//! served road needs, and `dependency-boundaries.json` now admits
//! `mandate-control-plane → mandate-authz`, `mandate-graph` and `mandate-policy` for exactly
//! this call. The file itself records no reasons — it is a map of package to admitted
//! dependency names and the checker (`xtask/src/main.rs`) reads nothing else — so the reason
//! is recorded where `services/control-plane/src/adapters.rs` records the same kind of
//! reason for the three port adapters: in the module that takes the dependency.
//!
//! # Every decision this module can take today is a double's
//!
//! `mandate_authz::check` reads two ports, and each has exactly one implementor outside a
//! test file:
//!
//! | Port | Only implementor |
//! |---|---|
//! | `mandate_graph::port::GraphRead` | `mandate_graph::double::GraphDouble` |
//! | `mandate_policy::port::PolicyEvaluator` | `mandate_policy::double::PolicyDouble` |
//!
//! So a deployment can be configured with a stand-in and with nothing else, and the
//! refusals this module routes are refusals a stand-in was written to give. That is why
//! [`Deployment::with_authority`](crate::adapters::Deployment::with_authority) is opt-in and
//! why `src/main.rs` configures none: a composition that failed closed on an unconfigured
//! decision point would refuse every request a shipped binary serves, and one that failed
//! open while claiming to decide would be worse. The engine behind the ports is
//! `story:graph-policy-adapter`'s, and until it lands the honest configuration is *none*.
//!
//! **The half that is decided over live state.** `mandate_authz::check` binds through
//! `mandate_authz::context::bind_any`, which reads `mandate_model::tenancy::Tenancy` and
//! `mandate_model::graph::Topology`, both folds, and decides three things before either port
//! is read: the organization still admits authority, the subject is a member of it, and the
//! credential's audience is the one the caller requires. A request that involves an agent is
//! then decided over the delegation fold the decision point holds (see *The delegation fold*
//! below). A caller failing any of those is refused before the graph or policy is asked.
//!
//! **This composition can fail every one of them but the audience.**
//! `bind` compares `context.audience` against the `expected_audience` the *caller* states,
//! and a caller has two independent sources only when the context comes from credential
//! validation and the expectation from a registry.
//! [`Deployment::authorize`](crate::adapters::Deployment::authorize) has one: it is the
//! authorization endpoint, before any credential exists — the assembled context carries
//! `CredentialId::new([0; 16])` — so both the context's audience and the expectation it
//! passes are the registered target's, read from the credential fold. Two reads of one
//! value cannot disagree, so `DenialReason::AudienceMismatch` is unreachable from this call
//! site. It is **not** unreachable from the decision point, which any caller with a real
//! expectation reaches, and
//! `mandate-control-plane::authority::a_context_whose_audience_is_not_the_expected_one_is_refused_by_the_decision_point`
//! is the case that decides it. Passing a value this composition does not have — the
//! deployment's own issuer audience, say — would make the arm reachable by comparing the
//! target's audience against something no contract says it should equal, which is a
//! refusal invented rather than decided.
//!
//! What a fold cannot answer at all is the one thing the caller-authority clauses name —
//! whether the caller *holds* the authority — because `tenancy.rs:317-318` puts that with
//! "grants and relationships", which are the graph's and the policy's.
//!
//! # The delegation fold
//!
//! `mandate_authz::check` reads the agent, its capability ceilings, the delegation and the
//! execution a request names through `mandate_authz::agent::AgentAuthorityRead`. A
//! [`DecisionPoint`] answers it from its own `mandate_authz::event::DelegationProjection`,
//! the fold of the `mandate.delegation` events (`docs/adr/0009-event-sourced-persistence.md`):
//! the projection is the log and the records folded from it, never a table written beside a
//! log. [`Deployment::record_delegation`](crate::adapters::Deployment::record_delegation)
//! appends an event the decide functions of `mandate-authz` produced — `CreateDelegation`,
//! `RevokeDelegation`, `RetireAgent`, `CompleteExecution`, `ConsumeApproval`, and the
//! `ApprovedDecisionRecorded` of `CheckWithApproval` through its `From` — and applies it, so
//! the next check reads what the command wrote: a delegated request is admitted over a
//! recorded delegation and refused once its revocation is recorded. Applying is total, as
//! the projection's own `apply` is, so no write can be refused half-way and nothing is copied
//! to be swapped.
//!
//! The fold belongs to the decision point because nothing else in the composition reads it:
//! a deployment configured with no decision point decides no authority, and it refuses to
//! record a delegation event (`DelegationUnrecorded`) rather than keeping one nothing reads.
//! A direct request of a principal that is no agent reads no record of the fold and is
//! decided as it was over the empty read.
//!
//! # Named residue
//!
//! * **The relation is a constant this module states.** `mandate-authz`'s own header says
//!   "no domain declares a mapping from an action to the roles that carry it, so the caller
//!   names the relation". [`ISSUANCE_RELATION`] is this composition naming one. A declared
//!   action-to-role mapping is a contract change and is nobody's here.
//! * **`scope` is `None` on every check this composition makes.** The OAuth
//!   `requested_scope` of an authorization request is the authority the *credential* is
//!   asked to carry; `mandate_authz::CheckRequest::scope` is an
//!   `mandate.core.AuthorityScope` intersected with the check's own action and resource.
//!   The two are different vocabularies and passing one as the other would refuse every
//!   request by construction. Reconciling them is the credential-scope story's, not this
//!   one's.
//! * **Agents, ceilings, executions and approvals are seeded, not recorded.** No command
//!   creates them yet (`story:declared-writers`; `SupersedeAgentCapabilityCeiling` stays
//!   `declared` on `story:agent-security`, because ESS 0.59.0 cannot declare a create beside a
//!   move in one outcome, ESS-COMMAND-009), so the projection starts from the records the
//!   operator configures, as `DelegationProjection::fold(records, events)` takes them, and
//!   only delegations — and the
//!   moves the commands make on the seeded records — come from events. The seeding goes in
//!   with the decision point, through the opt-in
//!   [`Deployment::with_authority`](crate::adapters::Deployment::with_authority); `src/main.rs`
//!   configures none, for the reason the section above gives.
//! * **No route serves a delegation command.** The deployment records the events a caller of
//!   the decide functions hands it; serving `CreateDelegation` and its siblings over HTTP is
//!   not done here.
//! * **The log is in memory**, as every fold of the deployment is until the event-log adapter
//!   lands (`crate::adapters::Deployment`).
//! * **No denial is audited.** `decision-blocker:audit-routing` holds the vocabulary and
//!   `mandate-audit` is outside this package's ceiling, exactly as `adapters.rs` records
//!   for every other refusal the road gives.

use mandate_authz::decision::{ChallengeIssuer, DecisionIdAllocator, Denied};
use mandate_authz::event::{DelegationEvent, DelegationProjection};
use mandate_authz::{CheckRequest, Pdp, check};
use mandate_graph::port::GraphRead;
use mandate_graph::topology::ResourceLookup;
use mandate_model::Decision;
use mandate_model::graph::Topology;
use mandate_model::tenancy::Tenancy;
use mandate_policy::port::{AttributeSet, PolicyEvaluator};
use mandate_policy::precedence::RoleCatalog;
use mandate_types::{
    Action, Audience, AuthorityScope, AuthzRevision, ResourceRef, Timestamp, VerifiedContext,
};

/// The `mandate.core.ResourceType` the composition names a registered target by.
///
/// A `mandate.credential.ResourceServer` is the resource an authorization request acts on,
/// and `mandate.core.ResourceRef` is how every authority question names a resource. The
/// registration's own identity is the resource identity, so the two cannot drift.
pub const RESOURCE_SERVER: &str = "mandate.credential.ResourceServer";

/// The action the composition asks about before it dispatches the authorization endpoint:
/// the command it is about to dispatch, named as the contract names it.
pub const ISSUE_AUTHORIZATION_CODE: &str = "mandate.credential.IssueAuthorizationCode";

/// The graph relation the composition asks about for that action.
///
/// See the module header: no declared mapping from an action to the roles carrying it
/// exists, so the caller of `mandate_authz::check` names the relation and
/// `mandate_policy::precedence::expand` decides whether it carries the action.
pub const ISSUANCE_RELATION: &str = "credential.issuer";

/// The clause a refusal from this module carries, so a reader can tell an authority refusal
/// from the handler's own clauses.
pub const AUTHORITY_DENIED: &str = "AuthorityDenied";

/// What the composition asks about one dispatch.
///
/// The three contract inputs of `mandate.authorization.Check` plus the two values no port
/// in the ceiling answers for, carried by reference because the caller holds them all.
#[derive(Debug)]
pub struct Admission<'a> {
    /// The credential-derived context the dispatch would run under. Its organization is
    /// the tenancy bound and is never a caller-supplied selector.
    pub context: &'a VerifiedContext,
    /// The action the dispatch performs.
    pub action: &'a Action,
    /// The resource the action is on.
    pub resource: &'a ResourceRef,
    /// The audience the credential is required to have been issued for.
    pub expected_audience: &'a Audience,
    /// The graph relation asked about.
    pub relation: &'a str,
    /// The authority scope the request is made under, when it is made under one.
    pub scope: Option<&'a AuthorityScope>,
    /// The instant the decision is taken at: the request's own, read once
    /// ([`crate::adapters::Deployment::now`]).
    pub at: &'a Timestamp,
}

/// The decision the composition takes before it dispatches a handler.
///
/// Object-safe on purpose: [`crate::adapters::Deployment`] holds one behind a `Box` rather
/// than growing four more type parameters, and the ports a deployment is configured with
/// are the operator's choice rather than the composition's type.
pub trait Admitting {
    /// Decide one `mandate.authorization.Check`.
    ///
    /// # Errors
    ///
    /// The declared refusal, [`Denied`], carrying both the reason that crosses the wire and
    /// the decision that was taken.
    fn admit(&mut self, admission: &Admission<'_>) -> Result<Decision, Denied>;

    /// The `mandate.delegation` fold [`Admitting::admit`] decides a request that involves an
    /// agent over: the seeded records with every event recorded since applied, and the log
    /// of those events.
    ///
    /// The read the decide half of a delegation command takes
    /// (`mandate_authz::command::decide_revoke_delegation` and its siblings), so a command
    /// is decided over exactly the records the next check reads.
    fn delegations(&self) -> &DelegationProjection;

    /// Record one `mandate.delegation` event a decide function of `mandate-authz` produced:
    /// append it to the log and apply it to the fold the next [`Admitting::admit`] reads.
    ///
    /// Total, as `DelegationProjection::apply` is: the decide half has refused everything
    /// the contract refuses, and recording re-checks nothing.
    fn record_delegation(&mut self, event: &DelegationEvent);
}

/// A decision point: the ports, the folds and the two request values the composition states
/// once rather than per call.
#[derive(Debug)]
pub struct DecisionPoint<G, P, C, I, A> {
    /// The relationship graph: the authority read, and where a resource sits.
    pub graph: G,
    /// The policy evaluator.
    pub policy: P,
    /// What actions a role name carries.
    pub catalog: C,
    /// What an approval-required decision needs and no port answers.
    pub issuer: I,
    /// The identities decisions are recorded under.
    pub allocator: A,
    /// The tenancy projection: which organizations admit authority, and who is a member.
    pub tenancy: Tenancy,
    /// The resource projection, read for a resource's space.
    pub topology: Topology,
    /// The revision the graph read must not answer below.
    pub minimum: AuthzRevision,
    /// The attribute input policy evaluates against.
    pub attributes: AttributeSet,
    /// The `mandate.delegation` projection: the agents, ceilings, executions and approvals
    /// the operator seeds (no command creates them yet), and the delegation events the
    /// deployment records over them ([`Admitting::record_delegation`]).
    pub delegations: DelegationProjection,
}

impl<G, P, C, I, A> Admitting for DecisionPoint<G, P, C, I, A>
where
    G: GraphRead<Revision = AuthzRevision> + ResourceLookup,
    P: PolicyEvaluator,
    C: RoleCatalog,
    I: ChallengeIssuer,
    A: DecisionIdAllocator,
{
    fn admit(&mut self, admission: &Admission<'_>) -> Result<Decision, Denied> {
        let pdp = Pdp {
            graph: &self.graph,
            policy: &self.policy,
            catalog: &self.catalog,
            issuer: &self.issuer,
            tenancy: &self.tenancy,
            topology: &self.topology,
            // The fold of the `mandate.delegation` events this decision point recorded, over
            // its seeded records: a request naming an agent, a delegation or an execution is
            // decided over what the commands wrote (see the module header).
            agents: &self.delegations,
        };
        check(
            &pdp,
            &mut self.allocator,
            &CheckRequest {
                context: admission.context,
                action: admission.action,
                resource: admission.resource,
                expected_audience: admission.expected_audience,
                relation: admission.relation,
                minimum: &self.minimum,
                attributes: &self.attributes,
                scope: admission.scope,
                at: admission.at,
            },
        )
    }

    fn delegations(&self) -> &DelegationProjection {
        &self.delegations
    }

    fn record_delegation(&mut self, event: &DelegationEvent) {
        self.delegations.apply(event);
    }
}
