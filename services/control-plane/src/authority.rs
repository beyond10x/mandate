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
//! **The half that is decided over live state.** `mandate_authz::context::bind` reads
//! `mandate_model::tenancy::Tenancy` and `mandate_model::graph::Topology`, both folds, and
//! decides four things before either port is read: the organization still admits authority,
//! the subject is a member of it, the request is direct, and the credential's audience is
//! the expected one. A caller failing any of those is refused over the fold. What a fold
//! cannot answer is the one thing the caller-authority clauses name — whether the caller
//! *holds* the authority — because `tenancy.rs:317-318` puts that with "grants and
//! relationships", which are the graph's and the policy's.
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
//! * **No ceiling is passed.** No `mandate.delegation.AgentCapabilityCeiling` is readable
//!   from this package's ceiling either, and `mandate_authz::context::direct` already
//!   refuses a delegated context outright. `story:agent-authority-kernel` owns that.
//! * **No denial is audited.** `decision-blocker:audit-routing` holds the vocabulary and
//!   `mandate-audit` is outside this package's ceiling, exactly as `adapters.rs` records
//!   for every other refusal the road gives.

use mandate_authz::decision::{ChallengeIssuer, DecisionIdAllocator, Denied};
use mandate_authz::{CheckRequest, Pdp, check};
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
                ceilings: &[],
            },
        )
    }
}
