//! Validated-context binding: what must hold before any authority is read.
//!
//! `systems/mandate/domains/authorization.yaml:22` refuses a request whose
//! "credential-derived context is invalid" or whose "tenant/audience/resource/space
//! binding mismatches" in the same clause that covers a policy denial. The two are not the
//! same thing and this module is the difference: binding is decided from the verified
//! context and the tenancy and topology projections alone, and it is decided *first*, so a
//! request that does not bind reads no authority at all.
//!
//! Every selector here comes from [`mandate_types::VerifiedContext`]. Nothing is read from
//! a caller-supplied organization: `docs/architecture/combined.md` and `AGENTS.md` both
//! require the organization to come from credential validation, and the one value the
//! caller does supply — the audience it expects the credential to have been issued for —
//! is compared against the verified one rather than substituted for it.

use mandate_graph::topology::ResourceLookup;
use mandate_model::graph::Topology;
use mandate_model::tenancy::Tenancy;
use mandate_types::{
    Audience, AuthorityScope, AuthoritySubject, DenialReason, OrganizationId, ResourceRef, SpaceId,
    VerifiedContext,
};

/// What a `mandate.authorization.Check` binds against.
///
/// The three contract inputs are `context`, `action` and `resource`
/// (`authorization.yaml:5-11`); `action` is not a binding input, and the two further
/// fields here are values no port in this crate's dependency ceiling can answer for:
///
/// * `expected_audience` — the audience the caller requires the credential to carry. No
///   audience registry is reachable from the ceiling (`mandate-token` owns resource
///   servers and is not a dependency), so the comparison is against a value the caller
///   states rather than one this crate looks up.
/// * `scope` — the authority scope the request is made under, read here only for its
///   space. `mandate.core.AuthorityScope.space` is the one declared way a request names a
///   space (`crates/mandate-types/src/record.rs:31-43`).
#[derive(Debug)]
pub struct Binding<'a> {
    /// The credential-derived context. Its organization is the tenancy bound.
    pub context: &'a VerifiedContext,
    /// The resource the action is on.
    pub resource: &'a ResourceRef,
    /// The audience the caller requires the credential to have been issued for.
    pub expected_audience: &'a Audience,
    /// The scope the request is made under, when it is made under one.
    pub scope: Option<&'a AuthorityScope>,
}

/// A context that bound: what the authority read is then made for.
///
/// Constructed only by [`bind`], so a value of this type is evidence that the tenant,
/// audience, resource and space bindings all held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bound {
    /// The subject the question is about, taken from the verified context.
    ///
    /// `mandate.core.VerifiedContext` declares `subject: PrincipalId`, so the tagged
    /// subject a graph query carries is always the principal half of
    /// [`mandate_types::AuthoritySubject`]. A team subject is not a credential-derived
    /// context and cannot arrive here.
    pub subject: AuthoritySubject,
    /// The organization every later read is bound to.
    pub organization: OrganizationId,
    /// The resource as the topology records it.
    pub resource: ResourceRef,
    /// The space the request is confined to, when it names one.
    pub space: Option<SpaceId>,
}

/// Bind the verified context, or name the reason it does not bind.
///
/// In order, because each step is a precondition of the next and a refusal reads nothing
/// further:
///
/// 1. the organization the context names still admits authority ([`Tenancy::admits`]);
/// 2. the subject holds an active membership of it ([`Tenancy::is_member`]);
/// 3. the request is direct ([`direct`]);
/// 4. the credential's audience is the one the caller expects;
/// 5. the resource is placed in that organization ([`ResourceLookup::placement`]);
/// 6. the space the scope names resolves in that organization ([`Tenancy::resolve_space`])
///    and the resource is bound to it.
///
/// # Errors
///
/// * [`DenialReason::InvalidCredential`] — the organization the context was validated
///   against no longer admits authority, so nothing the context carries stands. This is
///   not a mismatch between two tenants: there is no second tenant in it.
/// * [`DenialReason::TenantMismatch`] — the subject is not a member of the verified
///   organization, the resource resolves under another one, or the space binding fails.
/// * [`DenialReason::Denied`] — the context is not direct: see [`direct`].
/// * [`DenialReason::AudienceMismatch`] — the credential was issued for another audience.
/// * [`DenialReason::Unavailable`] — the resource does not resolve at all. An absence, not
///   a decision, and it fails closed (`crates/mandate-graph/src/port.rs:76-85`).
pub fn bind<L: ResourceLookup + ?Sized>(
    tenancy: &Tenancy,
    topology: &Topology,
    lookup: &L,
    binding: &Binding<'_>,
) -> Result<Bound, DenialReason> {
    let context = binding.context;
    let organization = context.organization;

    if !tenancy.admits(organization) {
        return Err(DenialReason::InvalidCredential);
    }
    if !tenancy.is_member(organization, context.subject) {
        return Err(DenialReason::TenantMismatch);
    }
    if !direct(context) {
        return Err(DenialReason::Denied);
    }
    if &context.audience != binding.expected_audience {
        return Err(DenialReason::AudienceMismatch);
    }

    let placement = lookup
        .placement(&organization, binding.resource)
        .map_err(|refusal| refusal.denial_reason())?;

    let space = match binding.scope.and_then(|scope| scope.space) {
        None => None,
        Some(named) => {
            // The space is the caller's claim; that it exists in this organization is
            // the tenancy's. A space another organization holds is indistinguishable
            // here from one nobody holds, which is the isolation the resolver is for.
            if tenancy.resolve_space(context, named).is_none() {
                return Err(DenialReason::TenantMismatch);
            }
            // The resource's own space, as the projection records it. No command in
            // `systems/mandate` writes `mandate.graph.Resource.space_id`
            // (`crates/mandate-model/src/graph.rs:34-41`), so a request that names a
            // space binds to nothing today and is refused. That is the closed
            // direction, and inventing an input the contract does not declare to open
            // it is `story:event-payloads-for-folds`'s to fix at the contract.
            let recorded = topology
                .resolve(context, binding.resource.resource_id)
                .and_then(|resource| resource.space_id);
            if recorded != Some(named) {
                return Err(DenialReason::TenantMismatch);
            }
            Some(named)
        }
    };

    Ok(Bound {
        subject: AuthoritySubject::Principal(context.subject),
        organization,
        resource: placement.resource,
        space,
    })
}

/// Whether the request is a direct one: the subject acting as itself, under no delegated
/// authority this crate cannot bound.
///
/// `docs/architecture/combined.md:53` makes effective authority the intersection of, among
/// others, the **actor ceiling** and the **explicit delegation**. `mandate.core.VerifiedContext`
/// carries all three of the inputs that say a request is not direct — `actor`, `delegation`
/// and `execution` (`crates/mandate-types/src/record.rs:63-95`) — and this crate's
/// dependency ceiling contains no port that reads any of them: `mandate.delegation` is
/// projected by nothing in `dependency-boundaries.json:20-25`, and no ceiling record is
/// reachable. A bound that cannot be evaluated cannot be intersected, and granting as
/// though it were unbounded is the open direction, so a request that names one is refused.
///
/// * `actor` absent, or equal to the subject — the subject acting as itself. Direct.
/// * any other `actor` — refused: the actor ceiling is `story:agent-authority-kernel`'s
///   (`docs/architecture/ownership.md:16`), together with the `agent_id` binding of
///   `mandate.delegation.AgentCapabilityCeiling`, and is not implemented here.
/// * `delegation` or `execution` present — refused for the same reason, one field over: an
///   explicit delegation and an execution each bound the authority, and neither record is
///   readable from here.
///
/// The refusal is [`DenialReason::Denied`]: it is a decision about this request's
/// authority, not an outage and not a statement that some record is missing.
#[must_use]
pub fn direct(context: &VerifiedContext) -> bool {
    let acting_as_itself = context
        .actor
        .as_ref()
        .is_none_or(|actor| actor == &context.subject);

    acting_as_itself && context.delegation.is_none() && context.execution.is_none()
}
