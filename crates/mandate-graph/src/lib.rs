//! Relationship storage ports and adapters.
//!
//! The graph is reached through the ports in [`port`]: a revision-bound read, and one
//! port for each command `systems/mandate/domains/graph.yaml` declares. [`double`] is an
//! in-memory fold behind the same ports, publicly constructible, for a caller under test.
//! No storage engine is chosen here; choosing one is `story:graph-policy-adapter`'s.
//!
//! # The port boundary
//!
//! A port speaks the canonical vocabulary and nothing else. The revision a caller
//! requires is [`mandate_types::AuthzRevision`]: [`port::Revision`] is sealed, so an
//! adapter maps its backend's own consistency token onto the canonical revision rather
//! than teaching the port a second revision type. Which token that is, and how it maps,
//! is `story:graph-policy-adapter`'s.
//!
//! An adapter that speaks the canonical revision implements the read port:
//!
//! ```
//! use mandate_graph::port::{GraphError, GraphQuery, GraphRead, Observed, Unanswered};
//! use mandate_types::AuthzRevision;
//!
//! struct Adapter;
//!
//! impl GraphRead for Adapter {
//!     type Revision = AuthzRevision;
//!
//!     fn check(
//!         &self,
//!         _query: &GraphQuery<'_>,
//!         _minimum: &AuthzRevision,
//!     ) -> Result<Observed, GraphError> {
//!         Err(GraphError::CouldNotAnswer(Unanswered::NotCaughtUp))
//!     }
//! }
//! ```
//!
//! The same adapter carrying a backend token does not compile, and it does not compile
//! even when the adapter teaches its token the revision trait first. That second half is
//! what makes this a boundary rather than a convention: the seal, not the bound, is what
//! refuses it.
//!
//! ```compile_fail
//! use mandate_graph::port::{
//!     GraphError, GraphQuery, GraphRead, Observed, Revision, Unanswered,
//! };
//! use mandate_types::AuthzRevision;
//!
//! #[derive(Debug, Clone, PartialEq, Eq)]
//! struct BackendToken(u64);
//!
//! impl Revision for BackendToken {
//!     fn as_authz_revision(&self) -> &AuthzRevision {
//!         unimplemented!()
//!     }
//! }
//!
//! struct Adapter;
//!
//! impl GraphRead for Adapter {
//!     type Revision = BackendToken;
//!
//!     fn check(
//!         &self,
//!         _query: &GraphQuery<'_>,
//!         _minimum: &BackendToken,
//!     ) -> Result<Observed, GraphError> {
//!         Err(GraphError::CouldNotAnswer(Unanswered::NotCaughtUp))
//!     }
//! }
//! ```

pub mod double;
pub mod port;
pub mod record;
pub mod relationship;
pub mod revocation;
pub mod topology;

mandate_types::realizes! {
    "mandate.graph.WriteRelationship" => crate::relationship::RelationshipWriter,
    "mandate.graph.RemoveRelation" => crate::revocation::RevocationWriter,
    "mandate.graph.RevokeGrant" => crate::revocation::RevocationWriter,
    "mandate.graph.RegisterResource" => crate::topology::ResourceRegistry,
    "mandate.graph.DeregisterResource" => crate::topology::ResourceRegistry,
    "mandate.graph.Relation" => crate::record::Relation,
    "mandate.graph.Grant" => crate::record::Grant,
    "mandate.graph.Relation.State" => crate::record::RelationState,
    "mandate.graph.Grant.State" => crate::record::GrantState,
    "mandate.graph.Denied" => crate::port::GraphError,
    // A command is realized by the port that declares it, not by a handler: this crate
    // chooses no storage engine (`story:graph-policy-adapter` does), so what it implements
    // of each command is the operation's signature, its refusals and the rule the graph
    // itself owns. `double` is one implementation of those ports and is not the
    // realization; an adapter is another.
}

/// Every declared `mandate.graph` element this crate does **not** realize, with the reason.
///
/// A coverage registry that names what it covers and says nothing about the rest is read as
/// a claim about the whole domain. This is the other half of [`ESS_REALIZATIONS`], and
/// `crates/mandate-graph/tests/contract_agreement.rs` decides the pair against the compiled
/// model in both directions: an element this list names and the registry also realizes is a
/// contradiction, and an element neither one names is an element nobody accounted for.
///
/// Two groups, and neither is an oversight.
///
/// Four elements of this domain are realized in **another crate**. `ownership.md:13` splits
/// `mandate.graph` between `mandate-model`, which holds the `Resource` projection, and this
/// crate, which holds the relation and grant projections of its own fold and the ports.
/// [`topology`] says the same thing from this side: this crate never holds a resource as a
/// struct, it asks a [`topology::ResourceLookup`] where one sits. One declared element has
/// one realizer, so these are named here rather than registered twice.
///
/// Three are the events an accepted mutation emits. This crate declares no payload type for
/// any of them: [`relationship::Written`], [`revocation::Removal`] and
/// [`revocation::Revocation`] are what a port call returns — the projection, the fold
/// position and whether the move was already recorded — and none carries the declared
/// `context` an event payload leads with. Building the payload is the adapter's, with the
/// engine `story:graph-policy-adapter` chooses.
pub const ESS_UNREALIZED: &[(&str, &str)] = &[
    (
        "mandate.graph.Resource",
        "realized by mandate_model::graph::Resource; ownership.md:13 gives the Resource \
         projection to mandate-model; owner story:tenancy-topology",
    ),
    (
        "mandate.graph.Resource.State",
        "realized by mandate_model::graph::ResourceState beside the record it folds; owner \
         story:tenancy-topology",
    ),
    (
        "mandate.graph.ResourceRegistered",
        "realized by mandate_model::graph::ResourceEvent::Registered; owner \
         story:tenancy-graph-events",
    ),
    (
        "mandate.graph.ResourceDeregistered",
        "realized by mandate_model::graph::ResourceEvent::Deregistered; owner \
         story:tenancy-graph-events",
    ),
    (
        "mandate.graph.RelationshipWritten",
        "no event payload type is declared here: relationship::Written is a port outcome, \
         not the declared payload, and the adapter that appends the event builds it; owner \
         story:graph-policy-adapter",
    ),
    (
        "mandate.graph.RelationRemoved",
        "no event payload type is declared here: revocation::Removal is a port outcome, not \
         the declared payload; owner story:graph-policy-adapter",
    ),
    (
        "mandate.graph.GrantRevoked",
        "no event payload type is declared here: revocation::Revocation is a port outcome, \
         not the declared payload; owner story:graph-policy-adapter",
    ),
];
