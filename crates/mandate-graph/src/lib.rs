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
