//! Conditional policies, deny precedence and ceilings.
//!
//! Policy is reached through the ports in [`port`]: an evaluation that answers allow, deny
//! or approval-required and names the version it answered under, and the administration
//! port for the two supersede commands `systems/mandate/domains/policy.yaml` declares.
//! [`precedence`] is the single home of deny precedence and of role expansion;
//! `story:check-api` consumes it. [`double`] is an in-memory evaluator behind the same
//! ports, publicly constructible, for a caller under test. No policy engine is chosen
//! here; choosing one is `story:graph-policy-adapter`'s.
//!
//! A port here returns components, never a `mandate.authorization.Decision`: combined
//! decision evaluation is `mandate-authz`'s (`docs/architecture/ownership.md:13`).
//!
//! # The port boundary
//!
//! The attribute input is deliberately opaque — `docs/sources/original-design.md:738`
//! still asks how resource attributes are trusted and distributed, so the parameter cannot
//! be frozen yet. Opaque does not mean untyped: [`port::AttributeInput`] is sealed, so the
//! set carries canonical values and a backend's own row cannot be carried through it.
//!
//! A canonical value goes in:
//!
//! ```
//! use mandate_policy::port::{AttributeSet, AttributeValue};
//! use mandate_types::Action;
//!
//! let attributes = AttributeSet::new()
//!     .with("classification", "restricted")
//!     .with("action", Action::new("read"));
//!
//! assert_eq!(
//!     attributes.get("classification"),
//!     Some(&AttributeValue::Text("restricted".to_owned())),
//! );
//! ```
//!
//! A backend row does not, and it does not even when the adapter teaches its row the
//! input trait first. That second half is what makes this a boundary rather than a
//! convention: the seal, not the bound, is what refuses it.
//!
//! ```compile_fail
//! use mandate_policy::port::{AttributeInput, AttributeSet, AttributeValue};
//!
//! #[derive(Debug, Clone, PartialEq, Eq)]
//! struct BackendRow {
//!     column: u64,
//! }
//!
//! impl AttributeInput for BackendRow {
//!     fn into_value(self) -> AttributeValue {
//!         AttributeValue::Text(self.column.to_string())
//!     }
//! }
//!
//! let attributes = AttributeSet::new()
//!     .with("classification", BackendRow { column: 1 });
//! ```

pub mod double;
pub mod port;
pub mod precedence;
pub mod record;

mandate_types::realizes! {
    "mandate.policy.SupersedePolicy" => crate::port::PolicyAdministration,
    "mandate.policy.SupersedeAuthorizationModel" => crate::port::PolicyAdministration,
    "mandate.policy.Policy" => crate::record::Policy,
    "mandate.policy.AuthorizationModel" => crate::record::AuthorizationModel,
    "mandate.policy.Policy.State" => crate::record::PolicyState,
    "mandate.policy.AuthorizationModel.State" => crate::record::AuthorizationModelState,
    "mandate.policy.Denied" => crate::port::PolicyError,
    // A command is realized by the port that declares it, not by a handler: this crate
    // chooses no policy engine (`story:graph-policy-adapter` does), so what it implements of
    // each supersede command is the operation's signature, its refusals and the transition
    // the projection owns. `double` is one implementation of those ports and is not the
    // realization; an adapter is another.
}

/// Every declared `mandate.policy` element this crate does **not** realize, with the reason.
///
/// A coverage registry that names what it covers and says nothing about the rest is read as
/// a claim about the whole domain. This is the other half of [`ESS_REALIZATIONS`], and
/// `crates/mandate-policy/tests/contract_agreement.rs` decides the pair against the compiled
/// model in both directions: an element this list names and the registry also realizes is a
/// contradiction, and an element neither one names is an element nobody accounted for.
///
/// Both are the events an accepted supersede emits, and neither is an oversight. This crate
/// declares no payload type for either: [`port::Superseded`] is what the port call returns —
/// the projection as it now stands and whether the move was already recorded — and it
/// carries neither the declared `context` the payload leads with nor the identity it names.
/// Building the payload is the adapter's, with the engine `story:graph-policy-adapter`
/// chooses.
pub const ESS_UNREALIZED: &[(&str, &str)] = &[
    (
        "mandate.policy.PolicySuperseded",
        "no event payload type is declared here: port::Superseded is a port outcome, not the \
         declared payload, and the adapter that appends the event builds it; owner \
         story:graph-policy-adapter",
    ),
    (
        "mandate.policy.AuthorizationModelSuperseded",
        "no event payload type is declared here: port::Superseded is a port outcome, not the \
         declared payload; owner story:graph-policy-adapter",
    ),
];
