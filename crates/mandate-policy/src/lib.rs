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
