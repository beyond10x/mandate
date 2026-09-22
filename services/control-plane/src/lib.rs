//! The composition: the control plane and the STS hosted in one process for the first
//! served vertical, with the port adapters that let each side read the other's records,
//! and the listener that serves the login road over HTTP/1.1.
//!
//! The authority rows of `docs/architecture/ownership.md` do not move: the STS handlers in
//! `services/sts` still decide issuance and redemption, the control plane's still decide
//! authentication and authorization. This crate wires them and speaks HTTP.
//!
//! It decides one thing of its own, and only when a deployment is configured to:
//! [`authority`] asks `mandate.authorization.Check` before a handler is dispatched and
//! returns the declared refusal when the answer is not an allow. That question has one
//! decider in this workspace, `mandate_authz::check`, and no composition could reach it
//! until `dependency-boundaries.json` admitted the edge; [`authority`]'s header records why
//! the edge is here and why every answer it can get today is a double's.

pub mod adapters;
pub mod authority;
pub mod serve;
