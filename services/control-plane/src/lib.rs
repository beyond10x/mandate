//! The composition: the control plane and the STS hosted in one process for the first
//! served vertical, with the port adapters that let each side read the other's records,
//! and the listener that serves the login road over HTTP/1.1.
//!
//! The authority rows of `docs/architecture/ownership.md` do not move: the STS handlers in
//! `services/sts` still decide issuance and redemption, the control plane's still decide
//! authentication and authorization. This crate wires them and speaks HTTP; it decides
//! nothing about a request beyond what `mandate_server::decode` and the handlers decide.

pub mod adapters;
pub mod serve;
