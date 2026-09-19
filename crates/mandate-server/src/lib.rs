//! Transport and validated security-context extraction.
//!
//! The adapter library of the customer login road: the request value a listener fills, one
//! decoder per road command, the product route table, the RFC 8414 and JWKS document shapes,
//! and the typed registry of every command's adapter obligations.
//!
//! # What this crate is not
//!
//! It holds no listener, no socket and no async: `story:product-listener` binds this library
//! to transport in `services/control-plane`. It holds no PDP and no issuance authority either
//! (`docs/architecture/ownership.md:20`) — every decision a road request needs is a handler's,
//! in `crates/mandate-federation` and `services/sts`, and this crate reaches neither.
//!
//! # The dependency ceiling is the design
//!
//! `dependency-boundaries.json` gives this crate `mandate-types` and `mandate-proto`. There is
//! no `http`, no `url`, no `percent-encoding`, no `httparse`, no `serde` and no `serde_json`,
//! and nothing may be added. Every wire form here is therefore built from `std` and from what
//! `mandate_proto::oauth` carries, and every value is a `mandate-types` value or a plain
//! `String`, `Vec<u8>` or `bool`.
//!
//! The written contract this library is the code of is `docs/architecture/adapter-contract.md`.

pub mod decode;
pub mod metadata;
pub mod obligations;
pub mod routes;
