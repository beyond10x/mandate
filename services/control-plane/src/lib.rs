//! The composition: the control plane and the STS hosted in one process for the first
//! served vertical, with the port adapters that let each side read the other's records.
//!
//! `src/main.rs` stays the scaffold that refuses `serve` until `story:product-listener`
//! lands its listener; the authority rows of `docs/architecture/ownership.md` do not move.
//! Modules are added by that story.
