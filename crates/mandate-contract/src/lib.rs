//! Generated structural shapes of the Mandate contract: events, command inputs and
//! responses, entities and errors.
//!
//! This crate is a re-export surface and holds no hand-written shape. `cargo xtask generate`
//! emits `generated/rust/mandate-contract/src/{types,entities,commands,events}.rs` from the
//! compiled model at `generated/ir/system.json`, and the four modules below are those files.
//! Nothing under `generated/` is ever hand-edited; `cargo xtask contracts` byte-compares the
//! committed emission against a fresh one, so a shape that drifts from its ESS declaration is
//! a failing gate rather than a silent divergence. To change a shape, change the declaration
//! in `systems/mandate` and run `cargo xtask generate`.
//!
//! What the shapes state is structure, and only structure: which keys a document carries and
//! what kind of value each holds. Every record refuses a key its declaration does not name and
//! every declared key is required, so a representation that has drifted from its declaration
//! fails to round-trip rather than silently dropping or inventing a field. A declared-optional
//! key is carried by [`types::Presence`], which distinguishes a missing key from `null`
//! because ESS `optional` admits the first and not the second. Lexical constraints — a
//! timestamp's format, a uuid's shape, the base64 alphabet of a `bytes` value — belong to the
//! JSON Schema projection beside these files; a Rust type that claimed them here would be
//! claiming validation it does not do.
//!
//! An event and an entity may not carry credential material, and the emitter refuses to write
//! one that reaches `mandate.core.CredentialSecret` or `mandate.core.CredentialProof` through
//! any chain of declared types. A command input may: it is the message that carries a
//! credential to be verified.
//!
//! Its dependencies are `serde` and `serde_json` and will stay that way: a shape crate that
//! could reach a Mandate domain crate would let a hand-written type answer for a generated one.

/// The declared types: newtypes, enums, structs, unions and the `Presence` carrier.
#[path = "../../../generated/rust/mandate-contract/src/types.rs"]
pub mod types;

/// The entity records and their lifecycle state enums.
#[path = "../../../generated/rust/mandate-contract/src/entities.rs"]
pub mod entities;

/// The command inputs, the responses of the commands that declare one, and the refusals.
#[path = "../../../generated/rust/mandate-contract/src/commands.rs"]
pub mod commands;

/// The event payloads.
#[path = "../../../generated/rust/mandate-contract/src/events.rs"]
pub mod events;
