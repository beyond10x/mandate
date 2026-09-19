//! Generated structural shapes of the Mandate contract: events, command inputs and
//! responses, entities and errors.
//!
//! This crate is a re-export surface and holds no hand-written shape. `story:contract-shapes`
//! fills it: `cargo xtask generate` emits
//! `generated/rust/mandate-contract/src/{types,entities,commands,events}.rs` from the compiled
//! model at `generated/ir/system.json`, and this file will re-export those modules with
//! `#[path = "../../../generated/rust/mandate-contract/src/<kind>.rs"] pub mod <kind>;`.
//! Nothing under `generated/` is ever hand-edited; `cargo xtask contracts` byte-compares the
//! committed emission against a fresh one, so a shape that drifts from its ESS declaration is a
//! failing gate rather than a silent divergence.
//!
//! The crate exists ahead of that emission because the emitter, the boundary policy and the
//! workspace membership are wired once, by the coordinator, and the story that writes the
//! shapes then only adds files under `generated/`. Its dependencies are `serde` and
//! `serde_json` and will stay that way: a shape crate that could reach a Mandate domain crate
//! would let a hand-written type answer for a generated one.
