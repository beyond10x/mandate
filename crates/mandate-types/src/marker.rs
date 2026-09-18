//! The boundary between a value that may be persisted and one that may not.
//!
//! `docs/architecture/combined.md` states it as a rule: "CredentialSecret and
//! CredentialProof are transient boundary types, never persisted entity fields or audit
//! payloads." [`PersistedValue`] is that rule expressed so the compiler decides it.
//!
//! The guarantee, stated at the width it actually holds: [`PersistedValue`] is not
//! implemented for [`crate::CredentialSecret`] or [`crate::CredentialProof`] here, and no
//! other crate can add it *for those types*, because both the trait and the types are
//! foreign to it. So no record declared through [`crate::canonical_record`] can name one
//! as a field type, nor `Option` or `Vec` of one.
//!
//! It does not extend to every type that contains one. A crate may declare its own
//! `struct Envelope<T>(T)` and implement [`PersistedValue`] for `Envelope<CredentialSecret>`
//! — a local type, so the orphan rule permits it — and [`crate::canonical_record`] will
//! admit that field. Sealing this trait would close that hole and also stop
//! [`crate::canonical_record`] working in any crate but this one, which is the whole point
//! of it, so the hole is left open and named here instead of being claimed shut.
//!
//! What holds regardless of the wrapper is the other half of the boundary: the transient
//! types serialize as [`crate::REDACTED`], so a laundered field still puts no credential
//! material on a record's wire form. `mandate-model`'s adversary suite pins exactly that.

use crate::value::{Duration, Timestamp};

/// A value admitted into a record that may be persisted.
///
/// Every field of every record declared through [`crate::canonical_record`] must
/// implement this trait.
pub trait PersistedValue {}

/// A boundary value that exists only while a request is in flight.
pub trait Transient {}

impl<T: PersistedValue> PersistedValue for Option<T> {}
impl<T: PersistedValue> PersistedValue for Vec<T> {}
impl PersistedValue for bool {}
impl PersistedValue for String {}

const _: () = {
    // Timestamp and Duration carry their own impl beside their declaration; naming them
    // here keeps this module's import honest about what the boundary admits.
    fn admitted<T: PersistedValue>() {}
    #[allow(dead_code)]
    fn check() {
        admitted::<Timestamp>();
        admitted::<Duration>();
    }
};
