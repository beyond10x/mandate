//! The transient credential boundary.
//!
//! `docs/architecture/combined.md`: "CredentialSecret and CredentialProof are transient
//! boundary types, never persisted entity fields or audit payloads." Neither type
//! implements `PersistedValue`, and no crate outside this one can add that impl.

canonical_transient_bytes! {
    CredentialSecret, CredentialProof,
}
