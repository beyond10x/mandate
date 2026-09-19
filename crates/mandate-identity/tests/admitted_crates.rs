//! The generated contract shape admitted to `mandate-identity` resolves and links.
//!
//! The identity fold opens a Session from the payload `mandate-federation` emits, so it reads
//! the generated shape rather than a hand-written copy of it. Naming the type here shows the
//! regular dependency resolves and keeps the direction `mandate-federation → mandate-identity`:
//! `mandate-contract` re-exports generated structure and can reach no Mandate domain crate.

#[test]
fn the_generated_federation_authenticated_payload_is_reachable_from_identity() {
    assert!(size_of::<mandate_contract::events::MandateFederationFederationAuthenticated>() > 0);
}
