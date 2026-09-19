//! Step 3 of the resolution order over a real JOSE implementation: the seam's landing site.
//!
//! The real [`crate::FederationVerifier`] lands here in `story:signing-and-verification`, over
//! the JOSE crate that story's dependency decision admits. This file is the pre-landed stub
//! that story's verifier unit fills, so the unit touches no crate root:
//! `crates/mandate-federation/src/lib.rs` belongs to `story:federation-identity-alignment` in
//! this wave, and two units editing one root is the collision the pre-land exists to avoid.
//!
//! # The network is a port, not a call
//!
//! OIDC discovery and JWKS retrieval are the only part of verification that leaves the
//! process, so they sit behind [`JwksSource`] rather than inside the verifier. The unit drives
//! an in-memory implementation; a `ureq` implementation is exercised only against a listener
//! the test itself owns. No case in this crate reaches the network.

use mandate_types::Issuer;

/// OIDC discovery and JWKS retrieval for one issuer, behind a port.
///
/// An implementation answers with the key set the issuer published, as the document it was
/// served and nothing more: key selection, `kid` matching and rollover across a rotation
/// window read that document and belong to the verifier, not to the transport that fetched it.
///
/// `None` is "this source holds no key set for this issuer", which a verifier refuses. It is
/// not "the signature was absent" and not "the signature was valid"; a verifier that collapsed
/// the three would admit an unsigned proof whenever discovery failed.
pub trait JwksSource {
    /// The key set published for `issuer`, if this source holds one.
    fn jwks(&self, issuer: &Issuer) -> Option<serde_json::Value>;
}
