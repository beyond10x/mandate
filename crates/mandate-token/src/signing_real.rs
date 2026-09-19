//! Credential signing over a real cryptographic implementation: the seam's landing site.
//!
//! The signing port implementation lands here in `story:signing-and-verification`, over the
//! crate that story's dependency decision admits. This file is the pre-landed stub that
//! story's signing unit fills, so the unit touches no crate root.
//!
//! The module is empty on purpose, and it is empty in a second way worth naming: this crate
//! declares no signing port trait at all. `mandate-federation` declares `FederationVerifier`
//! and `SessionIssuer` as traits its handlers call through, and the verifier unit attaches to
//! the first of those; `mandate-token` has no matching seam, so the signing unit has nothing
//! to implement until one is declared. Declaring it is not this pre-land's to do, and the
//! unit reports rather than adding a trait to a root it does not own.
