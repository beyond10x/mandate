//! The non-reversible reference verifier, as a port.
//!
//! `mandate.credential.AccessCredential.reference_verifier` is what a reference credential
//! leaves behind: "only non-reversible verifier persists; raw secret returned once"
//! (`tests/security/cases.json`, `reference-persistence`). This module is the two halves of
//! that — deriving the verifier from material, and deciding whether presented material
//! derives a recorded one — and neither half can put the material into a record:
//! [`mandate_types::CredentialSecret`] and [`mandate_types::CredentialProof`] are transient
//! and are not [`mandate_types::PersistedValue`], so a projection cannot name one.
//!
//! # Why the material carries a domain tag
//!
//! One deployment holds verifiers for material of several kinds in one index. [`verifier_in`]
//! prefixes each kind's [`CredentialDomain`] tag before the digest sees the material, so the
//! kinds occupy disjoint spaces and a value of one kind cannot resolve to a record of
//! another. It is done here, at the port, rather than inside an implementation: an
//! implementation that forgot would be a silent loss of the separation, and there is nothing
//! a record could be checked against to notice.
//!
//! # Why the digest is the caller's
//!
//! `dependency-boundaries.json` admits no digest implementation to this crate; `services/sts`
//! has `sha2`. [`CredentialDigest`] is therefore a port, and the deployment supplies the
//! function. What stays here is what does not depend on which digest it is: that a verifier
//! is *derived* rather than stored, that equal material derives one verifier, and how two
//! verifiers are compared.
//!
//! # Why the comparison is written out
//!
//! `==` on two byte strings is free to return at the first differing byte, and a comparison
//! that answers sooner for a longer shared prefix is how a verifier is recovered one byte at
//! a time from a remote caller. [`constant_time_eq`] reads both values to the end of the
//! longer one and folds the length difference in rather than branching on it, so its
//! running time is a function of the two lengths and of nothing in the bytes.
//!
//! The guarantee is the one the source can make. Whether the compiler and the processor
//! preserve it is not decidable in this repository's dependency set; a deployment that needs
//! that assurance supplies a digest and a comparison from a crate that carries it, through
//! this same port.

use mandate_types::{CredentialVerifier, Transient};

/// The digest a deployment supplies: material in, a non-reversible verifier out.
///
/// An implementation must be a function — equal material derives an equal verifier — and
/// must not be invertible, because what it returns is what the record keeps.
///
/// It is handed material that already carries its [`CredentialDomain`] tag, so no
/// implementation has to remember to separate the families and none can forget to; see
/// [`verifier_in`].
pub trait CredentialDigest {
    /// The verifier this material derives.
    fn digest(&self, material: &[u8]) -> CredentialVerifier;
}

/// Which kind of credential material is being digested.
///
/// One deployment stores verifiers for material of several kinds in one place — a reference
/// secret, a self-contained token, and the authorization-code verifier
/// `story:oauth-integration` will add (`credential.yaml`: "STS alone owns
/// authorization-code verifier storage and consumption"). Digesting all three into one
/// space means a value of one kind can resolve to a record of another: an authorization
/// code presented where a credential proof is expected resolves to the code's record if the
/// two digests are the same function of the same bytes.
///
/// Each kind is therefore digested in its own domain, and the domains are disjoint by
/// construction: [`verifier_in`] prefixes the tag and a separator byte that no tag contains,
/// so no material of one kind can produce the tagged input of another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CredentialDomain {
    /// The secret a reference issuance returns once.
    ReferenceSecret,
    /// The compact token a self-contained issuance returns.
    SelfContainedToken,
    /// The authorization code an `IssueAuthorizationCode` returns.
    ///
    /// Named here and used by nothing in this wave: the command and the record are
    /// `story:oauth-integration`'s, and the tag exists so that story adds a call site rather
    /// than a third digest space.
    AuthorizationCodeVerifier,
}

impl CredentialDomain {
    /// The constant this domain's material is prefixed with.
    ///
    /// Qualified names, so a tag is a statement about the contract and not a word that
    /// might mean something else in another deployment.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::ReferenceSecret => "mandate.credential.reference-secret",
            Self::SelfContainedToken => "mandate.credential.self-contained-token",
            Self::AuthorizationCodeVerifier => "mandate.credential.authorization-code-verifier",
        }
    }
}

/// The verifier a transient value derives in a named domain.
///
/// The domain's tag and a `0x00` separator are prefixed to the material before the digest
/// sees it. The separator is what makes the encoding unambiguous — no tag contains a zero
/// byte, so `tag(a) ‖ 0 ‖ x` and `tag(b) ‖ 0 ‖ y` are equal only when the domains and the
/// material are both equal — and prefixing here rather than inside an implementation means
/// the separation is a property of this port and not of one deployment's hash choice.
pub fn verifier_in<T: Transient + ?Sized>(
    digest: &impl CredentialDigest,
    domain: CredentialDomain,
    material: &T,
) -> CredentialVerifier {
    let material = material.expose_material();
    let tag = domain.tag().as_bytes();
    let mut tagged = Vec::with_capacity(tag.len() + 1 + material.len());
    tagged.extend_from_slice(tag);
    tagged.push(0);
    tagged.extend_from_slice(material);
    digest.digest(&tagged)
}

/// The verifier a **reference secret** derives.
///
/// [`verifier_in`] in the [`CredentialDomain::ReferenceSecret`] domain, which is the family
/// whose material *is* the credential. The other families name their domain.
///
/// One function for both boundary types: the secret an issuance returns once and the proof
/// a holder presents back carry the same material, and a record that resolved them through
/// two digests would resolve nothing.
pub fn verifier_for<T: Transient + ?Sized>(
    digest: &impl CredentialDigest,
    material: &T,
) -> CredentialVerifier {
    verifier_in(digest, CredentialDomain::ReferenceSecret, material)
}

/// Whether a presented verifier is the recorded one.
///
/// Compared through [`constant_time_eq`]; see the module documentation for why.
#[must_use]
pub fn matches(recorded: &CredentialVerifier, presented: &CredentialVerifier) -> bool {
    constant_time_eq(recorded.as_str().as_bytes(), presented.as_str().as_bytes())
}

/// Whether presented material derives the recorded verifier in a named domain.
///
/// The composition of the two halves, so that no caller has to remember to compare the
/// derived value rather than the material.
pub fn presents_in<T: Transient + ?Sized>(
    digest: &impl CredentialDigest,
    domain: CredentialDomain,
    recorded: &CredentialVerifier,
    material: &T,
) -> bool {
    matches(recorded, &verifier_in(digest, domain, material))
}

/// [`presents_in`] in the [`CredentialDomain::ReferenceSecret`] domain.
pub fn presents<T: Transient + ?Sized>(
    digest: &impl CredentialDigest,
    recorded: &CredentialVerifier,
    material: &T,
) -> bool {
    presents_in(
        digest,
        CredentialDomain::ReferenceSecret,
        recorded,
        material,
    )
}

/// Whether two byte strings are equal, in a time that depends on their lengths alone.
///
/// No early return on the first differing byte, and no branch on the length difference:
/// both values are read to the end of the longer one, a byte past the end reads as zero,
/// and the length difference is folded into the same accumulator. A shorter value whose
/// bytes are a prefix of the longer one is therefore refused by the length term alone.
#[must_use]
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = (left.len() ^ right.len()) as u64;
    let width = if left.len() > right.len() {
        left.len()
    } else {
        right.len()
    };
    for index in 0..width {
        let one = left.get(index).copied().unwrap_or(0);
        let other = right.get(index).copied().unwrap_or(0);
        difference |= u64::from(one ^ other);
    }
    difference == 0
}
